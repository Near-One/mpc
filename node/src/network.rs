pub mod computation;
pub mod conn;
pub mod constants;
pub mod handshake;
pub mod indexer_heights;
pub mod signing;

use crate::metrics;
use crate::primitives::{
    ChannelId, IndexerHeightMessage, MpcMessage, MpcMessageKind, MpcPeerMessage, MpcStartMessage,
    MpcTaskId, ParticipantId, PeerMessage, UniqueId,
};
use crate::tracking::{self, AutoAbortTask};
use conn::{ConnectionVersion, NodeConnectivityInterface};
use indexer_heights::IndexerHeightTracker;
use lru::LruCache;
use rand::prelude::IteratorRandom;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::option::Option;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Abstraction of the networking layer, from the view of one client, the sender side.
/// For a running node, there should be only one such instance that handles all
/// p2p network communication. This is thread safe; it's expected that there would be
/// many references to this object via Arc.
#[async_trait::async_trait]
pub trait MeshNetworkTransportSender: Send + Sync + 'static {
    /// Returns the participant ID of the current node.
    fn my_participant_id(&self) -> ParticipantId;
    /// Returns the participant IDs of all nodes in the network, including the current node.
    fn all_participant_ids(&self) -> Vec<ParticipantId>;
    /// Returns a connectivity interface for the given other participant.
    fn connectivity(&self, participant_id: ParticipantId) -> Arc<dyn NodeConnectivityInterface>;
    /// Sends a message to the specified recipient.
    ///
    /// For messages M = [m_0, m_1, m_2, ..., m_n] sent via this method to the same recipient
    /// for which this method returned Ok, it is guaranteed that the recipient will receive
    /// M[0..i] for some 0 <= i <= n.
    ///
    /// The connection_version is used to detect if the connection is broken, in which case
    /// such a guarantee is no longer possible.
    fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
        connection_version: ConnectionVersion,
    ) -> anyhow::Result<()>;
    /// Sends a message to everyone on a best-effort basis about the current height of our indexer.
    fn send_indexer_height(&self, height: IndexerHeightMessage);
    /// Waits until at least `threshold` nodes in the network have been connected to initially,
    /// the threshold includes ourselves.
    async fn wait_for_ready(&self, threshold: usize) -> anyhow::Result<()>;
}

/// The receiving side of the networking layer. It is expected that the node will run
/// a loop that calls receive(), and then immediately hand off the message to another
/// tokio task to process it.
#[async_trait::async_trait]
pub trait MeshNetworkTransportReceiver: Send + 'static {
    async fn receive(&mut self) -> anyhow::Result<PeerMessage>;
}

/// Concrete logic for a client based on the networking layer.
/// Manages a collection of MPC tasks so that they can be multiplexed onto the
/// networking layer underneath.
pub struct MeshNetworkClient {
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    channels: Arc<Mutex<NetworkTaskChannelManager>>,
    indexer_heights: Arc<IndexerHeightTracker>,
    /// Helper data to ensure `ChannelId` uniqueness.
    last_id: Arc<Mutex<UniqueId>>,
}

/// Manages currently active channels as well as buffering messages for channels that are waiting
/// for the Start message.
struct NetworkTaskChannelManager {
    senders: HashMap<ChannelId, mpsc::UnboundedSender<MpcPeerMessage>>,
    channels_waiting_for_start: LruCache<ChannelId, IncompleteNetworkTaskChannel>,
}

impl NetworkTaskChannelManager {
    fn new() -> Self {
        Self {
            senders: HashMap::new(),
            channels_waiting_for_start: LruCache::new(LRU_CAPACITY.try_into().unwrap()),
        }
    }
}

const LRU_CAPACITY: usize = 10000;

impl MeshNetworkClient {
    fn new(
        transport_sender: Arc<dyn MeshNetworkTransportSender>,
        channels: Arc<Mutex<NetworkTaskChannelManager>>,
        indexer_heights: Arc<IndexerHeightTracker>,
    ) -> Self {
        let last_id = Arc::new(Mutex::new(UniqueId::generate(
            transport_sender.my_participant_id(),
        )));
        Self {
            transport_sender,
            channels,
            indexer_heights,
            last_id,
        }
    }

    fn generate_unique_channel_id(&self) -> ChannelId {
        let mut last_id = self.last_id.lock().unwrap();
        let new = last_id.pick_new_after();
        *last_id = new;
        ChannelId(new)
    }

    /// Primary functionality for the MeshNetworkClient: returns a channel for the given
    /// new MPC task. It is expected that the caller is the leader of this MPC task.
    /// There may be two tasks with the same `MpcTaskId` (e.g. EdDSA retry computation),
    /// but they would have different channel ids.
    pub fn new_channel_for_task(
        &self,
        task_id: impl Into<MpcTaskId>,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        let task_id: MpcTaskId = task_id.into();
        tracing::debug!(
            target: "network",
            "[{}] Creating new channel for task {:?}",
            self.my_participant_id(),
            task_id
        );
        let channel_id = self.generate_unique_channel_id();
        let start_message = MpcStartMessage {
            task_id,
            participants: participants.clone(),
        };
        let SenderOrNewChannel::NewChannel(channel) =
            self.sender_for(channel_id, Some(&start_message), self.my_participant_id())
        else {
            anyhow::bail!("Channel already exists");
        };
        for participant in &participants {
            if participant == &self.my_participant_id() {
                continue;
            }
            channel.sender.send_raw(
                *participant,
                MpcMessage {
                    channel_id,
                    kind: MpcMessageKind::Start(start_message.clone()),
                },
            )?;
        }
        Ok(channel)
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.transport_sender.my_participant_id()
    }

    pub fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.transport_sender.all_participant_ids()
    }

    /// Returns the participant IDs of all nodes in the network that are currently alive.
    /// This is a subset of all_participant_ids, and includes our own participant ID.
    pub fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
        let mut result = Vec::new();
        for participant in self.all_participant_ids() {
            if participant == self.my_participant_id() {
                continue;
            }
            if self
                .transport_sender
                .connectivity(participant)
                .is_bidirectionally_connected()
            {
                result.push(participant);
            }
        }
        result.push(self.my_participant_id());
        result.sort();
        result
    }

    pub fn select_random_active_participants_including_me(
        &self,
        total: usize,
    ) -> anyhow::Result<Vec<ParticipantId>> {
        let me = self.my_participant_id();
        let participants = self.all_alive_participant_ids();

        if participants.len() < total {
            anyhow::bail!(
                "Not enough active participants: need {}, got {}",
                total,
                participants.len()
            );
        }
        if !participants.contains(&me) {
            anyhow::bail!("There's no `me` in active participants");
        }

        let mut res = participants
            .into_iter()
            .filter(|p| p != &me)
            .choose_multiple(&mut rand::thread_rng(), total - 1);
        res.push(me);
        Ok(res)
    }

    /// Returns once all participants in the network are simultaneously connected to us.
    /// Internally, this calls `wait_for_ready(total_num_participants)` on the underlying
    /// `transport_sender`.
    pub async fn leader_wait_for_all_connected(&self) -> anyhow::Result<()> {
        self.transport_sender
            .wait_for_ready(self.all_participant_ids().len())
            .await
    }

    /// Internal function to either return a new channel or a sender for the existing channel.
    /// A new channel is created only when the Start message is received for the first time.
    /// Otherwise, returns a Sender that'll send to the existing channel, or, if we receive
    /// a message for a task before its Start message, we'll still return a Sender that will
    /// buffer the messages and deliver them to the channel, once a Start message is received.
    fn sender_for(
        &self,
        channel_id: ChannelId,
        start: Option<&MpcStartMessage>,
        originator: ParticipantId,
    ) -> SenderOrNewChannel {
        // INVARIANT: For each key in the `senders` map, exactly one of the following is true:
        //  - It is in the channels_waiting_for_start LruCache.
        //    - This is maintained when we insert an entry into the LruCache, where if an
        //      entry is evicted, we also remove the corresponding entry from the senders map.
        //  - There is a NetworkTaskChannel object alive for this MpcTaskId.
        //    - This is maintained by the drop_fn we give to NetworkTaskChannel, which is called
        //      when the NetworkTaskChannel is destroyed.
        let mut channels = self.channels.lock().unwrap();
        let sender = match channels.senders.entry(channel_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let (sender, receiver) = mpsc::unbounded_channel();
                entry.insert(sender.clone());
                let incomplete_channel = IncompleteNetworkTaskChannel { receiver };
                if let Some((k, _)) = channels
                    .channels_waiting_for_start
                    .push(channel_id, incomplete_channel)
                {
                    // If k != task_id, that means the LruCache evicted some other entry.
                    // That means that other channel never received Start and is old enough,
                    // so we also remove it from the senders map. See the above invariant.
                    if k != channel_id {
                        channels.senders.remove(&k);
                    }
                }
                sender
            }
        };
        if let Some(start) = start {
            // Note: It's possible that the channel is NOT in channels_waiting_for_start:
            //  - It's possible the channel was buffered but the Start message arrived way too late.
            //    In this case, we unfortunately never start the channel, but that is OK.
            //  - It's possible that we received Start message twice. That's erroneous, but we'll
            //    just deliver the second Start message to the channel, where the channel handling
            //    code will fail.
            if let Some(incomplete_channel) = channels.channels_waiting_for_start.pop(&channel_id) {
                drop(channels); // release lock
                let drop_fn = {
                    let channels = self.channels.clone();
                    move || {
                        channels.lock().unwrap().senders.remove(&channel_id);
                    }
                };
                let channel = NetworkTaskChannel {
                    sender: Arc::new(NetworkTaskChannelSender {
                        channel_id,
                        task_id: start.task_id,
                        leader: originator,
                        my_participant_id: self.my_participant_id(),
                        participants: start.participants.clone(),
                        connection_versions: start
                            .participants
                            .iter()
                            .filter(|id| **id != self.my_participant_id())
                            .map(|id| {
                                (
                                    *id,
                                    self.transport_sender.connectivity(*id).connection_version(),
                                )
                            })
                            .collect(),
                        transport_sender: self.transport_sender.clone(),
                    }),
                    successful_participants: HashSet::new(),
                    receiver: incomplete_channel.receiver,
                    drop: Some(Box::new(drop_fn)),
                };
                return SenderOrNewChannel::NewChannel(channel);
            }
        }
        SenderOrNewChannel::Sender(sender)
    }

    /// Emit network metrics through Prometheus counters
    pub fn emit_metrics(&self) {
        let my_participant_id = self.my_participant_id();
        metrics::NETWORK_LIVE_CONNECTIONS.reset();

        for id in self.all_participant_ids() {
            let metric = metrics::NETWORK_LIVE_CONNECTIONS
                .with_label_values(&[&my_participant_id.to_string(), &id.to_string()]);
            if id == my_participant_id {
                metric.set(1);
            } else {
                let is_live_participant = self
                    .transport_sender
                    .connectivity(id)
                    .is_bidirectionally_connected();
                metric.set(is_live_participant.into());
            }
        }
    }

    // TODO(#226): Use.
    #[allow(dead_code)]
    pub fn update_indexer_height(&self, height: u64) {
        self.indexer_heights
            .set_height(self.my_participant_id(), height);
        self.transport_sender
            .send_indexer_height(IndexerHeightMessage { height });
    }

    // TODO(#226): Use.
    #[allow(dead_code)]
    pub fn get_indexer_heights(&self) -> HashMap<ParticipantId, u64> {
        self.indexer_heights.get_heights()
    }
}

struct IncompleteNetworkTaskChannel {
    receiver: tokio::sync::mpsc::UnboundedReceiver<MpcPeerMessage>,
}

enum SenderOrNewChannel {
    Sender(mpsc::UnboundedSender<MpcPeerMessage>),
    NewChannel(NetworkTaskChannel),
}

/// Runs the loop of receiving messages from the transport and dispatching them to the
/// appropriate MPC task channels. Any new MPC tasks that are triggered due to receiving
/// a message for an unknown MPC task would be notified via `new_channel_sender`.
async fn run_receive_messages_loop(
    client: Arc<MeshNetworkClient>,
    mut receiver: Box<dyn MeshNetworkTransportReceiver>,
    new_channel_sender: mpsc::UnboundedSender<NetworkTaskChannel>,
    indexer_heights: Arc<IndexerHeightTracker>,
) -> anyhow::Result<()> {
    loop {
        let message = receiver.receive().await?;
        match message {
            PeerMessage::Mpc(message) => {
                let channel_id = message.message.channel_id;
                let start_msg = match &message.message.kind {
                    MpcMessageKind::Start(start_msg) => Some(start_msg),
                    _ => None,
                };
                match client.sender_for(channel_id, start_msg, message.from) {
                    SenderOrNewChannel::Sender(sender) => {
                        sender.send(message)?;
                    }
                    SenderOrNewChannel::NewChannel(channel) => {
                        new_channel_sender.send(channel)?;
                    }
                }
            }
            PeerMessage::IndexerHeight(message) => {
                indexer_heights.set_height(message.from, message.message.height);
            }
        }
    }
}

/// The main entry point for the networking layer. Spawns a tokio task that runs the message
/// receiving loop, and returns a client that can be used to create new MPC tasks, as well as a
/// receiver for triggering new MPC tasks that the node should passively participate in.
pub fn run_network_client(
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    transport_receiver: Box<dyn MeshNetworkTransportReceiver>,
) -> (
    Arc<MeshNetworkClient>,
    mpsc::UnboundedReceiver<NetworkTaskChannel>,
    AutoAbortTask<()>,
) {
    let indexer_heights = Arc::new(IndexerHeightTracker::new(
        &transport_sender.all_participant_ids(),
    ));
    let client = Arc::new(MeshNetworkClient::new(
        transport_sender,
        Arc::new(Mutex::new(NetworkTaskChannelManager::new())),
        indexer_heights.clone(),
    ));
    let (new_channel_sender, new_channel_receiver) = mpsc::unbounded_channel();
    let handle = tracking::spawn_checked(
        "Network receive message loop",
        run_receive_messages_loop(
            client.clone(),
            transport_receiver,
            new_channel_sender,
            indexer_heights,
        ),
    );
    (client, new_channel_receiver, handle)
}

/// Channel for a specific MPC task that allows sending and receiving messages in order to compute
/// the MPC task. There is one such object for each MPC task.
///
/// If the MPC task times out or aborts for any reason, this object must be dropped to ensure
/// proper cleanup of the associated resources.
pub struct NetworkTaskChannel {
    sender: Arc<NetworkTaskChannelSender>,
    /// Used for calling receive(&mut self).
    receiver: tokio::sync::mpsc::UnboundedReceiver<MpcPeerMessage>,
    /// The set of participants who sent us a Success message; for leader only.
    successful_participants: HashSet<ParticipantId>,
    /// Function to clean up relevant data structures in the network transport implementation.
    drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

/// A subset of the NetworkTaskChannel that doesn't include the mutable parts.
pub struct NetworkTaskChannelSender {
    /// Unique channel ID across participants.
    /// It is needed as `task_id` might not be globally unique.
    channel_id: ChannelId,
    /// The task ID associated with the computation.
    task_id: MpcTaskId,
    /// The leader of the computation; there is exactly one leader for each computation.
    leader: ParticipantId,
    /// The participant ID of our node.
    my_participant_id: ParticipantId,
    /// The participant IDs of all participants in the computation, including our own.
    participants: Vec<ParticipantId>,
    /// The version of the connection we have with each other participant.
    /// This is used to detect dropped connections. See ConnectionVersion for details.
    connection_versions: HashMap<ParticipantId, ConnectionVersion>,
    /// The underlying transport layer.
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
}

/// A computation data message received from a participant.
pub struct TaskChannelComputationData {
    pub from: ParticipantId,
    pub data: Vec<Vec<u8>>,
}

impl Drop for NetworkTaskChannel {
    fn drop(&mut self) {
        if let Some(drop) = self.drop.take() {
            drop();
        }
    }
}

impl NetworkTaskChannelSender {
    /// Sends a raw MpcMessage to the participant over the network.
    /// It fails if the connection is not established to the participant, or if the connection is
    /// a different one from the original when the channel was created.
    fn send_raw(&self, recipient_id: ParticipantId, message: MpcMessage) -> anyhow::Result<()> {
        self.transport_sender.send(
            recipient_id,
            message,
            self.connection_versions
                .get(&recipient_id)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("No connection version for recipient"))?,
        )?;
        Ok(())
    }

    /// Sends a message to another participant in the MPC task.
    /// Returns an error only if there is something seriously wrong with the networking layer so
    /// that there's no meaningful way for the MPC task to proceed.
    ///
    /// This does not guarantee that the message will be received by the recipient. However, it
    /// does guarantee that any messages sent via this channel would be received in the same order,
    /// if they would be received at all. This implies that the underlying persistent connection is
    /// reset, future sends will fail as we cannot ensure that previous messages were received.
    ///
    /// The implementation of this function will guarantee that all messages sent are encrypted,
    /// i.e. can only be decrypted by the recipient.
    pub fn send(&self, recipient_id: ParticipantId, data: Vec<Vec<u8>>) -> anyhow::Result<()> {
        self.send_raw(
            recipient_id,
            MpcMessage {
                channel_id: self.channel_id,
                kind: MpcMessageKind::Computation(data),
            },
        )
    }

    pub fn is_leader(&self) -> bool {
        self.my_participant_id == self.leader
    }

    pub fn get_leader(&self) -> ParticipantId {
        self.leader
    }

    /// Waits for each participant involved in this task to be bidirectionally connected to us
    /// at least once. This way, the connection version for each participant is properly established
    /// and when we send messages to any participant we can rely on that connection version.
    /// It is possible after this that some participant is no longer connected to us (with the
    /// original connection), in which case the sending would then fail (due to outdated connection
    /// version) immediately.
    ///
    /// This should be called at the beginning of the computation if:
    ///  - This is a leader-centric computation, and we are a follower.
    ///    (Rationale: the leader already determined that the participants are online. We wait
    ///    for connections because even though the leader has connected to everyone, it is
    ///    possible we have yet to establish connections to everyone. We assume that if the
    ///    leader can connect to two nodes B and C, then B and C can also connect to each other.
    ///    If it happens that a node is actually unavailable, then the leader would realize that
    ///    too, and abort the computation.)
    ///
    /// This should NOT be called if:
    ///  - We are the leader. This is redundant because the leader already queried the alive
    ///    participants when making the choice of participants to use in the computation. And in
    ///    fact, if we have the leader also call this, then the leader may get stuck waiting
    ///    forever (and having to rely on timeouts), because just because a participant was alive
    ///    when the leader determines the participant list, doesn't mean that the participant is
    ///    still alive by the time the computation is started. By not calling this at the leader,
    ///    if a participant is disconnected, the leader will be able to abort when carrying out the
    ///    computation.
    async fn initialize_all_participants_connections(&self) -> anyhow::Result<()> {
        for &participant in &self.participants {
            if participant == self.my_participant_id {
                continue;
            }
            tracking::set_progress(&format!("Waiting for connection to {}", participant));
            self.transport_sender
                .connectivity(participant)
                .wait_for_connection(self.connection_versions[&participant])
                .await?;
        }
        tracking::set_progress("All participants connected");
        Ok(())
    }

    /// Communicates the success result to the leader of the computation.
    fn communicate_success(&self) -> anyhow::Result<()> {
        if self.is_leader() {
            anyhow::bail!("Only followers can communicate success");
        }
        self.send_raw(
            self.leader,
            MpcMessage {
                channel_id: self.channel_id,
                kind: MpcMessageKind::Success,
            },
        )?;
        Ok(())
    }

    /// Sends an Abort message to other parties in the computation. For leader, this is
    /// communicated to all followers; for a follower, this is communicated only to the leader.
    fn communicate_failure(&self, err: &anyhow::Error) {
        let err_msg = err.to_string();
        if self.is_leader() {
            for participant in &self.participants {
                if participant == &self.my_participant_id {
                    continue;
                }

                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Sending Abort message to participant {}",
                    self.my_participant_id,
                    self.task_id,
                    participant
                );
                // Don't fail just because we cannot send an abort message.
                let _ = self.send_raw(
                    *participant,
                    MpcMessage {
                        channel_id: self.channel_id,
                        kind: MpcMessageKind::Abort(err_msg.clone()),
                    },
                );
            }
        } else {
            tracing::debug!(
                target: "network",
                "[{}] [Task {:?}] Sending Abort message to leader {}",
                self.my_participant_id,
                self.task_id,
                self.leader
            );
            // Don't fail just because we cannot send an abort message.
            let _ = self.send_raw(
                self.leader,
                MpcMessage {
                    channel_id: self.channel_id,
                    kind: MpcMessageKind::Abort(err_msg),
                },
            );
        }
    }
}

impl NetworkTaskChannel {
    /// Returns a sender to be used to send a message to another participant in the MPC task.
    pub fn sender(&self) -> Arc<NetworkTaskChannelSender> {
        self.sender.clone()
    }

    pub fn task_id(&self) -> MpcTaskId {
        self.sender.task_id
    }

    pub fn participants(&self) -> &[ParticipantId] {
        &self.sender.participants
    }

    pub fn my_participant_id(&self) -> ParticipantId {
        self.sender.my_participant_id
    }

    /// Receives a single MPC message from any participant from the network, without processing it.
    /// This will return error early if any connection is broken.
    async fn receive_raw(&mut self) -> anyhow::Result<MpcPeerMessage> {
        let received = loop {
            let timer = tokio::time::sleep(Duration::from_secs(1));

            tokio::select! {
                _ = timer => {
                    if self.sender.connection_versions.iter().any(|(id, version)| {
                        self.sender.transport_sender.connectivity(*id).was_connection_interrupted(*version)
                    }) {
                        anyhow::bail!("Computation cannot succeed as not all participants are alive anymore");
                    }
                }
                received = self.receiver.recv() => {
                    let Some(received) = received else {
                        anyhow::bail!("Channel closed");
                    };
                    break received;
                }
            }
        };

        tracing::debug!(
            target: "network",
            "[{}] [Task {:?}] Received message: {:?}",
            self.sender.my_participant_id, self.sender.task_id, received
        );
        Ok(received)
    }

    /// Receives one message from the network and process it; that message may or may not be a
    /// computation message.
    async fn receive_one(&mut self) -> anyhow::Result<Option<TaskChannelComputationData>> {
        let message = self.receive_raw().await?;
        match message.message.kind {
            MpcMessageKind::Computation(data) => {
                return Ok(Some(TaskChannelComputationData {
                    from: message.from,
                    data,
                }))
            }
            MpcMessageKind::Abort(err) => {
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Received abort from participant {}: {}",
                    self.sender.my_participant_id,
                    self.sender.task_id,
                    message.from,
                    err
                );
                if self.sender.is_leader() {
                    anyhow::bail!("Aborted by participant {}: {}", message.from, err);
                } else {
                    anyhow::bail!("Aborted by leader: {}", err);
                }
            }
            MpcMessageKind::Success => {
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Received success from participant {}",
                    self.sender.my_participant_id,
                    self.sender.task_id,
                    message.from
                );
                if self.sender.is_leader() {
                    self.successful_participants.insert(message.from);
                } else {
                    anyhow::bail!("Received unexpected Success message when we are not the leader");
                }
            }
            MpcMessageKind::Start(mpc_start_message) => {
                // `Self` was created upon receiving `MpcMessageKind::Start`, further we don't expect
                // any `Start` messages.
                anyhow::bail!("Unexpected Start message: {:?}", mpc_start_message);
            }
        }
        Ok(None)
    }

    /// Receives a computation message from another participant.
    /// Blocks until a message is received, but will return early if:
    ///   - Any connection to any participant is broken.
    ///   - The computation is aborted by a follower (if we're the leader) or the leader
    ///     (if we're a follower).
    pub async fn receive(&mut self) -> anyhow::Result<TaskChannelComputationData> {
        loop {
            if let Some(data) = self.receive_one().await? {
                return Ok(data);
            }
        }
    }

    /// The leader may call this to wait for all followers to succeed.
    /// This will return error if any connection is broken, or if any follower ends up
    /// sending the leader an Abort message instead.
    async fn wait_for_followers_to_succeed(&mut self) -> anyhow::Result<()> {
        if !self.sender.is_leader() {
            anyhow::bail!("Only the leader can wait for others to succeed");
        }
        while self.successful_participants.len() < self.sender.participants.len() - 1 {
            tracking::set_progress(&format!(
                "Waiting for followers to succeed: {} out of {}",
                self.successful_participants.len(),
                self.sender.participants.len() - 1
            ));
            let _ = self.receive_one().await?;
        }
        tracking::set_progress("All followers succeeded");
        Ok(())
    }
}

#[cfg(test)]
pub mod testing {
    use super::conn::{ConnectionVersion, NodeConnectivityInterface};
    use super::MeshNetworkTransportSender;
    use crate::primitives::{MpcPeerMessage, ParticipantId, PeerMessage};
    use crate::tracking;
    use std::collections::HashMap;
    use std::sync::Arc;

    pub struct TestMeshTransport {
        participant_ids: Vec<ParticipantId>,
        senders: HashMap<ParticipantId, tokio::sync::mpsc::UnboundedSender<PeerMessage>>,
    }

    pub struct TestMeshTransportSender {
        transport: Arc<TestMeshTransport>,
        my_participant_id: ParticipantId,
    }

    pub struct TestMeshTransportReceiver {
        receiver: tokio::sync::mpsc::UnboundedReceiver<PeerMessage>,
    }

    pub struct TestConnectivityInterface;

    #[async_trait::async_trait]
    impl NodeConnectivityInterface for TestConnectivityInterface {
        fn is_bidirectionally_connected(&self) -> bool {
            true
        }

        async fn wait_for_connection(
            &self,
            _connection_version: ConnectionVersion,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn was_connection_interrupted(&self, _connection_version: ConnectionVersion) -> bool {
            false
        }

        fn connection_version(&self) -> ConnectionVersion {
            ConnectionVersion::default()
        }
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportSender for TestMeshTransportSender {
        fn my_participant_id(&self) -> ParticipantId {
            self.my_participant_id
        }

        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            self.transport.participant_ids.clone()
        }

        fn connectivity(
            &self,
            _participant_id: ParticipantId,
        ) -> Arc<dyn NodeConnectivityInterface> {
            Arc::new(TestConnectivityInterface)
        }

        fn send(
            &self,
            recipient_id: ParticipantId,
            message: crate::primitives::MpcMessage,
            _connection_version: ConnectionVersion,
        ) -> anyhow::Result<()> {
            self.transport
                .senders
                .get(&recipient_id)
                .ok_or_else(|| anyhow::anyhow!("Unknown recipient"))?
                .send(PeerMessage::Mpc(MpcPeerMessage {
                    from: self.my_participant_id,
                    message,
                }))?;
            Ok(())
        }

        fn send_indexer_height(&self, _height: crate::primitives::IndexerHeightMessage) {
            // TODO(#226): Test this.
        }

        async fn wait_for_ready(&self, _threshold: usize) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl super::MeshNetworkTransportReceiver for TestMeshTransportReceiver {
        async fn receive(&mut self) -> anyhow::Result<PeerMessage> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Channel closed"))
        }
    }

    pub fn new_test_transports(
        participants: Vec<ParticipantId>,
    ) -> Vec<(Arc<TestMeshTransportSender>, Box<TestMeshTransportReceiver>)> {
        let mut sender_by_participant_id = HashMap::new();
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for participant_id in &participants {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            sender_by_participant_id.insert(*participant_id, sender.clone());
            senders.push(sender);
            receivers.push(receiver);
        }

        let transport = Arc::new(TestMeshTransport {
            participant_ids: participants.clone(),
            senders: sender_by_participant_id,
        });

        let mut transports = Vec::new();
        for (i, receiver) in receivers.into_iter().enumerate() {
            let participant_id = participants[i];
            let transport = transport.clone();
            let sender = Arc::new(TestMeshTransportSender {
                transport,
                my_participant_id: participant_id,
            });
            let receiver = Box::new(TestMeshTransportReceiver { receiver });
            transports.push((sender, receiver));
        }

        transports
    }

    pub async fn run_test_clients<T: 'static + Send, F, FR>(
        participants: Vec<ParticipantId>,
        client_runner: F,
    ) -> anyhow::Result<Vec<T>>
    where
        F: Fn(
            Arc<super::MeshNetworkClient>,
            tokio::sync::mpsc::UnboundedReceiver<super::NetworkTaskChannel>,
        ) -> FR,
        FR: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let transports = new_test_transports(participants.clone());
        let join_handles = transports
            .into_iter()
            .enumerate()
            .map(|(i, (sender, receiver))| {
                let (client, new_channel_receiver, task) =
                    super::run_network_client(sender, receiver);
                let client_runner_future = client_runner(client, new_channel_receiver);
                tracking::spawn(&format!("client {}", i), async move {
                    let _task = task;
                    client_runner_future.await
                })
            })
            .collect::<Vec<_>>();
        futures::future::join_all(join_handles)
            .await
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::computation::MpcLeaderCentricComputation;
    use super::{MeshNetworkClient, NetworkTaskChannel};
    use crate::network::testing::run_test_clients;
    use crate::primitives::{MpcTaskId, UniqueId};
    use crate::providers::EcdsaTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use crate::tracking::{self, AutoAbortTaskCollection};
    use borsh::{BorshDeserialize, BorshSerialize};
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Just some big prime number
    static MOD: u64 = 1_000_000_007;

    #[tokio::test]
    async fn test_network_basic() {
        start_root_task_with_periodic_dump(async move {
            run_test_clients(TestGenerators::new(4, 3).participant_ids(), run_test_client)
                .await
                .unwrap();
        })
        .await;
    }

    async fn run_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        let _passive_handle = tracking::spawn("monitor passive channels", async move {
            let mut tasks = AutoAbortTaskCollection::new();
            loop {
                let Some(channel) = channel_receiver.recv().await else {
                    break;
                };
                tasks.spawn_checked(
                    &format!("passive task {:?}", channel.task_id()),
                    TaskFollower.perform_leader_centric_computation(
                        channel,
                        std::time::Duration::from_secs(10),
                    ),
                );
            }
        });

        let participant_id = client.my_participant_id();
        let other_participant_ids = client
            .all_participant_ids()
            .into_iter()
            .filter(|id| id != &participant_id)
            .collect::<Vec<_>>();

        let mut handles = Vec::new();
        let mut expected_results = Vec::new();
        for seed in 0..5 {
            let channel = client.new_channel_for_task(
                EcdsaTaskId::ManyTriples {
                    start: UniqueId::new(participant_id, seed, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?;
            handles.push(tracking::spawn(
                &format!("task {}", seed),
                TaskLeader { seed }.perform_leader_centric_computation(
                    channel,
                    std::time::Duration::from_secs(10),
                ),
            ));

            let expected_total: u64 = other_participant_ids
                .iter()
                .map(|id| {
                    let input = id.raw() as u64 + seed;
                    (input * input) % MOD
                })
                .sum();
            expected_results.push(expected_total);
        }
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await??);
        }
        println!("Results: {:?}", results);
        assert_eq!(results, expected_results);

        Ok(())
    }

    struct TaskLeader {
        seed: u64,
    }

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<u64> for TaskLeader {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<u64> {
            for other_participant_id in channel.participants() {
                if other_participant_id == &channel.my_participant_id() {
                    continue;
                }
                channel.sender().send(
                    *other_participant_id,
                    vec![borsh::to_vec(&TestTripleMessage {
                        data: other_participant_id.raw() as u64 + self.seed,
                    })
                    .unwrap()],
                )?;
            }
            let mut total = 0;
            let mut heard_from = HashSet::new();
            for _ in 1..channel.participants().len() {
                let msg = channel.receive().await?;
                assert!(heard_from.insert(msg.from));
                let inner: TestTripleMessage = borsh::from_slice(&msg.data[0])?;
                total += inner.data;
            }
            Ok(total)
        }

        fn leader_waits_for_success(&self) -> bool {
            true
        }
    }

    struct TaskFollower;

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<()> for TaskFollower {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
            match channel.task_id() {
                MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples { .. }) => {
                    let msg = channel.receive().await?;
                    let inner: TestTripleMessage = borsh::from_slice(&msg.data[0])?;
                    channel.sender().send(
                        msg.from,
                        vec![borsh::to_vec(&TestTripleMessage {
                            data: (inner.data * inner.data) % MOD,
                        })
                        .unwrap()],
                    )?;
                }
                _ => unreachable!(),
            }
            Ok(())
        }

        fn leader_waits_for_success(&self) -> bool {
            true
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct TestTripleMessage {
        data: u64,
    }
}

#[cfg(test)]
mod fault_handling_tests {
    use super::computation::MpcLeaderCentricComputation;
    use super::{MeshNetworkClient, NetworkTaskChannel};
    use crate::network::testing::run_test_clients;
    use crate::primitives::{ParticipantId, UniqueId};
    use crate::providers::EcdsaTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use near_o11y::testonly::init_integration_logger;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_network_fault_handling() {
        init_integration_logger();
        let test_cases = vec![
            FaultTestCase::NoFault,
            FaultTestCase::Crash(ParticipantId::from_raw(0)),
            FaultTestCase::Crash(ParticipantId::from_raw(2)),
            FaultTestCase::Slow(ParticipantId::from_raw(0), CancellationToken::new()),
            FaultTestCase::Slow(ParticipantId::from_raw(3), CancellationToken::new()),
            FaultTestCase::SlowNoWaitSuccess(ParticipantId::from_raw(1), CancellationToken::new()),
            FaultTestCase::Timeout(ParticipantId::from_raw(0)),
            FaultTestCase::Timeout(ParticipantId::from_raw(3)),
            FaultTestCase::AllTimeout,
        ];
        for test_case in test_cases {
            tracing::info!("Running test case: {:?}", test_case);
            let test_case = Arc::new(test_case);
            start_root_task_with_periodic_dump(async move {
                run_test_clients(
                    TestGenerators::new_contiguous_participant_ids(4, 3).participant_ids(),
                    move |client, channel_receiver| {
                        let test_case = test_case.clone();
                        async move {
                            run_fault_handling_test_client(client, channel_receiver, test_case)
                                .await
                        }
                    },
                )
                .await
                .unwrap();
            })
            .await;
        }
    }

    #[derive(Debug)]
    enum FaultTestCase {
        /// All parties succeed.
        NoFault,
        /// One party crashes.
        Crash(ParticipantId),
        /// One party is slow in the computation.
        Slow(ParticipantId, CancellationToken),
        /// One party is slow, but the leader does not wait for successes.
        SlowNoWaitSuccess(ParticipantId, CancellationToken),
        /// One party times out before the others (contrived case).
        Timeout(ParticipantId),
        /// All parties time out at the same time.
        AllTimeout,
    }

    async fn run_fault_handling_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        test_case: Arc<FaultTestCase>,
    ) -> anyhow::Result<()> {
        let me = client.my_participant_id();

        let is_leader = client.my_participant_id().raw() == 0;
        let channel = if is_leader {
            client.new_channel_for_task(
                EcdsaTaskId::ManyTriples {
                    start: UniqueId::new(me, 0, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?
        } else {
            channel_receiver.recv().await.unwrap()
        };

        let timeout = match test_case.as_ref() {
            FaultTestCase::Timeout(participant_id) if me == *participant_id => {
                std::time::Duration::from_secs(1)
            }
            FaultTestCase::AllTimeout => std::time::Duration::from_secs(1),
            _ => std::time::Duration::from_secs(10),
        };
        let result = Task {
            test_case: test_case.clone(),
        }
        .perform_leader_centric_computation(channel, timeout)
        .await;

        match test_case.as_ref() {
            FaultTestCase::NoFault => {
                assert!(result.is_ok());
            }
            FaultTestCase::Crash(participant_id) => {
                assert!(result.is_err());
                let err_string = result.as_ref().unwrap_err().to_string();
                assert!(err_string.contains("Crashed"), "{}", err_string);
                if participant_id == &client.my_participant_id() {
                } else if me.raw() == 0 {
                    assert!(
                        err_string.contains(&format!("Aborted by participant {}", participant_id)),
                        "{}",
                        err_string
                    );
                } else {
                    assert!(err_string.contains("Aborted by leader"), "{}", err_string);
                }
            }
            FaultTestCase::Slow(participant_id, cancellation_token) => {
                assert!(result.is_ok());
                if is_leader || *participant_id == client.my_participant_id() {
                    assert!(cancellation_token.is_cancelled());
                } else {
                    assert!(!cancellation_token.is_cancelled());
                }
            }
            FaultTestCase::SlowNoWaitSuccess(participant_id, cancellation_token) => {
                assert!(result.is_ok());
                if *participant_id == client.my_participant_id() {
                    assert!(cancellation_token.is_cancelled());
                } else {
                    assert!(!cancellation_token.is_cancelled());
                }
            }
            FaultTestCase::Timeout(participant_id) => {
                assert!(result.is_err());
                let err_string = result.as_ref().unwrap_err().to_string();
                assert!(err_string.contains("Timeout"), "{}", err_string);
                if participant_id == &client.my_participant_id() {
                } else if me.raw() == 0 {
                    assert!(
                        err_string.contains(&format!("Aborted by participant {}", participant_id)),
                        "{}",
                        err_string
                    );
                } else {
                    assert!(err_string.contains("Aborted by leader"), "{}", err_string);
                }
            }
            FaultTestCase::AllTimeout => {
                assert!(result.is_err());
                let err_string = result.as_ref().unwrap_err().to_string();
                assert!(err_string.contains("Timeout"), "{}", err_string);
            }
        }
        Ok(())
    }

    async fn send_recv_all(channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let participants = channel.participants();
        for participant in participants {
            if participant == &channel.my_participant_id() {
                continue;
            }
            channel.sender().send(*participant, vec![vec![]])?;
        }
        for _ in 1..participants.len() {
            channel.receive().await?;
        }
        Ok(())
    }

    struct Task {
        test_case: Arc<FaultTestCase>,
    }

    #[async_trait::async_trait]
    impl MpcLeaderCentricComputation<()> for Task {
        async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
            match self.test_case.as_ref() {
                FaultTestCase::NoFault => {
                    send_recv_all(channel).await?;
                }
                FaultTestCase::Crash(participant_id) => {
                    if channel.my_participant_id() == *participant_id {
                        anyhow::bail!("Crashed");
                    } else {
                        send_recv_all(channel).await?;
                    }
                }
                FaultTestCase::Slow(participant_id, cancellation_token)
                | FaultTestCase::SlowNoWaitSuccess(participant_id, cancellation_token) => {
                    send_recv_all(channel).await?;
                    if channel.my_participant_id() == *participant_id {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        cancellation_token.cancel();
                    }
                }
                FaultTestCase::Timeout(participant_id) => {
                    if channel.my_participant_id() == *participant_id {
                        // This will timeout (the timeout is set at 1 sec).
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        // Shouldn't be reached.
                        send_recv_all(channel).await?;
                    } else {
                        send_recv_all(channel).await?;
                    }
                }
                FaultTestCase::AllTimeout => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                }
            }
            Ok(())
        }

        fn leader_waits_for_success(&self) -> bool {
            !matches!(
                self.test_case.as_ref(),
                FaultTestCase::SlowNoWaitSuccess(_, _)
            )
        }
    }
}
