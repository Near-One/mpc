pub mod conn;
pub mod constants;
pub mod handshake;
pub mod indexer_heights;

use crate::metrics;
use crate::primitives::{
    IndexerHeightMessage, MpcMessage, MpcMessageKind, MpcPeerMessage, MpcStartMessage, MpcTaskId,
    ParticipantId, PeerMessage,
};
use crate::tracking::{self, AutoAbortTask};
use conn::{ConnectionVersion, NodeConnectivityInterface};
use futures::future::BoxFuture;
use indexer_heights::IndexerHeightTracker;
use lru::LruCache;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
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
}

struct NetworkTaskChannelManager {
    senders: HashMap<MpcTaskId, mpsc::UnboundedSender<MpcPeerMessage>>,
    channels_waiting_for_start: LruCache<MpcTaskId, IncompleteNetworkTaskChannel>,
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
    /// Primary functionality for the MeshNetworkClient: returns a channel for the given
    /// new MPC task. It is expected that the caller is the leader of this MPC task, and that the
    /// way the MPC task IDs are assigned ensures that no two participants would initiate
    /// tasks with the same MPC task ID.
    pub fn new_channel_for_task(
        &self,
        task_id: MpcTaskId,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannelWrapper> {
        tracing::debug!(
            target: "network",
            "[{}] Creating new channel for task {:?}",
            self.my_participant_id(),
            task_id
        );
        let start_message = MpcStartMessage {
            participants: participants.clone(),
        };
        let SenderOrNewChannel::NewChannel(channel) =
            self.sender_for(task_id, Some(&start_message), self.my_participant_id())
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
                    task_id,
                    kind: MpcMessageKind::Start(start_message.clone()),
                },
            )?;
        }
        Ok(NetworkTaskChannelWrapper(channel))
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

    /// Internal function shared between new_channel_for_task and MeshNetworkClientDriver::run.
    /// Returns an existing sender for the MPC task, or creates a new one if it doesn't exist.
    /// This is used to determine whether an incoming network message belongs to an existing
    /// MPC task, or if it should trigger the creation of a new MPC task that this node passively
    /// participates in.
    fn sender_for(
        &self,
        task_id: MpcTaskId,
        start: Option<&MpcStartMessage>,
        originator: ParticipantId,
    ) -> SenderOrNewChannel {
        let drop_fn = {
            let channels = self.channels.clone();
            move || {
                channels.lock().unwrap().senders.remove(&task_id);
            }
        };
        let mut channels = self.channels.lock().unwrap();
        let sender = match channels.senders.entry(task_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let (sender, receiver) = mpsc::unbounded_channel();
                entry.insert(sender.clone());
                let incomplete_channel = IncompleteNetworkTaskChannel { receiver };
                if let Some((k, _)) = channels
                    .channels_waiting_for_start
                    .push(task_id, incomplete_channel)
                {
                    if k != task_id {
                        // Keep channels_waiting_for_start a subset of senders.
                        channels.senders.remove(&k);
                    }
                }
                sender
            }
        };
        if let Some(start) = start {
            if let Some(incomplete_channel) = channels.channels_waiting_for_start.pop(&task_id) {
                drop(channels); // release lock
                let channel = NetworkTaskChannel {
                    sender: Arc::new(NetworkTaskChannelSender {
                        task_id,
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
            if id == my_participant_id {
                continue;
            }
            let is_live_participant = self
                .transport_sender
                .connectivity(id)
                .is_bidirectionally_connected();
            metrics::NETWORK_LIVE_CONNECTIONS
                .with_label_values(&[&my_participant_id.to_string(), &id.to_string()])
                .set(is_live_participant.into());
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
    new_channel_sender: mpsc::UnboundedSender<NetworkTaskChannelWrapper>,
    indexer_heights: Arc<IndexerHeightTracker>,
) -> anyhow::Result<()> {
    loop {
        let message = receiver.receive().await?;
        match message {
            PeerMessage::Mpc(message) => {
                let task_id = message.message.task_id;
                let start_msg = match &message.message.kind {
                    MpcMessageKind::Start(start_msg) => Some(start_msg),
                    _ => None,
                };
                match client.sender_for(task_id, start_msg, message.from) {
                    SenderOrNewChannel::Sender(sender) => {
                        sender.send(message)?;
                    }
                    SenderOrNewChannel::NewChannel(channel) => {
                        new_channel_sender.send(NetworkTaskChannelWrapper(channel))?;
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
    mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
    AutoAbortTask<()>,
) {
    let indexer_heights = Arc::new(IndexerHeightTracker::new(
        &transport_sender.all_participant_ids(),
    ));
    let client = Arc::new(MeshNetworkClient {
        transport_sender,
        channels: Arc::new(Mutex::new(NetworkTaskChannelManager::new())),
        indexer_heights: indexer_heights.clone(),
    });
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

/// A wrapper around NetworkTaskChannel,
pub struct NetworkTaskChannelWrapper(NetworkTaskChannel);

impl Deref for NetworkTaskChannelWrapper {
    type Target = NetworkTaskChannel;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
                task_id: self.task_id,
                kind: MpcMessageKind::Computation(data),
            },
        )
    }

    pub fn is_leader(&self) -> bool {
        self.my_participant_id == self.leader
    }

    /// Waits for all participants involved in this task to be bidirectionally connected to us.
    /// This should be called at the beginning of the computation if:
    ///  - This is a leader-centric computation, and we are a follower.
    ///    (Rationale: the leader already determined that the participants are online. We wait
    ///     for connections because even though the leader has connected to everyone, it is
    ///     possible we have yet to establish connections to everyone. We assume that if the
    ///     leader can connect to two nodes B and C, then B and C can also connect to each other.)
    ///
    /// This should NOT be called if:
    ///  - We are the leader. This is redundant because the leader already queried the alive
    ///    participants when making the choice of participants to use in the computation.
    async fn wait_for_all_participants_connected(&self) -> anyhow::Result<()> {
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

    /// This is called at the end of a leader-centric computation to communicate the result to
    /// other parties. For leaders, only failures are communicated to followers; for followers,
    /// failures are communicated to the leader, and if leader waits for success, also
    /// communicate successes to the leader.
    fn communicate_result<T>(
        &self,
        result: &anyhow::Result<T>,
        leader_waits_for_success: bool,
    ) -> anyhow::Result<()> {
        match result {
            Ok(_) => {
                if !self.is_leader() && leader_waits_for_success {
                    tracing::debug!(
                        target: "network",
                        "[{}] [Task {:?}] Sending Success message to leader {}",
                        self.my_participant_id,
                        self.task_id,
                        self.leader
                    );
                    self.send_raw(
                        self.leader,
                        MpcMessage {
                            task_id: self.task_id,
                            kind: MpcMessageKind::Success,
                        },
                    )?;
                }
            }
            Err(err) => {
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
                                task_id: self.task_id,
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
                            task_id: self.task_id,
                            kind: MpcMessageKind::Abort(err_msg),
                        },
                    );
                }
            }
        }
        Ok(())
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
                    anyhow::bail!("Unexpected Success message from leader");
                }
            }
            MpcMessageKind::Start(mpc_start_message) => {
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

impl NetworkTaskChannelWrapper {
    /// Perform the given computation in a leader-centric way:
    ///  - If any follower's computation returns error, it automatically sends an Abort message to
    ///    the leader, causing the leader to fail as well.
    ///  - If the leader's computation returns error, it automatically sends an Abort message to
    ///    all followers, causing their computation to fail as well.
    ///
    /// If leader_waits_for_success is true, then additionally:
    ///  - Followers who succeed send a Success message to the leader.
    ///  - The leader will wait for all Success messages before returning.
    pub async fn perform_leader_centric_computation<R: Send + 'static>(
        self,
        leader_waits_for_success: bool,
        f: impl for<'a> FnOnce(&'a mut NetworkTaskChannel) -> BoxFuture<'a, anyhow::Result<R>>
            + Send
            + 'static,
    ) -> anyhow::Result<R> {
        let mut channel = self.0;
        let sender = channel.sender();
        if !sender.is_leader() {
            sender.wait_for_all_participants_connected().await?;
        }
        let result = f(&mut channel).await;
        let result = match result {
            Ok(result) => result,
            err @ Err(_) => {
                sender.communicate_result(&err, leader_waits_for_success)?;
                return err;
            }
        };
        if leader_waits_for_success && sender.is_leader() {
            if let err @ Err(_) = channel.wait_for_followers_to_succeed().await {
                sender.communicate_result(&err, leader_waits_for_success)?;
                err?;
            }
        }
        sender.communicate_result(&Ok(()), leader_waits_for_success)?;
        tracking::set_progress("Computation complete");
        Ok(result)
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
            tokio::sync::mpsc::UnboundedReceiver<super::NetworkTaskChannelWrapper>,
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
    use super::{MeshNetworkClient, NetworkTaskChannel, NetworkTaskChannelWrapper};
    use crate::assets::UniqueId;
    use crate::network::testing::run_test_clients;
    use crate::primitives::MpcTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use crate::tracking::{self, AutoAbortTaskCollection};
    use borsh::{BorshDeserialize, BorshSerialize};
    use futures::FutureExt;
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
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
    ) -> anyhow::Result<()> {
        let _passive_handle = tracking::spawn("monitor passive channels", async move {
            let mut tasks = AutoAbortTaskCollection::new();
            loop {
                let Some(channel) = channel_receiver.recv().await else {
                    break;
                };
                tasks.spawn_checked(
                    &format!("passive task {:?}", channel.task_id()),
                    channel.perform_leader_centric_computation(true, move |channel| {
                        task_follower(channel).boxed()
                    }),
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
                MpcTaskId::ManyTriples {
                    start: UniqueId::new(participant_id, seed, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?;
            handles.push(tracking::spawn(
                &format!("task {}", seed),
                channel.perform_leader_centric_computation(true, move |channel| {
                    task_leader(channel, seed).boxed()
                }),
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

    async fn task_leader(channel: &mut NetworkTaskChannel, seed: u64) -> anyhow::Result<u64> {
        for other_participant_id in channel.participants() {
            if other_participant_id == &channel.my_participant_id() {
                continue;
            }
            channel.sender().send(
                *other_participant_id,
                vec![borsh::to_vec(&TestTripleMessage {
                    data: other_participant_id.raw() as u64 + seed,
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

    async fn task_follower(channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        println!("Task follower started: task id: {:?}", channel.task_id());
        match channel.task_id() {
            MpcTaskId::ManyTriples { .. } => {
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

    #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct TestTripleMessage {
        data: u64,
    }
}

#[cfg(test)]
mod fault_handling_tests {
    use super::{MeshNetworkClient, NetworkTaskChannel, NetworkTaskChannelWrapper};
    use crate::assets::UniqueId;
    use crate::network::testing::run_test_clients;
    use crate::primitives::{MpcTaskId, ParticipantId};
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use futures::FutureExt;
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
    }

    async fn run_fault_handling_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
        test_case: Arc<FaultTestCase>,
    ) -> anyhow::Result<()> {
        let me = client.my_participant_id();

        let is_leader = client.my_participant_id().raw() == 0;
        let channel = if is_leader {
            client.new_channel_for_task(
                MpcTaskId::ManyTriples {
                    start: UniqueId::new(me, 0, 0),
                    count: 1,
                },
                client.all_participant_ids(),
            )?
        } else {
            channel_receiver.recv().await.unwrap()
        };

        let leader_waits_for_success =
            !matches!(test_case.as_ref(), FaultTestCase::SlowNoWaitSuccess(_, _));
        let result = {
            let test_case = test_case.clone();
            channel
                .perform_leader_centric_computation(leader_waits_for_success, move |channel| {
                    task(channel, test_case).boxed()
                })
                .await
        };

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

    async fn task(
        channel: &mut NetworkTaskChannel,
        test_case: Arc<FaultTestCase>,
    ) -> anyhow::Result<()> {
        match test_case.as_ref() {
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
        }
        Ok(())
    }
}
