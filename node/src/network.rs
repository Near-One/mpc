use crate::primitives::{BatchedMessages, MpcMessage, MpcPeerMessage, MpcTaskId, ParticipantId};
use crate::tracking::{self, AutoAbortTask};
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use lru::LruCache;
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
///
/// TODO(#15): Is this the best API?
#[async_trait::async_trait]
pub trait MeshNetworkTransportSender: Send + Sync + 'static {
    /// Returns the participant ID of the current node.
    fn my_participant_id(&self) -> ParticipantId;
    /// Returns the participant IDs of all nodes in the network, including the current node.
    fn all_participant_ids(&self) -> Vec<ParticipantId>;
    /// Returns an identifier for the current persistent connection to the participant. This
    /// identifier should change whenever the connection is reset.
    fn connection_version(&self, participant_id: ParticipantId) -> usize;
    /// Sends a message to the specified recipient.
    /// It is not expected to really block. It's only async because messages may be congested.
    /// Returns an error if something serious goes wrong so that the task that expects the
    /// message to be sent has no meaningful way to proceed. Otherwise, just because the
    /// message is sent doesn't guarantee that the recipient will receive it; that is up to
    /// the user of the networking layer to deal with. This method should fail if the current
    /// connection version is different from the one supplied (i.e. the connection was reset).
    async fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
        connection_version: usize,
    ) -> anyhow::Result<()>;
    /// Waits until at least `threshold` nodes in the network have been connected to initially,
    /// the threshold includes ourselves.
    async fn wait_for_ready(&self, threshold: usize) -> anyhow::Result<()>;
    /// Returns the participant IDs of all nodes in the network that are currently alive.
    /// This is a subset of all_participant_ids, and includes our own participant ID.
    fn all_alive_participant_ids(&self) -> Vec<ParticipantId>;
}

/// The receiving side of the networking layer. It is expected that the node will run
/// a loop that calls receive(), and then immediately hand off the message to another
/// tokio task to process it.
#[async_trait::async_trait]
pub trait MeshNetworkTransportReceiver: Send + 'static {
    async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage>;
}

/// Concrete logic for a client based on the networking layer.
/// Manages a collection of MPC tasks so that they can be multiplexed onto the
/// networking layer underneath.
#[derive(Clone)]
pub struct MeshNetworkClient {
    transport_sender: Arc<dyn MeshNetworkTransportSender>,
    senders_for_tasks: Arc<Mutex<HashMap<MpcTaskId, mpsc::Sender<MpcPeerMessage>>>>,
    deleted_channels: Arc<Mutex<LruCache<MpcTaskId, ()>>>,
}

impl MeshNetworkClient {
    /// Primary functionality for the MeshNetworkClient: returns a channel for the given
    /// new MPC task. It is expected that the caller is the leader of this MPC task, and that the
    /// way the MPC task IDs are assigned ensures that no two participants would initiate
    /// tasks with the same MPC task ID.
    pub fn new_channel_for_task(
        &self,
        task_id: MpcTaskId,
        participants: Vec<ParticipantId>,
    ) -> anyhow::Result<NetworkTaskChannel> {
        tracing::debug!(
            target: "network",
            "[{}] Creating new channel for task {:?}",
            self.my_participant_id(),
            task_id
        );
        match self.sender_for(task_id, participants) {
            SenderOrNewChannel::Existing(_) => anyhow::bail!("Channel already exists"),
            SenderOrNewChannel::NewChannel { channel, .. } => Ok(channel),
            SenderOrNewChannel::RemovedChannel => anyhow::bail!("Channel was removed"),
        }
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
        self.transport_sender.all_alive_participant_ids()
    }

    /// Internal function shared between new_channel_for_task and MeshNetworkClientDriver::run.
    /// Returns an existing sender for the MPC task, or creates a new one if it doesn't exist.
    /// This is used to determine whether an incoming network message belongs to an existing
    /// MPC task, or if it should trigger the creation of a new MPC task that this node passively
    /// participates in.
    fn sender_for(
        &self,
        task_id: MpcTaskId,
        participants: Vec<ParticipantId>,
    ) -> SenderOrNewChannel {
        if self.deleted_channels.lock().unwrap().contains(&task_id) {
            return SenderOrNewChannel::RemovedChannel;
        }
        let mut senders_for_tasks = self.senders_for_tasks.lock().unwrap();
        match senders_for_tasks.entry(task_id) {
            Entry::Occupied(entry) => SenderOrNewChannel::Existing(entry.get().clone()),
            Entry::Vacant(entry) => {
                let (sender, receiver) = mpsc::channel(10000);
                entry.insert(sender.clone());
                drop(senders_for_tasks); // release lock

                let senders_for_tasks = self.senders_for_tasks.clone();
                let deleted_channels = self.deleted_channels.clone();
                let drop_fn = move || {
                    deleted_channels.lock().unwrap().put(task_id, ());
                    senders_for_tasks.lock().unwrap().remove(&task_id);
                };

                SenderOrNewChannel::NewChannel {
                    sender,
                    channel: NetworkTaskChannel {
                        task_id,
                        my_participant_id: self.my_participant_id(),
                        connection_versions: Arc::new(
                            participants
                                .iter()
                                .map(|id| (*id, self.transport_sender.connection_version(*id)))
                                .collect(),
                        ),
                        sender: self.transport_sender.clone(),
                        receiver,
                        drop: Some(Box::new(drop_fn)),
                        participants,
                    },
                }
            }
        }
    }
}

enum SenderOrNewChannel {
    Existing(mpsc::Sender<MpcPeerMessage>),
    NewChannel {
        sender: mpsc::Sender<MpcPeerMessage>,
        channel: NetworkTaskChannel,
    },
    RemovedChannel,
}

/// Runs the loop of receiving messages from the transport and dispatching them to the
/// appropriate MPC task channels. Any new MPC tasks that are triggered due to receiving
/// a message for an unknown MPC task would be notified via `new_channel_sender`.
async fn run_receive_messages_loop(
    client: Arc<MeshNetworkClient>,
    mut receiver: Box<dyn MeshNetworkTransportReceiver>,
    new_channel_sender: mpsc::Sender<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    loop {
        let message = receiver.receive().await?;
        let task_id = message.message.task_id;
        let channel = client.sender_for(task_id, message.message.participants.clone());
        match channel {
            SenderOrNewChannel::Existing(sender) => {
                // Should we try_send in case the channel is full?
                sender.send(message).await?;
            }
            SenderOrNewChannel::NewChannel { channel, sender } => {
                sender.send(message).await?;
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Passively created new channel for task",
                    client.my_participant_id(),
                    task_id
                );
                new_channel_sender.send(channel).await?;
            }
            SenderOrNewChannel::RemovedChannel => {
                tracing::debug!(
                    target: "network",
                    "[{}] [Task {:?}] Ignoring message for removed channel",
                    client.my_participant_id(),
                    task_id
                );
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
    mpsc::Receiver<NetworkTaskChannel>,
    AutoAbortTask<()>,
) {
    // TODO: read duration from config
    let client = Arc::new(MeshNetworkClient {
        transport_sender,
        senders_for_tasks: Arc::new(Mutex::new(HashMap::new())),
        deleted_channels: Arc::new(Mutex::new(LruCache::new(10000.try_into().unwrap()))),
    });
    let (new_channel_sender, new_channel_receiver) = mpsc::channel(1000);
    let handle = tracking::spawn_checked(
        "Network receive message loop",
        run_receive_messages_loop(client.clone(), transport_receiver, new_channel_sender),
    );
    (client, new_channel_receiver, handle)
}

/// Channel for a specific MPC task that allows sending and receiving messages in order to compute
/// the MPC task. There is one such object for each MPC task.
///
/// If the MPC task times out or aborts for any reason, this object must be dropped to ensure
/// proper cleanup of the associated resources.
pub struct NetworkTaskChannel {
    pub task_id: MpcTaskId,
    my_participant_id: ParticipantId, // for debugging
    pub participants: Vec<ParticipantId>,
    connection_versions: Arc<HashMap<ParticipantId, usize>>,
    sender: Arc<dyn MeshNetworkTransportSender>,
    receiver: tokio::sync::mpsc::Receiver<MpcPeerMessage>,
    drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

type SendFnForTaskChannel = Arc<
    dyn Fn(
            ParticipantId,
            BatchedMessages,
            Vec<ParticipantId>,
        ) -> BoxFuture<'static, anyhow::Result<()>>
        + Send
        + Sync,
>;

impl Drop for NetworkTaskChannel {
    fn drop(&mut self) {
        if let Some(drop) = self.drop.take() {
            drop();
        }
    }
}

impl NetworkTaskChannel {
    /// Returns a sender to be used to send a message to another participant in the MPC task.
    ///
    /// Documentation for the sender function returned:
    ///
    /// Sends a message to another participant in the MPC task.
    /// Returns an error only if there is something seriously wrong with the networking layer so
    /// that there's no meaningful way for the MPC task to proceed.
    ///
    /// This does not guarantee that the message will be received by the recipient. Although the
    /// communication layer uses a persistent QUIC connection, there can be disconnects, node
    /// restarts, etc. and there API does not provide an application-layer acknowledgment or retry
    /// mechanism. The MPC task's implementation shall not assume reliable message passing, and
    /// should instead have an appropriate timeout or retry mechanism.
    ///
    /// Even multiple messages sent to the same recipient may be received in a different order.
    /// However, the messages will be received in whole, i.e. they will never be split or combined.
    ///
    /// The implementation of this function will guarantee that all messages sent are encrypted,
    /// i.e. can only be decrypted by the recipient.
    pub fn sender(&self) -> SendFnForTaskChannel {
        let transport_sender = self.sender.clone();
        let connection_versions = self.connection_versions.clone();
        let task_id = self.task_id;
        Arc::new(
            move |recipient_id, message, participants: Vec<ParticipantId>| {
                let transport_sender = transport_sender.clone();
                let connection_versions = connection_versions.clone();
                async move {
                    transport_sender
                        .send(
                            recipient_id,
                            MpcMessage {
                                task_id,
                                data: message,
                                participants,
                            },
                            connection_versions.get(&recipient_id).copied().unwrap_or(0),
                        )
                        .await?;
                    Ok(())
                }
                .boxed()
            },
        )
    }

    /// Receives a message from another participant in the MPC task.
    ///
    /// If there are multiple messages available, they may be received in arbitrary order, even if
    /// they were sent from the same participant. However, any message that is received will always
    /// be received in whole, exactly as they were sent, never split or combined.
    ///
    /// Returns an error if the networking client is dropped (during node shutdown).
    ///
    /// This future may never resolve if the MPC computation fails to progress (i.e. all clients
    /// decide they need to receive a message before sending one). It is up to the caller to
    /// implement a timeout mechanism. However, if we notice that not all participants of the
    /// computation are online anymore, this method will return an error soon.
    pub async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage> {
        loop {
            let timer = tokio::time::sleep(Duration::from_secs(1));
            tokio::select! {
                _ = timer => {
                    if !self.all_participants_still_alive() {
                        anyhow::bail!("Computation cannot succeed as not all participants are alive anymore");
                    }
                }
                result = self.receiver.recv() => {
                    let Some(result) = result else {
                        anyhow::bail!("Channel closed");
                    };
                    tracing::debug!(
                        target: "network",
                        "[{}] [Task {:?}] Received message: {:?}",
                        self.my_participant_id, self.task_id, result
                    );
                    return Ok(result);
                }
            }
        }
    }

    fn all_participants_still_alive(&self) -> bool {
        let still_alive = self
            .sender
            .all_alive_participant_ids()
            .into_iter()
            .collect::<HashSet<_>>();
        self.participants
            .iter()
            .all(|participant_id| still_alive.contains(participant_id))
    }
}

#[cfg(test)]
pub mod testing {
    use super::MeshNetworkTransportSender;
    use crate::primitives::{MpcPeerMessage, ParticipantId};
    use crate::tracking;
    use std::collections::HashMap;
    use std::sync::Arc;

    pub struct TestMeshTransport {
        participant_ids: Vec<ParticipantId>,
        senders: HashMap<ParticipantId, tokio::sync::mpsc::UnboundedSender<MpcPeerMessage>>,
    }

    pub struct TestMeshTransportSender {
        transport: Arc<TestMeshTransport>,
        my_participant_id: ParticipantId,
    }

    pub struct TestMeshTransportReceiver {
        receiver: tokio::sync::mpsc::UnboundedReceiver<MpcPeerMessage>,
    }

    #[async_trait::async_trait]
    impl MeshNetworkTransportSender for TestMeshTransportSender {
        fn my_participant_id(&self) -> ParticipantId {
            self.my_participant_id
        }

        fn all_participant_ids(&self) -> Vec<ParticipantId> {
            self.transport.participant_ids.clone()
        }

        fn connection_version(&self, _participant_id: ParticipantId) -> usize {
            0
        }

        async fn send(
            &self,
            recipient_id: ParticipantId,
            message: crate::primitives::MpcMessage,
            _connection_version: usize,
        ) -> anyhow::Result<()> {
            self.transport
                .senders
                .get(&recipient_id)
                .ok_or_else(|| anyhow::anyhow!("Unknown recipient"))?
                .send(MpcPeerMessage {
                    from: self.my_participant_id,
                    message,
                })?;
            Ok(())
        }

        async fn wait_for_ready(&self, _threshold: usize) -> anyhow::Result<()> {
            Ok(())
        }

        fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
            self.all_participant_ids()
        }
    }

    #[async_trait::async_trait]
    impl super::MeshNetworkTransportReceiver for TestMeshTransportReceiver {
        async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage> {
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
        num_participants: usize,
        client_runner: F,
    ) -> anyhow::Result<Vec<T>>
    where
        F: Fn(
            Arc<super::MeshNetworkClient>,
            tokio::sync::mpsc::Receiver<super::NetworkTaskChannel>,
        ) -> FR,
        FR: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let participants = (0..num_participants)
            .map(|_| ParticipantId::from_raw(rand::random::<u32>()))
            .collect::<Vec<_>>();
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
    use super::{MeshNetworkClient, NetworkTaskChannel};
    use crate::assets::UniqueId;
    use crate::network::testing::run_test_clients;
    use crate::primitives::{MpcTaskId, ParticipantId};
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
            run_test_clients(4, run_test_client).await.unwrap();
        })
        .await;
    }

    async fn run_test_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<()> {
        let _passive_handle = tracking::spawn("monitor passive channels", async move {
            let mut tasks = AutoAbortTaskCollection::new();
            loop {
                let Some(channel) = channel_receiver.recv().await else {
                    break;
                };
                tasks.spawn_checked(
                    &format!("passive task {:?}", channel.task_id),
                    task_follower(channel),
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
                task_leader(channel, other_participant_ids.clone(), seed),
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

    async fn task_leader(
        mut channel: NetworkTaskChannel,
        participants: Vec<ParticipantId>,
        seed: u64,
    ) -> anyhow::Result<u64> {
        for other_participant_id in &participants {
            channel.sender()(
                *other_participant_id,
                vec![borsh::to_vec(&TestTripleMessage {
                    data: other_participant_id.raw() as u64 + seed,
                })
                .unwrap()],
                channel.participants.clone(),
            )
            .await?;
        }
        let mut total = 0;
        let mut heard_from = HashSet::new();
        for _ in 0..participants.len() {
            let msg = channel.receive().await?;
            assert!(heard_from.insert(msg.from));
            let inner: TestTripleMessage = borsh::from_slice(&msg.message.data[0])?;
            total += inner.data;
        }
        Ok(total)
    }

    async fn task_follower(mut channel: NetworkTaskChannel) -> anyhow::Result<()> {
        println!("Task follower started: task id: {:?}", channel.task_id);
        match channel.task_id {
            id @ MpcTaskId::ManyTriples { .. } => {
                let message = channel.receive().await?;
                assert_eq!(message.message.task_id, id);

                let inner: TestTripleMessage = borsh::from_slice(&message.message.data[0])?;
                channel.sender()(
                    message.from,
                    vec![borsh::to_vec(&TestTripleMessage {
                        data: (inner.data * inner.data) % MOD,
                    })
                    .unwrap()],
                    channel.participants.clone(),
                )
                .await?;

                Ok(())
            }
            _ => unreachable!(),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
    struct TestTripleMessage {
        data: u64,
    }
}
