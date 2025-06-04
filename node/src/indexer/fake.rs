use super::handler::{ChainBlockUpdate, SignatureRequestFromChain};
use super::participants::ContractState;
use super::types::{ChainRespondArgs, ChainSendTransactionRequest};
use super::IndexerAPI;
use crate::config::ParticipantsConfig;
use crate::sign_request::SignatureId;
use crate::signing::recent_blocks_tracker::tests::TestBlockMaker;
use crate::tracking::{AutoAbortTask, AutoAbortTaskCollection};
use mpc_contract::config::Config;
use mpc_contract::primitives::test_utils::mock_tee_participant_info;
use mpc_contract::primitives::{
    domain::{DomainConfig, DomainRegistry},
    key_state::{EpochId, KeyEventId, Keyset},
    participants::{ParticipantId, ParticipantInfo, Participants},
    signature::Payload,
    thresholds::{Threshold, ThresholdParameters},
};
use mpc_contract::state::{
    initializing::InitializingContractState, key_event::tests::Environment, key_event::KeyEvent,
    resharing::ResharingContractState, running::RunningContractState, ProtocolContractState,
};
use near_crypto::PublicKey;
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{broadcast, mpsc, watch};

/// A simplification of the real MPC contract state for testing.
pub struct FakeMpcContractState {
    pub state: ProtocolContractState,
    config: Config,
    env: Environment,
    pub pending_signatures: BTreeMap<Payload, SignatureId>,
}

impl FakeMpcContractState {
    pub fn new() -> Self {
        let state = ProtocolContractState::NotInitialized;
        let config = Config {
            key_event_timeout_blocks: 10,
        };
        let block_timestamp = 1757785600_u64 * 1_000_000_u64; // 2025-05-21 00:00:00 UTC to ensure TEE quote verification succeeds
        let env = Environment::new(None, None, None, Some(block_timestamp));
        Self {
            state,
            config,
            env,
            pending_signatures: BTreeMap::new(),
        }
    }

    pub fn initialize(&mut self, participants: ParticipantsConfig) {
        assert!(matches!(self.state, ProtocolContractState::NotInitialized));

        self.state = ProtocolContractState::Running(RunningContractState::new(
            DomainRegistry::default(),
            Keyset::new(EpochId::new(0), Vec::new()),
            participants_config_to_threshold_parameters(&participants),
        ));
    }

    pub fn add_domains(&mut self, domains: Vec<DomainConfig>) {
        let state = match &mut self.state {
            ProtocolContractState::Running(state) => state,
            _ => panic!("Cannot add domains to non-running state"),
        };
        let new_state = InitializingContractState {
            domains: state
                .domains
                .add_domains(domains.clone())
                .expect("Failed to add domains"),
            epoch_id: state.keyset.epoch_id,
            generated_keys: state.keyset.domains.clone(),
            generating_key: KeyEvent::new(
                state.keyset.epoch_id,
                domains[0].clone(),
                state.parameters.clone(),
            ),
            cancel_votes: BTreeSet::new(),
        };
        self.state = ProtocolContractState::Initializing(new_state);
    }

    pub fn start_resharing(&mut self, new_participants: ParticipantsConfig) {
        let (previous_running_state, prev_epoch_id) = match &self.state {
            ProtocolContractState::Running(state) => (state, state.keyset.epoch_id),
            ProtocolContractState::Resharing(state) => {
                (&state.previous_running_state, state.prospective_epoch_id())
            }
            _ => panic!("Cannot start resharing from non-running state"),
        };
        self.state = ProtocolContractState::Resharing(ResharingContractState {
            previous_running_state: RunningContractState::new(
                previous_running_state.domains.clone(),
                previous_running_state.keyset.clone(),
                previous_running_state.parameters.clone(),
            ),
            reshared_keys: Vec::new(),
            resharing_key: KeyEvent::new(
                prev_epoch_id.next(),
                previous_running_state
                    .domains
                    .get_domain_by_index(0)
                    .unwrap()
                    .clone(),
                participants_config_to_threshold_parameters(&new_participants),
            ),
        });
    }

    pub fn vote_pk(&mut self, account_id: AccountId, key_id: KeyEventId, pk: PublicKey) {
        let near_sdk_pk: near_sdk::PublicKey = pk.to_string().parse().unwrap();
        let contract_extended_pk = near_sdk_pk.try_into().unwrap();

        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                self.env.set_signer(&account_id);
                let result = match state.vote_pk(key_id, contract_extended_pk) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::info!("vote_pk transaction failed: {}", e);
                        return;
                    }
                };
                if let Some(new_state) = result {
                    self.state = ProtocolContractState::Running(new_state);
                }
            }
            _ => {
                tracing::info!(
                    "vote_pk transaction ignored because the contract is not in initializing state"
                );
            }
        }
    }

    pub fn vote_start_keygen(&mut self, account_id: AccountId, id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                self.env.set_signer(&account_id);
                if let Err(e) = state.start(id, self.config.key_event_timeout_blocks) {
                    tracing::info!("vote_start_keygen transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_start_keygen transaction ignored because the contract is not in initializing state"
                );
            }
        }
    }

    pub fn vote_abort_key_event(&mut self, account_id: AccountId, id: KeyEventId) {
        self.env.set_signer(&account_id);
        match &mut self.state {
            ProtocolContractState::Initializing(state) => {
                if let Err(e) = state.vote_abort(id) {
                    tracing::info!("vote_abort_key_event transaction failed: {}", e);
                }
            }
            ProtocolContractState::Resharing(state) => {
                if let Err(e) = state.vote_abort(id) {
                    tracing::info!("vote_abort_key_event transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_abort_key_event transaction ignored because the contract is not in initializing or resharing state"
                );
            }
        }
    }

    pub fn vote_start_reshare(&mut self, account_id: AccountId, id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Resharing(state) => {
                self.env.set_signer(&account_id);
                if let Err(e) = state.start(id, self.config.key_event_timeout_blocks) {
                    tracing::info!("vote_start_reshare transaction failed: {}", e);
                }
            }
            _ => {
                tracing::info!(
                    "vote_start_reshare transaction ignored because the contract is not in resharing state"
                );
            }
        }
    }

    pub fn vote_reshared(&mut self, account_id: AccountId, key_id: KeyEventId) {
        match &mut self.state {
            ProtocolContractState::Resharing(state) => {
                self.env.set_signer(&account_id);
                let result = match state.vote_reshared(key_id) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::info!("vote_reshared transaction failed: {}", e);
                        return;
                    }
                };
                if let Some(new_state) = result {
                    self.state = ProtocolContractState::Running(new_state);
                }
            }
            _ => {
                tracing::info!(
                    "vote_reshared transaction ignored because the contract is not in resharing state"
                );
            }
        }
    }
}

fn participants_config_to_threshold_parameters(
    participants_config: &ParticipantsConfig,
) -> ThresholdParameters {
    let mut participants = Participants::new();
    let mut infos = participants_config.participants.clone();
    infos.sort_by_key(|info| info.id);

    for info in infos {
        participants
            .insert_with_id(
                info.near_account_id,
                ParticipantInfo {
                    sign_pk: info.p2p_public_key.to_string().parse().unwrap(),
                    url: format!("http://{}:{}", info.address, info.port),
                },
                ParticipantId(info.id.raw()),
            )
            .expect("Failed to insert participant");
    }
    ThresholdParameters::new(
        participants,
        Threshold::new(participants_config.threshold),
        mock_tee_participant_info(),
    )
    .unwrap()
}

/// Runs the fake indexer's shared state and logic. There's one instance of this per test.
struct FakeIndexerCore {
    clock: Clock,
    /// Delay (in number of blocks) from when a txn is submitted to when it affects the contract
    /// state.
    txn_delay_blocks: u64,
    /// A fake contract state to emulate the real MPC contract but with much less complexity.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
    /// Receives transactions sent via the APIs of each node.
    txn_receiver: mpsc::UnboundedReceiver<(ChainSendTransactionRequest, AccountId)>,
    /// Receives signature requests from the FakeIndexerManager.
    signature_request_receiver: mpsc::UnboundedReceiver<SignatureRequestFromChain>,
    /// Broadcasts the contract state to each node.
    state_change_sender: broadcast::Sender<ContractState>,
    /// Broadcasts block updates to each node.
    block_update_sender: broadcast::Sender<ChainBlockUpdate>,

    /// When the core receives signature response txns, it processes them by sending them through
    /// this sender. The receiver end of this is in FakeIndexManager to be received by the test
    /// code.
    sign_response_sender: mpsc::UnboundedSender<ChainRespondArgs>,
}

impl FakeIndexerCore {
    pub async fn run(mut self) {
        let mut tasks = AutoAbortTaskCollection::new();
        let contract = self.contract.clone();
        tasks.spawn_with_tokio({
            let contract = contract.clone();
            let clock = self.clock.clone();
            let state_change_sender = self.state_change_sender.clone();
            async move {
                loop {
                    {
                        let state = contract.lock().await;
                        let config = ContractState::from_contract_state(
                            &state.state,
                            state.env.block_height,
                            None,
                        )
                        .expect("Failed to convert contract state");
                        state_change_sender.send(config).ok();
                    }
                    clock.sleep(Duration::seconds(1)).await;
                }
            }
        });

        let block_maker = TestBlockMaker::new();
        let mut current_block = block_maker.block(1);
        let mut pending_transactions = VecDeque::new();
        loop {
            loop {
                match self.txn_receiver.try_recv() {
                    Ok((txn, account_id)) => {
                        pending_transactions.push_back((
                            current_block.height() + self.txn_delay_blocks,
                            txn,
                            account_id,
                        ));
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            let block = current_block.child(current_block.height() + 1);

            let mut transactions_to_process = Vec::new();
            while let Some((height, _, _)) = pending_transactions.front() {
                if *height <= block.height() {
                    let (_, txn, account_id) = pending_transactions.pop_front().unwrap();
                    transactions_to_process.push((txn, account_id));
                } else {
                    break;
                }
            }

            let mut signature_requests = Vec::new();
            loop {
                match self.signature_request_receiver.try_recv() {
                    Ok(request) => {
                        signature_requests.push(request);
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                }
            }

            for signature_request in &signature_requests {
                let mut contract = contract.lock().await;
                let signature_id = signature_request.signature_id;
                contract
                    .pending_signatures
                    .insert(signature_request.request.payload.clone(), signature_id);
            }

            let mut block_update = ChainBlockUpdate {
                block: block.to_block_view(),
                signature_requests,
                completed_signatures: Vec::new(),
            };
            contract.lock().await.env.set_block_height(block.height());
            for (txn, account_id) in transactions_to_process {
                match txn {
                    ChainSendTransactionRequest::VotePk(vote_pk) => {
                        let mut contract = contract.lock().await;
                        contract.vote_pk(account_id, vote_pk.key_event_id, vote_pk.public_key);
                    }
                    ChainSendTransactionRequest::Respond(respond) => {
                        let mut contract = contract.lock().await;
                        let signature_id =
                            contract.pending_signatures.remove(&respond.request.payload);
                        if let Some(signature_id) = signature_id {
                            self.sign_response_sender.send(respond.clone()).unwrap();
                            block_update.completed_signatures.push(signature_id);
                        } else {
                            tracing::warn!(
                                "Ignoring respond transaction for unknown (possibly already-responded-to) signature: {:?}",
                                respond.request.payload
                            );
                        }
                    }
                    ChainSendTransactionRequest::VoteReshared(reshared) => {
                        let mut contract = contract.lock().await;
                        contract.vote_reshared(account_id, reshared.key_event_id);
                    }
                    ChainSendTransactionRequest::StartKeygen(start) => {
                        // todo: timeout logic in fake indexer?
                        let mut contract = contract.lock().await;
                        contract.vote_start_keygen(account_id, start.key_event_id);
                    }
                    ChainSendTransactionRequest::StartReshare(start) => {
                        let mut contract = contract.lock().await;
                        contract.vote_start_reshare(account_id, start.key_event_id);
                    }
                    ChainSendTransactionRequest::VoteAbortKeyEvent(abort) => {
                        let mut contract = contract.lock().await;
                        contract.vote_abort_key_event(account_id, abort.key_event_id);
                    }
                    ChainSendTransactionRequest::VerifyTee() => {
                        // do nothing
                    }
                }
            }
            self.block_update_sender.send(block_update).ok();
            current_block = block;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

/// User-facing object for using the fake indexer for testing.
/// Create one of these for each test, and call `add_indexer_node` for each node.
pub struct FakeIndexerManager {
    /// Sends transactions to the core for processing. This is cloned to each node,
    /// so each node can send transactions (with its AccountId) to the core.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    /// Used to call .subscribe() so that each node can receive changes to the
    /// contract state.
    core_state_change_sender: broadcast::Sender<ContractState>,
    /// Used to call .subscribe() so that each node can receive block updates.
    core_block_update_sender: broadcast::Sender<ChainBlockUpdate>,
    /// Task that runs the core logic.
    _core_task: AutoAbortTask<()>,

    /// Collects signature responses from the core. When the core processes signature
    /// response transactions, it sends them to this receiver. See `next_response()`.
    response_receiver: mpsc::UnboundedReceiver<ChainRespondArgs>,
    /// Used to send signature requests to the core.
    signature_request_sender: mpsc::UnboundedSender<SignatureRequestFromChain>,

    /// Allows nodes to be disabled during tests. See `disable()`.
    node_disabler: HashMap<AccountId, NodeDisabler>,
    /// Allows modification of the contract.
    contract: Arc<tokio::sync::Mutex<FakeMpcContractState>>,
}

/// Allows a node to be disabled during tests.
struct NodeDisabler {
    disable: Arc<AtomicBool>,
    /// For querying whether the node is running the Invalid job,
    /// indicating it has been disabled.
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

/// While holding this, the node remains disabled.
pub struct DisabledNode {
    disable: Arc<AtomicBool>,
    currently_running_job_name: Arc<std::sync::Mutex<String>>,
}

impl DisabledNode {
    pub async fn reenable_and_wait_till_running(self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
        loop {
            {
                let name = self.currently_running_job_name.lock().unwrap();
                if &*name == "Running" {
                    break;
                }
                tracing::info!(
                    "Waiting for node to be reenabled and running; currently running job: {}",
                    *name
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

impl Drop for DisabledNode {
    fn drop(&mut self) {
        self.disable
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Runs the fake indexer logic for one node.
struct FakeIndexerOneNode {
    /// Account under which transactions by this node are originated.
    account_id: AccountId,

    // The following are counterparts of the core channels.
    core_txn_sender: mpsc::UnboundedSender<(ChainSendTransactionRequest, AccountId)>,
    core_state_change_receiver: broadcast::Receiver<ContractState>,
    block_update_receiver: broadcast::Receiver<ChainBlockUpdate>,

    /// Whether the node should yield ContractState::Invalid to artificially simulate bringing the
    /// node down.
    disable: Arc<AtomicBool>,

    // The following are counterparts of the API channels.
    api_state_sender: watch::Sender<ContractState>,
    api_block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
    api_txn_receiver: mpsc::Receiver<ChainSendTransactionRequest>,
}

impl FakeIndexerOneNode {
    async fn run(self) {
        let FakeIndexerOneNode {
            account_id,
            core_txn_sender,
            mut core_state_change_receiver,
            mut block_update_receiver,
            disable: shutdown,
            api_state_sender,
            api_block_update_sender,
            mut api_txn_receiver,
            ..
        } = self;
        let monitor_state_changes = AutoAbortTask::from(tokio::spawn(async move {
            let mut last_state = ContractState::WaitingForSync;
            loop {
                let state = core_state_change_receiver.recv().await.unwrap();
                let state = if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    ContractState::Invalid
                } else {
                    state
                };
                if state != last_state {
                    tracing::info!("State changed: {:?}", state);
                    api_state_sender.send(state.clone()).unwrap();
                    last_state = state;
                }
            }
        }));
        let monitor_signature_requests = AutoAbortTask::from(tokio::spawn(async move {
            loop {
                let request = block_update_receiver.recv().await.unwrap();
                api_block_update_sender.send(request).unwrap();
            }
        }));
        let forward_txn_requests = AutoAbortTask::from(tokio::spawn(async move {
            while let Some(txn) = api_txn_receiver.recv().await {
                core_txn_sender.send((txn, account_id.clone())).unwrap();
            }
        }));
        monitor_state_changes.await.unwrap();
        monitor_signature_requests.await.unwrap();
        forward_txn_requests.await.unwrap();
    }
}

impl FakeIndexerManager {
    /// Creates a new fake indexer whose contract state begins with WaitingForSync.
    pub fn new(clock: Clock, txn_delay_blocks: u64) -> Self {
        let (txn_sender, txn_receiver) = mpsc::unbounded_channel();
        let (state_change_sender, _) = broadcast::channel(1000);
        let (block_update_sender, _) = broadcast::channel(1000);
        let (signature_request_sender, signature_request_receiver) = mpsc::unbounded_channel();
        let (sign_response_sender, response_receiver) = mpsc::unbounded_channel();
        let contract = Arc::new(tokio::sync::Mutex::new(FakeMpcContractState::new()));
        let core = FakeIndexerCore {
            clock: clock.clone(),
            txn_delay_blocks,
            signature_request_receiver,
            contract: contract.clone(),
            txn_receiver,
            state_change_sender: state_change_sender.clone(),
            block_update_sender: block_update_sender.clone(),
            sign_response_sender,
        };
        let core_task = AutoAbortTask::from(tokio::spawn(async move { core.run().await }));
        Self {
            core_txn_sender: txn_sender,
            core_state_change_sender: state_change_sender,
            core_block_update_sender: block_update_sender,
            _core_task: core_task,
            response_receiver,
            signature_request_sender,
            node_disabler: HashMap::new(),
            contract,
        }
    }

    /// Waits for the next signature response submitted by any node.
    pub async fn next_response(&mut self) -> ChainRespondArgs {
        self.response_receiver.recv().await.unwrap()
    }

    /// Sends a signature request to the fake blockchain.
    pub fn request_signature(&self, request: SignatureRequestFromChain) {
        self.signature_request_sender.send(request).unwrap();
    }

    /// Adds a new node to the fake indexer. Returns the API for the node, a task that
    /// runs the node's logic, and the running job name to passed to the coordinator.
    pub fn add_indexer_node(
        &mut self,
        account_id: AccountId,
    ) -> (IndexerAPI, AutoAbortTask<()>, Arc<std::sync::Mutex<String>>) {
        let (api_state_sender, api_state_receiver) = watch::channel(ContractState::WaitingForSync);
        let (api_signature_request_sender, api_signature_request_receiver) =
            mpsc::unbounded_channel();
        let (api_txn_sender, api_txn_receiver) = mpsc::channel(1000);
        let indexer = IndexerAPI {
            contract_state_receiver: api_state_receiver,
            block_update_receiver: Arc::new(tokio::sync::Mutex::new(
                api_signature_request_receiver,
            )),
            txn_sender: api_txn_sender,
        };
        let currently_running_job_name = Arc::new(std::sync::Mutex::new("".to_string()));
        let disabler = NodeDisabler {
            disable: Arc::new(AtomicBool::new(false)),
            currently_running_job_name: currently_running_job_name.clone(),
        };
        let one_node = FakeIndexerOneNode {
            account_id: account_id.clone(),
            core_txn_sender: self.core_txn_sender.clone(),
            core_state_change_receiver: self.core_state_change_sender.subscribe(),
            block_update_receiver: self.core_block_update_sender.subscribe(),
            disable: disabler.disable.clone(),
            api_state_sender,
            api_block_update_sender: api_signature_request_sender,
            api_txn_receiver,
        };
        self.node_disabler.insert(account_id, disabler);
        (
            indexer,
            AutoAbortTask::from(tokio::spawn(one_node.run())),
            currently_running_job_name,
        )
    }

    /// Waits for the contract state to satisfy the given predicate.
    pub async fn wait_for_contract_state(&mut self, f: impl Fn(&ContractState) -> bool) {
        let mut state_change_receiver = self.core_state_change_sender.subscribe();
        loop {
            let state = state_change_receiver.recv().await.unwrap();
            if f(&state) {
                break;
            }
        }
    }

    /// Disables a node, in order to test resilience to node failures.
    pub async fn disable(&self, account_id: AccountId) -> DisabledNode {
        let NodeDisabler {
            disable,
            currently_running_job_name,
        } = self.node_disabler.get(&account_id).unwrap();
        disable.store(true, std::sync::atomic::Ordering::Relaxed);
        loop {
            {
                let name = currently_running_job_name.lock().unwrap();
                if &*name == "Invalid" {
                    break;
                }
                tracing::info!(
                    "Waiting for node to be disabled; currently running job: {}",
                    *name
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        DisabledNode {
            disable: disable.clone(),
            currently_running_job_name: currently_running_job_name.clone(),
        }
    }

    pub async fn contract_mut(&self) -> tokio::sync::MutexGuard<'_, FakeMpcContractState> {
        self.contract.lock().await
    }
}
