use crate::config::{ConfigFile, MpcConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::hkdf::affine_point_to_public_key;
use crate::indexer::handler::ChainBlockUpdate;
use crate::indexer::participants::{
    ContractInitializingState, ContractKeyEventInstance, ContractResharingState,
    ContractRunningState, ContractState,
};
use crate::indexer::types::{
    ChainSendTransactionRequest, ChainStartKeygenArgs, ChainStartReshareArgs, ChainVotePkArgs,
    ChainVoteResharedArgs,
};
use crate::indexer::IndexerAPI;
use crate::keyshare::{KeyStorageConfig, Keyshare};
use crate::keyshare::{KeyshareData, KeyshareStorage};
use crate::metrics;
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::new_tls_mesh_network;
use crate::primitives::MpcTaskId;
use crate::providers::ecdsa::key_resharing::public_key_to_affine_point;
use crate::providers::{EcdsaSignatureProvider, EcdsaTaskId, SignatureProvider};
use crate::runtime::AsyncDroppableRuntime;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self};
use crate::web::SignatureDebugRequest;
use futures::future::BoxFuture;
use futures::FutureExt;
use near_time::{Clock, Duration};
use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc, watch};

/// Main entry point for the MPC node logic. Assumes the existence of an
/// indexer. Queries and monitors the contract for state transitions, and act
/// accordingly: if the contract says we need to generate keys, we generate
/// keys; if the contract says we're running, we run the MPC protocol; if the
/// contract says we need to perform key resharing, we perform key resharing.
pub struct Coordinator {
    pub clock: Clock,
    pub secrets: SecretsConfig,
    pub config_file: ConfigFile,

    /// Storage for triples, presignatures, signing requests.
    pub secret_db: Arc<SecretDB>,
    /// Storage config for keyshares.
    pub key_storage_config: KeyStorageConfig,

    /// For interaction with the indexer.
    pub indexer: IndexerAPI,

    /// For testing, to know what the current state is.
    pub currently_running_job_name: Arc<Mutex<String>>,

    /// For debug UI to send us debug requests.
    pub signature_debug_request_sender: broadcast::Sender<SignatureDebugRequest>,
}

/// Represents a top-level task that we run for the current contract state.
/// There is a different one of these for each contract state.
struct MpcJob {
    /// Friendly name for the currently running task.
    name: &'static str,
    /// The future for the MPC task (keygen, resharing, or normal run).
    fut: BoxFuture<'static, anyhow::Result<MpcJobResult>>,
    /// a function that looks at a new contract state and returns true iff the
    /// current task should be killed.
    stop_fn: Box<dyn Fn(&ContractState) -> bool + Send>,
    /// a future that resolves when the current task exceeds the desired
    /// timeout.
    timeout_fut: BoxFuture<'static, ()>,
}

/// When an MpcJob future returns successfully, it returns one of the following.
enum MpcJobResult {
    /// This MpcJob has been completed successfully.
    Done,
    /// This MpcJob could not run because the contract is in a state that we
    /// cannot handle (such as the contract being invalid or we're not a current
    /// participant). If this is returned, the coordinator should do nothing
    /// until either timeout or the contract state changed. During this time,
    /// block updates are buffered.
    HaltUntilInterrupted,
}

impl Coordinator {
    pub async fn run(mut self) -> anyhow::Result<()> {
        loop {
            let wrapped_state = self.indexer.contract_state_receiver.borrow().clone();
            let mut job: MpcJob = match wrapped_state {
                ContractState::WaitingForSync => {
                    // This is the initial state. We stop this state for any state changes.
                    MpcJob {
                        name: "WaitingForSync",
                        fut: futures::future::ready(Ok(MpcJobResult::HaltUntilInterrupted)).boxed(),
                        stop_fn: Box::new(|_| true),
                        timeout_fut: futures::future::pending().boxed(),
                    }
                }
                ContractState::Invalid => {
                    // Invalid state. Similar to initial state; we do nothing until the state changes.
                    MpcJob {
                        name: "Invalid",
                        fut: futures::future::ready(Ok(MpcJobResult::HaltUntilInterrupted)).boxed(),
                        stop_fn: Box::new(|_| true),
                        timeout_fut: futures::future::pending().boxed(),
                    }
                }
                ContractState::Initializing(state) => {
                    // For initialization state, we generate keys and vote for the public key.
                    // We give it a timeout, so that if somehow the keygen and voting fail to
                    // progress, we can retry.
                    let (key_event_sender, key_event_receiver) =
                        watch::channel(state.key_event.clone());
                    MpcJob {
                        name: "Initializing",
                        fut: Self::create_runtime_and_run(
                            "Initializing",
                            self.config_file.cores,
                            Self::run_initialization(
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.key_storage_config.create().await?,
                                state.clone(),
                                self.indexer.txn_sender.clone(),
                                key_event_receiver,
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Initializing(new_state) => {
                                if new_state.key_event.id == state.key_event.id {
                                    // still same attempt, send the update
                                    if key_event_sender.send(new_state.key_event.clone()).is_ok() {
                                        return false;
                                    }
                                }
                                true
                            }
                            _ => true,
                        }),
                        // TODO(#151): This timeout is not ideal. If participants are not synchronized,
                        // they might each timeout out of order and never complete keygen?
                        timeout_fut: sleep(
                            &self.clock,
                            Duration::seconds(self.config_file.keygen.timeout_sec as i64),
                        ),
                    }
                }
                ContractState::Running(state) => {
                    // For the running state, we run the full MPC protocol.
                    // There's no timeout. The only time we stop is when the contract state
                    // changes to no longer be running (or if somehow the epoch changes).
                    MpcJob {
                        name: "Running",
                        fut: Self::create_runtime_and_run(
                            "Running",
                            self.config_file.cores,
                            Self::run_mpc(
                                self.clock.clone(),
                                self.secret_db.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.key_storage_config.create().await?,
                                state.clone(),
                                self.indexer.txn_sender.clone(),
                                self.indexer
                                    .block_update_receiver
                                    .clone()
                                    .lock_owned()
                                    .await,
                                self.signature_debug_request_sender.subscribe(),
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Running(new_state) => {
                                new_state.keyset.epoch_id != state.keyset.epoch_id
                            }
                            _ => true,
                        }),
                        timeout_fut: futures::future::pending().boxed(),
                    }
                }
                ContractState::Resharing(state) => {
                    // In resharing state, we perform key resharing, again with a timeout.
                    let (key_event_sender, key_event_receiver) =
                        watch::channel(state.key_event.clone());
                    MpcJob {
                        name: "Resharing",
                        fut: Self::create_runtime_and_run(
                            "Resharing",
                            self.config_file.cores,
                            Self::run_key_resharing(
                                self.secret_db.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.key_storage_config.create().await?,
                                state.clone(),
                                self.indexer.txn_sender.clone(),
                                key_event_receiver,
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Resharing(new_state) => {
                                if new_state.key_event.id == state.key_event.id {
                                    // still same attempt, just send the update
                                    if key_event_sender.send(new_state.key_event.clone()).is_ok() {
                                        return false;
                                    }
                                }
                                // reset everything.
                                true
                            }
                            _ => true,
                        }),
                        timeout_fut: sleep(
                            &self.clock,
                            Duration::seconds(self.config_file.keygen.timeout_sec as i64),
                        ),
                    }
                }
            };
            tracing::info!("[{}] Starting", job.name);
            let _report_guard =
                ReportCurrentJobGuard::new(job.name, self.currently_running_job_name.clone());

            loop {
                tokio::select! {
                    res = &mut job.fut => {
                        match res {
                            Err(e) => {
                                tracing::error!("[{}] failed: {:?}", job.name, e);
                                break;
                            }
                            Ok(MpcJobResult::Done) => {
                                tracing::info!("[{}] finished successfully", job.name);
                                break;
                            }
                            Ok(MpcJobResult::HaltUntilInterrupted) => {
                                tracing::info!("[{}] halted; waiting for state change or timeout", job.name);
                                // Replace it with a never-completing future so next iteration we wait for
                                // only state change or timeout.
                                job.fut = futures::future::pending().boxed();
                                continue;
                            }
                        }
                    }
                    _ = self.indexer.contract_state_receiver.changed() => {
                        if (job.stop_fn)(&self.indexer.contract_state_receiver.borrow()) {
                            tracing::info!(
                                "[{}] contract state changed incompatibly, stopping",
                                job.name
                            );
                            break;
                        }
                    }
                    _ = &mut job.timeout_fut => {
                        tracing::error!("[{}] timed out, stopping", job.name);
                        break;
                    }
                }
            }
        }
    }

    fn create_runtime_and_run(
        description: &str,
        cores: Option<usize>,
        task: impl Future<Output = anyhow::Result<MpcJobResult>> + Send + 'static,
    ) -> anyhow::Result<BoxFuture<'static, anyhow::Result<MpcJobResult>>> {
        let task_handle = tracking::current_task();

        // Create a separate runtime, as opposed to making a runtime when the
        // binary starts, for these reasons:
        //  - so that we can limit the number of cores used for MPC tasks,
        //    in order to avoid starving the indexer, causing it to fall behind.
        //  - so that we can ensure that all MPC tasks are shut down when we
        //    encounter contract state transitions. By dropping the entire
        //    runtime, we can ensure that all tasks are stopped. Otherwise, it
        //    would be very difficult and error-prone to ensure we don't leave
        //    some long-running task behind.
        let mpc_runtime = if let Some(n_threads) = cores {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(std::cmp::max(n_threads, 1))
                .enable_all()
                .build()?
        } else {
            tokio::runtime::Runtime::new()?
        };
        let mpc_runtime = AsyncDroppableRuntime::new(mpc_runtime);
        let fut = mpc_runtime.spawn(task_handle.scope(description, task));
        Ok(async move {
            let _mpc_runtime = mpc_runtime;
            anyhow::Ok(fut.await??)
        }
        .boxed())
    }

    /// Entry point to handle the Initializing state of the contract.
    /// If we have a keyshare, we make sure we call vote_pk.
    /// If we don't have a keyshare, we run key generation.
    async fn run_initialization(
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: KeyshareStorage,
        contract_state: ContractInitializingState,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        // ensure we have all the previous keys
        let generated_keyset = contract_state.generated_keyset;
        if let Err(e) = keyshare_storage
            .ensure_can_generate_key(generated_keyset.epoch_id, &generated_keyset.domains)
            .await
        {
            tracing::error!("Cannot participate in key generation: {:?}", e);
            return Ok(MpcJobResult::HaltUntilInterrupted);
        }

        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            contract_state.participants,
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the initial candidates list; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        tracking::set_progress(&format!(
            "Generating key as participant {}",
            mpc_config.my_participant_id
        ));

        // todo: lets see if this timout can be removed.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;

        // Must wait for all participants to be ready before starting key generation.
        sender
            .wait_for_ready(mpc_config.participants.participants.len())
            .await?;
        let (network_client, mut channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));

        let is_leader = mpc_config.is_leader_for_keygen();
        let keyshare_storage = Arc::new(keyshare_storage);
        if !is_leader {
            'follower: loop {
                let channel = channel_receiver.recv().await.unwrap();
                let task_id = channel.task_id();
                let MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyGeneration {
                    key_event: task_key_event_id,
                }) = task_id
                else {
                    tracing::info!(
                        "Expected Keygeneration task id, received: {:?}; ignoring.",
                        task_id,
                    );
                    continue 'follower;
                };
                let max_timeout = 120;
                let key_event_receiver_cloned = key_event_receiver.clone();
                let mpc_config_cloned = mpc_config.clone();
                let chain_txn_sender_cloned = chain_txn_sender.clone();
                let keyshare_storage_cloned = keyshare_storage.clone();
                tokio::spawn(async move {
                    // Wait for the contract to confirm this key event
                    let mut contract_event = key_event_receiver_cloned.borrow().clone();
                    let mut n = 0; // one minute max
                    while contract_event.id != task_key_event_id && !contract_event.started {
                        if n > max_timeout {
                            anyhow::bail!("timed out");
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        contract_event = key_event_receiver_cloned.borrow().clone();
                        n += 1;
                    }
                    if contract_event
                        .completed
                        .contains(&mpc_config_cloned.my_participant_id)
                    {
                        anyhow::bail!(
                            "We already completed this resharing. Why is there a second attempt?"
                        );
                    }
                    tracing::info!(
                        "Joining ecdsa secp256k1 key generation for key id {:?}",
                        contract_event.id
                    );
                    // join computation
                    // note: we could inline this, but maybe better to wait and see how other
                    // singauter schemes will be handled.
                    let res = EcdsaSignatureProvider::run_key_generation_client(
                        mpc_config_cloned.clone(),
                        channel,
                    )
                    .await?;
                    tracing::info!("Ecdsa secp256k1 key generation completed.");
                    let keyshare = Keyshare {
                        key_id: contract_event.id,
                        data: KeyshareData::Secp256k1(res.clone()),
                    };
                    keyshare_storage_cloned.store_key(keyshare).await?;
                    tracing::info!("Key generation complete; Follower calls vote_pk.");
                    chain_txn_sender_cloned
                        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                            key_event_id: contract_event.id,
                            public_key: affine_point_to_public_key(res.public_key)?,
                        }))
                        .await?;
                    Ok(())
                });
            }
        } else {
            let n_participants = mpc_config.participants.participants.len();
            'leader: loop {
                let mut contract_event = key_event_receiver.borrow_and_update().clone();
                if !contract_event.started {
                    tracing::info!(
                        "Leader is starting ecdsa secp256k1 key generation for key id {:?}",
                        contract_event.id
                    );
                    // open the channel
                    let channel = network_client.new_channel_for_task(
                        EcdsaTaskId::KeyGeneration {
                            key_event: contract_event.id.clone(),
                        },
                        network_client.all_participant_ids(),
                    )?;
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::StartKeygen(
                            ChainStartKeygenArgs {},
                        ))
                        .await?;
                    // note: we could inline below function, but maybe better to wait and see how other
                    // singauter schemes will be handled.
                    let res = EcdsaSignatureProvider::run_key_generation_client(
                        mpc_config.clone(),
                        channel,
                    )
                    .await?;
                    let keyshare = Keyshare {
                        key_id: contract_event.id.clone(),
                        data: KeyshareData::Secp256k1(res.clone()),
                    };
                    keyshare_storage.store_key(keyshare).await?;
                    let my_public_key = affine_point_to_public_key(res.public_key)?;
                    let key_event_id = contract_event.id;
                    while contract_event.completed.len() != n_participants - 1 {
                        contract_event = key_event_receiver.borrow_and_update().clone();
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    if contract_event.id != key_event_id {
                        tracing::info!("Key generation timed out.");
                        continue 'leader;
                    }
                    tracing::info!("Key generation complete; Leader calls vote_pk.");
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                            key_event_id: contract_event.id,
                            public_key: my_public_key,
                        }))
                        .await?;
                }
            }
        }
    }

    /// Entry point to handle the Running state of the contract.
    /// In this state, we generate triples and presignatures, and listen to
    /// signature requests and submit signature responses.
    #[allow(clippy::too_many_arguments)]
    async fn run_mpc(
        clock: Clock,
        secret_db: Arc<SecretDB>,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: KeyshareStorage,
        contract_state: ContractRunningState,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        signature_debug_request_receiver: broadcast::Receiver<SignatureDebugRequest>,
    ) -> anyhow::Result<MpcJobResult> {
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            contract_state.participants,
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the current epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        let keyshares = match keyshare_storage.load_keyset(&contract_state.keyset).await {
            Ok(keyshares) => keyshares,
            Err(e) => {
                tracing::error!(
                    "Failed to load keyshares: {:?}; doing nothing until contract state change",
                    e
                );
                return Ok(MpcJobResult::HaltUntilInterrupted);
            }
        };

        if keyshares.is_empty() {
            tracing::info!("We have no keyshares. Waiting for Initialization.");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        }

        tracking::set_progress(&format!(
            "Running epoch {:?} as participant {}",
            contract_state.keyset.epoch_id, mpc_config.my_participant_id
        ));

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        sender
            .wait_for_ready(mpc_config.participants.threshold as usize)
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));

        let sign_request_store = Arc::new(SignRequestStorage::new(secret_db.clone())?);
        let KeyshareData::Secp256k1(keyshare) = &keyshares.first().unwrap().data;
        let ecdsa_signature_provider = Arc::new(EcdsaSignatureProvider::new(
            config_file.clone().into(),
            mpc_config.clone().into(),
            network_client.clone(),
            clock,
            secret_db,
            sign_request_store.clone(),
            keyshare.clone(),
        )?);

        let mpc_client = Arc::new(MpcClient::new(
            config_file.clone().into(),
            network_client,
            sign_request_store,
            ecdsa_signature_provider,
        ));
        mpc_client
            .run(
                channel_receiver,
                block_update_receiver,
                chain_txn_sender,
                signature_debug_request_receiver,
            )
            .await?;

        Ok(MpcJobResult::Done)
    }
    async fn run_key_resharing(
        secret_db: Arc<SecretDB>,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: KeyshareStorage,
        resharing_state: ContractResharingState,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            resharing_state.new_participants.clone(),
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the new epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        let was_participant_last_epoch = resharing_state
            .previous_running_state
            .participants
            .participants
            .iter()
            .any(|p| p.near_account_id == config_file.my_near_account_id);

        if let Err(e) = keyshare_storage
            .ensure_can_reshare_key(
                resharing_state.reshared_keys.epoch_id,
                &resharing_state.reshared_keys.domains,
            )
            .await
        {
            tracing::error!("Cannot participate in key resharing: {:?}", e);
            return Ok(MpcJobResult::HaltUntilInterrupted);
        }
        let previous_keyset = &resharing_state.previous_running_state.keyset;
        let existing_keyshares = if was_participant_last_epoch {
            match keyshare_storage.load_keyset(previous_keyset).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!(
                        "Failed to load keyshare for epoch {:?}: {:?}; doing nothing until contract state change",
                        previous_keyset.epoch_id,
                        e
                    );
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                }
            }
        } else {
            if keyshare_storage.load_keyset(previous_keyset).await.is_ok() {
                tracing::info!("We should not have theses")
            }
            Vec::new()
        };
        // Delete all presignatures from the previous epoch; they are no longer usable
        // once we reshare keys.
        tracing::info!("Deleting all presignatures...");
        let mut update = secret_db.update();
        let _ = update.delete_all(DBCol::Presignature);
        let _ = update.commit();
        tracing::info!("Deleted all presignatures");
        // TODO: see if we can remove this.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        // Must wait for all participants to be ready before starting key generation.
        sender
            .wait_for_ready(mpc_config.participants.participants.len())
            .await?;
        let (network_client, mut channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        let is_leader = mpc_config.is_leader_for_keygen();
        let keyshare_storage = Arc::new(keyshare_storage);
        if !is_leader {
            'follower: loop {
                let channel = channel_receiver.recv().await.unwrap();
                let task_id = channel.task_id();
                let MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing {
                    key_event: task_key_event_id,
                }) = task_id
                else {
                    tracing::info!(
                        "Expected Keygeneration task id, received: {:?}; ignoring.",
                        task_id,
                    );
                    continue 'follower;
                };
                let key_event_receiver_cloned = key_event_receiver.clone();
                let chain_txn_sender_cloned = chain_txn_sender.clone();

                let max_timeout = 120;
                let keyshare_storage_ref = keyshare_storage.clone();
                let resharing_state_cloned = resharing_state.clone();
                let existing_keyshares_cloned = existing_keyshares.clone();
                let mpc_config_cloned = mpc_config.clone();
                tokio::spawn(async move {
                    // Wait for the contract to confirm this key event
                    let mut contract_event = key_event_receiver_cloned.borrow().clone();
                    let mut n = 0; // one minute max
                    while contract_event.id != task_key_event_id && !contract_event.started {
                        if n > max_timeout {
                            anyhow::bail!("timed out");
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        contract_event = key_event_receiver_cloned.borrow().clone();
                        n += 1;
                    }
                    if contract_event
                        .completed
                        .contains(&mpc_config_cloned.my_participant_id)
                    {
                        anyhow::bail!(
                            "We already completed this resharing. Why is there a second attempt?"
                        );
                    }
                    tracing::info!(
                        "Joining ecdsa secp256k1 key resharing for key id {:?}",
                        contract_event.id
                    );
                    // join computation
                    let my_share = existing_keyshares_cloned
                        .clone()
                        .iter()
                        .find(|share| share.key_id == contract_event.id)
                        .map(|share| share.data.clone())
                        .map(|KeyshareData::Secp256k1(data)| data.private_share);
                    // todo: fix the silly conversion chain below.
                    let public_key = resharing_state_cloned
                        .previous_running_state
                        .keyset
                        .public_key(task_key_event_id.domain_id)
                        .unwrap();
                    let public_key = near_crypto::PublicKey::from_str(&String::from(&public_key));
                    let public_key = public_key_to_affine_point(public_key.unwrap().into())?;
                    let res = EcdsaSignatureProvider::run_key_resharing_client(
                        mpc_config_cloned.clone().into(),
                        my_share,
                        public_key,
                        &resharing_state_cloned.previous_running_state.participants,
                        channel,
                    )
                    .await?;
                    let keyshare = Keyshare {
                        key_id: contract_event.id,
                        data: KeyshareData::Secp256k1(res),
                    };
                    keyshare_storage_ref.store_key(keyshare).await?;
                    tracing::info!("Key resharing complete; Follower calls vote_pk.");
                    chain_txn_sender_cloned
                        .send(ChainSendTransactionRequest::VoteReshared(
                            ChainVoteResharedArgs {
                                key_event_id: contract_event.id,
                            },
                        ))
                        .await?;
                    Ok(())
                });
            }
        } else {
            let n_participants = mpc_config.participants.participants.len();
            'leader: loop {
                let mut contract_event = key_event_receiver.borrow_and_update().clone();
                if !contract_event.started {
                    tracing::info!(
                        "Leader is starting ecdsa secp256k1 key resharing for key id {:?}",
                        contract_event.id
                    );
                    // open the channel
                    let channel = network_client.new_channel_for_task(
                        EcdsaTaskId::KeyResharing {
                            key_event: contract_event.id.clone(),
                        },
                        network_client.all_participant_ids(),
                    )?;
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::StartReshare(
                            ChainStartReshareArgs {},
                        ))
                        .await?;
                    let my_share = existing_keyshares
                        .iter()
                        .find(|share| share.key_id == contract_event.id)
                        .map(|share| share.data.clone())
                        .map(|KeyshareData::Secp256k1(data)| data.private_share);
                    // todo: fix the silly conversion chain below.
                    let public_key = resharing_state
                        .previous_running_state
                        .keyset
                        .public_key(contract_event.id.domain_id)
                        .unwrap();
                    let public_key = near_crypto::PublicKey::from_str(&String::from(&public_key));
                    let public_key = public_key_to_affine_point(public_key.unwrap().into())?;
                    let res = EcdsaSignatureProvider::run_key_resharing_client(
                        mpc_config.clone().into(),
                        my_share,
                        public_key,
                        &resharing_state.previous_running_state.participants,
                        channel,
                    )
                    .await?;
                    let keyshare = Keyshare {
                        key_id: contract_event.id.clone(),
                        data: KeyshareData::Secp256k1(res.clone()),
                    };
                    keyshare_storage.store_key(keyshare).await?;
                    tracing::info!("Key resharing complete; Leader waits for completion.");
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::VoteReshared(
                            ChainVoteResharedArgs {
                                key_event_id: contract_event.id,
                            },
                        ))
                        .await?;
                    let key_event_id = contract_event.id;
                    while contract_event.completed.len() != n_participants - 1 {
                        contract_event = key_event_receiver.borrow_and_update().clone();
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    if contract_event.id != key_event_id {
                        tracing::info!("Key generation timed out.");
                        continue 'leader;
                    }
                    let my_public_key = affine_point_to_public_key(res.public_key)?;
                    tracing::info!("Key generation complete; Leader calls vote_pk.");
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                            key_event_id: contract_event.id,
                            public_key: my_public_key,
                        }))
                        .await?;
                }
            }
        }
    }
}

fn sleep(clock: &Clock, duration: Duration) -> BoxFuture<'static, ()> {
    let clock = clock.clone();
    async move {
        clock.sleep(duration).await;
    }
    .boxed()
}

/// Simple RAII to export current job name to metrics and /debug/tasks.
struct ReportCurrentJobGuard {
    name: String,
    currently_running_job_name: Arc<Mutex<String>>,
}

impl ReportCurrentJobGuard {
    fn new(name: &str, currently_running_job_name: Arc<Mutex<String>>) -> Self {
        metrics::MPC_CURRENT_JOB_STATE
            .with_label_values(&[name])
            .inc();
        tracking::set_progress(name);
        *currently_running_job_name.lock().unwrap() = name.to_string();
        Self {
            name: name.to_string(),
            currently_running_job_name,
        }
    }
}

impl Drop for ReportCurrentJobGuard {
    fn drop(&mut self) {
        metrics::MPC_CURRENT_JOB_STATE
            .with_label_values(&[&self.name])
            .dec();
        tracking::set_progress("Transitioning state");
        *self.currently_running_job_name.lock().unwrap() = "".to_string();
    }
}
