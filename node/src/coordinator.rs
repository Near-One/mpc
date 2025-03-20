use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::hkdf::affine_point_to_public_key;
use crate::indexer::handler::ChainBlockUpdate;
use crate::indexer::participants::{
    ContractInitializingState, ContractKeyEventInstance, ContractRunningState, ContractState,
};
use crate::indexer::types::{
    ChainSendTransactionRequest, ChainStartKeygenArgs, ChainStartReshareArgs, ChainVotePkArgs,
    ChainVoteResharedArgs,
};
use crate::indexer::IndexerAPI;
use crate::keyshare::{
    KeyShare, KeyShareData, KeyshareStorage, KeyshareStorageFactory, Secp256k1Data,
};
use crate::mpc_client::MpcClient;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{run_network_client, MeshNetworkClient, MeshNetworkTransportSender};
use crate::p2p::new_tls_mesh_network;
use crate::primitives::MpcTaskId;
use crate::providers::{EcdsaSignatureProvider, EcdsaTaskId, SignatureProvider};
use crate::runtime::AsyncDroppableRuntime;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self};
use crate::web::SignatureDebugRequest;
use crate::{metrics, providers};
use futures::future::BoxFuture;
use futures::FutureExt;
use mpc_contract::primitives::domain::SignatureScheme;
use mpc_contract::primitives::key_state::KeyEventId;
use near_time::{Clock, Duration};
use std::future::Future;
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
    /// Storage for keyshare.
    pub keyshare_storage_factory: KeyshareStorageFactory,

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
                                self.keyshare_storage_factory.create().await?,
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
                                self.keyshare_storage_factory.create().await?,
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
                                self.keyshare_storage_factory.create().await?,
                                state.current_state,
                                state.new_participants,
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
        keyshare_storage: Box<dyn KeyshareStorage>,
        contract_state: ContractInitializingState,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            contract_state.participants,
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the initial candidates list; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        // Get existing keyshares. This call is expected to throw an error if not all keyshares are available.
        let existing_keyshare = keyshare_storage.load_keyset(&contract_state.keyset).await?;
        tracing::info!("Contract is in initialization state. We have our keyshares.");

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

        // follower loop:

        loop {
            //let task_id = expected_task_id.into();
            'awaiting_task: loop {
                let channel = channel_receiver.recv().await.unwrap();
                let task_id = channel.task_id();
                let MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing {
                    key_event: task_key_event_id,
                }) = task_id
                else {
                    tracing::info!(
                        "Expected Resharing task id, received: {:?}; ignoring.",
                        task_id,
                    );
                    continue 'awaiting_task;
                };
                let contract_event = key_event_receiver.borrow_and_update().clone();
                if task_key_event_id == contract_event.id && contract_event.started_in.is_some() {
                    tracing::info!(
                        "Joining ecdsa secp256k1 key generation for key id {:?}",
                        contract_event.id
                    );
                    // join computation
                    let threshold = mpc_config.participants.threshold as usize;
                    let comp =
                        providers::ecdsa::key_generation::KeyGenerationComputation { threshold };
                    let res = MpcLeaderCentricComputation::perform_leader_centric_computation(
                        comp,
                        channel,
                        std::time::Duration::from_secs(60),
                    )
                    .await?;
                    tracing::info!("Ecdsa secp256k1 key generation completed.");
                    let keyshare = KeyShare {
                        key_id: contract_event.id,
                        data: KeyShareData::Secp256k1(Secp256k1Data {
                            private_share: res.private_share,
                            public_key: res.public_key,
                        }),
                    };
                    keyshare_storage.store(&keyshare);
                    let my_public_key = affine_point_to_public_key(res.public_key)?;
                    tracing::info!("Key generation complete; Follower calls vote_pk.");
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                            key_event_id: contract_event.id,
                            public_key: my_public_key,
                        }))
                        .await?;
                    continue;
                }

                break;
            }
            break;
            //   let channel = MeshNetworkClient::wait_for_task(
            //       channel_receiver,
            //       EcdsaTaskId::KeyGeneration { key_event: key_id },
            //   )
            //   .await;
        }

        // start key generation:
        let is_leader = mpc_config.is_leader_for_keygen();

        loop {
            let mut current_event = key_event_receiver.borrow_and_update().clone();
        }

        let n_participants = mpc_config.participants.participants.len();

        let started_in = current_event.last_updated;
        while !current_event.started_in.is_some() {
            if is_leader {
                tracing::info!("We are waiting for all other participants");
                let indexer_heights = network_client.get_indexer_heights();
                let mut ready = true;
                for (p_id, h) in indexer_heights {
                    if h < started_in {
                        tracing::info!(
                            "Waiting on participant {:?}, who is still at height {}",
                            p_id,
                            h
                        );
                        ready = false;
                    }
                }
                if ready {
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::StartKeygen(
                            ChainStartKeygenArgs {},
                        ))
                        .await?;
                }
            }
            // wait for the reshare to start:
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            current_event = key_event_receiver.borrow_and_update().clone();
        }

        //    let channel = if is_leader {
        //        network_client.new_channel_for_task(
        //            EcdsaTaskId::KeyGeneration { key_event: key_id },
        //            network_client.all_participant_ids(),
        //        )?
        //    } else {
        //        MeshNetworkClient::wait_for_task(
        //            channel_receiver,
        //            EcdsaTaskId::KeyGeneration { key_event: key_id },
        //        )
        //        .await
        //    };

        //    let threshold = mpc_config.participants.threshold as usize;
        //    let key = KeyGenerationComputation { threshold }
        //        .perform_leader_centric_computation(
        //            channel,
        //            // TODO(#195): Move timeout here instead of in Coordinator.
        //            std::time::Duration::from_secs(60),
        //        )
        //        .await?;
        //    tracing::info!("Ecdsa secp256k1 key generation completed");

        //    Ok(key)
        //}
        let key = EcdsaSignatureProvider::run_key_generation_client(
            mpc_config,
            network_client,
            &mut channel_receiver,
            current_event.id,
            is_leader,
        )
        .await?;

        let my_public_key = affine_point_to_public_key(key.public_key)?;
        // todo: store to temporary keystore here
        if !is_leader {
            tracing::info!("Key generation complete; Follower calls vote_pk.");
            chain_txn_sender
                .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                    key_event_id: current_event.id,
                    public_key: my_public_key,
                }))
                .await?;
            while current_event.completed.len() != n_participants {
                // wait for the reshare to start:
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                current_event = key_event_receiver.borrow_and_update().clone();
                tracing::info!("Key generation complete; Follower waiting for leader.");
            }
        } else {
            // as the leader, we wait for everyone else to vote
            while current_event.completed.len() != n_participants - 1 {
                // wait for the reshare to start:
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                current_event = key_event_receiver.borrow_and_update().clone();
                tracing::info!("Key generation complete; Leader waiting for followers.");
            }
            tracing::info!("Key generation complete; Leader calls vote_pk.");
            chain_txn_sender
                .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                    key_event_id: current_event.id,
                    public_key: my_public_key,
                }))
                .await?;
        }

        keyshare_storage
            .store(&KeyShare::new(current_event.id, key.clone()))
            .await?;

        tracing::info!("Key generation complete;");
        // Exit; we'll immediately re-enter the same function and send vote_pk.
        anyhow::Ok(MpcJobResult::Done)
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
        keyshare_storage: Box<dyn KeyshareStorage>,
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
            // TODO(#150): Implement sending join txn.
            tracing::info!("We are not a participant in the current epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };
        let Some(contract_key) = contract_state.keyset.domains.first() else {
            tracing::error!("missing keyshares");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };
        if contract_key.domain.scheme != SignatureScheme::Secp256k1 {
            anyhow::bail!("not implemented");
        }
        let contract_key_id = KeyEventId::new(
            contract_state.keyset.epoch_id,
            contract_key.domain.id,
            contract_key.attempt,
        );
        let keyshare = keyshare_storage.load().await?;
        let keyshare = match keyshare {
            Some(keyshare) if keyshare.key_id == contract_key_id => keyshare,
            _ => {
                // This case can happen if a participant is misconfigured or lost its keyshare.
                // We can't do anything. The only way to recover if the keyshare is truly lost
                // is to leave and rejoin the network.
                tracing::error!(
                    "This node is a participant in the current epoch but is missing a keyshare."
                );
                return Ok(MpcJobResult::HaltUntilInterrupted);
            }
        };
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

        let ecdsa_signature_provider = Arc::new(EcdsaSignatureProvider::new(
            config_file.clone().into(),
            mpc_config.clone().into(),
            network_client.clone(),
            clock,
            secret_db,
            sign_request_store.clone(),
            keyshare.keygen_output(),
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

    /// Entry point to handle the Resharing state of the contract.
    /// In this state, we perform key resharing and call vote_reshared.
    async fn run_key_resharing(
        secret_db: Arc<SecretDB>,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: Box<dyn KeyshareStorage>,
        previous_state: ContractRunningState,
        new_participants: ParticipantsConfig,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        mut key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        let mut current_event = key_event_receiver.borrow_and_update().clone();
        let n_participants = new_participants.participants.len();
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            new_participants.clone(),
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the new epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };
        let was_participant_last_epoch = previous_state
            .participants
            .participants
            .iter()
            .any(|p| p.near_account_id == config_file.my_near_account_id);
        // todo: adjust for multiple domains
        let existing_keyshare = match keyshare_storage.load().await? {
            Some(existing_keyshare) => {
                // only enter this if the full key event id matches.
                if existing_keyshare.key_id == current_event.id {
                    // We already have a matching key. We vote for the event to conclude:
                    if current_event
                        .completed
                        .contains(&mpc_config.my_participant_id)
                    {
                        tracing::info!(
                            "We already performed key resharing for key event {:?} and already performed vote_reshared; waiting for contract state to transition into Running",
                            current_event.id);
                    } else {
                        tracing::info!(
                        "We already performed key resharing for event {:?}; sending vote_reshared.",
                        current_event.id
                    );
                        chain_txn_sender
                            .send(ChainSendTransactionRequest::VoteReshared(
                                ChainVoteResharedArgs {
                                    key_event_id: existing_keyshare.key_id,
                                },
                            ))
                            .await?;
                        tracing::info!("Sent vote_reshared txn; waiting for contract state to transition into Running");
                    }
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                }
                // Get the previous key id from the contract. This is the id of the key that will be reshared.
                let Some(previous_key) = previous_state.keyset.domains.first() else {
                    tracing::error!("missing keyshares");
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                };
                if previous_key.domain.scheme != SignatureScheme::Secp256k1 {
                    anyhow::bail!("not implemented");
                }
                let previous_key_id = KeyEventId::new(
                    previous_state.keyset.epoch_id,
                    previous_key.domain.id,
                    previous_key.attempt,
                );
                if was_participant_last_epoch {
                    // If we were a participant of the previous epoch, we ensure the key from the keystore matches the one from the contract.
                    anyhow::ensure!(
                        existing_keyshare.key_id == previous_key_id,
                        "We were a participant last epoch, but we somehow have a key of id #{:?}",
                        existing_keyshare.key_id
                    );
                    Some(existing_keyshare)
                } else {
                    // Else, we make sure we do not have any other key.
                    // This is a pure sanity check.
                    anyhow::ensure!(
                        existing_keyshare.key_id != previous_key_id,
                        "We were not a participant last epoch, but we somehow have a key of matching id #{:?}",
                        existing_keyshare.key_id
                    );
                    None
                }
            }
            None => {
                if was_participant_last_epoch {
                    anyhow::bail!("We were a participant last epoch, but we don't have a keyshare");
                }
                None
            }
        };
        // at this stage, if we were a participant in the previous epoch, then we have a valid keyshare
        // of the key to be reshared.
        // if we were not a participant of the previous epoch, then we have no keyshare.
        tracking::set_progress(&format!(
            "Resharing for key event {:?} as participant {}",
            current_event.id, mpc_config.my_participant_id
        ));

        // Delete all presignatures from the previous epoch; they are no longer usable
        // once we reshare keys.
        tracing::info!("Deleting all presignatures...");
        let mut update = secret_db.update();
        update.delete_all(DBCol::Presignature)?;
        update.commit()?;
        tracing::info!("Deleted all presignatures");
        // establish network connections
        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;

        // Must wait for all participants to be ready before starting key generation.
        sender
            .wait_for_ready(mpc_config.participants.participants.len())
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));

        // see if we are leader:
        let is_leader = mpc_config.is_leader_for_keygen();

        // as the leader, we ensure that everyone is ready:
        let started_in = current_event.last_updated;
        while !current_event.started_in.is_some() {
            if is_leader {
                tracing::info!("We are waiting for all other participants");
                let indexer_heights = network_client.get_indexer_heights();
                let mut ready = true;
                for (p_id, h) in indexer_heights {
                    if h < started_in {
                        tracing::info!(
                            "Waiting on participant {:?}, who is still at height {}",
                            p_id,
                            h
                        );
                        ready = false;
                    }
                }
                if ready {
                    chain_txn_sender
                        .send(ChainSendTransactionRequest::StartReshare(
                            ChainStartReshareArgs {},
                        ))
                        .await?;
                }
            }
            // wait for the keygen to start:
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            current_event = key_event_receiver.borrow_and_update().clone();
        }
        let new_keygen_output = EcdsaSignatureProvider::run_key_resharing_client(
            mpc_config.clone().into(),
            network_client,
            previous_state.keyset.domains.first().unwrap().key.clone(),
            &previous_state.participants,
            existing_keyshare.map(|k| k.private_share),
            channel_receiver,
            current_event.id,
            is_leader,
        )
        .await?;
        // todo: store to temporary keystore here
        if !is_leader {
            tracing::info!("Key resharing complete; Follower calls vote_reshared.");
            chain_txn_sender
                .send(ChainSendTransactionRequest::VoteReshared(
                    ChainVoteResharedArgs {
                        key_event_id: current_event.id,
                    },
                ))
                .await?;
            while current_event.completed.len() != n_participants {
                // wait for the reshare to start:
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                current_event = key_event_receiver.borrow_and_update().clone();
                tracing::info!("Key resharing complete; Follower waiting for leader.");
            }
        } else {
            // as the leader, we wait for everyone else to vote
            while current_event.completed.len() != n_participants - 1 {
                // wait for the reshare to start:
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                current_event = key_event_receiver.borrow_and_update().clone();
                tracing::info!("Key resharig complete; Leader waiting for followers.");
            }
            tracing::info!("Key resharing complete; Leader calls vote_reshared.");
            chain_txn_sender
                .send(ChainSendTransactionRequest::VoteReshared(
                    ChainVoteResharedArgs {
                        key_event_id: current_event.id,
                    },
                ))
                .await?;
        }

        keyshare_storage
            .store(&KeyShare::new(current_event.id, new_keygen_output))
            .await?;
        tracing::info!("Key resharing complete;");

        Ok(MpcJobResult::Done)
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
