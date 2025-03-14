use crate::config::{ConfigFile, MpcConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::indexer::handler::ChainBlockUpdate;
use crate::indexer::participants::{
    ContractInitializingState, ContractResharingState, ContractRunningState, ContractState,
};
use crate::indexer::types::{ChainSendTransactionRequest, ChainVotePkArgs, ChainVoteResharedArgs};
use crate::indexer::IndexerAPI;
use crate::key_generation::{affine_point_to_public_key, run_key_generation_client};
use crate::key_resharing::run_key_resharing_client;
use crate::keyshare::{KeyshareStorage, KeyshareStorageFactory};
use crate::metrics;
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::new_tls_mesh_network;
use crate::primitives::HasParticipants;
use crate::runtime::AsyncDroppableRuntime;
use crate::sign::PresignatureStorage;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self};
use crate::triple::TripleStorage;
use crate::web::SignatureDebugRequest;
use futures::future::BoxFuture;
use futures::FutureExt;
use near_time::{Clock, Duration};
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

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
            let state = self.indexer.contract_state_receiver.borrow().clone();
            let mut job = match state {
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
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Initializing(new_state) => {
                                new_state.participants != state.participants
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
                            ContractState::Running(new_state) => new_state.epoch != state.epoch,
                            _ => true,
                        }),
                        timeout_fut: futures::future::pending().boxed(),
                    }
                }
                ContractState::Resharing(state) => {
                    // In resharing state, we perform key resharing, again with a timeout.
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
                                state.clone(),
                                self.indexer.txn_sender.clone(),
                                // here, pass self.indexer.reshare_instance_receiver
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Resharing(new_state) => {
                                new_state.old_epoch != state.old_epoch// add comparison for instance id? or just pass through channel?
                                    || new_state.new_participants != state.new_participants
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
    ) -> anyhow::Result<MpcJobResult> {
        let existing_key = keyshare_storage.load().await?;
        if let Some(existing_key) = existing_key {
            if existing_key.epoch != 0 {
                tracing::error!(
                    "Contract is in initialization state. We already have a keyshare, but its epoch is not zero. Refusing to participate in initialization"
                );
                // This is an error situation; we can't recover from it so we just halt.
                return Ok(MpcJobResult::HaltUntilInterrupted);
            }

            let my_public_key = affine_point_to_public_key(existing_key.public_key)?;
            if let Some(votes) = contract_state.pk_votes.get(&my_public_key) {
                if votes.contains(&config_file.my_near_account_id) {
                    tracing::info!("Initialization: we already voted for our public key; waiting for public key consensus");
                    // Wait indefinitely. We will be terminated when config changes, or when we timeout.
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                }
            }

            tracing::info!("Contract is in initialization state. We have our keyshare. Sending vote_pk to vote for our public key");

            chain_txn_sender
                .send(ChainSendTransactionRequest::VotePk(ChainVotePkArgs {
                    public_key: my_public_key,
                }))
                .await?;

            // Like above, just wait.
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

        // TODO(#195): We do not have proper retry or failure handling for key generation.
        // To lower the risk of test flakiness, we will sleep 2 seconds to avoid repeated
        // failures like the scenario described in #151.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;

        // Must wait for all participants to be ready before starting key generation.
        sender
            .wait_for_ready(mpc_config.participants.participants.len())
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        run_key_generation_client(
            mpc_config.clone().into(),
            network_client,
            keyshare_storage,
            channel_receiver,
        )
        .await?;
        tracing::info!("Key generation complete");
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

        let keyshare = keyshare_storage.load().await?;
        let keyshare = match keyshare {
            Some(keyshare) if keyshare.epoch == contract_state.epoch => keyshare,
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
            "Running epoch {} as participant {}",
            contract_state.epoch, mpc_config.my_participant_id
        ));

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        sender
            .wait_for_ready(mpc_config.participants.threshold as usize)
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));

        let active_participants_query = {
            let network_client = network_client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        let triple_store = Arc::new(TripleStorage::new(
            clock.clone(),
            secret_db.clone(),
            DBCol::Triple,
            network_client.my_participant_id(),
            |participants, pair| pair.is_subset_of_active_participants(participants),
            active_participants_query.clone(),
        )?);

        let presignature_store = Arc::new(PresignatureStorage::new(
            clock,
            secret_db.clone(),
            DBCol::Presignature,
            network_client.my_participant_id(),
            |participants, presignature| {
                presignature.is_subset_of_active_participants(participants)
            },
            active_participants_query,
        )?);

        let sign_request_store = Arc::new(SignRequestStorage::new(secret_db.clone())?);

        let mpc_client = Arc::new(MpcClient::new(
            config_file.clone().into(),
            mpc_config.clone().into(),
            network_client,
            triple_store,
            presignature_store,
            sign_request_store,
            keyshare,
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
        contract_state: ContractResharingState,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        // reshare_instance_receiver
    ) -> anyhow::Result<MpcJobResult> {
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            contract_state.new_participants.clone(),
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the new epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        let was_participant_last_epoch = contract_state
            .old_participants
            .participants
            .iter()
            .any(|p| p.near_account_id == config_file.my_near_account_id);

        let existing_keyshare = match keyshare_storage.load().await? {
            Some(existing_keyshare) => {
                // only enter this if the full key event id matches.
                if existing_keyshare.epoch == contract_state.old_epoch + 1 {
                    // check key id: a mismatch should (theoretically) never happen.
                    if contract_state
                        .finished_votes
                        .contains(&config_file.my_near_account_id)
                    {
                        tracing::info!(
                            "We already performed key resharing for epoch {} and already performed vote_reshared; waiting for contract state to transition into Running",
                            contract_state.old_epoch + 1);
                    } else {
                        tracing::info!(
                            "We already performed key resharing for epoch {}; sending vote_reshared.",
                            contract_state.old_epoch + 1
                        );
                        chain_txn_sender
                            .send(ChainSendTransactionRequest::VoteReshared(
                                ChainVoteResharedArgs {
                                    epoch: contract_state.old_epoch + 1,
                                },
                            ))
                            .await?; // adjust
                        tracing::info!("Sent vote_reshared txn; waiting for contract state to transition into Running");
                    }
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                }
                if was_participant_last_epoch {
                    anyhow::ensure!(
                        existing_keyshare.epoch == contract_state.old_epoch,
                        "We were a participant last epoch, but we somehow have a key of epoch #{}",
                        existing_keyshare.epoch
                    );
                    Some(existing_keyshare)
                } else {
                    anyhow::ensure!(
                        existing_keyshare.epoch < contract_state.old_epoch,
                        "We were not a participant last epoch, but we somehow have a key of epoch #{}",
                        existing_keyshare.epoch
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

        tracking::set_progress(&format!(
            "Resharing for epoch {} as participant {}",
            contract_state.old_epoch + 1,
            mpc_config.my_participant_id
        ));

        // Delete all presignatures from the previous epoch; they are no longer usable
        // once we reshare keys.
        tracing::info!("Deleting all presignatures...");
        let mut update = secret_db.update();
        update.delete_all(DBCol::Presignature)?;
        update.commit()?;
        tracing::info!("Deleted all presignatures");

        // TODO(#195): We do not have proper retry or failure handling for key resharing.
        // To lower the risk of test flakiness, we will sleep 2 seconds to avoid repeated
        // failures like the scenario described in #151.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;

        // Must wait for all participants to be ready before starting key generation.
        sender
            .wait_for_ready(mpc_config.participants.participants.len())
            .await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        run_key_resharing_client(
            mpc_config.clone().into(),
            network_client,
            contract_state,
            existing_keyshare.map(|k| k.private_share),
            keyshare_storage,
            channel_receiver,
        )
        .await?;
        tracing::info!("Key resharing complete; will call vote_reshared next");
        // Exit; we'll immediately re-enter the same function and send vote_reshared.
        // maybe send vote_instance_complete() here, before exiting.
        //

        // leader needs to observe the contract state here.
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
