use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB};
use crate::indexer::handler::ChainBlockUpdate;
use crate::indexer::participants::{ContractKeyEventInstance, ContractRunningState, ContractState};
use crate::indexer::types::ChainSendTransactionRequest;
use crate::indexer::IndexerAPI;
use crate::key_events::{
    keygen_follower, keygen_leader, resharing_follower, resharing_leader, ResharingArgs,
};
use crate::keyshare::KeyStorageConfig;
use crate::keyshare::{KeyshareData, KeyshareStorage};
use crate::metrics;
use crate::mpc_client::MpcClient;
use crate::network::{run_network_client, MeshNetworkTransportSender};
use crate::p2p::new_tls_mesh_network;
use crate::providers::eddsa::EddsaSignatureProvider;
use crate::providers::EcdsaSignatureProvider;
use crate::runtime::AsyncDroppableRuntime;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self};
use crate::web::SignatureDebugRequest;
use cait_sith::{ecdsa, eddsa};
use futures::future::BoxFuture;
use futures::FutureExt;
use mpc_contract::primitives::domain::{DomainId, SignatureScheme};
use near_time::Clock;
use std::collections::HashMap;
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
}

#[derive(Debug)]
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
            tracing::info!("New state is: {:?}", state);
            let mut job: MpcJob = match state {
                ContractState::WaitingForSync => {
                    // This is the initial state. We stop this state for any state changes.
                    MpcJob {
                        name: "WaitingForSync",
                        fut: futures::future::ready(Ok(MpcJobResult::HaltUntilInterrupted)).boxed(),
                        stop_fn: Box::new(|_| true),
                    }
                }
                ContractState::Invalid => {
                    // Invalid state. Similar to initial state; we do nothing until the state changes.
                    MpcJob {
                        name: "Invalid",
                        fut: futures::future::ready(Ok(MpcJobResult::HaltUntilInterrupted)).boxed(),
                        stop_fn: Box::new(|_| true),
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
                                self.key_storage_config.create().await?.into(),
                                state.participants.clone(),
                                self.indexer.txn_sender.clone(),
                                key_event_receiver,
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Initializing(new_state) => {
                                if new_state.key_event.id.epoch_id != state.key_event.id.epoch_id {
                                    tracing::info!("dropping initializing");
                                    true
                                } else {
                                    key_event_sender.send(new_state.key_event.clone()).is_err()
                                }
                            }
                            _ => {
                                tracing::info!("dropping initializing");
                                true
                            }
                        }),
                    }
                }
                ContractState::Running(state) => {
                    // For the running state, we run the full MPC protocol.
                    // There's no timeout. The only time we stop is when the contract state
                    // changes to no longer be running (or if somehow the epoch changes).
                    tracing::debug!("Entering Running branch");
                    let storage = self.key_storage_config.create().await;
                    tracing::info!("Fetching Key Storage: {:?}", storage);

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
                                storage?,
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
                                self.key_storage_config.create().await?.into(),
                                state.previous_running_state.clone(),
                                state.new_participants.clone(),
                                self.indexer.txn_sender.clone(),
                                key_event_receiver,
                            ),
                        )?,
                        stop_fn: Box::new(move |new_state| match new_state {
                            ContractState::Resharing(new_state) => {
                                if new_state.key_event.id.epoch_id == state.key_event.id.epoch_id {
                                    // still same attempt, just send the update
                                    if key_event_sender.send(new_state.key_event.clone()).is_ok() {
                                        return false;
                                    }
                                }
                                true
                            }
                            _ => true,
                        }),
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
                    res = self.indexer.contract_state_receiver.changed() => {
                        if res.is_err() {
                            anyhow::bail!("[{}] contract state receiver closed", job.name);
                        }
                        if (job.stop_fn)(&self.indexer.contract_state_receiver.borrow()) {
                            tracing::info!(
                                "[{}] contract state changed incompatibly, stopping",
                                job.name
                            );
                            break;
                        }
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
        tracing::info!("Getting task handle");
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
            tracing::info!("Creating runtime with {:?} cores", cores);
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(std::cmp::max(n_threads, 1))
                .enable_all()
                .build()?
        } else {
            tracing::info!("Creating runtime with default");
            tokio::runtime::Runtime::new()?
        };
        tracing::info!("Creating AsyncDroppableRuntime");
        let mpc_runtime = AsyncDroppableRuntime::new(mpc_runtime);
        tracing::info!("Spawning on AsyncDroppableRuntime");
        let fut = mpc_runtime.spawn(task_handle.scope(description, task));
        Ok(async move {
            let _mpc_runtime = mpc_runtime;
            let l1 = fut.await;
            tracing::info!("Nested future await {:?}", l1);
            anyhow::Ok(l1??)
        }
        .boxed())
    }

    /// Entry point to handle the Initializing state of the contract.
    async fn run_initialization(
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: Arc<KeyshareStorage>,
        participants: ParticipantsConfig,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            participants,
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the current epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        tracking::set_progress(&format!(
            "Generating key(s) as participant {}",
            mpc_config.my_participant_id
        ));

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        if mpc_config.is_leader_for_key_event() {
            keygen_leader(
                network_client,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                mpc_config.participants.threshold as usize,
            )
            .await?;
        } else {
            keygen_follower(
                channel_receiver,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                mpc_config.participants.threshold as usize,
            )
            .await?;
        }
        Ok(MpcJobResult::Done)
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
        tracing::info!("Entering running state: {}", mpc_config.my_participant_id);

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

        let mut ecdsa_keyshares: HashMap<DomainId, ecdsa::KeygenOutput> = HashMap::new();
        let mut eddsa_keyshares: HashMap<DomainId, eddsa::KeygenOutput> = HashMap::new();
        let mut domain_to_scheme: HashMap<DomainId, SignatureScheme> = HashMap::new();

        for keyshare in keyshares {
            let domain_id = keyshare.key_id.domain_id;
            match keyshare.data {
                KeyshareData::Secp256k1(data) => {
                    ecdsa_keyshares.insert(keyshare.key_id.domain_id, data);
                    domain_to_scheme.insert(domain_id, SignatureScheme::Secp256k1);
                }
                KeyshareData::Ed25519(data) => {
                    eddsa_keyshares.insert(keyshare.key_id.domain_id, data);
                    domain_to_scheme.insert(domain_id, SignatureScheme::Ed25519);
                }
            }
        }

        let ecdsa_signature_provider = Arc::new(EcdsaSignatureProvider::new(
            config_file.clone().into(),
            mpc_config.clone().into(),
            network_client.clone(),
            clock,
            secret_db,
            sign_request_store.clone(),
            ecdsa_keyshares,
        )?);

        let eddsa_signature_provider = Arc::new(EddsaSignatureProvider::new(
            config_file.clone().into(),
            mpc_config.clone().into(),
            network_client.clone(),
            sign_request_store.clone(),
            eddsa_keyshares,
        ));

        let mpc_client = Arc::new(MpcClient::new(
            config_file.clone().into(),
            network_client,
            sign_request_store,
            ecdsa_signature_provider,
            eddsa_signature_provider,
            domain_to_scheme,
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
    #[allow(clippy::too_many_arguments)]
    async fn run_key_resharing(
        secret_db: Arc<SecretDB>,
        secrets: SecretsConfig,
        config_file: ConfigFile,
        keyshare_storage: Arc<KeyshareStorage>,
        previous_running_state: ContractRunningState,
        new_participants: ParticipantsConfig,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            new_participants.clone(),
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the new epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        let previous_keyset = previous_running_state.keyset;
        let was_participant_last_epoch = previous_running_state
            .participants
            .participants
            .iter()
            .any(|p| p.near_account_id == config_file.my_near_account_id);
        let existing_keyshares = if was_participant_last_epoch {
            let keyshares = match keyshare_storage.load_keyset(&previous_keyset).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::error!(
                        "Failed to load keyshare for epoch {:?}: {:?}; doing nothing until contract state change",
                        previous_keyset.epoch_id,
                        e
                    );
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                }
            };
            Some(keyshares)
        } else {
            if keyshare_storage.load_keyset(&previous_keyset).await.is_ok() {
                tracing::warn!("We should not have the previous keyshares when we were not a participant last epoch");
            }
            None
        };
        // Delete all triples and presignatures from the previous epoch;
        // they are no longer usable once we reshare keys. Presignatures are dependent on key so
        // those are completely invalidated, and triples may have different threshold or assume
        // different participants, so it would be too much trouble to keep them around.
        tracing::info!("Deleting all triples and presignatures...");
        let mut update = secret_db.update();
        let _ = update.delete_all(DBCol::Presignature);
        let _ = update.delete_all(DBCol::Triple);
        let _ = update.commit();
        tracing::info!("Deleted all presignatures");
        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        let (network_client, channel_receiver, _handle) =
            run_network_client(Arc::new(sender), Box::new(receiver));
        let args = Arc::new(ResharingArgs {
            previous_keyset,
            existing_keyshares,
            new_threshold: mpc_config.participants.threshold as usize,
            old_participants: previous_running_state.participants,
        });
        if mpc_config.is_leader_for_key_event() {
            resharing_leader(
                network_client,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                args,
            )
            .await?;
        } else {
            resharing_follower(
                channel_receiver,
                keyshare_storage,
                key_event_receiver,
                chain_txn_sender,
                args,
            )
            .await?;
        }
        Ok(MpcJobResult::Done)
    }
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
