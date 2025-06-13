use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig, SecretsConfig};
use crate::db::{DBCol, SecretDB, EPOCH_ID_KEY};
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
use crate::network::{
    run_network_client, MeshNetworkClient, MeshNetworkTransportSender, NetworkTaskChannel,
};
use crate::p2p::new_tls_mesh_network;
use crate::primitives::MpcTaskId;
use crate::providers::eddsa::{EddsaSignatureProvider, EddsaTaskId};
use crate::providers::{EcdsaSignatureProvider, EcdsaTaskId};
use crate::runtime::AsyncDroppableRuntime;
use crate::sign_request::SignRequestStorage;
use crate::tracking::{self};
use crate::web::SignatureDebugRequest;
use anyhow::Context;
use cait_sith::{ecdsa, eddsa};
use futures::future::BoxFuture;
use futures::FutureExt;
use mpc_contract::primitives::domain::{DomainId, SignatureScheme};
use mpc_contract::primitives::key_state::EpochId;
use near_time::Clock;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

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

type StopFn = Box<dyn Fn(&ContractState) -> bool + Send>;

/// Represents a top-level task that we run for the current contract state.
/// There is a different one of these for each contract state.
struct MpcJob {
    /// Friendly name for the currently running task.
    name: &'static str,
    /// The future for the MPC task (keygen, resharing, or normal run).
    fut: BoxFuture<'static, anyhow::Result<MpcJobResult>>,
    /// a function that looks at a new contract state and returns true iff the
    /// current task should be killed.
    stop_fn: StopFn,
}

/// When an MpcJob future returns successfully, it returns one of the following.
#[derive(Debug)]
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
        // This future is cancel safe
        let mut wait_for_new_mpc_state = async move || loop {
            self.indexer
                .contract_state_receiver
                .changed()
                .await
                .context("Contract state watcher closed")?;

            let (height, state) = &*self.indexer.contract_state_receiver.borrow_and_update();

            match ContractState::from_contract_state(state, *height, None) {
                Ok(state) => break anyhow::Ok(state),
                Err(err) => {
                    error!("Failed to parse contract state: {:?}", err);
                    continue;
                }
            }
        };

        // This is the initial state. We stop this state for any state changes.
        let mut job = MpcJob {
            name: "WaitingForSync",
            fut: futures::future::ready(Ok(MpcJobResult::HaltUntilInterrupted)).boxed(),
            stop_fn: Box::new(|_| true),
        };

        loop {
            // Wait for current job to be cancelled or complete by itself.
            let state =  loop {
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
                    new_state = wait_for_new_mpc_state() => {
                        let new_state = new_state.with_context(|| format!("[{}] contract state receiver closed", job.name))?;

                        if (job.stop_fn)(&new_state) {
                            tracing::info!(
                                "[{}] contract state changed incompatibly, stopping",
                                job.name
                            );
                            break new_state;
                        }
                    }
                }
            }

            let mut job: MpcJob = match state.clone() {
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
                ContractState::Running(running_state) => {
                    // For the running state, we run the full MPC protocol.
                    // There's no timeout. The only time we stop is when the contract state
                    // changes to no longer be running or if the epoch changes.
                    tracing::info!("Resharing process is: {:?}", &running_state.resharing_state);

                    let (key_event_receiver, stop_fn): (_, StopFn) = match running_state
                        .resharing_state
                        .clone()
                    {
                        Some(resharing_state) => {
                            let (key_event_sender, key_event_receiver) =
                                watch::channel(resharing_state.key_event.clone());

                            let current_resharing_epoch_id = resharing_state.key_event.id.epoch_id;

                            let stop_fn =
                                Box::new(move |new_state: &ContractState| match new_state {
                                    ContractState::Running(new_state) => {
                                        let Some(new_resharing_state) = &new_state.resharing_state
                                        else {
                                            // resharing completed.
                                            return true;
                                        };

                                        let epoch_changed =
                                            new_resharing_state.key_event.id.epoch_id
                                                != current_resharing_epoch_id;

                                        if epoch_changed {
                                            return true;
                                        }

                                        key_event_sender
                                            .send(new_resharing_state.key_event.clone())
                                            .is_err()
                                    }
                                    _ => true,
                                });

                            (Some(key_event_receiver), stop_fn)
                        }
                        None => (
                            None,
                            Box::new(move |new_state| match new_state {
                                ContractState::Running(new_state) => {
                                    let new_running_epoch =
                                        new_state.keyset.epoch_id != running_state.keyset.epoch_id;
                                    let resharing_started = new_state.resharing_state.is_some();

                                    new_running_epoch | resharing_started
                                }
                                _ => true,
                            }),
                        ),
                    };

                    tracing::info!("Key event receiver is: {:?}", key_event_receiver);

                    let job_name = if key_event_receiver.is_some() {
                        "Resharing"
                    } else {
                        "Running"
                    };

                    MpcJob {
                        name: job_name,
                        fut: Self::create_runtime_and_run(
                            "Running",
                            self.config_file.cores,
                            Self::run_mpc(
                                self.clock.clone(),
                                self.secret_db.clone(),
                                self.secrets.clone(),
                                self.config_file.clone(),
                                self.key_storage_config.create().await?,
                                running_state.clone(),
                                self.indexer.txn_sender.clone(),
                                self.indexer
                                    .block_update_receiver
                                    .clone()
                                    .lock_owned()
                                    .await,
                                self.signature_debug_request_sender.subscribe(),
                                key_event_receiver,
                            ),
                        )?,
                        stop_fn,
                    }
                }
            };
            tracing::info!("[{}] Starting", job.name);
            let _report_guard =
                ReportCurrentJobGuard::new(job.name, self.currently_running_job_name.clone());
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
        running_state: ContractRunningState,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        signature_debug_request_receiver: broadcast::Receiver<SignatureDebugRequest>,
        resharing_state_receiver: Option<watch::Receiver<ContractKeyEventInstance>>,
    ) -> anyhow::Result<MpcJobResult> {
        tracing::info!("Entering running state.");
        let keyshare_storage = Arc::new(keyshare_storage);

        delete_stale_triples_and_presignatures(&secret_db, running_state.keyset.epoch_id)?;

        let mut running_participants = running_state.participants.clone();

        let participants_config = match &running_state.resharing_state {
            Some(resharing_state) => resharing_state.new_participants.clone(),
            None => running_participants.clone(),
        };

        // Only consider the running participants that are also members of the new resharing state.
        running_participants
            .participants
            .retain(|p| participants_config.participants.contains(p));

        let Some(mpc_config) = MpcConfig::from_participants_with_near_account_id(
            participants_config,
            &config_file.my_near_account_id,
        ) else {
            tracing::info!("We are not a participant in the current epoch; doing nothing until contract state change");
            return Ok(MpcJobResult::HaltUntilInterrupted);
        };

        tracing::info!("Creating tls mesh");

        let (sender, receiver) =
            new_tls_mesh_network(&mpc_config, &secrets.p2p_private_key).await?;
        let sender = Arc::new(sender);

        tracing::info!("Creating network client.");
        let (network_client, mut channel_receiver, _handle) =
            run_network_client(sender.clone(), Box::new(receiver));

        let cancellation_token = CancellationToken::new();
        let cancellation_token_child = cancellation_token.child_token();
        let _drop_guard = cancellation_token.drop_guard();

        let (running_network_receiver, resharing_network_receiver) = {
            let (running_sender, running_receiver) = unbounded_channel();
            let (resharing_sender, resharing_receiver) = unbounded_channel();

            let _multiplexer_handle = tokio::spawn(async move {
                loop {
                    select! {
                        network_channel = channel_receiver.recv()  => {
                            let Some(network_channel) = network_channel else {
                                tracing::info!("Network channel dropped.");
                                break;
                            };

                            let is_resharing_message = matches!(
                                network_channel.task_id(),
                                MpcTaskId::EcdsaTaskId(EcdsaTaskId::KeyResharing { .. })
                                    | MpcTaskId::EddsaTaskId(EddsaTaskId::KeyResharing { .. })
                            );

                            if is_resharing_message {
                                let send_result = resharing_sender.send(network_channel);
                                if send_result.is_err() {
                                    error!("resharing receiver dropped.");
                                }
                            } else {
                                let send_result = running_sender.send(network_channel);
                                if send_result.is_err() {
                                    error!("running receiver dropped.");
                                }
                            }
                        }

                        _ = cancellation_token_child.cancelled() => {
                            info!("Network multiplexer cancelled.");
                            break;
                        }

                    }
                }
                info!("Exiting network multiplexer.");
            });

            (running_receiver, resharing_receiver)
        };

        // This handle must be alive, otherwise the AutoAbortTask will get cancelled on drop.
        let resharing_handle = resharing_state_receiver.map(|resharing_state_receiver| {
            let config_file = config_file.clone();
            let running_state = running_state.clone();
            let keyshare_storage = keyshare_storage.clone();
            let chain_txn_sender = chain_txn_sender.clone();
            let network_client = network_client.clone();
            let mpc_config = mpc_config.clone();

            tracking::spawn_checked("key_resharing", async move {
                Self::run_key_resharing(
                    &config_file,
                    keyshare_storage.clone(),
                    running_state.clone(),
                    &mpc_config,
                    network_client,
                    resharing_network_receiver,
                    chain_txn_sender,
                    resharing_state_receiver,
                )
                .await
            })
        });

        let running_handle = tracking::spawn::<_, anyhow::Result<MpcJobResult>>(
            "running mpc job",
            async move {
                let Some(running_mpc_config) = MpcConfig::from_participants_with_near_account_id(
                    running_participants.clone(),
                    &config_file.my_near_account_id,
                ) else {
                    tracing::info!("We are not a participant in the current epoch; doing nothing until contract state change");
                    return Ok(MpcJobResult::HaltUntilInterrupted);
                };

                let keyshares = match keyshare_storage.load_keyset(&running_state.keyset).await {
                    Ok(keyshares) => keyshares,
                    Err(e) => {
                        tracing::error!(
                        "Failed to load keyshares: {:?}; doing nothing until contract state changes.",
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
                    running_state.keyset.epoch_id, running_mpc_config.my_participant_id
                ));

                tracing::info!("wait for ready.");
                let running_participant_ids = running_mpc_config
                    .participants
                    .participants
                    .iter()
                    .map(|p| p.id)
                    .collect::<Vec<_>>();

                sender
                    .wait_for_ready(
                        running_mpc_config.participants.threshold as usize,
                        &running_participant_ids,
                    )
                    .await?;

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
                    running_mpc_config.clone().into(),
                    network_client.clone(),
                    clock,
                    secret_db,
                    sign_request_store.clone(),
                    ecdsa_keyshares,
                )?);

                let eddsa_signature_provider = Arc::new(EddsaSignatureProvider::new(
                    config_file.clone().into(),
                    running_mpc_config.clone().into(),
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
                        running_network_receiver,
                        block_update_receiver,
                        chain_txn_sender,
                        signature_debug_request_receiver,
                    )
                    .await?;

                Ok(MpcJobResult::Done)
            },
        );

        if let Some(resharing_handle) = resharing_handle {
            tracing::info!("Waiting on resharing handle.");
            resharing_handle.await?;
        }

        running_handle.await??;

        Ok(MpcJobResult::Done)
    }

    /// Entry point to handle the Resharing state of the contract.
    #[allow(clippy::too_many_arguments)]
    async fn run_key_resharing(
        config_file: &ConfigFile,
        keyshare_storage: Arc<KeyshareStorage>,
        current_running_state: ContractRunningState,
        mpc_config: &MpcConfig,
        network_client: Arc<MeshNetworkClient>,
        channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        key_event_receiver: watch::Receiver<ContractKeyEventInstance>,
    ) -> anyhow::Result<MpcJobResult> {
        tracing::info!("Starting key resharing.");

        let previous_keyset = current_running_state.keyset;
        let was_participant_last_epoch = current_running_state
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
            info!("Not participant in last epoch.");
            if keyshare_storage.load_keyset(&previous_keyset).await.is_ok() {
                tracing::warn!("We should not have the previous keyshares when we were not a participant last epoch");
            }
            None
        };

        let args = Arc::new(ResharingArgs {
            previous_keyset,
            existing_keyshares,
            new_threshold: mpc_config.participants.threshold as usize,
            old_participants: current_running_state.participants,
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

pub fn delete_stale_triples_and_presignatures(
    db: &Arc<SecretDB>,
    new_epoch_id: EpochId,
) -> anyhow::Result<()> {
    let previous_epoch_id: Option<EpochId> =
        db.get(DBCol::EpochId, EPOCH_ID_KEY)?
            .and_then(|bytes: Vec<u8>| {
                let bytes_array = bytes
                    .try_into()
                    .inspect_err(|bytes| error!("PREVIOUS EPOCH_ID ENTRY NOT u64: {:?}", bytes))
                    .ok()?;
                let epoch_id_number = u64::from_be_bytes(bytes_array);

                Some(EpochId::new(epoch_id_number))
            });

    let new_epoch_id_is_seen =
        previous_epoch_id.is_some_and(|previous_epoch_id| previous_epoch_id == new_epoch_id);

    if new_epoch_id_is_seen {
        return Ok(());
    }

    info!(
        "Updating running epoch. NEW EPOCH: {:?}, OLD EPOCH {:?}.",
        new_epoch_id.get(),
        previous_epoch_id
    );
    let mut update_writer = db.update();
    let big_endian_bytes_repr = &new_epoch_id.get().to_be_bytes();
    update_writer.put(DBCol::EpochId, EPOCH_ID_KEY, big_endian_bytes_repr);

    // Delete all triples and presignatures from the previous epoch;
    // They are no longer usable once we have completed resharing of keys. Presignatures are
    // dependent on key so those are completely invalidated, and triples may have different threshold
    // or assume different participants, so it would be too much trouble to keep them around.
    tracing::info!("Deleting all triples and presignatures...");
    let _ = update_writer.delete_all(DBCol::Presignature);
    let _ = update_writer.delete_all(DBCol::Triple);
    tracing::info!("Deleted all presignatures");

    update_writer.commit()?;

    Ok(())
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
