use super::handler::listen_blocks;
use super::participants::{monitor_contract_state, ContractState};
use super::stats::{indexer_logger, IndexerStats};
use super::tx_sender::handle_txn_requests;
use super::{IndexerAPI, IndexerState};
use crate::config::{load_respond_config_file, IndexerConfig, RespondConfigFile};
use mpc_contract::state::ProtocolContractState;
use near_crypto::SecretKey;
use near_sdk::AccountId;
use tokio::select;
use tracing::{error, info};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

/// Spawns a real indexer, returning a handle to the indexer, [`IndexerApi`].
///
/// If an unrecoverable error occurs, the spawned indexer will terminate, and the provided [`oneshot::Sender`]
/// will be used to propagate the error.
pub fn spawn_real_indexer(
    home_dir: PathBuf,
    indexer_config: IndexerConfig,
    my_near_account_id: AccountId,
    account_secret_key: SecretKey,
    protocol_state_sender: watch::Sender<ProtocolContractState>,
    indexer_exit_sender: oneshot::Sender<anyhow::Result<()>>,
) -> IndexerAPI {
    let (chain_config_sender, chain_config_receiver) =
        tokio::sync::watch::channel::<ContractState>(ContractState::WaitingForSync);
    let (block_update_sender, block_update_receiver) = mpsc::unbounded_channel();
    let (chain_txn_sender, chain_txn_receiver) = mpsc::channel(10000);

    // TODO(#156): replace actix with tokio
    std::thread::spawn(move || {
        actix::System::new().block_on(async {
            let indexer =
                near_indexer::Indexer::new(indexer_config.to_near_indexer_config(home_dir.clone()))
                    .expect("Failed to initialize the Indexer");
            let respond_config = match load_respond_config_file(&home_dir) {
                Ok(Some(respond_config)) => respond_config,
                Ok(None) => {
                    tracing::warn!("No respond.yaml provided. Using the node's main account to send respond transactions.");
                    RespondConfigFile {
                        account_id: my_near_account_id.clone(),
                        access_keys: vec![account_secret_key.clone()],
                    }
                }
                Err(err) => {
                    panic!("respond.yaml is provided but failed to parse: {err:?}");
                }
            };
            
            let mut stream = indexer.streamer();
            let (sender, receiver) = tokio::sync::mpsc::channel(10_000);
            
            actix::spawn(async move {
                let mut messages_received_from_indexer = 0;
                let mut messages_received_from_indexer_total = 0;
                const REPORT_DURATION: Duration = Duration::from_secs(5);
                let mut tick_interval = tokio::time::interval(REPORT_DURATION);
                

                loop {
                    select! {
                        streamer_message = stream.recv() => {
                            let Some(streamer_message) = streamer_message else {
                                error!("NEAR INDEXER STREAMER IS CLOSED");
                                continue;
                            };
                            let Ok(_) = sender.send(streamer_message).await else {
                                error!("BLOCK MONITOR DROPPED RECEIVER.");
                                break;
                            };
                            messages_received_from_indexer += 1;
                            messages_received_from_indexer_total += 1;
                        }

                        _ = tick_interval.tick() => {
                            info!("BLOCKS PROCESSED LAST {:?} => {:?} blocks", REPORT_DURATION, messages_received_from_indexer);
                            info!("MESSAGES IN TOTAL: {:?}", messages_received_from_indexer_total);
                            messages_received_from_indexer = 0;
                        }
                    }
                }
            });


            let (view_client, client, tx_processor) = indexer.client_actors();
            let indexer_state = Arc::new(IndexerState::new(
                view_client,
                client,
                tx_processor,
                indexer_config.mpc_contract_id.clone(),
            ));
            // TODO: migrate this into IndexerState
            let stats: Arc<Mutex<IndexerStats>> = Arc::new(Mutex::new(IndexerStats::new()));
            actix::spawn(monitor_contract_state(
                indexer_state.clone(),
                indexer_config.port_override,
                chain_config_sender,
                protocol_state_sender,
            ));
            actix::spawn(indexer_logger(Arc::clone(&stats), indexer_state.view_client.clone()));
            actix::spawn(handle_txn_requests(
                chain_txn_receiver,
                my_near_account_id,
                account_secret_key.clone(),
                respond_config,
                indexer_state.clone(),
            ));
            let indexer_result = listen_blocks(
                receiver,
                indexer_config.concurrency,
                Arc::clone(&stats),
                indexer_config.mpc_contract_id,
                block_update_sender,
            )
            .await;

            if indexer_exit_sender.send(indexer_result).is_err() {
                tracing::error!("Indexer thread could not send result back to main driver.")
            };
        });
    });

    IndexerAPI {
        contract_state_receiver: chain_config_receiver,
        block_update_receiver: Arc::new(Mutex::new(block_update_receiver)),
        txn_sender: chain_txn_sender,
    }
}
