use super::handler::listen_blocks;
use super::participants::{monitor_chain_state, ContractState};
use super::response::handle_txn_requests;
use super::stats::{indexer_logger, IndexerStats};
use super::transaction::TransactionSigner;
use super::{IndexerAPI, IndexerState};
use crate::config::IndexerConfig;
use near_crypto::SecretKey;
use near_sdk::AccountId;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Spawn a real indexer, returning a handle to the indexer root thread,
/// and an API to interact with the indexer.
pub fn spawn_real_indexer(
    home_dir: PathBuf,
    indexer_config: IndexerConfig,
    my_near_account_id: AccountId,
    account_secret_key: Option<SecretKey>,
) -> (std::thread::JoinHandle<()>, IndexerAPI) {
    let (chain_config_sender, chain_config_receiver) =
        tokio::sync::watch::channel::<ContractState>(ContractState::WaitingForSync);
    let (sign_request_sender, sign_request_receiver) = mpsc::unbounded_channel();
    let (chain_txn_sender, chain_txn_receiver) = mpsc::channel(10000);

    let thread = std::thread::spawn(move || {
        // todo: replace actix with tokio
        actix::System::new().block_on(async {
            let transaction_signer = account_secret_key.clone().map(|account_secret_key| {
                Arc::new(TransactionSigner::from_key(
                    my_near_account_id.clone(),
                    account_secret_key,
                ))
            });
            let indexer =
                near_indexer::Indexer::new(indexer_config.to_near_indexer_config(home_dir.clone()))
                    .expect("Failed to initialize the Indexer");
            let stream = indexer.streamer();
            let (view_client, client) = indexer.client_actors();
            let indexer_state = Arc::new(IndexerState::new(
                view_client.clone(),
                client.clone(),
                indexer_config.mpc_contract_id.clone(),
            ));
            // TODO: migrate this into IndexerState
            let stats: Arc<Mutex<IndexerStats>> = Arc::new(Mutex::new(IndexerStats::new()));

            actix::spawn(monitor_chain_state(
                indexer_config.mpc_contract_id.clone(),
                indexer_config.port_override,
                view_client.clone(),
                client.clone(),
                chain_config_sender,
            ));
            actix::spawn(indexer_logger(Arc::clone(&stats), view_client.clone()));
            actix::spawn(handle_txn_requests(
                chain_txn_receiver,
                transaction_signer,
                indexer_state.clone(),
            ));
            listen_blocks(
                stream,
                indexer_config.concurrency,
                Arc::clone(&stats),
                indexer_config.mpc_contract_id,
                account_secret_key.map(|key| key.public_key()),
                sign_request_sender,
                indexer_state,
            )
            .await;
        });
    });
    (
        thread,
        IndexerAPI {
            contract_state_receiver: chain_config_receiver,
            sign_request_receiver: Arc::new(Mutex::new(sign_request_receiver)),
            txn_sender: chain_txn_sender,
        },
    )
}
