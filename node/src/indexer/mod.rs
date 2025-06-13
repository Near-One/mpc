pub mod configs;
#[cfg(test)]
pub mod fake;
pub mod handler;
pub mod lib;
pub mod participants;
pub mod real;
pub mod stats;
pub mod tx_sender;
pub mod tx_signer;
pub mod types;

use handler::ChainBlockUpdate;
use mpc_contract::state::ProtocolContractState;
use near_indexer_primitives::types::{AccountId, BlockHeight};
use participants::ContractState;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use types::ChainSendTransactionRequest;

pub(crate) struct IndexerState {
    /// For querying blockchain state.
    view_client: actix::Addr<near_client::ViewClientActor>,
    /// For querying blockchain sync status.
    client: actix::Addr<near_client::ClientActor>,
    /// For sending txs to the chain.
    tx_processor: actix::Addr<near_client::TxRequestHandlerActor>,
    /// AccountId for the mpc contract.
    mpc_contract_id: AccountId,
}

impl IndexerState {
    pub fn new(
        view_client: actix::Addr<near_client::ViewClientActor>,
        client: actix::Addr<near_client::ClientActor>,
        tx_processor: actix::Addr<near_client::TxRequestHandlerActor>,
        mpc_contract_id: AccountId,
    ) -> Self {
        Self {
            view_client,
            client,
            tx_processor,
            mpc_contract_id,
        }
    }
}

/// API to interact with the indexer. Can be replaced by a dummy implementation.
/// The MPC node implementation needs this and only this to be able to interact
/// with the indexer.
/// TODO(#155): This would be the interface to abstract away having an indexer
/// running in a separate process.
pub struct IndexerAPI {
    /// Provides the current contract state as well as updates to it.
    pub contract_state_receiver: watch::Receiver<(BlockHeight, ProtocolContractState)>,
    /// Provides block updates (signature requests and other relevant receipts).
    /// It is in a mutex, because the logical "owner" of this receiver can
    /// change over time (specifically, when we transition from the Running
    /// state to a Resharing state to the Running state again, two different
    /// tasks would successively "own" the receiver).
    /// We do not want to re-create the channel, because while resharing is
    /// happening we want to buffer the signature requests.
    pub block_update_receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ChainBlockUpdate>>>,
    /// Sender to request transactions be signed (by a TransactionSigner that
    /// the indexer is initialized with) and sent to the chain.
    pub txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
}
