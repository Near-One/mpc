use crate::hkdf::ScalarExt;
use crate::indexer::stats::IndexerStats;
use crate::indexer::IndexerState;
use crate::metrics;
use k256::Scalar;
use near_crypto::PublicKey;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use crate::primitives::KeyType;

/// Arguments passed to a `sign` function call on-chain
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct UnvalidatedSignArgsInner {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct UnvalidatedSignArgs {
    request: UnvalidatedSignArgsInner,
}

/// A validated version of the signature request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignArgs {
    pub payload: Scalar,
    pub path: String,
    pub key_version: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChainSignatureRequest {
    pub request_id: [u8; 32],
    pub request: SignArgs,
    pub predecessor_id: AccountId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
    pub key_type: KeyType
}

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
    account_public_key: Option<PublicKey>,
    sign_request_sender: mpsc::UnboundedSender<ChainSignatureRequest>,
    indexer_state: Arc<IndexerState>,
) {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(
                streamer_message,
                Arc::clone(&stats),
                &mpc_contract_id,
                &account_public_key,
                sign_request_sender.clone(),
                indexer_state.clone(),
            )
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
    _account_public_key: &Option<PublicKey>,
    sign_request_sender: mpsc::UnboundedSender<ChainSignatureRequest>,
    indexer_state: Arc<IndexerState>,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    let mut signature_requests = vec![];
    let my_tx_nonces = vec![];

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
            let receipt = outcome.receipt.clone();
            let execution_outcome = outcome.execution_outcome.clone();
            if let Some(sign_args) =
                maybe_get_sign_args(&receipt, &execution_outcome, mpc_contract_id.clone())
            {
                signature_requests.push(ChainSignatureRequest {
                    request_id: receipt.receipt_id.0,
                    request: sign_args,
                    predecessor_id: receipt.predecessor_id.clone(),
                    entropy: streamer_message.block.header.random_value.into(),
                    timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
                    key_type: KeyType::SECP256K1 // TODO: It should be read from chain too.
                });
            }
        }

        // TODO(#153): fix or remove this
        /*if let Some(account_public_key) = account_public_key {
            if let Some(chunk) = &shard.chunk {
                for tx in &chunk.transactions {
                    if tx.transaction.public_key == *account_public_key {
                        let nonce = tx.transaction.nonce;
                        metrics::MPC_ACCESS_KEY_NONCE.set(nonce as i64);
                        my_tx_nonces.push(nonce);
                    }
                }
            }
        }*/
    }

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT.set(block_height as i64);

    for request in signature_requests {
        metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
        if let Err(err) = sign_request_sender.send(request) {
            tracing::error!(target: "mpc", %err, "error sending sign request to mpc node");
        }
    }

    for nonce in my_tx_nonces {
        indexer_state.insert_nonce(nonce);
    }

    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.remove(&block_height);
    stats_lock.blocks_processed_count += 1;
    stats_lock.last_processed_block_height = block_height;
    drop(stats_lock);
    Ok(())
}

fn maybe_get_sign_args(
    receipt: &ReceiptView,
    execution_outcome: &ExecutionOutcomeWithIdView,
    mpc_contract_id: AccountId,
) -> Option<SignArgs> {
    let outcome = &execution_outcome.outcome;
    if outcome.executor_id != *mpc_contract_id {
        return None;
    }
    let ExecutionStatusView::SuccessReceiptId(receipt_id) = outcome.status else {
        return None;
    };
    let ReceiptEnumView::Action { ref actions, .. } = receipt.receipt else {
        return None;
    };
    if actions.len() != 1 {
        return None;
    }
    let ActionView::FunctionCall {
        ref method_name,
        ref args,
        ..
    } = actions[0]
    else {
        return None;
    };
    if method_name != "sign" {
        return None;
    }
    tracing::debug!(target: "mpc", "found `sign` function call");

    let sign_args = match serde_json::from_slice::<'_, UnvalidatedSignArgs>(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `sign` arguments");
            return None;
        }
    };
    let Some(payload) = Scalar::from_bytes(sign_args.request.payload) else {
        tracing::warn!(
            target: "mpc",
            "`sign` did not produce payload correctly: {:?}",
            sign_args.request.payload,
        );
        return None;
    };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        payload = hex::encode(sign_args.request.payload),
        key_version = sign_args.request.key_version,
        "indexed new `sign` function call"
    );
    Some(SignArgs {
        payload,
        path: sign_args.request.path,
        key_version: sign_args.request.key_version,
    })
}
