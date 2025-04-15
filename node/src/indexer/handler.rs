use crate::indexer::stats::IndexerStats;
use crate::metrics;
use crate::sign_request::SignatureId;
use crate::signing::recent_blocks_tracker::BlockViewLite;
use futures::StreamExt;
use mpc_contract::primitives::domain::DomainId;
use mpc_contract::primitives::signature::{Payload, SignRequest, SignRequestArgs};
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UnvalidatedSignArgs {
    request: SignRequestArgs,
}

/// A validated version of the signature request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignArgs {
    pub payload: Payload,
    pub path: String,
    pub domain_id: DomainId,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignatureRequestFromChain {
    pub signature_id: SignatureId,
    pub receipt_id: CryptoHash,
    pub request: SignArgs,
    pub predecessor_id: AccountId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

#[derive(Clone)]
pub struct ChainBlockUpdate {
    pub block: BlockViewLite,
    pub signature_requests: Vec<SignatureRequestFromChain>,
    pub completed_signatures: Vec<SignatureId>,
}

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
) {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(
                streamer_message,
                Arc::clone(&stats),
                &mpc_contract_id,
                block_update_sender.clone(),
            )
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
    block_update_sender: mpsc::UnboundedSender<ChainBlockUpdate>,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    let mut signature_requests = vec![];
    let mut completed_signatures = vec![];

    for shard in streamer_message.shards {
        for outcome in shard.receipt_execution_outcomes {
            metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
            let receipt = outcome.receipt.clone();
            let execution_outcome = outcome.execution_outcome.clone();
            if let Some((signature_id, sign_args)) =
                maybe_get_sign_args(&receipt, &execution_outcome, mpc_contract_id)
            {
                signature_requests.push(SignatureRequestFromChain {
                    signature_id,
                    receipt_id: receipt.receipt_id,
                    request: sign_args,
                    predecessor_id: receipt.predecessor_id.clone(),
                    entropy: streamer_message.block.header.random_value.into(),
                    timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
                });
                metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
            } else if let Some(signature_id) =
                maybe_get_signature_completion(&receipt, mpc_contract_id)
            {
                completed_signatures.push(signature_id);
                metrics::MPC_NUM_SIGN_RESPONSES_INDEXED.inc();
            }
        }
    }

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT.set(block_height as i64);

    block_update_sender
        .send(ChainBlockUpdate {
            block: BlockViewLite {
                hash: streamer_message.block.header.hash,
                height: streamer_message.block.header.height,
                prev_hash: streamer_message.block.header.prev_hash,
                last_final_block: streamer_message.block.header.last_final_block,
            },
            signature_requests,
            completed_signatures,
        })
        .expect("Receiving channel must be alive.");

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
    mpc_contract_id: &AccountId,
) -> Option<(SignatureId, SignArgs)> {
    let outcome = &execution_outcome.outcome;
    if &outcome.executor_id != mpc_contract_id {
        return None;
    }
    let ExecutionStatusView::SuccessReceiptId(next_receipt_id) = outcome.status else {
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

    let sign_request: SignRequest = match sign_args.request.try_into() {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(target: "mpc", %err, "failed to parse `sign` arguments");
            return None;
        }
    };

    tracing::info!(
        target: "mpc",
        receipt_id = %receipt.receipt_id,
        next_receipt_id = %next_receipt_id,
        caller_id = receipt.predecessor_id.to_string(),
        request = ?sign_request,
        "indexed new `sign` function call"
    );
    Some((
        next_receipt_id,
        SignArgs {
            payload: sign_request.payload,
            path: sign_request.path,
            domain_id: sign_request.domain_id,
        },
    ))
}

fn maybe_get_signature_completion(
    receipt: &ReceiptView,
    mpc_contract_id: &AccountId,
) -> Option<SignatureId> {
    if &receipt.receiver_id != mpc_contract_id {
        return None;
    };
    let ReceiptEnumView::Action { ref actions, .. } = receipt.receipt else {
        return None;
    };
    if actions.len() != 1 {
        return None;
    }
    let ActionView::FunctionCall {
        ref method_name, ..
    } = actions[0]
    else {
        return None;
    };
    if method_name != "return_signature_and_clean_state_on_success" {
        return None;
    }
    tracing::debug!(target: "mpc", "found `return_signature_and_clean_state_on_success` function call");

    Some(receipt.receipt_id)
}
