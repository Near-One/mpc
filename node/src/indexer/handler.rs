use crate::hkdf::ScalarExt;
use crate::indexer::stats::IndexerStats;
use crate::metrics;
use k256::Scalar;
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::views::{
    ActionView, ExecutionOutcomeWithIdView, ExecutionStatusView, ReceiptEnumView, ReceiptView,
};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

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
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ChainSignatureRequest {
    pub request_id: [u8; 32],
    pub request: SignArgs,
    pub predecessor_id: AccountId,
    pub entropy: [u8; 32],
    pub timestamp_nanosec: u64,
}

pub(crate) async fn listen_blocks(
    stream: tokio::sync::mpsc::Receiver<near_indexer_primitives::StreamerMessage>,
    concurrency: std::num::NonZeroU16,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: AccountId,
    sign_request_sender: mpsc::Sender<ChainSignatureRequest>,
) {
    let mut handle_messages = tokio_stream::wrappers::ReceiverStream::new(stream)
        .map(|streamer_message| {
            handle_message(
                streamer_message,
                Arc::clone(&stats),
                &mpc_contract_id,
                sign_request_sender.clone(),
            )
        })
        .buffer_unordered(usize::from(concurrency.get()));

    while let Some(_handle_message) = handle_messages.next().await {}
}

async fn handle_message(
    streamer_message: near_indexer_primitives::StreamerMessage,
    stats: Arc<Mutex<IndexerStats>>,
    mpc_contract_id: &AccountId,
    sign_request_sender: mpsc::Sender<ChainSignatureRequest>,
) -> anyhow::Result<()> {
    let block_height = streamer_message.block.header.height;
    let mut stats_lock = stats.lock().await;
    stats_lock.block_heights_processing.insert(block_height);
    drop(stats_lock);

    let signature_requests: Vec<ChainSignatureRequest> = streamer_message
        .shards
        .iter()
        .flat_map(|shard| {
            shard
                .receipt_execution_outcomes
                .iter()
                .filter_map(|outcome| {
                    metrics::MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES.inc();
                    let receipt = outcome.receipt.clone();
                    let execution_outcome = outcome.execution_outcome.clone();
                    let sign_args =
                        maybe_get_sign_args(&receipt, &execution_outcome, mpc_contract_id.clone())?;
                    Some(ChainSignatureRequest {
                        request_id: receipt.receipt_id.0,
                        request: sign_args,
                        predecessor_id: receipt.predecessor_id.clone(),
                        entropy: streamer_message.block.header.random_value.into(),
                        timestamp_nanosec: streamer_message.block.header.timestamp_nanosec,
                    })
                })
        })
        .collect::<Vec<_>>();

    crate::metrics::MPC_INDEXER_LATEST_BLOCK_HEIGHT.set(block_height as i64);

    for request in signature_requests {
        metrics::MPC_NUM_SIGN_REQUESTS_INDEXED.inc();
        if let Err(err) = sign_request_sender.send(request).await {
            tracing::error!(target: "mpc", %err, "error sending sign request to mpc node");
        }
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
    todo!()
    // Some(SignArgs {
    //     payload,
    //     path: sign_args.request.path,
    //     key_version: sign_args.request.key_version,
    // })
}
