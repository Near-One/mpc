use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::types::ChainGetPendingRequestArgs;
use super::ChainSendTransactionRequest;
use super::IndexerState;
use crate::config::RespondConfigFile;
use crate::metrics;
use legacy_mpc_contract;
use near_client::Query;
use near_crypto::SecretKey;
use near_indexer_primitives::types::Gas;
use near_indexer_primitives::types::{BlockReference, Finality};
use near_indexer_primitives::views::{QueryRequest, QueryResponseKind};
use near_o11y::WithSpanContextExt;
use near_sdk::AccountId;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

/// Creates, signs, and submits a function call with the given method and serialized arguments.
async fn submit_tx(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    method: String,
    params_ser: String,
    gas: Gas,
) -> anyhow::Result<()> {
    let block = indexer_state
        .view_client
        .send(near_client::GetBlock(BlockReference::Finality(Finality::Final)).with_span_context())
        .await??;

    let transaction = tx_signer.create_and_sign_function_call_tx(
        indexer_state.mpc_contract_id.clone(),
        method,
        params_ser.into(),
        gas,
        block.header.hash,
        block.header.height,
    );

    let tx_hash = transaction.get_hash();
    tracing::info!(
        target = "mpc",
        "sending tx {:?} with ak={} nonce={}",
        tx_hash,
        tx_signer.public_key(),
        transaction.transaction.nonce(),
    );

    let response = indexer_state
        .tx_processor
        .send(
            near_client::ProcessTxRequest {
                transaction,
                is_forwarded: false,
                check_only: false,
            }
            .with_span_context(),
        )
        .await?;
    match response {
        // We're not a validator, so we should always be routing the transaction.
        near_client::ProcessTxResponse::RequestRouted => Ok(()),
        _ => {
            anyhow::bail!("unexpected ProcessTxResponse: {:?}", response);
        }
    }
}

enum ChainTransactionState {
    Executed,
    NotExecuted,
    Unknown,
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
async fn observe_tx_result(
    indexer_state: Arc<IndexerState>,
    request: &ChainSendTransactionRequest,
) -> anyhow::Result<ChainTransactionState> {
    match request {
        ChainSendTransactionRequest::Respond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending signature request still exists in the contract state
            let get_pending_request_args: Vec<u8> =
                serde_json::to_string(&ChainGetPendingRequestArgs {
                    request: respond_args.request.clone(),
                })
                .unwrap()
                .into_bytes();
            let query_response = indexer_state
                .view_client
                .send(
                    Query {
                        block_reference: BlockReference::Finality(Finality::Final),
                        request: QueryRequest::CallFunction {
                            account_id: indexer_state.mpc_contract_id.clone(),
                            method_name: "get_pending_request".to_string(),
                            args: get_pending_request_args.into(),
                        },
                    }
                    .with_span_context(),
                )
                .await??;
            match query_response.kind {
                QueryResponseKind::CallResult(call_result) => {
                    let pending_request = serde_json::from_slice::<
                        Option<legacy_mpc_contract::primitives::YieldIndex>,
                    >(&call_result.result)?;
                    Ok(if pending_request.is_none() {
                        ChainTransactionState::Executed
                    } else {
                        ChainTransactionState::NotExecuted
                    })
                }
                _ => {
                    anyhow::bail!("Unexpected result from a view client function call");
                }
            }
        }
        ChainSendTransactionRequest::StartKeygen(_) => {
            // we don't care. The contract state change will handle this.
            Ok(ChainTransactionState::Unknown)
        }
        ChainSendTransactionRequest::StartReshare(_) => {
            // we don't care. The contract state change will handle this.
            Ok(ChainTransactionState::Unknown)
        }
        ChainSendTransactionRequest::VotePk(_) => {
            // we don't care. The contract state change will handle this.
            Ok(ChainTransactionState::Unknown)
        }
        ChainSendTransactionRequest::VoteReshared(_) => {
            // we don't care. The contract state change will handle this.
            Ok(ChainTransactionState::Unknown)
        }
        ChainSendTransactionRequest::VoteAbortKeyEvent(_) => {
            // we don't care. The contract state change will handle this.
            Ok(ChainTransactionState::Unknown)
        }
        ChainSendTransactionRequest::VerifyTee() => {
            // we don't care. The contract state change will handle this.
            Ok(ChainTransactionState::Unknown)
        }
    }
}

/// Attempts to ensure that a function call with given method and args is included on-chain.
/// If the submitted transaction is not observed by the indexer before the `timeout`, tries again.
/// Will make up to `num_attempts` attempts.
async fn ensure_send_transaction(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    request: ChainSendTransactionRequest,
    params_ser: String,
    timeout: Duration,
    num_attempts: NonZeroUsize,
) {
    for _ in 0..num_attempts.into() {
        if let Err(err) = submit_tx(
            tx_signer.clone(),
            indexer_state.clone(),
            request.method().to_string(),
            params_ser.clone(),
            request.gas_required(),
        )
        .await
        {
            // If the transaction fails to send immediately, wait a short period and try again
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[request.method(), "local_error"])
                .inc();
            tracing::error!(%err, "Failed to forward transaction {:?}", request);
            time::sleep(Duration::from_secs(1)).await;
            continue;
        };

        // Allow time for the transaction to be included
        time::sleep(timeout).await;
        // Then try to check whether it had the intended effect
        match observe_tx_result(indexer_state.clone(), &request).await {
            Ok(ChainTransactionState::Executed) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "succeeded"])
                    .inc();
                return;
            }
            Ok(ChainTransactionState::NotExecuted) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "timed_out"])
                    .inc();
                continue;
            }
            Ok(ChainTransactionState::Unknown) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "unknown"])
                    .inc();
                return;
            }
            Err(err) => {
                metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                    .with_label_values(&[request.method(), "unknown_err"])
                    .inc();
                tracing::warn!(target:"mpc", %err, "encountered error trying to confirm result of transaction {:?}", request);
                return;
            }
        }
    }
}

pub(crate) async fn handle_txn_requests(
    mut receiver: mpsc::Receiver<ChainSendTransactionRequest>,
    owner_account_id: AccountId,
    owner_secret_key: SecretKey,
    config: RespondConfigFile,
    indexer_state: Arc<IndexerState>,
) {
    let mut signers = TransactionSigners::new(config, owner_account_id, owner_secret_key)
        .expect("Failed to initialize transaction signers");

    while let Some(tx_request) = receiver.recv().await {
        let tx_signer = signers.signer_for(&tx_request);
        let indexer_state = indexer_state.clone();
        actix::spawn(async move {
            let Ok(txn_json) = serde_json::to_string(&tx_request) else {
                tracing::error!(target: "mpc", "Failed to serialize response args");
                return;
            };
            tracing::debug!(target = "mpc", "tx args {:?}", txn_json);
            ensure_send_transaction(
                tx_signer.clone(),
                indexer_state.clone(),
                tx_request,
                txn_json,
                Duration::from_secs(10),
                // TODO(#226): We no longer need retries. However, the metrics from querying the
                // tx results appear useful. We should probably export some metrics from the
                // signature processing pipeline instead, and remove this retry.
                NonZeroUsize::new(1).unwrap(),
            )
            .await;
        });
    }
}
