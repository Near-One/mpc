use crate::config::ConfigFile;
use crate::hkdf::derive_tweak;
use crate::indexer::handler::{ChainBlockUpdate, SignatureRequestFromChain};
use crate::indexer::types::{ChainRespondArgs, ChainSendTransactionRequest};
use crate::metrics;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::{EcdsaSignatureProvider, SignatureProvider};
use crate::sign_request::{SignRequestStorage, SignatureRequest};
use crate::signing::queue::{PendingSignatureRequests, CHECK_EACH_SIGNATURE_REQUEST_INTERVAL};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::web::{SignatureDebugRequest, SignatureDebugRequestKind};
use near_time::Clock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// A one-time delay before processing signature requests on startup. This is to prevent the case
/// where we have not yet connected to all participants, and the signature processing code thinks
/// that others are offline, leading to signature requests having multiple leaders and unnecessarily
/// responded to multiple times. It doesn't affect correctness, but can make tests less flaky and
/// production runs experience fewer redundant signatures.
const INITIAL_STARTUP_SIGNATURE_PROCESSING_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<ConfigFile>,
    client: Arc<MeshNetworkClient>,
    sign_request_store: Arc<SignRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
}

impl MpcClient {
    pub fn new(
        config: Arc<ConfigFile>,
        client: Arc<MeshNetworkClient>,
        sign_request_store: Arc<SignRequestStorage>,
        ecdsa_secp256k1signature_provider: Arc<EcdsaSignatureProvider>,
    ) -> Self {
        Self {
            config,
            client,
            sign_request_store,
            ecdsa_signature_provider: ecdsa_secp256k1signature_provider,
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self: &Arc<Self>,
        channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        signature_debug_receiver: tokio::sync::broadcast::Receiver<SignatureDebugRequest>,
    ) -> anyhow::Result<()> {
        let client = self.client.clone();
        let metrics_emitter = tracking::spawn("periodically emits metrics", async move {
            loop {
                client.emit_metrics();
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        let monitor_passive_channels = {
            tracking::spawn(
                "monitor passive channels",
                MpcClient::monitor_passive_channels_inner(channel_receiver, self.clone()),
            )
        };

        let monitor_chain = {
            tracking::spawn(
                "monitor chain",
                self.clone().monitor_block_updates(
                    block_update_receiver,
                    chain_txn_sender,
                    signature_debug_receiver,
                ),
            )
        };

        let ecdsa_background_tasks = tracking::spawn(
            "ecdsa_background_tasks",
            self.ecdsa_signature_provider
                .clone()
                .spawn_background_tasks(),
        );

        let _ = monitor_passive_channels.await?;
        metrics_emitter.await?;
        monitor_chain.await?;
        let _ = ecdsa_background_tasks.await?;

        Ok(())
    }

    async fn monitor_block_updates(
        self: Arc<Self>,
        mut block_update_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainBlockUpdate>,
        >,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
        mut signature_debug_receiver: tokio::sync::broadcast::Receiver<SignatureDebugRequest>,
    ) {
        let mut tasks = AutoAbortTaskCollection::new();
        let mut pending_signatures = PendingSignatureRequests::new(
            Clock::real(),
            self.client.all_participant_ids(),
            self.client.my_participant_id(),
            self.client.clone(),
        );

        let start_time = Clock::real().now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CHECK_EACH_SIGNATURE_REQUEST_INTERVAL.unsigned_abs()) => {
                }
                block_update = block_update_receiver.recv() => {
                    let Some(block_update) = block_update else {
                        // If this branch hits, it means the channel is closed, meaning the
                        // indexer is being shutdown. So just quit this task.
                        break;
                    };
                    self.client.update_indexer_height(block_update.block.height);
                    let signature_requests = block_update
                        .signature_requests
                        .into_iter()
                        .map(|signature_request| {
                            let SignatureRequestFromChain {
                                signature_id,
                                receipt_id,
                                request,
                                predecessor_id,
                                entropy,
                                timestamp_nanosec,
                            } = signature_request;
                            SignatureRequest {
                                id: signature_id,
                                receipt_id,
                                msg_hash: request.payload,
                                tweak: derive_tweak(&predecessor_id, &request.path),
                                entropy,
                                timestamp_nanosec,
                            }
                        })
                        .collect::<Vec<_>>();

                    // Index the signature requests as soon as we see them. We'll decide
                    // whether to *process* them after.
                    for signature_request in &signature_requests {
                        self.sign_request_store.add(signature_request);
                    }
                    pending_signatures.notify_new_block(
                        signature_requests,
                        block_update.completed_signatures,
                        &block_update.block,
                    );
                }
                debug_request = signature_debug_receiver.recv() => {
                    if let Ok(debug_request) = debug_request {
                        match debug_request.kind {
                            SignatureDebugRequestKind::RecentBlocks => {
                                let debug_output = pending_signatures.debug_print_recent_blocks();
                                debug_request.respond(debug_output);
                            }
                            SignatureDebugRequestKind::RecentSignatures => {
                                let debug_output = format!("{:?}", pending_signatures);
                                debug_request.respond(debug_output);
                            }
                        }
                    }
                }
            }

            if start_time.elapsed() < INITIAL_STARTUP_SIGNATURE_PROCESSING_DELAY {
                continue;
            }
            let signature_attempts = pending_signatures.get_signatures_to_attempt();

            for signature_attempt in signature_attempts {
                let this = self.clone();
                let chain_txn_sender = chain_txn_sender.clone();
                tasks.spawn_checked(
                    &format!(
                        "leader for signature request {:?}",
                        signature_attempt.request.id
                    ),
                    async move {
                        // Only issue a MPC signature computation if we haven't computed it
                        // in a previous attempt.
                        let existing_response = signature_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .computed_response
                            .clone();
                        let response = match existing_response {
                            None => {
                                metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED
                                    .with_label_values(&["total"])
                                    .inc();

                                let (signature, public_key) = timeout(
                                    Duration::from_secs(this.config.signature.timeout_sec),
                                    this.ecdsa_signature_provider
                                        .clone()
                                        .make_signature(signature_attempt.request.id),
                                )
                                .await??;

                                metrics::MPC_NUM_SIGNATURE_COMPUTATIONS_LED
                                    .with_label_values(&["succeeded"])
                                    .inc();

                                let response = ChainRespondArgs::new(
                                    &signature_attempt.request,
                                    &signature,
                                    &public_key,
                                )?;
                                signature_attempt
                                    .computation_progress
                                    .lock()
                                    .unwrap()
                                    .computed_response = Some(response.clone());
                                response
                            }
                            Some(response) => response,
                        };
                        let _ = chain_txn_sender
                            .send(ChainSendTransactionRequest::Respond(response))
                            .await;
                        signature_attempt
                            .computation_progress
                            .lock()
                            .unwrap()
                            .last_response_submission = Some(Clock::real().now());

                        anyhow::Ok(())
                    },
                );
            }
        }
    }

    async fn monitor_passive_channels_inner(
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
        mpc_client: Arc<MpcClient>,
    ) -> anyhow::Result<()> {
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            let mpc_clone = mpc_client.clone();
            tasks.spawn_checked(
                &format!("passive task {:?}", channel.task_id()),
                async move { mpc_clone.process_channel_task(channel).await },
            );
        }
    }

    async fn process_channel_task(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EcdsaTaskId(_) => {
                self.ecdsa_signature_provider
                    .clone()
                    .process_channel(channel)
                    .await?
            }
        }

        Ok(())
    }
}
