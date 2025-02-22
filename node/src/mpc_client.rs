use crate::config::{ConfigFile, MpcConfig};
use crate::hkdf::derive_tweak;
use crate::indexer::handler::ChainSignatureRequest;
use crate::indexer::types::{ChainRespondArgs, ChainSendTransactionRequest};
use crate::keyshare::RootKeyshareData;
use crate::metrics;
use crate::network::{MeshNetworkClient, NetworkTaskChannelWrapper};
use crate::primitives::{MpcTaskId, PresignOutputWithParticipants};
use crate::sign::{
    pre_sign_unowned, run_background_presignature_generation, sign, PresignatureStorage,
};
use crate::sign_request::{
    compute_leaders_for_signing, SignRequestStorage, SignatureId, SignatureRequest,
};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::triple::{
    run_background_triple_generation, run_many_triple_generation, TripleStorage,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};
use cait_sith::FullSignature;
use futures::FutureExt;
use k256::{AffinePoint, Secp256k1};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    root_keyshare: RootKeyshareData,
}

impl MpcClient {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        sign_request_store: Arc<SignRequestStorage>,
        root_keyshare: RootKeyshareData,
    ) -> Self {
        Self {
            config,
            mpc_config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            root_keyshare,
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
        mut sign_request_receiver: tokio::sync::OwnedMutexGuard<
            mpsc::UnboundedReceiver<ChainSignatureRequest>,
        >,
        chain_txn_sender: mpsc::Sender<ChainSendTransactionRequest>,
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
            let this = Arc::new(self.clone());
            let config = self.config.clone();
            let mpc_config = self.mpc_config.clone();
            let network_client = self.client.clone();
            tracking::spawn("monitor chain", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                loop {
                    let this = this.clone();
                    let config = config.clone();
                    let mpc_config = mpc_config.clone();
                    let sign_request_store = self.sign_request_store.clone();
                    let chain_tx_sender = chain_txn_sender.clone();

                    let Some(ChainSignatureRequest {
                        request_id,
                        request,
                        predecessor_id,
                        entropy,
                        timestamp_nanosec,
                    }) = sign_request_receiver.recv().await
                    else {
                        // If this branch hits, it means the channel is closed, meaning the
                        // indexer is being shutdown. So just quit this task.
                        break;
                    };

                    let alive_participants = network_client.all_alive_participant_ids();

                    tasks.spawn_checked(
                        &format!("indexed sign request {:?}", request_id),
                        async move {
                            let request = SignatureRequest {
                                id: request_id,
                                msg_hash: request.payload,
                                tweak: derive_tweak(&predecessor_id, &request.path),
                                entropy,
                                timestamp_nanosec,
                            };

                            // Check if we've already seen this request
                            if !sign_request_store.add(&request) {
                                return anyhow::Ok(());
                            }

                            let (primary_leader, secondary_leader) =
                                compute_leaders_for_signing(&mpc_config, &request);
                            // start the signing process if we are the primary leader or if we are the secondary leader
                            // and the primary leader is not alive
                            if mpc_config.my_participant_id == primary_leader
                                || (mpc_config.my_participant_id == secondary_leader
                                    && !alive_participants.contains(&primary_leader))
                            {
                                metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                    .with_label_values(&["total"])
                                    .inc();

                                let (signature, public_key) = timeout(
                                    Duration::from_secs(config.signature.timeout_sec),
                                    this.clone().make_signature(request.id),
                                )
                                .await??;

                                metrics::MPC_NUM_SIGN_REQUESTS_LEADER
                                    .with_label_values(&["succeeded"])
                                    .inc();

                                let response =
                                    ChainRespondArgs::new(&request, &signature, &public_key)?;
                                let _ = chain_tx_sender
                                    .send(ChainSendTransactionRequest::Respond(response))
                                    .await;
                            }

                            anyhow::Ok(())
                        },
                    );
                }
            })
        };

        let generate_triples = tracking::spawn(
            "generate triples",
            run_background_triple_generation(
                self.client.clone(),
                self.mpc_config.participants.threshold as usize,
                self.config.triple.clone().into(),
                self.triple_store.clone(),
            ),
        );

        let generate_presignatures = tracking::spawn(
            "generate presignatures",
            run_background_presignature_generation(
                self.client.clone(),
                self.mpc_config.participants.threshold as usize,
                self.config.presignature.clone().into(),
                self.triple_store.clone(),
                self.presignature_store.clone(),
                self.root_keyshare.keygen_output(),
            ),
        );

        let _ = monitor_passive_channels.await?;
        metrics_emitter.await?;
        monitor_chain.await?;
        generate_triples.await??;
        generate_presignatures.await??;

        Ok(())
    }

    async fn monitor_passive_channels_inner(
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
        mpc_client: MpcClient,
    ) -> anyhow::Result<()> {
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            let mpc_clone = mpc_client.clone();
            tasks.spawn_checked(
                &format!("passive task {:?}", channel.task_id()),
                async move { MpcClient::process_channel_task(channel, mpc_clone).await },
            );
        }
    }

    async fn process_channel_task(
        channel: NetworkTaskChannelWrapper,
        mpc_client: MpcClient,
    ) -> anyhow::Result<()> {
        let MpcClient {
            config,
            mpc_config,
            triple_store,
            presignature_store,
            root_keyshare,
            sign_request_store,
            ..
        } = mpc_client;
        match channel.task_id() {
            MpcTaskId::KeyGeneration => {
                anyhow::bail!("Key generation rejected in normal node operation");
            }
            MpcTaskId::KeyResharing { .. } => {
                anyhow::bail!("Key resharing rejected in normal node operation");
            }
            MpcTaskId::ManyTriples { start, count } => {
                if count as usize != SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE {
                    return Err(anyhow::anyhow!(
                        "Unsupported batch size for triple generation"
                    ));
                }
                let pending_paired_triples = (0..count / 2)
                    .map(|i| Ok(triple_store.prepare_unowned(start.add_to_counter(i)?)))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let triples = timeout(
                    Duration::from_secs(config.triple.timeout_sec),
                    channel.perform_leader_centric_computation(true, move |channel| {
                        run_many_triple_generation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE>(
                            channel,
                            mpc_config.participants.threshold as usize,
                        )
                        .boxed()
                    }),
                )
                .await??;
                for (pending_triple, paired_triple) in
                    pending_paired_triples.into_iter().zip(triples.into_iter())
                {
                    pending_triple.commit(paired_triple);
                }
            }
            MpcTaskId::Presignature {
                id,
                paired_triple_id,
            } => {
                let pending_asset = presignature_store.prepare_unowned(id);
                let participants = channel.participants().to_vec();
                let presignature = timeout(
                    Duration::from_secs(config.presignature.timeout_sec),
                    channel.perform_leader_centric_computation(true, move |channel| {
                        pre_sign_unowned(
                            channel,
                            mpc_config.participants.threshold as usize,
                            root_keyshare.keygen_output(),
                            triple_store.clone(),
                            paired_triple_id,
                        )
                        .boxed()
                    }),
                )
                .await??;
                pending_asset.commit(PresignOutputWithParticipants {
                    presignature,
                    participants,
                });
            }
            MpcTaskId::Signature {
                id,
                presignature_id,
            } => {
                metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
                let SignatureRequest {
                    msg_hash,
                    tweak,
                    entropy,
                    ..
                } = timeout(
                    Duration::from_secs(config.signature.timeout_sec),
                    sign_request_store.get(id),
                )
                .await??;
                metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

                timeout(
                    Duration::from_secs(config.signature.timeout_sec),
                    channel.perform_leader_centric_computation(false, move |channel| {
                        async move {
                            let presignature = presignature_store
                                .take_unowned(presignature_id)
                                .await?
                                .presignature;
                            sign(
                                channel,
                                root_keyshare.keygen_output(),
                                presignature,
                                msg_hash,
                                tweak,
                                entropy,
                            )
                            .await
                        }
                        .boxed()
                    }),
                )
                .await??;
            }
        }

        Ok(())
    }

    pub async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, AffinePoint)> {
        let (presignature_id, presignature) = self.presignature_store.take_owned().await;
        let sign_request = self.sign_request_store.get(id).await?;
        let channel = self.client.new_channel_for_task(
            MpcTaskId::Signature {
                id,
                presignature_id,
            },
            presignature.participants,
        )?;
        let keygen_output = self.root_keyshare.keygen_output();
        let (signature, public_key) = channel
            .perform_leader_centric_computation(false, move |channel| {
                sign(
                    channel,
                    keygen_output,
                    presignature.presignature,
                    sign_request.msg_hash,
                    sign_request.tweak,
                    sign_request.entropy,
                )
                .boxed()
            })
            .await?;

        Ok((signature, public_key))
    }
}
