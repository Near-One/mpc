use crate::config::Config;
use crate::hkdf::derive_tweak;
use crate::indexer::handler::ChainSignatureRequest;
use crate::indexer::response::ChainRespondArgs;
use crate::metrics;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
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

use crate::key_generation::RootKeyshareData;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use crate::validation::Validation;

#[derive(Clone)]
pub struct MpcClient {
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    root_keyshare: RootKeyshareData,
    web_client: Arc<reqwest::Client>,
    validation: Arc<Validation>,
}

impl MpcClient {
    pub fn get_config(&self) -> Arc<Config> { self.config.clone() }
    pub fn get_web_client(&self) -> Arc<reqwest::Client> { self.web_client.clone() }
    pub fn get_validation(&self) -> Arc<Validation> { self.validation.clone() }
    pub fn get_public_key(&self) -> AffinePoint { self.root_keyshare.public_key }

    pub fn new(
        config: Arc<Config>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        sign_request_store: Arc<SignRequestStorage>,
        root_keyshare: RootKeyshareData,
        web_client: Arc<reqwest::Client>,
        validation: Arc<Validation>
    ) -> Self {
        Self {
            config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            root_keyshare,
            web_client,
            validation
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
        mut sign_request_receiver: mpsc::Receiver<ChainSignatureRequest>,
        sign_response_sender: mpsc::Sender<ChainRespondArgs>,
    ) -> anyhow::Result<()> {
        let monitor_passive_channels = {
            let client = self.client.clone();
            let config = self.config.clone();
            let triple_store = self.triple_store.clone();
            let presignature_store = self.presignature_store.clone();
            let sign_request_store = self.sign_request_store.clone();
            let root_keyshare = self.root_keyshare.clone();
            tracking::spawn("monitor passive channels", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    let client = client.clone();
                    let config = config.clone();
                    let triple_store = triple_store.clone();
                    let presignature_store = presignature_store.clone();
                    let sign_request_store = sign_request_store.clone();
                    let root_keyshare = root_keyshare.clone();
                    tasks.spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        async move {
                            match channel.task_id {
                                MpcTaskId::KeyGeneration => {
                                    anyhow::bail!(
                                        "Key generation rejected in normal node operation"
                                    );
                                }
                                MpcTaskId::ManyTriples { start, count } => {
                                    if count as usize != SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE {
                                        return Err(anyhow::anyhow!(
                                            "Unsupported batch size for triple generation"
                                        ));
                                    }
                                    let pending_paired_triples = (0..count / 2)
                                        .map(|i| {
                                            anyhow::Ok(
                                                triple_store
                                                    .prepare_unowned(start.add_to_counter(i)?),
                                            )
                                        })
                                        .collect::<anyhow::Result<Vec<_>>>()?;
                                    let triples = timeout(
                                        Duration::from_secs(config.triple.timeout_sec),
                                        run_many_triple_generation::<
                                            SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
                                        >(
                                            channel,
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                        ),
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
                                    let participants = channel.participants.clone();
                                    let presignature = timeout(
                                        Duration::from_secs(config.presignature.timeout_sec),
                                        pre_sign_unowned(
                                            channel,
                                            client.my_participant_id(),
                                            config.mpc.participants.threshold as usize,
                                            root_keyshare.keygen_output(),
                                            triple_store.clone(),
                                            paired_triple_id,
                                        ),
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
                                    // TODO(#69): decide a better timeout for this
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

                                    timeout(
                                        Duration::from_secs(config.signature.timeout_sec),
                                        sign(
                                            channel,
                                            client.my_participant_id(),
                                            root_keyshare.keygen_output(),
                                            presignature_store
                                                .take_unowned(presignature_id)
                                                .await?
                                                .presignature,
                                            msg_hash,
                                            tweak,
                                            entropy,
                                        ),
                                    )
                                    .await??;
                                }
                            }
                            anyhow::Ok(())
                        },
                    );
                }
            })
        };

        let monitor_chain = {
            let this = Arc::new(self.clone());
            let config = self.config.clone();
            let network_client = self.client.clone();
            tracking::spawn("monitor chain", async move {
                let mut tasks = AutoAbortTaskCollection::new();
                loop {
                    let this = this.clone();
                    let config = config.clone();
                    let sign_request_store = self.sign_request_store.clone();
                    let sign_response_sender = sign_response_sender.clone();

                    let ChainSignatureRequest {
                        request_id,
                        request,
                        predecessor_id,
                        entropy,
                        timestamp_nanosec,
                    } = sign_request_receiver.recv().await.unwrap();

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
                                compute_leaders_for_signing(&config.mpc, &request);
                            // start the signing process if we are the primary leader or if we are the secondary leader
                            // and the primary leader is not alive
                            if config.mpc.my_participant_id == primary_leader
                                || (config.mpc.my_participant_id == secondary_leader
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
                                let _ = sign_response_sender.send(response).await;
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
                self.config.mpc.participants.threshold as usize,
                self.config.triple.clone().into(),
                self.triple_store.clone(),
            ),
        );

        let generate_presignatures = tracking::spawn(
            "generate presignatures",
            run_background_presignature_generation(
                self.client.clone(),
                self.config.mpc.participants.threshold as usize,
                self.config.presignature.clone().into(),
                self.triple_store.clone(),
                self.presignature_store.clone(),
                self.root_keyshare.keygen_output(),
            ),
        );

        monitor_passive_channels.await?;
        monitor_chain.await?;
        generate_triples.await??;
        generate_presignatures.await??;

        Ok(())
    }

    // TODO: this is testonly and needs to be protected
    pub fn add_sign_request(&self, request: &SignatureRequest) {
        self.sign_request_store.add(request);
    }

    pub async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, AffinePoint)> {
        let (presignature_id, presignature) = self
            .presignature_store
            .take_owned(&self.client.all_alive_participant_ids())
            .await;
        let sign_request = self.sign_request_store.get(id).await?;
        let (signature, public_key) = sign(
            self.client.new_channel_for_task(
                MpcTaskId::Signature {
                    id,
                    presignature_id,
                },
                presignature.participants,
            )?,
            self.client.my_participant_id(),
            self.root_keyshare.keygen_output(),
            presignature.presignature,
            sign_request.msg_hash,
            sign_request.tweak,
            sign_request.entropy,
        )
        .await?;

        Ok((signature, public_key))
    }
}
