use crate::config::Config;
use crate::indexer::handler::ChainSignatureRequest;
use crate::indexer::response::ChainRespondArgs;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{
    choose_random_participants, MpcTaskId, MpcTaskSignatureType, PresignOutputWithParticipants,
};
use crate::sign::{
    pre_sign_unowned, run_background_presignature_generation, sign_ecdsa, sign_eddsa_coordinator,
    sign_eddsa_participant, PresignatureStorage,
};
use crate::sign_request::{SignRequestStorage, SignatureId, SignatureRequest};
use crate::tracking::{self, AutoAbortTaskCollection};
use crate::triple::{
    run_background_triple_generation, run_many_triple_generation, TripleStorage,
    SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
};

use crate::key_generation::RootKeyshareData;
use crate::validation::Validation;
use crate::web::KeyType;
use cait_sith::FullSignature;
use k256::Secp256k1;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

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

pub struct EcdsaSignature {
    pub signature: FullSignature<Secp256k1>,
    pub public_key: k256::AffinePoint,
}

pub struct EddsaSignature {
    pub signature: frost_ed25519::Signature,
    pub public_key: frost_ed25519::VerifyingKey,
}

pub enum SignatureResult {
    Ecdsa(EcdsaSignature),
    Eddsa(EddsaSignature),
}

impl MpcClient {
    pub fn get_config(&self) -> Arc<Config> {
        self.config.clone()
    }
    pub fn get_web_client(&self) -> Arc<reqwest::Client> {
        self.web_client.clone()
    }
    pub fn get_validation(&self) -> Arc<Validation> {
        self.validation.clone()
    }
    pub fn get_public_key(&self) -> (frost_ed25519::keys::PublicKeyPackage, k256::AffinePoint) {
        (
            self.root_keyshare.eddsa.public_key.clone(),
            self.root_keyshare.ecdsa.public_key,
        )
    }

    pub fn new(
        config: Arc<Config>,
        client: Arc<MeshNetworkClient>,
        triple_store: Arc<TripleStorage>,
        presignature_store: Arc<PresignatureStorage>,
        sign_request_store: Arc<SignRequestStorage>,
        root_keyshare: RootKeyshareData,
        web_client: Arc<reqwest::Client>,
        validation: Arc<Validation>,
    ) -> Self {
        Self {
            config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            root_keyshare,
            web_client,
            validation,
        }
    }

    /// Main entry point for the MPC node. Runs all the business logic for doing
    /// multiparty computation.
    pub async fn run(
        self,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
        sign_request_receiver: mpsc::Receiver<ChainSignatureRequest>,
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
                                MpcTaskId::KeyGenerationEddsa |
                                MpcTaskId::KeyGenerationEcdsa => {
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
                                            root_keyshare.ecdsa.keygen_output(),
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
                                    signature_type,
                                } => {
                                    // TODO(#69): decide a better timeout for this
                                    let SignatureRequest {
                                        message,
                                        tweak,
                                        entropy,
                                        ..
                                    } = timeout(
                                        Duration::from_secs(config.signature.timeout_sec),
                                        sign_request_store.get(id),
                                    )
                                    .await??;

                                    match signature_type {
                                        MpcTaskSignatureType::Eddsa => {
                                            timeout(
                                                Duration::from_secs(config.signature.timeout_sec),
                                                sign_eddsa_participant(
                                                    channel,
                                                    client.my_participant_id(),
                                                    root_keyshare.eddsa.clone().into(),
                                                    message,
                                                    tweak,
                                                )
                                            ).await??;
                                        }
                                        MpcTaskSignatureType::Ecdsa { presignature_id } => {
                                            let msg_hash: [u8; 32] = hex::decode(message)?
                                                .try_into()
                                                .map_err(|_| anyhow::anyhow!("Decoded hex message expected to be exactly 32 bytes long"))?;

                                            timeout(
                                                Duration::from_secs(config.signature.timeout_sec),
                                                sign_ecdsa(
                                                    channel,
                                                    client.my_participant_id(),
                                                    root_keyshare.ecdsa.keygen_output(),
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
                                }
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
                self.root_keyshare.ecdsa.keygen_output(),
            ),
        );

        monitor_passive_channels.await?;
        // monitor_chain.await?;
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
    ) -> anyhow::Result<SignatureResult> {
        let sign_request = self.sign_request_store.get(id).await?;
        match sign_request.key_type {
            KeyType::Ecdsa => self.make_ecdsa_signature(sign_request).await,
            KeyType::Ed25519 => self.make_eddsa_signature(sign_request).await,
        }
    }

    async fn make_ecdsa_signature(
        self: Arc<Self>,
        sign_request: SignatureRequest,
    ) -> anyhow::Result<SignatureResult> {
        let message: [u8; 32] = hex::decode(&sign_request.message)?
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("Decoded hex message expected to be exactly 32 bytes long")
            })?;

        let (presignature_id, presignature) = self
            .presignature_store
            .take_owned(&self.client.all_alive_participant_ids())
            .await;

        let (signature, public_key) = sign_ecdsa(
            self.client.new_channel_for_task(
                MpcTaskId::Signature {
                    id: sign_request.id,
                    signature_type: MpcTaskSignatureType::Ecdsa { presignature_id },
                },
                presignature.participants,
            )?,
            self.client.my_participant_id(),
            self.root_keyshare.ecdsa.keygen_output(),
            presignature.presignature,
            message,
            sign_request.tweak,
            sign_request.entropy,
        )
        .await?;

        Ok(SignatureResult::Ecdsa(EcdsaSignature {
            signature,
            public_key,
        }))
    }

    async fn make_eddsa_signature(
        self: Arc<Self>,
        sign_request: SignatureRequest,
    ) -> anyhow::Result<SignatureResult> {
        let task_id = MpcTaskId::Signature {
            id: sign_request.id,
            signature_type: MpcTaskSignatureType::Eddsa,
        };

        //

        let client = self.client.clone();
        let threshold = self.config.mpc.participants.threshold as usize;

        let current_active_participants_ids = client.all_alive_participant_ids();

        if current_active_participants_ids.len() < threshold {
            anyhow::bail!("Not enough participants to sign");
        }

        let participants = choose_random_participants(
            current_active_participants_ids,
            client.my_participant_id(),
            threshold,
        );

        //

        let channel = self.client.new_channel_for_task(task_id, participants)?;

        let (signature, public_key) = sign_eddsa_coordinator(
            channel,
            self.config.mpc.my_participant_id,
            self.root_keyshare.eddsa.clone().into(),
            sign_request.message,
            sign_request.tweak,
        )
        .await?;

        Ok(SignatureResult::Eddsa(EddsaSignature {
            signature,
            public_key,
        }))
    }
}
