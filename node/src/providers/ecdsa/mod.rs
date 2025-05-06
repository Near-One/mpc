pub mod key_generation;
mod presign;
mod sign;

use mpc_contract::primitives::key_state::KeyEventId;
pub use presign::PresignatureStorage;
use std::collections::HashMap;
mod kdf;
pub mod key_resharing;
pub mod triple;

pub use triple::TripleStorage;

use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::db::SecretDB;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::{PublicKeyConversion, SignatureProvider};
use crate::sign_request::{SignRequestStorage, SignatureId};
use crate::tracking;
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::ecdsa::sign::FullSignature;
use cait_sith::ecdsa::KeygenOutput;
use cait_sith::frost_secp256k1::keys::SigningShare;
use cait_sith::frost_secp256k1::VerifyingKey;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, Secp256k1};
use mpc_contract::primitives::domain::DomainId;
use near_time::Clock;
use std::sync::Arc;

pub struct EcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    per_domain_data: HashMap<DomainId, PerDomainData>,
}

#[derive(Clone)]
pub(super) struct PerDomainData {
    pub keyshare: KeygenOutput,
    pub presignature_store: Arc<PresignatureStorage>,
}

impl EcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keyshares: HashMap<DomainId, KeygenOutput>,
    ) -> anyhow::Result<Self> {
        let active_participants_query = {
            let network_client = client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        let triple_store = Arc::new(TripleStorage::new(
            clock.clone(),
            db.clone(),
            client.my_participant_id(),
            active_participants_query.clone(),
        )?);

        let mut per_domain_data = HashMap::new();
        for (domain_id, keyshare) in keyshares {
            let presignature_store = Arc::new(PresignatureStorage::new(
                clock.clone(),
                db.clone(),
                client.my_participant_id(),
                active_participants_query.clone(),
                domain_id,
            )?);
            per_domain_data.insert(
                domain_id,
                PerDomainData {
                    keyshare,
                    presignature_store,
                },
            );
        }

        Ok(Self {
            config,
            mpc_config,
            client,
            triple_store,
            sign_request_store,
            per_domain_data,
        })
    }

    pub(super) fn domain_data(&self, domain_id: DomainId) -> anyhow::Result<PerDomainData> {
        self.per_domain_data
            .get(&domain_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No keyshare for domain {:?}", domain_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum EcdsaTaskId {
    KeyGeneration {
        key_event: KeyEventId,
    },
    KeyResharing {
        key_event: KeyEventId,
    },
    ManyTriples {
        start: UniqueId,
        count: u32,
    },
    Presignature {
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    },
    Signature {
        id: SignatureId,
        presignature_id: UniqueId,
    },
}

impl From<EcdsaTaskId> for MpcTaskId {
    fn from(val: EcdsaTaskId) -> Self {
        MpcTaskId::EcdsaTaskId(val)
    }
}

impl SignatureProvider for EcdsaSignatureProvider {
    type PublicKey = VerifyingKey;
    type SecretShare = SigningShare;
    type KeygenOutput = KeygenOutput;
    type Signature = FullSignature<Secp256k1>;
    type TaskId = EcdsaTaskId;

    async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(Self::Signature, Self::PublicKey)> {
        self.make_signature_leader(id).await
    }

    async fn run_key_generation_client(
        threshold: usize,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_generation_client_internal(threshold, channel).await
    }

    async fn run_key_resharing_client(
        new_threshold: usize,
        my_share: Option<SigningShare>,
        public_key: VerifyingKey,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_resharing_client_internal(
            new_threshold,
            my_share,
            public_key,
            old_participants,
            channel,
        )
        .await
    }

    async fn process_channel(self: Arc<Self>, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::EcdsaTaskId(task) => match task {
                EcdsaTaskId::KeyGeneration { .. } => {
                    anyhow::bail!("Key generation rejected in normal node operation");
                }
                EcdsaTaskId::KeyResharing { .. } => {
                    anyhow::bail!("Key resharing rejected in normal node operation");
                }
                EcdsaTaskId::ManyTriples { start, count } => {
                    self.run_triple_generation_follower(channel, start, count)
                        .await?;
                }
                EcdsaTaskId::Presignature {
                    id,
                    domain_id,
                    paired_triple_id,
                } => {
                    self.run_presignature_generation_follower(
                        channel,
                        id,
                        domain_id,
                        paired_triple_id,
                    )
                    .await?;
                }
                EcdsaTaskId::Signature {
                    id,
                    presignature_id,
                } => {
                    self.make_signature_follower(channel, id, presignature_id)
                        .await?;
                }
            },

            _ => anyhow::bail!(
                "eddsa task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }
        Ok(())
    }

    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()> {
        let generate_triples = tracking::spawn(
            "generate triples",
            Self::run_background_triple_generation(
                self.client.clone(),
                self.mpc_config.participants.threshold as usize,
                self.config.triple.clone().into(),
                self.triple_store.clone(),
            ),
        );

        let generate_presignatures = self
            .per_domain_data
            .iter()
            .map(|(domain_id, data)| {
                tracking::spawn(
                    &format!("generate presignatures for domain {}", domain_id.0),
                    Self::run_background_presignature_generation(
                        self.client.clone(),
                        self.mpc_config.participants.threshold as usize,
                        self.config.presignature.clone().into(),
                        self.triple_store.clone(),
                        *domain_id,
                        data.presignature_store.clone(),
                        data.keyshare.clone(),
                    ),
                )
            })
            .collect::<Vec<_>>();

        generate_triples.await??;
        for task in generate_presignatures {
            task.await??;
        }

        Ok(())
    }
}

impl PublicKeyConversion for VerifyingKey {
    fn to_near_public_key(&self) -> anyhow::Result<near_crypto::PublicKey> {
        let bytes = self.to_element().to_encoded_point(false).to_bytes();
        anyhow::ensure!(bytes[0] == 0x04);
        Ok(near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(&bytes[1..65])
                .context("Failed to convert public key to near crypto type")?,
        ))
    }

    fn from_near_crypto(public_key: &near_crypto::PublicKey) -> anyhow::Result<Self> {
        match public_key {
            near_crypto::PublicKey::SECP256K1(key) => {
                let mut bytes = [0u8; 65];
                bytes[0] = 0x04;
                bytes[1..65].copy_from_slice(key.as_ref());

                let encoded_point = EncodedPoint::from_bytes(bytes)?;
                let affine_point = AffinePoint::from_encoded_point(&encoded_point)
                    .into_option()
                    .ok_or(anyhow::anyhow!(
                        "Failed to convert encoded point to affine point"
                    ))?;
                Ok(VerifyingKey::new(affine_point.into()))
            }
            _ => anyhow::bail!("Unsupported public key type"),
        }
    }
}

#[test]
fn check_pubkey_conversion_to_sdk() -> anyhow::Result<()> {
    use crate::tests::TestGenerators;
    let x = TestGenerators::new(4, 3)
        .make_ecdsa_keygens()
        .values()
        .next()
        .unwrap()
        .clone();
    x.public_key.to_near_public_key()?;
    Ok(())
}

#[test]
fn check_conversion_from_sdk() -> anyhow::Result<()> {
    let near_sdk: near_sdk::PublicKey = "secp256k1:5TJSTQwYwe3MgTCep9DbLxLT6UjB6LFn3SStpBMgdfGjBopNjxL7mpNK92R6cdyByjz7vUQdRgtLiu9w84kopNqn"
                .parse()?;
    let _ = VerifyingKey::from_near_sdk(&near_sdk)?;
    Ok(())
}
