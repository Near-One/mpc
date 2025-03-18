pub mod key_generation;
mod presign;
mod sign;
use mpc_contract::primitives::key_state::KeyEventId;
pub use presign::PresignatureStorage;
mod kdf;
pub mod key_resharing;
pub mod triple;

pub use triple::TripleStorage;

use crate::assets::UniqueId;
use crate::config::{ConfigFile, MpcConfig, ParticipantsConfig};
use crate::db::{DBCol, SecretDB};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::MpcTaskId;
use crate::providers::{HasParticipants, KeyshareId, SignatureProvider};
use crate::sign_request::{SignRequestStorage, SignatureId};
use crate::tracking;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::{FullSignature, KeygenOutput};
use k256::{AffinePoint, Scalar, Secp256k1};
use near_time::Clock;
use std::sync::Arc;

#[derive(Clone)]
pub struct EcdsaSignatureProvider {
    config: Arc<ConfigFile>,
    mpc_config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    sign_request_store: Arc<SignRequestStorage>,
    keygen_output: KeygenOutput<Secp256k1>,
}

impl EcdsaSignatureProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        mpc_config: Arc<MpcConfig>,
        client: Arc<MeshNetworkClient>,
        clock: Clock,
        db: Arc<SecretDB>,
        sign_request_store: Arc<SignRequestStorage>,
        keygen_output: KeygenOutput<Secp256k1>,
    ) -> anyhow::Result<Self> {
        let active_participants_query = {
            let network_client = client.clone();
            Arc::new(move || network_client.all_alive_participant_ids())
        };

        let triple_store = Arc::new(TripleStorage::new(
            clock.clone(),
            db.clone(),
            DBCol::Triple,
            client.my_participant_id(),
            |participants, pair| pair.is_subset_of_active_participants(participants),
            active_participants_query.clone(),
        )?);

        let presignature_store = Arc::new(PresignatureStorage::new(
            clock,
            db.clone(),
            DBCol::Presignature,
            client.my_participant_id(),
            |participants, presignature| {
                presignature.is_subset_of_active_participants(participants)
            },
            active_participants_query,
        )?);

        Ok(Self {
            config,
            mpc_config,
            client,
            triple_store,
            presignature_store,
            sign_request_store,
            keygen_output,
        })
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

impl KeyshareId for KeygenOutput<Secp256k1> {
    fn keyshare_id() -> &'static str {
        "ecdsa"
    }
}

impl SignatureProvider for EcdsaSignatureProvider {
    type KeygenOutput = KeygenOutput<Secp256k1>;
    type SignatureOutput = (FullSignature<Secp256k1>, AffinePoint);
    type TaskId = EcdsaTaskId;

    async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<Self::SignatureOutput> {
        self.make_signature_leader(id).await
    }

    async fn run_key_generation_client(
        mpc_config: MpcConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_generation_client_internal(mpc_config, channel).await
    }

    async fn run_key_resharing_client(
        config: Arc<MpcConfig>,
        my_share: Option<Scalar>,
        public_key: AffinePoint,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput> {
        EcdsaSignatureProvider::run_key_resharing_client_internal(
            config,
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
                    paired_triple_id,
                } => {
                    self.run_presignature_generation_follower(channel, id, paired_triple_id)
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

            // (#119): Temporary unreachable, since there's only one provider atm
            #[allow(unreachable_patterns)]
            _ => {
                anyhow::bail!(
                    "`process_channel_task` was expecting an `EcdsaSecp256k1TaskId` task"
                );
            }
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

        let generate_presignatures = tracking::spawn(
            "generate presignatures",
            Self::run_background_presignature_generation(
                self.client.clone(),
                self.mpc_config.participants.threshold as usize,
                self.config.presignature.clone().into(),
                self.triple_store.clone(),
                self.presignature_store.clone(),
                self.keygen_output.clone(),
            ),
        );

        generate_triples.await??;
        generate_presignatures.await??;

        Ok(())
    }
}
