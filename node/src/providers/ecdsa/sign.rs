use crate::assets::UniqueId;
use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::ParticipantId;
use crate::protocol::run_protocol;
use crate::providers::ecdsa::kdf::{derive_public_key, derive_randomness};
use crate::providers::ecdsa::{EcdsaSignatureProvider, EcdsaTaskId, PresignatureStorage};
use crate::sign_request::{SignatureId, SignatureRequest};
use cait_sith::protocol::Participant;
use cait_sith::{FullSignature, KeygenOutput, PresignOutput};
use k256::{AffinePoint, Scalar, Secp256k1};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

impl EcdsaSignatureProvider {
    pub(super) async fn make_signature_leader(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, AffinePoint)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let (presignature_id, presignature) = self.presignature_store.take_owned().await;
        let channel = self.client.new_channel_for_task(
            EcdsaTaskId::Signature {
                id,
                presignature_id,
            },
            presignature.participants,
        )?;
        let keygen_output = self.keygen_output.clone();
        let (signature, public_key) = SignComputation {
            keygen_out: keygen_output,
            presign_out: presignature.presignature,
            msg_hash: sign_request.msg_hash,
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await?;

        Ok((signature, public_key))
    }

    pub(super) async fn make_signature_follower(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
        id: SignatureId,
        presignature_id: UniqueId,
    ) -> anyhow::Result<()> {
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED.inc();
        let SignatureRequest {
            msg_hash,
            tweak,
            entropy,
            ..
        } = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        FollowerSignComputation {
            keygen_out: self.keygen_output.clone(),
            presignature_store: self.presignature_store.clone(),
            presignature_id,
            msg_hash,
            tweak,
            entropy,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.signature.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

/// Performs an MPC signature operation. This is the same for the initiator
/// and for passive participants.
/// The entropy is used to rerandomize the presignature (inspired by [GS21])
/// The tweak allows key derivation
pub struct SignComputation {
    pub keygen_out: KeygenOutput<Secp256k1>,
    pub presign_out: PresignOutput<Secp256k1>,
    pub msg_hash: Scalar,
    pub tweak: Scalar,
    pub entropy: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<(FullSignature<Secp256k1>, AffinePoint)> for SignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, AffinePoint)> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();

        let public_key = derive_public_key(self.keygen_out.public_key, self.tweak);

        // rerandomize the presignature: a variant of [GS21]
        let PresignOutput { big_r, k, sigma } = self.presign_out;
        let delta = derive_randomness(
            public_key,
            self.msg_hash,
            big_r,
            channel.participants().to_vec(),
            self.entropy,
        );
        // we use the default inversion: it is absolutely fine to use a
        // variable time inversion since delta is a public value
        let inverted_delta = delta.invert().unwrap();
        let presign_out = PresignOutput {
            // R' = [delta] R
            big_r: (big_r * delta).to_affine(),
            // k' = k/delta
            k: k * inverted_delta,
            // sigma = sigma/delta + k tweak/delta
            sigma: (sigma + self.tweak * k) * inverted_delta,
        };

        let protocol = cait_sith::sign::<Secp256k1>(
            &cs_participants,
            me.into(),
            public_key,
            presign_out,
            self.msg_hash,
        )?;
        let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature = run_protocol("sign", channel, protocol).await?;
        Ok((signature, public_key))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Performs an MPC signature operation as a follower.
/// The difference is that the follower needs to look up the presignature, which may fail.
pub struct FollowerSignComputation {
    pub keygen_out: KeygenOutput<Secp256k1>,
    pub presignature_id: UniqueId,
    pub presignature_store: Arc<PresignatureStorage>,
    pub msg_hash: Scalar,
    pub tweak: Scalar,
    pub entropy: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerSignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let presign_out = self
            .presignature_store
            .take_unowned(self.presignature_id)?
            .presignature;
        SignComputation {
            keygen_out: self.keygen_out,
            presign_out,
            msg_hash: self.msg_hash,
            tweak: self.tweak,
            entropy: self.entropy,
        }
        .compute(channel)
        .await?;
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Simple ID generator for signatures. Generates monotonically increasing IDs.
/// Does not persist state across restarts, so if the clock rewinds then the
/// generated IDs can conflict with previously generated IDs.
#[allow(dead_code)]
pub struct SignatureIdGenerator {
    last_id: Mutex<UniqueId>,
}

#[allow(dead_code)]
impl SignatureIdGenerator {
    pub fn new(my_participant_id: ParticipantId) -> Self {
        Self {
            last_id: Mutex::new(UniqueId::generate(my_participant_id)),
        }
    }

    pub fn generate_signature_id(&self) -> UniqueId {
        let mut last_id = self.last_id.lock().unwrap();
        let new_id = last_id.pick_new_after();
        *last_id = new_id;
        new_id
    }
}
