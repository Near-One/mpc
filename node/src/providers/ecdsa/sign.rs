use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::NetworkTaskChannel;
use crate::primitives::UniqueId;
use crate::protocol::run_protocol;
use crate::providers::ecdsa::kdf::{derive_public_key, derive_randomness};
use crate::providers::ecdsa::{
    EcdsaSignatureProvider, EcdsaTaskId, KeygenOutput, PresignatureStorage,
};
use crate::sign_request::SignatureId;
use anyhow::Context;
use cait_sith::ecdsa::presign::PresignOutput;
use cait_sith::ecdsa::sign::FullSignature;
use cait_sith::frost_secp256k1::VerifyingKey;
use cait_sith::protocol::Participant;
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, Secp256k1};
use mpc_contract::primitives::signature::Tweak;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

impl EcdsaSignatureProvider {
    pub(super) async fn make_signature_leader(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, VerifyingKey)> {
        let sign_request = self.sign_request_store.get(id).await?;
        let domain_data = self.domain_data(sign_request.domain)?;
        let (presignature_id, presignature) = domain_data.presignature_store.take_owned().await;
        let channel = self.client.new_channel_for_task(
            EcdsaTaskId::Signature {
                id,
                presignature_id,
            },
            presignature.participants,
        )?;

        let (signature, public_key) = SignComputation {
            keygen_out: domain_data.keyshare,
            presign_out: presignature.presignature,
            msg_hash: *sign_request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
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
        let sign_request = timeout(
            Duration::from_secs(self.config.signature.timeout_sec),
            self.sign_request_store.get(id),
        )
        .await??;
        metrics::MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED.inc();

        let domain_data = self.domain_data(sign_request.domain)?;

        FollowerSignComputation {
            keygen_out: domain_data.keyshare,
            presignature_store: domain_data.presignature_store.clone(),
            presignature_id,
            msg_hash: *sign_request
                .payload
                .as_ecdsa()
                .ok_or_else(|| anyhow::anyhow!("Payload is not an ECDSA payload"))?,
            tweak: sign_request.tweak,
            entropy: sign_request.entropy,
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
    pub keygen_out: KeygenOutput,
    pub presign_out: PresignOutput<Secp256k1>,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
    pub entropy: [u8; 32],
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<(FullSignature<Secp256k1>, VerifyingKey)> for SignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<(FullSignature<Secp256k1>, VerifyingKey)> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();

        let tweak = Scalar::from_repr(self.tweak.as_bytes().into())
            .into_option()
            .context("Couldn't construct k256 point")?;
        let msg_hash = Scalar::from_repr(self.msg_hash.into())
            .into_option()
            .context("Couldn't construct k256 point")?;

        let public_key =
            derive_public_key(self.keygen_out.public_key.to_element().to_affine(), tweak);

        // rerandomize the presignature: a variant of [GS21]
        let PresignOutput { big_r, k, sigma } = self.presign_out;
        let delta = derive_randomness(
            public_key,
            msg_hash,
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
            sigma: (sigma + tweak * k) * inverted_delta,
        };

        let protocol = cait_sith::ecdsa::sign::sign(
            &cs_participants,
            me.into(),
            public_key,
            presign_out,
            msg_hash,
        )?;
        let _timer = metrics::MPC_SIGNATURE_TIME_ELAPSED.start_timer();
        let signature = run_protocol("sign", channel, protocol).await?;
        Ok((signature, VerifyingKey::new(public_key.into())))
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

/// Performs an MPC signature operation as a follower.
/// The difference is that the follower needs to look up the presignature, which may fail.
pub struct FollowerSignComputation {
    pub keygen_out: KeygenOutput,
    pub presignature_id: UniqueId,
    pub presignature_store: Arc<PresignatureStorage>,
    pub msg_hash: [u8; 32],
    pub tweak: Tweak,
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
