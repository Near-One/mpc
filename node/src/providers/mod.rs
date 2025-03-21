//! This module abstracts the Signature Schema,
//! i.e., we might want to use ECDSA over the Secp256k1 curve, EdDSA over Ed25519, or something else.
//! `SignatureProvider` exposes an interface for such add-ons. Alongside it, helper functions
//! (like `RegisterMpcTask`) are exposed, which somewhat guarantees that if the code compiles,
//! you don’t need to add anything more internally for it to work.
//!
//! As a reference, check the existing implementations.

pub mod ecdsa;
pub use ecdsa::EcdsaSignatureProvider;
pub use ecdsa::EcdsaTaskId;
use k256::AffinePoint;

use crate::config::ParticipantsConfig;
use crate::network::NetworkTaskChannel;
use crate::sign_request::SignatureId;
use k256::Scalar;
use std::sync::Arc;

use crate::config::MpcConfig;
use crate::primitives::{MpcTaskId, ParticipantId};

/// This `keyshare_id` is used for persisting a key share.
/// The returned value should be unique across all `SignatureProviders`.
#[allow(dead_code)] // TODO: To be fixed in #252 follow-up
pub trait KeyshareId {
    fn keyshare_id() -> &'static str;
}

/// The interface that defines the requirements for a signing schema to be correctly used in the code.
#[allow(dead_code)] // TODO: To be fixed in #252 follow-up
pub trait SignatureProvider {
    type KeygenOutput: KeyshareId;
    type SignatureOutput;

    /// Trait bound `Into<MpcTaskId>` serves as a way to see what logic needs to be added,
    /// when introducing new `TaskId`. Implementation of the trait should be trivial.
    type TaskId: Into<MpcTaskId>;

    /// Generates a signature.
    /// The implementation should handle the key derivation function (KDF) if needed.
    /// Only the leader should call this function.
    async fn make_signature(
        self: Arc<Self>,
        id: SignatureId,
    ) -> anyhow::Result<Self::SignatureOutput>;

    /// Executes the key generation protocol.
    /// Returns once key generation is complete or encounters an error.
    /// This should only succeed if all participants are online and running this function.
    ///
    /// Both leaders and followers call this function.
    ///
    /// It drains `channel_receiver` until the required task is found, meaning these clients must not be run in parallel.
    async fn run_key_generation_client(
        mpc_config: MpcConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput>;

    /// Executes the key resharing protocol. This can only succeed if all new participants are online.
    /// Both leaders and followers call this function.
    /// It drains `channel_receiver` until the required task is found, meaning these clients must not be run in parallel.
    async fn run_key_resharing_client(
        config: Arc<MpcConfig>,
        key_share: Option<Scalar>,
        public_key: AffinePoint,
        old_participants: &ParticipantsConfig,
        channel: NetworkTaskChannel,
    ) -> anyhow::Result<Self::KeygenOutput>;

    /// Expected to be called in a common loop that handles received channels and redirects them
    /// to the respective `SignatureProvider`.
    /// This function is called during the "normal MPC run",
    /// i.e., it should fail if it receives messages from the `KeyGeneration` or `KeyResharing` stage.
    async fn process_channel(self: Arc<Self>, channel: NetworkTaskChannel) -> anyhow::Result<()>;

    /// Spawns any auxiliary logic that performs pre-computation (typically meant to optimize signature delay).
    async fn spawn_background_tasks(self: Arc<Self>) -> anyhow::Result<()>;
}

/// A resource might be generated with a set of some participants `A`.
/// This trait helps check whether the current set of participants contains `A`.
pub trait HasParticipants {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool;
}
