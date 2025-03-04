use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use cait_sith::protocol::{Participant, Protocol};
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};

mod common;
mod refresh;
mod repair;
mod reshare;
mod tests;

#[allow(dead_code)] // TODO(#119): remove the directive when this will be actually used.
pub(crate) fn reshare_old_participant<RNG: CryptoRng + RngCore + 'static + Send + Clone>(
    rng: RNG,
    old_participants: &[Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
    my_share: KeygenOutput,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    reshare::reshare_old_participant_internal(
        rng,
        old_participants,
        old_threshold,
        new_participants,
        new_threshold,
        me,
        my_share,
    )
}

#[allow(dead_code)] // TODO(#119): remove the directive when this will be actually used.
pub(crate) fn reshare_new_participant<RNG: CryptoRng + RngCore + 'static + Send + Clone>(
    rng: RNG,
    old_participants: &[Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    reshare::reshare_new_participant_internal(
        rng,
        old_participants,
        old_threshold,
        new_participants,
        new_threshold,
        me,
    )
}

/// Participant's key-pair in Frost
#[derive(Debug, Clone)]
pub struct KeygenOutput {
    pub key_package: KeyPackage,
    // Although group's public key can be found in `KeyPackage` too,
    //  `PublicKeyPackage` is needed when calling signature `aggregate()`.
    pub public_key_package: PublicKeyPackage,
}

/// Derive Frost identifier (ed25519 scalar) from u32
pub fn to_frost_identifier(participant: Participant) -> frost_ed25519::Identifier {
    frost_ed25519::Identifier::derive(participant.bytes().as_slice())
        .expect("Identifier derivation must succeed: cipher suite is guaranteed to be implemented")
}
