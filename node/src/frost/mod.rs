//! This module serves as a wrapper for Frost protocol.
//!
//! Frost library exposes methods like `sign::round1()`, `sign::round2()`, `sign::aggregate()`, etc.
//! The output of those functions needs to be communicated to other participants in a specific order.
//! Such a process can be described as a state machine and its state transitions.
//!
//! To construct it, an `impl Protocol` from `cait_sith` library was used, together with related "plumbing"
//! code, that allows us to implement a protocol as an async function with yield points,
//! which simplifies code maintenance.
//!
//! To run Frost protocol, we have to assign each participant its identifier.
//! We do so by converting existing `ParticipantId` via `to_frost_identifier()`.
//! This is a one way process, since the conversion requires hashing/modulo reduce.
//! In order to do the inverse cast (frost, EdDSA identifier) -> (cait-sith, Participant),
//! one should have all (historical) `Participants`.
//!
//! There's no identifiable aborts, i.e. you might see an Err(_) with e.g. "incorrect number of shares supplied",
//! or "Participant X supplied incorrect data", but pragmatically you will not be able to do anything with this info.

mod dkg;
mod kdf;
mod sign;
mod tests;

use cait_sith::protocol::{Participant, Protocol};
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::Signature;
use rand::{CryptoRng, RngCore};

/// Build a signature protocol for `coordinator`.
///
/// Amongst protocol `participants` has to be exactly one Coordinator.
/// It's the only party, who eventually constructs a full signature.
/// It's up to the application to decide who needs to be the coordinator.
///
/// If a party is included in `participants` set, then it has to supply their share to the coordinator
/// in order for a protocol to succeed. Even if the set size is greater than the required `threshold`.
/// It is up to the application to construct such a set.
#[allow(dead_code)] // TODO(#119): remove the directive when this will be actually used.
pub fn sign_coordinator<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    keygen_output: KeygenOutput,
    msg_hash: Vec<u8>,
) -> anyhow::Result<impl Protocol<Output = Signature>> {
    sign::sign_internal_coordinator(rng, participants, me, keygen_output, msg_hash)
}

/// Build a signature protocol for a passive `participant`.
#[allow(dead_code)] // TODO(#119): remove the directive when this will be actually used.
pub fn sign_passive<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    keygen_output: KeygenOutput,
    msg_hash: Vec<u8>,
) -> anyhow::Result<impl Protocol<Output = ()>> {
    sign::sign_internal_passive(rng, keygen_output, msg_hash)
}

/// Participant's key-pair in Frost
#[allow(dead_code)] // TODO(#119): remove compiler directive when this will be actually used.
#[derive(Debug, Clone)]
pub struct KeygenOutput {
    pub key_package: KeyPackage,
    // Although group's public key can be found in `KeyPackage` too,
    //  `PublicKeyPackage` is needed when calling signature `aggregate()`.
    pub public_key_package: PublicKeyPackage,
}

/// Do key derivation from the main key-pair
#[allow(dead_code)] // TODO(#119): remove this compiler directive when this will be actually used.
pub fn derive_keygen_output(keygen_output: &KeygenOutput, tweak: [u8; 32]) -> KeygenOutput {
    kdf::derive_keygen_output(keygen_output, tweak)
}

/// Distributed Key Generation protocol.
#[allow(dead_code)] // TODO(#119): remove compiler directive when this will be actually used.
pub fn dkg<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    threshold: usize,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    dkg::dkg_internal(rng, participants, me, threshold)
}

/// Derive Frost identifier (ed25519 scalar) from u32
pub fn to_frost_identifier(participant: Participant) -> frost_ed25519::Identifier {
    frost_ed25519::Identifier::derive(participant.bytes().as_slice())
        .expect("Identifier derivation must succeed: cipher suite is guaranteed to be implemented")
}
