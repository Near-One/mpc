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
mod sign;
mod tests;

use cait_sith::protocol::{Participant, Protocol};
use rand::{CryptoRng, RngCore};

/// Build a signature protocol.
///
/// Amongst protocol `participants` has to be exactly one Coordinator.
/// It's the only party, who eventually constructs a full signature.
/// This party calls the function with `is_coordinator=true`, while everyone else supplies `false`.
/// It's up to the application to decide who needs to be the coordinator.
///
/// If a party is included in `participants` set, then it has to supply their share to the coordinator
/// in order for a protocol to succeed. Even if the set size is greater than the required `threshold`.
/// It is up to the application to construct such a set.
///
/// Return type is a boxed protocol, because we can have:
///     (a) single entry point for a coordinator/participant protocol creation
///     (b) test executor for such protocols
pub fn sign<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    is_coordinator: bool,
    participants: Vec<Participant>,
    me: Participant,
    key_package: frost_ed25519::keys::KeyPackage,
    pubkeys: frost_ed25519::keys::PublicKeyPackage,
    msg_hash: Vec<u8>,
) -> anyhow::Result<Box<dyn Protocol<Output = SignatureOutput>>> {
    sign::sign_internal(
        rng,
        is_coordinator,
        participants,
        me,
        key_package,
        pubkeys,
        msg_hash,
    )
}

/// Mentioned Coordinator/Participant separation in sign protocol results in different return types.
#[derive(Debug)]
pub enum SignatureOutput {
    Coordinator(frost_ed25519::Signature),
    Participant,
}

pub struct KeygenOutput {
    key_package: frost_ed25519::keys::KeyPackage,
    public_key_package: frost_ed25519::keys::PublicKeyPackage,
}

/// Distributed Key Generation protocol.
pub fn dkg<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    threshold: u16,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    dkg::dkg_internal(rng, participants, me, threshold)
}

/// Derive Frost identifier (ed25519 scalar) from u32
pub fn to_frost_identifier(participant: Participant) -> frost_ed25519::Identifier {
    frost_ed25519::Identifier::derive(participant.bytes().as_slice())
        .expect("Identifier derivation must succeed: cipher suite is guaranteed to be implemented")
}
