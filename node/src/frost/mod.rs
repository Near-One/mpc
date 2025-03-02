use cait_sith::protocol::Participant;
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};

mod refresh;
mod repair;
mod tests;
mod reshare;

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
