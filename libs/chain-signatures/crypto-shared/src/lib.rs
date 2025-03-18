pub mod kdf;
pub mod types;

use ed25519_dalek::VerifyingKey;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::EncodedPoint;
pub use kdf::{
    derive_epsilon,
    secp256k1::{derive_key, x_coordinate},
};
use types::Scheme;
pub use types::{
    curve25519_types, k256_types, Ed25519PublicKey, ScalarExt, Secp256k1PublicKey,
    SignatureResponse,
};

// Our wasm runtime doesn't support good syncronous entropy.
// We could use something VRF + pseudorandom here, but someone would likely shoot themselves in the foot with it.
// Our crypto libraries should definately panic, because they normally expect randomness to be private
#[cfg(target_arch = "wasm32")]
use getrandom::{register_custom_getrandom, Error};
#[cfg(target_arch = "wasm32")]
pub fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
register_custom_getrandom!(randomness_unsupported);

pub fn near_public_key_to_affine_point(pk: near_sdk::PublicKey) -> Secp256k1PublicKey {
    let mut bytes = pk.into_bytes();
    bytes[0] = 0x04;
    let point = EncodedPoint::from_bytes(bytes).unwrap();
    Secp256k1PublicKey::from_encoded_point(&point).unwrap()
}

// TODO: Verify with Simon if this is needed
pub fn near_public_key_to_edwards_point(pk: near_sdk::PublicKey) -> VerifyingKey {
    todo!()
}
