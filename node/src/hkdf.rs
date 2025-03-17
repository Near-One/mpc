use anyhow::Context;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, PrimeField},
    AffinePoint, Scalar, U256,
};
use near_indexer_primitives::types::AccountId;
use sha3::{Digest, Sha3_256};

// taken from previous implementation
pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare (probability around 1/2^224) with random bytes as the field size is
    /// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }
}

// TODO: Modify the following function and use instead hkdf.
// WARNING: DO NOT change anything before making sure that the legacy secret/public keys are also changed
// and stored signatures could still be verified.
const TWEAK_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Scalar {
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    // Do not reuse this hash function on anything that isn't an account
    // ID or it'll be vunerable to Hash Melleability/extention attacks.
    let derivation_path = format!("{TWEAK_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes(hash).expect(
        "Expected hash of derived key to be in the
        field of size 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 ",
    )
}

pub fn affine_point_to_public_key(point: AffinePoint) -> anyhow::Result<near_crypto::PublicKey> {
    Ok(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(&point.to_encoded_point(false).as_bytes()[1..65])
            .context("Failed to convert affine point to public key")?,
    ))
}
