use crate::{
    crypto_shared::types::{k256_types, ScalarExt},
    primitives::signature::Tweak,
};
use anyhow::Context;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use k256::{
    ecdsa::{RecoveryId, Signature},
    elliptic_curve::{point::AffineCoordinates, sec1::ToEncodedPoint, CurveArithmetic},
    Secp256k1,
};
use near_account_id::AccountId;
use sha3::{Digest, Sha3_256};

// Constant prefix that ensures tweak derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const TWEAK_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_tweak(predecessor_id: &AccountId, path: &str) -> Tweak {
    // TODO: Use a key derivation library instead of doing this manually.
    // https://crates.io/crates/hkdf might be a good option?
    //
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    // Do not reuse this hash function on anything that isn't an account
    // ID or it'll be vunerable to Hash Melleability/extention attacks.
    let derivation_path = format!("{TWEAK_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    Tweak::new(hash)
}

pub fn derive_key_secp256k1(
    public_key: &k256_types::PublicKey,
    tweak: &Tweak,
) -> k256_types::PublicKey {
    let tweak = k256::Scalar::from_non_biased(tweak.as_bytes());
    (<Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * tweak + public_key).to_affine()
}

pub fn derive_public_key_edwards_point_edd25519(
    point: &curve25519_dalek::EdwardsPoint,
    tweak: &Tweak,
) -> curve25519_dalek::EdwardsPoint {
    let tweak = curve25519_dalek::Scalar::from_non_biased(tweak.as_bytes());
    point + ED25519_BASEPOINT_POINT * tweak
}

/// Get the x coordinate of a point, as a scalar
pub fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

pub fn check_ec_signature(
    expected_pk: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: &[u8; 32],
    recovery_id: u8,
) -> anyhow::Result<()> {
    let public_key = expected_pk.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from cait_sith signature")?;
    let found_pk = recover(
        msg_hash,
        &signature,
        RecoveryId::try_from(recovery_id).context("invalid recovery ID")?,
    )?
    .to_encoded_point(false);
    if public_key == found_pk {
        return Ok(());
    }

    anyhow::bail!("cannot use either recovery id={recovery_id} to recover pubic key")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn recover(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> anyhow::Result<k256::ecdsa::VerifyingKey> {
    k256::ecdsa::VerifyingKey::recover_from_prehash(prehash, signature, recovery_id)
        .context("Unable to recover public key")
}

#[cfg(target_arch = "wasm32")]
pub fn recover(
    prehash: &[u8],
    signature: &Signature,
    recovery_id: RecoveryId,
) -> anyhow::Result<k256::ecdsa::VerifyingKey> {
    use k256::EncodedPoint;
    use near_sdk::env;
    // While this function also works on native code, it's a bit weird and unsafe.
    // I'm more comfortable using an existing library instead.
    let recovered_key_bytes =
        env::ecrecover(prehash, &signature.to_bytes(), recovery_id.to_byte(), true)
            .context("Unable to recover public key")?;
    k256::ecdsa::VerifyingKey::from_encoded_point(&EncodedPoint::from_untagged_bytes(
        &recovered_key_bytes.into(),
    ))
    .context("Failed to parse returned key")
}
