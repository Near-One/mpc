use anyhow::Context;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::AffinePoint;

pub fn affine_point_to_public_key(point: AffinePoint) -> anyhow::Result<near_crypto::PublicKey> {
    Ok(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(&point.to_encoded_point(false).as_bytes()[1..65])
            .context("Failed to convert affine point to public key")?,
    ))
}
