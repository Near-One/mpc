use std::{env, fs};

use anyhow::{Context, Result};
use crypto_bigint::ArrayEncoding;
use hex::FromHex;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use k256::{ecdsa::RecoveryId, AffinePoint, EncodedPoint, U256};
use serde_json::Value;

pub fn x_coordinate(
    point: &<Secp256k1 as CurveArithmetic>::AffinePoint,
) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as k256::elliptic_curve::ops::Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&point.x())
}

fn get_pk(res: EcdsaSigRes, msg_hash: &str) -> EncodedPoint {
    let msg_hash = <[u8; 32]>::from_hex(msg_hash).expect("invalid payload");
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(&res.big_r), res.s)
        .context("cannot create signature from cait_sith signature")
        .expect("invalid signature");
    k256::ecdsa::VerifyingKey::recover_from_prehash(
        &msg_hash,
        &signature,
        RecoveryId::try_from(res.recovery_id).expect("invalid recovery id"),
    )
    .expect("could not recover")
    .to_encoded_point(false)
}

struct EcdsaSigRes {
    big_r: AffinePoint,
    s: k256::Scalar,
    recovery_id: u8,
}

fn parse_res(json: &str) -> EcdsaSigRes {
    let json: Value = serde_json::from_str(json).expect("invalid JSON");
    let big_r = json["big_r"]["affine_point"].as_str().unwrap().to_string();
    let big_r =
        EncodedPoint::from_bytes(hex::decode(big_r).expect("invalid hex")).expect("invalid point");
    let big_r = AffinePoint::try_from(big_r).expect("invalid point");
    let s = json["s"]["scalar"].as_str().unwrap().to_string();
    let s = U256::from_be_slice(&<[u8; 32]>::from_hex(s).expect("invalid hex"));
    let s = k256::Scalar::from_repr(s.to_be_byte_array())
        .into_option()
        .expect("error");
    let recovery_id = json["recovery_id"].as_u64().unwrap() as u8;
    EcdsaSigRes {
        big_r,
        s,
        recovery_id,
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!(
            "Usage: {} <path-to-json>\n\n\
        The input JSON file should look like:\n\
        {{\n  \"old_res\": {{ ... }},\n  \"new_res\": {{ \"Secp256k1\": {{ ... }}}},\n  \"msg_hash\": \"...\"\n}}",
            args.first()
                .map(|s| s.as_str())
                .unwrap_or("sig_recovery_check")
        );
        std::process::exit(1);
    }

    let path = &args[1];
    let json_all = fs::read_to_string(path)?; // Read file contents into a String
    let json: Value = serde_json::from_str(&json_all)?;
    let json_old = serde_json::to_string(&json["old_res"])?;
    let json_new = serde_json::to_string(&json["new_res"]["Secp256k1"])?;
    let msg_hash = json["msg_hash"].as_str().unwrap();
    let pk_v1 = get_pk(parse_res(&json_old), msg_hash);
    let pk_v2 = get_pk(parse_res(&json_new), msg_hash);
    assert_eq!(pk_v1, pk_v2);
    println!("derived public key: {}", pk_v1);
    Ok(())
}
