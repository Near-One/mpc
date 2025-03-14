use crate::sign_request::SignatureRequest;
use anyhow::Context;
use cait_sith::FullSignature;
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic},
    AffinePoint, Scalar, Secp256k1,
};
use legacy_mpc_contract;
use near_crypto::PublicKey;
use near_indexer_primitives::types::Gas;
use serde::{Deserialize, Serialize};

const TGAS: u64 = 1_000_000_000_000;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub struct SerializableScalar {
    pub scalar: Scalar,
}

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableScalar { scalar }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}

/* The format in which the chain signatures contract expects
 * to receive the details of the original request. `epsilon`
 * is used to refer to the (serializable) tweak derived from the caller's
 * account id and the derivation path.
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainSignatureRequest {
    pub epsilon: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

impl ChainSignatureRequest {
    pub fn new(payload_hash: Scalar, tweak: Scalar) -> Self {
        let epsilon = SerializableScalar { scalar: tweak };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        ChainSignatureRequest {
            epsilon,
            payload_hash,
        }
    }
}

/* The format in which the chain signatures contract expects
 * to receive the completed signature.
 */
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct ChainSignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

const MAX_RECOVERY_ID: u8 = 3;

impl ChainSignatureResponse {
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> anyhow::Result<Self> {
        if recovery_id > MAX_RECOVERY_ID {
            anyhow::bail!("Invalid Recovery Id: recovery id larger than 3.");
        }
        Ok(ChainSignatureResponse {
            big_r: SerializableAffinePoint {
                affine_point: big_r,
            },
            s: SerializableScalar { scalar: s },
            recovery_id,
        })
    }
}

/* These arguments are passed to the `respond` function of the
 * chain signatures contract. It takes both the details of the
 * original request and the completed signature, then verifies
 * that the signature matches the requested key and payload.
 */
#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct ChainRespondArgs {
    pub request: ChainSignatureRequest,
    response: ChainSignatureResponse,
}

#[derive(Serialize, Debug)]
pub struct ChainGetPendingRequestArgs {
    pub request: ChainSignatureRequest,
}

#[derive(Serialize, Debug)]
pub struct ChainJoinArgs {
    pub url: String,
    pub cipher_pk: legacy_mpc_contract::primitives::hpke::PublicKey,
    pub sign_pk: PublicKey,
}

#[derive(Serialize, Debug)]
pub struct ChainVotePkArgs {
    pub public_key: PublicKey,
}

#[derive(Serialize, Debug)]
pub struct ChainVoteResharedArgs {
    pub epoch: u64,
}

/// Request to send a transaction to the contract on chain.
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum ChainSendTransactionRequest {
    Respond(ChainRespondArgs),
    // TODO(#150): Implement join.
    #[allow(dead_code)]
    Join(ChainJoinArgs),
    VotePk(ChainVotePkArgs),
    // TODO(#43): Implement vote_reshared.
    #[allow(dead_code)]
    VoteReshared(ChainVoteResharedArgs),
}

impl ChainSendTransactionRequest {
    pub fn method(&self) -> &'static str {
        match self {
            ChainSendTransactionRequest::Respond(_) => "respond",
            ChainSendTransactionRequest::Join(_) => "join",
            ChainSendTransactionRequest::VotePk(_) => "vote_pk",
            ChainSendTransactionRequest::VoteReshared(_) => "vote_reshared",
        }
    }

    pub fn gas_required(&self) -> Gas {
        match self {
            Self::Respond(_) | Self::Join(_) | Self::VotePk(_) | Self::VoteReshared(_) => {
                300 * TGAS
            }
        }
    }
}

impl ChainRespondArgs {
    /// WARNING: this function assumes the input full signature is valid and comes from an authentic response
    pub fn new(
        request: &SignatureRequest,
        response: &FullSignature<Secp256k1>,
        public_key: &AffinePoint,
    ) -> anyhow::Result<Self> {
        let recovery_id = Self::brute_force_recovery_id(public_key, response, &request.msg_hash)?;
        Ok(ChainRespondArgs {
            request: ChainSignatureRequest::new(request.msg_hash, request.tweak),
            response: ChainSignatureResponse::new(response.big_r, response.s, recovery_id)?,
        })
    }

    /// Brute forces the recovery id to find a recovery_id that matches the public key
    pub(crate) fn brute_force_recovery_id(
        expected_pk: &AffinePoint,
        signature: &FullSignature<Secp256k1>,
        msg_hash: &Scalar,
    ) -> anyhow::Result<u8> {
        let partial_signature = k256::ecdsa::Signature::from_scalars(
            <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>
            ::reduce_bytes(&signature.big_r.x()), signature.s)
            .context("Cannot create signature from cait_sith signature")?;
        let expected_pk = match VerifyingKey::from_affine(*expected_pk) {
            Ok(pk) => pk,
            _ => anyhow::bail!("The affine point cannot be transformed into a verifying key"),
        };
        match RecoveryId::trial_recovery_from_prehash(
            &expected_pk,
            &msg_hash.to_bytes(),
            &partial_signature,
        ) {
            Ok(rec_id) => Ok(rec_id.to_byte()),
            _ => anyhow::bail!(
                "No recovery id found for such a tuple of public key, signature, message hash"
            ),
        }
    }
}

#[cfg(test)]
mod recovery_id_tests {
    use crate::hkdf::ScalarExt;
    use crate::indexer::types::ChainRespondArgs;
    use cait_sith::FullSignature;
    use k256::ecdsa::{RecoveryId, SigningKey};
    use k256::elliptic_curve::{point::DecompressPoint, PrimeField};
    use k256::{AffinePoint, Scalar};
    use rand::rngs::OsRng;

    #[test]
    fn test_brute_force_recovery_id() {
        for _ in 0..256 {
            // generate a pair of ecdsa keys
            let mut rng = OsRng;
            let signing_key = SigningKey::random(&mut rng);

            // compute a signature with recovery id
            let prehash: [u8; 32] = rand::random();
            match signing_key.sign_prehash_recoverable(&prehash) {
                // match signing_key.sign_digest_recoverable(digest) {
                Ok((signature, recid)) => {
                    let (r, s) = signature.split_scalars();
                    let msg_hash = Scalar::from_bytes(prehash).unwrap();

                    // create a full signature
                    // any big_r creation works here as we only need it's x coordinate during bruteforce (big_r.x())

                    let r_bytes = r.to_repr();
                    let hypothetical_big_r = AffinePoint::decompress(&r_bytes, 0.into()).unwrap();

                    let full_sig = FullSignature {
                        big_r: hypothetical_big_r,
                        s: *s.as_ref(),
                    };

                    let tested_recid = ChainRespondArgs::brute_force_recovery_id(
                        signing_key.verifying_key().as_affine(),
                        &full_sig,
                        &msg_hash,
                    )
                    .unwrap();

                    // compute recovery_id using our function
                    let tested_recid = RecoveryId::from_byte(tested_recid).unwrap();

                    assert!(tested_recid.is_x_reduced() == recid.is_x_reduced());
                    assert!(tested_recid.is_y_odd() == recid.is_y_odd());
                }
                Err(_) => panic!("The signature in the test has failed"),
            }
        }
    }
}
