use crate::indexer::transaction::TransactionSigner;
use crate::metrics;
use crate::sign_request::SignatureRequest;
use cait_sith::FullSignature;
use k256::{
    elliptic_curve::bigint::U256, elliptic_curve::ops::Reduce,
    elliptic_curve::point::AffineCoordinates, elliptic_curve::PrimeField, AffinePoint, Scalar,
    Secp256k1,
};
use near_indexer_primitives::types::AccountId;
use near_indexer_primitives::types::{BlockReference, Finality};
use near_o11y::WithSpanContextExt;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
struct SerializableScalar {
    pub scalar: Scalar,
}

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableScalar { scalar }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Copy)]
struct SerializableAffinePoint {
    pub affine_point: AffinePoint,
}

/* The format in which the chain signatures contract expects
 * to receive the details of the original request. `epsilon`
 * is used to refer to the (serializable) tweak derived from the caller's
 * account id and the derivation path.
 */
#[derive(Serialize, Debug, Clone)]
struct ChainSignatureRequest {
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
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct ChainSignatureResponse {
    pub big_r: SerializableAffinePoint,
    pub s: SerializableScalar,
    pub recovery_id: u8,
}

impl ChainSignatureResponse {
    const MAX_RECOVERY_ID: u8 = 3;
    pub fn new(big_r: AffinePoint, s: Scalar, recovery_id: u8) -> anyhow::Result<Self> {
        if recovery_id > Self::MAX_RECOVERY_ID {
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
#[derive(Serialize)]
pub struct ChainRespondArgs {
    request: ChainSignatureRequest,
    response: ChainSignatureResponse,
}

impl ChainRespondArgs {
    /// WARNING: this function assumes the input full signature is valid and comes from an authentic response
    pub fn new(request: &SignatureRequest, response: &FullSignature<Secp256k1>) -> Self {
        // figure out correct recovery_id for the public key
        let recovery_id = Self::ecdsa_recovery_from_big_r(&response.big_r);
        ChainRespondArgs {
            request: ChainSignatureRequest::new(request.msg_hash, request.tweak),
            response: ChainSignatureResponse::new(response.big_r, response.s, recovery_id)
                .expect("Expected Chain Signature Response instead of error, panicking!"),
        }
    }

    /// The recovery id is only made of two significant bits
    /// The lower bit determines the sign bit of the point R
    /// The higher bit determines whether the x coordinate of R exceeded
    /// the curve order when computing R_x mod p
    pub(crate) fn ecdsa_recovery_from_big_r(big_r: &AffinePoint) -> u8 {
        // compare Rx representation before and after reducing it modulo the group order
        let big_r_x = big_r.x();
        let reduced_big_r_x = <Scalar as Reduce<U256>>::reduce_bytes(&big_r_x);
        let is_x_reduced = reduced_big_r_x.to_repr() != big_r_x;

        // if Rx is larger than the group order then set recovery_id higher bit to 1
        // if Ry is odd then set recovery_id lower bit to 1
        (is_x_reduced as u8) << 1 | big_r.y_is_odd().unwrap_u8()
    }
}

pub(crate) async fn handle_sign_responses(
    tx_signer: Option<Arc<TransactionSigner>>,
    mpc_contract_id: AccountId,
    mut receiver: mpsc::Receiver<ChainRespondArgs>,
    view_client: actix::Addr<near_client::ViewClientActor>,
    client: actix::Addr<near_client::ClientActor>,
) {
    while let Some(respond_args) = receiver.recv().await {
        let Some(tx_signer) = tx_signer.clone() else {
            tracing::error!(target: "mpc", "Transaction signer unavailable; account secret key not provided");
            continue;
        };
        let mpc_contract_id = mpc_contract_id.clone();
        let view_client = view_client.clone();
        let client = client.clone();
        actix::spawn(async move {
            let Ok(response_ser) = serde_json::to_string(&respond_args) else {
                tracing::error!(target: "mpc", "Failed to serialize response args");
                return;
            };
            tracing::debug!(target = "mpc", "tx args {:?}", response_ser);

            let Ok(Ok(block)) = view_client
                .send(
                    near_client::GetBlock(BlockReference::Finality(Finality::Final))
                        .with_span_context(),
                )
                .await
            else {
                tracing::warn!(
                    target = "mpc",
                    "failed to get block hash to send response tx"
                );
                return;
            };

            let transaction = tx_signer.create_and_sign_function_call_tx(
                mpc_contract_id.clone(),
                "respond".to_string(),
                response_ser.into(),
                block.header.hash,
                block.header.height,
            );
            tracing::info!(
                target = "mpc",
                "sending response tx {:?}",
                transaction.get_hash()
            );

            let result = client
                .send(
                    near_client::ProcessTxRequest {
                        transaction,
                        is_forwarded: false,
                        check_only: false,
                    }
                    .with_span_context(),
                )
                .await;
            match result {
                Ok(response) => match response {
                    // We're not a validator, so we should always be routing the transaction.
                    near_client::ProcessTxResponse::RequestRouted => {
                        metrics::MPC_NUM_SIGN_RESPONSES_SENT.inc();
                    }
                    _ => {
                        metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
                        tracing::error!(
                            target: "mpc",
                            "Failed to send response tx: unexpected ProcessTxResponse: {:?}",
                            response
                        );
                    }
                },
                Err(err) => {
                    metrics::MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY.inc();
                    tracing::error!(target: "mpc", "Failed to send response tx: {:?}", err);
                }
            }
        });
    }
}

// Test the recovery_id generation
#[cfg(test)]
mod recovery_id_tests {
    use crate::indexer::response::ChainRespondArgs;
    use k256::ecdsa::{RecoveryId, SigningKey};
    use k256::elliptic_curve::{point::DecompressPoint, PrimeField};
    use k256::sha2::{Digest, Sha256};
    use k256::AffinePoint;
    use rand::rngs::OsRng;

    #[test]
    fn test_ecdsa_recovery_from_big_r() {
        for _ in 0..256 {
            // generate a pair of ecdsa keys
            let mut rng = OsRng;
            let signing_key = SigningKey::random(&mut rng);

            // compute a signature with recovery id
            let message = b"Testing ECDSA with recovery ID!";
            let digest = Sha256::new_with_prefix(message);
            match signing_key.sign_digest_recoverable(digest) {
                Ok((signature, recid)) => {
                    // recover R
                    let (r, _) = signature.split_scalars();
                    let r_bytes = r.to_repr();
                    let big_r =
                        AffinePoint::decompress(&r_bytes, u8::from(recid.is_y_odd()).into())
                            .unwrap();
                    // compute recovery_id using our function
                    let tested_recid = ChainRespondArgs::ecdsa_recovery_from_big_r(&big_r);
                    let tested_recid = RecoveryId::from_byte(tested_recid).unwrap();

                    assert!(tested_recid.is_x_reduced() == recid.is_x_reduced());
                    assert!(tested_recid.is_y_odd() == recid.is_y_odd());
                }
                Err(_) => panic!("The signature in the test has failed"),
            }
        }
    }
}
