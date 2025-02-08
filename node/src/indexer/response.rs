use crate::indexer::transaction::TransactionSigner;
use crate::metrics;
use crate::sign_request::SignatureRequest;
use anyhow::Context;
use cait_sith::FullSignature;
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    elliptic_curve::{ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic},
    AffinePoint, Scalar, Secp256k1,
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
#[derive(Serialize)]
pub struct ChainRespondArgs {
    request: ChainSignatureRequest,
    response: ChainSignatureResponse,
}

impl ChainRespondArgs {
    /// WARNING: this function assumes the input full signature is valid and comes from an authentic response
    pub fn new(
        request: &SignatureRequest,
        response: &FullSignature<Secp256k1>,
        public_key: &AffinePoint,
    ) -> anyhow::Result<Self> {
        // let recovery_id = Self::brute_force_recovery_id(public_key, response, &request.msg_hash)?;
        // Ok(ChainRespondArgs {
        //     request: ChainSignatureRequest::new(request.msg_hash, request.tweak),
        //     response: ChainSignatureResponse::new(response.big_r, response.s, recovery_id)?,
        // })
        todo!()
    }

    /// Brute forces the recovery id to find a recovery_id that matches the public key
    pub(crate) fn brute_force_recovery_id(
        expected_pk: &AffinePoint,
        signature: &FullSignature<Secp256k1>,
        msg_hash: &Scalar,
    ) -> anyhow::Result<u8> {
        // let partial_signature = k256::ecdsa::Signature::from_scalars(
        //     <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>
        //     ::reduce_bytes(&signature.big_r.x()), signature.s)
        //     .context("Cannot create signature from cait_sith signature")?;
        // let expected_pk = match VerifyingKey::from_affine(*expected_pk) {
        //     Ok(pk) => pk,
        //     _ => anyhow::bail!("The affine point cannot be transformed into a verifying key"),
        // };
        // match RecoveryId::trial_recovery_from_prehash(
        //     &expected_pk,
        //     &msg_hash.to_bytes(),
        //     &partial_signature,
        // ) {
        //     Ok(rec_id) => Ok(rec_id.to_byte()),
        //     _ => anyhow::bail!(
        //         "No recovery id found for such a tuple of public key, signature, message hash"
        //     ),
        // }
        todo!()
    }

    // /// The recovery id is only made of two significant bits
    // /// The lower bit determines the sign bit of the point R
    // /// The higher bit determines whether the x coordinate of R exceeded
    // /// the curve order when computing R_x mod p
    // /// TODO(#98): This function doesn't work. Why?
    // #[cfg(test)]
    // pub(crate) fn ecdsa_recovery_from_big_r(big_r: &AffinePoint, s: &Scalar) -> u8 {
    //     use k256::elliptic_curve::bigint::ArrayEncoding;
    //     use k256::elliptic_curve::PrimeField;
    //     use k256::U256;
    // 
    //     // compare Rx representation before and after reducing it modulo the group order
    //     let big_r_x = big_r.x();
    //     let reduced_big_r_x = <Scalar as Reduce<
    //         <Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    //     >>::reduce_bytes(&big_r_x);
    //     let is_x_reduced = reduced_big_r_x.to_repr() != big_r_x;
    // 
    //     let mut y_bit = big_r.y_is_odd().unwrap_u8();
    //     let order_divided_by_two =
    //         "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";
    //     let order_divided_by_two = U256::from_be_hex(order_divided_by_two);
    //     let s_int = U256::from_be_byte_array(s.to_bytes());
    //     if s_int > order_divided_by_two {
    //         println!("Flipped");
    //         // flip the bit
    //         y_bit ^= 1;
    //     }
    //     // if Rx is larger than the group order then set recovery_id higher bit to 1
    //     // if Ry is odd then set recovery_id lower bit to 1
    //     (is_x_reduced as u8) << 1 | y_bit
    // }
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

#[cfg(test)]
mod recovery_id_tests {
    use crate::hkdf::ScalarExt;
    use crate::indexer::response::ChainRespondArgs;
    use cait_sith::FullSignature;
    use k256::ecdsa::{RecoveryId, SigningKey};
    use k256::elliptic_curve::{
        bigint::CheckedAdd, point::DecompressPoint, Curve, FieldBytesEncoding, PrimeField,
    };
    use k256::AffinePoint;
    use k256::{Scalar, Secp256k1};
    use rand::rngs::OsRng;

    // #[test]
    // fn test_ecdsa_recovery_from_big_r() {
    //     for _ in 0..256 {
    //         // generate a pair of ecdsa keys
    //         let mut rng = OsRng;
    //         let signing_key = SigningKey::random(&mut rng);
    // 
    //         // compute a signature with recovery id
    //         let prehash: [u8; 32] = rand::random();
    //         match signing_key.sign_prehash_recoverable(&prehash) {
    //             // match signing_key.sign_digest_recoverable(digest) {
    //             Ok((signature, recid)) => {
    //                 let try_recid = RecoveryId::trial_recovery_from_prehash(
    //                     signing_key.verifying_key(),
    //                     &prehash,
    //                     &signature,
    //                 )
    //                 .unwrap();
    //                 // recover R
    //                 let (r, s) = signature.split_scalars();
    //                 let mut r_bytes = r.to_repr();
    //                 // if r is reduced then recover the unreduced one
    //                 if recid.is_x_reduced() {
    //                     match Option::<<Secp256k1 as Curve>::Uint>::from(
    //                         <<Secp256k1 as Curve>::Uint>::decode_field_bytes(&r_bytes)
    //                             .checked_add(&Secp256k1::ORDER),
    //                     ) {
    //                         Some(restored) => r_bytes = restored.encode_field_bytes(),
    //                         None => panic!("No reduction should happen here if r was reduced"),
    //                     };
    //                 }
    //                 let big_r =
    //                     AffinePoint::decompress(&r_bytes, u8::from(recid.is_y_odd()).into())
    //                         .unwrap();
    //                 // compute recovery_id using our function
    //                 let tested_recid = ChainRespondArgs::ecdsa_recovery_from_big_r(&big_r, &s);
    //                 let tested_recid = RecoveryId::from_byte(tested_recid).unwrap();
    // 
    //                 assert!(tested_recid.is_x_reduced() == recid.is_x_reduced());
    //                 assert!(tested_recid.is_y_odd() == recid.is_y_odd());
    //                 assert!(tested_recid.is_y_odd() == try_recid.is_y_odd());
    //                 assert!(tested_recid.is_x_reduced() == try_recid.is_x_reduced());
    //             }
    //             Err(_) => panic!("The signature in the test has failed"),
    //         }
    //     }
    // }

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
