use crypto_shared::{
    self,
    curve25519_types::{self},
    derive_epsilon,
    k256_types::{self},
    types::Scheme,
    ScalarExt,
};
use near_sdk::{env, near, AccountId, CryptoHash};

use crate::errors::InvalidParameters;

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone)]
#[near(serializers=[borsh, json])]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct InnerSecp256k1 {
    pub epsilon: k256_types::SerializableScalar,
    pub payload_hash: k256_types::SerializableScalar,
}

impl InnerSecp256k1 {
    pub fn new(payload_hash: k256::Scalar, predecessor_id: &AccountId, path: &str) -> Self {
        let epsilon = derive_epsilon::<k256::Scalar>(predecessor_id, path).into();
        let payload_hash = payload_hash.into();
        Self {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct InnerEd25519 {
    pub epsilon: curve25519_types::SerializableScalar,
    pub payload_hash: curve25519_types::SerializableScalar,
}

impl InnerEd25519 {
    pub fn new(
        payload_hash: curve25519_dalek::Scalar,
        predecessor_id: &AccountId,
        path: &str,
    ) -> Self {
        let epsilon = derive_epsilon::<curve25519_dalek::Scalar>(predecessor_id, path).into();
        let payload_hash = payload_hash.into();
        Self {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct Inner<Scalar: ScalarExt + Sized> {
    pub epsilon: Scalar,
    pub payload_hash: Scalar,
}

impl<Scalar> Inner<Scalar>
where
    Scalar: ScalarExt,
{
    pub fn new(payload_hash: Scalar, predecessor_id: &AccountId, path: &str) -> Self {
        let epsilon = derive_epsilon::<Scalar>(predecessor_id, path).into();
        let payload_hash = payload_hash.into();
        Self {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub enum SignatureRequestMpc {
    // // TODO: Use generics
    // Secp256k1 {
    //     request: Inner<k256_types::SerializableScalar>,
    // },
    // Ed25519 {
    //     request: Inner<curve25519_types::SerializableScalar>,
    // },
    Secp256k1(InnerSecp256k1),
    Ed25519(InnerEd25519),
}

impl SignatureRequestMpc {
    pub fn new(request: &SignatureRequestContract, predecessor_id: &AccountId) -> Self {
        match request.scheme {
            Some(Scheme::Secp256k1) | None => {
                // ensure the signer sent a valid signature request

                // It's important we fail here because the MPC nodes will fail in an identical way.
                // This allows users to get the error message
                let payload = match ScalarExt::from_bytes(request.payload) {
                    Some(payload) => payload,
                    None => {
                        env::panic_str(
                            &InvalidParameters::MalformedPayload
                                .message("Payload hash cannot be convereted to Scalar")
                                .to_string(),
                        );
                    }
                };

                Self::Secp256k1(InnerSecp256k1::new(
                    payload,
                    predecessor_id,
                    request.path.as_str(),
                ))
            }
            Some(Scheme::Ed25519) => {
                // ensure the signer sent a valid signature request

                // It's important we fail here because the MPC nodes will fail in an identical way.
                // This allows users to get the error message
                let payload = match ScalarExt::from_bytes(request.payload) {
                    Some(payload) => payload,
                    None => {
                        env::panic_str(
                            &InvalidParameters::MalformedPayload
                                .message("Payload hash cannot be convereted to Scalar")
                                .to_string(),
                        );
                    }
                };

                Self::Ed25519(InnerEd25519::new(
                    payload,
                    predecessor_id,
                    request.path.as_str(),
                ))
            }
        }
    }

    pub fn scheme(&self) -> Scheme {
        match self {
            SignatureRequestMpc::Secp256k1(_) => Scheme::Secp256k1,
            SignatureRequestMpc::Ed25519(_) => Scheme::Ed25519,
        }
    }
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh, json])]
pub struct SignatureRequestContract {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
    pub scheme: Option<Scheme>,
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
