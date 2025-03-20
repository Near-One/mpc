use crate::crypto_shared;

use crypto_shared::{derive_epsilon, SerializableScalar};
use k256::Scalar;
use near_sdk::{near, AccountId, CryptoHash};

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(Debug, Clone)]
#[near(serializers=[borsh, json])]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct SignatureRequest {
    pub epsilon: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

impl SignatureRequest {
    pub fn new(payload_hash: Scalar, predecessor_id: &AccountId, path: &str) -> Self {
        let epsilon = derive_epsilon(predecessor_id, path);
        let epsilon = SerializableScalar { scalar: epsilon };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        SignatureRequest {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh, json])]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
