use crate::crypto_shared;

use crypto_shared::derive_tweak;
use near_sdk::{near, AccountId, CryptoHash};

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct Tweak([u8; 32]);

impl Tweak {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct PayloadHash([u8; 32]);

impl PayloadHash {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

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
    pub tweak: Tweak,
    pub payload_hash: PayloadHash,
}

impl SignatureRequest {
    pub fn new(payload_hash: PayloadHash, predecessor_id: &AccountId, path: &str) -> Self {
        let tweak = derive_tweak(predecessor_id, path);
        SignatureRequest {
            tweak,
            payload_hash,
        }
    }
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh, json])]
pub struct SignRequest {
    pub payload: PayloadHash,
    pub path: String,
    pub key_version: u32,
}

#[derive(Clone, Debug)]
#[near(serializers=[borsh])]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}
