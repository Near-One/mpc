use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{BorshStorageKey, CryptoHash};
pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    // for backwards compatibility, ensure the order is preserved and only append to this list
    PendingRequests,
    ProposedUpdatesEntries,
    RequestsByTimestamp,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignaturePromiseError {
    Failed,
}
