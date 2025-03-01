use near_sdk::{near, BorshStorageKey};
#[near(serializers=[borsh, json] )]
#[derive(Hash, Clone, Debug, PartialEq, Eq, BorshStorageKey)]
pub enum StorageKey {
    // for backwards compatibility, ensure the order is preserved and only append to this list
    PendingRequests,
    ProposedUpdatesEntries,
    RequestsByTimestamp,
}
