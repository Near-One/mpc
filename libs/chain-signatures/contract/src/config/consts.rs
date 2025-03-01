// Default delay of 200 blocks. After that, request is removed from the contract state
pub const DEFAULT_REQUEST_TIMEOUT_BLOCKS: u64 = 200;
// Default timeout of 800 blocks. After that, the reshare is consiedered failed and removed from the contract state
pub const DEFAULT_RESHARE_TIMEOUT_BLOCKS: u64 = 800;
// The maximum number of requests to remove during a call
pub const MAX_NUM_REQUESTS_TO_REMOVE: u32 = 1;
