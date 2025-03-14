// Default delay of 200 blocks. After that, request is removed from the contract state
pub const DEFAULT_REQUEST_TIMEOUT_BLOCKS: u64 = 200;
// Default for `event_max_idle_blocks`.
pub const DEFAULT_EVENT_MAX_IDLE_BLOCKS: u64 = 20;
// The maximum number of requests to remove during a call
pub const MAX_NUM_REQUESTS_TO_REMOVE: u32 = 1;
