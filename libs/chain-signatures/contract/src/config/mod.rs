pub mod consts;
mod impls;
use near_sdk::near;

/// Config for V2 of the contract.
/// ```
/// use mpc_contract::config::Config;
/// let config = Config { max_num_requests_to_remove: 10, request_timeout_blocks: 1000, dk_event_timeout_blocks: 2000 };
/// let json = serde_json::to_string(&config).unwrap();
/// assert_eq!(config, serde_json::from_str(&json).unwrap());
/// ```
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub max_num_requests_to_remove: u32,
    pub request_timeout_blocks: u64,
    // the timeout for distributed key events (e.g. resharing or initialization).
    pub dk_event_timeout_blocks: u64,
}

/// Config for V2 of the contract.
///
/// # Usage
/// ```
/// use mpc_contract::config::InitConfig;
/// let init_config = InitConfig { max_num_requests_to_remove: Some(10), request_timeout_blocks: Some(1000), dk_event_timeout_blocks: None };
/// let json = serde_json::to_string(&init_config).unwrap();
/// assert_eq!(init_config, serde_json::from_str(&json).unwrap());
///
/// use mpc_contract::config::Config;
/// let config : Config = Some(init_config).into();
/// assert_eq!(config.max_num_requests_to_remove, 10);
/// assert_eq!(config.request_timeout_blocks, 1000);
/// use mpc_contract::config::consts::DEFAULT_RESHARE_TIMEOUT_BLOCKS;
/// assert_eq!(config.dk_event_timeout_blocks, DEFAULT_RESHARE_TIMEOUT_BLOCKS);
/// ```
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitConfig {
    pub max_num_requests_to_remove: Option<u32>,
    pub request_timeout_blocks: Option<u64>,
    pub dk_event_timeout_blocks: Option<u64>,
}
