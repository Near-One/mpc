pub mod consts;
mod impls;
use near_sdk::near;

/// Config for V2 of the contract.
/// ```
/// use mpc_contract::config::Config;
/// let config = Config { key_event_timeout_blocks: 2000 };
/// let json = serde_json::to_string(&config).unwrap();
/// assert_eq!(config, serde_json::from_str(&json).unwrap());
/// ```
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    // If a key event attempt has not successfully completed within this many blocks, it is
    // considered failed.
    pub key_event_timeout_blocks: u64,
}

/// Config for V2 of the contract.
///
/// # Usage
/// ```
/// use mpc_contract::config::InitConfig;
/// let init_config = InitConfig { key_event_timeout_blocks: None };
/// let json = serde_json::to_string(&init_config).unwrap();
/// assert_eq!(init_config, serde_json::from_str(&json).unwrap());
///
/// use mpc_contract::config::Config;
/// let config : Config = Some(init_config).into();
/// use mpc_contract::config::consts::DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS;
/// assert_eq!(config.key_event_timeout_blocks, DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS);
/// ```
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitConfig {
    pub key_event_timeout_blocks: Option<u64>,
}
