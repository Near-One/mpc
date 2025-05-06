pub mod consts;
mod impls;
use near_sdk::near;

/// Config for V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// If a key event attempt has not successfully completed within this many blocks,
    /// it is considered failed.
    pub key_event_timeout_blocks: u64,
}

/// Config for initializing V2 of the contract.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitConfig {
    pub key_event_timeout_blocks: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            key_event_timeout_blocks: 2000,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_init_config_serialization() {
        let init_config = InitConfig {
            key_event_timeout_blocks: None,
        };
        let json = serde_json::to_string(&init_config).unwrap();
        let deserialized: InitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(init_config, deserialized);
    }

    #[test]
    fn test_init_config_to_config_conversion() {
        let init_config = InitConfig {
            key_event_timeout_blocks: None,
        };
        let config: Config = Some(init_config).into();
        use consts::DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS;
        assert_eq!(
            config.key_event_timeout_blocks,
            DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS
        );
    }
}
