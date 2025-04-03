use crate::legacy_contract_state;

use super::consts::DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS;
use super::{Config, InitConfig};
impl Default for Config {
    fn default() -> Self {
        Config {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
        }
    }
}

impl From<Option<InitConfig>> for Config {
    fn from(value: Option<InitConfig>) -> Self {
        match value {
            None => Config::default(),
            Some(init_config) => Config {
                key_event_timeout_blocks: init_config
                    .key_event_timeout_blocks
                    .unwrap_or(DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS),
            },
        }
    }
}
impl From<&legacy_contract_state::ConfigV1> for Config {
    fn from(_config: &legacy_contract_state::ConfigV1) -> Self {
        Config {
            key_event_timeout_blocks: DEFAULT_KEY_EVENT_TIMEOUT_BLOCKS,
        }
    }
}
