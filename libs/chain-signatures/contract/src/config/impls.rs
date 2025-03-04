use super::consts::{
    DEFAULT_REQUEST_TIMEOUT_BLOCKS, DEFAULT_RESHARE_TIMEOUT_BLOCKS, MAX_NUM_REQUESTS_TO_REMOVE,
};
use super::{Config, InitConfig};
impl Default for Config {
    fn default() -> Self {
        Config {
            max_num_requests_to_remove: MAX_NUM_REQUESTS_TO_REMOVE,
            request_timeout_blocks: DEFAULT_REQUEST_TIMEOUT_BLOCKS,
            dk_event_timeout_blocks: DEFAULT_RESHARE_TIMEOUT_BLOCKS,
        }
    }
}

impl From<Option<InitConfig>> for Config {
    fn from(value: Option<InitConfig>) -> Self {
        match value {
            None => Config::default(),
            Some(init_config) => Config {
                max_num_requests_to_remove: init_config
                    .max_num_requests_to_remove
                    .unwrap_or(MAX_NUM_REQUESTS_TO_REMOVE),
                request_timeout_blocks: init_config
                    .request_timeout_blocks
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_BLOCKS),
                dk_event_timeout_blocks: init_config
                    .dk_event_timeout_blocks
                    .unwrap_or(DEFAULT_RESHARE_TIMEOUT_BLOCKS),
            },
        }
    }
}
impl From<&legacy_contract::config::ConfigV1> for Config {
    fn from(config: &legacy_contract::config::ConfigV1) -> Self {
        Config {
            max_num_requests_to_remove: config.max_num_requests_to_remove,
            request_timeout_blocks: config.request_timeout_blocks,
            dk_event_timeout_blocks: DEFAULT_RESHARE_TIMEOUT_BLOCKS,
        }
    }
}
