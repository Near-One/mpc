mod impls;

pub use impls::{min_to_ms, secs_to_ms};

use std::collections::HashMap;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

/// Dynamic value is used to store any kind of value in the contract state. These values
/// can be deserialized on the fly to get the actual configurations, but the contract will
/// not be the ones directly utilizing these values unless they are concrete types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicValue(serde_json::Value);

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ConfigV2 {
    pub max_num_requests_to_remove: u32,
    pub request_timeout_blocks: u64,
    pub reshare_timeout_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct InitConfigV2 {
    pub max_num_requests_to_remove: Option<u32>,
    pub request_timeout_blocks: Option<u64>,
    pub reshare_timeout_blocks: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ConfigV1 {
    pub max_num_requests_to_remove: u32,
    pub request_timeout_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct InitConfigV1 {
    pub max_num_requests_to_remove: Option<u32>,
    pub request_timeout_blocks: Option<u64>,
}
/* remove everything below after V1 is delpoyed */
#[derive(
    Clone, Default, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq,
)]
pub struct Config {
    pub protocol: ProtocolConfig,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// Message timeout in milliseconds for any protocol message that gets sent over the wire.
    /// This can be overriden by more specific timeouts in each protocol.
    pub message_timeout: u64,
    /// Garbage collection timeout in milliseconds for any protocol message. This is the timeout
    /// used for when any protocols have either been spent or failed, their IDs are kept to keep
    /// track of the state of the protocol until this timeout reaches.
    pub garbage_timeout: u64,
    /// Maximum amount of concurrent protocol generation that can be introduced by this node.
    /// This only includes protocols that generate triples and presignatures.
    pub max_concurrent_introduction: u32,
    /// Maximum amount of concurrent protocol generation that can be done per node.
    /// This only includes protocols that generate triples and presignatures.
    pub max_concurrent_generation: u32,
    /// Configuration for triple generation.
    pub triple: TripleConfig,
    /// Configuration for presignature generation.
    pub presignature: PresignatureConfig,
    /// Configuration for signature generation.
    pub signature: SignatureConfig,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct TripleConfig {
    /// Minimum amount of triples that is owned by each node.
    pub min_triples: u32,
    /// Maximum amount of triples that is in the whole network.
    pub max_triples: u32,
    /// Timeout for triple generation in milliseconds.
    pub generation_timeout: u64,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct PresignatureConfig {
    /// Minimum amount of presignatures that is owned by each node.
    pub min_presignatures: u32,
    /// Maximum amount of presignatures that is in the whole network.
    pub max_presignatures: u32,
    /// Timeout for presignature generation in milliseconds.
    pub generation_timeout: u64,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct SignatureConfig {
    /// Timeout for signature generation in milliseconds.
    pub generation_timeout: u64,
    /// Timeout for signature generation in milliseconds. This is the total timeout for
    /// the signature generation process. Mainly used to include the whole generation of
    /// signatures including their retries up till this timeout.
    pub generation_timeout_total: u64,
    /// Garbage collection timeout in milliseconds for signatures generated.
    pub garbage_timeout: u64,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_load_config() {
        let config_macro = serde_json::json!({
            "protocol": {
                "message_timeout": 10000,
                "garbage_timeout": 20000,
                "max_concurrent_introduction": 10,
                "max_concurrent_generation": 10,
                "triple": {
                    "min_triples": 10,
                    "max_triples": 100,
                    "generation_timeout": 10000
                },
                "presignature": {
                    "min_presignatures": 10,
                    "max_presignatures": 100,
                    "generation_timeout": 10000
                },
                "signature": {
                    "generation_timeout": 10000,
                    "generation_timeout_total": 1000000,
                    "garbage_timeout": 10000000
                },
                "string": "value",
                "integer": 1000
            },
            "string": "value2",
            "integer": 20
        });

        let config: Config = serde_json::from_value(config_macro).unwrap();
        assert_eq!(config.protocol.message_timeout, 10000);
        assert_eq!(config.get("integer").unwrap(), serde_json::json!(20));
        assert_eq!(config.get("string").unwrap(), serde_json::json!("value2"));
    }
}
