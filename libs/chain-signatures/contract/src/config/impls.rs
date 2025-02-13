use borsh::{self, BorshDeserialize, BorshSerialize};

use super::{
    Config, ConfigV1, ConfigV2, DynamicValue, InitConfigV1, InitConfigV2, PresignatureConfig,
    ProtocolConfig, SignatureConfig, TripleConfig,
};

/// This is maximum expected participants we aim to support right now. This can be different
/// in the future as we scale the network further.
const MAX_EXPECTED_PARTICIPANTS: u32 = 32;

/// The network multiplier is used to calculate the maximum amount of protocols in totality
/// that should be in the network.
const NETWORK_MULTIPLIER: u32 = 128;

// Default delay of 200 blocks. After that, request is removed from the contract state
const DEFAULT_REQUEST_TIMEOUT_BLOCKS: u64 = 200;

// Default timeout of 800 blocks. After that, the reshare is consiedered failed and removed from the contract state
const DEFAULT_RESHARE_TIMEOUT_BLOCKS: u64 = 800;

// The maximum number of requests to remove during a call
const MAX_NUM_REQUESTS_TO_REMOVE: u32 = 1;

impl Default for ConfigV2 {
    fn default() -> Self {
        ConfigV2 {
            max_num_requests_to_remove: MAX_NUM_REQUESTS_TO_REMOVE,
            request_timeout_blocks: DEFAULT_REQUEST_TIMEOUT_BLOCKS,
            reshare_timeout_blocks: DEFAULT_RESHARE_TIMEOUT_BLOCKS,
        }
    }
}

impl From<Option<InitConfigV2>> for ConfigV2 {
    fn from(value: Option<InitConfigV2>) -> Self {
        match value {
            None => ConfigV2::default(),
            Some(init_config) => ConfigV2 {
                max_num_requests_to_remove: init_config
                    .max_num_requests_to_remove
                    .unwrap_or(MAX_NUM_REQUESTS_TO_REMOVE),
                request_timeout_blocks: init_config
                    .request_timeout_blocks
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_BLOCKS),
                reshare_timeout_blocks: init_config
                    .reshare_timeout_blocks
                    .unwrap_or(DEFAULT_RESHARE_TIMEOUT_BLOCKS),
            },
        }
    }
}
impl From<&ConfigV1> for ConfigV2 {
    fn from(config: &ConfigV1) -> Self {
        ConfigV2 {
            max_num_requests_to_remove: config.max_num_requests_to_remove,
            request_timeout_blocks: config.request_timeout_blocks,
            reshare_timeout_blocks: DEFAULT_RESHARE_TIMEOUT_BLOCKS,
        }
    }
}

impl Default for ConfigV1 {
    fn default() -> Self {
        ConfigV1 {
            max_num_requests_to_remove: MAX_NUM_REQUESTS_TO_REMOVE,
            request_timeout_blocks: DEFAULT_REQUEST_TIMEOUT_BLOCKS,
        }
    }
}

impl From<Option<InitConfigV1>> for ConfigV1 {
    fn from(value: Option<InitConfigV1>) -> Self {
        match value {
            None => ConfigV1::default(),
            Some(init_config) => ConfigV1 {
                max_num_requests_to_remove: init_config
                    .max_num_requests_to_remove
                    .unwrap_or(MAX_NUM_REQUESTS_TO_REMOVE),
                request_timeout_blocks: init_config
                    .request_timeout_blocks
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT_BLOCKS),
            },
        }
    }
}
/* todo: Remove everything below after V1 is deployed */
impl Config {
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        match key {
            "protocol" => Some(serde_json::to_value(self.protocol.clone()).unwrap()),
            _ => {
                let value = self.other.get(key)?;
                Some(value.0.clone())
            }
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            message_timeout: min_to_ms(5),
            garbage_timeout: hours_to_ms(2),
            max_concurrent_introduction: 2,
            max_concurrent_generation: 2 * MAX_EXPECTED_PARTICIPANTS,
            triple: TripleConfig::default(),
            presignature: PresignatureConfig::default(),
            signature: Default::default(),

            other: Default::default(),
        }
    }
}

impl Default for TripleConfig {
    fn default() -> Self {
        Self {
            min_triples: 1024,
            max_triples: 1024 * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER,
            generation_timeout: min_to_ms(10),

            other: Default::default(),
        }
    }
}

impl Default for PresignatureConfig {
    fn default() -> Self {
        Self {
            min_presignatures: 512,
            max_presignatures: 512 * MAX_EXPECTED_PARTICIPANTS * NETWORK_MULTIPLIER,
            generation_timeout: secs_to_ms(45),

            other: Default::default(),
        }
    }
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            generation_timeout: secs_to_ms(45),
            generation_timeout_total: secs_to_ms(200),
            garbage_timeout: hours_to_ms(24),

            other: Default::default(),
        }
    }
}

impl From<serde_json::Value> for DynamicValue {
    fn from(value: serde_json::Value) -> Self {
        Self(value)
    }
}
impl BorshSerialize for DynamicValue {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let buf = serde_json::to_vec(&self.0)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        BorshSerialize::serialize(&buf, writer)
    }
}

impl BorshDeserialize for DynamicValue {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let buf: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        let value = serde_json::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self(value))
    }
}

pub const fn secs_to_ms(secs: u64) -> u64 {
    secs * 1000
}

pub const fn min_to_ms(min: u64) -> u64 {
    min * 60 * 1000
}

pub const fn hours_to_ms(hours: u64) -> u64 {
    hours * 60 * 60 * 1000
}
