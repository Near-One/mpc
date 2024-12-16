pub use crate::primitives::ParticipantId;
use anyhow::Context;
use near_crypto::PublicKey;
use near_indexer_primitives::types::AccountId;
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::validation::ChainValidationConfig;

/// The full configuration needed to run the node.
#[derive(Debug)]
pub struct Config {
    pub mpc: MpcConfig,
    pub secrets: SecretsConfig,
    pub web_ui: WebUIConfig,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    pub validation: ValidationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TripleConfig {
    pub concurrency: usize,
    pub desired_triples_to_buffer: usize,
    pub timeout_sec: u64,
    /// If we issued a triple generation, wait at least this number of seconds
    /// before issuing another one. This is to avoid thundering herd situations.
    pub parallel_triple_generation_stagger_time_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignatureConfig {
    pub concurrency: usize,
    pub desired_presignatures_to_buffer: usize,
    pub timeout_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    pub timeout_sec: u64,
}

/// Configuration about the MPC protocol. It can come from either the contract
/// on chain, or static offline config file.
#[derive(Debug)]
pub struct MpcConfig {
    pub my_participant_id: ParticipantId,
    pub participants: ParticipantsConfig,
}

impl MpcConfig {
    pub fn from_participants_with_near_account_id(
        participants: ParticipantsConfig,
        my_near_account_id: &AccountId,
    ) -> anyhow::Result<Self> {
        let my_participant_id = participants
            .participants
            .iter()
            .find(|p| &p.near_account_id == my_near_account_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "My near account id {} not found in participants",
                    my_near_account_id
                )
            })?
            .id;
        Ok(Self {
            my_participant_id,
            participants,
        })
    }
}

/// Config for the web UI, which is mostly for debugging and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUIConfig {
    pub host: String,
    pub port: u16,
}

/// Configures behavior of the near indexer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexerConfig {
    /// Tells whether to validate the genesis file before starting
    pub validate_genesis: bool,
    /// Sets the starting point for indexing
    pub sync_mode: SyncMode,
    /// Sets the concurrency for indexing
    pub concurrency: std::num::NonZeroU16,
    /// MPC contract id
    pub mpc_contract_id: AccountId,
    /// If specified, replaces the port number in any ParticipantInfos read from chain
    pub port_override: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMode {
    /// continue from the block Indexer was interrupted
    Interruption,
    /// start from the newest block after node finishes syncing
    Latest,
    /// start from specified block height
    Block(BlockArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockArgs {
    /// block height for block sync mode
    pub height: u64,
}

/// The contents of the on-disk config.yaml file. Contains no secrets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    /// The near account ID that this node owns. If an on-chain contract is
    /// used, this account is used to sign transactions for the on-chain
    /// contract. If static config is used, this account is used to look up
    /// the participant ID.
    #[serde(default = "near_account_id_from_env")]
    pub my_near_account_id: AccountId,
    pub web_ui: WebUIConfig,
    pub indexer: Option<IndexerConfig>,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    /// If specified, this is the static configuration for the MPC protocol,
    /// replacing what would be read from the contract.
    pub participants: Option<ParticipantsConfig>,
    pub validation: ValidationConfig
}

fn near_account_id_from_env() -> AccountId {
    std::env::var("MPC_NEAR_ACCOUNT_ID")
        .ok()
        .and_then(|id| id.parse().ok())
        .expect("MPC_NEAR_ACCOUNT_ID not found in environment variables")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub near: ChainValidationConfig,
    pub base: ChainValidationConfig,
    pub eth: ChainValidationConfig,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&file)?;
        Ok(config)
    }

    pub fn into_full_config(self, mpc: MpcConfig, secrets: SecretsConfig) -> Config {
        Config {
            mpc,
            secrets,
            web_ui: self.web_ui,
            triple: self.triple,
            presignature: self.presignature,
            signature: self.signature,
            validation: self.validation
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantsConfig {
    /// The threshold for the MPC protocol.
    pub threshold: u32,
    pub participants: Vec<ParticipantInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub id: ParticipantId,
    /// Address and port that this participant can be directly reached at.
    /// Used for the P2P communication. Communication happens over TCP.
    pub address: String,
    pub port: u16,
    /// Public key that corresponds to this P2P peer's private key.
    pub p2p_public_key: PublicKey,
    pub near_account_id: AccountId,
}

/// Secrets that come from environment variables rather than the config file.
#[derive(Clone, Debug)]
pub struct SecretsConfig {
    pub p2p_private_key: near_crypto::ED25519SecretKey,
    pub local_storage_aes_key: [u8; 16],
}

impl SecretsConfig {
    pub fn from_cli(
        local_storage_aes_key_hex: &str,
        p2p_private_key: near_crypto::SecretKey,
    ) -> anyhow::Result<Self> {
        let local_storage_aes_key = hex::decode(local_storage_aes_key_hex)
            .context("Encryption key must be 32 hex characters")?;
        let local_storage_aes_key: [u8; 16] = local_storage_aes_key
            .as_slice()
            .try_into()
            .context("Encryption key must be 16 bytes (32 bytes hex)")?;

        let near_crypto::SecretKey::ED25519(p2p_private_key) = p2p_private_key else {
            anyhow::bail!("P2P private key must be ed25519");
        };
        Ok(Self {
            p2p_private_key,
            local_storage_aes_key,
        })
    }
}

pub fn load_config_file(home_dir: &Path) -> anyhow::Result<ConfigFile> {
    let config_path = home_dir.join("config.yaml");
    ConfigFile::from_file(&config_path).context("Load config.yaml")
}
