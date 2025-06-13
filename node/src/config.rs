use crate::primitives::ParticipantId;
use anyhow::Context;
use near_crypto::{PublicKey, SecretKey};
use near_indexer_primitives::types::{AccountId, Finality};
use serde::{Deserialize, Serialize};
use std::path::Path;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenConfig {
    pub timeout_sec: u64,
}

impl Default for KeygenConfig {
    fn default() -> KeygenConfig {
        KeygenConfig { timeout_sec: 60 }
    }
}

/// Configuration about the MPC protocol. It can come from either the contract
/// on chain, or static offline config file.
#[derive(Debug, Clone)]
pub struct MpcConfig {
    pub my_participant_id: ParticipantId,
    pub participants: ParticipantsConfig,
}

impl MpcConfig {
    /// Finds the participant ID of the local node from the participants config
    /// and constructs the MpcConfig. Returns None if the local node is not
    /// found in the participants config.
    pub fn from_participants_with_near_account_id(
        participants: ParticipantsConfig,
        my_near_account_id: &AccountId,
    ) -> Option<Self> {
        let my_participant_id = participants
            .participants
            .iter()
            .find(|p| &p.near_account_id == my_near_account_id)?
            .id;
        Some(Self {
            my_participant_id,
            participants,
        })
    }

    /// When performing a key generation or key resharing protocol, someone has to create a channel.
    /// Don't confuse with Leader Centric Computations.
    pub fn is_leader_for_key_event(&self) -> bool {
        let my_participant_id = self.my_participant_id;
        let participant_with_lowest_id = self
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .expect("Participants list should not be empty");
        my_participant_id == participant_with_lowest_id
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
    /// Sets the finality level at which blocks are streamed
    pub finality: Finality,
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
    /// The near account ID that this node owns.
    /// If an on-chain contract is used, this account is used to invoke
    /// identity-sensitive functions of the contract (join, vote, etc.).
    /// If static ParticipantsConfig is specified, this account id is used
    /// to identify our own participant ID from within the static config.
    /// In both cases this account is *not* used to send signature responses.
    pub my_near_account_id: AccountId,
    pub web_ui: WebUIConfig,
    pub indexer: IndexerConfig,
    pub triple: TripleConfig,
    pub presignature: PresignatureConfig,
    pub signature: SignatureConfig,
    #[serde(default)]
    pub keygen: KeygenConfig,
    /// This value is only considered when the node is run in normal node. It defines the number of
    /// working threads for the runtime.
    pub cores: Option<usize>,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let file = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&file)?;
        Ok(config)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantsConfig {
    /// The threshold for the MPC protocol.
    pub threshold: u64,
    pub participants: Vec<ParticipantInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
        p2p_private_key: near_crypto::ED25519SecretKey,
    ) -> anyhow::Result<Self> {
        let local_storage_aes_key = hex::decode(local_storage_aes_key_hex)
            .context("Encryption key must be 32 hex characters")?;
        let local_storage_aes_key: [u8; 16] = local_storage_aes_key
            .as_slice()
            .try_into()
            .context("Encryption key must be 16 bytes (32 bytes hex)")?;
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

/// Credentials of the near account used to submit signature responses.
/// It is recommended to use a separate dedicated account for this purpose.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RespondConfigFile {
    /// It can be an arbitrary id because respond calls are not authenticated.
    /// The account should have sufficient NEAR to pay for the function calls.
    pub account_id: AccountId,
    /// In production it is recommended to provide 50+ distinct access keys
    /// to minimize incidence of nonce conflicts under heavy load.
    pub access_keys: Vec<SecretKey>,
}

impl RespondConfigFile {
    pub fn from_file(path: &Path) -> anyhow::Result<Option<Self>> {
        let file = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                } else {
                    return Err(err.into());
                }
            }
        };
        let config: Self = serde_yaml::from_str(&file)?;
        if config.access_keys.is_empty() {
            anyhow::bail!("At least one access key must be provided");
        }
        Ok(Some(config))
    }
}

pub fn load_respond_config_file(home_dir: &Path) -> anyhow::Result<Option<RespondConfigFile>> {
    let config_path = home_dir.join("respond.yaml");
    RespondConfigFile::from_file(&config_path).context("Load respond.yaml")
}
