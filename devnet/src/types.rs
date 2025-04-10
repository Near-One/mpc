use crate::rpc::NearRpcClients;
use near_crypto::SecretKey;
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Locally stored Near account information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NearAccount {
    pub account_id: AccountId,
    pub access_keys: Vec<SecretKey>,
    pub kind: NearAccountKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NearAccountKind {
    /// Account that is only used for funding other accounts.
    FundingAccount,
    /// Account that is used for sending miscellaneous transactions.
    Normal,
    /// Account used by MPC participants.
    MpcParticipant(MpcParticipantSetup),
    /// Account hosting a contract.
    Contract(ContractSetup),
}

/// Locally stored MPC participant keys and other info.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcParticipantSetup {
    pub p2p_private_key: SecretKey,
    /// The account this participant uses to respond to signature requests.
    pub responding_account_id: AccountId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractSetup {
    /// The filename that was deployed last time. This is just for informational purposes.
    pub deployed_filename: String,
}

/// The format of the devnet_setup.yaml file - all the local state we store.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DevnetSetupRepository {
    pub accounts: HashMap<AccountId, NearAccount>,
    pub mpc_setups: HashMap<String, MpcNetworkSetup>,
    pub loadtest_setups: HashMap<String, LoadtestSetup>,
}

/// Local state for a single MPC network.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct MpcNetworkSetup {
    pub participants: Vec<AccountId>,
    pub contract: Option<AccountId>,
    // These desired fields are used when updating the network.
    pub desired_balance_per_account: u128,
    pub num_responding_access_keys: usize,
    pub desired_balance_per_responding_account: u128,
    pub nomad_server_url: Option<String>,
}

/// Local state for a single loadtest setup.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LoadtestSetup {
    pub load_senders: Vec<AccountId>,
    pub desired_balance_per_account: u128,
    pub desired_keys_per_account: usize,
    pub parallel_signatures_contract: Option<AccountId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub rpcs: Vec<RpcConfig>,
    pub funding_account: Option<NearAccount>,
    // Path of the Near-One/infra-ops repository.
    // Used only for terraform deployment commands.
    pub infra_ops_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub url: String,
    /// Maximum number of requests per second that the RPC server will allow.
    pub rate_limit: usize,
    /// Maximum number of in-flight requests that the RPC server will allow.
    pub max_concurrency: usize,
}

pub struct ParsedConfig {
    pub rpc: Arc<NearRpcClients>,
    pub infra_ops_path: PathBuf,
    pub funding_account: Option<NearAccount>,
}

pub async fn load_config() -> ParsedConfig {
    const CONFIG_FILE: &str = "config.yaml";
    let config = std::fs::read_to_string(CONFIG_FILE).unwrap();
    let config: Config = serde_yaml::from_str(&config).unwrap();
    let client = Arc::new(NearRpcClients::new(config.rpcs).await);
    ParsedConfig {
        rpc: client,
        infra_ops_path: PathBuf::from(config.infra_ops_path),
        funding_account: config.funding_account,
    }
}
