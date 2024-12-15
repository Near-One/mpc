mod near;
mod light_proofs;

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use near_primitives::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::bs58;
use web3::ethabi::Contract;
use anyhow::Result;

pub(crate) const HOT_VERIFY_ABI: &'static str = r#"[{"inputs":[{"internalType":"bytes32","name":"msg_hash","type":"bytes32"},{"internalType":"bytes","name":"walletId","type":"bytes"},{"internalType":"bytes","name":"userPayload","type":"bytes"},{"internalType":"bytes","name":"metadata","type":"bytes"}],"name":"hot_verify","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]"#;
pub(crate) const HOT_VERIFY_METHOD_NAME: &'static str = "hot_verify";
pub(crate) const MPC_HOT_WALLET_CONTRACT: &'static str = "mpc.hot.tg";
pub(crate) const MPC_GET_WALLET_METHOD: &'static str = "get_wallet";

enum Chain {
    Near,
    Ethereum,
    Base,
}

impl Chain {
    fn from_usize(x: usize) -> Option<Chain> {
        match x {
            0 => Some(Chain::Near),
            1 => Some(Chain::Ethereum),
            8453 => Some(Chain::Base),
            _ => None
        }
    }
}

/// Arguments for `get_wallet` method on Near `mpc.hot.tg` smart contract.
#[derive(Debug, Serialize)]
struct GetWalletArgs {
    wallet_id: String,
}

/// Arguments for the `hot_verify` method on NEAR and EVM-based smart contracts.
#[derive(Debug, Serialize, Clone)]
pub struct VerifyArgs {
    /// The hash of a refund message, supplied by user as a base85-encoded string.
    pub msg_hash: String,
    /// Used in Near only, otherwise no bytes.
    pub wallet_id: Option<String>,
    /// On EVM: Encoded nonce. On Near something else.
    pub user_payload: String,
    /// Used in Near only, otherwise no bytes.
    pub metadata: Option<String>,
}


/// Data supplied by user, in order to get a signed message.
#[derive(
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Clone,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize
)]
pub struct ProofModel {
    pub auth_id: usize,
    pub message_body: Option<String>,
    pub user_payload: String,
    pub account_id: Option<String>,
}

/// The output of `get_wallet` on Near `mpc.hot.tg` smart contract.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq, Hash)]
pub struct WalletModel {
    pub access_list: Vec<WalletAccessModel>,
    pub key_gen: usize,
    pub block_height: u64,
}

/// `account_id` is the smart contract address, and `chain_id` is the internal identifier for the chain.
/// Together, they indicate where to call `hot_verify`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Eq, Hash)]
pub struct WalletAccessModel {
    pub account_id: String,
    pub metadata: Option<String>,
    pub chain_id: usize,
}

pub struct Validation {
    // near_validation: NearValidation,
    // base_validation: BaseValidation,
    // eth_validation: EthValidation,
}

pub struct NearValidationConfig {
    pub threshold: usize,
    pub servers: Vec<String>,
}

pub struct LightProofConfig {
    pub untrusted_rpc_url: String,
    pub consensus_rpc: String,
    pub data_dir: Option<PathBuf>,
}

// impl Validation {
//     pub async fn new(
//         near_validation_config: NearValidationConfig,
//     ) -> Self {
//         let evm_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
//         let near_validation = NearValidation::new(near_validation_config);
//
//         Self { near_validation }
//     }
//
//     pub async fn verify(
//         &self,
//         uid: String, // same as "tweak"/"epsilon"
//         message_hex: String,
//         proof: ProofModel,
//     ) -> Result<bool> {
//         let message_bs58 = hex::decode(&message_hex)
//             .map(|message_bytes| {
//                 bs58::encode(message_bytes).into_string()
//             })?;
//
//         let wallet_id = near::uid_to_wallet_id(&uid)?;
//         let wallet = self.near_validation.get_wallet_data(&wallet_id).await?;
//         let wallet_access = &wallet.access_list[proof.auth_id];
//         if let Some(chain) = Chain::from_usize(wallet_access.chain_id) {
//             let verify_args = VerifyArgs {
//                 wallet_id: Some(wallet_id),
//                 msg_hash: message_bs58,
//                 metadata: wallet_access.metadata.clone(),
//                 user_payload: proof.user_payload,
//             };
//
//             let result = match chain {
//                 Chain::Near => {
//                     self.near_validation.verify(wallet_access.account_id.as_str(), verify_args).await?
//                 }
//                 // Chain::Ethereum => {
//                 //     self.eth_validation.verify(wallet_access.account_id.as_str(), verify_args).await?
//                 // }
//                 // Chain::Base => {
//                 //     self.base_validation.verify(wallet_access.account_id.as_str(), verify_args).await?
//                 // }
//                 _ => { false }
//             };
//
//             Ok(result)
//         } else {
//             Ok(false)
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use tempfile::tempdir;
//     use super::*;
//
//     async fn build_validation() -> Validation {
//         let near_config: NearValidationConfig = NearValidationConfig {
//             threshold: 2,
//             servers: vec!(
//                 "https://rpc.mainnet.near.org".to_string(),
//                 "https://rpc.near.org".to_string(),
//                 "https://nearrpc.aurora.dev".to_string(),
//             ),
//         };
//
//         let base_config: LightProofConfig = LightProofConfig {
//             untrusted_rpc_url: "https://rpc-base.hotdao.ai".to_string(),
//             consensus_rpc: "https://base.operationsolarstorm.org".to_string(),
//             data_dir: None,
//         };
//
//         let tmp_dir = tempdir().expect("Failed to create temporary directory");
//         let tmp_dir_path: PathBuf = tmp_dir.path().to_path_buf();
//
//         let eth_config: LightProofConfig = LightProofConfig {
//             untrusted_rpc_url: "https://eth.meowrpc.com".to_string(),
//             consensus_rpc: "https://ethereum.operationsolarstorm.org".to_string(),
//             data_dir: Some(tmp_dir_path),
//         };
//
//         let validation = Validation::new(near_config).await;
//         validation
//     }
//
//
//     #[tokio::test]
//     async fn validate_on_near() {
//         // Making a single run due two timely setup
//         let validation = build_validation().await;
//
//         // Near
//         {
//             let uid = "0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f".to_string();
//             let message = "57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32".to_string();
//             let proof = ProofModel {
//                 auth_id: 0,
//                 message_body: Some("S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH".to_string()),
//                 user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
//                 account_id: Some("keys.auth.hot.tg".to_string()),
//             };
//
//             let actual = validation.verify(uid, message, proof).await.unwrap();
//             assert!(actual)
//         }
//
//         // TODO: Base, Eth
//     }
// }