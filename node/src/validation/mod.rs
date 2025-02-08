mod near;
mod evm;

use crate::validation::evm::EvmThresholdVerifier;
use crate::validation::near::NearThresholdVerifier;
use anyhow::{bail, Result};
use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use futures_util::stream::FuturesUnordered;
use near_sdk::{bs58};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_stream::StreamExt;
use tracing::log;
use web3::ethabi::Contract;

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
    pub msg_body: String,
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
    pub message_body: String,
    pub user_payloads: Vec<String>,
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

#[async_trait]
pub(crate) trait SingleVerifier {
    async fn verify(&self, auth_contract_id: &str, args: VerifyArgs) -> Result<()>;
}

pub(crate) trait ThresholdVerifier {
    fn get_verifiers(&self) -> Vec<impl SingleVerifier>;
    fn get_threshold(&self) -> usize;

    async fn verify(&self, auth_contract_id: &str, args: VerifyArgs) -> Result<()> {
        let verifiers = self.get_verifiers();
        let mut futures: FuturesUnordered<_> = verifiers
            .iter()
            .map(|caller| {
                caller.verify(auth_contract_id, args.clone())
            })
            .collect();

        let mut count = 0;
        let threshold = self.get_threshold();
        while let Some(result) = futures.next().await {
            match result {
                Ok(_) => { count += 1 },
                Err(e) => { log::warn!("{}", e) }
            }
            if count >= threshold {
                break;
            }
        }

        if count >= threshold {
            Ok(())
        } else {
            bail!("Threshold is not met: count: {count}, threshold: {threshold}, total: {}", verifiers.len());
        }
    }
}

pub struct Validation {
    near_validation: NearThresholdVerifier,
    base_validation: EvmThresholdVerifier,
    eth_validation: EvmThresholdVerifier,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainValidationConfig {
    pub threshold: usize,
    pub servers: Vec<String>,
}

pub(crate) fn uid_to_wallet_id(uid: &str) -> Result<String> {
    let uid_bytes = hex::decode(uid)?;
    let sha256_bytes = Sha256::new_with_prefix(uid_bytes).finalize();
    let uid_b58 = bs58::encode(sha256_bytes.as_slice()).into_string();
    Ok(uid_b58)
}

impl Validation {
    pub fn new(
        client: Arc<reqwest::Client>,
        near_validation_config: ChainValidationConfig,
        base_validation_config: ChainValidationConfig,
        eth_validation_config: ChainValidationConfig,
    ) -> Self {
        let near_validation = NearThresholdVerifier::new(near_validation_config, client.clone());

        let contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let base_validation = EvmThresholdVerifier::new(
            base_validation_config,
            client.clone(),
            contract.clone(),
        );

        let eth_validation = EvmThresholdVerifier::new(
            eth_validation_config,
            client.clone(),
            contract.clone(),
        );

        Self {
            near_validation,
            base_validation,
            eth_validation,
        }
    }

    pub async fn verify(
        &self,
        uid: String,
        message_hex: String,
        proof: ProofModel,
    ) -> Result<()> {
        let wallet_id = uid_to_wallet_id(&uid)?;
        let wallet = self.near_validation.get_wallet_data(&wallet_id).await?;

        if proof.user_payloads.len() != wallet.access_list.len() {
            bail!(
               "Length of provided user payloads ({}) doesn't match with required wallet authorization ({})",
               proof.user_payloads.len(),
               wallet.access_list.len()
           )
        }

        let mut futures = FuturesUnordered::new();
        for (wallet_access, user_payload) in wallet.access_list.iter().zip(proof.user_payloads.iter()) {
            let fut = self.verify_for_wallet_access(
                wallet_id.clone(),
                wallet_access.clone(),
                proof.message_body.clone(),
                message_hex.clone(),
                user_payload.clone(),
            );
            futures.push(fut);
        }

        while let Some(result) = futures.next().await {
            result?;
        }

        Ok(())
    }

    async fn verify_for_wallet_access(
        &self,
        wallet_id: String,
        wallet_access: WalletAccessModel,
        message_body: String,
        message_hex: String,
        user_payload: String,
    ) -> Result<()> {
        if let Some(chain) = Chain::from_usize(wallet_access.chain_id) {
            match chain {
                Chain::Near => {
                    let message_bs58 = hex::decode(&message_hex)
                        .map(|message_bytes| {
                            bs58::encode(message_bytes).into_string()
                        })?;

                    let verify_args = VerifyArgs {
                        wallet_id: Some(wallet_id),
                        msg_hash: message_bs58,
                        metadata: wallet_access.metadata.clone(),
                        user_payload,
                        msg_body: message_body
                    };
                    self.near_validation.verify(wallet_access.account_id.as_str(), verify_args).await?
                }
                Chain::Ethereum => {
                    let verify_args = VerifyArgs {
                        wallet_id: Some(wallet_id),
                        msg_hash: message_hex,
                        metadata: wallet_access.metadata.clone(),
                        user_payload,
                        msg_body: message_body
                    };
                    self.eth_validation.verify(wallet_access.account_id.as_str(), verify_args).await?
                }
                Chain::Base => {
                    let verify_args = VerifyArgs {
                        wallet_id: Some(wallet_id),
                        msg_hash: message_hex,
                        metadata: wallet_access.metadata.clone(),
                        user_payload,
                        msg_body: message_body
                    };
                    self.base_validation.verify(wallet_access.account_id.as_str(), verify_args).await?
                }
            };

            Ok(())
        } else {
            bail!("Unexpected chain id: {}", wallet_access.chain_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_validation_object() -> Validation {
        let validation = Validation::new(
            Arc::new(reqwest::Client::new()),
            ChainValidationConfig {
                threshold: 2,
                servers: vec!(
                    "https://rpc.mainnet.near.org".to_string(),
                    "https://rpc.near.org".to_string(),
                    "https://nearrpc.aurora.dev".to_string(),
                ),
            },
            ChainValidationConfig {
                threshold: 1,
                servers: vec![
                    "https://base-rpc.publicnode.com".to_string(),
                    "http://localhost:8545".to_string(),
                    "http://bad-rpc:8545".to_string(),
                ],
            },
            ChainValidationConfig {
                threshold: 1,
                servers: vec![
                    "http://localhost:8546".to_string(),
                    "http://bad-rpc:8546".to_string(),
                ],
            },
        );
        validation
    }

    #[tokio::test]
    async fn validate_on_near() {
        let validation = create_validation_object();

        let uid = "0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f".to_string();
        let message = "57f42da8350f6a7c6ad567d678355a3bbd17a681117e7a892db30656d5caee32".to_string();
        let proof = ProofModel {
            message_body: "S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH".to_string(),
            user_payloads: vec![r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string()],
        };

        validation.verify(uid, message, proof).await.unwrap();
    }

    #[tokio::test]
    async fn validate_on_base() {
        let validation = create_validation_object();

        let uid = "6c2015fd2a1a858144749d55d0f38f0632b8342f59a2d44ee374d64047b0f4f4".to_string();
        let message = "ef32edffb454d2a3172fd0af3fdb0e43fac5060a929f1b83b6de2b73754e3f45".to_string();
        let proof = ProofModel {
            message_body: "S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH".to_string(),
            user_payloads: vec!["00000000000000000000000000000000000000000000005e095d2c286c4414050000000000000000000000000000000000000000000000000000000000000000".to_string()],
        };

    validation.verify(uid, message, proof).await.unwrap();
    }
}