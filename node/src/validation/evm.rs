use crate::validation::{SingleVerifier, ThresholdVerifier, ChainValidationConfig, VerifyArgs, HOT_VERIFY_ABI, HOT_VERIFY_METHOD_NAME};
use anyhow::{Context, Result};
use k256::elliptic_curve::bigint::Zero;
use k256::U256;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use web3::ethabi;
use web3::ethabi::Contract;
use web3::types::{CallRequest, H160};

#[derive(Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: serde_json::Value,
}

impl RpcRequest {
    pub fn build(call_request: CallRequest) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: "dontcare".to_string(),
            method: "eth_call".to_string(),
            params: json!([call_request, "latest"]),
        }
    }
}

#[derive(Clone)]
struct EvmSingleVerifier {
    client: Arc<reqwest::Client>,
    server: String,
    contract: Contract,
}

impl EvmSingleVerifier {
    pub fn new(client: Arc<reqwest::Client>, server: String, contract: Contract) -> Self {
        Self { client, server, contract }
    }

    async fn call_rpc(&self, json: serde_json::Value) -> Result<String> {
        let response = self.client
            .post(&self.server)
            .timeout(Duration::from_secs(1))
            .json(&json)
            .send()
            .await?;

        if response.status().is_success() {
            let value = response.json::<serde_json::Value>().await?;
            let value = value
                .get("result")
                .context("missing result (rpc call is probably failed)")?;
            let value = serde_json::from_value::<String>(value.clone())?;
            Ok(value)
        } else {
            Err(anyhow::anyhow!(
                "Failed to call {}: {}",
                self.server,
                response.status()
            ))
        }
    }
}

#[async_trait]
impl SingleVerifier for EvmSingleVerifier {
    async fn verify(&self, auth_contract_id: &str, args: VerifyArgs) -> Result<bool> {
        let data = self.contract
            .function(HOT_VERIFY_METHOD_NAME)
            .unwrap()
            .encode_input(&[
                ethabi::token::Token::FixedBytes(hex::decode(args.msg_hash).unwrap()),
                ethabi::token::Token::Bytes(vec![]),
                ethabi::token::Token::Bytes(hex::decode(args.user_payload).unwrap()),
                ethabi::token::Token::Bytes(vec![]),
            ]).context("Bad arguments for evm smart contract")?;

        let call_request = CallRequest::builder()
            .to(H160::from_str(auth_contract_id)?)
            .data(data.into())
            .build();

        let rpc_request = RpcRequest::build(call_request);
        let rpc_request = serde_json::to_value(&rpc_request)?;

        let verify_result = self
            .call_rpc(rpc_request)
            .await?
            .trim_start_matches("0x")
            .to_string();
        let verify_result = U256::from_le_hex(verify_result.as_str());
        let verify_result_is_zero = bool::from(verify_result.is_zero());
        Ok(!verify_result_is_zero)
    }
}

pub struct EvmThresholdVerifier {
    threshold: usize,
    callers: Vec<EvmSingleVerifier>,
}

impl EvmThresholdVerifier {
    pub fn new(validation_config: ChainValidationConfig, client: Arc<reqwest::Client>, contract: Contract) -> Self {
        let threshold = validation_config.threshold;
        let servers = validation_config.servers;
        if threshold > servers.len() {
            panic!("There should be at least {} servers, got {}", threshold, servers.len())
        }
        let callers = servers
            .iter()
            .map(|s| {
                EvmSingleVerifier::new(client.clone(), s.clone(), contract.clone())
            })
            .collect();
        Self {
            threshold,
            callers,
        }
    }
}

impl ThresholdVerifier for EvmThresholdVerifier {
    fn get_verifiers(&self) -> Vec<impl SingleVerifier> {
        self.callers.clone()
    }

    fn get_threshold(&self) -> usize {
        self.threshold
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // Start local light client(s) before running tests.
    use crate::validation::{VerifyArgs, HOT_VERIFY_ABI};

    #[tokio::test]
    async fn base_single_verifier() {
        let evm_hot_verify_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let args = VerifyArgs {
            wallet_id: None,
            msg_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            metadata: None,
            user_payload: "00000000000000000000000000000000000000000000005dac769be0b6d400000000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let auth_contract_id = "0xf22Ef29d5Bb80256B569f4233a76EF09Cae996eC";
        let validation = EvmSingleVerifier::new(
            Arc::new(reqwest::Client::new()),
            "https://base-rpc.publicnode.com".to_string(),
            evm_hot_verify_contract,
        );
        let actual = validation.verify(auth_contract_id, args).await.unwrap();
        assert!(actual);
    }

    #[tokio::test]
    async fn base_single_verifier_non_trivial_message() {
        let evm_hot_verify_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let args = VerifyArgs {
            wallet_id: None,
            msg_hash: "ef32edffb454d2a3172fd0af3fdb0e43fac5060a929f1b83b6de2b73754e3f45".into(),
            metadata: None,
            user_payload: "00000000000000000000000000000000000000000000005e095d2c286c4414050000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let auth_contract_id = "0x42351e68420D16613BBE5A7d8cB337A9969980b4";
        let validation = EvmSingleVerifier::new(
            Arc::new(reqwest::Client::new()),
            "https://base-rpc.publicnode.com".to_string(),
            evm_hot_verify_contract,
        );
        let actual = validation.verify(auth_contract_id, args).await.unwrap();
        assert!(actual);
    }

    #[tokio::test]
    async fn base_single_verifier_wrong_message() {
        let evm_hot_verify_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let args = VerifyArgs {
            wallet_id: None,
            msg_hash: "0000000000012300000000000000000000000000000000000000000000000000".into(),
            metadata: None,
            user_payload: "00000000000000000000000000000000000000000000005dac769be0b6d400000000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let auth_contract_id = "0xf22Ef29d5Bb80256B569f4233a76EF09Cae996eC";
        let validation = EvmSingleVerifier::new(
            Arc::new(reqwest::Client::new()),
            "https://base-rpc.publicnode.com".to_string(),
            evm_hot_verify_contract,
        );
        let actual = validation.verify(auth_contract_id, args).await.unwrap();
        assert!(!actual);
    }

    #[tokio::test]
    async fn base_threshold_verifier() {
        let evm_hot_verify_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let args = VerifyArgs {
            wallet_id: None,
            msg_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            metadata: None,
            user_payload: "00000000000000000000000000000000000000000000005dac769be0b6d400000000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let auth_contract_id = "0xf22Ef29d5Bb80256B569f4233a76EF09Cae996eC";

        let validation = EvmThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 1,
                servers: vec![
                    "http://localhost:8545".to_string(),
                    "https://base-rpc.publicnode.com".to_string(),
                    "http://localhost:8545".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
            evm_hot_verify_contract,
        );

        let actual = validation.verify(auth_contract_id, args).await.unwrap();
        assert!(actual);
    }

    #[tokio::test]
    async fn base_threshold_verifier_with_bad_rpcs() {
        let evm_hot_verify_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let args = VerifyArgs {
            wallet_id: None,
            msg_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            metadata: None,
            user_payload: "00000000000000000000000000000000000000000000005dac769be0b6d400000000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let auth_contract_id = "0xf22Ef29d5Bb80256B569f4233a76EF09Cae996eC";

        let validation = EvmThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 1,
                servers: vec![
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:8545".to_string(),
                    "http://localhost:1000".to_string(),
                    "https://base-rpc.publicnode.com".to_string(),
                    "http://localhost:1000".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
            evm_hot_verify_contract,
        );

        let actual = validation.verify(auth_contract_id, args).await.unwrap();
        assert!(actual);
    }

    #[tokio::test]
    async fn base_threshold_verifier_all_rpcs_bad() {
        let evm_hot_verify_contract = Contract::load(HOT_VERIFY_ABI.as_bytes()).unwrap();
        let args = VerifyArgs {
            wallet_id: None,
            msg_hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            metadata: None,
            user_payload: "00000000000000000000000000000000000000000000005dac769be0b6d400000000000000000000000000000000000000000000000000000000000000000000".into(),
        };
        let auth_contract_id = "0xf22Ef29d5Bb80256B569f4233a76EF09Cae996eC";

        let validation = EvmThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 1,
                servers: vec![
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                    "http://localhost:1000".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
            evm_hot_verify_contract,
        );

        let actual = validation.verify(auth_contract_id, args).await.unwrap();
        assert!(!actual);
    }
}