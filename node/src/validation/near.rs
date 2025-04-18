use crate::validation::{
    ChainValidationConfig, GetWalletArgs, SingleVerifier, ThresholdVerifier, VerifyArgs,
    WalletModel, HOT_VERIFY_METHOD_NAME, MPC_GET_WALLET_METHOD, MPC_HOT_WALLET_CONTRACT,
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures_util::stream::FuturesUnordered;
use near_sdk::base64::prelude::BASE64_STANDARD;
use near_sdk::base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;

#[derive(Serialize, Deserialize)]
struct RpcParams {
    request_type: String,
    finality: String,
    account_id: String,
    method_name: String,
    args_base64: String,
}

impl RpcParams {
    pub fn build(account_id: String, method_name: String, args_base64: String) -> Self {
        Self {
            request_type: "call_function".to_string(),
            finality: "final".to_string(),
            account_id,
            method_name,
            args_base64,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: RpcParams,
}

impl RpcRequest {
    pub fn build(account_id: String, method_name: String, args_base64: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: "dontcare".to_string(),
            method: "query".to_string(),
            params: RpcParams::build(account_id, method_name, args_base64),
        }
    }
}

#[derive(Clone)]
struct NearSingleVerifier {
    client: Arc<reqwest::Client>,
    server: String,
}

impl NearSingleVerifier {
    fn new(client: Arc<reqwest::Client>, server: String) -> Self {
        Self { client, server }
    }

    async fn get_wallet(&self, wallet_id: String) -> Result<WalletModel> {
        let method_args = GetWalletArgs { wallet_id };
        let args_base64 = BASE64_STANDARD.encode(serde_json::to_vec(&method_args)?);
        let rpc_args = RpcRequest::build(
            MPC_HOT_WALLET_CONTRACT.to_string(),
            MPC_GET_WALLET_METHOD.to_string(),
            args_base64,
        );
        let wallet_model = self.call_rpc(serde_json::to_value(&rpc_args)?).await?;
        let wallet_model = serde_json::from_slice::<WalletModel>(wallet_model.as_slice())?;
        Ok(wallet_model)
    }

    async fn call_rpc(&self, json: serde_json::Value) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(&self.server)
            .timeout(Duration::from_secs(1))
            .json(&json)
            .send()
            .await?;

        if response.status().is_success() {
            let value = response.json::<serde_json::Value>().await?;
            // Intended.
            //  Call result is bytes, which are wrapped in "Result", which is wrapped in "Result"
            let value = value
                .get("result")
                .context("missing result (rpc call is probably failed)")?;
            let value = value.get("result").context("missing result in result")?;
            let value = serde_json::from_value::<Vec<u8>>(value.clone())?;
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
impl SingleVerifier for NearSingleVerifier {
    async fn verify(&self, auth_contract_id: &str, args: VerifyArgs) -> Result<()> {
        let args_base64 = BASE64_STANDARD.encode(serde_json::to_vec(&args)?);
        let rpc_args = RpcRequest::build(
            auth_contract_id.to_string(),
            HOT_VERIFY_METHOD_NAME.to_string(),
            args_base64,
        );
        let verify_result = self.call_rpc(serde_json::to_value(&rpc_args)?).await?;
        let verify_result = serde_json::from_slice::<bool>(verify_result.as_slice())?;
        if verify_result {
            Ok(())
        } else {
            bail!(
                "Near, {} -> {auth_contract_id} returned False on `verify()`",
                self.server
            )
        }
    }
}

pub struct NearThresholdVerifier {
    threshold: usize,
    callers: Vec<NearSingleVerifier>,
}

impl NearThresholdVerifier {
    pub fn new(
        near_validation_config: ChainValidationConfig,
        client: Arc<reqwest::Client>,
    ) -> Self {
        let threshold = near_validation_config.threshold;
        let servers = near_validation_config.servers;
        if threshold > servers.len() {
            panic!(
                "There should be at least {} servers, got {}",
                threshold,
                servers.len()
            )
        }
        let callers = servers
            .iter()
            .map(|s| NearSingleVerifier::new(client.clone(), s.clone()))
            .collect();
        Self { threshold, callers }
    }

    pub async fn get_wallet_data(&self, wallet_id: &str) -> Result<WalletModel> {
        let mut futures: FuturesUnordered<_> = self
            .callers
            .iter()
            .map(|caller| caller.get_wallet(wallet_id.to_owned()))
            .collect();

        let mut call_results: HashMap<WalletModel, usize> = HashMap::new();

        while let Some(result_wallet_model) = futures.next().await {
            if let Ok(wallet_model) = result_wallet_model {
                *call_results.entry(wallet_model).or_insert(0) += 1;
            }
        }

        let result = call_results
            .iter()
            .find(|(_, &count)| count >= self.threshold)
            .map(|(k, _)| k.clone())
            .ok_or_else(|| anyhow!("No consesus for `get_wallet`"))?;
        Ok(result)
    }
}

impl ThresholdVerifier for NearThresholdVerifier {
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
    use crate::validation::{uid_to_wallet_id, WalletAccessModel, NEAR_CHAIN_ID};

    #[tokio::test]
    async fn near_single_verifier() {
        let client = Arc::new(reqwest::Client::new());
        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = NearSingleVerifier::new(client, server_addr.to_string());

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();
        let auth_contract_id: &str = "keys.auth.hot.tg";

        let args = VerifyArgs {
            msg_body: "".to_string(),
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        rpc_caller.verify(auth_contract_id, args).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn near_single_verifier_bad_wallet() {
        let client = Arc::new(reqwest::Client::new());
        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = NearSingleVerifier::new(client, server_addr.to_string());

        let wallet_id = "B8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();
        let auth_contract_id: &str = "keys.auth.hot.tg";

        let args = VerifyArgs {
            msg_body: "".to_string(),
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        rpc_caller.verify(auth_contract_id, args).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn near_single_verifier_bad_auth_contract() {
        let client = Arc::new(reqwest::Client::new());
        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = NearSingleVerifier::new(client, server_addr.to_string());

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();
        let auth_contract_id: &str = "123123.auth.hot.tg";

        let args = VerifyArgs {
            msg_body: "".to_string(),
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        rpc_caller.verify(auth_contract_id, args).await.unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn near_single_verifier_bad_msg_hash() {
        let client = Arc::new(reqwest::Client::new());
        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = NearSingleVerifier::new(client, server_addr.to_string());

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();
        let auth_contract_id: &str = "keys.auth.hot.tg";

        let args = VerifyArgs {
            msg_body: "".to_string(),
            msg_hash: "7vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };
        rpc_caller.verify(auth_contract_id, args).await.unwrap();
    }

    #[tokio::test]
    async fn near_threshold_verifier() {
        let rpc_validation = NearThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 2,
                servers: vec![
                    "https://rpc.mainnet.near.org".to_string(),
                    "https://rpc.near.org".to_string(),
                    "https://nearrpc.aurora.dev".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
        );

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();
        let auth_contract_id: &str = "keys.auth.hot.tg";
        let args = VerifyArgs {
            msg_body: "".to_string(),
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        rpc_validation.verify(auth_contract_id, args).await.unwrap();
    }

    #[should_panic]
    #[tokio::test]
    async fn near_threshold_verifier_all_rpcs_bad() {
        let rpc_validation = NearThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 2,
                servers: vec![
                    "https://hello.com".to_string(),
                    "https://hello.com".to_string(),
                    "https://hello.com".to_string(),
                    "https://hello.com".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
        );

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();
        let auth_contract_id: &str = "keys.auth.hot.tg";
        let args = VerifyArgs {
            msg_body: "".to_string(),
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        rpc_validation.verify(auth_contract_id, args).await.unwrap();
    }

    #[tokio::test]
    async fn near_single_verifier_get_wallet() {
        let client = Arc::new(reqwest::Client::new());
        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = NearSingleVerifier::new(client, server_addr.to_string());

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: NEAR_CHAIN_ID,
            }],
            key_gen: 1,
            block_height: 0,
        };

        let actual = rpc_caller.get_wallet(wallet_id.to_string()).await.unwrap();
        assert_eq!(actual, expected)
    }

    #[tokio::test]
    async fn threshold_verifier_get_wallet() {
        let rpc_validation = NearThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 2,
                servers: vec![
                    "https://rpc.mainnet.near.org".to_string(),
                    "https://rpc.near.org".to_string(),
                    "https://nearrpc.aurora.dev".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
        );

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: NEAR_CHAIN_ID,
            }],
            key_gen: 1,
            block_height: 0,
        };

        let actual = rpc_validation
            .get_wallet_data(&wallet_id.to_string())
            .await
            .unwrap();

        assert_eq!(actual, expected)
    }

    #[tokio::test]
    async fn threshold_verifier_get_wallet_bad_rpcs() {
        let rpc_validation = NearThresholdVerifier::new(
            ChainValidationConfig {
                threshold: 3,
                servers: vec![
                    "https://google.com".to_string(),
                    "https://bim-bim-bom-bom.com".to_string(),
                    "https://rpc.mainnet.near.org".to_string(),
                    "https://hello.dev".to_string(),
                    "https://rpc.near.org".to_string(),
                    "https://nearrpc.aurora.dev".to_string(),
                ],
            },
            Arc::new(reqwest::Client::new()),
        );

        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: NEAR_CHAIN_ID,
            }],
            key_gen: 1,
            block_height: 0,
        };

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let actual = rpc_validation
            .get_wallet_data(&wallet_id.to_string())
            .await
            .unwrap();

        assert_eq!(actual, expected)
    }

    #[test]
    fn converter_to_base58_correct() {
        let uid = "0887d14fbe253e8b6a7b8193f3891e04f88a9ed744b91f4990d567ffc8b18e5f";
        let expected = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let actual = uid_to_wallet_id(uid).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    #[should_panic]
    fn converter_to_base58_incorrect() {
        let uid = "sha256 expected as uid";
        uid_to_wallet_id(uid).unwrap();
    }

    #[test]
    fn get_wallet_data_model_correct() {
        let sample_json = r#"{
            "access_list": [
                {
                    "account_id": "keys.auth.hot.tg",
                    "metadata": null,
                    "chain_id": 0
                }
            ],
            "key_gen": 1,
            "block_height": 0
        }"#;

        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: NEAR_CHAIN_ID,
            }],
            key_gen: 1,
            block_height: 0,
        };

        let actual: WalletModel = serde_json::from_str(sample_json).unwrap();

        assert_eq!(actual, expected);
    }
}
