use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use anyhow::{Result, anyhow, Context};
use futures_util::stream::FuturesUnordered;
use near_sdk::{bs58};
use near_sdk::base64::Engine;
use near_sdk::base64::prelude::BASE64_STANDARD;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tokio_stream::StreamExt;
use crate::validation::{GetWalletArgs, NearValidationConfig, VerifyArgs, WalletModel, HOT_VERIFY_METHOD_NAME, MPC_GET_WALLET_METHOD, MPC_HOT_WALLET_CONTRACT};

pub(crate) fn uid_to_wallet_id(uid: &str) -> Result<String> {
    let uid_bytes = hex::decode(uid)?;
    let sha256_bytes = Sha256::new_with_prefix(uid_bytes).finalize();
    let uid_b58 = bs58::encode(sha256_bytes.as_slice()).into_string();
    Ok(uid_b58)
}

struct RpcCaller {
    client: Arc<reqwest::Client>,
    server: String,
}

#[derive(Serialize, Deserialize)]
struct RpcParams {
    request_type: String,
    finality: String,
    account_id: String,
    method_name: String,
    args_base64: String
}

impl RpcParams {
    pub fn build(account_id: String,
                 method_name: String,
                 args_base64: String) -> Self {
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
    pub fn build(
        account_id: String,
        method_name: String,
        args_base64: String,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: "dontcare".to_string(),
            method: "query".to_string(),
            params: RpcParams::build(account_id, method_name, args_base64),
        }
    }
}

impl RpcCaller {
    fn new(client: Arc<reqwest::Client>, server: String) -> Self {
        Self { client, server, }
    }

    pub async fn verify(&self, auth_contract_id: &str, args: VerifyArgs) -> Result<bool> {
        let args_base64 = BASE64_STANDARD.encode(serde_json::to_vec(&args)?);
        let rpc_args = RpcRequest::build(
            auth_contract_id.to_string(),
            HOT_VERIFY_METHOD_NAME.to_string(),
            args_base64,
        );
        let verify_result = self.call_rpc(serde_json::to_value(&rpc_args)?).await?;
        let verify_result = serde_json::from_slice::<bool>(verify_result.as_slice())?;
        Ok(verify_result)
    }

    async fn get_wallet(&self, wallet_id: String) -> Result<WalletModel> {
        let method_args = GetWalletArgs { wallet_id };
        let args_base64 = BASE64_STANDARD.encode(serde_json::to_vec(&method_args)?);
        let rpc_args = RpcRequest::build(
            MPC_HOT_WALLET_CONTRACT.to_string(),
            MPC_GET_WALLET_METHOD.to_string(),
            args_base64
        );
        let wallet_model = self.call_rpc(serde_json::to_value(&rpc_args)?).await?;
        let wallet_model = serde_json::from_slice::<WalletModel>(wallet_model.as_slice())?;
        Ok(wallet_model)
    }

    async fn call_rpc(&self, json: serde_json::Value) -> Result<Vec<u8>> {
        let response = self.client
            .post(&self.server)
            .timeout(Duration::from_secs(1))
            .json(&json)
            .send()
            .await?;

        if response.status().is_success() {
            let value = response.json::<serde_json::Value>().await?;
            // Intended.
            //  Call result is bytes, which are wrapped in "Result", which is wrapped in "Result"
            let value = value.get("result").context("missing result (rpc call is probably failed)")?;
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

pub struct NearValidation {
    threshold: usize,
    callers: Vec<RpcCaller>,
}

impl NearValidation {
    pub fn new(near_validation_config: NearValidationConfig) -> Self {
        let threshold = near_validation_config.threshold;
        let servers = near_validation_config.servers;
        if threshold > servers.len() {
            panic!("There should be at least {} servers, got {}", threshold, servers.len())
        }
        let client = Arc::new(reqwest::Client::new());
        let callers = servers
            .iter()
            .map(|s| {
                RpcCaller::new(client.clone(), s.clone())
            })
            .collect();
        Self {
            threshold,
            callers,
        }
    }

    pub async fn get_wallet_data(&self, wallet_id: &String) -> Result<WalletModel> {
        let mut futures: FuturesUnordered<_> = self
            .callers
            .iter()
            .map(|caller| {
                caller.get_wallet(wallet_id.clone())
            })
            .collect();

        let mut call_results: HashMap<WalletModel, usize> = HashMap::new();

        while let Some(result_wallet_model) = futures.next().await {
            if let Ok(wallet_model) = result_wallet_model {
                *call_results.entry(wallet_model).or_insert(0) += 1;
            }
        }

        let result =
            call_results
                .iter()
                .find(|(_, &count)| count >= self.threshold)
                .map(|(k, _)| k.clone())
                .ok_or_else(|| anyhow!("No consesus for `get_wallet`"))?;

        Ok(result)
    }

    pub async fn verify(&self, auth_contract_id: &str, args: VerifyArgs) -> Result<bool> {
        let mut futures: FuturesUnordered<_> = self
            .callers
            .iter()
            .map(|caller| {
                caller.verify(auth_contract_id, args.clone())
            })
            .collect();

        let mut count = 0;

        while let Some(result) = futures.next().await {
            if let Ok(verdict) = result {
                if verdict {
                    count += 1
                }
            }
            if count >= self.threshold {
                break;
            }
        }

        Ok(count >= self.threshold)
    }
}

#[cfg(test)]
mod tests {
    use crate::validation::{ProofModel, WalletAccessModel};
    use super::*;

    #[tokio::test]
    async fn check_verify() {
        let client = Arc::new(reqwest::Client::new());
        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();

        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = RpcCaller::new(client, server_addr.to_string());

        let auth_contract_id: &str = "keys.auth.hot.tg";
        let args = VerifyArgs {
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        let result = rpc_caller.verify(auth_contract_id, args).await.unwrap();
        assert!(result)
    }

    #[tokio::test]
    #[should_panic]
    async fn check_verify_bad_wallet() {
        let client = Arc::new(reqwest::Client::new());
        let wallet_id = "B8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();

        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = RpcCaller::new(client, server_addr.to_string());

        let auth_contract_id: &str = "keys.auth.hot.tg";
        let args = VerifyArgs {
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        let result = rpc_caller.verify(auth_contract_id, args).await.unwrap();
        assert!(result)
    }

    #[tokio::test]
    #[should_panic]
    async fn check_verify_bad_auth_contract() {
        let client = Arc::new(reqwest::Client::new());
        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();

        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = RpcCaller::new(client, server_addr.to_string());

        let auth_contract_id: &str = "123123.auth.hot.tg";
        let args = VerifyArgs {
            msg_hash: "6vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        let result = rpc_caller.verify(auth_contract_id, args).await.unwrap();
        assert!(result)
    }

    #[tokio::test]
    #[should_panic]
    async fn check_verify_bad_msg_hash() {
        let client = Arc::new(reqwest::Client::new());
        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn".to_string();

        let server_addr = "https://rpc.mainnet.near.org";
        let rpc_caller = RpcCaller::new(client, server_addr.to_string());

        let auth_contract_id: &str = "keys.auth.hot.tg";
        let args = VerifyArgs {
            msg_hash: "7vLRVXiHvroXw1LEU1BNhz7QSaG73U41WM45m87X55H3".to_string(),
            wallet_id: Some(wallet_id),
            user_payload: r#"{"auth_method":0,"signatures":["HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH"]}"#.to_string(),
            metadata: None,
        };

        let result = rpc_caller.verify(auth_contract_id, args).await.unwrap();
        assert!(result)
    }

    #[test]
    fn proof_check_data_model() {
        let sample = r#"{
            "account_id":"keys.auth.hot.tg",
            "auth_id":0,
            "user_payload":"{\\\"auth_method\\\":0,\\\"signatures\\\":[\\\"HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH\\\"]}",
            "message_body":"S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH"
        }"#;

        let expected = ProofModel {
            auth_id: 0,
            message_body: Some("S8safEk4JWgnJsVKxans4TqBL796cEuV5GcrqnFHPdNW91AupymrQ6zgwEXoeRb6P3nyaSskoFtMJzaskXTDAnQUTKs5dGMWQHsz7irQJJ2UA2aDHSQ4qxgsU3h1U83nkq4rBstK8PL1xm6WygSYihvBTmuaMjuKCK6JT1tB4Uw71kGV262kU914YDwJa53BiNLuVi3s2rj5tboEwsSEpyJo9x5diq4Ckmzf51ZjZEDYCH8TdrP1dcY4FqkTCBA7JhjfCTToJR5r74ApfnNJLnDhTxkvJb4ReR9T9Ga7hPNazCFGE8Xq1deu44kcPjXNvb1GJGWLAZ5k1wxq9nnARb3bvkqBTmeYiDcPDamauhrwYWZkMNUsHtoMwF6286gcmY3ZgE3jja1NGuYKYQHnvscUqcutuT9qH".to_string()),
            user_payload: r#"{\"auth_method\":0,\"signatures\":[\"HZUhhJamfp8GJLL8gEa2F2qZ6TXPu4PYzzWkDqsTQsMcW9rQsG2Hof4eD2Vex6he2fVVy3UNhgi631CY8E9StAH\"]}"#.to_string(),
            account_id: Some("keys.auth.hot.tg".to_string()),
        };

        let actual = serde_json::from_str::<ProofModel>(sample).unwrap();
        assert_eq!(actual, expected)
    }

    #[tokio::test]
    async fn check_get_wallet() {
        let client = Arc::new(reqwest::Client::new());
        let server_addr = "https://rpc.mainnet.near.org";
        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let rpc_caller = RpcCaller::new(client, server_addr.to_string());

        let actual = rpc_caller.get_wallet(wallet_id.to_string()).await.unwrap();

        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: 0,
            }],
            key_gen: 1,
            block_height: 0,
        };

        assert_eq!(actual, expected)
    }

    #[tokio::test]
    async fn check_get_wallet_combined() {
        let rpc_validation = NearValidation::new(
            NearValidationConfig {
                threshold: 2,
                servers: vec!(
                    "https://rpc.mainnet.near.org".to_string(),
                    "https://rpc.near.org".to_string(),
                    "https://nearrpc.aurora.dev".to_string(),
                ),
            }
        );

        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: 0,
            }],
            key_gen: 1,
            block_height: 0,
        };

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let actual = rpc_validation
            .get_wallet_data(&wallet_id.to_string())
            .await.unwrap();

        assert_eq!(actual, expected)
    }

    #[tokio::test]
    async fn check_get_wallet_combined_with_bad_rpcs() {
        let rpc_validation = NearValidation::new(
            NearValidationConfig {
                threshold: 3,
                servers: vec!(
                    "https://google.com".to_string(),
                    "https://bim-bim-bom-bom.com".to_string(),
                    "https://rpc.mainnet.near.org".to_string(),
                    "https://hello.dev".to_string(),
                    "https://rpc.near.org".to_string(),
                    "https://nearrpc.aurora.dev".to_string(),
                ),
            }
        );

        let expected = WalletModel {
            access_list: vec![WalletAccessModel {
                account_id: "keys.auth.hot.tg".to_string(),
                metadata: None,
                chain_id: 0,
            }],
            key_gen: 1,
            block_height: 0,
        };

        let wallet_id = "A8NpkSkn1HZPYjxJRCpD4iPhDHzP81bbduZTqPpHmEgn";
        let actual = rpc_validation
            .get_wallet_data(&wallet_id.to_string())
            .await.unwrap();

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
            access_list: vec![
                WalletAccessModel {
                    account_id: "keys.auth.hot.tg".to_string(),
                    metadata: None,
                    chain_id: 0
                }
            ],
            key_gen: 1,
            block_height: 0,
        };

        let actual: WalletModel = serde_json::from_str(sample_json).unwrap();

        assert_eq!(actual, expected);
    }
}

