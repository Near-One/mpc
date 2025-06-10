use crate::common::{gen_accounts, PARTICIPANT_LEN};
use base64::{engine::general_purpose, Engine};
use common::current_contract;
use mpc_contract::{
    config::InitConfig,
    primitives::thresholds::{Threshold, ThresholdParameters},
};
use near_workspaces::{network::Sandbox, Contract, Worker};
use reqwest::Client;
pub mod common;
use serde::Deserialize;

#[derive(Deserialize)]
struct RpcResponse {
    result: RpcResult,
}

#[derive(Deserialize)]
struct RpcResult {
    code_base64: String,
}

enum Network {
    Testnet,
    Mainnet,
}

async fn fetch_contract_code(network: Network) -> anyhow::Result<Vec<u8>> {
    let (url, account_id) = match network {
        Network::Mainnet => ("https://rpc.mainnet.near.org", "v1.signer"),
        Network::Testnet => ("https://rpc.testnet.near.org", "v1.signer-prod.testnet"),
    };

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "query",
        "params": {
            "request_type": "view_code",
            "finality": "final",
            "account_id": account_id
        }
    });

    let client = Client::new();
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await?
        .json::<RpcResponse>()
        .await?;
    Ok(general_purpose::STANDARD.decode(&response.result.code_base64)?)
}

async fn init_contract(worker: Worker<Sandbox>, contract: &Contract) -> anyhow::Result<()> {
    let (_, participants) = gen_accounts(&worker, PARTICIPANT_LEN).await;

    let threshold = ((participants.len() as f64) * 0.6).ceil() as u64;
    let threshold = Threshold::new(threshold);
    let threshold_parameters = ThresholdParameters::new(participants, threshold).unwrap();

    contract
        .call("init")
        .args_json(serde_json::json!({
            "parameters": threshold_parameters,
            "init_config": None::<InitConfig>,
        }))
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

async fn healthcheck(contract: &Contract) -> anyhow::Result<bool> {
    let status = contract
        .call("state")
        .transact()
        .await?
        .into_result()
        .is_ok();
    Ok(status)
}

async fn deploy_old(worker: &Worker<Sandbox>, network: Network) -> anyhow::Result<Contract> {
    let old_wasm = fetch_contract_code(network).await?;
    let old_contract = worker.dev_deploy(&old_wasm).await?;
    Ok(old_contract)
}

async fn upgrade_to_new(old_contract: Contract) -> anyhow::Result<Contract> {
    let new_wasm = current_contract();
    let new_contract = old_contract
        .as_account()
        .deploy(new_wasm)
        .await?
        .into_result()?;
    Ok(new_contract)
}

async fn migrate(contract: &Contract) -> anyhow::Result<()> {
    contract.call("migrate").transact().await?.into_result()?;
    Ok(())
}

/// Checks the contract in the following order:
/// 1. Are there any state-breaking changes?
/// 2. If so, does `migrate()` still work correctly?
///
/// These checks use the previous contract version (the one that introduced breaking changes)
/// as a baseline. If step 2 fails, you will be prompted to update the baseline contract.
async fn back_compatibility(network: Network) -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;

    let contract = deploy_old(&worker, network).await?;

    init_contract(worker, &contract).await?;

    assert!(healthcheck(&contract).await?);

    let contract = upgrade_to_new(contract).await?;

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: no breaking changes found 🫧.");
        return Ok(());
    }

    println!("🟨 Found breaking changes in the contract state.");
    println!("⚙️ Testing migration() call...");

    migrate(&contract)
        .await
        .expect("❌ Back compatibility check failed: migration() failed");

    if healthcheck(&contract).await? {
        println!("✅ Back compatibility check succeeded: migration() works fine 👍");
        return Ok(());
    };

    anyhow::bail!("❌Back compatibility check failed: state() call doesnt work after migration(). Probably you should introduce new logic to the `migrate()` method.")
}

#[tokio::test]
async fn test_back_compatiblity_mainnet() {
    back_compatibility(Network::Mainnet).await.unwrap();
}

#[tokio::test]
async fn test_back_compatiblity_testnet() {
    back_compatibility(Network::Testnet).await.unwrap();
}
