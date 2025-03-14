pub mod common;
use common::{create_response, init_env};

use mpc_contract::primitives::signature::SignRequest;
use near_sdk::{CurveType, PublicKey};
use near_workspaces::types::NearToken;
use serde_json::json;
use std::str::FromStr;
#[tokio::test]
async fn test_key_version() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env().await;

    let version: u32 = contract
        .view("latest_key_version")
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(version, 0);
    Ok(())
}

#[tokio::test]
async fn test_public_key() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env().await;

    let key: String = contract.view("public_key").await.unwrap().json().unwrap();
    println!("{:?}", key);
    let pk = PublicKey::from_str(&key)?;
    assert_eq!(pk.curve_type(), CurveType::SECP256K1);
    Ok(())
}

#[tokio::test]
async fn test_derived_public_key() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env().await;

    let key: String = contract
        .view("derived_public_key")
        .args_json(json!({
            "path": "test",
            "predecessor": "alice.near"
        }))
        .await
        .unwrap()
        .json()
        .unwrap();
    let pk = PublicKey::from_str(&key)?;
    assert_eq!(pk.curve_type(), CurveType::SECP256K1);
    Ok(())
}

#[tokio::test]
async fn test_experimental_signature_deposit() -> anyhow::Result<()> {
    let (worker, contract, _, sk) = init_env().await;

    let deposit: u128 = contract
        .view("experimental_signature_deposit")
        .await
        .unwrap()
        .json::<String>()
        .unwrap()
        .parse()?;
    assert_eq!(deposit, 1);

    let alice = worker.dev_create_account().await?;
    let path = "test";

    for i in 1..5 {
        let msg = format!("hello world {}", i);
        println!("submitting: {msg}");
        let (payload_hash, _, _) = create_response(alice.id(), &msg, path, &sk).await;
        let request = SignRequest {
            payload: payload_hash,
            path: path.into(),
            key_version: 0,
        };
        let _status = alice
            .call(contract.id(), "sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .deposit(NearToken::from_near(1))
            .max_gas()
            .transact_async()
            .await?;
    }

    // wait so all sign are called, but not yet timeout
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    let deposit: u128 = contract
        .view("experimental_signature_deposit")
        .await
        .unwrap()
        .json::<String>()
        .unwrap()
        .parse()?;
    assert_eq!(deposit, NearToken::from_yoctonear(1).as_yoctonear());
    Ok(())
}
