pub mod common;
use common::{
    candidates, contruct_valid_key_state_proposal, create_response, init, init_env,
    sign_and_validate,
};

use mpc_contract::{
    config::InitConfig,
    errors,
    primitives::{
        key_state::KeyStateProposal,
        participants::Participants,
        signature::SignRequest,
        thresholds::{DKGThreshold, Threshold, ThresholdParameters},
    },
};
use near_workspaces::types::NearToken;

use crypto_shared::SignatureResponse;
use std::mem;

#[tokio::test]
async fn test_contract_sign_request() -> anyhow::Result<()> {
    let (_, contract, _, sk) = init_env().await;
    let predecessor_id = contract.id();
    let path = "test";

    let messages = [
        "hello world",
        "hello world!",
        "hello world!!",
        "hello world!!!",
        "hello world!!!!",
    ];

    for msg in messages {
        println!("submitting: {msg}");
        let (payload_hash, respond_req, respond_resp) =
            create_response(predecessor_id, msg, path, &sk).await;
        let request = SignRequest {
            payload: payload_hash,
            path: path.into(),
            key_version: 0,
        };

        sign_and_validate(&request, Some((&respond_req, &respond_resp)), &contract).await?;
    }

    // check duplicate requests can also be signed:
    let duplicate_msg = "welp";
    let (payload_hash, respond_req, respond_resp) =
        create_response(predecessor_id, duplicate_msg, path, &sk).await;
    let request = SignRequest {
        payload: payload_hash,
        path: path.into(),
        key_version: 0,
    };
    sign_and_validate(&request, Some((&respond_req, &respond_resp)), &contract).await?;
    sign_and_validate(&request, Some((&respond_req, &respond_resp)), &contract).await?;

    // Check that a sign with no response from MPC network properly errors out:
    let err = sign_and_validate(&request, None, &contract)
        .await
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::SignError::Timeout.to_string()));

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_success_refund() -> anyhow::Result<()> {
    let (worker, contract, _, sk) = init_env().await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";

    let msg = "hello world!";
    println!("submitting: {msg}");
    let (payload_hash, respond_req, respond_resp) =
        create_response(alice.id(), msg, path, &sk).await;
    let request = SignRequest {
        payload: payload_hash,
        path: path.into(),
        key_version: 0,
    };

    let status = alice
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_near(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Call `respond` as if we are the MPC network itself.
    let respond = contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);

    let execution = status.await?;
    dbg!(&execution);

    let execution = execution.into_result()?;

    // Finally wait the result:
    let returned_resp: SignatureResponse = execution.json()?;
    assert_eq!(
        returned_resp, respond_resp,
        "Returned signature request does not match"
    );

    let new_balance = alice.view_account().await?.balance;
    let new_contract_balance = contract.view_account().await?.balance;
    assert!(
        balance.as_millinear() - new_balance.as_millinear() < 10,
        "refund should happen"
    );
    println!(
        "{} {} {} {}",
        balance.as_millinear(),
        new_balance.as_millinear(),
        contract_balance.as_millinear(),
        new_contract_balance.as_millinear(),
    );
    assert!(
        contract_balance.as_millinear() - new_contract_balance.as_millinear() < 20,
        "respond should take less than 0.02 NEAR"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_fail_refund() -> anyhow::Result<()> {
    let (worker, contract, _, sk) = init_env().await;
    let alice = worker.dev_create_account().await?;
    let balance = alice.view_account().await?.balance;
    let contract_balance = contract.view_account().await?.balance;
    let path = "test";

    let msg = "hello world!";
    println!("submitting: {msg}");
    let (payload_hash, _, _) = create_response(alice.id(), msg, path, &sk).await;
    let request = SignRequest {
        payload: payload_hash,
        path: path.into(),
        key_version: 0,
    };

    let status = alice
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_near(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // we do not respond, sign will fail due to timeout
    let execution = status.await;
    dbg!(&execution);
    let err = execution
        .unwrap()
        .into_result()
        .expect_err("should have failed with timeout");
    assert!(err
        .to_string()
        .contains(&errors::SignError::Timeout.to_string()));

    let new_balance = alice.view_account().await?.balance;
    let new_contract_balance = contract.view_account().await?.balance;
    println!(
        "{} {} {} {}",
        balance.as_millinear(),
        new_balance.as_millinear(),
        contract_balance.as_yoctonear(),
        new_contract_balance.as_yoctonear(),
    );
    assert!(
        balance.as_millinear() - new_balance.as_millinear() < 10,
        "refund should happen"
    );
    assert!(
        contract_balance.as_millinear() - new_contract_balance.as_millinear() <= 1,
        "refund transfer should take less than 0.001 NEAR"
    );

    Ok(())
}

#[tokio::test]
async fn test_contract_sign_request_deposits() -> anyhow::Result<()> {
    let (_, contract, _, sk) = init_env().await;
    let predecessor_id = contract.id();
    let path = "testing-no-deposit";

    // Try to sign with no deposit, should fail.
    let msg = "without-deposit";
    let (payload_hash, respond_req, respond_resp) =
        create_response(predecessor_id, msg, path, &sk).await;
    let request = SignRequest {
        payload: payload_hash,
        path: path.into(),
        key_version: 0,
    };

    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    // Responding to the request should fail with missing request because the deposit is too low,
    // so the request should have never made it into the request queue and subsequently the MPC network.
    let respond = contract
        .call("respond")
        .args_json(serde_json::json!({
            "request": respond_req,
            "response": respond_resp
        }))
        .max_gas()
        .transact()
        .await?;
    dbg!(&respond);
    assert!(respond
        .into_result()
        .unwrap_err()
        .to_string()
        .contains(&errors::InvalidParameters::RequestNotFound.to_string()));

    let execution = status.await?;
    dbg!(&execution);
    assert!(execution
        .into_result()
        .unwrap_err()
        .to_string()
        .contains(&errors::InvalidParameters::InsufficientDeposit.to_string()));

    Ok(())
}

#[tokio::test]
async fn test_contract_initialization() -> anyhow::Result<()> {
    let (_, contract) = init().await;

    // Empty candidates should fail.
    let participants = Participants::new();
    let threshold = Threshold::new(0);
    let proposed_threshold_parameters: ThresholdParameters =
        unsafe { mem::transmute((participants, threshold)) };
    let key_event_threshold = DKGThreshold::new(0);
    let key_state_proposal: KeyStateProposal =
        unsafe { mem::transmute((proposed_threshold_parameters, key_event_threshold)) };
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "key_state_proposal": key_state_proposal,
            "init_config": None::<InitConfig>,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with zero candidates or less than threshold candidates should fail"
    );

    let key_state_proposal = contruct_valid_key_state_proposal(&candidates(None)).await;
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "key_state_proposal": key_state_proposal,
            "init_config": None::<InitConfig>,
        }))
        .transact()
        .await?;
    assert!(
        result.is_success(),
        "initializing with valid candidates should succeed"
    );

    // Reinitializing after the first successful initialization should fail.
    let result = contract
        .call("init")
        .args_json(serde_json::json!({
            "key_state_proposal": key_state_proposal,
            "init_config": None::<InitConfig>,
        }))
        .transact()
        .await?;
    assert!(
        result.is_failure(),
        "initializing with valid candidates again should fail"
    );

    Ok(())
}
