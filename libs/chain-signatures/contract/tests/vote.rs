pub mod common;
use common::init_env;

use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};
use serde_json::json;

#[tokio::test]
async fn test_join() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let alice = worker.dev_create_account().await?;

    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;

    assert!(execution.is_success());

    let state: legacy_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        legacy_contract::ProtocolContractState::Running(r) => {
            assert!(r.candidates.contains_key(alice.id()));
        }
        _ => panic!("should be in running state"),
    };

    // try join again, still ok, because not become participant yet
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // participant try join again, should fail
    let execution = accounts[0]
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());
    Ok(())
}

#[tokio::test]
async fn test_vote_join() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // vote by first candidate should success, but vote not pass threshold yet
    let execution = accounts[0]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    // vote by candidate itself should fail
    let execution = alice
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // vote by second candidate should success, and vote pass threshold
    let execution = accounts[1]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    // another try to join should fail, because it's in Resharing state now
    let bob = worker.dev_create_account().await?;
    let execution = bob
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    Ok(())
}

#[tokio::test]
async fn test_vote_leave() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    let alice = worker.dev_create_account().await?;
    let bob = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    // now alice is candidate, bob is just a random account

    // alice should not have permission to vote leave
    let execution = alice
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // bob should not have permission to vote leave
    let execution = bob
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // participant should have permission to vote leave
    let execution = accounts[1]
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    let execution = accounts[2]
        .call(contract.id(), "vote_leave")
        .args_json(json!({
            "kick": accounts[0].id(),
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    let state: legacy_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        legacy_contract::ProtocolContractState::Resharing(r) => {
            assert!(!r
                .new_participants
                .participants
                .contains_key(accounts[0].id()));
        }
        _ => panic!("should be in resharing state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_vote_pk() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env().await;

    let key: String = contract.view("public_key").await.unwrap().json().unwrap();

    let execution = accounts[2]
        .call(contract.id(), "vote_pk")
        .args_json(json!({
            "public_key": key
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    let key2 = "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae";
    let execution = accounts[2]
        .call(contract.id(), "vote_pk")
        .args_json(json!({
            "public_key": key2
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    Ok(())
}

#[tokio::test]
async fn test_vote_reshare() -> anyhow::Result<()> {
    let (worker, contract, accounts, _) = init_env().await;

    // in running state, vote current epoch will fail
    let execution = accounts[2]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "key_event_id": KeyEventId::new(EpochId::new(0), AttemptId::new())
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    //// in running state, vote other epoch will fail
    //let execution = accounts[2]
    //    .call(contract.id(), "vote_reshared")
    //    .args_json(json!({
    //        "epoch": 1
    //    }))
    //    .transact()
    //    .await?;
    //assert!(execution.is_failure());

    // join a new candidate
    let alice = worker.dev_create_account().await?;
    let execution = alice
        .call(contract.id(), "join")
        .args_json(json!({
            "url": "127.0.0.1",
            "cipher_pk": vec![1u8; 32],
            "sign_pk": "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
        }))
        .transact()
        .await?;
    assert!(execution.is_success());

    // vote to make it participant
    let execution = accounts[0]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);
    let execution = accounts[1]
        .call(contract.id(), "vote_join")
        .args_json(json!({
            "candidate": alice.id()
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);
    let state: legacy_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        legacy_contract::ProtocolContractState::Resharing(r) => {
            assert!(r.new_participants.participants.contains_key(alice.id()));
        }
        _ => panic!("should be in resharing state"),
    };

    // now we can vote reshared:
    let execution = accounts[0]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(!vote_pass);

    // not participant cannot vote
    let bob = worker.dev_create_account().await?;
    let execution = bob
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    // new participant also cannot vote
    let execution = alice
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_failure());

    let execution = accounts[1]
        .call(contract.id(), "vote_reshared")
        .args_json(json!({
            "epoch": 1
        }))
        .transact()
        .await?;
    assert!(execution.is_success());
    let vote_pass: bool = execution.json().unwrap();
    assert!(vote_pass);

    let state: legacy_contract::ProtocolContractState =
        contract.view("state").await.unwrap().json().unwrap();
    match state {
        legacy_contract::ProtocolContractState::Running(r) => {
            assert!(r.epoch == 1);
            assert!(r.participants.contains_key(alice.id()));
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}
