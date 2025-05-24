pub mod common;

use common::{check_call_success, gen_accounts, init_env_secp256k1};
use mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters};
use mpc_contract::state::running::RunningContractState;
use mpc_contract::state::ProtocolContractState;
use near_sdk::PublicKey;
use serde_json::json;
use std::str::FromStr;

#[tokio::test]
async fn test_keygen() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let args = json!({
        "domains": vec![
            json!({
                "id": 2,
                "scheme": "Ed25519",
            })
        ]
    });
    for i in [0, 1, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_add_domains")
                .args_json(args.clone())
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in initializing state"),
    };

    check_call_success(
        accounts[0]
            .call(contract.id(), "start_keygen_instance")
            .args_json(json!({
                "key_event_id": {
                    "epoch_id": 5,
                    "domain_id": 2,
                    "attempt_id": 0,
                },
            }))
            .transact()
            .await?,
    );

    let pk = PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();
    let vote_pk_args = json!( {
        "key_event_id": {
            "epoch_id": 5,
            "domain_id": 2,
            "attempt_id": 0,
        },
        "public_key": pk,
    });

    for account in &accounts[0..3] {
        check_call_success(
            account
                .call(contract.id(), "vote_pk")
                .args_json(vote_pk_args.clone())
                .transact()
                .await?,
        );
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.keyset.epoch_id.get(), 5); // we started with 5, should not change.
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_cancel_keygen() -> anyhow::Result<()> {
    let (_, contract, accounts, _) = init_env_secp256k1(1).await;

    let args = json!({
        "domains": vec![
            json!({
                "id": 2,
                "scheme": "Ed25519",
            })
        ]
    });
    for i in [0, 1, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_add_domains")
                .args_json(args.clone())
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Initializing(state) => {
            assert_eq!(state.domains.domains().len(), 2);
        }
        _ => panic!("should be in initializing state"),
    };

    for i in [0, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_cancel_keygen")
                .args_json(json!({
                    "next_domain_id": 3,
                }))
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json().unwrap();
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.keyset.epoch_id.get(), 5); // we started with 5, should not change.
            assert_eq!(state.domains.domains().len(), 1);
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_resharing() -> anyhow::Result<()> {
    let (worker, contract, mut accounts, _) = init_env_secp256k1(1).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let existing_params = match state {
        ProtocolContractState::Running(state) => state.parameters,
        _ => panic!("should be in running state"),
    };
    let mut new_participants = existing_params.participants().clone();
    let (acc, p) = gen_accounts(&worker, 1).await;
    let new_p = p.participants().first().unwrap().clone();
    new_participants.insert(new_p.0.clone(), new_p.2).unwrap();
    accounts.push(acc[0].clone());
    let proposal = ThresholdParameters::new(new_participants, Threshold::new(3)).unwrap();

    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": 6,
                    "proposal": proposal,
                }))
                .transact()
                .await?,
        );
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Running(RunningContractState {
            resharing_process: Some(resharing_process),
            ..
        }) => {
            assert_eq!(
                resharing_process.resharing_key.proposed_parameters(),
                &proposal
            );
        }
        _ => panic!("should be in running state."),
    }

    check_call_success(
        accounts[0]
            .call(contract.id(), "start_reshare_instance")
            .args_json(json!({
                "key_event_id": {
                    "epoch_id": 6,
                    "domain_id": 0,
                    "attempt_id": 0,
                },
            }))
            .transact()
            .await?,
    );

    let vote_reshared_args = json!( {
        "key_event_id": {
            "epoch_id": 6,
            "domain_id": 0,
            "attempt_id": 0,
        },
    });

    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_reshared")
                .args_json(vote_reshared_args.clone())
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Running(state) => {
            assert_eq!(state.parameters.participants().len(), 4);
            assert!(state.resharing_process.is_none());
            assert_eq!(state.keyset.epoch_id.get(), 6); // we started with 5.
        }
        _ => panic!("should be in running state"),
    };

    Ok(())
}

#[tokio::test]
async fn test_repropose_resharing() -> anyhow::Result<()> {
    let (worker, contract, mut accounts, _) = init_env_secp256k1(1).await;

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    let existing_params = match state {
        ProtocolContractState::Running(state) => state.parameters,
        _ => panic!("should be in running state"),
    };
    let mut new_participants = existing_params.participants().clone();
    let (acc, p) = gen_accounts(&worker, 1).await;
    let new_p = p.participants().first().unwrap().clone();
    new_participants.insert(new_p.0.clone(), new_p.2).unwrap();
    let proposal = ThresholdParameters::new(new_participants, Threshold::new(3)).unwrap();
    accounts.push(acc[0].clone());
    for account in &accounts {
        check_call_success(
            account
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": 6,
                    "proposal": proposal,
                }))
                .transact()
                .await?,
        );
    }
    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Running(RunningContractState {
            resharing_process: Some(resharing_process),
            ..
        }) => {
            assert_eq!(
                resharing_process.resharing_key.proposed_parameters(),
                &proposal
            );
        }
        _ => panic!("should be in resharing state"),
    }

    for i in [0, 1, 2] {
        check_call_success(
            accounts[i]
                .call(contract.id(), "vote_new_parameters")
                .args_json(json!({
                    "prospective_epoch_id": 7,
                    "proposal": existing_params,
                }))
                .transact()
                .await?,
        );
    }

    let state: ProtocolContractState = contract.view("state").await.unwrap().json()?;
    match state {
        ProtocolContractState::Running(RunningContractState {
            resharing_process: Some(resharing_process),
            ..
        }) => {
            assert_eq!(
                resharing_process
                    .resharing_key
                    .proposed_parameters()
                    .participants()
                    .len(),
                3
            );
            assert_eq!(resharing_process.resharing_key.epoch_id().get(), 7); // we started with 5.
        }
        _ => panic!("should be in resharing state"),
    };
    Ok(())
}
