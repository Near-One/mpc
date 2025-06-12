use crate::indexer::participants::ContractState;
use crate::metrics;
use crate::p2p::testing::PortSeed;
use crate::tests::{request_signature_and_await_response, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use serial_test::serial;
use tokio::time::timeout;

// Test a simple resharing of one node joining a cluster of 4 nodes.
#[tokio::test]
#[serial]
async fn test_key_resharing_simple() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::KEY_RESHARING_SIMPLE_TEST,
    );

    // Initialize the contract with one fewer participant.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants);

    timeout(
        std::time::Duration::from_secs(20),
        setup.indexer.wait_for_contract_state(|state| match state {
            ContractState::Running(running) => {
                running.keyset.epoch_id.get() == 1
                    && running.participants.participants.len() == NUM_PARTICIPANTS
            }
            _ => false,
        }),
    )
    .await
    .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}

// Tests that key resharing works, when new nodes join, and the nodes
// from the original set leave the network.
//
// Test scenario:
// 1. Setup network with 4 nodes.
// 2. Add 2 new nodes. Perform resharing.
// 3. Remove 2 nodes from the original participant set. Perform resharing.
// 4. Test that key resharing was successful by submitting the signature requests.
#[tokio::test]
#[serial]
async fn test_key_resharing_multistage() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 6;
    const THRESHOLD: usize = 4;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::KEY_RESHARING_MULTISTAGE_TEST,
    );

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Sanity check that requests work.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the fifth node join.
    let mut participants_2 = setup.participants.clone();
    participants_2.participants.pop();
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(participants_2);

    timeout(
        std::time::Duration::from_secs(20),
        setup.indexer.wait_for_contract_state(|state| match state {
            ContractState::Running(running) => {
                running.keyset.epoch_id.get() == 1
                    && running.participants.participants.len() == NUM_PARTICIPANTS - 1
            }
            _ => false,
        }),
    )
    .await
    .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the sixth node join.
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants.clone());
    timeout(
        std::time::Duration::from_secs(20),
        setup.indexer.wait_for_contract_state(|state| match state {
            ContractState::Running(running) => {
                running.keyset.epoch_id.get() == 2
                    && running.participants.participants.len() == NUM_PARTICIPANTS
            }
            _ => false,
        }),
    )
    .await
    .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user2",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the first node quit.
    let mut participants_3 = setup.participants.clone();
    participants_3.participants.remove(0);
    participants_3.threshold = 3;
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(participants_3);

    timeout(
        std::time::Duration::from_secs(20),
        setup.indexer.wait_for_contract_state(|state| match state {
            ContractState::Running(running) => {
                running.keyset.epoch_id.get() == 3
                    && running.participants.participants.len() == NUM_PARTICIPANTS - 1
            }
            _ => false,
        }),
    )
    .await
    .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the second node quit.
    let mut participants_4 = setup.participants.clone();
    participants_4.participants.remove(0);
    participants_4.participants.remove(0);
    participants_4.threshold = 3;
    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(participants_4);

    timeout(
        std::time::Duration::from_secs(20),
        setup.indexer.wait_for_contract_state(|state| match state {
            ContractState::Running(running) => {
                running.keyset.epoch_id.get() == 4
                    && running.participants.participants.len() == NUM_PARTICIPANTS - 2
            }
            _ => false,
        }),
    )
    .await
    .expect("Timeout waiting for resharing to complete");

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user1",
        &domain,
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}

/// Test that signatures during resharing
/// are also processed.
#[tokio::test]
#[serial]
async fn test_signature_requests_in_resharing_are_processed() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 5;
    const THRESHOLD: usize = 3;
    const TXN_DELAY_BLOCKS: u64 = 1;
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY_BLOCKS,
        PortSeed::KEY_RESHARING_SIGNATURE_BUFFERING_TEST,
    );

    let domain = DomainConfig {
        id: DomainId(0),
        scheme: SignatureScheme::Secp256k1,
    };

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(vec![domain.clone()]);
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    let response_time = request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        &domain,
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("Timed out generating the first signature");

    // Disable the last node to make resharing stall.
    let disabled = setup
        .indexer
        .disable(
            setup
                .participants
                .participants
                .last()
                .unwrap()
                .near_account_id
                .clone(),
        )
        .await;

    setup
        .indexer
        .contract_mut()
        .await
        .start_resharing(setup.participants);

    // Give nodes some time to transition into resharing state.
    for i in 0..20 {
        // We're running with [serial] so querying metrics should be OK.
        if let Ok(metric) =
            metrics::MPC_CURRENT_JOB_STATE.get_metric_with_label_values(&["Resharing"])
        {
            if metric.get() == NUM_PARTICIPANTS as i64 - 1 {
                break;
            }
        }
        if i == 19 {
            panic!("Timeout waiting for resharing to start");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Send a request for signature. This should timeout.
    request_signature_and_await_response(&mut setup.indexer, "user1", &domain, response_time * 2)
        .await
        .expect("Signature requests during resharing are processed.");

    // Re-enable the node. Now we should get the signature response.
    drop(disabled);

    // Give nodes some time to transition back to running state.
    // This is needed since we are dropping messages with current implementation.
    for i in 0..20 {
        // We're running with [serial] so querying metrics should be OK.
        if let Ok(metric) =
            metrics::MPC_CURRENT_JOB_STATE.get_metric_with_label_values(&["Running"])
        {
            if metric.get() == NUM_PARTICIPANTS as i64 {
                break;
            }
        }
        if i == 19 {
            panic!("Timeout waiting for running to start");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Send a request for signature. This should timeout.
    request_signature_and_await_response(&mut setup.indexer, "user1", &domain, response_time * 2)
        .await
        .expect("Signature request in running should be processed.");
}
