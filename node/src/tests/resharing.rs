use crate::indexer::participants::ContractState;
use crate::metrics;
use crate::p2p::testing::PortSeed;
use crate::tests::{request_signature_and_await_response, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
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

    setup
        .indexer
        .contract_mut()
        .await
        .initialize(initial_participants);

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
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
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}

// Test two nodes joining and two old nodes leaving.
#[tokio::test]
#[serial]
async fn test_key_resharing_multistage() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 6;
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
        PortSeed::KEY_RESHARING_MULTISTAGE_TEST,
    );

    // Initialize the contract with two fewer participants.
    let mut participants_1 = setup.participants.clone();
    participants_1.participants.pop();
    participants_1.participants.pop();

    setup
        .indexer
        .contract_mut()
        .await
        .initialize(participants_1);

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    // Sanity check.
    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
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
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the first node quit.
    let mut participants_3 = setup.participants.clone();
    participants_3.participants.remove(0);
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
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());

    // Have the second node quit.
    let mut participants_4 = setup.participants.clone();
    participants_4.participants.remove(0);
    participants_4.participants.remove(0);
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
        std::time::Duration::from_secs(60)
    )
    .await
    .is_some());
}

// Test that signatures buffered during resharing are not lost.
#[tokio::test]
#[serial]
async fn test_key_resharing_signature_buffering() {
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

    // Initialize the contract with one fewer participant.
    let mut initial_participants = setup.participants.clone();
    initial_participants.participants.pop();

    setup
        .indexer
        .contract_mut()
        .await
        .initialize(initial_participants);

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    let response_time = request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
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
    assert!(
        request_signature_and_await_response(&mut setup.indexer, "user1", response_time * 2)
            .await
            .is_none()
    );

    // Re-enable the node. Now we should get the signature response.
    drop(disabled);
    timeout(response_time * 2, setup.indexer.next_response())
        .await
        .expect("Timeout waiting for signature response");
}
