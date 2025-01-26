use crate::indexer::participants::ContractState;
use crate::tests::{generate_test_configs_with_fake_indexer, request_signature_and_await_response};
use crate::tracking::AutoAbortTask;
use near_o11y::testonly::init_integration_logger;
use near_sdk::AccountId;
use near_time::{Clock, Duration};
use rand::Rng;
use serial_test::serial;

// Make a cluster of four nodes. Test the following:
// 1. Shut down one node and confirms that signatures can still be generated.
// 2. Stop another node and assert that no signatures can be generated.
// 3. Restart the node that was later shutdown and assert that signatures can be generated again
#[tokio::test]
#[serial]
async fn test_faulty_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY: Duration = Duration::seconds(1);
    const PORT_SEED: u16 = 3;
    let temp_dir = tempfile::tempdir().unwrap();
    let accounts = (0..NUM_PARTICIPANTS)
        .map(|i| format!("test{}", i).parse().unwrap())
        .collect::<Vec<AccountId>>();
    let (mut indexer, configs) = generate_test_configs_with_fake_indexer(
        Clock::real(),
        temp_dir.path(),
        accounts.clone(),
        THRESHOLD,
        TXN_DELAY,
        PORT_SEED,
    );

    let _runs = configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    tracing::info!("Waiting for key generation to complete");
    indexer
        .wait_for_contract_state(|state| matches!(state, ContractState::Running(_)))
        .await;
    tracing::info!("Key generation complete");

    let Some(signature_delay) = request_signature_and_await_response(
        &mut indexer,
        "user0",
        std::time::Duration::from_secs(60),
    )
    .await
    else {
        panic!("Timed out generating the first signature");
    };

    // first step: drop one node, and make sure signatures can still be generated
    let mut rng = rand::thread_rng();
    let to_drop: usize = rng.gen_range(0..NUM_PARTICIPANTS);
    tracing::info!("Bringing down one node #{}", to_drop);
    let disabled1 = indexer.disable(accounts[to_drop].clone()).await;
    assert!(
        request_signature_and_await_response(&mut indexer, "user1", signature_delay * 2)
            .await
            .is_some()
    );
    tracing::info!("Step 1 complete");

    // Second step: drop another node, and make sure signatures cannot be generated
    let another_to_drop = loop {
        let i = rng.gen_range(0..NUM_PARTICIPANTS);
        if i != to_drop {
            break i;
        }
    };
    tracing::info!("Bringing down another node #{}", another_to_drop);
    let disabled2 = indexer.disable(accounts[another_to_drop].clone()).await;
    assert!(
        request_signature_and_await_response(&mut indexer, "user2", signature_delay * 2)
            .await
            .is_none()
    );
    tracing::info!("Step 2 complete");

    // Third step: bring up the dropped node in step 2, and make sure signatures can be generated again
    drop(disabled2);
    assert!(
        request_signature_and_await_response(&mut indexer, "user3", signature_delay * 2)
            .await
            .is_some()
    );
    tracing::info!("Step 3 complete");

    drop(disabled1);
}
