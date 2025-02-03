use crate::p2p::testing::PortSeed;
use crate::tests::{request_signature_and_await_response, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
use near_o11y::testonly::init_integration_logger;
use near_time::{Clock, Duration};
use serial_test::serial;
use crate::primitives::KeyType;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
#[serial]
async fn test_basic_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const TXN_DELAY: Duration = Duration::seconds(1);
    let temp_dir = tempfile::tempdir().unwrap();
    let mut setup = IntegrationTestSetup::new(
        Clock::real(),
        temp_dir.path(),
        (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        THRESHOLD,
        TXN_DELAY,
        PortSeed::BASIC_CLUSTER_TEST,
    );
    setup
        .indexer
        .contract_mut()
        .await
        .initialize(setup.participants);

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        KeyType::SECP256K1,
        std::time::Duration::from_secs(60),
    )
        .await
        .is_some());

    assert!(request_signature_and_await_response(
        &mut setup.indexer,
        "user0",
        KeyType::ED25519,
        std::time::Duration::from_secs(60),
    )
        .await
        .is_some());
}
