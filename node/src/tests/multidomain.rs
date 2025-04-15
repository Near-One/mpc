use crate::p2p::testing::PortSeed;
use crate::tests::{request_signature_and_await_response, IntegrationTestSetup};
use crate::tracking::AutoAbortTask;
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use near_o11y::testonly::init_integration_logger;
use near_time::Clock;
use serial_test::serial;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test]
#[serial]
async fn test_basic_multidomain() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
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
        PortSeed::BASIC_MULTIDOMAIN_TEST,
    );

    let mut domains = vec![
        DomainConfig {
            id: DomainId(0),
            scheme: SignatureScheme::Ed25519,
        },
        DomainConfig {
            id: DomainId(1),
            scheme: SignatureScheme::Ed25519,
        },
    ];

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.initialize(setup.participants.clone());
        contract.add_domains(domains.clone());
    }

    let _runs = setup
        .configs
        .into_iter()
        .map(|config| AutoAbortTask::from(tokio::spawn(config.run())))
        .collect::<Vec<_>>();

    for domain in &domains {
        assert!(request_signature_and_await_response(
            &mut setup.indexer,
            &format!("user{}", domain.id.0),
            domain,
            std::time::Duration::from_secs(60)
        )
        .await
        .is_some());
    }

    {
        let new_domains = vec![
            DomainConfig {
                id: DomainId(2),
                scheme: SignatureScheme::Ed25519,
            },
            DomainConfig {
                id: DomainId(3),
                scheme: SignatureScheme::Ed25519,
            },
        ];
        let mut contract = setup.indexer.contract_mut().await;
        contract.add_domains(new_domains.clone());
        domains.extend(new_domains);
    }

    for domain in &domains {
        assert!(request_signature_and_await_response(
            &mut setup.indexer,
            &format!("user{}", domain.id.0),
            domain,
            std::time::Duration::from_secs(60)
        )
        .await
        .is_some());
    }

    {
        let mut contract = setup.indexer.contract_mut().await;
        contract.start_resharing(setup.participants);
    }

    for domain in &domains {
        assert!(request_signature_and_await_response(
            &mut setup.indexer,
            &format!("user{}", domain.id.0),
            domain,
            std::time::Duration::from_secs(60)
        )
        .await
        .is_some());
    }
}
