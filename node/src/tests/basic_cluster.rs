use crate::cli::Cli;
use crate::config::load_config_file;
use crate::tests::free_resources_after_shutdown;
use crate::tracking::AutoAbortTask;
use near_o11y::testonly::init_integration_logger;
use serial_test::serial;

// Make a cluster of four nodes, test that we can generate keyshares
// and then produce signatures.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_basic_cluster() {
    init_integration_logger();
    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    let temp_dir = tempfile::tempdir().unwrap();
    let generate_configs = Cli::GenerateTestConfigs {
        output_dir: temp_dir.path().to_str().unwrap().to_string(),
        participants: (0..NUM_PARTICIPANTS)
            .map(|i| format!("test{}", i).parse().unwrap())
            .collect(),
        threshold: THRESHOLD,
        seed: Some(2),
        disable_indexer: true,
    };
    generate_configs.run().await.unwrap();

    let configs = (0..NUM_PARTICIPANTS)
        .map(|i| load_config_file(&temp_dir.path().join(format!("{}", i))).unwrap())
        .collect::<Vec<_>>();

    let encryption_keys = (0..NUM_PARTICIPANTS)
        .map(|_| rand::random::<[u8; 16]>())
        .collect::<Vec<_>>();

    // First, generate keys. All nodes run key generation until they exit.
    let key_generation_runs = (0..NUM_PARTICIPANTS)
        .map(|i| {
            let home_dir = temp_dir.path().join(format!("{}", i));
            let cli = Cli::GenerateKeyEcdsa {
                home_dir: home_dir.to_str().unwrap().to_string(),
                secret_store_key_hex: hex::encode(encryption_keys[i]),
                p2p_private_key: std::fs::read_to_string(home_dir.join("p2p_key"))
                    .unwrap()
                    .parse()
                    .unwrap(),
            };
            cli.run()
        })
        .collect::<Vec<_>>();

    futures::future::try_join_all(key_generation_runs)
        .await
        .unwrap();

    // Release the ports.
    for config in &configs {
        free_resources_after_shutdown(config).await;
    }

    tracing::info!("Key generation complete. Starting normal runs...");

    // We'll bring up the nodes in normal mode, and issue signature
    // requests, and check that they can be completed.
    let normal_runs = (0..NUM_PARTICIPANTS)
        .map(|i| {
            let home_dir = temp_dir.path().join(format!("{}", i));
            let cli = Cli::Start {
                home_dir: home_dir.to_str().unwrap().to_string(),
                secret_store_key_hex: hex::encode(encryption_keys[i]),
                p2p_private_key: std::fs::read_to_string(home_dir.join("p2p_key"))
                    .unwrap()
                    .parse()
                    .unwrap(),
                account_secret_key: None,
                root_keyshare: None,
            };
            AutoAbortTask::from(tokio::spawn(cli.run()))
        })
        .collect::<Vec<_>>();

    // First ask the nodes to "index" the signature requests
    let mut retries_left = 20;
    'outer: for i in 0..NUM_PARTICIPANTS {
        while retries_left > 0 {
            let url = format!(
                "http://{}:{}/debug/index?msg=hello&repeat=10&seed=23",
                "127.0.0.1",
                22000 + i
            );
            let response = match reqwest::get(&url).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!("Failed to get response from node {}: {}", i, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
            let response_success = response.status().is_success();
            let response_debug = format!("{:?}", response);
            let response_text = response.text().await.unwrap_or_default();
            if !response_success {
                tracing::error!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    i,
                    response_debug,
                    response_text
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                retries_left -= 1;
            } else {
                tracing::info!("Got response from node {}: {}", i, response_text);
                continue 'outer;
            }
        }
        panic!("Failed to get response from node {}", i);
    }

    let mut retries_left = 20;
    'outer: for i in 0..NUM_PARTICIPANTS {
        while retries_left > 0 {
            let url = format!(
                "http://{}:{}/debug/sign?repeat=10&seed=23",
                "127.0.0.1",
                22000 + i
            );
            let response = match reqwest::get(&url).await {
                Ok(response) => response,
                Err(e) => {
                    tracing::error!("Failed to get response from node {}: {}", i, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    continue;
                }
            };
            let response_success = response.status().is_success();
            let response_debug = format!("{:?}", response);
            let response_text = response.text().await.unwrap_or_default();
            if !response_success {
                tracing::error!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    i,
                    response_debug,
                    response_text
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                retries_left -= 1;
            } else {
                tracing::info!("Got response from node {}: {}", i, response_text);
                continue 'outer;
            }
        }
        panic!("Failed to get response from node {}", i);
    }

    drop(normal_runs);
    for config in &configs {
        free_resources_after_shutdown(config).await;
    }
}
