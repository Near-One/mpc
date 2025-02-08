use std::collections::{HashMap, HashSet};

use crate::cli::Cli;
use crate::config::load_config_file;
use crate::tests::free_resources_after_shutdown;
use crate::tracking::AutoAbortTask;
use near_o11y::testonly::init_integration_logger;
use rand::Rng;
use serial_test::serial;

struct DebugResponse {
    success: bool,
    debug: String,
    text: String,
}

async fn send_request(request_url: &str, index: usize) -> Result<DebugResponse, anyhow::Error> {
    let url = format!("http://{}:{}/{}", "127.0.0.1", 23000 + index, request_url);
    let response = reqwest::get(&url).await?;
    let response_success = response.status().is_success();
    let response_debug = format!("{:?}", response);
    let response_text = response.text().await.unwrap_or_default();
    Ok(DebugResponse {
        success: response_success,
        debug: response_debug,
        text: response_text,
    })
}

// Make a cluster of four nodes. Test the following:
// 1. Shut down one node and confirms that signatures can still be generated.
// 2. Stop another node and assert that no signatures can be generated.
// 3. Restart the node that was later shutdown and assert that signatures can be generated again
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_faulty_cluster() {
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
        seed: Some(3),
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
    let mut normal_runs = (0..NUM_PARTICIPANTS)
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
            (i, AutoAbortTask::from(tokio::spawn(cli.run())))
        })
        .collect::<HashMap<_, _>>();

    // First ask the nodes to "index" the signature requests

    let mut retries_left = 20;
    'outer: for i in 0..NUM_PARTICIPANTS {
        while retries_left > 0 {
            match send_request("debug/index?msg=hello&repeat=1&seed=23", i).await {
                Ok(response) => {
                    if response.success {
                        tracing::info!("Got response from node {}: {}", i, response.text);
                        continue 'outer;
                    } else {
                        tracing::error!(
                            "Unsuccessful response from node {}: {}, error: {}",
                            i,
                            response.debug,
                            response.text
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        retries_left -= 1;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to get response from node {}: {}", i, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    retries_left -= 1;
                    continue;
                }
            }
        }
        panic!("Failed to get response from node {}", i);
    }

    tracing::info!("Requests indexed");

    // First step: drop one node, and make sure we can still get a signature.

    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..NUM_PARTICIPANTS);
    let to_drop = normal_runs.remove(&index).unwrap();
    drop(to_drop);
    let mut dropped_indices = HashSet::new();
    dropped_indices.insert(index);

    free_resources_after_shutdown(&configs[index]).await;

    let mut signature_generated = false;
    'outer: for _ in 0..2 {
        for i in 0..NUM_PARTICIPANTS {
            match send_request("debug/sign?repeat=1&seed=23", i).await {
                Ok(response) => {
                    if response.success {
                        tracing::info!("Got response from node {}: {}", i, response.text);
                        signature_generated = true;
                        break 'outer;
                    } else {
                        tracing::error!(
                            "Unsuccessful response from node {}: {}, error: {}",
                            i,
                            response.debug,
                            response.text
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to get response from node {}: {}", i, e);
                    continue;
                }
            }
        }
    }

    if !signature_generated {
        panic!("Failed to get response from any node");
    }

    tracing::info!("Step 1 complete");

    // Second step: drop another node, and make sure signatures cannot be generated

    let another_index = loop {
        let i = rng.gen_range(0..NUM_PARTICIPANTS);
        if !dropped_indices.contains(&i) {
            break i;
        }
    };
    drop(normal_runs.remove(&another_index).unwrap());
    dropped_indices.insert(another_index);
    free_resources_after_shutdown(&configs[another_index]).await;

    let index = loop {
        let i = rng.gen_range(0..NUM_PARTICIPANTS);
        if !dropped_indices.contains(&i) {
            break i;
        }
    };

    match send_request("debug/sign?repeat=1&seed=23&timeout=30", index).await {
        Ok(response) => {
            let response_success = response.success;
            let response_debug = response.debug;
            let response_text = response.text;
            if !response_success {
                tracing::info!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    index,
                    response_debug,
                    response_text
                );
            } else {
                panic!(
                    "Got response from node {} unexpectedly: {}",
                    index, response_text
                );
            }
        }
        Err(e) => {
            tracing::info!("Failed to get response from node {}: {}", index, e);
        }
    }

    tracing::info!("Step 2 complete");

    // Third step: bring up the dropped node in step 2, and make sure signatures can be generated again

    let task = AutoAbortTask::from(tokio::spawn(async move {
        let home_dir = temp_dir.path().join(format!("{}", another_index));
        let cli = Cli::Start {
            home_dir: home_dir.to_str().unwrap().to_string(),
            secret_store_key_hex: hex::encode(encryption_keys[another_index]),
            p2p_private_key: std::fs::read_to_string(home_dir.join("p2p_key"))
                .unwrap()
                .parse()
                .unwrap(),
            account_secret_key: None,
            root_keyshare: None,
        };
        cli.run().await.unwrap();
    }));
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    match send_request("debug/index?msg=hello&repeat=1&seed=23", another_index).await {
        Ok(response) => {
            if !response.success {
                panic!(
                    "Unsuccessful response from node {}: {}, error: {}",
                    another_index, response.debug, response.text
                );
            }
        }
        Err(e) => {
            panic!("Failed to get response from node {}: {}", another_index, e);
        }
    }

    tracing::info!("Step 3 complete");

    drop(task);
    drop(normal_runs);

    for config in &configs {
        free_resources_after_shutdown(config).await;
    }
}
