#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::{OperatingAccessKey, OperatingAccounts};
use crate::cli::{
    DeployParallelSignContractCmd, DrainExpiredRequestsCmd, NewLoadtestCmd, RunLoadtestCmd,
    UpdateLoadtestCmd,
};
use crate::constants::{DEFAULT_PARALLEL_SIGN_CONTRACT_PATH, ONE_NEAR};
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::mpc::read_contract_state_v2;
use crate::types::{LoadtestSetup, NearAccount, ParsedConfig};
use futures::future::BoxFuture;
use futures::FutureExt;
use legacy_mpc_contract::primitives::SignRequest;
use mpc_contract::primitives::domain::SignatureScheme;
use mpc_contract::primitives::signature::{Bytes, Payload, SignRequestArgs};
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_sdk::AccountId;
use rand::RngCore;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;

/// Bring the loadtest setup to the desired parameterization.
async fn update_loadtest_setup(
    name: &str,
    accounts: &mut OperatingAccounts,
    loadtest_setup: &mut LoadtestSetup,
    desired_num_accounts: usize,
    funding_account: Option<NearAccount>,
) {
    // First create any accounts we don't already have, and refill existing.
    let mut accounts_to_fund = Vec::new();
    for i in 0..desired_num_accounts {
        if let Some(account_id) = loadtest_setup.load_senders.get(i) {
            accounts_to_fund.push(AccountToFund::from_existing(
                account_id.clone(),
                loadtest_setup.desired_balance_per_account,
            ));
        } else {
            accounts_to_fund.push(AccountToFund::from_new(
                loadtest_setup.desired_balance_per_account,
                format!("loadtest-{}-{}-", i, name),
            ));
        }
    }
    let funded_accounts = fund_accounts(accounts, accounts_to_fund, funding_account).await;

    loadtest_setup.load_senders = funded_accounts.clone();

    // Ensure that each account has the desired number of access keys.
    let futs = accounts
        .accounts_mut(&funded_accounts)
        .into_values()
        .map(|account| account.ensure_have_n_access_keys(loadtest_setup.desired_keys_per_account))
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

impl NewLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to create loadtest setup {} with {} loadtest accounts, each with {} keys (total {} keys) and {} NEAR",
            name,
            self.num_accounts,
            self.keys_per_account,
            self.num_accounts * self.keys_per_account,
            self.near_per_account,
        );

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        if setup.loadtest_setups.contains_key(name) {
            panic!("Loadtest setup with name {} already exists", name);
        }
        let loadtest_setup = setup
            .loadtest_setups
            .entry(name.to_string())
            .or_insert(Default::default());

        loadtest_setup.desired_balance_per_account = self.near_per_account * ONE_NEAR;
        loadtest_setup.desired_keys_per_account = self.keys_per_account;

        update_loadtest_setup(
            name,
            &mut setup.accounts,
            loadtest_setup,
            self.num_accounts,
            config.funding_account,
        )
        .await;
    }
}

impl UpdateLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to update loadtest setup {}", name);

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get_mut(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));

        let desired_num_accounts = self
            .num_accounts
            .unwrap_or(loadtest_setup.load_senders.len());
        if let Some(keys_per_account) = self.keys_per_account {
            loadtest_setup.desired_keys_per_account = keys_per_account;
        }
        if let Some(near_per_account) = self.near_per_account {
            loadtest_setup.desired_balance_per_account = near_per_account * ONE_NEAR;
        }

        update_loadtest_setup(
            name,
            &mut setup.accounts,
            loadtest_setup,
            desired_num_accounts,
            config.funding_account,
        )
        .await;
    }
}

impl DeployParallelSignContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to deploy parallel sign contract for loadtest setup {}",
            name
        );
        let contract_path = self
            .path
            .clone()
            .unwrap_or(DEFAULT_PARALLEL_SIGN_CONTRACT_PATH.to_string());
        let contract_data = std::fs::read(&contract_path).unwrap();

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get_mut(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));

        if let Some(old_contract) = &loadtest_setup.parallel_signatures_contract {
            let old_contract = setup
                .accounts
                .account(old_contract)
                .get_contract_code()
                .await
                .unwrap_or_default();
            if old_contract == contract_data {
                println!("Contract code is the same, not deploying");
                return;
            }
            println!("Contract code is different, going to redeploy");
        }

        let contract_account_to_fund =
            if let Some(contract) = &loadtest_setup.parallel_signatures_contract {
                AccountToFund::ExistingAccount {
                    account_id: contract.clone(),
                    desired_balance: self.deposit_near * ONE_NEAR,
                    do_not_refill_above: 0,
                }
            } else {
                AccountToFund::from_new(self.deposit_near * ONE_NEAR, format!("par-sign-{}-", name))
            };
        let contract_account = fund_accounts(
            &mut setup.accounts,
            vec![contract_account_to_fund],
            config.funding_account,
        )
        .await
        .into_iter()
        .next()
        .unwrap();
        loadtest_setup.parallel_signatures_contract = Some(contract_account.clone());

        setup
            .accounts
            .account_mut(&contract_account)
            .deploy_contract(contract_data, &contract_path)
            .await;
    }
}

impl RunLoadtestCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));
        let mpc_setup = setup.mpc_setups.get(&self.mpc_network).expect(&format!(
            "MPC network with name {} does not exist",
            self.mpc_network
        ));
        let mpc_account = mpc_setup
            .contract
            .clone()
            .expect("MPC network does not have a contract");
        println!(
            "Going to run loadtest setup {} against MPC network {} (contract {}) at {} QPS",
            name, self.mpc_network, mpc_account, self.qps
        );

        let domain_config = if let Some(domain_id) = self.domain_id {
            let contract_state = read_contract_state_v2(&setup.accounts, &mpc_account).await;
            match contract_state {
                mpc_contract::state::ProtocolContractState::Running(state) => Some(
                    state
                        .domains
                        .domains()
                        .iter()
                        .find(|domain| domain.id.0 == domain_id)
                        .expect("no such domain")
                        .clone(),
                ),
                _ => {
                    panic!("MPC network is not running");
                }
            }
        } else {
            None
        };

        let mut keys = Vec::new();
        for account_id in &loadtest_setup.load_senders {
            let account = setup.accounts.account(account_id);
            keys.extend(account.all_access_keys().await);
        }

        let tx_per_sec =
            if let Some(signatures_per_contract_call) = self.signatures_per_contract_call {
                self.qps as f64 / signatures_per_contract_call as f64
            } else {
                self.qps as f64
            };
        if tx_per_sec > config.rpc.total_qps() as f64 {
            println!("WARNING: Transactions to send per second is {}, but the RPC servers are only capable of handling an aggregate of {} QPS",
                tx_per_sec, config.rpc.total_qps());
        }

        let sender: LoadSenderAsyncFn<RpcTransactionResponse> = if let Some(
            signatures_per_contract_call,
        ) =
            self.signatures_per_contract_call
        {
            let contract = loadtest_setup.parallel_signatures_contract.clone().expect(
                "Signatures per contract call specified, but no parallel signatures contract is deployed",
            );
            Arc::new(move |key: &mut OperatingAccessKey| {
                let contract = contract.clone();
                let mpc_contract = mpc_account.clone();
                let domain_config = domain_config.clone();
                async move {
                    let args = if let Some(domain_config) = domain_config {
                        let mut ecdsa_calls_by_domain = BTreeMap::new();
                        let mut eddsa_calls_by_domain = BTreeMap::new();
                        match domain_config.scheme {
                            SignatureScheme::Secp256k1 => {
                                ecdsa_calls_by_domain.insert(
                                    domain_config.id.0,
                                    signatures_per_contract_call as u64,
                                );
                            }
                            SignatureScheme::Ed25519 => {
                                eddsa_calls_by_domain.insert(
                                    domain_config.id.0,
                                    signatures_per_contract_call as u64,
                                );
                            }
                        }
                        serde_json::to_vec(&ParallelSignArgsV2 {
                            target_contract: mpc_contract,
                            ecdsa_calls_by_domain,
                            eddsa_calls_by_domain,
                            seed: rand::random(),
                        })
                        .unwrap()
                    } else {
                        serde_json::to_vec(&ParallelSignArgsV1 {
                            target_contract: mpc_contract,
                            num_calls: signatures_per_contract_call as u64,
                            seed: rand::random(),
                        })
                        .unwrap()
                    };

                    key.submit_tx_to_call_function(
                        &contract,
                        "make_parallel_sign_calls",
                        &args,
                        300,
                        1,
                        near_primitives::views::TxExecutionStatus::Included,
                        false,
                    )
                    .await
                }
                .boxed()
            })
        } else if let Some(domain_config) = domain_config {
            Arc::new(move |key: &mut OperatingAccessKey| {
                let mpc_contract = mpc_account.clone();
                let domain_config = domain_config.clone();
                async move {
                    let payload = match domain_config.scheme {
                        SignatureScheme::Secp256k1 => {
                            Payload::Ecdsa(Bytes::new(rand::random::<[u8; 32]>().to_vec()).unwrap())
                        }
                        SignatureScheme::Ed25519 => {
                            let len = rand::random_range(32..=1232);
                            let mut payload = vec![0; len];
                            rand::rng().fill_bytes(&mut payload);
                            Payload::Eddsa(Bytes::new(payload).unwrap())
                        }
                    };
                    key.submit_tx_to_call_function(
                        &mpc_contract,
                        "sign",
                        &serde_json::to_vec(&SignArgsV2 {
                            request: SignRequestArgs {
                                domain_id: Some(domain_config.id),
                                path: "".to_string(),
                                payload_v2: Some(payload),
                                ..Default::default()
                            },
                        })
                        .unwrap(),
                        10,
                        1,
                        near_primitives::views::TxExecutionStatus::Included,
                        false,
                    )
                    .await
                }
                .boxed()
            })
        } else {
            Arc::new(move |key: &mut OperatingAccessKey| {
                let mpc_contract = mpc_account.clone();
                async move {
                    key.submit_tx_to_call_function(
                        &mpc_contract,
                        "sign",
                        &serde_json::to_vec(&SignArgsV1 {
                            request: SignRequest {
                                key_version: 0,
                                path: "".to_string(),
                                payload: rand::random(),
                            },
                        })
                        .unwrap(),
                        30,
                        1,
                        near_primitives::views::TxExecutionStatus::Included,
                        false,
                    )
                    .await
                }
                .boxed()
            })
        };

        send_load(keys, tx_per_sec, sender).await;
    }
}

#[derive(Serialize)]
pub struct SignArgsV1 {
    pub request: SignRequest,
}

#[derive(Serialize)]
pub struct SignArgsV2 {
    pub request: SignRequestArgs,
}

impl DrainExpiredRequestsCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        let loadtest_setup = setup
            .loadtest_setups
            .get(name)
            .expect(&format!("Loadtest setup with name {} does not exist", name));
        let mpc_setup = setup.mpc_setups.get(&self.mpc_network).expect(&format!(
            "MPC network with name {} does not exist",
            self.mpc_network
        ));
        let mpc_account = mpc_setup
            .contract
            .clone()
            .expect("MPC network does not have a contract");
        println!(
            "Going to drain expired requests against MPC network {} (contract {}) at {} QPS",
            self.mpc_network, mpc_account, self.qps
        );

        let mut keys = Vec::new();
        for account_id in &loadtest_setup.load_senders {
            let account = setup.accounts.account(account_id);
            keys.extend(account.all_access_keys().await);
        }

        let sender: LoadSenderAsyncFn<()> = Arc::new(move |key: &mut OperatingAccessKey| {
            let mpc_contract = mpc_account.clone();
            async move {
                match key
                    .submit_tx_to_call_function(
                        &mpc_contract,
                        "remove_timed_out_requests",
                        &serde_json::to_vec(&RemoveTimedOutRequestsArgs {
                            max_num_to_remove: 20,
                        })
                        .unwrap(),
                        300,
                        0,
                        near_primitives::views::TxExecutionStatus::ExecutedOptimistic,
                        false,
                    )
                    .await
                {
                    Ok(result) => match result.final_execution_outcome {
                        Some(err) => match err.into_outcome().status {
                            near_primitives::views::FinalExecutionStatus::SuccessValue(value) => {
                                let value = String::from_utf8_lossy(&value).parse::<u32>().unwrap();
                                println!("Removed {} requests", value);
                                if value == 0 {
                                    println!("Done removing requests. Exiting.");
                                    std::process::exit(0);
                                }
                            }
                            status => {
                                println!("Error executing transaction: {:?}", status);
                            }
                        },
                        None => println!("Error executing transaction: no outcome"),
                    },
                    Err(err) => {
                        println!("Error sending transaction: {:?}", err);
                    }
                }
                Ok(())
            }
            .boxed()
        });
        send_load(keys, self.qps as f64, sender).await;
    }
}

#[derive(Serialize)]
struct RemoveTimedOutRequestsArgs {
    max_num_to_remove: u32,
}

type LoadSenderAsyncFn<R> = Arc<
    dyn for<'a> Fn(&'a mut OperatingAccessKey) -> BoxFuture<'a, anyhow::Result<R>>
        + Send
        + Sync
        + 'static,
>;

/// Send parallel load up to the given QPS (may fluctuate within a second),
/// using the sender function. The sender function will only be executed once at a time for each
/// access key, so enough access keys would be needed to saturate the QPS.
/// Also, the rpc client will internally apply rate limits, so that's another possible bottleneck.
async fn send_load<R: 'static>(
    keys: Vec<OwnedMutexGuard<OperatingAccessKey>>,
    qps: f64,
    sender: LoadSenderAsyncFn<R>,
) {
    let mut handles = Vec::new();
    let (permits_sender, permits_receiver) = flume::bounded(qps.ceil() as usize);
    let total_txns_sent = Arc::new(AtomicUsize::new(0));
    let total_errors = Arc::new(AtomicUsize::new(0));
    for mut key in keys {
        let permits_receiver = permits_receiver.clone();
        let total_txns_sent = total_txns_sent.clone();
        let total_errors = total_errors.clone();
        let sender = sender.clone();
        handles.push(tokio::spawn(async move {
            loop {
                permits_receiver.recv_async().await.unwrap();
                if let Err(e) = sender(&mut key).await {
                    total_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("Error sending transaction: {:?}", e);
                }
                total_txns_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    handles.push(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs_f64(1.0 / qps));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            permits_sender.send_async(()).await.unwrap();
        }
    }));

    let total_txns_sent = total_txns_sent.clone();
    let total_errors = total_errors.clone();
    handles.push(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_total = 0;
        let mut last_error_total = 0;
        loop {
            interval.tick().await;
            let txns_sent = total_txns_sent.load(std::sync::atomic::Ordering::Relaxed);
            let errors = total_errors.load(std::sync::atomic::Ordering::Relaxed);
            println!(
                "Sent {} transactions, {} errors ({} successful QPS)",
                txns_sent,
                errors,
                (txns_sent - last_total) - (errors - last_error_total)
            );
            last_total = txns_sent;
            last_error_total = errors;
        }
    }));
    futures::future::join_all(handles).await;
}

#[derive(Serialize)]
struct ParallelSignArgsV1 {
    target_contract: AccountId,
    num_calls: u64,
    seed: u64,
}

#[derive(Serialize)]
struct ParallelSignArgsV2 {
    target_contract: AccountId,
    ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    eddsa_calls_by_domain: BTreeMap<u64, u64>,
    seed: u64,
}
