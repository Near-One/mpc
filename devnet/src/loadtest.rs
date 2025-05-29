#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::{OperatingAccessKey, OperatingAccounts};
use crate::cli::{
    DeployParallelSignContractCmd, NewLoadtestCmd, RunLoadtestCmd, UpdateLoadtestCmd,
};
use crate::constants::{DEFAULT_PARALLEL_SIGN_CONTRACT_PATH, ONE_NEAR};
use crate::contracts::{
    make_legacy_sign_action, make_parallel_sign_call_action, make_sign_action, ActionCall,
};
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::mpc::read_contract_state_v2;
use crate::rpc::NearRpcClients;
use crate::types::{LoadtestSetup, NearAccount, ParsedConfig};
use anyhow::anyhow;
use futures::future::BoxFuture;
use futures::FutureExt;
use near_jsonrpc_client::errors::JsonRpcError;
use near_jsonrpc_client::methods;
use near_jsonrpc_client::methods::tx::{RpcTransactionError, RpcTransactionResponse};
use near_primitives::transaction::SignedTransaction;
use near_primitives::views::{FinalExecutionStatus, TxExecutionStatus};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
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
                mpc_contract::state::ProtocolContractState::Resharing(state) => state
                    .previous_running_state
                    .domains
                    .domains()
                    .iter()
                    .find(|domain| domain.id.0 == domain_id)
                    .cloned(),
                _ => {
                    panic!("MPC network is not running or resharing");
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
        let rpc_clone = config.rpc.clone();

        let actions: ActionCall = if let Some(signatures_per_contract_call) =
            self.signatures_per_contract_call
        {
            let parallel_sign_contract = loadtest_setup.parallel_signatures_contract.clone().expect(
                "Signatures per contract call specified, but no parallel signatures contract is deployed");
            let actions = make_parallel_sign_call_action(
                parallel_sign_contract,
                mpc_account,
                domain_config.clone().expect("require domain"),
                signatures_per_contract_call as u64,
            );
            actions
        } else if let Some(domain_config) = &domain_config {
            make_sign_action(mpc_account, domain_config.clone())
        } else {
            make_legacy_sign_action(mpc_account)
        };
        let sender: LoadSenderAsyncFn<TxRpcResponse> =
            Arc::new(move |key: &mut OperatingAccessKey| {
                let actions = actions.clone();
                let rpc_clone = rpc_clone.clone();
                async move {
                    let signed_tx = key.sign_tx_from_actions(actions).await;
                    let request = methods::send_tx::RpcSendTransactionRequest {
                        signed_transaction: signed_tx.clone(),
                        wait_until: near_primitives::views::TxExecutionStatus::Included,
                    };
                    TxRpcResponse {
                        rpc_response: rpc_clone.submit(request).await,
                        signed_tx,
                    }
                }
                .boxed()
            });

        let rpc_clone = config.rpc.clone();
        tokio::spawn(async move {
            let mut txs: Vec<SignedTransaction> = Vec::new();
            while let Some(x) = tx_receiver.recv().await {
                txs.push(x);
            }

            let n_txs = txs.len();
            let mut failed = 0;
            for tx in txs {
                let request = methods::EXPERIMENTAL_tx_status::RpcTransactionStatusRequest {
                    transaction_info:
                        methods::EXPERIMENTAL_tx_status::TransactionInfo::Transaction(near_jsonrpc_primitives::types::transactions::SignedTransaction::SignedTransaction(tx)) ,
                    wait_until: TxExecutionStatus::Final,
                };
                let res = rpc_clone.submit(request).await.unwrap();
                let Some(res) = res.final_execution_outcome else {
                    failed += 1;
                    continue;
                };
                let FinalExecutionStatus::SuccessValue(sig) = res.into_outcome().status else {
                    failed += 1;
                    continue;
                };
                // todo: verify signature
                println!("{:?}", sig);
                // adjust sleep time to not owerwhelm rpc node
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            println!(
                "{} / {} signatures failed. Success Rate: {}",
                failed,
                n_txs,
                (n_txs - failed) as f64 / n_txs as f64
            );
        });
        // alternatively, timeout here?
        send_load(keys, tx_per_sec, sender).await;
    }
}

pub struct TxRpcResponse {
    pub rpc_response: Result<RpcTransactionResponse, JsonRpcError<RpcTransactionError>>,
    pub signed_tx: SignedTransaction,
}

type LoadSenderAsyncFn<R> =
    Arc<dyn for<'a> Fn(&'a mut OperatingAccessKey) -> BoxFuture<'a, R> + Send + Sync + 'static>;

/// Send parallel load up to the given QPS (may fluctuate within a second),
/// using the sender function. The sender function will only be executed once at a time for each
/// access key, so enough access keys would be needed to saturate the QPS.
/// Also, the rpc client will internally apply rate limits, so that's another possible bottleneck.
async fn send_load<R: 'static>(
    keys: Vec<OwnedMutexGuard<OperatingAccessKey>>,
    qps: f64,
    sender: LoadSenderAsyncFn<R>,
) {
    let (tx_sender, mut tx_receiver): (Sender<SignedTransaction>, Receiver<SignedTransaction>) =
        tokio::sync::mpsc::channel(500);
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
