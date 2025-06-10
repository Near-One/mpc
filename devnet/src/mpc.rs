#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::{OperatingAccount, OperatingAccounts};
use crate::cli::{
    ListMpcCmd, MpcDeployContractCmd, MpcDescribeCmd, MpcProposeUpdateContractCmd,
    MpcViewContractCmd, MpcVoteAddDomainsCmd, MpcVoteNewParametersCmd, MpcVoteUpdateCmd,
    NewMpcNetworkCmd, RemoveContractCmd, UpdateMpcNetworkCmd,
};
use crate::constants::{ONE_NEAR, TESTNET_CONTRACT_ACCOUNT_ID};
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::queries;
use crate::tx::IntoReturnValueExt;
use crate::types::{MpcNetworkSetup, MpcParticipantSetup, NearAccount, ParsedConfig};
use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::{
    config::InitConfig,
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::EpochId,
        participants::{ParticipantInfo, Participants},
        thresholds::{Threshold, ThresholdParameters},
    },
    state::ProtocolContractState,
    utils::protocol_state_to_string,
};
use near_crypto::SecretKey;
use near_sdk::{borsh, AccountId};
use serde::Serialize;
use std::str::FromStr;

impl ListMpcCmd {
    pub async fn run(&self, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setups = &setup.mpc_setups;
        for (name, setup) in mpc_setups {
            println!("{}: {}", name, setup);
        }
    }
}

/// Bring the MPC network up to the desired parameterization.
async fn update_mpc_network(
    name: &str,
    accounts: &mut OperatingAccounts,
    mpc_setup: &mut MpcNetworkSetup,
    desired_num_participants: usize,
    funding_account: Option<NearAccount>,
) {
    if desired_num_participants < mpc_setup.participants.len() {
        panic!(
            "Cannot reduce number of participants from {} to {}",
            mpc_setup.participants.len(),
            desired_num_participants
        );
    }

    // Create new participants as needed and refill existing participants' balances.
    // For each participant we maintain two accounts: the MPC account, and the responding account.
    let mut accounts_to_fund = Vec::new();
    for i in 0..desired_num_participants {
        if let Some(account_id) = mpc_setup.participants.get(i) {
            accounts_to_fund.push(AccountToFund::from_existing(
                account_id.clone(),
                mpc_setup.desired_balance_per_account,
            ));
            let participant = accounts
                .account(account_id)
                .get_mpc_participant()
                // We could recover from this, but that's too much work.
                .expect("Participant account is not marked as MPC participant");
            accounts_to_fund.push(AccountToFund::from_existing(
                participant.responding_account_id.clone(),
                mpc_setup.desired_balance_per_responding_account,
            ));
        } else {
            accounts_to_fund.push(AccountToFund::from_new(
                mpc_setup.desired_balance_per_account,
                format!("mpc-{}-{}-", i, name),
            ));
            accounts_to_fund.push(AccountToFund::from_new(
                mpc_setup.desired_balance_per_responding_account,
                format!("mpc-responder-{}-{}-", i, name),
            ));
        }
    }
    let funded_accounts = fund_accounts(accounts, accounts_to_fund, funding_account).await;

    for i in mpc_setup.participants.len()..desired_num_participants {
        let account_id = funded_accounts[i * 2].clone();
        accounts
            .account_mut(&account_id)
            .set_mpc_participant(MpcParticipantSetup {
                p2p_private_key: SecretKey::from_random(near_crypto::KeyType::ED25519),
                responding_account_id: funded_accounts[i * 2 + 1].clone(),
            });
        mpc_setup.participants.push(account_id);
    }

    let responding_accounts = mpc_setup
        .participants
        .iter()
        .map(|participant| {
            accounts
                .account(participant)
                .get_mpc_participant()
                .unwrap()
                .responding_account_id
                .clone()
        })
        .collect::<Vec<_>>();

    // Ensure that the responding accounts have enough access keys.
    let futs = accounts
        .accounts_mut(&responding_accounts)
        .into_values()
        .map(|account| account.ensure_have_n_access_keys(mpc_setup.num_responding_access_keys))
        .collect::<Vec<_>>();
    futures::future::join_all(futs).await;
}

impl NewMpcNetworkCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to create MPC network {} with {} maximum participants, {} NEAR per account, and {} additional access keys per participant for responding",
            name,
            self.num_participants,
            self.near_per_account,
            self.num_responding_access_keys,
        );

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        if setup.mpc_setups.contains_key(name) {
            panic!("MPC network {} already exists", name);
        }
        let mpc_setup = setup
            .mpc_setups
            .entry(name.to_string())
            .or_insert(MpcNetworkSetup {
                participants: Vec::new(),
                contract: None,
                desired_balance_per_account: self.near_per_account * ONE_NEAR,
                num_responding_access_keys: self.num_responding_access_keys,
                desired_balance_per_responding_account: self.near_per_responding_account * ONE_NEAR,
                nomad_server_url: None,
            });
        update_mpc_network(
            name,
            &mut setup.accounts,
            mpc_setup,
            self.num_participants,
            config.funding_account,
        )
        .await;
    }
}

impl UpdateMpcNetworkCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to update MPC network {}", name);

        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));

        let num_participants = self
            .num_participants
            .unwrap_or(mpc_setup.participants.len());

        if let Some(near_per_account) = self.near_per_account {
            mpc_setup.desired_balance_per_account = near_per_account * ONE_NEAR;
        }

        if let Some(num_responding_access_keys) = self.num_responding_access_keys {
            mpc_setup.num_responding_access_keys = num_responding_access_keys;
        }

        if let Some(near_per_responding_account) = self.near_per_responding_account {
            mpc_setup.desired_balance_per_responding_account =
                near_per_responding_account * ONE_NEAR;
        }

        update_mpc_network(
            name,
            &mut setup.accounts,
            mpc_setup,
            num_participants,
            config.funding_account,
        )
        .await;
    }
}

impl MpcDeployContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let (contract_data, contract_path) = match &self.path {
            Some(contract_path) => (std::fs::read(contract_path).unwrap(), contract_path.clone()),
            None => {
                println!(
                    "fetching and deploying contract from testnet account {}",
                    TESTNET_CONTRACT_ACCOUNT_ID
                );
                (
                    queries::get_contract_code(
                        &config.rpc,
                        TESTNET_CONTRACT_ACCOUNT_ID.parse().unwrap(),
                    )
                    .await
                    .unwrap()
                    .code,
                    TESTNET_CONTRACT_ACCOUNT_ID.to_string(),
                )
            }
        };
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if let Some(old_contract) = &mpc_setup.contract {
            let old_contract = setup
                .accounts
                .account(old_contract)
                .get_contract_code()
                .await
                .unwrap();
            if old_contract == contract_data {
                println!("Contract code is the same, not deploying");
                return;
            }
            println!("Contract code is different, going to redeploy");
        }

        let contract_account_to_fund = if let Some(contract) = &mpc_setup.contract {
            AccountToFund::ExistingAccount {
                account_id: contract.clone(),
                desired_balance: self.deposit_near * ONE_NEAR,
                do_not_refill_above: 0,
            }
        } else {
            AccountToFund::from_new(
                self.deposit_near * ONE_NEAR,
                format!("mpc-contract-{}-", name),
            )
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
        mpc_setup.contract = Some(contract_account.clone());

        setup
            .accounts
            .account_mut(&contract_account)
            .deploy_contract(contract_data, &contract_path)
            .await;

        let mut access_key = setup
            .accounts
            .account(&contract_account)
            .any_access_key()
            .await;

        let mut participants = Participants::new();
        for (i, account_id) in mpc_setup
            .participants
            .iter()
            .enumerate()
            .take(self.init_participants)
        {
            participants
                .insert(
                    account_id.clone(),
                    mpc_account_to_participant_info(setup.accounts.account(account_id), i),
                )
                .unwrap();
        }
        let parameters =
            ThresholdParameters::new(participants, Threshold::new(self.threshold)).unwrap();
        let args = serde_json::to_vec(&InitV2Args {
            parameters,
            init_config: None,
        })
        .unwrap();

        access_key
            .submit_tx_to_call_function(
                &contract_account,
                "init",
                &args,
                300,
                0,
                near_primitives::views::TxExecutionStatus::Final,
                true,
            )
            .await
            .into_return_value()
            .unwrap();
    }
}

#[derive(Serialize)]
struct InitV2Args {
    parameters: ThresholdParameters,
    init_config: Option<InitConfig>,
}

fn mpc_account_to_participant_info(account: &OperatingAccount, index: usize) -> ParticipantInfo {
    let mpc_setup = account.get_mpc_participant().unwrap();

    ParticipantInfo {
        sign_pk: near_sdk::PublicKey::from_str(&mpc_setup.p2p_private_key.public_key().to_string())
            .unwrap(),
        url: format!("http://mpc-node-{}.service.mpc.consul:3000", index),
    }
}

impl RemoveContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if mpc_setup.contract.is_some() {
            mpc_setup.contract = None;
            println!("Contract removed (not deleted; just removed from local view)");
        } else {
            println!("Contract is not deployed, nothing to do");
        }
    }
}

impl MpcViewContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        let Some(contract) = mpc_setup.contract.as_ref() else {
            println!("Contract is not deployed");
            return;
        };
        let contract_state = setup
            .accounts
            .account(contract)
            .query_contract("state", b"{}".to_vec())
            .await
            .expect("state() call failed");
        println!(
            "Contract state: {}",
            String::from_utf8_lossy(&contract_state.result)
        );
    }
}

/// Gets a list of voters who would send the vote txn, based on the cmdline flag (empty list means
/// all participants; otherwise it's the precise list of participant indices).
fn get_voter_account_ids<'a>(
    mpc_setup: &'a MpcNetworkSetup,
    voters: &[usize],
) -> Vec<&'a AccountId> {
    mpc_setup
        .participants
        .iter()
        .enumerate()
        .filter(|(i, _)| voters.is_empty() || voters.contains(i))
        .map(|(_, account_id)| account_id)
        .collect::<Vec<_>>()
}

impl MpcProposeUpdateContractCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!("Going to propose update contract for MPC network {}", name);
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let contract_code = std::fs::read(&self.path).unwrap();
        let proposer_account_id = &mpc_setup.participants[self.proposer_index];

        // Fund the proposer account with additional tokens first to cover the additional deposit.
        let account_to_fund = AccountToFund::from_existing(
            proposer_account_id.clone(),
            mpc_setup.desired_balance_per_account + self.deposit_near * ONE_NEAR,
        );
        fund_accounts(
            &mut setup.accounts,
            vec![account_to_fund],
            config.funding_account,
        )
        .await;
        let proposer = setup.accounts.account(proposer_account_id);

        let result = proposer
            .any_access_key()
            .await
            .submit_tx_to_call_function(
                &contract,
                "propose_update",
                &borsh::to_vec(&ProposeUpdateArgs {
                    contract: Some(contract_code),
                    config: None,
                })
                .unwrap(),
                300,
                self.deposit_near * ONE_NEAR,
                near_primitives::views::TxExecutionStatus::Final,
                false,
            )
            .await
            .into_return_value()
            .expect("Failed to propose update");
        let update_id: u64 = serde_json::from_slice(&result).expect(&format!(
            "Failed to deserialize result: {}",
            String::from_utf8_lossy(&result)
        ));
        println!("Proposed update with ID {}", update_id);
        println!("Run the following command to vote for the update:");
        let self_exe = std::env::current_exe()
            .expect("Failed to get current executable path")
            .to_str()
            .expect("Failed to convert path to string")
            .to_string();
        println!(
            "{} mpc {} vote-update --update-id={}",
            self_exe, name, update_id
        );
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProposeUpdateArgs {
    pub contract: Option<Vec<u8>>,
    pub config: Option<()>, // unsupported
}

impl MpcVoteUpdateCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote update contract for MPC network {} with update ID {}",
            name, self.update_id
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_update",
                    &serde_json::to_vec(&VoteUpdateArgs { id: self.update_id }).unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result.into_return_value() {
                Ok(_) => {
                    println!("Participant {} vote_update({}) succeed", i, self.update_id);
                }
                Err(err) => {
                    println!(
                        "Participant {} vote_update({}) failed: {:?}",
                        i, self.update_id, err
                    );
                }
            }
        }
    }
}

#[derive(Serialize)]
struct VoteUpdateArgs {
    id: u64,
}

impl MpcVoteAddDomainsCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_add_domains MPC network {} for signature schemes {:?}",
            name, self.signature_schemes
        );
        let signature_schemes: Vec<SignatureScheme> = self
            .signature_schemes
            .iter()
            .map(|scheme| {
                serde_json::from_str(&format!("\"{}\"", scheme))
                    .expect(&format!("Failed to parse signature scheme {}", scheme))
            })
            .collect::<Vec<_>>();
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");

        // Query the contract state and use the next_domain_id to construct the domain IDs we should
        // use for the proposal.
        let contract_state = read_contract_state_v2(&setup.accounts, &contract).await;
        let domains = match contract_state {
            ProtocolContractState::Running(running_contract_state) => {
                running_contract_state.domains
            }
            _ => {
                panic!(
                    "Cannot add domains when not in the running state: {:?}",
                    contract_state
                );
            }
        };
        let mut proposal = Vec::new();
        let mut next_domain = domains.next_domain_id();
        for signature_scheme in &signature_schemes {
            proposal.push(DomainConfig {
                id: DomainId(next_domain),
                scheme: *signature_scheme,
            });
            next_domain += 1;
        }

        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let proposal = proposal.clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_add_domains",
                    &serde_json::to_vec(&VoteAddDomainsArgs { domains: proposal }).unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result.into_return_value() {
                Ok(_) => {
                    println!("Participant {} vote_add_domains succeed", i);
                }
                Err(err) => {
                    println!("Participant {} vote_add_domains failed: {:?}", i, err);
                }
            }
        }
    }
}

#[derive(Serialize)]
struct VoteAddDomainsArgs {
    domains: Vec<DomainConfig>,
}

impl MpcVoteNewParametersCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_new_parameters for MPC network {}, adding participants {:?}, removing participants {:?}, and overriding threshold with {:?}",
            name, self.add, self.remove, self.set_threshold
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");

        // Query the contract state so we can incrementally construct the new parameters. This is
        // because the existing participants must have the same participant IDs, and the new
        // participants must have contiguous participant IDs.
        let contract_state = read_contract_state_v2(&setup.accounts, &contract).await;
        let prospective_epoch_id = match &contract_state {
            ProtocolContractState::Running(state) => state.keyset.epoch_id.next(),
            ProtocolContractState::Resharing(state) => state.prospective_epoch_id().next(),
            _ => panic!(),
        };
        let parameters = match contract_state {
            ProtocolContractState::Running(state) => state.parameters,
            ProtocolContractState::Resharing(state) => state.previous_running_state.parameters,
            _ => {
                panic!(
                    "Cannot vote for new parameters when not in the running or resharing state: {:?}",
                    contract_state
                );
            }
        };

        let mut participants = parameters.participants().clone();
        for participant_index in &self.remove {
            let account_id = mpc_setup.participants[*participant_index].clone();
            assert!(
                participants.is_participant(&account_id),
                "Participant {} is not in the network",
                account_id
            );
            participants.remove(&account_id);
        }
        for participant_index in &self.add {
            let account_id = mpc_setup.participants[*participant_index].clone();
            assert!(
                !participants.is_participant(&account_id),
                "Participant {} is already in the network",
                account_id
            );
            participants
                .insert(
                    account_id.clone(),
                    mpc_account_to_participant_info(
                        setup.accounts.account(&account_id),
                        *participant_index,
                    ),
                )
                .unwrap();
        }
        let threshold = if let Some(threshold) = self.set_threshold {
            Threshold::new(threshold)
        } else {
            parameters.threshold()
        };
        let proposal =
            ThresholdParameters::new(participants, threshold).expect("New parameters invalid");

        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let proposal = proposal.clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_new_parameters",
                    &serde_json::to_vec(&VoteNewParametersArgs {
                        prospective_epoch_id,
                        proposal,
                    })
                    .unwrap(),
                    300,
                    0,
                    near_primitives::views::TxExecutionStatus::Final,
                    true,
                )
                .await
            });
        }
        let results = futures::future::join_all(futs).await;
        for (i, result) in results.into_iter().enumerate() {
            match result.into_return_value() {
                Ok(_) => {
                    println!("Participant {} vote_new_parameters succeed", i);
                }
                Err(err) => {
                    println!("Participant {} vote_new_parameters failed: {:?}", i, err);
                }
            }
        }
    }
}

/// Read the contract state from the contract and deserialize it into the V2 state format.
pub async fn read_contract_state_v2(
    accounts: &OperatingAccounts,
    contract: &AccountId,
) -> ProtocolContractState {
    let contract_state = accounts
        .account(contract)
        .query_contract("state", b"{}".to_vec())
        .await
        .expect("state() call failed");
    serde_json::from_slice(&contract_state.result).expect(&format!(
        "Failed to deserialize contract state: {}",
        String::from_utf8_lossy(&contract_state.result)
    ))
}

#[derive(Serialize)]
struct VoteNewParametersArgs {
    prospective_epoch_id: EpochId,
    proposal: ThresholdParameters,
}

impl MpcDescribeCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        let setup = OperatingDevnetSetup::load(config.rpc.clone()).await;
        let mpc_setup = setup
            .mpc_setups
            .get(name)
            .expect(&format!("MPC network {} does not exist", name));
        if let Some(contract) = &mpc_setup.contract {
            println!("MPC contract deployed at: {}", contract);
            let contract_state = read_contract_state_v2(&setup.accounts, contract).await;
            print!("{}", protocol_state_to_string(&contract_state));
        } else {
            println!("MPC contract is not deployed");
        }
        println!();

        self.describe_terraform(name, &config).await;
    }
}
