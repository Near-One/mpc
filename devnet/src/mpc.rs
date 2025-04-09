#![allow(clippy::expect_fun_call)] // to reduce verbosity of expect calls
use crate::account::OperatingAccounts;
use crate::cli::{
    MpcDeployContractCmd, MpcDescribeCmd, MpcProposeUpdateContractCmd, MpcV1JoinCmd,
    MpcV1VoteJoinCmd, MpcV1VoteLeaveCmd, MpcViewContractCmd, MpcVoteAddDomainsCmd,
    MpcVoteNewParametersCmd, MpcVoteUpdateCmd, NewMpcNetworkCmd, RemoveContractCmd,
    UpdateMpcNetworkCmd,
};
use crate::constants::ONE_NEAR;
use crate::devnet::OperatingDevnetSetup;
use crate::funding::{fund_accounts, AccountToFund};
use crate::tx::IntoReturnValueExt;
use crate::types::{MpcNetworkSetup, MpcParticipantSetup, NearAccount, ParsedConfig};
use borsh::{BorshDeserialize, BorshSerialize};
use legacy_mpc_contract::config::InitConfigV1;
use legacy_mpc_contract::primitives::{self, CandidateInfo};
use mpc_contract::primitives::domain::{DomainConfig, DomainId, SignatureScheme};
use mpc_contract::primitives::key_state::EpochId;
use mpc_contract::primitives::participants::ParticipantInfo;
use mpc_contract::primitives::thresholds::{Threshold, ThresholdParameters};
use mpc_contract::state::ProtocolContractState;
use near_crypto::SecretKey;
use near_sdk::{borsh, AccountId};
use serde::Serialize;
use std::collections::BTreeMap;
use std::str::FromStr;

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
        println!("Going to create MPC network {} with {} participants, threshold {}, {} NEAR per account, and {} additional access keys per participant for responding",
            name,
            self.num_participants,
            self.threshold,
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
                threshold: self.threshold,
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

        if let Some(threshold) = self.threshold {
            mpc_setup.threshold = threshold;
        }

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
        println!("Going to deploy contract for MPC network {}", name);
        let contract_data = std::fs::read(&self.path).unwrap();
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
            .deploy_contract(contract_data, &self.path)
            .await;

        let mut access_key = setup
            .accounts
            .account(&contract_account)
            .any_access_key()
            .await;
        access_key
            .submit_tx_to_call_function(
                &contract_account,
                "init",
                &serde_json::to_vec(&InitArgs {
                    threshold: mpc_setup.threshold,
                    init_config: Some(InitConfigV1 {
                        max_num_requests_to_remove: self.max_requests_to_remove,
                        request_timeout_blocks: None,
                    }),
                    candidates: mpc_setup
                        .participants
                        .iter()
                        .take(self.init_participants)
                        .enumerate()
                        .map(|(i, account_id)| {
                            (
                                account_id.clone(),
                                mpc_account_to_candidate_info(&setup.accounts, account_id, i),
                            )
                        })
                        .collect(),
                })
                .unwrap(),
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
struct InitArgs {
    threshold: usize,
    candidates: BTreeMap<AccountId, CandidateInfo>,
    init_config: Option<InitConfigV1>,
}

fn mpc_account_to_candidate_info(
    accounts: &OperatingAccounts,
    account_id: &AccountId,
    index: usize,
) -> CandidateInfo {
    let account = accounts.account(account_id);
    let mpc_setup = account.get_mpc_participant().unwrap();
    CandidateInfo {
        account_id: account_id.clone(),
        cipher_pk: [0; 32],
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

impl MpcV1JoinCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to join MPC network {} as participant {}",
            name, self.account_index
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if self.account_index >= mpc_setup.participants.len() {
            panic!(
                "Account index {} is out of bounds for {} participants",
                self.account_index,
                mpc_setup.participants.len()
            );
        }
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        let account = setup
            .accounts
            .account(&mpc_setup.participants[self.account_index]);
        let mut key = account.any_access_key().await;

        let candidate = mpc_account_to_candidate_info(
            &setup.accounts,
            &mpc_setup.participants[self.account_index],
            self.account_index,
        );
        key.submit_tx_to_call_function(
            &contract,
            "join",
            &serde_json::to_vec(&JoinArgs {
                url: candidate.url,
                cipher_pk: candidate.cipher_pk,
                sign_pk: candidate.sign_pk,
            })
            .unwrap(),
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
struct JoinArgs {
    url: String,
    cipher_pk: primitives::hpke::PublicKey,
    sign_pk: near_sdk::PublicKey,
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

impl MpcV1VoteJoinCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_join MPC network {} for participant {}",
            name, self.for_account_index
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if self.for_account_index >= mpc_setup.participants.len() {
            panic!(
                "Target account index {} is out of bounds for {} participants",
                self.for_account_index,
                mpc_setup.participants.len()
            );
        }
        let contract = mpc_setup
            .contract
            .clone()
            .expect("Contract is not deployed");
        // This may make some voters that aren't part of the network vote, but that's OK.
        let from_accounts = get_voter_account_ids(mpc_setup, &self.voters);

        let mut futs = Vec::new();
        for account_id in from_accounts {
            let account = setup.accounts.account(account_id);
            let mut key = account.any_access_key().await;
            let contract = contract.clone();
            let candidate = mpc_setup.participants[self.for_account_index].clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_join",
                    &serde_json::to_vec(&VoteJoinArgs { candidate }).unwrap(),
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
                    println!(
                        "Participant {} vote_join({}) succeed",
                        i, self.for_account_index
                    );
                }
                Err(err) => {
                    println!(
                        "Participant {} vote_join({}) failed: {:?}",
                        i, self.for_account_index, err
                    );
                }
            }
        }
    }
}

impl MpcV1VoteLeaveCmd {
    pub async fn run(&self, name: &str, config: ParsedConfig) {
        println!(
            "Going to vote_leave MPC network {} for participant {}",
            name, self.for_account_index
        );
        let mut setup = OperatingDevnetSetup::load(config.rpc).await;
        let mpc_setup = setup
            .mpc_setups
            .get_mut(name)
            .expect(&format!("MPC network {} does not exist", name));
        if self.for_account_index >= mpc_setup.participants.len() {
            panic!(
                "Target account index {} is out of bounds for {} participants",
                self.for_account_index,
                mpc_setup.participants.len()
            );
        }
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
            let kick = mpc_setup.participants[self.for_account_index].clone();
            futs.push(async move {
                key.submit_tx_to_call_function(
                    &contract,
                    "vote_leave",
                    &serde_json::to_vec(&VoteLeaveArgs { kick }).unwrap(),
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
                    println!(
                        "Participant {} vote_leave({}) succeed",
                        i, self.for_account_index
                    );
                }
                Err(err) => {
                    println!(
                        "Participant {} vote_leave({}) failed: {:?}",
                        i, self.for_account_index, err
                    );
                }
            }
        }
    }
}

#[derive(Serialize)]
struct VoteJoinArgs {
    candidate: AccountId,
}

#[derive(Serialize)]
struct VoteLeaveArgs {
    kick: AccountId,
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
                    ParticipantInfo {
                        url: format!(
                            "http://mpc-node-{}.service.mpc.consul:3000",
                            participant_index
                        ),
                        sign_pk: near_sdk::PublicKey::from_str(
                            &setup
                                .accounts
                                .account(&account_id)
                                .get_mpc_participant()
                                .unwrap()
                                .p2p_private_key
                                .public_key()
                                .to_string(),
                        )
                        .unwrap(),
                    },
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
            match contract_state {
                ProtocolContractState::NotInitialized => {
                    println!("Contract is not initialized");
                }
                ProtocolContractState::Initializing(state) => {
                    println!("Contract is in Initializing state (key generation)");
                    println!("  Epoch: {}", state.generating_key.epoch_id());
                    println!("  Domains:");
                    for (i, domain) in state.domains.domains().iter().enumerate() {
                        print!("    Domain {}: {:?}, ", domain.id, domain.scheme);
                        if i < state.generated_keys.len() {
                            println!(
                                "key generated (attempt ID {})",
                                state.generated_keys[i].attempt
                            );
                        } else if i == state.generated_keys.len() {
                            print!("generating key: ");
                            if state.generating_key.is_active() {
                                println!(
                                    "active; current attempt ID: {}",
                                    state
                                        .generating_key
                                        .current_key_event_id()
                                        .unwrap()
                                        .attempt_id
                                );
                            } else {
                                println!(
                                    "not active; next attempt ID: {}",
                                    state.generating_key.next_attempt_id()
                                );
                            }
                        } else {
                            println!("queued for generation");
                        }
                    }
                    println!("  Parameters:");
                    Self::print_parameters(state.generating_key.proposed_parameters());
                    println!("  Warning: this tool does not calculate automatic timeouts for key generation attempts");
                }
                ProtocolContractState::Running(state) => {
                    println!("Contract is in Running state");
                    println!("  Epoch: {}", state.keyset.epoch_id);
                    println!("  Keyset:");
                    for (domain, key) in state
                        .domains
                        .domains()
                        .iter()
                        .zip(state.keyset.domains.iter())
                    {
                        println!(
                            "    Domain {}: {:?}, key from attempt {}",
                            domain.id, domain.scheme, key.attempt
                        );
                    }
                    println!("  Parameters:");
                    Self::print_parameters(&state.parameters);
                }
                ProtocolContractState::Resharing(state) => {
                    println!("Contract is in Initializing state (key generation)");
                    println!(
                        "  Epoch transition: original {} --> prospective {}",
                        state.previous_running_state.keyset.epoch_id,
                        state.prospective_epoch_id()
                    );
                    println!("  Domains:");
                    for (i, domain) in state
                        .previous_running_state
                        .domains
                        .domains()
                        .iter()
                        .enumerate()
                    {
                        print!(
                            "    Domain {}: {:?}, original key from attempt {}, ",
                            domain.id,
                            domain.scheme,
                            state.previous_running_state.keyset.domains[i].attempt
                        );

                        if i < state.reshared_keys.len() {
                            println!("reshared (attempt ID {})", state.reshared_keys[i].attempt);
                        } else if i == state.reshared_keys.len() {
                            print!("resharing key: ");
                            if state.resharing_key.is_active() {
                                println!(
                                    "active; current attempt ID: {}",
                                    state
                                        .resharing_key
                                        .current_key_event_id()
                                        .unwrap()
                                        .attempt_id
                                );
                            } else {
                                println!(
                                    "not active; next attempt ID: {}",
                                    state.resharing_key.next_attempt_id()
                                );
                            }
                        } else {
                            println!("queued for resharing");
                        }
                    }
                    println!("  Previous Parameters:");
                    Self::print_parameters(&state.previous_running_state.parameters);
                    println!("  Proposed Parameters:");
                    Self::print_parameters(state.resharing_key.proposed_parameters());

                    println!("  Warning: this tool does not calculate automatic timeouts for resharing attempts");
                }
            }
        } else {
            println!("MPC contract is not deployed");
        }
        println!();

        self.describe_terraform(name, &config).await;
    }

    fn print_parameters(parameters: &ThresholdParameters) {
        println!("    Participants:");
        for (account_id, id, info) in parameters.participants().participants() {
            println!("      ID {}: {} ({})", id, account_id, info.url);
        }
        println!("    Threshold: {}", parameters.threshold().value());
    }
}
