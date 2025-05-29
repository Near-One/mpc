//! Contains OperatingAccounts, OperatingAccount, and OperatingAccessKey.
//!
//! OperatingAccounts contain a collection of OperatingAccount, which contains a collection of
//! OperatingAccessKey.
//!
//! When we send a transaction to the chain, upon success we also mutate the local state we have.
//! For example, upon creating an account, we would make a new OperatingAccount for it and add it
//! to the OperatingAccounts structure.
//!
//! For this reason, we place methods in the appropriate structure depending on what needs to be
//! updated. The method for creating an access key, for example, lives in OperatingAccount,
//! because we need a mutable reference to it to add access keys to our local state. On the other
//! hand, sending an arbitrary transfer of NEAR tokens is in OperatingAccessKey, since no local
//! state needs changing (other than updating the nonce, which is per access key).
use crate::contracts::ActionCall;
use crate::queries;
use crate::rpc::NearRpcClients;
use crate::types::{ContractSetup, MpcParticipantSetup, NearAccount, NearAccountKind};
use futures::FutureExt;
use near_crypto::{InMemorySigner, PublicKey, SecretKey, Signer};
use near_jsonrpc_client::methods;
use near_jsonrpc_client::methods::send_tx::SignedTransaction;
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::account::AccessKey;
use near_primitives::action::{Action, AddKeyAction};
use near_primitives::hash::CryptoHash;
use near_primitives::types::Finality;
use near_primitives::types::{BlockReference, FunctionArgs};
use near_primitives::views::{CallResult, QueryRequest, TxExecutionStatus};
use near_sdk::AccountId;
use reqwest::StatusCode;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;

/// Current state of an account while the CLI is running.
pub struct OperatingAccount {
    /// The current view of the account data. This is persisted at the end of the CLI run.
    account_data: NearAccount,
    /// A recent block hash for submitting transactions to chain.
    recent_block_hash: CryptoHash,
    /// RPC for submitting transactions.
    client: Arc<NearRpcClients>,
    /// Access keys; each is a mutex so that they can simultaneously be used.
    keys: Vec<Arc<tokio::sync::Mutex<OperatingAccessKey>>>,
}

impl OperatingAccount {
    pub fn new(
        account_data: NearAccount,
        recent_block_hash: CryptoHash,
        client: Arc<NearRpcClients>,
    ) -> Self {
        Self {
            keys: account_data
                .access_keys
                .iter()
                .map(|key| {
                    Arc::new(tokio::sync::Mutex::new(OperatingAccessKey::new(
                        account_data.account_id.clone(),
                        key.clone(),
                        recent_block_hash,
                        client.clone(),
                    )))
                })
                .collect(),
            recent_block_hash,
            client,
            account_data,
        }
    }
}

/// An access key that can be used to send transactions.
/// Internally keeps track of the most recent nonce.
/// Can only send one transaction at once, in order to avoid nonce conflicts.
/// That transaction must at least be included in the chain before sending another.
pub struct OperatingAccessKey {
    account_id: AccountId,
    nonce: Option<u64>, // if none, need to fetch it later.
    recent_block_hash: CryptoHash,
    client: Arc<NearRpcClients>,
    signer: Signer,
    secret_key: SecretKey,
}

/// Returns {prefix}{random string}{suffix}.
pub fn make_random_account_name(prefix: &str, suffix: &str) -> AccountId {
    format!(
        "{}{}{}",
        prefix,
        hex::encode(rand::random::<[u8; 6]>()),
        suffix
    )
    .try_into()
    .unwrap()
}

impl OperatingAccessKey {
    pub fn new(
        account_id: AccountId,
        secret_key: SecretKey,
        recent_block_hash: CryptoHash,
        client: Arc<NearRpcClients>,
    ) -> Self {
        let signer = Signer::InMemory(InMemorySigner::from_secret_key(
            account_id.clone(),
            secret_key.clone(),
        ));
        Self {
            account_id,
            nonce: None,
            recent_block_hash,
            client,
            signer,
            secret_key,
        }
    }

    /// Returns the next nonce to use, querying it from RPC if needed.
    async fn next_nonce(&mut self) -> u64 {
        match &mut self.nonce {
            Some(nonce) => {
                *nonce += 1;
                *nonce
            }
            None => {
                let request = near_primitives::views::QueryRequest::ViewAccessKey {
                    account_id: self.account_id.clone(),
                    public_key: self.signer.public_key(),
                };
                let nonce = self
                    .client
                    .with_retry(10, |rpc| {
                        let request = request.clone();
                        async move {
                            let result = rpc
                                .call(methods::query::RpcQueryRequest {
                                    block_reference: BlockReference::Finality(Finality::None),
                                    request,
                                })
                                .await?;
                            match result.kind {
                                QueryResponseKind::AccessKey(access_key) => {
                                    anyhow::Ok(access_key.nonce)
                                }
                                _ => anyhow::bail!("Unexpected response: {:?}", result),
                            }
                        }
                        .boxed()
                    })
                    .await
                    .unwrap();
                self.nonce = Some(nonce + 1);
                nonce + 1
            }
        }
    }

    /// Creates an account, returning the new NearAccount structure that represents the created
    /// account. Note: the account created must be a subaccount of this account, so that's why
    /// only a prefix is taken and not a suffix.
    pub async fn create_account(
        &mut self,
        new_account_prefix: &str,
        secret_key: SecretKey,
        amount: u128,
    ) -> NearAccount {
        let new_account_id =
            make_random_account_name(new_account_prefix, &format!(".{}", self.account_id));
        println!(
            "[{}] Creating account {} with {} NEAR",
            self.account_id, new_account_id, amount,
        );
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::create_account(
                self.next_nonce().await,
                self.account_id.clone(),
                new_account_id.clone(),
                amount,
                secret_key.public_key(),
                &self.signer,
                self.recent_block_hash,
            ),
            wait_until: TxExecutionStatus::Final,
        };
        self.client.submit(request).await.unwrap();
        NearAccount {
            account_id: new_account_id,
            access_keys: vec![secret_key],
            kind: NearAccountKind::Normal,
        }
    }

    /// Adds the given access key to this account.
    pub async fn add_access_key(&mut self, key: PublicKey) {
        println!(
            "[{}] Adding access key {} to account {}",
            self.account_id, key, self.account_id,
        );
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::from_actions(
                self.next_nonce().await,
                self.account_id.clone(),
                self.account_id.clone(),
                &self.signer,
                vec![Action::AddKey(Box::new(AddKeyAction {
                    access_key: AccessKey {
                        nonce: 0,
                        permission: near_primitives::account::AccessKeyPermission::FullAccess,
                    },
                    public_key: key,
                }))],
                self.recent_block_hash,
                0,
            ),
            wait_until: TxExecutionStatus::Final,
        };
        self.client.submit(request).await.unwrap();
    }

    /// Submits a transaction to the chain to mutably call a function on a contract.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_tx_to_call_function(
        &mut self,
        contract_id: &AccountId,
        method: &str,
        args: &[u8],
        tgas: u64,
        deposit: u128,
        wait_until: TxExecutionStatus,
        verbose: bool,
    ) -> anyhow::Result<RpcTransactionResponse> {
        if verbose {
            println!(
                "[{}] Calling {}::{} with args {}",
                self.account_id,
                contract_id,
                method,
                String::from_utf8_lossy(args),
            );
        }
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::from_actions(
                self.next_nonce().await,
                self.account_id.clone(),
                contract_id.clone(),
                &self.signer,
                vec![Action::FunctionCall(Box::new(
                    near_primitives::action::FunctionCallAction {
                        method_name: method.to_string(),
                        args: args.to_vec(),
                        gas: tgas * 1_000_000_000_000,
                        deposit,
                    },
                ))],
                self.recent_block_hash,
                0,
            ),
            wait_until,
        };
        Ok(self.client.submit(request).await?)
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret_key.clone()
    }

    pub async fn sign_tx_from_actions(&mut self, action_call: ActionCall) -> SignedTransaction {
        SignedTransaction::from_actions(
            self.next_nonce().await,
            self.account_id.clone(),
            action_call.receiver_id,
            &self.signer,
            action_call.actions,
            self.recent_block_hash,
            0,
        )
    }
}

impl OperatingAccount {
    /// In log(N) serial steps, ensure that this account has at least the desired number of access
    /// keys. Internally, what this does is it uses each access key to add another key to the
    /// account, doubling the number of keys every time up to the desired limit.
    pub async fn ensure_have_n_access_keys(&mut self, desired_num_keys: usize) {
        while self.keys.len() < desired_num_keys {
            let keys_to_add = (desired_num_keys - self.keys.len()).min(self.keys.len());
            println!(
                "Account {} has {} / {} desired keys; adding {} more...",
                self.account_data.account_id,
                self.keys.len(),
                desired_num_keys,
                keys_to_add
            );
            let futs = self.keys.iter().take(keys_to_add).map(|key| {
                let key = key.clone();
                async move {
                    let mut key = key.lock().await;
                    let new_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
                    key.add_access_key(new_key.public_key()).await;
                    new_key
                }
            });
            let new_keys = futures::future::join_all(futs).await;
            for new_key in new_keys {
                {
                    let this = &mut *self;
                    this.account_data.access_keys.push(new_key.clone());
                    this.keys
                        .push(Arc::new(tokio::sync::Mutex::new(OperatingAccessKey::new(
                            this.account_data.account_id.clone(),
                            new_key,
                            this.recent_block_hash,
                            this.client.clone(),
                        ))));
                };
            }
        }
        println!(
            "Account {} now has {} keys",
            self.account_data.account_id,
            self.keys.len()
        );
    }

    /// Sets the metadata for this account to represent an MPC participant.
    pub fn set_mpc_participant(&mut self, mpc: MpcParticipantSetup) {
        self.account_data.kind = NearAccountKind::MpcParticipant(mpc);
    }

    pub fn get_mpc_participant(&self) -> Option<&MpcParticipantSetup> {
        match &self.account_data.kind {
            NearAccountKind::MpcParticipant(mpc) => Some(mpc),
            _ => None,
        }
    }

    /// Deploys the given contract. This will deploy over an existing contract if one exists
    /// already and the code isn't the same.
    pub async fn deploy_contract(&mut self, code: Vec<u8>, from_path: &str) {
        println!(
            "Deploying MPC contract to account {}",
            self.account_data.account_id
        );
        match &self.account_data.kind {
            NearAccountKind::Normal => {}
            NearAccountKind::Contract(setup) => {
                println!(
                    "Deploying over previous contract from {}",
                    setup.deployed_filename
                );
            }
            _ => {
                panic!("Account {} is not a normal or contract account, refusing to deploy contract to it", self.account_data.account_id);
            }
        }
        let mut key = self.keys[0].lock().await;
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::deploy_contract(
                key.next_nonce().await,
                &self.account_data.account_id,
                code,
                &key.signer,
                key.recent_block_hash,
            ),
            wait_until: TxExecutionStatus::Final,
        };
        self.client.submit(request).await.unwrap();
        self.account_data.kind = NearAccountKind::Contract(ContractSetup {
            deployed_filename: from_path.to_string(),
        });
    }

    /// Performs a readonly query to the contract.
    pub async fn query_contract(&self, method: &str, args: Vec<u8>) -> anyhow::Result<CallResult> {
        let request = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::Final),
            request: QueryRequest::CallFunction {
                account_id: self.account_data.account_id.clone(),
                method_name: method.to_string(),
                args: FunctionArgs::from(args),
            },
        };
        let result = self.client.submit(request).await?;
        match result.kind {
            QueryResponseKind::CallResult(result) => Ok(result),
            _ => anyhow::bail!("Unexpected response: {:?}", result),
        }
    }

    /// Queries the code of the contract.
    pub async fn get_contract_code(&self) -> anyhow::Result<Vec<u8>> {
        let res =
            queries::get_contract_code(&self.client, self.account_data.account_id.clone()).await?;
        Ok(res.code)
    }

    /// Returns the first access key, for transactions that don't need parallelism.
    pub async fn any_access_key(&self) -> OwnedMutexGuard<OperatingAccessKey> {
        self.keys[0].clone().lock_owned().await
    }

    /// Returns all access keys, for transactions that need full parallelism.
    pub async fn all_access_keys(&self) -> Vec<OwnedMutexGuard<OperatingAccessKey>> {
        futures::future::join_all(self.keys.iter().map(|key| key.clone().lock_owned())).await
    }
}

/// Represents the live state of the collection of all accounts the CLI knows.
pub struct OperatingAccounts {
    /// The current view of the account data. This is persisted at the end of the CLI run.
    pub accounts: HashMap<AccountId, OperatingAccount>,
    /// A recent block hash for submitting transactions to chain.
    pub recent_block_hash: CryptoHash,
    /// RPC for submitting transactions.
    pub client: Arc<NearRpcClients>,
}

impl OperatingAccounts {
    pub fn new(
        accounts: HashMap<AccountId, NearAccount>,
        recent_block_hash: CryptoHash,
        client: Arc<NearRpcClients>,
    ) -> Self {
        Self {
            accounts: accounts
                .into_iter()
                .map(|(account_id, account_data)| {
                    (
                        account_id.clone(),
                        OperatingAccount::new(account_data, recent_block_hash, client.clone()),
                    )
                })
                .collect(),
            recent_block_hash,
            client,
        }
    }

    /// Creates a new account using the funding_account. The created account will be a subaccount
    /// (suffixed by ".{funding_account}"), and adds the account to the list of accounts we keep
    /// track of.
    pub async fn create_account(
        &mut self,
        new_account_prefix: &str,
        amount: u128,
        funding_account: &AccountId,
    ) -> AccountId {
        let secret_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
        let new_account = self.accounts.get(funding_account).unwrap().keys[0]
            .lock()
            .await
            .create_account(new_account_prefix, secret_key.clone(), amount)
            .await;
        let account = OperatingAccount::new(
            new_account.clone(),
            self.recent_block_hash,
            self.client.clone(),
        );
        self.accounts
            .insert(new_account.account_id.clone(), account);
        new_account.account_id
    }

    /// Sends some balance from one account to another.
    pub async fn send_balance(&self, sender: &AccountId, receiver: &AccountId, amount: u128) {
        let mut sender = self.accounts.get(sender).unwrap().keys[0].lock().await;
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: SignedTransaction::send_money(
                sender.next_nonce().await,
                sender.account_id.clone(),
                receiver.clone(),
                &sender.signer,
                amount,
                sender.recent_block_hash,
            ),
            wait_until: TxExecutionStatus::Final,
        };
        self.client.submit(request).await.unwrap();
    }

    /// Creates a new account from the Testnet faucet, using it as a funding account to create or
    /// refill other accounts.
    pub async fn create_funding_account_from_faucet(&mut self, new_account_id: &AccountId) {
        let secret_key = SecretKey::from_random(near_crypto::KeyType::ED25519);
        let mut data = std::collections::HashMap::new();
        data.insert("newAccountId", new_account_id.to_string());
        data.insert("newAccountPublicKey", secret_key.public_key().to_string());
        let result = reqwest::Client::new()
            .post("https://helper.nearprotocol.com/account")
            .json(&data)
            .send()
            .await
            .unwrap();
        if result.status() != StatusCode::OK {
            let status = result.status();
            let error_text = result
                .text()
                .await
                .unwrap_or_else(|_| "No error message".to_string());
            println!(
                "Faucet RPC request failed: status {}, {}",
                status, error_text
            );
            std::process::exit(1);
        }
        let new_account = NearAccount {
            account_id: new_account_id.clone(),
            access_keys: vec![secret_key],
            kind: NearAccountKind::FundingAccount,
        };
        let account =
            OperatingAccount::new(new_account, self.recent_block_hash, self.client.clone());
        self.accounts.insert(new_account_id.clone(), account);
    }

    /// Get all funding accounts we know of.
    pub fn get_funding_accounts(&self) -> Vec<AccountId> {
        self.accounts
            .iter()
            .filter_map(|(account_id, account)| {
                if let NearAccountKind::FundingAccount = account.account_data.kind {
                    Some(account_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Queries the balances of any number of accounts, in parallel.
    pub async fn get_account_balances(&self, accounts: &[AccountId]) -> HashMap<AccountId, u128> {
        let futs = accounts.iter().map(|account_id| async {
            self.client
                .with_retry(10, |rpc| {
                    let account_id = account_id.clone();
                    async move {
                        match rpc
                            .call(methods::query::RpcQueryRequest {
                                block_reference: BlockReference::Finality(Finality::Final),
                                request: QueryRequest::ViewAccount {
                                    account_id: account_id.clone(),
                                },
                            })
                            .await?
                            .kind
                        {
                            QueryResponseKind::ViewAccount(account) => {
                                anyhow::Ok((account_id.clone(), account.amount))
                            }
                            _ => panic!("Unexpected response"),
                        }
                    }
                    .boxed()
                })
                .await
                .unwrap()
        });
        futures::future::join_all(futs).await.into_iter().collect()
    }

    /// Get the balance of a single account.
    pub async fn get_account_balance(&self, account_id: &AccountId) -> u128 {
        self.get_account_balances(&[account_id.clone()])
            .await
            .remove(account_id)
            .unwrap()
    }

    #[allow(dead_code)]
    pub fn account_mut(&mut self, account_id: &AccountId) -> &mut OperatingAccount {
        self.accounts.get_mut(account_id).unwrap()
    }

    pub fn account(&self, account_id: &AccountId) -> &OperatingAccount {
        self.accounts.get(account_id).unwrap()
    }

    /// Get mutable references to multiple accounts at the same time.
    pub fn accounts_mut(
        &mut self,
        account_ids: &[AccountId],
    ) -> HashMap<AccountId, &mut OperatingAccount> {
        let filter = account_ids
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        self.accounts
            .iter_mut()
            .filter(|(account_id, _)| filter.contains(*account_id))
            .map(|(account_id, account)| (account_id.clone(), account))
            .collect()
    }

    /// Removes an account from the list of accounts we know of.
    /// Does NOT delete the account on chain.
    pub fn discard_account(&mut self, account_id: &AccountId) {
        self.accounts.remove(account_id);
    }

    /// Serializes the persistent state of all accounts to the format we store on disk.
    pub fn to_data(&self) -> HashMap<AccountId, NearAccount> {
        self.accounts
            .iter()
            .map(|(account_id, account)| (account_id.clone(), account.account_data.clone()))
            .collect()
    }
}
