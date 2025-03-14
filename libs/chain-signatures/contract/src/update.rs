use std::collections::HashSet;
use std::hash::Hash;

use crate::config::Config;
use crate::storage_keys::StorageKey;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::IterableMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise};

#[derive(
    Copy,
    Clone,
    Default,
    Debug,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct UpdateId(pub(crate) u64);

impl UpdateId {
    pub fn generate(&mut self) -> Self {
        let id = self.0;
        self.0 += 1;
        Self(id)
    }
}

impl From<u64> for UpdateId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub enum Update {
    Contract(Vec<u8>),
    Config(Config),
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Default)]
pub struct ProposeUpdateArgs {
    pub code: Option<Vec<u8>>,
    pub config: Option<Config>,
}

#[near(serializers=[borsh ])]
#[derive(Debug)]
struct UpdateEntry {
    updates: Vec<Update>,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

#[near(serializers=[borsh ])]
#[derive(Debug)]
pub struct ProposedUpdates {
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

impl Default for ProposedUpdates {
    fn default() -> Self {
        Self {
            entries: IterableMap::new(StorageKey::ProposedUpdatesEntries),
            id: UpdateId::default(),
        }
    }
}

impl ProposedUpdates {
    pub fn required_deposit(code: &Option<Vec<u8>>, config: &Option<Config>) -> NearToken {
        required_deposit(bytes_used(code, config))
    }

    /// Propose an update given the new contract code and/or config.
    ///
    /// Returns Some(UpdateId) if the update was successfully proposed, otherwise None.
    pub fn propose(&mut self, code: Option<Vec<u8>>, config: Option<Config>) -> Option<UpdateId> {
        let bytes_used = bytes_used(&code, &config);
        let updates = match (code, config) {
            (Some(contract), Some(config)) => {
                vec![Update::Contract(contract), Update::Config(config)]
            }
            (Some(contract), None) => vec![Update::Contract(contract)],
            (None, Some(config)) => vec![Update::Config(config)],
            (None, None) => return None,
        };

        let id = self.id.generate();
        self.entries.insert(
            id,
            UpdateEntry {
                updates,
                votes: HashSet::new(),
                bytes_used,
            },
        );

        Some(id)
    }

    /// Vote for the update with the given id.
    ///
    /// Returns Some(votes) if the given [`UpdateId`] exists, otherwise None.
    pub fn vote(&mut self, id: &UpdateId, voter: AccountId) -> Option<&HashSet<AccountId>> {
        let entry = self.entries.get_mut(id)?;
        entry.votes.insert(voter);
        Some(&entry.votes)
    }

    fn remove(&mut self, id: &UpdateId) -> Option<UpdateEntry> {
        self.entries.remove(id)
    }

    pub fn do_update(&mut self, id: &UpdateId, gas: Gas) -> Option<Promise> {
        let entry = self.remove(id)?;

        let mut promise = Promise::new(env::current_account_id());
        for update in entry.updates {
            // does it make sense to update both code & config
            // simultaneously?
            match update {
                Update::Contract(code) => {
                    // deploy contract then do a `migrate` call to migrate state.
                    promise = promise.deploy_contract(code).function_call(
                        "migrate".into(),
                        Vec::new(),
                        NearToken::from_near(0),
                        gas,
                    );
                }
                Update::Config(config) => {
                    promise = promise.function_call(
                        "update_config".into(),
                        serde_json::to_vec(&(&config,)).unwrap(),
                        NearToken::from_near(0),
                        gas,
                    );
                }
            }
        }
        Some(promise)
    }
}

fn bytes_used(code: &Option<Vec<u8>>, config: &Option<Config>) -> u128 {
    let mut bytes_used = std::mem::size_of::<UpdateEntry>() as u128;

    // Assume a high max of 128 participant votes per update entry.
    bytes_used += 128 * std::mem::size_of::<AccountId>() as u128;

    if let Some(config) = config {
        let bytes = serde_json::to_vec(&config).unwrap();
        bytes_used += bytes.len() as u128;
    }
    if let Some(code) = code {
        bytes_used += code.len() as u128;
    }
    bytes_used
}

fn required_deposit(bytes_used: u128) -> NearToken {
    env::storage_byte_cost().saturating_mul(bytes_used)
}
