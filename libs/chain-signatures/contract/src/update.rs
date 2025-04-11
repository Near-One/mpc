use std::collections::HashSet;
use std::hash::Hash;

use crate::config::Config;
use crate::storage_keys::StorageKey;

use crate::errors::{ConversionError, Error};
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

impl TryFrom<ProposeUpdateArgs> for Update {
    type Error = Error;

    fn try_from(value: ProposeUpdateArgs) -> Result<Self, Self::Error> {
        let ProposeUpdateArgs { code, config } = value;
        let update = match (code, config) {
            (Some(contract), None) => Update::Contract(contract),
            (None, Some(config)) => Update::Config(config),
            (Some(_), Some(_)) => {
                return Err(ConversionError::DataConversion
                    .message("Code and config updates are not allowed at the same time"))
            }
            _ => {
                return Err(ConversionError::DataConversion
                    .message("Expected either code or config update, received none of them"))
            }
        };
        Ok(update)
    }
}

#[near(serializers=[borsh ])]
#[derive(Debug)]
struct UpdateEntry {
    update: Update,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

#[near(serializers=[borsh ])]
#[derive(Debug)]
pub struct ProposedUpdates {
    vote_by_participant: IterableMap<AccountId, UpdateId>,
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

impl Default for ProposedUpdates {
    fn default() -> Self {
        Self {
            vote_by_participant: IterableMap::new(StorageKey::ProposedUpdatesVotesV2),
            entries: IterableMap::new(StorageKey::ProposedUpdatesEntriesV2),
            id: UpdateId::default(),
        }
    }
}

impl ProposedUpdates {
    pub fn required_deposit(update: &Update) -> NearToken {
        required_deposit(bytes_used(update))
    }

    /// Propose an update given the new contract code and/or config.
    ///
    /// Returns UpdateId
    pub fn propose(&mut self, update: Update) -> UpdateId {
        let bytes_used = bytes_used(&update);

        let id = self.id.generate();
        self.entries.insert(
            id,
            UpdateEntry {
                update,
                votes: HashSet::new(),
                bytes_used,
            },
        );

        id
    }

    /// Vote for the update with the given id.
    ///
    /// Returns Some(votes) if the given [`UpdateId`] exists, otherwise None.
    pub fn vote(&mut self, id: &UpdateId, voter: AccountId) -> Option<&HashSet<AccountId>> {
        // If participant has voted before, remove their vote
        if let Some(previous_id) = self.vote_by_participant.get(&voter) {
            self.entries.get_mut(previous_id)?.votes.remove(&voter);
        }
        self.vote_by_participant.insert(voter.clone(), *id);

        let entry = self.entries.get_mut(id)?;
        entry.votes.insert(voter);
        Some(&entry.votes)
    }

    pub fn do_update(&mut self, id: &UpdateId, gas: Gas) -> Option<Promise> {
        let entry = self.entries.remove(id)?;

        // Clear all entries as they might be no longer valid
        self.entries.clear();
        self.vote_by_participant.clear();

        let mut promise = Promise::new(env::current_account_id());
        match entry.update {
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
        Some(promise)
    }
}

fn bytes_used(update: &Update) -> u128 {
    let mut bytes_used = std::mem::size_of::<UpdateEntry>() as u128;

    // Assume a high max of 128 participant votes per update entry.
    bytes_used += 128 * std::mem::size_of::<AccountId>() as u128;

    match update {
        Update::Contract(code) => {
            bytes_used += code.len() as u128;
        }
        Update::Config(config) => {
            let bytes = serde_json::to_vec(&config).unwrap();
            bytes_used += bytes.len() as u128;
        }
    }

    bytes_used
}

fn required_deposit(bytes_used: u128) -> NearToken {
    env::storage_byte_cost().saturating_mul(bytes_used)
}
