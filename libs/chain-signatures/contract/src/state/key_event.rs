use super::running::RunningContractState;
use crate::errors::VoteError;
use crate::errors::{Error, KeyEventError};
use crate::primitives::key_state::{DKState, KeyEventId, KeyStateProposal};
use crate::primitives::leader::{leader, leaders};
use crate::primitives::participants::{ParticipantId, Participants};
use crate::primitives::thresholds::DKGThreshold;
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{env, near, AccountId, PublicKey};
use near_sdk::{log, BlockHeight};
use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEventInstance {
    key_event_id: KeyEventId,
    start_block: BlockHeight,
    last_vote_block: BlockHeight,
    completed: BTreeSet<AccountId>,
    aborted: BTreeSet<AccountId>, // abort either by leader or by vote.
}

impl KeyEventInstance {
    pub fn new(key_event_id: KeyEventId) -> Self {
        KeyEventInstance {
            key_event_id,
            start_block: env::block_height(),
            last_vote_block: env::block_height(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
        }
    }
    pub fn next_key_event(&self) -> Self {
        KeyEventInstance {
            key_event_id: KeyEventId::new(self.key_event_id.epoch_id(), self.key_event_id.id()),
            start_block: (),
            last_vote_block: (),
            completed: (),
            aborted: (),
        }
    }
    pub fn vote_complete(&mut self, account_id: &AccountId) -> Result<bool, Error> {
        if self.aborted.contains(account_id) {
            Err(VoteError::VoterAlreadyAborted.into())
        } else {
            Ok(self.completed.insert(account_id.clone()))
        }
    }
    pub fn completed(&self) -> &BTreeSet<AccountId> {
        &self.completed
    }
    pub fn vote_abort(&mut self, account_id: &AccountId) -> bool {
        self.completed.remove(account_id);
        self.aborted.insert(account_id.clone())
    }
    pub fn aborted(&self) -> &BTreeSet<AccountId> {
        &self.aborted
    }
    pub fn start(&self) -> BlockHeight {
        self.start
    }
    pub fn id(&self) -> &KeyEventId {
        &self.key_event_id
    }
}

pub struct KeyEvent {
    key_event_id: KeyEventId,
    leader_order: Vec<ParticipantId>,
    current_instance: Option<KeyEventInstance>,
}

impl KeyEvent {
    pub fn new(participants: &Participants, last_key_event_id: Option<&KeyEventId>) -> Self {
        let uid = match last_key_event_id {
            Some(id) => id.next_epoch_id() + id.id(),
            None => 0,
        };
        let leader_order = leaders(participants, uid);
        KeyEvent {
            leader_order,
            current_instance: None,
        }
    }
    pub fn start_next_instance(&mut self) {
        match self.current_instance {
            None => {}
        }
    }
    pub fn active(instance_timeout_blocks: u64, threshold: DKGThreshold) -> bool {}
    pub fn concluded() -> bool {}
    //pub fn succeeded(event_timeout_blocks,threshold) -> bool
    //pub fn active(event_timeout_blocks,threshold) -> bool
}
