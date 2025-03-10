use super::key_event::{self, AuthenticatedLeader, KeyEvent, KeyEventInstance};
use super::running::RunningContractState;
use crate::errors::VoteError;
use crate::errors::{Error, KeyEventError};
use crate::primitives::key_state::{
    AuthenticatedCandidateId, DKState, EpochId, KeyEventAttempt, KeyEventId, KeyStateProposal,
};
use crate::primitives::leader::leader;
use crate::primitives::participants::{ParticipantId, Participants};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{env, near, AccountId, PublicKey};
use near_sdk::{log, BlockHeight};
use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, BTreeSet<AuthenticatedCandidateId>>,
}

impl Default for PkVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl PkVotes {
    pub fn new() -> Self {
        PkVotes {
            votes: BTreeMap::new(),
        }
    }
    pub fn n_votes(&self, public_key: &PublicKey) -> usize {
        self.votes.get(public_key).map_or(0, |votes| votes.len())
    }

    pub fn entry(&mut self, public_key: PublicKey) -> &mut BTreeSet<AuthenticatedCandidateId> {
        self.votes.entry(public_key).or_default()
    }
}

//#[near(serializers=[borsh, json])]
//#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
//pub struct AuthenticatedCandidateId(ParticipantId);
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeygenInstance {
    key_event_instance: KeyEventInstance,
    pk_votes: PkVotes,
    completed: BTreeMap<AuthenticatedCandidateId, PublicKey>,
    aborted: BTreeSet<AuthenticatedCandidateId>,
    started: Option<AuthenticatedLeader>, // indicates if the leader started the computation
}
//#[near(serializers=[borsh, json])]
//#[derive(Debug)]
//pub struct Keygen {
//    key_event: KeyEvent,
//    pk_votes: PkVotes,
//    completed: BTreeMap<AuthenticatedCandidateId, PublicKey>,
//    aborted: BTreeSet<AuthenticatedCandidateId>,
//    //key_event_id: KeyEventId,
//    //active: bool, replace with function: active(event_timeout_blocks,threshold)
//}

impl KeygenInstance {
    pub fn activate(&mut self, leader: AuthenticatedLeader) {
        if self.started.is_none() {
            self.key_event_instance.vote_alive();
        }
        self.started = Some(leader);
    }
    //pub fn succeeded(event_timeout_blocks,threshold) -> bool
    //pub fn active(event_timeout_blocks,threshold) -> bool
    //pub fn deactivate(&mut self) {
    //    self.active = false;
    //}
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.key_event_instance.timed_out(timeout_in_blocks)
    }
    pub fn new() -> Self {
        KeygenInstance {
            key_event_instance: KeyEventInstance::new(),
            pk_votes: PkVotes::new(),
            completed: BTreeMap::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    pub fn next_instance(&self) -> Self {
        KeygenInstance {
            key_event_instance: self.key_event_instance.next(),
            pk_votes: PkVotes::new(),
            completed: BTreeMap::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    /// Commits the vote of `account_id` to `public_key`, removing any previous votes and returning the total number of votes for `public_key`.
    pub fn vote_pk(
        &mut self,
        candidate_id: AuthenticatedCandidateId,
        public_key: PublicKey,
    ) -> Result<u64, Error> {
        // if candidate already aborted, then exit with error
        if self.aborted.contains(&candidate_id) {
            return Err(VoteError::VoterAlreadyAborted.into());
        }

        // label candidate as complete
        if let Some(prev_vote) = self
            .completed
            .insert(candidate_id.clone(), public_key.clone())
        {
            // remove previous vote
            log!("removing previous vote");
            if !self.pk_votes.entry(prev_vote).remove(&candidate_id) {
                return Err(VoteError::InconsistentVotingState.into());
            }
        }
        // vote for public_key
        self.pk_votes.entry(public_key.clone()).insert(candidate_id);
        Ok(self.pk_votes.entry(public_key).len() as u64)
    }

    pub fn remove_vote(&mut self, candidate_id: &AuthenticatedCandidateId) -> bool {
        if let Some(pk) = self.completed.remove(candidate_id) {
            self.pk_votes.entry(pk).remove(candidate_id)
        } else {
            false
        }
    }

    /// Returns the total number of votes for `public_key`
    pub fn n_votes(&self, public_key: &PublicKey) -> u64 {
        self.pk_votes.n_votes(public_key) as u64
    }

    pub fn n_aborts(&self) -> u64 {
        self.aborted.len() as u64
    }
    /// Casts a vote from `candidate_id` to abort the current keygen.
    /// Removes any previous votes by `candidate_id`.
    /// Returns the number of votes received to abort.
    pub fn vote_abort(&mut self, candidate_id: AuthenticatedCandidateId) -> u64 {
        self.remove_vote(&candidate_id);
        self.aborted.insert(candidate_id);
        self.n_aborts()
    }
    pub fn current_attempt(&self) -> KeyEventAttempt {
        self.key_event_instance.current_attempt()
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub key_event: KeyEvent,
    pub current_keygen_instance: KeygenInstance,
}
impl InitializingContractState {
    //pub fn authenticate(&self) -> Result<AuthenticatedCandidateId, Error> {
    //    self.proposed_key_state.authenticate()
    //}
    /// Starts a new keygen instance.
    /// Returns an Error if the signer is not the leader of the current keygen.
    pub fn activate_keygen_instance(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        // update the current instance (including the leader), if required:
        if self
            .current_keygen_instance
            .timed_out(dk_event_timeout_blocks)
        {
            self.current_keygen_instance = self.current_keygen_instance.next_instance();
        }
        // check that the signer is the current leader:
        let leader = self
            .key_event
            .authenticate_leader(self.current_keygen_instance.current_attempt())?;
        // set the keygen as active:
        self.current_keygen_instance.activate(leader);
        Ok(())
    }
    pub fn current_key_event_id(&self) -> KeyEventId {
        KeyEventId::new(
            self.key_event.epoch_id(),
            self.current_keygen_instance.current_attempt(),
        )
    }
    /// Casts a vote for `public_key` in `key_event_id`, removing any prior votes by `signer`.
    /// Fails if `signer` is not a candidate or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        let candidate_id = self.verify_vote(&key_event_id, dk_event_timeout_blocks)?;
        let n_votes = self
            .current_keygen_instance
            .vote_pk(candidate_id, public_key.clone())?;
        // Finally, vote for the reshare instance
        //let n_votes = current.vote_pk(signer, public_key.clone())?;
        if self.key_event.threshold().value() <= n_votes {
            return Ok(Some(RunningContractState {
                key_state: DKState::new(
                    public_key,
                    key_event_id,
                    self.key_event.proposed_threshold_parameters().clone(),
                )?,
                key_state_votes: KeyStateVotes::default(),
            }));
        }
        Ok(None)
    }
    // returns true if the leader started the keygen and the current keygen has not yet timed out.
    pub fn has_active_keygen(&self, dk_event_timeout_blocks: u64) -> bool {
        self.current_keygen_instance.started.is_some()
            && !self
                .current_keygen_instance
                .timed_out(dk_event_timeout_blocks)
    }
    /// Ensures the signer of the transaction is a candidate, that the current reshare is active
    /// and that the `key_event_id` matches.
    fn verify_vote(
        &self,
        key_event_id: &KeyEventId,
        dk_event_timeout_blocks: u64,
    ) -> Result<AuthenticatedCandidateId, Error> {
        // ensure the signer is a candidate
        let candidate_id = self.key_event.authenticate_candidate()?;
        // ensure the keygen was started and is active
        if !self.current_keygen_instance.started.is_some()
            || self
                .current_keygen_instance
                .timed_out(dk_event_timeout_blocks)
        {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        }
        // Ensure the key_event_id matches
        if self.current_key_event_id() != *key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        Ok(candidate_id)
    }
    fn vote_abort(
        &mut self,
        key_event_id: KeyEventId,
        dk_event_timeout_blocks: BlockHeight,
    ) -> Result<bool, Error> {
        let candidate_id = self.verify_vote(&key_event_id, dk_event_timeout_blocks)?;
        let n_votes = self.current_keygen_instance.vote_abort(candidate_id);
        if self
            .key_event
            .proposed_threshold_parameters()
            .n_participants()
            - n_votes
            < self.key_event.threshold().value()
        {
            // we can't achieve threshold votes anymore, abort this keygen and reset
            self.current_keygen_instance = self.current_keygen_instance.next_instance();
            return Ok(true);
        }
        Ok(false)
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(state: &legacy_contract::InitializingContractState) -> Self {
        InitializingContractState {
            key_event: KeyEvent::new(EpochId::new(0), state.into()),
            current_keygen_instance: KeygenInstance::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    //
    //pub fn start_keygen_instance(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
    //
    //pub fn vote_pk(
    //pub fn has_active_keygen(&self, dk_event_timeout_blocks: u64) -> bool {
    //pub fn keygen_leader(&self) -> AccountId {
    //pub fn abort()
    //migrating
    //use super::*;
    //use crate::state::tests::test_utils::gen_account_id;
    //use crate::state::tests::test_utils::gen_pk;
    //use near_sdk::{AccountId, PublicKey};

    //#[test]
    //fn test_keygen_instance() {
    //    let leader_account: AccountId = gen_account_id();
    //    //let key_event_id = KeyEventId::new(1, leader_account.clone());
    //    let mut instance = Keygen::new(key_event_id);
    //    let account_id = gen_account_id();
    //    let pk1: PublicKey = gen_pk();
    //    let votes = instance.vote_pk(account_id.clone(), pk1.clone()).unwrap();
    //    assert_eq!(votes, 1);
    //    assert_eq!(instance.n_votes(&pk1), 1);

    //    let pk2: PublicKey = gen_pk();
    //    let votes = instance.vote_pk(account_id.clone(), pk2.clone()).unwrap();
    //    assert_eq!(votes, 1);
    //    assert_eq!(instance.n_votes(&pk1), 0);
    //    assert_eq!(instance.n_votes(&pk2), 1);
    //    assert!(instance.remove_vote(&account_id));
    //    assert_eq!(instance.abort(account_id.clone()), 1);
    //    assert!(instance.vote_pk(account_id.clone(), pk1.clone()).is_err());
    //    let account_id = gen_account_id();
    //    let votes = instance.vote_pk(account_id.clone(), pk1.clone()).unwrap();
    //    assert_eq!(votes, 1);
    //    assert_eq!(instance.n_votes(&pk1), 1);
    //    assert_eq!(instance.n_votes(&pk2), 0);
    //}
}
