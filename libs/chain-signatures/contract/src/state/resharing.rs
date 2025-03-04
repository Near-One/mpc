use super::key_state::{DKState, KeyEventId, KeyStateProposal};
use super::running::RunningContractState;
use super::votes::KeyStateVotes;
use crate::errors::VoteError;
use crate::errors::{Error, KeyEventError};
use near_sdk::{env, near, AccountId};
use std::collections::BTreeSet;
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq)]
pub struct ReshareInstance {
    pub key_event_id: KeyEventId,
    pub participants_completed: BTreeSet<AccountId>,
    pub active: bool,
}

impl ReshareInstance {
    pub fn active(&self, timeout_in_blocks: u64) -> bool {
        self.active && !self.key_event_id.timed_out(timeout_in_blocks)
    }
    pub fn new(key_event_id: KeyEventId) -> Self {
        ReshareInstance {
            key_event_id,
            participants_completed: BTreeSet::new(),
            active: true,
        }
    }
    /// Adds `account_id` to the current set of votes and returns the number of votes collected.
    pub fn vote_completed(&mut self, account_id: AccountId) -> u64 {
        self.participants_completed.insert(account_id);
        self.participants_completed.len() as u64
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct ResharingContractState {
    pub current_state: RunningContractState,
    pub proposed_key_state: KeyStateProposal,
    pub current_reshare: Option<ReshareInstance>,
}

impl From<&legacy_contract::ResharingContractState> for ResharingContractState {
    fn from(state: &legacy_contract::ResharingContractState) -> Self {
        ResharingContractState {
            // todo: test what happens when you update during keyshare. specifically, when you
            // update while a reshare has been initiated
            current_state: RunningContractState {
                key_state: state.into(),
                key_state_votes: KeyStateVotes::default(),
            },
            proposed_key_state: state.into(),
            current_reshare: None,
        }
    }
}

impl ResharingContractState {
    pub fn vote_new_key_state(
        &mut self,
        proposal: &KeyStateProposal,
    ) -> Result<Option<ResharingContractState>, Error> {
        if self.current_state.vote_key_state_proposal(proposal)? {
            return Ok(Some(ResharingContractState {
                current_state: RunningContractState {
                    key_state: self.current_state.key_state.clone(),
                    key_state_votes: KeyStateVotes::default(),
                },
                proposed_key_state: proposal.clone(),
                current_reshare: None,
            }));
        }
        Ok(None)
    }

    /// returns the AccountId of the current reshare leader
    pub fn reshare_leader(&self) -> AccountId {
        match self.get_leader_from_seed(self.last_uid()) {
            Ok(res) => res,
            Err(err) => env::panic_str(&err.to_string()),
        }
    }
    pub fn get_candidate_by_index(&self, idx: u64) -> Result<AccountId, Error> {
        self.proposed_key_state.candidate_by_index(idx)
    }
    pub fn n_proposed_participants(&self) -> u64 {
        self.proposed_key_state.n_proposed_participants()
    }
    ///// set of proposed participants for the next epoch
    //pub fn proposed_participants(&self) -> &BTreeMap<AccountId, ParticipantInfo> {
    //    self.proposed_key_state.proposed_participants()
    //}
    // returns true if account_id is a participant in the next epoch
    pub fn is_new_participant(&self, account_id: &AccountId) -> bool {
        self.proposed_key_state.is_proposed(account_id)
    }
    // returns true if account_id is a participant in the current epoch
    pub fn is_old_participant(&self, account_id: &AccountId) -> bool {
        self.current_state.is_participant(account_id)
    }
    // returns true if there is an active reshare instance
    pub fn has_active_reshare(&self, dk_event_timeout_blocks: u64) -> bool {
        match &self.current_reshare {
            None => false,
            Some(current) => current.active(dk_event_timeout_blocks),
        }
    }
    /// Returns true if `account_id` is the leader for this reshare
    pub fn is_leader(&self, account_id: &AccountId) -> bool {
        *account_id != self.reshare_leader()
    }
}

/// Helper functions
impl ResharingContractState {
    /// returns the uid of the last key event
    fn last_uid(&self) -> u64 {
        if let Some(current_resharing) = &self.current_reshare {
            current_resharing.key_event_id.uid()
        } else {
            self.current_state.last_uid()
        }
    }

    /// returns the seed%len(participants)-th in the participants set.
    fn get_leader_from_seed(&self, seed: u64) -> Result<AccountId, Error> {
        let leader_idx = seed % self.n_proposed_participants();
        self.get_candidate_by_index(leader_idx)
    }
}

// Leader API. Below functions shall only be called by a leader account
impl ResharingContractState {
    //    /// Aborts the current reshare. Returns an error if there is no active reshare
    //    fn abort_reshare(&mut self) -> Result<(), Error> {
    //        // ensure this function is called by the leader
    //        if env::signer_account_id() != self.reshare_leader() {
    //            return Err(KeyEventError::SignerNotLeader.into());
    //        }
    //        self.current_reshare.as_mut().map_or(
    //            Err(KeyEventError::NoActiveKeyEvent.into()),
    //            |current| {
    //                current.active = false;
    //                Ok(())
    //            },
    //        )
    //    }
    //
    // starts a new reshare instance if there is no active reshare instance
    pub fn start_reshare_instance(
        &mut self,
        new_epoch_id: u64,
        dk_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let signer = env::signer_account_id();
        // ensure this function is called by the leader
        if signer != self.reshare_leader() {
            return Err(VoteError::VoterNotLeader.into());
        }

        // ensure there is no active resharing
        if self.has_active_reshare(dk_event_timeout_blocks) {
            return Err(KeyEventError::ActiveKeyEvent.into());
        }

        // ensure epoch_id matches:
        if self.current_state.next_epoch_id() != new_epoch_id {
            return Err(KeyEventError::EpochMismatch.message(format!(
                "current epoch id: {}, new epoch id: {}",
                self.current_state.epoch_id(),
                new_epoch_id
            )));
        }

        // generate new key event id
        let key_event_id = KeyEventId::new(new_epoch_id, signer);
        // reset resharing instance:
        self.current_reshare = Some(ReshareInstance::new(key_event_id));
        Ok(())
    }
}

// Participants API
impl ResharingContractState {
    /// Returns true if `key_event_threshold` has been reached for this `key_event`
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.is_old_participant(&signer) && !self.is_new_participant(&signer) {
            return Err(VoteError::VoterNotParticipantNorProposedParticipant.into());
        }
        // ensure there is an active reshare
        if !self.has_active_reshare(dk_event_timeout_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        }
        // Ensure the key_event_id matches
        let current = self.current_reshare.as_mut().unwrap();
        if current.key_event_id != key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        // Finally, vote for the reshare instance
        let n_votes = current.vote_completed(signer);
        if self.proposed_key_state.key_event_threshold().value() <= n_votes {
            return Ok(Some(RunningContractState {
                key_state: DKState::from((
                    &self.proposed_key_state,
                    &self.current_state.key_state.public_key,
                    &self.current_reshare.as_ref().unwrap().key_event_id,
                )),
                key_state_votes: KeyStateVotes::default(),
            }));
        }
        Ok(None)
    }
}
