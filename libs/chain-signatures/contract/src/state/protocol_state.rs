use super::key_state::{DKState, KeyEventId, KeyStateProposal};
use super::votes::{KeyStateVotes, PkVotes};
use crate::errors::{Error, InvalidCandidateSet, KeyEventError};
use crate::errors::{InvalidState, VoteError};
use near_sdk::{env, log, near, AccountId, PublicKey};
use std::collections::{BTreeMap, BTreeSet};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeygenInstance {
    pub key_event_id: KeyEventId,
    pub participants_completed: BTreeMap<AccountId, PublicKey>,
    pub pk_votes: PkVotes,
    pub active: bool,
}
impl KeygenInstance {
    pub fn active(&self, timeout_in_blocks: u64) -> bool {
        self.active && !self.key_event_id.timed_out(timeout_in_blocks)
    }
    pub fn new(key_event_id: KeyEventId) -> Self {
        KeygenInstance {
            key_event_id,
            participants_completed: BTreeMap::new(),
            pk_votes: PkVotes::new(),
            active: true,
        }
    }
    /// Adds `account_id` to the current set of votes and returns the number of votes collected.
    pub fn vote_completed(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<u64, Error> {
        if self
            .participants_completed
            .insert(account_id.clone(), public_key.clone())
            .is_some()
        {
            // todo: do we want a remove mechanism, or only allow a single vote per participant and
            // require timeout?
            return Err(VoteError::ParticipantVoteAlreadyRegistered.into()); // todo: should we just remove?
        }
        self.pk_votes.entry(public_key.clone()).insert(account_id);
        Ok(self.pk_votes.entry(public_key).len() as u64)
    }
}
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
pub struct InitializingContractState {
    pub proposed_key_state: KeyStateProposal,
    pub current_keygen_instance: Option<KeygenInstance>,
}
impl InitializingContractState {
    pub fn vote_keygen(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        reshare_timeout_blocks: u64,
    ) -> Result<bool, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.is_candidate(&signer) {
            return Err(VoteError::VoterNotParticipant.into());
        }
        // ensure there is an active reshare
        if !self.has_active_keygen(reshare_timeout_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into()); // todo: fix errors and clean them up
        }
        // Ensure the key_event_id matches
        let current = self.current_keygen_instance.as_mut().unwrap();
        if current.key_event_id != key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        // Finally, vote for the reshare instance
        let n_votes = current.vote_completed(signer, public_key)?;
        if self.proposed_key_state.key_event_threshold().value() <= n_votes {
            return Ok(true);
        }
        Ok(false)
    }
    // returns true if there is an active reshare instance
    pub fn has_active_keygen(&self, reshare_timeout_blocks: u64) -> bool {
        match &self.current_keygen_instance {
            None => false,
            Some(current) => current.active(reshare_timeout_blocks),
        }
    }
    fn last_uid(&self) -> u64 {
        if let Some(current_keygen) = &self.current_keygen_instance {
            current_keygen.key_event_id.uid()
        } else {
            0
        }
    }
    pub fn is_candidate(&self, account_id: &AccountId) -> bool {
        self.proposed_key_state.is_proposed(account_id)
    }
    pub fn get_candidate_by_index(&self, idx: u64) -> Result<AccountId, Error> {
        self.proposed_key_state.candidate_by_index(idx)
    }
    pub fn n_proposed_participants(&self) -> u64 {
        self.proposed_key_state.n_proposed_participants()
    }
    /// returns the seed%len(participants)-th in the participants set.
    fn get_leader_from_seed(&self, seed: u64) -> Result<AccountId, Error> {
        let leader_idx = seed % self.n_proposed_participants();
        self.get_candidate_by_index(leader_idx)
    }
    pub fn keygen_leader(&self) -> AccountId {
        match self.get_leader_from_seed(self.last_uid()) {
            Ok(res) => res,
            Err(err) => env::panic_str(&err.to_string()),
        }
    }
    pub fn start_keygen_instance(&mut self, reshare_timeout_blocks: u64) -> Result<(), Error> {
        let signer = env::signer_account_id();
        // ensure there is no active resharing
        if self.has_active_keygen(reshare_timeout_blocks) {
            return Err(KeyEventError::ActiveKeyEvent.into());
        }
        // ensure this function is called by the leader
        if signer != self.keygen_leader() {
            return Err(VoteError::VoterNotLeader.into());
        }

        // generate new key event id
        let key_event_id = KeyEventId::new(0, signer);
        // reset resharing instance:
        self.current_keygen_instance = Some(KeygenInstance::new(key_event_id));
        Ok(())
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(state: &legacy_contract::InitializingContractState) -> Self {
        InitializingContractState {
            proposed_key_state: state.into(),
            current_keygen_instance: None,
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct RunningContractState {
    pub key_state: DKState,
    pub key_state_votes: KeyStateVotes,
}
impl From<&legacy_contract::RunningContractState> for RunningContractState {
    fn from(state: &legacy_contract::RunningContractState) -> Self {
        RunningContractState {
            key_state: state.into(),
            key_state_votes: KeyStateVotes::default(),
        }
    }
}

impl From<&ResharingContractState> for RunningContractState {
    fn from(state: &ResharingContractState) -> Self {
        RunningContractState {
            key_state: DKState::from((
                &state.proposed_key_state,
                &state.current_state.key_state.public_key,
                &state.current_reshare.as_ref().unwrap().key_event_id,
            )),
            key_state_votes: KeyStateVotes::default(),
        }
    }
}

impl RunningContractState {
    pub fn epoch_id(&self) -> u64 {
        self.key_state.epoch_id()
    }
    pub fn next_epoch_id(&self) -> u64 {
        self.key_state.next_epoch_id()
    }
    pub fn last_uid(&self) -> u64 {
        self.key_state.uid()
    }
    /// returns true if `account_id` is in the participant set
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.key_state.is_participant(account_id)
    }

    /// returns true if threshold has been reached
    pub fn vote_key_state_proposal(&mut self, proposal: &KeyStateProposal) -> Result<bool, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.is_participant(&signer) {
            return Err(VoteError::VoterNotParticipant.into());
        }
        // ensure the proposed threshold is valid:
        proposal.validate()?;

        // ensure there are enough old participant in the new participant set:
        //
        let new_participant_set: BTreeSet<AccountId> =
            proposal.candidates().keys().cloned().collect();
        let old_participant_set: BTreeSet<AccountId> =
            self.key_state.participants().keys().cloned().collect();
        let n_old = new_participant_set
            .intersection(&old_participant_set)
            .count() as u64;
        if n_old < self.key_state.threshold().value() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }

        // remove any previous votes submitted by the signer:
        if self.key_state_votes.remove_vote(&signer) {
            log!("removed one vote for signer");
        }

        // finally, vote. Propagate any errors
        let n_votes = self.key_state_votes.vote(proposal, &signer)?;
        if self.key_state.threshold().value() <= n_votes {
            return Ok(true);
        }
        Ok(false)
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
impl From<(&RunningContractState, &KeyStateProposal)> for ResharingContractState {
    fn from((current, proposal): (&RunningContractState, &KeyStateProposal)) -> Self {
        ResharingContractState {
            current_state: RunningContractState {
                key_state: current.key_state.clone(),
                key_state_votes: KeyStateVotes::default(),
            },
            proposed_key_state: proposal.clone(),
            current_reshare: None,
        }
    }
}
impl From<(&ResharingContractState, &KeyStateProposal)> for ResharingContractState {
    fn from((current, proposal): (&ResharingContractState, &KeyStateProposal)) -> Self {
        ResharingContractState {
            current_state: RunningContractState {
                key_state: current.current_state.key_state.clone(),
                key_state_votes: KeyStateVotes::default(),
            },
            proposed_key_state: proposal.clone(),
            current_reshare: None,
        }
    }
}
impl ResharingContractState {
    pub fn vote_key_state_proposal(&mut self, proposal: &KeyStateProposal) -> Result<bool, Error> {
        self.current_state.vote_key_state_proposal(proposal)
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
    //pub fn proposed_participants(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
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
    pub fn has_active_reshare(&self, reshare_timeout_blocks: u64) -> bool {
        match &self.current_reshare {
            None => false,
            Some(current) => current.active(reshare_timeout_blocks),
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
        reshare_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let signer = env::signer_account_id();
        // ensure this function is called by the leader
        if signer != self.reshare_leader() {
            return Err(VoteError::VoterNotLeader.into());
        }

        // ensure there is no active resharing
        if self.has_active_reshare(reshare_timeout_blocks) {
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
        reshare_timeout_blocks: u64,
    ) -> Result<bool, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.is_old_participant(&signer) && !self.is_new_participant(&signer) {
            return Err(VoteError::VoterNotParticipantNorProposedParticipant.into());
        }
        // ensure there is an active reshare
        if !self.has_active_reshare(reshare_timeout_blocks) {
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
            return Ok(true);
        }
        Ok(false)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl From<&legacy_contract::ProtocolContractState> for ProtocolContractState {
    fn from(protocol_state: &legacy_contract::ProtocolContractState) -> Self {
        // can this be simplified?
        match &protocol_state {
            legacy_contract::ProtocolContractState::NotInitialized => {
                ProtocolContractState::NotInitialized
            }
            legacy_contract::ProtocolContractState::Initializing(state) => {
                ProtocolContractState::Initializing(state.into())
            }
            legacy_contract::ProtocolContractState::Running(state) => {
                ProtocolContractState::Running(state.into())
            }
            legacy_contract::ProtocolContractState::Resharing(state) => {
                ProtocolContractState::Resharing(state.into())
            }
        }
    }
}

impl ProtocolContractState {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractState::NotInitialized => "NotInitialized",
            ProtocolContractState::Initializing(_) => "Initializing",
            ProtocolContractState::Running(_) => "Running",
            ProtocolContractState::Resharing(_) => "Resharing",
        }
    }
    pub fn is_participant(&self, voter: AccountId) -> Result<AccountId, Error> {
        match &self {
            ProtocolContractState::Initializing(state) => {
                if !state.proposed_key_state.is_proposed(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::Running(state) => {
                if !state.key_state.is_participant(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::Resharing(state) => {
                if !state.is_old_participant(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        }
        Ok(voter)
    }
}
