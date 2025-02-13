use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, log, AccountId, PublicKey};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::errors::{Error, InvalidCandidateSet, ReshareError};
use crate::errors::{InvalidState, VoteError};
use crate::primitives::{
    Candidates, KeyEventId, KeyState, KeyStateProposal, KeygenInstance, ParticipantInfoV2,
    Participants, PkVotes, ReshareInstance, Votes,
};

#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize)]
pub struct InitializingContractStateV2 {
    pub proposed_key_state: KeyStateProposal,
    pub current_keygen_instance: Option<KeygenInstance>,
}
impl InitializingContractStateV2 {
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
            return Err(ReshareError::NoOngoingReshare.into()); // todo: fix errors and clean them up
        }
        // Ensure the key_event_id matches
        let current = self.current_keygen_instance.as_mut().unwrap();
        if current.key_event_id != key_event_id {
            return Err(ReshareError::KeyEventIdMismatch.into());
        }
        // Finally, vote for the reshare instance
        let n_votes = current.vote_completed(signer, public_key)?;
        if self.proposed_key_state.key_event_threshold <= n_votes {
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
            current_keygen.key_event_id.random_uid
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
        // ensure this function is called by the leader
        if signer != self.keygen_leader() {
            return Err(ReshareError::SignerNotLeader.into());
        }

        // ensure there is no active resharing
        if self.has_active_keygen(reshare_timeout_blocks) {
            return Err(ReshareError::ReshareOngoing.into());
        }

        // generate new key event id
        let key_event_id = KeyEventId::new(0, signer);
        // reset resharing instance:
        self.current_keygen_instance = Some(KeygenInstance::new(key_event_id));
        Ok(())
    }
}

impl From<&InitializingContractState> for InitializingContractStateV2 {
    fn from(state: &InitializingContractState) -> Self {
        InitializingContractStateV2 {
            proposed_key_state: state.into(),
            current_keygen_instance: None,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize)]
pub struct KeyStateVotes {
    pub votes_by_proposal: BTreeMap<KeyStateProposal, HashSet<AccountId>>,
    pub proposal_by_account: BTreeMap<AccountId, KeyStateProposal>,
}

impl KeyStateVotes {
    /// removes the vote submitted by `account_id` from the state.
    /// returns true if the vote was removed and false else.
    pub fn remove_vote(&mut self, account_id: &AccountId) -> bool {
        if let Some(proposal) = self.proposal_by_account.remove(account_id) {
            self.votes_by_proposal
                .get_mut(&proposal)
                .map_or(false, |vote_set| vote_set.remove(account_id));
        }
        false
    }
    /// Registers a vote by `account_id` for `proposal`, inserts `proposal` if necessary.
    /// Returns an Error if `account_id` already registered a vote.
    /// Returns the number of votes for the current proposal.
    pub fn vote(
        &mut self,
        proposal: &KeyStateProposal,
        account_id: &AccountId,
    ) -> Result<u64, Error> {
        if self
            .proposal_by_account
            .insert(account_id.clone(), proposal.clone())
            .is_some()
        {
            return Err(VoteError::ParticipantVoteAlreadyRegistered.into());
        }
        Ok(self
            .votes_by_proposal
            .entry(proposal.clone())
            .and_modify(|votes| {
                votes.insert(account_id.clone());
            })
            .or_insert({
                let mut x = HashSet::new();
                x.insert(account_id.clone());
                x
            })
            .len() as u64)
    }
    pub fn new() -> Self {
        KeyStateVotes {
            votes_by_proposal: BTreeMap::new(),
            proposal_by_account: BTreeMap::new(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize)]
pub struct RunningContractStateV2 {
    pub key_state: KeyState,
    pub key_state_votes: KeyStateVotes,
}
impl From<&RunningContractState> for RunningContractStateV2 {
    fn from(state: &RunningContractState) -> Self {
        RunningContractStateV2 {
            key_state: state.into(),
            key_state_votes: KeyStateVotes::new(),
        }
    }
}

impl From<&ResharingContractStateV2> for RunningContractStateV2 {
    fn from(state: &ResharingContractStateV2) -> Self {
        RunningContractStateV2 {
            key_state: KeyState::from((
                &state.proposed_key_state,
                &state.current_state.key_state.public_key,
                &state.current_reshare.as_ref().unwrap().key_event_id,
            )),
            key_state_votes: KeyStateVotes::new(),
        }
    }
}

impl RunningContractStateV2 {
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
        return self.key_state.is_participant(account_id);
    }

    /// returns true if threshold has been reached
    pub fn vote_key_state_proposal(&mut self, proposal: &KeyStateProposal) -> Result<bool, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.is_participant(&signer) {
            return Err(VoteError::VoterNotParticipant.into());
        }
        // ensure the proposed threshold is valid:
        proposal.threshold_is_valid();

        // ensure there are enough old participant in the new participant set:
        //
        let new_participant_set: BTreeSet<AccountId> = proposal
            .proposed_threshold_parameters
            .participants
            .keys()
            .cloned()
            .collect();
        let old_participant_set: BTreeSet<AccountId> =
            self.key_state.participants().keys().cloned().collect();
        let n_old = new_participant_set
            .intersection(&old_participant_set)
            .count() as u64;
        if n_old < self.key_state.threshold() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }

        // remove any previous votes submitted by the signer:
        if self.key_state_votes.remove_vote(&signer) {
            log!("removed one vote for signer");
        }

        // finally, vote. Propagate any errors
        let n_votes = self.key_state_votes.vote(proposal, &signer)?;
        if self.key_state.threshold() <= n_votes {
            return Ok(true);
        }
        return Ok(false);
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractStateV2 {
    pub current_state: RunningContractStateV2,
    pub proposed_key_state: KeyStateProposal,
    pub current_reshare: Option<ReshareInstance>,
}

impl From<&ResharingContractState> for ResharingContractStateV2 {
    fn from(state: &ResharingContractState) -> Self {
        ResharingContractStateV2 {
            // todo: test what happens when you update during keyshare. specifically, when you
            // update while a reshare has been initiated
            current_state: RunningContractStateV2 {
                key_state: state.into(),
                key_state_votes: KeyStateVotes::new(),
            },
            proposed_key_state: state.into(),
            current_reshare: None,
        }
    }
}
impl From<(&RunningContractStateV2, &KeyStateProposal)> for ResharingContractStateV2 {
    fn from((current, proposal): (&RunningContractStateV2, &KeyStateProposal)) -> Self {
        ResharingContractStateV2 {
            current_state: RunningContractStateV2 {
                key_state: current.key_state.clone(),
                key_state_votes: KeyStateVotes::new(),
            },
            proposed_key_state: proposal.clone(),
            current_reshare: None,
        }
    }
}
impl From<(&ResharingContractStateV2, &KeyStateProposal)> for ResharingContractStateV2 {
    fn from((current, proposal): (&ResharingContractStateV2, &KeyStateProposal)) -> Self {
        ResharingContractStateV2 {
            current_state: RunningContractStateV2 {
                key_state: current.current_state.key_state.clone(),
                key_state_votes: KeyStateVotes::new(),
            },
            proposed_key_state: proposal.clone(),
            current_reshare: None,
        }
    }
}
impl ResharingContractStateV2 {
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
    /// set of proposed participants for the next epoch
    pub fn proposed_participants(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
        self.proposed_key_state.proposed_participants()
    }
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
impl ResharingContractStateV2 {
    /// returns the uid of the last key event
    fn last_uid(&self) -> u64 {
        if let Some(current_resharing) = &self.current_reshare {
            current_resharing.key_event_id.random_uid
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
impl ResharingContractStateV2 {
    /// Aborts the current reshare. Returns an error if there is no active reshare
    fn abort_reshare(&mut self) -> Result<(), Error> {
        // ensure this function is called by the leader
        if env::signer_account_id() != self.reshare_leader() {
            return Err(ReshareError::SignerNotLeader.into());
        }
        self.current_reshare.as_mut().map_or(
            Err(ReshareError::NoOngoingReshare.into()),
            |current| {
                current.active = false;
                Ok(())
            },
        )
    }

    // starts a new reshare instance if there is no active reshare instance
    pub fn start_reshare_instance(
        &mut self,
        new_epoch_id: u64,
        reshare_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let signer = env::signer_account_id();
        // ensure this function is called by the leader
        if signer != self.reshare_leader() {
            return Err(ReshareError::SignerNotLeader.into());
        }

        // ensure there is no active resharing
        if self.has_active_reshare(reshare_timeout_blocks) {
            return Err(ReshareError::ReshareOngoing.into());
        }

        // ensure epoch_id matches:
        if self.current_state.next_epoch_id() != new_epoch_id {
            return Err(ReshareError::EpochMismatch.message(format!(
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
impl ResharingContractStateV2 {
    /// Returns true if `key_event_threshold` has been reached for this `key_event`
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
        reshare_timeout_blocks: u64,
    ) -> Result<bool, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.is_old_participant(&signer) && !self.is_new_participant(&signer) {
            return Err(ReshareError::SignerNotParticipant.into());
        }
        // ensure there is an active reshare
        if !self.has_active_reshare(reshare_timeout_blocks) {
            return Err(ReshareError::NoOngoingReshare.into());
        }
        // Ensure the key_event_id matches
        let current = self.current_reshare.as_mut().unwrap();
        if current.key_event_id != key_event_id {
            return Err(ReshareError::KeyEventIdMismatch.into());
        }
        // Finally, vote for the reshare instance
        let n_votes = current.vote_completed(signer);
        if self.proposed_key_state.key_event_threshold <= n_votes {
            return Ok(true);
        }
        Ok(false)
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractStateV2 {
    NotInitialized,
    Initializing(InitializingContractStateV2),
    Running(RunningContractStateV2),
    Resharing(ResharingContractStateV2),
}

impl From<&ProtocolContractState> for ProtocolContractStateV2 {
    fn from(protocol_state: &ProtocolContractState) -> Self {
        // can this be simplified?
        match &protocol_state {
            ProtocolContractState::NotInitialized => ProtocolContractStateV2::NotInitialized,
            ProtocolContractState::Initializing(state) => {
                ProtocolContractStateV2::Initializing(state.into())
            }
            ProtocolContractState::Running(state) => ProtocolContractStateV2::Running(state.into()),
            ProtocolContractState::Resharing(state) => {
                ProtocolContractStateV2::Resharing(state.into())
            }
        }
    }
}

impl ProtocolContractStateV2 {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractStateV2::NotInitialized => "NotInitialized",
            ProtocolContractStateV2::Initializing(_) => "Initializing",
            ProtocolContractStateV2::Running(_) => "Running",
            ProtocolContractStateV2::Resharing(_) => "Resharing",
        }
    }
    pub fn is_participant(&self, voter: AccountId) -> Result<AccountId, Error> {
        match &self {
            ProtocolContractStateV2::Initializing(state) => {
                if !state.proposed_key_state.is_proposed(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractStateV2::Running(state) => {
                if !state.key_state.is_participant(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractStateV2::Resharing(state) => {
                if !state.is_old_participant(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractStateV2::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        }
        Ok(voter)
    }
}

/** Deprecated V0 and V1 contract state. Can be removed eventually. **/
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
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
                if !state.candidates.contains_key(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::Running(state) => {
                if !state.participants.contains_key(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::Resharing(state) => {
                if !state.old_participants.contains_key(&voter) {
                    return Err(VoteError::VoterNotParticipant.into());
                }
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        }
        Ok(voter)
    }
    pub fn threshold(&self) -> Result<usize, Error> {
        match self {
            ProtocolContractState::Initializing(state) => Ok(state.threshold),
            ProtocolContractState::Running(state) => Ok(state.threshold),
            ProtocolContractState::Resharing(state) => Ok(state.threshold),
            ProtocolContractState::NotInitialized => {
                Err(InvalidState::UnexpectedProtocolState.message(self.name()))
            }
        }
    }
}
