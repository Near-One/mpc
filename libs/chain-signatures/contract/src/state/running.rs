use super::key_event::KeyEventState;
use super::resharing::ResharingContractState;
use crate::errors::{Error, InvalidCandidateSet};
use crate::primitives::key_state::{
    AuthenticatedParticipantId, DKState, EpochId, KeyStateProposal,
};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{log, near, AccountId, PublicKey};
use std::collections::BTreeSet;

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

impl RunningContractState {
    pub fn authenticate_participant(&self) -> Result<AuthenticatedParticipantId, Error> {
        self.key_state.authenticate()
    }
    pub fn public_key(&self) -> &PublicKey {
        self.key_state.public_key()
    }
    pub fn epoch_id(&self) -> EpochId {
        self.key_state.epoch_id()
    }
    /// returns true if `account_id` is in the participant set
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.key_state.is_participant(account_id)
    }
    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContract state if the proposal is accepted.
    pub fn vote_new_key_state(
        &mut self,
        proposal: &KeyStateProposal,
    ) -> Result<Option<ResharingContractState>, Error> {
        if self.vote_key_state_proposal(proposal)? {
            return Ok(Some(ResharingContractState {
                current_state: RunningContractState {
                    key_state: self.key_state.clone(),
                    key_state_votes: KeyStateVotes::default(),
                },
                event_state: KeyEventState::new(self.epoch_id().next(), proposal.clone()),
            }));
        }
        Ok(None)
    }
    /// Casts a vote for `proposal`, removing any previous votes by `env::signer_account_id()`.
    /// Fails if the proposal is invalid or the signer is not a participant.
    /// Returns true if the proposal reached `threshold` number of votes.
    pub fn vote_key_state_proposal(&mut self, proposal: &KeyStateProposal) -> Result<bool, Error> {
        // ensure the signer is a participant
        let participant = self.key_state.authenticate()?;
        // ensure the proposed threshold parameters are valid:
        proposal.validate()?;
        // ensure there are enough old participant in the new participant set:
        let new_participant_set: BTreeSet<AccountId> = proposal
            .candidates()
            .participants()
            .keys()
            .cloned()
            .collect();
        let old_participant_set: BTreeSet<AccountId> = self
            .key_state
            .participants()
            .participants()
            .keys()
            .cloned()
            .collect();
        let inter: BTreeSet<&AccountId> = new_participant_set
            .intersection(&old_participant_set)
            .collect();
        let n_old = inter.len() as u64;
        if n_old < self.key_state.threshold().value() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }
        // ensure that the participant id is preseved:
        for account_id in inter {
            let existing_id = self.key_state.participants().id(account_id)?;
            let new_id = proposal.candidates().id(account_id)?;
            if existing_id != new_id {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            }
        }
        // remove any previous votes submitted by the signer:
        if self.key_state_votes.remove_vote(&participant) {
            log!("removed one vote for signer");
        }

        // finally, vote. Propagate any errors
        let n_votes = self.key_state_votes.vote(proposal, &participant)?;
        Ok(self.key_state.threshold().value() <= n_votes)
    }
}
