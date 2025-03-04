use super::key_state::{DKState, KeyStateProposal};
use super::resharing::ResharingContractState;
use super::votes::KeyStateVotes;
use crate::errors::VoteError;
use crate::errors::{Error, InvalidCandidateSet};
use near_sdk::{env, log, near, AccountId};
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
                proposed_key_state: proposal.clone(),
                current_reshare: None,
            }));
        }
        Ok(None)
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
        Ok(self.key_state.threshold().value() <= n_votes)
    }
}
