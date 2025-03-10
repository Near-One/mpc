use super::key_event::KeyEventState;
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::key_state::{
    AuthenticatedCandidateId, AuthenticatedParticipantId, DKState, EpochId, KeyEventId,
    KeyStateProposal,
};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{near, BlockHeight, PublicKey};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct ResharingContractState {
    pub current_state: RunningContractState,
    pub event_state: KeyEventState,
}

impl From<&legacy_contract::ResharingContractState> for ResharingContractState {
    fn from(state: &legacy_contract::ResharingContractState) -> Self {
        ResharingContractState {
            // todo: test this.
            current_state: RunningContractState {
                key_state: state.into(),
                key_state_votes: KeyStateVotes::default(),
            },
            event_state: KeyEventState::new(EpochId::new(state.old_epoch + 1), state.into()),
        }
    }
}

impl ResharingContractState {
    pub fn authenticate_participant(&self) -> Result<AuthenticatedParticipantId, Error> {
        self.current_state.authenticate_participant()
    }
    pub fn public_key(&self) -> &PublicKey {
        self.current_state.public_key()
    }
    /// Casts a vote for `proposal`, removing any exiting votes by `signer_account_id()`.
    /// Returns an error if `proposal` is invalid or signer not in the old partipicant set.
    /// Returns ResharingContract state if the proposal is accepted.
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
                event_state: KeyEventState::new(
                    self.current_state.epoch_id().next(),
                    proposal.clone(),
                ),
            }));
        }
        Ok(None)
    }
}

// Leader API. Below functions shall only be called by a leader account
impl ResharingContractState {
    // starts a new reshare instance if there is no active reshare instance
    pub fn start(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        self.event_state.start(dk_event_timeout_blocks)
    }
    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        if self.event_state.vote_success(
            &key_event_id,
            dk_event_timeout_blocks,
            None::<fn(AuthenticatedCandidateId)>,
        )? {
            return Ok(Some(RunningContractState {
                key_state: DKState::new(
                    self.public_key().clone(),
                    key_event_id,
                    self.event_state.proposed_threshold_parameters().clone(),
                )?,
                key_state_votes: KeyStateVotes::default(),
            }));
        }
        Ok(None)
    }
    /// Casts a vote to abort the current keygen instance.
    /// Replaces the current instance in case dkg threshold can't be reached anymore.
    pub fn vote_abort(
        &mut self,
        key_event_id: KeyEventId,
        dk_event_timeout_blocks: BlockHeight,
    ) -> Result<bool, Error> {
        self.event_state
            .vote_abort(key_event_id, dk_event_timeout_blocks)
    }
}
