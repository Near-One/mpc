pub mod initializing;
pub mod resharing;
pub mod running;
#[cfg(test)]
pub mod tests;

use crate::errors::{Error, InvalidState, VoteError};
use crate::primitives::key_state::{KeyEventId, KeyStateProposal};
use crate::primitives::thresholds::Threshold;
use initializing::InitializingContractState;
use near_sdk::{near, AccountId, PublicKey};
use resharing::ResharingContractState;
use running::RunningContractState;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl ProtocolContractState {
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        match self {
            ProtocolContractState::Running(state) => Ok(state.public_key().clone()),
            ProtocolContractState::Resharing(state) => Ok(state.public_key().clone()),
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
    }
    pub fn threshold(&self) -> Result<Threshold, Error> {
        match self {
            ProtocolContractState::Initializing(state) => {
                Ok(state.proposed_key_state.proposed_threshold())
            }
            ProtocolContractState::Running(state) => Ok(state.key_state.threshold()),
            ProtocolContractState::Resharing(state) => {
                Ok(state.current_state.key_state.threshold())
            }
            ProtocolContractState::NotInitialized => {
                Err(InvalidState::UnexpectedProtocolState.into())
            }
        }
    }
    pub fn start_keygen_instance(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotInitializing.into());
        };
        state.start_keygen_instance(dk_event_timeout_blocks)
    }
    pub fn start_reshare_instance(
        &mut self,
        new_epoch_id: u64,
        dk_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state.start_reshare_instance(new_epoch_id, dk_event_timeout_blocks)
    }
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state
            .vote_reshared(key_event_id, dk_event_timeout_blocks)
            .map(|x| x.map(ProtocolContractState::Running))
    }
    /// Casts a vote for `public_key` in `key_event_id` during Initializtion.
    /// Fails if the protocol is not in `Initializing` state.
    /// Returns the new protocol state if enough votes have been submitted.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state
            .vote_pk(key_event_id, public_key, dk_event_timeout_blocks)
            .map(|x| x.map(ProtocolContractState::Running))
    }
    /// Casts a vote for `proposed_key_state`, returning the new protocol state if the proposal is
    /// accepted.
    /// Returns an error if the protocol is not in running resharing.
    pub fn vote_new_key_state(
        &mut self,
        proposed_key_state: &KeyStateProposal,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Running(state) => state.vote_new_key_state(proposed_key_state),
            ProtocolContractState::Resharing(state) => state.vote_new_key_state(proposed_key_state),
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
        .map(|x| x.map(ProtocolContractState::Resharing))
    }
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
    pub fn is_running(&self) -> bool {
        if let ProtocolContractState::Running(_) = self {
            return true;
        }
        false
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
