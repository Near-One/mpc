use near_sdk::{near, AccountId, PublicKey};
use std::collections::HashSet;

use crate::errors::Error;
use crate::errors::{InvalidState, VoteError};

use super::participants::{Candidates, Participants};
use super::votes::{PkVotes, Votes};

/** Deprecated V0 and V1 contract state. Can be removed eventually. **/
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
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
