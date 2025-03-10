use super::running::RunningContractState;
use crate::errors::VoteError;
use crate::errors::{Error, KeyEventError};
use crate::primitives::key_state::{
    AuthenticatedCandidateId, DKState, EpochId, KeyEventAttempt, KeyEventId, KeyStateProposal,
};
use crate::primitives::leader::leaders;
use crate::primitives::participants::{ParticipantId, Participants};
use crate::primitives::signature::YieldIndex;
use crate::primitives::thresholds::{DKGThreshold, ThresholdParameters};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{env, near, AccountId, PublicKey};
use near_sdk::{log, BlockHeight};
use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::collections::{BTreeMap, BTreeSet};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEventInstance {
    attempt: KeyEventAttempt,
    last_vote: BlockHeight,
    //conclusion: YieldIndex,
}

impl KeyEventInstance {
    //pub fn new(conclusion: YieldIndex) -> Self {
    //    KeyEventInstance {
    //        attempt: KeyEventAttempt::new(),
    //        last_vote: env::block_height(),
    //        conclusion,
    //    }
    //}
    pub fn new() -> Self {
        KeyEventInstance {
            attempt: KeyEventAttempt::new(),
            last_vote: env::block_height(),
        }
    }
    pub fn next(&self) -> Self {
        KeyEventInstance {
            attempt: self.attempt.next(),
            last_vote: env::block_height(),
        }
    }
    pub fn current_attempt(&self) -> KeyEventAttempt {
        self.attempt.clone()
    }
    //pub fn next(&self, conclusion: YieldIndex) -> Self {
    //    KeyEventInstance {
    //        attempt: self.attempt.next(),
    //        last_vote: env::block_height(),
    //        conclusion,
    //    }
    //}
    pub fn vote_alive(&mut self) {
        self.last_vote = env::block_height()
    }
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.last_vote + timeout_in_blocks < env::block_height()
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEvent {
    epoch_id: EpochId,
    leader_order: Vec<ParticipantId>,
    proposed_key_state: KeyStateProposal,
    //current_instance: KeyEventInstance,
}
pub struct AuthenticatedLeader(ParticipantId);
impl KeyEvent {
    pub fn proposed_threshold_parameters(&self) -> &ThresholdParameters {
        self.proposed_key_state.proposed_threshold_parameters()
    }
    pub fn new(epoch_id: EpochId, proposed_key_state: KeyStateProposal) -> Self {
        let seed = env::random_seed();
        let seed = u64::from_le_bytes(seed[..8].try_into().unwrap());
        let seed = seed ^ epoch_id.get();
        let leader_order = leaders(proposed_key_state.candidates(), seed);
        KeyEvent {
            epoch_id,
            leader_order,
            proposed_key_state,
        }
    }
    pub fn authenticate_leader(
        &self,
        attempt: KeyEventAttempt,
    ) -> Result<AuthenticatedLeader, Error> {
        let n_candidates = self.leader_order.len();
        let idx = attempt.get() % (n_candidates as u64);
        let expected_id = self.leader_order[idx as usize].clone();
        let candidate_id = self.proposed_key_state.authenticate()?;
        if expected_id == candidate_id.get() {
            Ok(AuthenticatedLeader(candidate_id.get()))
        } else {
            Err(VoteError::VoterNotLeader.into())
        }
    }
    pub fn authenticate_candidate(&self) -> Result<AuthenticatedCandidateId, Error> {
        self.proposed_key_state.authenticate()
    }
    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id.clone()
    }
    pub fn threshold(&self) -> DKGThreshold {
        self.proposed_key_state.key_event_threshold()
    }
    //pub fn start_next_instance(&mut self) {
    //    match self.current_instance {
    //        None => {}
    //    }
    //}
    //pub fn active(instance_timeout_blocks: u64, threshold: DKGThreshold) -> bool {}
    //pub fn concluded() -> bool {}
    //pub fn succeeded(event_timeout_blocks,threshold) -> bool
    //pub fn active(event_timeout_blocks,threshold) -> bool
}
