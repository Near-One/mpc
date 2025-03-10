use std::collections::BTreeSet;

use crate::errors::Error;
use crate::errors::KeyEventError;
use crate::errors::VoteError;
use crate::primitives::key_state::KeyEventId;
use crate::primitives::key_state::{
    AttemptId, AuthenticatedCandidateId, EpochId, KeyStateProposal,
};
use crate::primitives::leader::leaders;
use crate::primitives::participants::ParticipantId;
use crate::primitives::thresholds::Threshold;
use crate::primitives::thresholds::{DKGThreshold, ThresholdParameters};
use near_sdk::BlockHeight;
use near_sdk::{env, near};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEventInstance {
    key_event_instance: KeyEventAttempt,
    completed: BTreeSet<AuthenticatedCandidateId>,
    aborted: BTreeSet<AuthenticatedCandidateId>,
    started: Option<AuthenticatedLeader>, // indicates if the leader started the computation
}

impl KeyEventInstance {
    pub fn started(&self) -> bool {
        self.started.is_some()
    }
    pub fn activate(&mut self, leader: AuthenticatedLeader) {
        if self.started.is_none() {
            self.key_event_instance.vote_alive();
        }
        self.started = Some(leader);
    }
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.key_event_instance.timed_out(timeout_in_blocks)
    }
    pub fn new() -> Self {
        KeyEventInstance {
            key_event_instance: KeyEventAttempt::new(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    pub fn next(&mut self) -> Self {
        KeyEventInstance {
            key_event_instance: self.key_event_instance.next(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    /// Commits the vote of `candidate_id` to `public_key`, returning the total number of votes for `public_key`.
    /// Fails if the candidate already submitted a vote.
    pub fn vote_success(&mut self, candidate: AuthenticatedCandidateId) -> Result<u64, Error> {
        // if candidate already aborted, then exit with error
        if self.aborted.contains(&candidate) {
            return Err(VoteError::VoterAlreadyAborted.into());
        }
        // return error if the candidate alredy submitted a vote.
        if self.completed.contains(&candidate) {
            return Err(VoteError::VoteAlreadySubmitted.into());
        }
        // label candidate as complete
        self.completed.insert(candidate.clone());
        Ok(self.completed.len() as u64)
    }

    /// Returns the total number of votes for `public_key`
    pub fn n_votes(&self) -> u64 {
        self.completed.len() as u64
    }

    pub fn n_aborts(&self) -> u64 {
        self.aborted.len() as u64
    }
    /// Casts a vote from `candidate_id` to abort the current instance.
    /// Returns an error if `candidate_id` already voted.
    /// Returns the number of votes received to abort.
    pub fn vote_abort(&mut self, candidate_id: AuthenticatedCandidateId) -> Result<u64, Error> {
        // return error if the candidate alredy submitted a vote.
        if self.completed.contains(&candidate_id) {
            return Err(VoteError::VoteAlreadySubmitted.into());
        }
        self.aborted.insert(candidate_id);
        Ok(self.n_aborts())
    }

    pub fn current_attempt(&self) -> AttemptId {
        self.key_event_instance.current_attempt()
    }
}
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEventAttempt {
    attempt: AttemptId,
    last_vote: BlockHeight,
}

impl KeyEventAttempt {
    pub fn new() -> Self {
        KeyEventAttempt {
            attempt: AttemptId::new(),
            last_vote: env::block_height(),
        }
    }
    pub fn next(&self) -> Self {
        KeyEventAttempt {
            attempt: self.attempt.next(),
            last_vote: env::block_height(),
        }
    }
    pub fn current_attempt(&self) -> AttemptId {
        self.attempt.clone()
    }
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
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct AuthenticatedLeader(ParticipantId);

impl KeyEvent {
    pub fn n_candidates(&self) -> u64 {
        self.proposed_key_state.n_proposed_participants()
    }
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
    /// Ensures that the signer account matches the leader for `attempt`.
    pub fn authenticate_leader(&self, attempt: AttemptId) -> Result<AuthenticatedLeader, Error> {
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
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEventState {
    event: KeyEvent,
    instance: KeyEventInstance,
}

impl KeyEventState {
    pub fn authenticate_candidate(&self) -> Result<AuthenticatedCandidateId, Error> {
        self.event.authenticate_candidate()
    }
    pub fn proposed_threshold(&self) -> Threshold {
        self.event.proposed_key_state.proposed_threshold()
    }
    pub fn proposed_threshold_parameters(&self) -> ThresholdParameters {
        self.event
            .proposed_key_state
            .proposed_threshold_parameters()
            .clone()
    }
    pub fn new(epoch_id: EpochId, proposed_key_state: KeyStateProposal) -> Self {
        KeyEventState {
            event: KeyEvent::new(epoch_id, proposed_key_state),
            instance: KeyEventInstance::new(),
        }
    }
    fn verify_vote(
        &self,
        key_event_id: &KeyEventId,
        dk_event_timeout_blocks: u64,
    ) -> Result<AuthenticatedCandidateId, Error> {
        // ensure the signer is a candidate
        let candidate_id = self.event.authenticate_candidate()?;
        // ensure the instance was started and is active
        if !self.instance.started() || self.instance.timed_out(dk_event_timeout_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        }
        // Ensure the key_event_id matches
        if self.current_key_event_id() != *key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        Ok(candidate_id)
    }
    // starts a new reshare instance if there is no active reshare instance
    pub fn start(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        // update the current instance if required:
        if self.instance.timed_out(dk_event_timeout_blocks) {
            self.instance = self.instance.next();
        }
        // check that the signer is the current leader:
        let leader = self
            .event
            .authenticate_leader(self.instance.current_attempt())?;
        // set the instance as active:
        self.instance.activate(leader);
        Ok(())
    }
    pub fn current_key_event_id(&self) -> KeyEventId {
        KeyEventId::new(self.event.epoch_id(), self.instance.current_attempt())
    }
    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_success<F>(
        &mut self,
        key_event_id: &KeyEventId,
        dk_event_timeout_blocks: u64,
        callback: Option<F>,
    ) -> Result<bool, Error>
    where
        F: FnOnce(AuthenticatedCandidateId),
    {
        let candidate_id = self.verify_vote(key_event_id, dk_event_timeout_blocks)?;
        let n_votes = self.instance.vote_success(candidate_id.clone())?;
        if let Some(cb) = callback {
            cb(candidate_id);
        }
        Ok(self.event.threshold().value() <= n_votes)
    }
    /// Casts a vote to abort the current keygen instance.
    /// Replaces the current instance in case dkg threshold can't be reached anymore.
    pub fn vote_abort(
        &mut self,
        key_event_id: KeyEventId,
        dk_event_timeout_blocks: BlockHeight,
    ) -> Result<bool, Error> {
        let candidate_id = self.verify_vote(&key_event_id, dk_event_timeout_blocks)?;
        let n_votes = self.instance.vote_abort(candidate_id)?;
        if self.event.n_candidates() - n_votes < self.event.threshold().value() {
            // we can't achieve `dkg_threshold` votes anymore, abort this instance and reset
            self.instance = self.instance.next();
            return Ok(true);
        }
        Ok(false)
    }
}
