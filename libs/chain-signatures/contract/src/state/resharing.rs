use super::key_event::KeyEventState;
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::key_state::{
    AuthenticatedCandidateId, AuthenticatedParticipantId, DKState, EpochId, KeyEventId,
    KeyStateProposal,
};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{near, BlockHeight, PublicKey};

//#[near(serializers=[borsh, json])]
//#[derive(Debug)]
//pub struct ReshareInstance {
//    key_event_instance: KeyEventAttempt,
//    completed: BTreeSet<AuthenticatedCandidateId>,
//    aborted: BTreeSet<AuthenticatedCandidateId>,
//    started: Option<AuthenticatedLeader>, // indicates if the leader started the computation
//}
//
//impl ReshareInstance {
//    pub fn activate(&mut self, leader: AuthenticatedLeader) {
//        if self.started.is_none() {
//            self.key_event_instance.vote_alive();
//        }
//        self.started = Some(leader);
//    }
//    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
//        self.key_event_instance.timed_out(timeout_in_blocks)
//    }
//    pub fn new() -> Self {
//        ReshareInstance {
//            key_event_instance: KeyEventAttempt::new(),
//            completed: BTreeSet::new(),
//            aborted: BTreeSet::new(),
//            started: None,
//        }
//    }
//    pub fn next(&mut self) -> Self {
//        ReshareInstance {
//            key_event_instance: self.key_event_instance.next(),
//            completed: BTreeSet::new(),
//            aborted: BTreeSet::new(),
//            started: None,
//        }
//    }
//    /// Commits the vote of `candidate_id` to `public_key`, returning the total number of votes for `public_key`.
//    /// Fails if the candidate already submitted a vote.
//    pub fn vote_reshared(&mut self, candidate: AuthenticatedCandidateId) -> Result<u64, Error> {
//        // if candidate already aborted, then exit with error
//        if self.aborted.contains(&candidate) {
//            return Err(VoteError::VoterAlreadyAborted.into());
//        }
//        // return error if the candidate alredy submitted a vote.
//        if self.completed.contains(&candidate) {
//            return Err(VoteError::VoteAlreadySubmitted.into());
//        }
//        // label candidate as complete
//        self.completed.insert(candidate.clone());
//        Ok(self.completed.len() as u64)
//    }
//
//    /// Returns the total number of votes for `public_key`
//    pub fn n_votes(&self) -> u64 {
//        self.completed.len() as u64
//    }
//
//    pub fn n_aborts(&self) -> u64 {
//        self.aborted.len() as u64
//    }
//    /// Casts a vote from `candidate_id` to abort the current instance.
//    /// Removes any previous votes by `candidate_id`.
//    /// Returns the number of votes received to abort.
//    pub fn vote_abort(&mut self, candidate_id: AuthenticatedCandidateId) -> u64 {
//        // remove any existing votes
//        self.completed.remove(&candidate_id);
//        self.aborted.insert(candidate_id);
//        self.n_aborts()
//    }
//    pub fn current_attempt(&self) -> AttemptId {
//        self.key_event_instance.current_attempt()
//    }
//}

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
    //fn verify_candidate_vote(
    //    &self,
    //    key_event_id: &KeyEventId,
    //    dk_event_timeout_blocks: u64,
    //) -> Result<AuthenticatedCandidateId, Error> {
    //    // ensure the signer is a candidate
    //    let candidate_id = self.event.authenticate_candidate()?;
    //    // ensure the instance was started and is active
    //    if !self.instance.started() || self.instance.timed_out(dk_event_timeout_blocks) {
    //        return Err(KeyEventError::NoActiveKeyEvent.into());
    //    }
    //    // Ensure the key_event_id matches
    //    if self.current_key_event_id() != *key_event_id {
    //        return Err(KeyEventError::KeyEventIdMismatch.into());
    //    }
    //    Ok(candidate_id)
    //}
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
    //pub fn current_key_event_id(&self) -> KeyEventId {
    //    KeyEventId::new(self.event.epoch_id(), self.instance.current_attempt())
    //}
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
