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
use std::collections::BTreeSet;

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
            self.instance = self.instance.next_instance();
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
            self.instance = self.instance.next_instance();
            return Ok(true);
        }
        Ok(false)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEventInstance {
    key_event_instance: KeyEventAttempt,
    completed: BTreeSet<AuthenticatedCandidateId>,
    aborted: BTreeSet<AuthenticatedCandidateId>,
    started: Option<AuthenticatedLeader>,
}

impl KeyEventInstance {
    pub fn new() -> Self {
        KeyEventInstance {
            key_event_instance: KeyEventAttempt::new(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    pub fn next_instance(&mut self) -> Self {
        KeyEventInstance {
            key_event_instance: self.key_event_instance.next(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    pub fn started(&self) -> bool {
        self.started.is_some()
    }
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.key_event_instance.timed_out(timeout_in_blocks)
    }
    pub fn current_attempt(&self) -> AttemptId {
        self.key_event_instance.id()
    }
    pub fn activate(&mut self, leader: AuthenticatedLeader) {
        if self.started.is_none() {
            self.key_event_instance.vote_alive();
        }
        self.started = Some(leader);
        self.key_event_instance.vote_alive();
    }
    /// Commits the vote of `candidate_id` to `public_key`, returning the total number of votes for `public_key`.
    /// Fails if the candidate already submitted a vote.
    pub fn vote_success(&mut self, candidate: AuthenticatedCandidateId) -> Result<u64, Error> {
        if self.started.is_none() {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        }
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
        self.key_event_instance.vote_alive();
        Ok(self.completed.len() as u64)
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
        Ok(self.aborted.len() as u64)
    }
}

impl Default for KeyEventInstance {
    fn default() -> Self {
        Self::new()
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
    pub fn id(&self) -> AttemptId {
        self.attempt.clone()
    }
    pub fn vote_alive(&mut self) {
        self.last_vote = env::block_height()
    }
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.last_vote + timeout_in_blocks < env::block_height()
    }
}

impl Default for KeyEventAttempt {
    fn default() -> Self {
        KeyEventAttempt::new()
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct AuthenticatedLeader(ParticipantId);

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeyEvent {
    epoch_id: EpochId,
    leader_order: Vec<ParticipantId>,
    proposed_key_state: KeyStateProposal,
}

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

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeSet, mem};

    use near_sdk::{env::block_height, test_utils::VMContextBuilder, testing_env, AccountId};
    use rand::Rng;

    use crate::{
        primitives::key_state::{
            tests::gen_key_state_proposal, AttemptId, AuthenticatedCandidateId, EpochId, KeyEventId,
        },
        state::{
            key_event::{KeyEventInstance, KeyEventState},
            tests::test_utils::{gen_account_id, gen_seed},
        },
    };

    use super::{AuthenticatedLeader, KeyEvent, KeyEventAttempt};

    #[test]
    fn test_key_event_attempt() {
        let bh = rand::thread_rng().gen();
        let mut context = VMContextBuilder::new();
        context.block_height(bh);
        testing_env!(context.build());
        let mut kea = KeyEventAttempt::new();
        assert_eq!(kea.id().get(), 0);
        assert!(!kea.timed_out(0));
        let mut context = VMContextBuilder::new();
        context.block_height(bh + 200);
        testing_env!(context.build());
        assert!(!kea.timed_out(200));
        assert!(kea.timed_out(199));
        kea.vote_alive();
        assert!(!kea.timed_out(0));
        let mut context = VMContextBuilder::new();
        context.block_height(bh + 300);
        testing_env!(context.build());
        assert!(kea.timed_out(99));
        let kea = kea.next();
        assert!(!kea.timed_out(0));
        assert_eq!(kea.id().get(), 1);
    }
    #[test]
    fn test_key_event() {
        let epoch_id = rand::thread_rng().gen();
        let epoch_id = EpochId::new(epoch_id);
        let n = 30;
        let proposed_key_state = gen_key_state_proposal(Some(n));
        let n = proposed_key_state.n_proposed_participants();
        let mut context = VMContextBuilder::new();
        let seed = gen_seed();
        context.random_seed(seed);
        testing_env!(context.build());
        let ke = KeyEvent::new(epoch_id.clone(), proposed_key_state.clone());
        assert_eq!(epoch_id, ke.epoch_id());
        assert_eq!(proposed_key_state.key_event_threshold(), ke.threshold());
        assert_eq!(
            proposed_key_state.n_proposed_participants(),
            ke.n_candidates()
        );
        assert_eq!(
            *proposed_key_state.proposed_threshold_parameters(),
            *ke.proposed_threshold_parameters()
        );
        let mut attempt = AttemptId::new();
        let mut leaders = BTreeSet::new();
        for _ in 0..n {
            let mut found = false;
            for account_id in proposed_key_state.candidates().participants().keys() {
                let mut context = VMContextBuilder::new();
                context.signer_account_id(account_id.clone());
                testing_env!(context.build());
                if let Ok(leader) = ke.authenticate_leader(attempt.clone()) {
                    assert!(!found);
                    found = true;
                    leaders.insert(leader.0);
                }
                assert!(ke.authenticate_candidate().is_ok());
            }
            assert!(found);
            attempt = attempt.next();
        }
        assert_eq!(leaders.len() as u64, n);

        for _ in 0..10 {
            let account_id = gen_account_id();
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id);
            testing_env!(context.build());
            assert!(ke.authenticate_candidate().is_err());
        }
    }
    #[test]
    fn test_key_event_instance() {
        let mut kei = KeyEventInstance::new();
        assert!(!kei.started());
        let id: u32 = rand::thread_rng().gen();
        let leader: AuthenticatedLeader = unsafe { mem::transmute(id) };
        kei.activate(leader);
        assert!(kei.started());
        let id: u32 = rand::thread_rng().gen();
        let candidate: AuthenticatedCandidateId = unsafe { mem::transmute(id) };
        assert_eq!(kei.vote_success(candidate.clone()).unwrap(), 1);
        assert!(kei.vote_success(candidate.clone()).is_err());
        assert!(kei.vote_abort(candidate).is_err());
        let id: u32 = rand::thread_rng().gen();
        let candidate: AuthenticatedCandidateId = unsafe { mem::transmute(id) };
        assert_eq!(kei.vote_success(candidate).unwrap(), 2);
        let id: u32 = rand::thread_rng().gen();
        let candidate: AuthenticatedCandidateId = unsafe { mem::transmute(id) };
        assert_eq!(kei.vote_abort(candidate).unwrap(), 1);
        let id: u32 = rand::thread_rng().gen();
        let candidate: AuthenticatedCandidateId = unsafe { mem::transmute(id) };
        assert_eq!(kei.vote_abort(candidate).unwrap(), 2);
    }

    #[test]
    fn test_key_event_state() {
        let block_height = 100;
        let mut context = VMContextBuilder::new();
        let seed = gen_seed();
        context.random_seed(seed).block_height(block_height);
        testing_env!(context.build());
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let proposed_key_state = gen_key_state_proposal(Some(10));
        let mut kes = KeyEventState::new(epoch_id.clone(), proposed_key_state.clone());
        let key_id = KeyEventId::new(epoch_id.clone(), AttemptId::new());
        // try to vote as a non participants:
        let counted = RefCell::new(0);
        let count = Some(|_: AuthenticatedCandidateId| {
            *counted.borrow_mut() += 1;
        });
        for _ in 0..10 {
            let account_id = gen_account_id();
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id);
            context.block_height(block_height);
            testing_env!(context.build());
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), 0);
        }

        let account_id: AccountId = proposed_key_state
            .candidates()
            .participants()
            .keys()
            .next()
            .unwrap()
            .clone();
        let mut context = VMContextBuilder::new();
        context.signer_account_id(account_id);
        testing_env!(context.build());
        assert!(kes.vote_success(&key_id, 100, count).is_err());
        for account_id in proposed_key_state.candidates().participants().keys() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            context.block_height(block_height);
            testing_env!(context.build());
            if kes.start(100).is_ok() {
                break;
            }
        }
        for (i, account_id) in proposed_key_state
            .candidates()
            .participants()
            .keys()
            .enumerate()
        {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            context.block_height(block_height);
            testing_env!(context.build());
            let wrong_key_id = KeyEventId::new(epoch_id.clone(), AttemptId::new().next());
            assert!(kes.vote_success(&wrong_key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), i);
            assert!(kes.vote_abort(wrong_key_id, 100).is_err());
            let wrong_key_id = KeyEventId::new(epoch_id.next(), AttemptId::new());
            assert!(kes.vote_success(&wrong_key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), i);
            assert!(kes.vote_abort(wrong_key_id, 100).is_err());
            let res = kes.vote_success(&key_id, 100, count).unwrap();
            assert_eq!(*counted.borrow(), i + 1);
            if proposed_key_state.key_event_threshold().value() <= ((i + 1) as u64) {
                assert!(res);
            } else {
                assert!(!res);
            }
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), i + 1);
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
        }
        // start new instance
        let block_height = block_height + 1;
        for account_id in proposed_key_state.candidates().participants().keys() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            context.block_height(block_height);
            testing_env!(context.build());
            if kes.start(0).is_ok() {
                break;
            }
        }
        let key_id = KeyEventId::new(key_id.epoch_id(), key_id.attempt().next());
        *counted.borrow_mut() = 0;
        for (i, account_id) in proposed_key_state
            .candidates()
            .participants()
            .keys()
            .enumerate()
        {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            context.block_height(block_height);
            testing_env!(context.build());
            let res = kes.vote_abort(key_id.clone(), 100);
            println!("{:?}", res);
            let res = res.unwrap();
            if proposed_key_state.key_event_threshold().value()
                > proposed_key_state.n_proposed_participants() - ((i + 1) as u64)
            {
                assert!(res);
            } else {
                assert!(!res);
            }
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), 0);
        }
        // start new instance
        let block_height = block_height + 1;
        for account_id in proposed_key_state.candidates().participants().keys() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            context.block_height(block_height);
            testing_env!(context.build());
            if kes.start(0).is_ok() {
                break;
            }
        }
        let key_id = KeyEventId::new(key_id.epoch_id(), key_id.attempt().next());
        *counted.borrow_mut() = 0;
        for account_id in proposed_key_state.candidates().participants().keys() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            context.block_height(block_height + 100);
            testing_env!(context.build());
            assert!(kes.vote_abort(key_id.clone(), 0).is_err());
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), 0);
        }
        // todo: vote abort first and verify you can't vote for success
        // test for timeout
        // start as leader:

        //#[near(serializers=[borsh, json])]
        //#[derive(Debug)]
        //pub struct KeyEventState {
        //    event: KeyEvent,
        //    instance: KeyEventInstance,
        //}
        //
        //impl KeyEventState {
        //    pub fn authenticate_candidate(&self) -> Result<AuthenticatedCandidateId, Error> {
        //        self.event.authenticate_candidate()
        //    }
        //    pub fn proposed_threshold(&self) -> Threshold {
        //        self.event.proposed_key_state.proposed_threshold()
        //    }
        //    pub fn proposed_threshold_parameters(&self) -> ThresholdParameters {
        //        self.event
        //            .proposed_key_state
        //            .proposed_threshold_parameters()
        //            .clone()
        //    }
        //    pub fn new(epoch_id: EpochId, proposed_key_state: KeyStateProposal) -> Self {
        //        KeyEventState {
        //            event: KeyEvent::new(epoch_id, proposed_key_state),
        //            instance: KeyEventInstance::new(),
        //        }
        //    }
        //    fn verify_vote(
        //        &self,
        //        key_event_id: &KeyEventId,
        //        dk_event_timeout_blocks: u64,
        //    ) -> Result<AuthenticatedCandidateId, Error> {
        //        // ensure the signer is a candidate
        //        let candidate_id = self.event.authenticate_candidate()?;
        //        // ensure the instance was started and is active
        //        if !self.instance.started() || self.instance.timed_out(dk_event_timeout_blocks) {
        //            return Err(KeyEventError::NoActiveKeyEvent.into());
        //        }
        //        // Ensure the key_event_id matches
        //        if self.current_key_event_id() != *key_event_id {
        //            return Err(KeyEventError::KeyEventIdMismatch.into());
        //        }
        //        Ok(candidate_id)
        //    }
        //    // starts a new reshare instance if there is no active reshare instance
        //    pub fn start(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        //        // update the current instance if required:
        //        if self.instance.timed_out(dk_event_timeout_blocks) {
        //            self.instance = self.instance.next_instance();
        //        }
        //        // check that the signer is the current leader:
        //        let leader = self
        //            .event
        //            .authenticate_leader(self.instance.current_attempt())?;
        //        // set the instance as active:
        //        self.instance.activate(leader);
        //        Ok(())
        //    }
        //    pub fn current_key_event_id(&self) -> KeyEventId {
        //        KeyEventId::new(self.event.epoch_id(), self.instance.current_attempt())
        //    }
        //    /// Casts a vote for `public_key` in `key_event_id`.
        //    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
        //    /// Returns `RunningContractState` if `public_key` reaches the required votes.
        //    pub fn vote_success<F>(
        //        &mut self,
        //        key_event_id: &KeyEventId,
        //        dk_event_timeout_blocks: u64,
        //        callback: Option<F>,
        //    ) -> Result<bool, Error>
        //    where
        //        F: FnOnce(AuthenticatedCandidateId),
        //    {
        //        let candidate_id = self.verify_vote(key_event_id, dk_event_timeout_blocks)?;
        //        let n_votes = self.instance.vote_success(candidate_id.clone())?;
        //        if let Some(cb) = callback {
        //            cb(candidate_id);
        //        }
        //        Ok(self.event.threshold().value() <= n_votes)
        //    }
        //    /// Casts a vote to abort the current keygen instance.
        //    /// Replaces the current instance in case dkg threshold can't be reached anymore.
        //    pub fn vote_abort(
        //        &mut self,
        //        key_event_id: KeyEventId,
        //        dk_event_timeout_blocks: BlockHeight,
        //    ) -> Result<bool, Error> {
        //        let candidate_id = self.verify_vote(&key_event_id, dk_event_timeout_blocks)?;
        //        let n_votes = self.instance.vote_abort(candidate_id)?;
        //        if self.event.n_candidates() - n_votes < self.event.threshold().value() {
        //            // we can't achieve `dkg_threshold` votes anymore, abort this instance and reset
        //            self.instance = self.instance.next_instance();
        //            return Ok(true);
        //        }
        //        Ok(false)
        //    }
        //}
    }
}
