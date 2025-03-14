use crate::errors::Error;
use crate::errors::KeyEventError;
use crate::errors::VoteError;
use crate::primitives::key_state::KeyEventId;
use crate::primitives::key_state::{AttemptId, EpochId, KeyStateProposal};
use crate::primitives::leader::leaders;
use crate::primitives::participants::AuthenticatedCandidateId;
use crate::primitives::participants::ParticipantId;
use crate::primitives::thresholds::Threshold;
use crate::primitives::thresholds::{DKGThreshold, ThresholdParameters};
use near_sdk::env::block_height;
use near_sdk::BlockHeight;
use near_sdk::{env, near};
use std::collections::BTreeSet;

/// Stores the information for the current key event:
/// - the epoch_id for which the new keyshares shall be valid.
/// - the proposed threshold parameters
/// - the key event threshold
/// - the current instance of the key event
/// - a leader order, pseudo-randomly generated from `env::random_seed()` and `epoch_id`.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct KeyEvent {
    epoch_id: EpochId,
    leader_order: Vec<ParticipantId>,
    parameters: ThresholdParameters,
    event_threshold: DKGThreshold,
    instance: KeyEventInstance, // if we add key types, we will have one instance per key type.
}
#[derive(Debug, PartialEq)]
pub enum Tally {
    //The threshold has been met
    ThresholdReached(AuthenticatedCandidateId),
    /// The vote result is still pending.
    ThresholdPending(AuthenticatedCandidateId),
}
#[derive(Debug, PartialEq)]
pub enum InstanceStatus {
    // The key event instance has been aborted and replaced.
    Replaced,
    // The key event instance may still succeed.
    Pending,
}

// voting API
impl KeyEvent {
    // starts a new reshare instance if there is no active reshare instance
    pub fn start(&mut self, event_max_idle_blocks: u64) -> Result<(), Error> {
        // update the current instance if required:
        if self.timed_out(event_max_idle_blocks) {
            self.instance = self.instance.next_instance();
        }
        // check that the signer is the current leader:
        let leader = self.authenticate_leader(self.instance.current_attempt())?;
        // set the instance as active:
        self.instance.activate(leader)
    }
    pub fn current_key_event_id(&self) -> KeyEventId {
        KeyEventId::new(self.epoch_id.clone(), self.instance.current_attempt())
    }
    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns the current tally of the key event instance.
    pub fn vote_success(
        &mut self,
        key_event_id: &KeyEventId,
        event_max_idle_blocks: u64,
        //callback: Option<F>,
    ) -> Result<Tally, Error> {
        let candidate = self.verify_vote(key_event_id, event_max_idle_blocks)?;
        let n_votes = self.instance.vote_success(candidate.clone())?;
        //if let Some(cb) = callback {
        //    cb(candidate);
        //}
        if self.event_threshold().value() <= n_votes {
            Ok(Tally::ThresholdReached(candidate))
        } else {
            Ok(Tally::ThresholdPending(candidate))
        }
    }
    /// Casts a vote to abort the current keygen instance.
    /// Replaces the current instance in case dkg threshold can't be reached anymore.
    /// Returns the status of the current key event instance.
    pub fn vote_abort(
        &mut self,
        key_event_id: KeyEventId,
        event_max_idle_blocks: BlockHeight,
    ) -> Result<InstanceStatus, Error> {
        let candidate = self.verify_vote(&key_event_id, event_max_idle_blocks)?;
        let n_votes = self.instance.vote_abort(candidate)?;
        if self.proposed_threshold_parameters().participants().count() - n_votes
            < self.event_threshold().value()
        {
            // we can't achieve `dkg_threshold` votes anymore, abort this instance and reset
            self.instance = self.instance.next_instance();
            return Ok(InstanceStatus::Replaced);
        }
        Ok(InstanceStatus::Pending)
    }
}

// Getters
impl KeyEvent {
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.instance.last_vote + timeout_in_blocks < env::block_height()
    }
    pub fn authenticate_candidate(&self) -> Result<AuthenticatedCandidateId, Error> {
        AuthenticatedCandidateId::new(self.parameters.participants())
    }
    /// Ensures that the signer account matches the leader for `attempt`.
    pub fn authenticate_leader(&self, attempt: AttemptId) -> Result<AuthenticatedLeader, Error> {
        let n_candidates = self.leader_order.len();
        let idx = attempt.get() % (n_candidates as u64);
        let expected_id = self.leader_order[idx as usize].clone();
        let candidate = self.authenticate_candidate()?;
        if expected_id == candidate.get() {
            Ok(AuthenticatedLeader(candidate.get()))
        } else {
            Err(VoteError::VoterNotLeader.into())
        }
    }
    pub fn proposed_threshold(&self) -> Threshold {
        self.proposed_threshold_parameters().threshold()
    }
    pub fn event_threshold(&self) -> DKGThreshold {
        self.event_threshold.clone()
    }
    pub fn proposed_threshold_parameters(&self) -> ThresholdParameters {
        self.parameters.clone()
    }
}

// Constuctor
impl KeyEvent {
    pub fn new(epoch_id: EpochId, proposed_key_state: KeyStateProposal) -> Self {
        let seed = env::random_seed();
        let seed = u64::from_le_bytes(seed[..8].try_into().unwrap());
        let seed = seed ^ epoch_id.get();
        let leader_order = leaders(
            proposed_key_state
                .proposed_threshold_parameters()
                .participants(),
            seed,
        );
        KeyEvent {
            epoch_id,
            leader_order,
            parameters: proposed_key_state.proposed_threshold_parameters().clone(),
            event_threshold: proposed_key_state.key_event_threshold(),
            instance: KeyEventInstance::new(),
        }
    }
}

// helper function
impl KeyEvent {
    fn verify_vote(
        &self,
        key_event_id: &KeyEventId,
        event_max_idle_blocks: u64,
    ) -> Result<AuthenticatedCandidateId, Error> {
        // ensure the signer is a candidate
        let candidate = self.authenticate_candidate()?;
        // ensure the instance was started and is active
        if !self.instance.started() || self.timed_out(event_max_idle_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        }
        // Ensure the key_event_id matches
        if self.current_key_event_id() != *key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        Ok(candidate)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct KeyEventInstance {
    attempt: AttemptId,
    last_vote: BlockHeight,
    completed: BTreeSet<AuthenticatedCandidateId>,
    aborted: BTreeSet<AuthenticatedCandidateId>,
    started: Option<AuthenticatedLeader>,
}

// Constructors
impl KeyEventInstance {
    pub fn new() -> Self {
        KeyEventInstance {
            attempt: AttemptId::new(),
            last_vote: block_height(),
            //key_event_instance: KeyEventAttempt::new(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
    pub fn next_instance(&self) -> Self {
        KeyEventInstance {
            attempt: self.attempt.next(),
            last_vote: block_height(),
            //key_event_instance: self.key_event_instance.next(),
            completed: BTreeSet::new(),
            aborted: BTreeSet::new(),
            started: None,
        }
    }
}

impl Default for KeyEventInstance {
    fn default() -> Self {
        Self::new()
    }
}

// Getters
impl KeyEventInstance {
    pub fn started(&self) -> bool {
        self.started.is_some()
    }
    pub fn current_attempt(&self) -> AttemptId {
        self.attempt.clone()
    }
}
// helper function
impl KeyEventInstance {
    fn vote_alive(&mut self) {
        self.last_vote = env::block_height()
    }
}
// Voting API
impl KeyEventInstance {
    pub fn activate(&mut self, leader: AuthenticatedLeader) -> Result<(), Error> {
        if self.started.is_none() {
            self.vote_alive();
            self.started = Some(leader);
            Ok(())
        } else {
            Err(KeyEventError::ActiveKeyEvent.into())
        }
    }
    /// Commits the vote of `candidate` to `public_key`, returning the total number of votes for `public_key`.
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
        self.vote_alive();
        Ok(self.completed.len() as u64)
    }
    /// Casts a vote from `candidate` to abort the current instance.
    /// Returns an error if `candidate` already voted.
    /// Returns the number of votes received to abort.
    pub fn vote_abort(&mut self, candidate: AuthenticatedCandidateId) -> Result<u64, Error> {
        // if candidate already aborted, then exit with error
        if self.aborted.contains(&candidate) {
            return Err(VoteError::VoterAlreadyAborted.into());
        }
        // return error if the candidate alredy submitted a vote.
        if self.completed.contains(&candidate) {
            return Err(VoteError::VoteAlreadySubmitted.into());
        }
        self.aborted.insert(candidate);
        self.vote_alive();
        Ok(self.aborted.len() as u64)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct AuthenticatedLeader(ParticipantId);

#[cfg(test)]
pub mod tests {
    use super::AuthenticatedLeader;
    use crate::primitives::key_state::tests::gen_key_state_proposal;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyEventId};
    use crate::primitives::participants::{AuthenticatedCandidateId, ParticipantId};
    use crate::primitives::test_utils::{gen_account_id, gen_seed};
    use crate::state::key_event::{InstanceStatus, KeyEvent, KeyEventInstance, Tally};
    use near_sdk::{test_utils::VMContextBuilder, testing_env, AccountId, BlockHeight};
    use rand::Rng;
    use std::collections::BTreeSet;
    use std::mem;
    pub struct Environment {
        pub signer: AccountId,
        pub block_height: BlockHeight,
        pub seed: [u8; 32],
    }
    impl Environment {
        pub fn new(
            block_height: Option<BlockHeight>,
            signer: Option<AccountId>,
            seed: Option<[u8; 32]>,
        ) -> Self {
            let seed = seed.unwrap_or(gen_seed());
            let mut ctx = VMContextBuilder::new();
            let block_height = block_height.unwrap_or(rand::thread_rng().gen());
            ctx.block_height(block_height);
            ctx.random_seed(seed);
            let signer = signer.unwrap_or(gen_account_id());
            ctx.signer_account_id(signer.clone());
            testing_env!(ctx.build());
            Environment {
                signer,
                block_height,
                seed,
            }
        }
        pub fn set_signer(&mut self, signer: &AccountId) {
            self.signer = signer.clone();
            self.set();
        }
        pub fn set(&self) {
            let mut ctx = VMContextBuilder::new();
            ctx.block_height(self.block_height);
            ctx.random_seed(self.seed);
            ctx.signer_account_id(self.signer.clone());
            testing_env!(ctx.build());
        }
        pub fn set_block_height(&mut self, block_height: BlockHeight) {
            self.block_height = block_height;
            self.set();
        }
        pub fn advance_block_height(&mut self, delta: BlockHeight) {
            self.block_height += delta;
            self.set();
        }
    }
    fn gen_authentciated_leader() -> AuthenticatedLeader {
        let id: u32 = rand::thread_rng().gen();
        let leader: AuthenticatedLeader = unsafe { mem::transmute(id) };
        leader
    }
    #[test]
    fn test_key_event_instance_activate() {
        let mut env = Environment::new(None, None, None);
        let mut kei = KeyEventInstance::new();
        assert!(!kei.started());
        assert_eq!(kei.last_vote, env.block_height);
        env.advance_block_height(10);
        let leader = gen_authentciated_leader();
        assert!(kei.activate(leader).is_ok());
        assert_eq!(kei.last_vote, env.block_height);
        assert!(kei.started());
    }
    #[test]
    fn test_key_event_instance_vote_alive() {
        let mut env = Environment::new(None, None, None);
        let mut kei = KeyEventInstance::new();
        assert_eq!(kei.last_vote, env.block_height);
        env.advance_block_height(10);
        kei.vote_alive();
        assert!(!kei.started());
        assert_eq!(kei.last_vote, env.block_height);
    }
    #[test]
    fn test_key_event_instance_constructor() {
        let mut env = Environment::new(None, None, None);
        let kei = KeyEventInstance::new();
        assert_eq!(kei.current_attempt().get(), 0);
        assert!(!kei.started());
        assert_eq!(kei.last_vote, env.block_height);
        env.advance_block_height(10);
        let kei = kei.next_instance();
        assert_eq!(kei.current_attempt().get(), 1);
        assert_eq!(kei.last_vote, env.block_height);
    }
    fn gen_auth_candidate() -> AuthenticatedCandidateId {
        let id: u32 = rand::thread_rng().gen();
        let candidate: AuthenticatedCandidateId = unsafe { mem::transmute(id) };
        candidate
    }

    #[test]
    fn test_key_event_instance_vote_success() {
        let mut env = Environment::new(None, None, None);
        let mut kei = KeyEventInstance::new();
        // do not accept votes if not yet started:
        env.advance_block_height(10);
        let candidate = gen_auth_candidate();
        assert!(kei.vote_success(candidate.clone()).is_err());
        assert_eq!(kei.last_vote, env.block_height - 10);
        let leader = gen_authentciated_leader();
        assert!(kei.activate(leader).is_ok());
        assert_eq!(kei.last_vote, env.block_height);
        // do accept votes if started:
        env.advance_block_height(10);
        let candidate = gen_auth_candidate();
        assert_eq!(kei.vote_success(candidate.clone()).unwrap(), 1);
        assert_eq!(kei.last_vote, env.block_height);
        // do not accept subsequent abort votes
        assert!(kei.vote_abort(candidate.clone()).is_err());
        assert_eq!(kei.last_vote, env.block_height);
        env.advance_block_height(10);
        // do not accept subsequent success votes
        assert!(kei.vote_success(candidate.clone()).is_err());
        assert_eq!(kei.last_vote, env.block_height - 10);
    }
    #[test]
    fn test_key_event_instance_vote_abort() {
        let mut env = Environment::new(None, None, None);
        let mut kei = KeyEventInstance::new();
        // do accept aborts if not yet started:
        let candidate = gen_auth_candidate();
        assert_eq!(kei.vote_abort(candidate.clone()).unwrap(), 1);
        assert_eq!(kei.last_vote, env.block_height);
        // start instance
        env.advance_block_height(10);
        let leader = gen_authentciated_leader();
        assert!(kei.activate(leader).is_ok());
        assert_eq!(kei.last_vote, env.block_height);
        // do accept votes if started:
        env.advance_block_height(10);
        let candidate = gen_auth_candidate();
        assert_eq!(kei.vote_abort(candidate.clone()).unwrap(), 2);
        assert_eq!(kei.last_vote, env.block_height);
        env.advance_block_height(10);
        // do not accept subsequent success votes
        assert!(kei.vote_success(candidate.clone()).is_err());
        assert_eq!(kei.last_vote, env.block_height - 10);
        // do not accept subsequent abort votes
        assert!(kei.vote_abort(candidate.clone()).is_err());
        assert_eq!(kei.last_vote, env.block_height - 10);
    }
    pub fn find_leader(attempt: &AttemptId, kes: &KeyEvent) -> (AccountId, ParticipantId) {
        let mut env = Environment::new(None, None, None);
        let mut leader = None;
        for (account_id, _, _) in kes
            .proposed_threshold_parameters()
            .participants()
            .participants()
        {
            env.set_signer(account_id);
            if let Ok(tmp) = kes.authenticate_leader(attempt.clone()) {
                assert!(leader.is_none());
                leader = Some((account_id.clone(), tmp.0));
            }
            // ensure that each candidate is authenticated
            assert!(kes.authenticate_candidate().is_ok());
            // test a random account does not get authorized
            env.set_signer(&gen_account_id());
            assert!(kes.authenticate_candidate().is_err());
            assert!(kes.authenticate_leader(attempt.clone()).is_err());
        }
        assert!(leader.is_some());
        leader.unwrap()
    }
    #[test]
    fn test_key_event_state_constructors() {
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let proposed = gen_key_state_proposal(Some(10));
        let kes = KeyEvent::new(epoch_id.clone(), proposed.clone());
        let key_id = KeyEventId::new(epoch_id.clone(), AttemptId::new());
        assert_eq!(kes.current_key_event_id(), key_id);
        assert_eq!(kes.event_threshold(), proposed.key_event_threshold());
        assert_eq!(
            kes.proposed_threshold(),
            proposed.proposed_threshold_parameters().threshold()
        );
        assert_eq!(
            kes.proposed_threshold_parameters(),
            *proposed.proposed_threshold_parameters()
        );
        let mut attempt = AttemptId::new();
        let mut leaders = BTreeSet::new();
        for _ in 0..proposed
            .proposed_threshold_parameters()
            .participants()
            .count()
        {
            leaders.insert(find_leader(&attempt, &kes));
            attempt = attempt.next();
        }
        assert_eq!(
            leaders.len() as u64,
            proposed
                .proposed_threshold_parameters()
                .participants()
                .count()
        );
    }
    #[test]
    fn test_key_event_state_vote() {
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let proposed = gen_key_state_proposal(Some(10));
        let mut env = Environment::new(None, None, None);
        let mut kes = KeyEvent::new(epoch_id.clone(), proposed.clone());
        let key_id = KeyEventId::new(epoch_id.clone(), AttemptId::new());
        let attempt = AttemptId::new();
        let (leader_account, _) = find_leader(&attempt, &kes);

        // participants should not be able to vote before starting the event
        for (account_id, _, _) in proposed
            .proposed_threshold_parameters()
            .participants()
            .participants()
        {
            env.set_signer(account_id);
            if *account_id != leader_account {
                assert!(kes.start(100).is_err());
                assert!(kes.vote_abort(key_id.clone(), 100).is_err());
                assert!(kes.vote_success(&key_id, 100).is_err());
            } else {
                assert!(kes.vote_abort(key_id.clone(), 100).is_err());
                assert!(kes.vote_success(&key_id, 100).is_err());
            }
        }
        // non participant should not be able to vote
        for _ in 0..20 {
            env.set_signer(&gen_account_id());
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100).is_err());
        }

        // start event
        env.set_signer(&leader_account);
        assert!(kes.start(0).is_ok());

        // votes should not count if timed out:
        for (account_id, _, _) in proposed
            .proposed_threshold_parameters()
            .participants()
            .participants()
        {
            Environment::new(Some(env.block_height + 1), Some(account_id.clone()), None);
            assert!(kes.vote_abort(key_id.clone(), 0).is_err());
            assert!(kes.vote_success(&key_id, 0).is_err());
        }

        // non participant should not be able to vote
        for _ in 0..20 {
            Environment::new(Some(env.block_height), None, None);
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100).is_err());
        }

        // votes should count if not timed out:
        for (i, (account_id, _, _)) in proposed
            .proposed_threshold_parameters()
            .participants()
            .participants()
            .iter()
            .enumerate()
        {
            env.advance_block_height(1);
            env.set_signer(account_id);
            let x = kes.vote_success(&key_id, 1).unwrap();
            let reached = proposed.key_event_threshold().value() <= (i + 1) as u64;
            match x {
                Tally::ThresholdReached(_) => assert!(reached),
                Tally::ThresholdPending(_) => assert!(!reached),
            }
            // abort should not work after submitting a vote:
            assert!(kes.vote_abort(key_id.clone(), 1).is_err());
            // submitting another vote should not work
            assert!(kes.vote_success(&key_id, 1).is_err());

            // non-leaders should still not be able to start
            if *account_id != leader_account {
                assert!(kes.start(200).is_err());
            }
            // non participant should still not be able to vote
            env.set_signer(&gen_account_id());
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100).is_err());
        }

        // start another attempt:
        let attempt = attempt.next();
        let key_id = KeyEventId::new(epoch_id.clone(), attempt.clone());
        env.advance_block_height(300);
        let (leader_account, _) = find_leader(&attempt, &kes);
        env.set_signer(&leader_account);
        assert!(kes.start(1).is_ok());
        for (i, (account_id, _, _)) in proposed
            .proposed_threshold_parameters()
            .participants()
            .participants()
            .iter()
            .enumerate()
        {
            env.set_signer(account_id);
            // abort should count if not timed out:
            let x = kes.vote_abort(key_id.clone(), 1).unwrap();
            if proposed.key_event_threshold().value()
                > proposed
                    .proposed_threshold_parameters()
                    .participants()
                    .count()
                    - ((i + 1) as u64)
            {
                assert_eq!(x, InstanceStatus::Replaced);
                break;
            } else {
                assert_eq!(x, InstanceStatus::Pending);
                // abort should not work after aborting:
                assert!(kes.vote_abort(key_id.clone(), 1).is_err());
                // submitting another vote should not work either
                assert!(kes.vote_success(&key_id, 1).is_err());
                // non-leaders should still not be able to start
                if *account_id != leader_account {
                    assert!(kes.start(200).is_err());
                }
            }

            // non participant should still not be able to vote
            env.set_signer(&gen_account_id());
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100).is_err());
        }
    }
}
