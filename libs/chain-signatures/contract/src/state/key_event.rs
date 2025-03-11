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
#[derive(Debug, Clone)]
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
    pub fn event_threshold(&self) -> DKGThreshold {
        self.event.threshold()
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
        let candidate = self.event.authenticate_candidate()?;
        // ensure the instance was started and is active
        if !self.instance.started() || self.instance.timed_out(dk_event_timeout_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        }
        // Ensure the key_event_id matches
        if self.current_key_event_id() != *key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        Ok(candidate)
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
        let candidate = self.verify_vote(key_event_id, dk_event_timeout_blocks)?;
        let n_votes = self.instance.vote_success(candidate.clone())?;
        if let Some(cb) = callback {
            cb(candidate);
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
        let candidate = self.verify_vote(&key_event_id, dk_event_timeout_blocks)?;
        let n_votes = self.instance.vote_abort(candidate)?;
        if self.event.n_candidates() - n_votes < self.event.threshold().value() {
            // we can't achieve `dkg_threshold` votes anymore, abort this instance and reset
            self.instance = self.instance.next_instance();
            return Ok(true);
        }
        Ok(false)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
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
        self.key_event_instance.vote_alive();
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
        Ok(self.aborted.len() as u64)
    }
}

impl Default for KeyEventInstance {
    fn default() -> Self {
        Self::new()
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct AuthenticatedLeader(ParticipantId);

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
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
        let candidate = self.proposed_key_state.authenticate()?;
        if expected_id == candidate.get() {
            Ok(AuthenticatedLeader(candidate.get()))
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
pub mod tests {
    use super::{AuthenticatedLeader, KeyEvent, KeyEventAttempt};
    use crate::primitives::key_state::tests::gen_key_state_proposal;
    use crate::primitives::key_state::{
        AttemptId, AuthenticatedCandidateId, EpochId, KeyEventId, KeyStateProposal,
    };
    use crate::primitives::participants::ParticipantId;
    use crate::state::key_event::{KeyEventInstance, KeyEventState};
    use crate::state::tests::test_utils::{gen_account_id, gen_seed};
    use near_sdk::{test_utils::VMContextBuilder, testing_env, AccountId, BlockHeight};
    use rand::Rng;
    use std::{cell::RefCell, collections::BTreeSet, mem};

    pub struct EnvVars {
        pub block_height: BlockHeight,
        pub seed: [u8; 32],
    }
    /// Sets environment variables `block_height`, `random_seed` and `signer_account_id`.
    /// Generates pseudo-random values if none are provided.
    pub fn set_env(
        block_height: Option<BlockHeight>,
        signer: Option<AccountId>,
        seed: Option<[u8; 32]>,
    ) -> EnvVars {
        let seed = seed.unwrap_or(gen_seed());
        let mut ctx = VMContextBuilder::new();
        let block_height = block_height.unwrap_or(rand::thread_rng().gen());
        ctx.block_height(block_height);
        ctx.random_seed(seed);
        let signer = signer.unwrap_or(gen_account_id());
        ctx.signer_account_id(signer.clone());
        testing_env!(ctx.build());
        EnvVars { block_height, seed }
    }

    #[test]
    fn test_key_event_attempt() {
        let EnvVars { block_height, .. } = set_env(None, None, None);
        let mut kea = KeyEventAttempt::new();
        assert_eq!(kea.id().get(), 0);
        assert!(!kea.timed_out(0));
        set_env(Some(block_height + 200), None, None);
        assert!(kea.timed_out(199));
        assert!(!kea.timed_out(200));
        kea.vote_alive();
        assert!(!kea.timed_out(0));
        let kea = kea.next();
        assert_eq!(kea.id().get(), 1);
        assert!(!kea.timed_out(0));
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
    pub fn find_leader(
        proposed: &KeyStateProposal,
        attempt: &AttemptId,
        ke: &KeyEvent,
    ) -> ParticipantId {
        let mut leader = None;
        for account_id in proposed.candidates().participants().keys() {
            set_env(None, Some((*account_id).clone()), None);
            if let Ok(tmp) = ke.authenticate_leader(attempt.clone()) {
                assert!(leader.is_none());
                leader = Some(tmp.0);
            }
            // ensure that each candidate is authenticated
            assert!(ke.authenticate_candidate().is_ok());
            set_env(None, None, None);
            // test if a random account gets any authorizations
            assert!(ke.authenticate_candidate().is_err());
            assert!(ke.authenticate_leader(attempt.clone()).is_err());
        }
        assert!(leader.is_some());
        leader.unwrap()
        //leaders.insert(leader.unwrap());
        //attempt = attempt.next();
    }
    #[test]
    fn test_key_event() {
        let epoch_id = rand::thread_rng().gen();
        let epoch_id = EpochId::new(epoch_id);
        let proposed = gen_key_state_proposal(Some(30));
        set_env(None, None, None);
        let ke = KeyEvent::new(epoch_id.clone(), proposed.clone());
        assert_eq!(proposed, ke.proposed_key_state);
        assert_eq!(epoch_id, ke.epoch_id());
        assert_eq!(proposed.key_event_threshold(), ke.threshold());
        assert_eq!(proposed.n_proposed_participants(), ke.n_candidates());
        assert_eq!(
            *proposed.proposed_threshold_parameters(),
            *ke.proposed_threshold_parameters()
        );
        let mut attempt = AttemptId::new();
        let mut leaders = BTreeSet::new();
        for _ in 0..proposed.n_proposed_participants() {
            leaders.insert(find_leader(&proposed, &attempt, &ke));
            attempt = attempt.next();
        }
        assert_eq!(leaders.len() as u64, proposed.n_proposed_participants());
    }

    #[test]
    fn test_key_event_state() {
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let proposed = gen_key_state_proposal(Some(10));
        let EnvVars {
            block_height, seed, ..
        } = set_env(None, None, None);
        let mut kes = KeyEventState::new(epoch_id.clone(), proposed.clone());
        let key_id = KeyEventId::new(epoch_id.clone(), AttemptId::new());
        // try to vote as a non participants:
        let counted = RefCell::new(0);
        let count = Some(|_: AuthenticatedCandidateId| {
            *counted.borrow_mut() += 1;
        });
        let attempt = AttemptId::new();
        let leader = find_leader(&proposed, &attempt, &kes.event);

        for account_id in proposed.candidates().participants().keys() {
            set_env(Some(block_height), Some(account_id.clone()), Some(seed));
            // votes should not count if submitted before starting:
            if proposed.candidates().id(account_id).unwrap() != leader {
                assert!(kes.start(100).is_err());
                assert!(kes.vote_abort(key_id.clone(), 100).is_err());
                assert!(kes.vote_success(&key_id, 100, count).is_err());
                assert_eq!(*counted.borrow(), 0);
            } else {
                assert!(kes.vote_abort(key_id.clone(), 100).is_err());
                assert!(kes.vote_success(&key_id, 100, count).is_err());
                assert_eq!(*counted.borrow(), 0);
            }
            // non participant should not be able to vote
            set_env(Some(block_height), None, Some(seed));
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), 0);
        }

        set_env(
            Some(block_height),
            Some(proposed.candidates().account_id(&leader).unwrap()),
            Some(seed),
        );
        assert!(kes.start(0).is_ok());

        for account_id in proposed.candidates().participants().keys() {
            set_env(Some(block_height + 1), Some(account_id.clone()), Some(seed));
            // votes should not count if timed out:
            assert!(kes.vote_abort(key_id.clone(), 0).is_err());
            assert!(kes.vote_success(&key_id, 0, count).is_err());
            assert_eq!(*counted.borrow(), 0);
            // non participant should still not be able to vote
            set_env(Some(block_height), None, Some(seed));
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), 0);
        }

        let mut block_height = block_height;
        for (i, account_id) in proposed.candidates().participants().keys().enumerate() {
            block_height += 1;
            set_env(Some(block_height), Some(account_id.clone()), Some(seed));
            // votes should count if not timed out:
            let x = kes.vote_success(&key_id, 1, count).unwrap();
            assert_eq!(*counted.borrow(), i + 1);
            if proposed.key_event_threshold().value() <= (i + 1) as u64 {
                assert!(x);
            } else {
                assert!(!x);
            }

            // abort should not work after submitting a vote:
            assert!(kes.vote_abort(key_id.clone(), 1).is_err());
            // submitting another vote should not work
            assert!(kes.vote_success(&key_id, 1, count).is_err());
            assert_eq!(*counted.borrow(), i + 1);

            // non-leaders should still not be able to start
            if proposed.candidates().id(account_id).unwrap() != leader {
                assert!(kes.start(200).is_err());
            }
            // non participant should still not be able to vote
            set_env(Some(block_height), None, Some(seed));
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), i + 1);
        }

        // start another attempt:
        let attempt = attempt.next();
        let key_id = KeyEventId::new(epoch_id.clone(), attempt.clone());
        block_height += 300;
        let EnvVars { seed, .. } = set_env(Some(block_height), None, None);
        let leader = find_leader(&proposed, &attempt, &kes.event);
        set_env(
            Some(block_height),
            Some(proposed.candidates().account_id(&leader).unwrap()),
            Some(seed),
        );
        assert!(kes.start(1).is_ok());
        *counted.borrow_mut() = 0;
        for (i, account_id) in proposed.candidates().participants().keys().enumerate() {
            set_env(Some(block_height), Some(account_id.clone()), Some(seed));
            // abort should count if not timed out:
            let x = kes.vote_abort(key_id.clone(), 1).unwrap();
            if proposed.key_event_threshold().value()
                > proposed.n_proposed_participants() - ((i + 1) as u64)
            {
                assert!(x);
                break;
            } else {
                assert!(!x);
                // abort should not work after aborting:
                assert!(kes.vote_abort(key_id.clone(), 1).is_err());
                // submitting another vote should not work either
                assert!(kes.vote_success(&key_id, 1, count).is_err());
                assert_eq!(*counted.borrow(), 0);
                // non-leaders should still not be able to start
                if proposed.candidates().id(account_id).unwrap() != leader {
                    assert!(kes.start(200).is_err());
                }
            }

            // non participant should still not be able to vote
            set_env(Some(block_height), None, Some(seed));
            assert!(kes.start(100).is_err());
            assert!(kes.vote_abort(key_id.clone(), 100).is_err());
            assert!(kes.vote_success(&key_id, 100, count).is_err());
            assert_eq!(*counted.borrow(), 0);
        }
    }
}
