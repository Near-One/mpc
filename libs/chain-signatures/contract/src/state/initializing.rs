use super::key_event::{InstanceStatus, KeyEvent, Tally};
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::key_state::{DKState, EpochId, KeyEventId};
use crate::primitives::participants::AuthenticatedCandidateId;
use crate::primitives::votes::KeyStateVotes;
use near_sdk::BlockHeight;
use near_sdk::{near, PublicKey};
use std::collections::BTreeMap;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<AuthenticatedCandidateId, PublicKey>,
}

impl Default for PkVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl PkVotes {
    pub fn new() -> Self {
        PkVotes {
            votes: BTreeMap::new(),
        }
    }
    pub fn n_votes(&self, public_key: &PublicKey) -> u64 {
        self.votes.values().filter(|&pk| pk == public_key).count() as u64
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub keygen: KeyEvent,
    pub pk_votes: PkVotes,
}
impl InitializingContractState {
    pub fn authenticate_candidate(&self) -> Result<AuthenticatedCandidateId, Error> {
        self.keygen.authenticate_candidate()
    }
    /// Starts a new keygen instance.
    /// Returns an Error if the signer is not the leader of the current keygen.
    pub fn start(&mut self, event_max_idle_blocks: u64) -> Result<(), Error> {
        self.keygen.start(event_max_idle_blocks)
    }
    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        event_max_idle_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        let x = self
            .keygen
            .vote_success(&key_event_id, event_max_idle_blocks)?;
        match x {
            Tally::ThresholdReached(candidate_id) => {
                self.pk_votes.votes.insert(candidate_id, public_key.clone());
                if self.pk_votes.n_votes(&public_key) >= self.keygen.event_threshold().value() {
                    return Ok(Some(RunningContractState {
                        key_state: DKState::new(
                            public_key,
                            key_event_id,
                            self.keygen.proposed_threshold_parameters().clone(),
                        )?,
                        key_state_votes: KeyStateVotes::default(),
                    }));
                }
            }
            Tally::ThresholdPending(candidate_id) => {
                self.pk_votes.votes.insert(candidate_id, public_key.clone());
            }
        }
        Ok(None)
    }
    /// Casts a vote to abort the current keygen instance.
    /// Replaces the current instance in case dkg threshold can't be reached anymore.
    pub fn vote_abort(
        &mut self,
        key_event_id: KeyEventId,
        event_max_idle_blocks: BlockHeight,
    ) -> Result<InstanceStatus, Error> {
        self.keygen.vote_abort(key_event_id, event_max_idle_blocks)
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(state: &legacy_contract::InitializingContractState) -> Self {
        InitializingContractState {
            keygen: KeyEvent::new(EpochId::new(0), state.into()),
            pk_votes: PkVotes::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InitializingContractState;
    use crate::primitives::key_state::KeyEventId;
    use crate::primitives::key_state::{tests::gen_key_state_proposal, EpochId};
    use crate::primitives::test_utils::{gen_account_id, gen_legacy_initializing_state, gen_pk};
    use crate::primitives::votes::KeyStateVotes;
    use crate::state::key_event::tests::{find_leader, Environment};
    use crate::state::key_event::{InstanceStatus, KeyEvent};
    use crate::state::running::RunningContractState;
    use near_sdk::AccountId;
    use rand::Rng;
    use std::collections::BTreeSet;

    #[test]
    fn test_migration() {
        let n = 200;
        let k = 2;
        let legacy_state = gen_legacy_initializing_state(n, k);
        let state: InitializingContractState = (&legacy_state).into();
        assert_eq!(
            state
                .keygen
                .proposed_threshold_parameters()
                .threshold()
                .value(),
            k as u64
        );
        assert_eq!(state.keygen.event_threshold().value(), n as u64);
        assert_eq!(state.keygen.current_key_event_id().epoch_id().get(), 0u64);
        assert_eq!(state.keygen.current_key_event_id().attempt().get(), 0u64);
    }
    fn gen_initializing_state() -> (Environment, InitializingContractState) {
        let env = Environment::new(None, None, None);
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let proposed = gen_key_state_proposal(Some(30));
        let ke = KeyEvent::new(epoch_id.clone(), proposed.clone());
        (
            env,
            InitializingContractState {
                keygen: ke.clone(),
                pk_votes: super::PkVotes::new(),
            },
        )
    }

    #[test]
    fn test_initializing_contract_state() {
        let (mut env, mut state) = gen_initializing_state();
        let candidates: BTreeSet<AccountId> = state
            .keygen
            .proposed_threshold_parameters()
            .participants()
            .participants()
            .iter()
            .map(|(aid, _, _)| aid.clone())
            .collect();
        let key_event = state.keygen.current_key_event_id();
        let leader = find_leader(&key_event.attempt(), &state.keygen);
        for c in &candidates {
            env.set_signer(c);
            // verify that each candidate is authorized
            assert!(state.authenticate_candidate().is_ok());
            // verify that no votes are casted before the kegen started.
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
            if *c != leader.0 {
                assert!(state.start(1).is_err());
            }
        }
        // check that some randos can't vote
        for _ in 0..20 {
            env.set_signer(&gen_account_id());
            assert!(state.authenticate_candidate().is_err());
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
        }
        // start the keygen:
        env.set_signer(&leader.0);
        assert!(state.start(0).is_ok());

        // assert that timed out votes do not count
        env.advance_block_height(1);
        for c in &candidates {
            env.set_signer(c);
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
        }

        // check that some randos can't vote
        env.block_height -= 1;
        env.set();
        for _ in 0..20 {
            env.set_signer(&gen_account_id());
            assert!(state.authenticate_candidate().is_err());
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
        }

        // assert that votes for a different keygen do not count
        let ke = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
        for c in &candidates {
            env.set_signer(c);
            assert!(state.vote_pk(ke.clone(), gen_pk(), 10).is_err());
            assert!(state.vote_abort(ke.clone(), 10).is_err());
        }
        let ke = KeyEventId::new(key_event.epoch_id().next(), key_event.attempt());
        for c in &candidates {
            env.set_signer(c);
            assert!(state.vote_pk(ke.clone(), gen_pk(), 10).is_err());
            assert!(state.vote_abort(ke.clone(), 10).is_err());
        }

        // assert that valid votes do count
        for c in &candidates {
            env.set_signer(c);
            let x = state.vote_pk(key_event.clone(), gen_pk(), 0).unwrap();
            // everybody voting for a random key
            assert!(x.is_none());
            // assert we can't abort after voting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
            // assert we can't vote after voting
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
        }

        // find leader for next attempt
        env.advance_block_height(100);
        let leader = find_leader(&key_event.attempt().next(), &state.keygen);
        env.set_signer(&leader.0);
        assert!(state.start(0).is_ok());
        let key_event = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
        assert_eq!(key_event, state.keygen.current_key_event_id());

        // assert that valid votes get counted correctly:
        let pk = gen_pk();
        let mut res: Option<RunningContractState> = None;
        for (i, c) in candidates.clone().into_iter().enumerate() {
            env.set_signer(&c);
            res = state.vote_pk(key_event.clone(), pk.clone(), 0).unwrap();
            // everybody voting for the same key
            if ((i + 1) as u64) < state.keygen.event_threshold().value() {
                assert!(res.is_none());
            } else {
                assert!(res.is_some());
                break;
            }
            // assert we can't abort after voting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
        }
        // assert running state is correct
        let running_state = res.unwrap();
        assert_eq!(
            running_state.key_state.threshold(),
            state.keygen.proposed_threshold(),
        );
        assert_eq!(
            *running_state.key_state.participants(),
            *state.keygen.proposed_threshold_parameters().participants()
        );
        assert_eq!(*running_state.public_key(), pk);
        assert_eq!(running_state.key_state.key_event_id(), key_event);
        assert_eq!(running_state.key_state_votes, KeyStateVotes::new());

        // assert that the instance resets after a timeout
        env.advance_block_height(100);
        let leader = find_leader(&key_event.attempt().next(), &state.keygen);
        env.set_signer(&leader.0);
        assert!(state.start(0).is_ok());
        let key_event = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
        assert_eq!(key_event, state.keygen.current_key_event_id());
        // assert that valid aborts get counted correctly:
        for (i, c) in candidates.clone().into_iter().enumerate() {
            env.set_signer(&c);
            // assert we can abort
            let x = state.vote_abort(key_event.clone(), 0).unwrap();
            if state
                .keygen
                .proposed_threshold_parameters()
                .participants()
                .count()
                - ((i + 1) as u64)
                < state.keygen.event_threshold().value()
            {
                assert_eq!(x, InstanceStatus::Replaced);
                let key_event = KeyEventId::new(key_event.epoch_id(), key_event.attempt().next());
                assert_eq!(state.keygen.current_key_event_id(), key_event);
                break;
            } else {
                assert_eq!(x, InstanceStatus::Pending);
            }
            // assert we can't abort after aborting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
            // assert we can't vote after aborting
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
        }
        // restart the keygen
        let attempt = key_event.attempt().next();
        let leader = find_leader(&attempt, &state.keygen);
        println!("{:?}", state.keygen.current_key_event_id());
        println!("{:?}", attempt);
        env.set_signer(&leader.0);
        let res = state.start(0);
        println!("{:?}", res);
        println!("{:?}", state.keygen.current_key_event_id());
        assert!(res.is_ok());
    }
}
