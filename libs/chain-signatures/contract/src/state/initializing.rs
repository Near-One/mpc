use super::key_event::KeyEventState;
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::key_state::{AuthenticatedCandidateId, DKState, EpochId, KeyEventId};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::BlockHeight;
use near_sdk::{near, PublicKey};
use std::collections::{BTreeMap, BTreeSet};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, BTreeSet<AuthenticatedCandidateId>>,
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
    pub fn n_votes(&self, public_key: &PublicKey) -> usize {
        self.votes.get(public_key).map_or(0, |votes| votes.len())
    }

    pub fn entry(&mut self, public_key: PublicKey) -> &mut BTreeSet<AuthenticatedCandidateId> {
        self.votes.entry(public_key).or_default()
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub keygen: KeyEventState,
    pub pk_votes: PkVotes,
}
impl InitializingContractState {
    pub fn authenticate_candidate(&self) -> Result<AuthenticatedCandidateId, Error> {
        self.keygen.authenticate_candidate()
    }
    /// Starts a new keygen instance.
    /// Returns an Error if the signer is not the leader of the current keygen.
    pub fn start(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        self.keygen.start(dk_event_timeout_blocks)
    }
    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        let callback = Some(|candidate_id: AuthenticatedCandidateId| {
            self.pk_votes.entry(public_key.clone()).insert(candidate_id);
        });
        let reached = self
            .keygen
            .vote_success(&key_event_id, dk_event_timeout_blocks, callback)?;
        if reached
            && ((self.pk_votes.entry(public_key.clone()).len() as u64)
                >= self.keygen.event_threshold().value())
        {
            return Ok(Some(RunningContractState {
                key_state: DKState::new(
                    public_key,
                    key_event_id,
                    self.keygen.proposed_threshold_parameters().clone(),
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
        self.keygen
            .vote_abort(key_event_id, dk_event_timeout_blocks)
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(state: &legacy_contract::InitializingContractState) -> Self {
        InitializingContractState {
            keygen: KeyEventState::new(EpochId::new(0), state.into()),
            pk_votes: PkVotes::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::primitives::key_state::{tests::gen_key_state_proposal, EpochId};
    use crate::primitives::key_state::{AttemptId, KeyEventId};
    use crate::primitives::votes::KeyStateVotes;
    use crate::state::key_event::tests::{set_env, EnvVars};
    use crate::state::key_event::KeyEventState;
    use crate::state::running::RunningContractState;
    use crate::state::tests::test_utils::gen_pk;
    use near_sdk::AccountId;
    use rand::Rng;

    use super::InitializingContractState;
    #[test]
    fn test_initializing_contract_state() {
        let epoch_id = rand::thread_rng().gen();
        let epoch_id = EpochId::new(epoch_id);
        let proposed = gen_key_state_proposal(Some(30));
        let EnvVars { block_height, seed } = set_env(None, None, None);
        let ke = KeyEventState::new(epoch_id.clone(), proposed.clone());
        let mut state = InitializingContractState {
            keygen: ke.clone(),
            pk_votes: super::PkVotes::new(),
        };
        let key_event = KeyEventId::new(epoch_id.clone(), AttemptId::new());
        let candidates: BTreeSet<AccountId> = ke
            .proposed_threshold_parameters()
            .participants()
            .participants()
            .keys()
            .cloned()
            .collect();
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            // verify that each candidate is authorized
            assert!(state.authenticate_candidate().is_ok());
            // verify that no votes are casted before the kegen started.
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
        }
        // check that some randos can't vote
        for _ in 0..20 {
            set_env(Some(block_height), None, Some(seed));
            assert!(state.authenticate_candidate().is_err());
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
        }

        // start the keygen:
        let mut leader = None;
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            if state.start(0).is_ok() {
                assert!(leader.is_none());
                leader = Some(c);
            }
        }
        assert!(leader.is_some());

        // assert that timed out votes do not count
        for c in &candidates {
            set_env(Some(block_height + 1), Some(c.clone()), Some(seed));
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
        }

        // check that some randos can't vote
        for _ in 0..20 {
            set_env(Some(block_height), None, Some(seed));
            assert!(state.authenticate_candidate().is_err());
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
            assert!(state.vote_abort(key_event.clone(), 100).is_err());
        }

        // assert that votes for a different keygen do not count
        let ke = KeyEventId::new(epoch_id.next(), key_event.attempt().next());
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            assert!(state.vote_pk(ke.clone(), gen_pk(), 10).is_err());
            assert!(state.vote_abort(ke.clone(), 10).is_err());
        }
        // assert that valid votes do count
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            let x = state.vote_pk(key_event.clone(), gen_pk(), 0).unwrap();
            // everybody voting for a random key
            assert!(x.is_none());
            // assert we can't abort after voting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
            // assert we can't vote after voting
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
        }

        // reset the keygen
        let block_height = block_height + 100;
        let mut leader = None;
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            if state.start(0).is_ok() {
                assert!(leader.is_none());
                leader = Some(c);
            }
        }
        assert!(leader.is_some());
        let key_event = KeyEventId::new(epoch_id.clone(), key_event.attempt().next());
        assert_eq!(key_event, state.keygen.current_key_event_id());

        // assert that valid votes get counted correctly:
        let pk = gen_pk();
        let mut res: Option<RunningContractState> = None;
        for (i, c) in candidates.clone().into_iter().enumerate() {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            res = state.vote_pk(key_event.clone(), pk.clone(), 0).unwrap();
            // everybody voting for the same key
            if ((i + 1) as u64) < proposed.key_event_threshold().value() {
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
            proposed.proposed_threshold()
        );
        assert_eq!(
            *running_state.key_state.participants(),
            *proposed.candidates()
        );
        assert_eq!(*running_state.public_key(), pk);
        assert_eq!(running_state.key_state.key_event_id(), key_event);
        assert_eq!(running_state.key_state_votes, KeyStateVotes::new());

        // assert that the instance resets after a timeout
        // reset the keygen
        let block_height = block_height + 100;
        let mut leader = None;
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            if state.start(0).is_ok() {
                assert!(leader.is_none());
                leader = Some(c);
            }
        }
        assert!(leader.is_some());
        let key_event = KeyEventId::new(epoch_id, key_event.attempt().next());
        assert_eq!(key_event, state.keygen.current_key_event_id());
        // assert that valid aborts get counted correctly:
        //let mut res: Option<RunningContractState> = None;
        for (i, c) in candidates.clone().into_iter().enumerate() {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            // assert we can abort
            let x = state.vote_abort(key_event.clone(), 0).unwrap();
            if proposed.n_proposed_participants() - ((i + 1) as u64)
                < proposed.key_event_threshold().value()
            {
                assert!(x);
                break;
            } else {
                assert!(!x);
            }
            // assert we can't abort after aborting
            assert!(state.vote_abort(key_event.clone(), 0).is_err());
            // assert we can't vote after aborting
            assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
            //res = state.vote_pk(key_event.clone(), pk.clone(), 0).unwrap();
            // everybody voting for the same key
        }
        // assert that we can start anew:
        // assert that the instance resets after a timeout
        // reset the keygen
        let block_height = block_height + 100;
        let mut leader = None;
        for c in &candidates {
            set_env(Some(block_height), Some(c.clone()), Some(seed));
            if state.start(0).is_ok() {
                assert!(leader.is_none());
                leader = Some(c);
            }
        }
    }
}
