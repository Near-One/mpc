use super::key_event::KeyEventState;
use super::running::RunningContractState;
use crate::errors::Error;
use crate::primitives::key_state::{
    AuthenticatedCandidateId, AuthenticatedParticipantId, DKState, EpochId, KeyEventId,
    KeyStateProposal,
};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{near, BlockHeight, PublicKey};

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
#[cfg(test)]
mod tests {
    //use crate::primitives::key_state::tests::gen_key_state_proposal;
    //use crate::primitives::key_state::{DKState, EpochId};
    //use crate::primitives::votes::KeyStateVotes;
    //use crate::state::key_event::tests::{set_env, EnvVars};
    //use crate::state::key_event::KeyEventState;
    //use crate::state::resharing::ResharingContractState;
    //use crate::state::running::RunningContractState;
    //use crate::state::tests::test_utils::{
    //    gen_key_event_id, gen_legacy_resharing_state, gen_pk, gen_threshold_params,
    //};
    //use rand::Rng;
    use crate::state::{
        resharing::ResharingContractState, tests::test_utils::gen_legacy_resharing_state,
    };

    #[test]
    fn test_migration() {
        let n = 200;
        let k = 2;
        let legacy_state = gen_legacy_resharing_state(n, k);
        let state: ResharingContractState = (&legacy_state).into();
        assert_eq!(*state.public_key(), legacy_state.public_key);
        assert_eq!(state.current_state.epoch_id().get(), legacy_state.old_epoch);
        assert_eq!(
            state.current_state.key_state.threshold().value(),
            legacy_state.threshold as u64
        );
        assert_eq!(state.event_state.event_threshold().value(), k as u64);
        assert_eq!(
            state.event_state.current_key_event_id().epoch_id().get(),
            legacy_state.old_epoch + 1
        );
        assert_eq!(
            state.event_state.current_key_event_id().attempt().get(),
            0u64
        );
    }
    //#[test]
    //fn test_initializing_contract_state() {
    //    // todo
    //    //let epoch_id = rand::thread_rng().gen();
    //    //let epoch_id = EpochId::new(epoch_id);
    //    //let proposed = gen_key_state_proposal(Some(30));
    //    //let EnvVars { block_height, seed } = set_env(None, None, None);
    //    //let ke = KeyEventState::new(epoch_id.clone(), proposed.clone());
    //    //let public_key = gen_pk();
    //    //let key_event_id = gen_key_event_id();
    //    //let threshold_params = gen_threshold_params(50);
    //    //let participants = threshold_params.participants().clone();
    //    //let key_state = DKState::new(public_key.clone(), key_event_id, threshold_params).unwrap();
    //    ////gen_key_state_proposal(max_n)
    //    //let current_state = RunningContractState {
    //    //    key_state,
    //    //    key_state_votes: KeyStateVotes::default(),
    //    //};
    //    //gen_key_e(max_n)
    //    //let event_state = KeyEventState{};
    //    //let mut state = ResharingContractState {
    //    //    current_state,
    //    //    event_state:
    //    //    keygen: ke.clone(),
    //    //    pk_votes: super::PkVotes::new(),
    //    //};
    //    //let key_event = KeyEventId::new(epoch_id.clone(), AttemptId::new());
    //    //let candidates: BTreeSet<AccountId> = ke
    //    //    .proposed_threshold_parameters()
    //    //    .participants()
    //    //    .participants()
    //    //    .keys()
    //    //    .cloned()
    //    //    .collect();
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    // verify that each candidate is authorized
    //    //    assert!(state.authenticate_candidate().is_ok());
    //    //    // verify that no votes are casted before the kegen started.
    //    //    assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
    //    //    assert!(state.vote_abort(key_event.clone(), 100).is_err());
    //    //}
    //    //// check that some randos can't vote
    //    //for _ in 0..20 {
    //    //    set_env(Some(block_height), None, Some(seed));
    //    //    assert!(state.authenticate_candidate().is_err());
    //    //    assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
    //    //    assert!(state.vote_abort(key_event.clone(), 100).is_err());
    //    //}

    //    //// start the keygen:
    //    //let mut leader = None;
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    if state.start(0).is_ok() {
    //    //        assert!(leader.is_none());
    //    //        leader = Some(c);
    //    //    }
    //    //}
    //    //assert!(leader.is_some());

    //    //// assert that timed out votes do not count
    //    //for c in &candidates {
    //    //    set_env(Some(block_height + 1), Some(c.clone()), Some(seed));
    //    //    assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
    //    //    assert!(state.vote_abort(key_event.clone(), 0).is_err());
    //    //}

    //    //// check that some randos can't vote
    //    //for _ in 0..20 {
    //    //    set_env(Some(block_height), None, Some(seed));
    //    //    assert!(state.authenticate_candidate().is_err());
    //    //    assert!(state.vote_pk(key_event.clone(), gen_pk(), 100).is_err());
    //    //    assert!(state.vote_abort(key_event.clone(), 100).is_err());
    //    //}

    //    //// assert that votes for a different keygen do not count
    //    //let ke = KeyEventId::new(epoch_id.next(), key_event.attempt().next());
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    assert!(state.vote_pk(ke.clone(), gen_pk(), 10).is_err());
    //    //    assert!(state.vote_abort(ke.clone(), 10).is_err());
    //    //}
    //    //// assert that valid votes do count
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    let x = state.vote_pk(key_event.clone(), gen_pk(), 0).unwrap();
    //    //    // everybody voting for a random key
    //    //    assert!(x.is_none());
    //    //    // assert we can't abort after voting
    //    //    assert!(state.vote_abort(key_event.clone(), 0).is_err());
    //    //    // assert we can't vote after voting
    //    //    assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
    //    //}

    //    //// reset the keygen
    //    //let block_height = block_height + 100;
    //    //let mut leader = None;
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    if state.start(0).is_ok() {
    //    //        assert!(leader.is_none());
    //    //        leader = Some(c);
    //    //    }
    //    //}
    //    //assert!(leader.is_some());
    //    //let key_event = KeyEventId::new(epoch_id.clone(), key_event.attempt().next());
    //    //assert_eq!(key_event, state.keygen.current_key_event_id());

    //    //// assert that valid votes get counted correctly:
    //    //let pk = gen_pk();
    //    //let mut res: Option<RunningContractState> = None;
    //    //for (i, c) in candidates.clone().into_iter().enumerate() {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    res = state.vote_pk(key_event.clone(), pk.clone(), 0).unwrap();
    //    //    // everybody voting for the same key
    //    //    if ((i + 1) as u64) < proposed.key_event_threshold().value() {
    //    //        assert!(res.is_none());
    //    //    } else {
    //    //        assert!(res.is_some());
    //    //        break;
    //    //    }
    //    //    // assert we can't abort after voting
    //    //    assert!(state.vote_abort(key_event.clone(), 0).is_err());
    //    //}
    //    //// assert running state is correct
    //    //let running_state = res.unwrap();
    //    //assert_eq!(
    //    //    running_state.key_state.threshold(),
    //    //    proposed.proposed_threshold()
    //    //);
    //    //assert_eq!(
    //    //    *running_state.key_state.participants(),
    //    //    *proposed.candidates()
    //    //);
    //    //assert_eq!(*running_state.public_key(), pk);
    //    //assert_eq!(running_state.key_state.key_event_id(), key_event);
    //    //assert_eq!(running_state.key_state_votes, KeyStateVotes::new());

    //    //// assert that the instance resets after a timeout
    //    //// reset the keygen
    //    //let block_height = block_height + 100;
    //    //let mut leader = None;
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    if state.start(0).is_ok() {
    //    //        assert!(leader.is_none());
    //    //        leader = Some(c);
    //    //    }
    //    //}
    //    //assert!(leader.is_some());
    //    //let key_event = KeyEventId::new(epoch_id, key_event.attempt().next());
    //    //assert_eq!(key_event, state.keygen.current_key_event_id());
    //    //// assert that valid aborts get counted correctly:
    //    ////let mut res: Option<RunningContractState> = None;
    //    //for (i, c) in candidates.clone().into_iter().enumerate() {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    // assert we can abort
    //    //    let x = state.vote_abort(key_event.clone(), 0).unwrap();
    //    //    if proposed.n_proposed_participants() - ((i + 1) as u64)
    //    //        < proposed.key_event_threshold().value()
    //    //    {
    //    //        assert!(x);
    //    //        break;
    //    //    } else {
    //    //        assert!(!x);
    //    //    }
    //    //    // assert we can't abort after aborting
    //    //    assert!(state.vote_abort(key_event.clone(), 0).is_err());
    //    //    // assert we can't vote after aborting
    //    //    assert!(state.vote_pk(key_event.clone(), gen_pk(), 0).is_err());
    //    //    //res = state.vote_pk(key_event.clone(), pk.clone(), 0).unwrap();
    //    //    // everybody voting for the same key
    //    //}
    //    //// assert that we can start anew:
    //    //// assert that the instance resets after a timeout
    //    //// reset the keygen
    //    //let block_height = block_height + 100;
    //    //let mut leader = None;
    //    //for c in &candidates {
    //    //    set_env(Some(block_height), Some(c.clone()), Some(seed));
    //    //    if state.start(0).is_ok() {
    //    //        assert!(leader.is_none());
    //    //        leader = Some(c);
    //    //    }
    //    //}
    //}
}
