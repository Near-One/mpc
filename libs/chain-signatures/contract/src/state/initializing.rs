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
        if self
            .keygen
            .vote_success(&key_event_id, dk_event_timeout_blocks, callback)?
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
    //
    //pub fn start_keygen_instance(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
    //
    //pub fn vote_pk(
    //pub fn has_active_keygen(&self, dk_event_timeout_blocks: u64) -> bool {
    //pub fn keygen_leader(&self) -> AccountId {
    //pub fn abort()
    //migrating
    //use super::*;
    //use crate::state::tests::test_utils::gen_account_id;
    //use crate::state::tests::test_utils::gen_pk;
    //use near_sdk::{AccountId, PublicKey};

    //#[test]
    //fn test_keygen_instance() {
    //    let leader_account: AccountId = gen_account_id();
    //    //let key_event_id = KeyEventId::new(1, leader_account.clone());
    //    let mut instance = Keygen::new(key_event_id);
    //    let account_id = gen_account_id();
    //    let pk1: PublicKey = gen_pk();
    //    let votes = instance.vote_pk(account_id.clone(), pk1.clone()).unwrap();
    //    assert_eq!(votes, 1);
    //    assert_eq!(instance.n_votes(&pk1), 1);

    //    let pk2: PublicKey = gen_pk();
    //    let votes = instance.vote_pk(account_id.clone(), pk2.clone()).unwrap();
    //    assert_eq!(votes, 1);
    //    assert_eq!(instance.n_votes(&pk1), 0);
    //    assert_eq!(instance.n_votes(&pk2), 1);
    //    assert!(instance.remove_vote(&account_id));
    //    assert_eq!(instance.abort(account_id.clone()), 1);
    //    assert!(instance.vote_pk(account_id.clone(), pk1.clone()).is_err());
    //    let account_id = gen_account_id();
    //    let votes = instance.vote_pk(account_id.clone(), pk1.clone()).unwrap();
    //    assert_eq!(votes, 1);
    //    assert_eq!(instance.n_votes(&pk1), 1);
    //    assert_eq!(instance.n_votes(&pk2), 0);
    //}
}
