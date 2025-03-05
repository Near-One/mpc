use super::running::RunningContractState;
use crate::errors::VoteError;
use crate::errors::{Error, KeyEventError};
use crate::primitives::key_state::{DKState, KeyEventId, KeyStateProposal};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::log;
use near_sdk::{env, near, AccountId, PublicKey};
use std::collections::BTreeMap;

use std::collections::HashSet;

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct Votes {
    pub votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Default for Votes {
    fn default() -> Self {
        Self::new()
    }
}

impl Votes {
    pub fn new() -> Self {
        Votes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, account_id: AccountId) -> &mut HashSet<AccountId> {
        self.votes.entry(account_id).or_default()
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, HashSet<AccountId>>,
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

    pub fn entry(&mut self, public_key: PublicKey) -> &mut HashSet<AccountId> {
        self.votes.entry(public_key).or_default()
    }
}
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct KeygenInstance {
    pub key_event_id: KeyEventId,
    pub participants_completed: BTreeMap<AccountId, PublicKey>,
    pub pk_votes: PkVotes,
    pub active: bool,
}
impl KeygenInstance {
    pub fn active(&self, timeout_in_blocks: u64) -> bool {
        self.active && !self.key_event_id.timed_out(timeout_in_blocks)
    }
    pub fn new(key_event_id: KeyEventId) -> Self {
        KeygenInstance {
            key_event_id,
            participants_completed: BTreeMap::new(),
            pk_votes: PkVotes::new(),
            active: true,
        }
    }
    /// Commits the vote of `account_id` to `public_key`, removing any previous votes and returning the total number of votes for `public_key`.
    pub fn vote_pk(&mut self, account_id: AccountId, public_key: PublicKey) -> Result<u64, Error> {
        if let Some(prev_vote) = self
            .participants_completed
            .insert(account_id.clone(), public_key.clone())
        {
            log!("removing previous vote");
            if !self.pk_votes.entry(prev_vote).remove(&account_id) {
                return Err(VoteError::InconsistentVotingState.into());
            }
        }
        self.pk_votes.entry(public_key.clone()).insert(account_id);
        Ok(self.pk_votes.entry(public_key).len() as u64)
    }
    /// Returns the total number of votes for `public_key`
    pub fn n_votes(&self, public_key: &PublicKey) -> u64 {
        self.pk_votes.n_votes(public_key) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::test_utils::gen_rand_account_id;
    //use crate::state::protocol_state::KeygenInstance;
    use crate::state::tests::test_utils::gen_rand_pk;
    use near_sdk::{AccountId, PublicKey};

    #[test]
    fn test_keygen_instance() {
        let leader_account: AccountId = gen_rand_account_id();
        let key_event_id = KeyEventId::new(1, leader_account.clone());
        //assert_eq!(leader_account, *key_event_id.leader());
        //log!(key_event_id.)
        //assert_eq!(leader_account, *key_event_id.leader());
        let mut instance = KeygenInstance::new(key_event_id);
        let account_id = gen_rand_account_id();
        let pk1: PublicKey = gen_rand_pk();
        let votes = instance.vote_pk(account_id.clone(), pk1.clone()).unwrap();
        assert_eq!(votes, 1);
        assert_eq!(instance.n_votes(&pk1), 1);

        let pk2: PublicKey = "secp256k1:qMoRgcoXai4mBPsdbHi1wfyxF9TdbPCF4qSDQTRP3TfescSRoUdSx6nmeQoN3aiwGzwMyGXAb1gUjBTv5AY8DXj".parse().unwrap();
        let votes = instance.vote_pk(account_id, pk2.clone()).unwrap();
        assert_eq!(votes, 1);
        assert_eq!(instance.n_votes(&pk1), 0);
        assert_eq!(instance.n_votes(&pk2), 1);
    }
}
#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub proposed_key_state: KeyStateProposal,
    pub current_keygen_instance: Option<KeygenInstance>,
}
impl InitializingContractState {
    /// Starts a new keygen instance.
    /// Returns an Error if the signer is not the leader of the current keygen leader or there is an active keygen ongoing
    pub fn start_keygen_instance(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        let signer = env::signer_account_id();
        // ensure there is no active keygen
        if self.has_active_keygen(dk_event_timeout_blocks) {
            return Err(KeyEventError::ActiveKeyEvent.into());
        }
        // ensure this function is called by the leader
        if signer != self.keygen_leader() {
            return Err(VoteError::VoterNotLeader.into());
        }

        // generate new key event id
        let key_event_id = KeyEventId::new(0, signer);
        // reset resharing instance:
        self.current_keygen_instance = Some(KeygenInstance::new(key_event_id));
        Ok(())
    }
    /// Casts a vote for `public_key` in `key_event_id`, removing any prior votes by `signer`.
    /// Fails if `signer` is not a candidate or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.proposed_key_state.is_proposed(&signer) {
            return Err(VoteError::VoterNotParticipant.into());
        }
        // ensure there is an active reshare
        if !self.has_active_keygen(dk_event_timeout_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into()); // todo: fix errors and clean them up
        }
        // Ensure the key_event_id matches
        let current = self.current_keygen_instance.as_mut().unwrap();
        if current.key_event_id != key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        // Finally, vote for the reshare instance
        let n_votes = current.vote_pk(signer, public_key.clone())?;
        if self.proposed_key_state.key_event_threshold().value() <= n_votes {
            return Ok(Some(RunningContractState {
                key_state: DKState::new(
                    public_key,
                    self.current_keygen_instance
                        .as_ref()
                        .unwrap()
                        .key_event_id
                        .clone(),
                    self.proposed_key_state
                        .proposed_threshold_parameters()
                        .clone(),
                )?,
                key_state_votes: KeyStateVotes::default(),
            }));
        }
        Ok(None)
    }
    /// returns true if there is an active reshare instance
    pub fn has_active_keygen(&self, dk_event_timeout_blocks: u64) -> bool {
        match &self.current_keygen_instance {
            None => false,
            Some(current) => current.active(dk_event_timeout_blocks),
        }
    }
    /// Returns the AccountId of the current keygen leader
    pub fn keygen_leader(&self) -> AccountId {
        let last_uid = if let Some(current_keygen) = &self.current_keygen_instance {
            current_keygen.key_event_id.uid()
        } else {
            0
        };
        let leader_idx = last_uid % self.proposed_key_state.n_proposed_participants();
        match self.proposed_key_state.candidate_by_index(leader_idx) {
            Ok(res) => res,
            Err(err) => env::panic_str(&err.to_string()),
        }
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(state: &legacy_contract::InitializingContractState) -> Self {
        InitializingContractState {
            proposed_key_state: state.into(),
            current_keygen_instance: None,
        }
    }
}
