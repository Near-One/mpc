use super::key_state::KeyEventId;
use super::votes::PkVotes;
use crate::errors::Error;
use crate::errors::VoteError;
use near_sdk::{log, near, AccountId, PublicKey};
use std::collections::BTreeMap;

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
    use crate::state::{key_state::KeyEventId, tests::test_utils::gen_rand_account_id};
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
