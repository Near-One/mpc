use crate::errors::{Error, VoteError};
use crate::primitives::key_state::KeyStateProposal;
use near_sdk::{near, AccountId};
use std::collections::{BTreeMap, HashSet};

#[near(serializers=[borsh, json])]
#[derive(Debug, Default)]
pub struct KeyStateVotes {
    votes_by_proposal: BTreeMap<KeyStateProposal, HashSet<AccountId>>,
    proposal_by_account: BTreeMap<AccountId, KeyStateProposal>,
}

impl KeyStateVotes {
    pub fn new() -> Self {
        KeyStateVotes {
            votes_by_proposal: BTreeMap::new(),
            proposal_by_account: BTreeMap::new(),
        }
    }
    /// Removes the vote submitted by `account_id` from the state.
    /// Returns true if the vote was removed and false else.
    pub fn remove_vote(&mut self, account_id: &AccountId) -> bool {
        if let Some(proposal) = self.proposal_by_account.remove(account_id) {
            return self
                .votes_by_proposal
                .get_mut(&proposal)
                .is_some_and(|vote_set| vote_set.remove(account_id));
        }
        false
    }
    /// Registers a vote by `account_id` for `proposal` (inserts `proposal` if necessary).
    /// Returns an Error if `account_id` already registered a vote.
    /// Returns the number of votes for the current proposal.
    pub fn vote(
        &mut self,
        proposal: &KeyStateProposal,
        account_id: &AccountId,
    ) -> Result<u64, Error> {
        if self.proposal_by_account.contains_key(account_id) {
            return Err(VoteError::ParticipantVoteAlreadyRegistered.into());
        }
        if self
            .proposal_by_account
            .insert(account_id.clone(), proposal.clone())
            .is_some()
        {
            // this should not really happen
            return Err(VoteError::ParticipantVoteAlreadyRegistered.into());
        }
        Ok(self
            .votes_by_proposal
            .entry(proposal.clone())
            .and_modify(|votes| {
                votes.insert(account_id.clone());
            })
            .or_insert({
                let mut x = HashSet::new();
                x.insert(account_id.clone());
                x
            })
            .len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        primitives::key_state::tests::gen_key_state_proposal,
        state::tests::test_utils::gen_account_id,
    };

    use super::KeyStateVotes;

    #[test]
    fn test_voting_and_removal() {
        let account_id = gen_account_id();
        let mut ksv = KeyStateVotes::new();
        let ksp = gen_key_state_proposal();
        assert!(!ksv.remove_vote(&account_id));
        assert_eq!(ksv.vote(&ksp, &account_id).unwrap(), 1);
        assert!(ksv.vote(&ksp, &account_id).is_err());
        assert!(ksv.remove_vote(&account_id));
        let account_id = gen_account_id();
        assert_eq!(ksv.vote(&ksp, &account_id).unwrap(), 1);
    }
}
