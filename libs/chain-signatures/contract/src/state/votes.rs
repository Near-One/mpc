use super::key_state::KeyStateProposal;
use crate::errors::{Error, VoteError};
use near_sdk::{near, AccountId, PublicKey};
use std::collections::{BTreeMap, HashSet};

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

    pub fn entry(&mut self, public_key: PublicKey) -> &mut HashSet<AccountId> {
        self.votes.entry(public_key).or_default()
    }
}

/// Tracks votes for key state proposals. Each participant is allowed only a single vote.
///
/// # Examples
/// ```
/// use mpc_contract::state::votes::KeyStateVotes;
/// let mut ksv = KeyStateVotes::default();
/// assert!(false == ksv.remove_vote(&"account.near".parse().unwrap()));
/// ```
#[near(serializers=[borsh, json])]
#[derive(Debug, Default)]
pub struct KeyStateVotes {
    votes_by_proposal: BTreeMap<KeyStateProposal, HashSet<AccountId>>,
    proposal_by_account: BTreeMap<AccountId, KeyStateProposal>,
}

impl KeyStateVotes {
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
        if self
            .proposal_by_account
            .insert(account_id.clone(), proposal.clone())
            .is_some()
        {
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

//#[cfg(test)]
//mod tests {
//
//    use super::*;
//    use crate::state::{key_state::ThresholdParameters, test_utils::dummy_participants};
//    #[test]
//    fn test_voting_and_removal() {
//        // todo: move these to their file
//        let n = 40;
//        let min_threshold = 24; // 60%
//        let participant_set_a = dummy_participants(n);
//        //for k in 1..min_threshold {
//        //    assert!(ThresholdParameters::new(participant_set_a.clone(), k as u64).is_err());
//        //}
//        //for k in min_threshold..(n + 1) {
//        //    assert!(ThresholdParameters::new(participant_set_a.clone(), k as u64).is_ok());
//        //}
//        //let tpt = min_threshold;
//        //let tp = ThresholdParameters::new(participant_set_a, tpt as u64).unwrap();
//        //for ket in tpt..(n + 1) {
//        //    assert!(KeyStateProposal::new(tp.clone(), ket as u64).is_ok());
//        //}
//
//        //        // 3. Assert
//        //        assert!(vote_result.is_ok());
//        //        assert_eq!(vote_result.unwrap(), 1);
//        //
//        //        // Now remove the vote
//        //        let removed = votes.remove_vote(&account_1);
//        //        assert!(removed);
//        //
//        //        // Check that the vote no longer exists
//        //        assert_eq!(votes.proposal_by_account.contains_key(&account_1), false);
//    }
//}
