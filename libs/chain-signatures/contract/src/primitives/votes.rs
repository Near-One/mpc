use super::key_state::AuthenticatedParticipantId;
use crate::errors::{Error, VoteError};
use crate::primitives::key_state::KeyStateProposal;
use near_sdk::near;
use std::collections::{BTreeMap, BTreeSet};

#[near(serializers=[borsh, json])]
#[derive(Debug, Default)]
pub struct KeyStateVotes {
    votes_by_proposal: BTreeMap<KeyStateProposal, BTreeSet<AuthenticatedParticipantId>>,
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, KeyStateProposal>,
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
    pub fn remove_vote(&mut self, participant: &AuthenticatedParticipantId) -> bool {
        if let Some(proposal) = self.proposal_by_account.remove(participant) {
            return self
                .votes_by_proposal
                .get_mut(&proposal)
                .is_some_and(|vote_set| vote_set.remove(participant));
        }
        false
    }
    /// Registers a vote by `participant` for `proposal` (inserts `proposal` if necessary).
    /// Returns an Error if `participant` already registered a vote.
    /// Returns the number of votes for the current proposal.
    pub fn vote(
        &mut self,
        proposal: &KeyStateProposal,
        participant: &AuthenticatedParticipantId,
    ) -> Result<u64, Error> {
        if self.proposal_by_account.contains_key(participant) {
            return Err(VoteError::ParticipantVoteAlreadyRegistered.into());
        }
        if self
            .proposal_by_account
            .insert(participant.clone(), proposal.clone())
            .is_some()
        {
            // this should not really happen
            return Err(VoteError::ParticipantVoteAlreadyRegistered.into());
        }
        Ok(self
            .votes_by_proposal
            .entry(proposal.clone())
            .and_modify(|votes| {
                votes.insert(participant.clone());
            })
            .or_insert({
                let mut x = BTreeSet::new();
                x.insert(participant.clone());
                x
            })
            .len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyStateVotes;
    use crate::primitives::key_state::{tests::gen_key_state_proposal, AuthenticatedParticipantId};
    use rand::Rng;
    use std::mem;

    #[test]
    fn test_voting_and_removal() {
        //let account_id = gen_account_id();
        let id: u64 = rand::thread_rng().gen();
        let participant: AuthenticatedParticipantId = unsafe { mem::transmute_copy(&id) };
        let mut ksv = KeyStateVotes::new();
        let ksp = gen_key_state_proposal(None);
        assert!(!ksv.remove_vote(&participant));
        assert_eq!(ksv.vote(&ksp, &participant).unwrap(), 1);
        assert!(ksv.vote(&ksp, &participant).is_err());
        assert!(ksv.remove_vote(&participant));
        let participant: AuthenticatedParticipantId = unsafe { mem::transmute_copy(&(id + 1)) };
        assert_eq!(ksv.vote(&ksp, &participant).unwrap(), 1);
    }
}
