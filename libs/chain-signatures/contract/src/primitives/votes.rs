use super::key_state::AuthenticatedParticipantId;
use crate::errors::{Error, VoteError};
use crate::primitives::key_state::KeyStateProposal;
use near_sdk::near;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

#[near(serializers=[borsh, json])]
#[derive(Debug, Default, PartialEq)]
pub struct KeyStateVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, KeyStateProposal>,
}

impl KeyStateVotes {
    pub fn new() -> Self {
        KeyStateVotes {
            proposal_by_account: BTreeMap::new(),
        }
    }
    /// Removes the vote submitted by `account_id` from the state.
    /// Returns true if the vote was removed and false else.
    pub fn remove_vote(&mut self, participant: &AuthenticatedParticipantId) -> bool {
        self.proposal_by_account.remove(participant).is_some()
    }
    /// Registers a vote by `participant` for `proposal` (inserts `proposal` if necessary).
    /// Returns an Error if `participant` already registered a vote.
    /// Returns the number of votes for the current proposal.
    pub fn vote(
        &mut self,
        proposal: &KeyStateProposal,
        participant: &AuthenticatedParticipantId,
    ) -> Result<u64, Error> {
        match self.proposal_by_account.entry(participant.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(proposal.clone());
            }
            Entry::Occupied(_) => {
                return Err(VoteError::ParticipantVoteAlreadyRegistered.into());
            }
        };
        Ok(self
            .proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64)
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
