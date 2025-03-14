use super::key_state::AuthenticatedParticipantId;
use crate::primitives::key_state::KeyStateProposal;
use near_sdk::{log, near};
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
    /// Registers a vote by `participant` for `proposal` (inserts `proposal` if necessary).
    /// Removes any existing votes by `participant`.
    /// Returns an Error if `participant` already registered a vote.
    /// Returns the number of votes for the current proposal.
    pub fn vote(
        &mut self,
        proposal: &KeyStateProposal,
        participant: &AuthenticatedParticipantId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant.clone(), proposal.clone())
            .is_some()
        {
            log!("removed one vote for signer");
        }
        self.proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64
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
        assert_eq!(ksv.vote(&ksp, &participant), 1);
        assert_eq!(ksv.vote(&ksp, &participant), 1);
        let participant: AuthenticatedParticipantId = unsafe { mem::transmute_copy(&(id + 1)) };
        assert_eq!(ksv.vote(&ksp, &participant), 2);
    }
}
