use super::thresholds::ThresholdParameters;
use super::{key_state::AuthenticatedAccountId, participants::Participants};
use near_sdk::{log, near};
use std::collections::BTreeMap;

/// Tracks votes for ThresholdParameters (new participants and threshold).
/// Each current participant can maintain one vote.
#[near(serializers=[borsh, json])]
#[derive(Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedAccountId, ThresholdParameters>,
}

impl ThresholdParametersVotes {
    /// return the number of votes for `proposal` casted by members of `participants`
    pub fn n_votes(&self, proposal: &ThresholdParameters, participants: &Participants) -> u64 {
        self.proposal_by_account
            .iter()
            .filter(|&(acc, prop)| {
                participants
                    .participants()
                    .iter()
                    .any(|(acc_id, _, _)| acc.get() == acc_id)
                    && prop == proposal
            })
            .count() as u64
    }
    /// Registers a vote by `participant` for `proposal`.
    /// Removes any existing votes by `participant`.
    /// Returns the number of participants who have voted for the same proposal (including the new
    /// vote).
    pub fn vote(
        &mut self,
        proposal: &ThresholdParameters,
        participant: AuthenticatedAccountId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant, proposal.clone())
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
    use super::ThresholdParametersVotes;
    use crate::primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        test_utils::{gen_participant, gen_threshold_params},
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env};

    #[test]
    fn test_voting_and_removal() {
        let mut participants = Participants::default();
        let p0 = gen_participant(0);
        participants.insert(p0.0.clone(), p0.1).expect("error");
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(p0.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        let params = gen_threshold_params(30);
        let mut votes = ThresholdParametersVotes::default();
        assert_eq!(votes.vote(&params, participant.clone()), 1);
        assert_eq!(votes.n_votes(&params, &participants), 1);
        let params2 = gen_threshold_params(30);
        assert_eq!(votes.vote(&params2, participant), 1);
        assert_eq!(votes.n_votes(&params2, &participants), 1);
        assert_eq!(votes.n_votes(&params, &participants), 0);

        // new participant
        let p1 = gen_participant(1);
        participants.insert(p1.0.clone(), p1.1).expect("error");
        ctx.signer_account_id(p1.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        assert_eq!(votes.vote(&params, participant.clone()), 1);
        assert_eq!(votes.n_votes(&params2, &participants), 1);
        assert_eq!(votes.vote(&params2, participant), 2);
        assert_eq!(votes.n_votes(&params2, &participants), 2);
        assert_eq!(votes.n_votes(&params2, params2.participants()), 0);
        assert_eq!(votes.n_votes(&params, &participants), 0);
    }
}
