use super::key_event::KeyEvent;
use super::resharing::ResharingContractState;
use crate::errors::{Error, InvalidCandidateSet};
use crate::primitives::key_state::{
    AuthenticatedParticipantId, DKState, EpochId, KeyStateProposal,
};
use crate::primitives::votes::KeyStateVotes;
use near_sdk::{near, AccountId, PublicKey};
use std::collections::BTreeSet;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct RunningContractState {
    pub key_state: DKState,
    pub key_state_votes: KeyStateVotes,
}
impl From<&legacy_contract::RunningContractState> for RunningContractState {
    fn from(state: &legacy_contract::RunningContractState) -> Self {
        RunningContractState {
            key_state: state.into(),
            key_state_votes: KeyStateVotes::default(),
        }
    }
}

impl RunningContractState {
    pub fn authenticate_participant(&self) -> Result<AuthenticatedParticipantId, Error> {
        self.key_state.authenticate()
    }
    pub fn public_key(&self) -> &PublicKey {
        self.key_state.public_key()
    }
    pub fn epoch_id(&self) -> EpochId {
        self.key_state.epoch_id()
    }
    /// returns true if `account_id` is in the participant set
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.key_state.is_participant(account_id)
    }
    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContract state if the proposal is accepted.
    pub fn vote_new_key_state(
        &mut self,
        proposal: &KeyStateProposal,
    ) -> Result<Option<ResharingContractState>, Error> {
        if self.vote_key_state_proposal(proposal)? {
            return Ok(Some(ResharingContractState {
                current_state: RunningContractState {
                    key_state: self.key_state.clone(),
                    key_state_votes: KeyStateVotes::default(),
                },
                event_state: KeyEvent::new(self.epoch_id().next(), proposal.clone()),
            }));
        }
        Ok(None)
    }
    /// Casts a vote for `proposal`, removing any previous votes by `env::signer_account_id()`.
    /// Fails if the proposal is invalid or the signer is not a participant.
    /// Returns true if the proposal reached `threshold` number of votes.
    pub fn vote_key_state_proposal(&mut self, proposal: &KeyStateProposal) -> Result<bool, Error> {
        // ensure the signer is a participant
        let participant = self.key_state.authenticate()?;
        // ensure the proposed threshold parameters are valid:
        proposal.validate()?;
        let new_participant_set: BTreeSet<AccountId> = proposal
            .proposed_threshold_parameters()
            .participants()
            .participants()
            .keys()
            .cloned()
            .collect();
        let old_participant_set: BTreeSet<AccountId> = self
            .key_state
            .participants()
            .participants()
            .keys()
            .cloned()
            .collect();
        let mut new_min_id = u32::MAX;
        let mut new_max_id = 0u32;
        let mut n_old = 0u64;
        for account_id in new_participant_set {
            let new_id = proposal
                .proposed_threshold_parameters()
                .participants()
                .id(&account_id)?;
            if old_participant_set.contains(&account_id) {
                // ensure that the participant id is preseved
                let existing_id = self.key_state.participants().id(&account_id)?;
                if existing_id != new_id {
                    return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
                }
                n_old += 1;
            } else {
                new_min_id = std::cmp::min(new_min_id, new_id.get());
                new_max_id = std::cmp::max(new_max_id, new_id.get());
            }
        }
        // assert there are enough old participants
        if n_old < self.key_state.threshold().value() {
            return Err(InvalidCandidateSet::InsufficientOldParticipants.into());
        }
        // ensure the new ids are contiguous and unique
        let n_new = proposal
            .proposed_threshold_parameters()
            .participants()
            .count()
            - n_old;
        if n_new > 0 {
            if n_new - 1 != (new_max_id - new_min_id) as u64 {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_min_id != self.key_state.participants().next_id().get() {
                return Err(InvalidCandidateSet::NewParticipantIdsNotContiguous.into());
            }
            if new_max_id + 1
                != proposal
                    .proposed_threshold_parameters()
                    .participants()
                    .next_id()
                    .get()
            {
                return Err(InvalidCandidateSet::NewParticipantIdsTooHigh.into());
            }
        }
        // finally, vote. Propagate any errors
        let n_votes = self.key_state_votes.vote(proposal, &participant);
        Ok(self.key_state.threshold().value() <= n_votes)
    }
}
#[cfg(test)]
pub mod running_tests {
    use std::collections::BTreeSet;

    use super::RunningContractState;
    use crate::primitives::key_state::tests::gen_key_state_proposal;
    use crate::primitives::key_state::{AttemptId, DKState, EpochId, KeyEventId, KeyStateProposal};
    use crate::primitives::participants::Participants;
    use crate::primitives::test_utils::{gen_participant, gen_pk, gen_threshold_params};
    use crate::primitives::thresholds::{DKGThreshold, Threshold, ThresholdParameters};
    use crate::primitives::votes::KeyStateVotes;
    use crate::state::key_event::tests::Environment;
    use rand::Rng;

    pub fn gen_running_state() -> RunningContractState {
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let mut attempt = AttemptId::default();
        let x: usize = rand::thread_rng().gen();
        let x = x % 800;
        for _ in 0..x {
            attempt = attempt.next();
        }
        let key_event_id = KeyEventId::new(epoch_id, attempt);
        let max_n = 300;
        let threshold_parameters = gen_threshold_params(max_n);
        let public_key = gen_pk();
        let key_state_votes = KeyStateVotes::default();
        let key_state = DKState::new(public_key, key_event_id, threshold_parameters).unwrap();
        RunningContractState {
            key_state,
            key_state_votes,
        }
    }
    pub fn gen_valid_ksp(dkg: &DKState) -> KeyStateProposal {
        let mut rng = rand::thread_rng();
        let current_k = dkg.threshold().value() as usize;
        let current_n = dkg.participants().count() as usize;
        let n_old_participants: usize = rng.gen_range(current_k..current_n + 1);
        let current_participants = dkg.participants();
        let mut old_ids = current_participants.ids();
        let mut new_ids = BTreeSet::new();
        while new_ids.len() < (n_old_participants as usize) {
            let x: usize = rng.gen::<usize>() % old_ids.len();
            let c = old_ids.iter().nth(x).unwrap().clone();
            new_ids.insert(c.clone());
            old_ids.remove(&c);
        }
        let mut new_participants = Participants::default();
        for id in new_ids {
            let account_id = current_participants.account_id(&id).unwrap();
            let info = current_participants.info(&account_id).unwrap();
            let _ = new_participants.insert_with_id(account_id, info.clone(), id.clone());
        }
        let max_added: usize = rng.gen_range(0..10);
        let mut next_id = current_participants.next_id();
        for i in 0..max_added {
            let (account_id, info) = gen_participant(i);
            let _ = new_participants.insert_with_id(account_id, info, next_id.clone());
            next_id = next_id.next();
        }

        let threshold = ((new_participants.count() as f64) * 0.6).ceil() as u64;
        let dkg_threshold = DKGThreshold::new(new_participants.count());
        let proposed =
            ThresholdParameters::new(new_participants, Threshold::new(threshold)).unwrap();
        KeyStateProposal::new(proposed, dkg_threshold).unwrap()
    }

    #[test]
    fn test_running() {
        let mut state = gen_running_state();
        let mut env = Environment::new(None, None, None);
        let participants = state.key_state.participants().clone();
        // assert that random proposals fail:
        for account_id in participants.participants().keys() {
            let ksp = gen_key_state_proposal(None);
            env.set_signer(account_id);
            assert!(state.vote_key_state_proposal(&ksp).is_err());
        }
        for account_id in participants.participants().keys() {
            env.set_signer(account_id);
            let ksp = gen_valid_ksp(&state.key_state);
            assert!(!state.vote_key_state_proposal(&ksp).unwrap())
        }
        let ksp = gen_valid_ksp(&state.key_state);

        for (i, account_id) in participants.participants().keys().enumerate() {
            env.set_signer(account_id);
            let res = state.vote_key_state_proposal(&ksp).unwrap();
            if i + 1 < state.key_state.threshold().value() as usize {
                assert!(!res);
            } else {
                assert!(res);
            }
        }
        let account_id = participants.participants().keys().next().unwrap();
        env.set_signer(account_id);
        let resharing = state.vote_new_key_state(&ksp).unwrap().unwrap();
        assert_eq!(resharing.current_state.key_state, state.key_state);
        let ke = resharing.event_state;
        assert_eq!(
            ke.current_key_event_id(),
            KeyEventId::new(state.epoch_id().next(), AttemptId::new())
        );
        assert_eq!(
            ke.proposed_threshold_parameters(),
            *ksp.proposed_threshold_parameters()
        );
        assert_eq!(ke.event_threshold(), ksp.key_event_threshold());
    }
}
