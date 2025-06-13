use super::key_event::KeyEvent;
use super::running::RunningContractState;
use crate::errors::{Error, InvalidParameters};
use crate::primitives::key_state::{EpochId, KeyEventId, KeyForDomain, Keyset};
use crate::primitives::thresholds::ThresholdParameters;
use near_sdk::near;

/// In this state, we reshare the key of every domain onto a new set of participants and threshold.
/// Similar to key generation, we reshare the key of one domain at a time; when we finish resharing
/// for one domain, we move on to the next or transition to the Running state.
///
/// This state is reached by calling vote_new_parameters from the Running state.
///
/// This state keeps the previous running state because:
///  - The previous running state's ThresholdParameters are needed in order to facilitate the
///    possible re-proposal of a new ThresholdParameters, in case the currently proposed set of
///    participants are no longer all online. For tracking the votes we also use the same
///    tracking structure in the running state.
///  - The previous running state's keys are needed to copy the public keys.
///  - We use the previous running state's DomainRegistry.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ResharingContractState {
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
}

impl ResharingContractState {
    pub fn previous_keyset(&self) -> &Keyset {
        &self.previous_running_state.keyset
    }

    /// Returns the epoch ID that we would transition into if resharing were completed successfully.
    /// This would increment if we end up voting for a re-proposal.
    pub fn prospective_epoch_id(&self) -> EpochId {
        self.resharing_key.epoch_id()
    }

    /// Casts a vote for a re-proposal. Requires the signer to be a participant of the prospective epoch.
    /// Returns a new [`ResharingContractState`] if all participants of the re-proposal voted for the re-proposal.
    /// Note that transitioning to a new state implicitly requires `threshold` number of votes from participants of the
    /// previous running state.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: &ThresholdParameters,
    ) -> Result<Option<ResharingContractState>, Error> {
        if prospective_epoch_id != self.prospective_epoch_id().next() {
            return Err(InvalidParameters::EpochMismatch.into());
        }
        if self
            .previous_running_state
            .process_new_parameters_proposal(proposal)?
        {
            return Ok(Some(ResharingContractState {
                previous_running_state: RunningContractState::new(
                    self.previous_running_state.domains.clone(),
                    self.previous_running_state.keyset.clone(),
                    self.previous_running_state.parameters.clone(),
                ),
                reshared_keys: Vec::new(),
                resharing_key: KeyEvent::new(
                    self.prospective_epoch_id().next(),
                    self.previous_running_state
                        .domains
                        .get_domain_by_index(0)
                        .unwrap()
                        .clone(),
                    proposal.clone(),
                ),
            }));
        }
        Ok(None)
    }

    /// Starts a new attempt to reshare the key for the current domain.
    /// Returns an Error if the signer is not the leader (the participant with the lowest ID).
    pub fn start(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        self.resharing_key
            .start(key_event_id, key_event_timeout_blocks)
    }

    /// Casts a successfully-reshared vote for for the attempt identified by `key_event_id`.
    /// Upon success (a return of Ok(...)), the effect of this method is one of the following:
    ///  - A vote has been collected but we don't have enough votes yet.
    ///  - Everyone has now voted; the state transitions into resharing the key for the next domain.
    ///    (This returns Ok(None) still).
    ///  - Same as the last case, except that all domains' keys have been reshared now, and we
    ///    return Ok(Some(running state)) that the caller should now transition into.
    ///
    /// Fails in the following cases:
    ///  - There is no active key resharing attempt (including if the attempt timed out).
    ///  - The key_event_id corresponds to a different domain, different epoch, or different attempt
    ///    from the current key resharing attempt.
    ///  - The signer is not a participant in the *proposed* set of participants.
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
    ) -> Result<Option<RunningContractState>, Error> {
        let previous_key = self.previous_keyset().domains[self.reshared_keys.len()].clone();
        if self
            .resharing_key
            .vote_success(&key_event_id, previous_key.key.clone())?
        {
            let new_key = KeyForDomain {
                domain_id: key_event_id.domain_id,
                attempt: key_event_id.attempt_id,
                key: previous_key.key,
            };
            self.reshared_keys.push(new_key);
            if let Some(next_domain) = self
                .previous_running_state
                .domains
                .get_domain_by_index(self.reshared_keys.len())
            {
                self.resharing_key = KeyEvent::new(
                    self.prospective_epoch_id(),
                    next_domain.clone(),
                    self.resharing_key.proposed_parameters().clone(),
                );
            } else {
                return Ok(Some(RunningContractState::new(
                    self.previous_running_state.domains.clone(),
                    Keyset::new(self.prospective_epoch_id(), self.reshared_keys.clone()),
                    self.resharing_key.proposed_parameters().clone(),
                )));
            }
        }
        Ok(None)
    }

    /// Casts a vote to abort the current key resharing attempt.
    /// After aborting, another call to start() is necessary to start a new attempt.
    /// Returns error if there is no active attempt, or if the signer is not a proposed participant.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        self.resharing_key.vote_abort(key_event_id)
    }
}
#[cfg(test)]
mod tests {
    use crate::primitives::domain::{AddDomainsVotes, DomainId};
    use crate::primitives::key_state::{AttemptId, KeyEventId};
    use crate::primitives::test_utils::gen_account_id;
    use crate::primitives::thresholds::{Threshold, ThresholdParameters};
    use crate::primitives::votes::ThresholdParametersVotes;
    use crate::state::key_event::tests::{find_leader, Environment};
    use crate::state::resharing::ResharingContractState;
    use crate::state::running::running_tests::{gen_running_state, gen_valid_params_proposal};
    use crate::state::running::RunningContractState;
    use near_sdk::AccountId;
    use std::collections::BTreeSet;

    /// Generates a resharing state with the given number of domains.
    /// We do this by starting from the Running state and calling vote_new_parameters to have it
    /// transition into Resharing. (This also tests the transitioning code path.)
    fn gen_resharing_state(num_domains: usize) -> (Environment, ResharingContractState) {
        let mut env = Environment::new(Some(100), None, None);
        let mut running = gen_running_state(num_domains);
        let proposal = gen_valid_params_proposal(&running.parameters);
        let mut resharing_state = None;
        for (account, _, _) in proposal.participants().participants() {
            env.set_signer(account);
            assert!(resharing_state.is_none());
            resharing_state = running
                .vote_new_parameters(running.keyset.epoch_id.next(), &proposal)
                .unwrap();
        }
        (
            env,
            resharing_state.expect("Should've transitioned into resharing"),
        )
    }

    fn test_resharing_contract_state_for(num_domains: usize) {
        println!("Testing with {} domains", num_domains);
        let (mut env, mut state) = gen_resharing_state(num_domains);
        let candidates: BTreeSet<AccountId> = state
            .resharing_key
            .proposed_parameters()
            .participants()
            .participants()
            .iter()
            .map(|(aid, _, _)| aid.clone())
            .collect();

        let mut resulting_running_state: Option<RunningContractState> = None;
        for i in 0..num_domains {
            println!("Testing domain {}", i);
            assert!(!state.resharing_key.is_active());
            let first_key_event_id = KeyEventId {
                attempt_id: AttemptId::new(),
                domain_id: state
                    .previous_running_state
                    .domains
                    .get_domain_by_index(i)
                    .unwrap()
                    .id,
                epoch_id: state.prospective_epoch_id(),
            };
            let leader = find_leader(&state.resharing_key);
            for c in &candidates {
                env.set_signer(c);
                // verify that no votes can be cast before the resharing started.
                assert!(state.vote_reshared(first_key_event_id).is_err());
                assert!(state.vote_abort(first_key_event_id).is_err());
                if *c != leader.0 {
                    assert!(state.start(first_key_event_id, 1).is_err());
                } else {
                    // Also check that starting with the wrong KeyEventId fails.
                    assert!(state.start(first_key_event_id.next_attempt(), 1).is_err());
                }
            }
            // start the resharing; verify that the resharing is for the right epoch and domain ID.
            env.set_signer(&leader.0);
            assert!(state.start(first_key_event_id, 0).is_ok());
            let key_event = state.resharing_key.current_key_event_id().unwrap();
            assert_eq!(key_event, first_key_event_id);

            // check that randos can't vote.
            for _ in 0..20 {
                env.set_signer(&gen_account_id());
                assert!(state.vote_reshared(key_event).is_err());
                assert!(state.vote_abort(key_event).is_err());
            }

            // check that timing out will abort the instance
            env.advance_block_height(1);
            assert!(!state.resharing_key.is_active());
            for c in &candidates {
                env.set_signer(c);
                assert!(state.vote_reshared(key_event).is_err());
                assert!(state.vote_abort(key_event).is_err());
                assert!(!state.resharing_key.is_active());
            }

            // assert that votes for a different resharings do not count
            env.set_signer(&leader.0);
            assert!(state.start(first_key_event_id.next_attempt(), 0).is_ok());
            let key_event = state.resharing_key.current_key_event_id().unwrap();
            let bad_key_events = [
                KeyEventId::new(
                    key_event.epoch_id,
                    key_event.domain_id,
                    key_event.attempt_id.next(),
                ),
                KeyEventId::new(
                    key_event.epoch_id,
                    DomainId(key_event.domain_id.0 + 1),
                    key_event.attempt_id,
                ),
                KeyEventId::new(
                    key_event.epoch_id.next(),
                    key_event.domain_id,
                    key_event.attempt_id,
                ),
            ];
            for bad_key_event in bad_key_events {
                for c in &candidates {
                    env.set_signer(c);
                    assert!(state.vote_reshared(bad_key_event).is_err());
                    assert!(state.vote_abort(bad_key_event).is_err());
                }
            }
            assert_eq!(state.resharing_key.num_completed(), 0);

            // check that vote_abort immediately causes failure.
            env.advance_block_height(1);
            env.set_signer(&leader.0);
            assert!(state.start(key_event.next_attempt(), 0).is_ok());
            let key_event = state.resharing_key.current_key_event_id().unwrap();
            env.set_signer(candidates.iter().next().unwrap());
            assert!(state.vote_abort(key_event).is_ok());
            assert!(!state.resharing_key.is_active());

            // assert that valid votes get counted correctly
            env.set_signer(&leader.0);
            assert!(state.start(key_event.next_attempt(), 0).is_ok());
            let key_event = state.resharing_key.current_key_event_id().unwrap();
            for (i, c) in candidates.clone().into_iter().enumerate() {
                env.set_signer(&c);
                assert!(resulting_running_state.is_none());
                assert_eq!(state.resharing_key.num_completed(), i);
                resulting_running_state = state.vote_reshared(key_event).unwrap();
                assert!(state.vote_abort(key_event).is_err());
            }
        }

        // assert that the final running state is correct
        let running_state = resulting_running_state.unwrap();
        assert_eq!(
            &running_state.parameters,
            state.resharing_key.proposed_parameters(),
        );
        assert_eq!(running_state.keyset.epoch_id, state.prospective_epoch_id());
        assert_eq!(running_state.keyset.domains, state.reshared_keys);
        assert_eq!(running_state.keyset.domains.len(), num_domains);
        assert_eq!(running_state.domains, state.previous_running_state.domains);
        assert_eq!(
            running_state.parameters_votes,
            ThresholdParametersVotes::default()
        );
        assert_eq!(running_state.add_domains_votes, AddDomainsVotes::default());
    }

    #[test]
    fn test_resharing_contract_state_1() {
        test_resharing_contract_state_for(1);
    }
    #[test]
    fn test_resharing_contract_state_2() {
        test_resharing_contract_state_for(2);
    }
    #[test]
    fn test_resharing_contract_state_3() {
        test_resharing_contract_state_for(3);
    }
    #[test]
    fn test_resharing_contract_state_4() {
        test_resharing_contract_state_for(4);
    }

    #[test]
    fn test_resharing_reproposal() {
        let (mut env, mut state) = gen_resharing_state(3);

        // Vote for first domain's key.
        let leader = find_leader(&state.resharing_key);
        env.set_signer(&leader.0);
        let first_key_event_id = KeyEventId {
            attempt_id: AttemptId::new(),
            domain_id: state
                .previous_running_state
                .domains
                .get_domain_by_index(0)
                .unwrap()
                .id,
            epoch_id: state.prospective_epoch_id(),
        };
        assert!(state.start(first_key_event_id, 0).is_ok());

        let old_participants = state
            .previous_running_state
            .parameters
            .participants()
            .clone();
        {
            let new_participants = state
                .resharing_key
                .proposed_parameters()
                .participants()
                .participants()
                .clone();
            for (account, _, _) in new_participants {
                env.set_signer(&account);
                state.vote_reshared(first_key_event_id).unwrap();
            }
        }
        assert!(state.reshared_keys.len() == 1);

        // Generate two sets of params:
        //  - old params -> new_params_1 is a valid proposal.
        //  - new_params_1 -> new_params_2 is a valid proposal.
        //  - old params -> new_params_2 is NOT a valid proposal.
        //
        // Reproposing with new_params_1 should succeed, but then reproposing with new_params_2
        // should be rejected, since all re-proposals must be valid against the original.
        let mut new_participants_1 = old_participants.clone();
        let new_threshold = Threshold::new(old_participants.len() as u64);
        new_participants_1.add_random_participants_till_n((old_participants.len() * 3).div_ceil(2));
        let new_participants_2 = new_participants_1
            .subset(new_participants_1.len() - old_participants.len()..new_participants_1.len());
        let new_params_1 =
            ThresholdParameters::new(new_participants_1, new_threshold.clone()).unwrap();
        let new_params_2 = ThresholdParameters::new(new_participants_2, new_threshold).unwrap();
        assert!(state
            .previous_running_state
            .parameters
            .validate_incoming_proposal(&new_params_1)
            .is_ok());
        assert!(new_params_1
            .validate_incoming_proposal(&new_params_2)
            .is_ok());
        assert!(state
            .previous_running_state
            .parameters
            .validate_incoming_proposal(&new_params_2)
            .is_err());

        // Reproposing with invalid epoch ID should fail.
        {
            env.set_signer(&old_participants.participants()[0].0);
            assert!(state
                .vote_new_parameters(state.prospective_epoch_id(), &new_params_1)
                .is_err());
            assert!(state
                .vote_new_parameters(state.prospective_epoch_id().next().next(), &new_params_1)
                .is_err());
        }

        // Repropose with new_params_1.
        let mut new_state = None;
        for (account, _, _) in new_params_1.participants().participants() {
            env.set_signer(account);
            assert!(new_state.is_none());
            new_state = state
                .vote_new_parameters(state.prospective_epoch_id().next(), &new_params_1)
                .unwrap();
        }
        // We should've gotten a new resharing state.
        assert!(new_state.is_some());
        let mut new_state = new_state.unwrap();
        // New state should start from the beginning, with the epoch ID bumped.
        assert_eq!(new_state.reshared_keys.len(), 0);
        assert_eq!(
            new_state.resharing_key.epoch_id(),
            state.prospective_epoch_id().next()
        );
        assert_eq!(new_state.resharing_key.proposed_parameters(), &new_params_1);
        assert_eq!(
            new_state.resharing_key.domain_id(),
            state
                .previous_running_state
                .domains
                .get_domain_by_index(0)
                .unwrap()
                .id
        );

        // Repropose with new_params_2. That should fail.
        env.set_signer(&old_participants.participants()[0].0);
        assert!(new_state
            .vote_new_parameters(new_state.prospective_epoch_id().next(), &new_params_2)
            .is_err());
    }
}
