use super::key_event::KeyEvent;
use super::running::RunningContractState;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{Error, InvalidParameters};
use crate::primitives::domain::DomainRegistry;
use crate::primitives::key_state::{
    AuthenticatedParticipantId, EpochId, KeyEventId, KeyForDomain, Keyset,
};
use near_sdk::near;
use std::collections::BTreeSet;

/// In this state, we generate a new key for each new domain. At any given point of time, we are
/// generating the key of a single domain. After that, we move on to the next domain, or if there
/// are no more domains, transition into the Running state.
///
/// This state is reached by calling vote_add_domains from the Running state by a threshold number
/// of participants.
///
/// While generating the key for a domain, the `generating_key` field internally handles multiple
/// attempts as needed, only finishing when an attempt has succeeded.
///
/// Additionally, a threshold number of participants can vote to cancel this state; doing so will
/// revert back to the Running state but deleting the domains for which we have not yet successfully
/// generated a key. This can be useful if the current set of participants are no longer all online
/// and we wish to perform a resharing before adding domains again.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct InitializingContractState {
    /// All domains, including the already existing ones and the ones we're generating a new key for
    pub domains: DomainRegistry,
    /// The epoch ID; this is the same as the Epoch ID of the Running state we transitioned from.
    pub epoch_id: EpochId,
    /// The key for each domain we have already generated a key for; this is in the same order as
    /// the domains in the DomainRegistry, except that it only has a prefix of the domains.
    pub generated_keys: Vec<KeyForDomain>,
    /// The key generation state for the currently generating domain (the next domain after
    /// `generated_keys`).
    pub generating_key: KeyEvent,
    /// Votes that have been cast to cancel the key generation.
    pub cancel_votes: BTreeSet<AuthenticatedParticipantId>,
}

impl InitializingContractState {
    /// Starts a new attempt to generate a key for the current domain.
    /// Returns an Error if the signer is not the leader (the participant with the lowest ID).
    pub fn start(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        self.generating_key
            .start(key_event_id, key_event_timeout_blocks)
    }

    /// Casts a vote for `public_key` for the attempt identified by `key_event_id`.
    /// Upon success (a return of Ok(...)), the effect of this method is one of the following:
    ///  - A vote has been collected but we don't have enough votes yet.
    ///  - This vote is for a public key that disagrees from an earlier voted public key, causing
    ///    the attempt to abort; another call to `start` is then necessary.
    ///  - Everyone has now voted for the same public key; the state transitions into generating a
    ///    key for the next domain. (This returns Ok(None) still).
    ///  - Same as the last case, except that all domains have a generated key now, and we return
    ///    Ok(Some(running state)) that the caller should now transition into.
    ///
    /// Fails in the following cases:
    ///  - There is no active key generation attempt (including if the attempt timed out).
    ///  - The key_event_id corresponds to a different domain, different epoch, or different attempt
    ///    from the current key generation attempt.
    ///  - The signer is not a participant.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKeyExtended,
    ) -> Result<Option<RunningContractState>, Error> {
        if self
            .generating_key
            .vote_success(&key_event_id, public_key.clone())?
        {
            self.generated_keys.push(KeyForDomain {
                domain_id: key_event_id.domain_id,
                key: public_key.clone(),
                attempt: key_event_id.attempt_id,
            });
            if let Some(next_domain) = self.domains.get_domain_by_index(self.generated_keys.len()) {
                self.generating_key = KeyEvent::new(
                    self.epoch_id,
                    next_domain.clone(),
                    self.generating_key.proposed_parameters().clone(),
                );
            } else {
                return Ok(Some(RunningContractState::new(
                    self.domains.clone(),
                    Keyset::new(self.epoch_id, self.generated_keys.clone()),
                    self.generating_key.proposed_parameters().clone(),
                )));
            }
        }
        Ok(None)
    }

    /// Casts a vote to abort the current key generation attempt.
    /// After aborting, another call to start() is necessary to start a new attempt.
    /// Returns error if there is no active attempt, or if the signer is not a participant.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        self.generating_key.vote_abort(key_event_id)
    }

    /// Casts a vote to cancel key generation. Any keys that have already been generated
    /// are kept and we transition into Running state; remaining domains are permanently deleted.
    /// Deleted domain IDs are not reused again.
    ///
    /// The next_domain_id parameter is used to verify that this cancel vote is indeed for this
    /// particular instance of key generation, not some older instance.
    pub fn vote_cancel(
        &mut self,
        next_domain_id: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        if next_domain_id != self.domains.next_domain_id() {
            return Err(InvalidParameters::NextDomainIdMismatch.into());
        }
        let participant = AuthenticatedParticipantId::new(
            self.generating_key.proposed_parameters().participants(),
        )?;
        let required_threshold = self
            .generating_key
            .proposed_parameters()
            .threshold()
            .value() as usize;
        if self.cancel_votes.insert(participant) && self.cancel_votes.len() >= required_threshold {
            let mut domains = self.domains.clone();
            domains.retain_domains(self.generated_keys.len());
            return Ok(Some(RunningContractState::new(
                domains,
                Keyset::new(self.epoch_id, self.generated_keys.clone()),
                self.generating_key.proposed_parameters().clone(),
            )));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::InitializingContractState;
    use crate::primitives::domain::tests::gen_domains_to_add;
    use crate::primitives::domain::{AddDomainsVotes, DomainId};
    use crate::primitives::key_state::{AttemptId, KeyEventId};
    use crate::primitives::test_utils::{bogus_ed25519_public_key_extended, gen_account_id};
    use crate::primitives::votes::ThresholdParametersVotes;
    use crate::state::key_event::tests::{find_leader, Environment};
    use crate::state::running::running_tests::gen_running_state;
    use crate::state::running::RunningContractState;
    use near_sdk::AccountId;
    use std::collections::BTreeSet;

    /// Randomly generates an InitializingContractState where we already have keys for
    /// `num_generated` domains, and we are targeting `num_domains` total domains.
    /// This is done by starting from a Running state with `num_generated` keys and then transition
    /// into Initializing state by calling vote_add_domains. (We also test that code path.)
    fn gen_initializing_state(
        num_domains: usize,
        num_generated: usize,
    ) -> (Environment, InitializingContractState) {
        let mut env = Environment::new(None, None, None);
        let mut running = gen_running_state(num_generated);
        let domains_to_add = gen_domains_to_add(&running.domains, num_domains - num_generated);

        let mut initializing_state = None;
        for (account, _, _) in running.parameters.participants().participants().clone() {
            env.set_signer(&account);
            assert!(initializing_state.is_none());
            initializing_state = running.vote_add_domains(domains_to_add.clone()).unwrap();
        }
        let initializing_state = initializing_state
            .expect("Enough votes to add domains should transition into initializing");
        (env, initializing_state)
    }

    fn test_initializing_contract_state_for(num_domains: usize, num_already_generated: usize) {
        let (mut env, mut state) = gen_initializing_state(num_domains, num_already_generated);
        let candidates: BTreeSet<AccountId> = state
            .generating_key
            .proposed_parameters()
            .participants()
            .participants()
            .iter()
            .map(|(aid, _, _)| aid.clone())
            .collect();

        let mut resulting_running_state: Option<RunningContractState> = None;
        for i in num_already_generated..num_domains {
            println!("Testing domain {}", i);
            assert!(!state.generating_key.is_active());
            let first_key_event_id = KeyEventId {
                attempt_id: AttemptId::new(),
                domain_id: state.domains.get_domain_by_index(i).unwrap().id,
                epoch_id: state.epoch_id,
            };
            let leader = find_leader(&state.generating_key);
            for c in &candidates {
                env.set_signer(c);
                // verify that no votes can be cast before the keygen started.
                assert!(state
                    .vote_pk(first_key_event_id, bogus_ed25519_public_key_extended())
                    .is_err());
                assert!(state.vote_abort(first_key_event_id).is_err());
                if *c != leader.0 {
                    assert!(state.start(first_key_event_id, 1).is_err());
                } else {
                    // Also check that starting with the wrong KeyEventId fails.
                    assert!(state.start(first_key_event_id.next_attempt(), 1).is_err());
                }
            }
            // start the keygen; verify that the keygen is for the right epoch and domain ID.
            env.set_signer(&leader.0);
            assert!(state.start(first_key_event_id, 0).is_ok());
            let key_event = state.generating_key.current_key_event_id().unwrap();
            assert_eq!(key_event, first_key_event_id);

            // check that randos can't vote.
            for _ in 0..20 {
                env.set_signer(&gen_account_id());
                assert!(state
                    .vote_pk(key_event, bogus_ed25519_public_key_extended())
                    .is_err());
                assert!(state.vote_abort(key_event).is_err());
            }

            // check that timing out will abort the instance
            env.advance_block_height(1);
            assert!(!state.generating_key.is_active());
            for c in &candidates {
                env.set_signer(c);
                assert!(state
                    .vote_pk(key_event, bogus_ed25519_public_key_extended())
                    .is_err());
                assert!(state.vote_abort(key_event).is_err());
                assert!(!state.generating_key.is_active());
            }

            // assert that votes for a different keygen do not count
            env.set_signer(&leader.0);
            assert!(state.start(first_key_event_id.next_attempt(), 0).is_ok());
            let key_event = state.generating_key.current_key_event_id().unwrap();
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
                    assert!(state
                        .vote_pk(bad_key_event, bogus_ed25519_public_key_extended())
                        .is_err());
                    assert!(state.vote_abort(bad_key_event).is_err());
                }
            }
            assert_eq!(state.generating_key.num_completed(), 0);

            // assert that voting for different keys will fail
            for (j, account) in candidates.iter().enumerate() {
                env.set_signer(account);
                let res = state.vote_pk(key_event, bogus_ed25519_public_key_extended());
                // the first vote goes through, the second vote resets the instance; the third and subsequent ones fail.
                if j < 2 {
                    assert!(res.expect("Should not fail").is_none());
                } else {
                    assert!(!state.generating_key.is_active());
                    assert!(res.is_err());
                }
            }

            // check that vote_abort immediately causes failure.
            env.set_signer(&leader.0);
            assert!(state.start(key_event.next_attempt(), 0).is_ok());
            let key_event = state.generating_key.current_key_event_id().unwrap();
            env.set_signer(candidates.iter().next().unwrap());
            assert!(state.vote_abort(key_event).is_ok());
            assert!(!state.generating_key.is_active());

            // assert that valid votes get counted correctly
            env.set_signer(&leader.0);
            assert!(state.start(key_event.next_attempt(), 0).is_ok());
            let key_event = state.generating_key.current_key_event_id().unwrap();
            let pk = bogus_ed25519_public_key_extended();
            for (i, c) in candidates.clone().into_iter().enumerate() {
                env.set_signer(&c);
                assert!(resulting_running_state.is_none());
                assert_eq!(state.generating_key.num_completed(), i);
                resulting_running_state = state.vote_pk(key_event, pk.clone()).unwrap();
                assert!(state.vote_abort(key_event).is_err());
            }
        }

        // assert that the final running state is correct
        let running_state = resulting_running_state.unwrap();
        assert_eq!(
            &running_state.parameters,
            state.generating_key.proposed_parameters(),
        );
        assert_eq!(running_state.keyset.epoch_id, state.epoch_id);
        assert_eq!(running_state.keyset.domains, state.generated_keys);
        assert_eq!(running_state.keyset.domains.len(), num_domains);
        assert_eq!(running_state.domains, state.domains);
        assert_eq!(
            running_state.parameters_votes,
            ThresholdParametersVotes::default()
        );
        assert_eq!(running_state.add_domains_votes, AddDomainsVotes::default());
    }

    #[test]
    fn test_initializing_contract_state_1_0() {
        test_initializing_contract_state_for(1, 0);
    }

    #[test]
    fn test_initializing_contract_state_2_0() {
        test_initializing_contract_state_for(2, 0);
    }

    #[test]
    fn test_initializing_contract_state_2_1() {
        test_initializing_contract_state_for(2, 1);
    }

    #[test]
    fn test_initializing_contract_state_3_0() {
        test_initializing_contract_state_for(3, 0);
    }

    #[test]
    fn test_initializing_contract_state_3_1() {
        test_initializing_contract_state_for(3, 1);
    }

    #[test]
    fn test_initializing_contract_state_3_2() {
        test_initializing_contract_state_for(3, 2);
    }

    #[test]
    fn test_cancel_key_generation() {
        let (mut env, mut state) = gen_initializing_state(5, 2);

        // Vote for domain #2.
        let leader = find_leader(&state.generating_key);
        env.set_signer(&leader.0);
        let first_key_event_id = KeyEventId {
            attempt_id: AttemptId::new(),
            domain_id: state.domains.get_domain_by_index(2).unwrap().id,
            epoch_id: state.epoch_id,
        };
        assert!(state.start(first_key_event_id, 0).is_ok());

        let pk = bogus_ed25519_public_key_extended();
        let participants = state
            .generating_key
            .proposed_parameters()
            .participants()
            .participants()
            .clone();
        let threshold = state
            .generating_key
            .proposed_parameters()
            .threshold()
            .value() as usize;
        for (account, _, _) in &participants {
            env.set_signer(account);
            state.vote_pk(first_key_event_id, pk.clone()).unwrap();
        }

        // we should have 3 keys now.
        assert!(state.generated_keys.len() == 3);
        let mut running = None;
        for (account, _, _) in &participants[0..threshold] {
            env.set_signer(account);
            assert!(running.is_none());
            // Check that using the wrong next_domain_id fails.
            assert!(state
                .vote_cancel(state.domains.next_domain_id() - 1)
                .is_err());
            running = state.vote_cancel(state.domains.next_domain_id()).unwrap();
        }
        let running = running.expect("Enough votes to cancel should transition into running");
        assert_eq!(running.keyset.domains.len(), 3);
        assert_eq!(running.domains.domains().len(), 3);
        assert_eq!(running.keyset.domains[2].key, pk);

        assert_eq!(
            running.domains.next_domain_id(),
            state.domains.next_domain_id(),
        );
    }
}
