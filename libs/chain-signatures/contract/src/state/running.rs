use super::initializing::InitializingContractState;
use super::key_event::KeyEvent;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidParameters, InvalidState, VoteError};
use crate::legacy_contract_state;
use crate::primitives::domain::{AddDomainsVotes, DomainConfig, DomainId, DomainRegistry};
use crate::primitives::key_state::{
    AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyEventId,
    KeyForDomain, Keyset,
};
use crate::primitives::thresholds::ThresholdParameters;
use crate::primitives::votes::ThresholdParametersVotes;
use near_sdk::near;
use std::collections::BTreeSet;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ResharingState {
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
}

/// In this state, the contract is ready to process signature requests.
///
/// Proposals can be submitted to modify the state:
///  - vote_add_domains, upon threshold agreement, transitions into the
///    Initializing state to generate keys for new domains.
///  - vote_new_parameters, upon threshold agreement, transitions into the
///    Resharing state to reshare keys for new participants and also change the
///    threshold if desired.
#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct RunningContractState {
    /// The domains for which we have a key ready for signature processing.
    pub domains: DomainRegistry,
    /// The keys that are currently in use; for each domain provides an unique identifier for a
    /// distributed key, so that the nodes can identify which local keyshare to use.
    pub keyset: Keyset,
    /// The current participants and threshold.
    pub parameters: ThresholdParameters,
    /// Votes for proposals for a new set of participants and threshold.
    pub parameters_votes: ThresholdParametersVotes,
    /// Votes for proposals to add new domains.
    pub add_domains_votes: AddDomainsVotes,
    pub resharing_process: Option<ResharingState>,
}

impl From<&legacy_contract_state::ResharingContractState> for RunningContractState {
    fn from(_state: &legacy_contract_state::ResharingContractState) -> Self {
        // It's complicated to upgrade the contract while resharing. Just don't support it.
        unimplemented!("Cannot migrate from Resharing state")
    }
}

impl From<&legacy_contract_state::RunningContractState> for RunningContractState {
    fn from(state: &legacy_contract_state::RunningContractState) -> Self {
        let key = match state.public_key.curve_type() {
            near_sdk::CurveType::ED25519 => unreachable!("Legacy contract does not have any ED25519 keys in its state. An EdwardsPoint can not be constructed within the max gas limit."),
            near_sdk::CurveType::SECP256K1 => PublicKeyExtended::Secp256k1 { near_public_key: state.public_key.clone() },
        };
        RunningContractState::new(
            DomainRegistry::new_single_ecdsa_key_from_legacy(),
            Keyset::new(
                EpochId::new(state.epoch),
                vec![KeyForDomain {
                    attempt: AttemptId::default(),
                    domain_id: DomainId::legacy_ecdsa_id(),
                    key,
                }],
            ),
            ThresholdParameters::migrate_from_legacy(state.threshold, state.participants.clone()),
        )
    }
}

impl RunningContractState {
    pub fn new(domains: DomainRegistry, keyset: Keyset, parameters: ThresholdParameters) -> Self {
        RunningContractState {
            domains,
            keyset,
            parameters,
            parameters_votes: ThresholdParametersVotes::default(),
            add_domains_votes: AddDomainsVotes::default(),
            resharing_process: None,
        }
    }

    pub fn prospective_epoch_id(&self) -> EpochId {
        match &self.resharing_process {
            Some(active_resharing_process) => active_resharing_process.resharing_key.epoch_id(),
            None => self.keyset.epoch_id,
        }
    }

    /// Casts a vote for a re-proposal. Requires the signer to be a participant of the prospective epoch.
    pub fn vote_new_parameters(
        &mut self,
        proposed_epoch_id: EpochId,
        proposal: &ThresholdParameters,
    ) -> Result<(), Error> {
        let next_epoch_id = self.prospective_epoch_id().next();

        if proposed_epoch_id != next_epoch_id {
            return Err(InvalidParameters::EpochMismatch.into());
        }

        self.parameters.validate_incoming_proposal(proposal)?;

        let candidate = AuthenticatedAccountId::new(proposal.participants())?;

        // If the signer is not a participant of the current epoch, they can only vote after
        // `threshold` participant of the current epoch have casted their vote to admit them.
        if AuthenticatedAccountId::new(self.parameters.participants()).is_err() {
            let n_votes = self
                .parameters_votes
                .n_votes(proposal, self.parameters.participants());

            if n_votes < self.parameters.threshold().value() {
                return Err(VoteError::VoterPending.into());
            }
        }

        let number_of_casted_votes = self.parameters_votes.vote(proposal, candidate);

        let proposal_accepted = proposal.participants().len() as u64 == number_of_casted_votes;

        // Reset the resharing state
        if proposal_accepted {
            let first_domain = self.domains.get_domain_by_index(0);

            self.parameters_votes = ThresholdParametersVotes::default();

            match first_domain {
                Some(first_domain) => {
                    self.resharing_process = Some(ResharingState {
                        reshared_keys: Vec::new(),
                        resharing_key: KeyEvent::new(
                            next_epoch_id,
                            first_domain.clone(),
                            proposal.clone(),
                        ),
                    });
                }
                // A new ThresholdParameters was proposed, but we have no keys.
                // Bump the EpochId.
                None => {
                    self.keyset = Keyset::new(next_epoch_id, Vec::new());
                }
            }
        }

        Ok(())
    }

    pub fn vote_reshared(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        let Some(resharing_process) = &mut self.resharing_process else {
            return Err(InvalidState::ProtocolRunningStateIsNotResharing.into());
        };

        enum VoteOutcome {
            /// A vote has been collected but we don't have enough votes yet for the current
            /// domain.
            VoteCollected,

            /// Everyone has voted for the current domain;
            /// The state transitions into resharing the key for the next domain
            NextDomainResharing,

            /// All domains' keys have been reshared.
            AllDomainsReshared(Keyset, ThresholdParameters),
        }

        let vote_outcome = {
            let keyset = &self.keyset;
            let domains = &self.domains;

            let current_key = keyset.domains[resharing_process.reshared_keys.len()]
                .clone()
                .key;

            if resharing_process
                .resharing_key
                .vote_success(&key_event_id, current_key.clone())?
            {
                let new_key = KeyForDomain {
                    domain_id: key_event_id.domain_id,
                    attempt: key_event_id.attempt_id,
                    key: current_key,
                };
                resharing_process.reshared_keys.push(new_key);

                let prospective_epoch_id = resharing_process.resharing_key.epoch_id();
                match domains.get_domain_by_index(resharing_process.reshared_keys.len()) {
                    Some(next_domain) => {
                        resharing_process.resharing_key = KeyEvent::new(
                            prospective_epoch_id,
                            next_domain.clone(),
                            resharing_process
                                .resharing_key
                                .proposed_parameters()
                                .clone(),
                        );

                        VoteOutcome::NextDomainResharing
                    }
                    None => VoteOutcome::AllDomainsReshared(
                        Keyset::new(
                            prospective_epoch_id,
                            resharing_process.reshared_keys.clone(),
                        ),
                        resharing_process
                            .resharing_key
                            .proposed_parameters()
                            .clone(),
                    ),
                }
            } else {
                VoteOutcome::VoteCollected
            }
        };

        match vote_outcome {
            VoteOutcome::AllDomainsReshared(new_keyset, new_threshold_parameters) => {
                self.keyset = new_keyset;
                self.parameters = new_threshold_parameters;
                self.resharing_process = None;
            }
            VoteOutcome::VoteCollected | VoteOutcome::NextDomainResharing => {}
        }

        Ok(())
    }

    /// Casts a vote for the signer participant to add new domains, replacing any previous vote.
    /// If the number of votes for the same set of new domains reaches the number of participants,
    /// returns the InitializingContractState we should transition into to generate keys for these
    /// new domains.
    pub fn vote_add_domains(
        &mut self,
        domains: Vec<DomainConfig>,
    ) -> Result<Option<InitializingContractState>, Error> {
        if domains.is_empty() {
            return Err(DomainError::AddDomainsMustAddAtLeastOneDomain.into());
        }
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;
        let n_votes = self.add_domains_votes.vote(domains.clone(), &participant);
        if self.parameters.participants().len() as u64 == n_votes {
            let new_domains = self.domains.add_domains(domains.clone())?;
            Ok(Some(InitializingContractState {
                generated_keys: self.keyset.domains.clone(),
                domains: new_domains,
                epoch_id: self.keyset.epoch_id,
                generating_key: KeyEvent::new(
                    self.keyset.epoch_id,
                    domains[0].clone(),
                    self.parameters.clone(),
                ),
                cancel_votes: BTreeSet::new(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Casts a vote to abort the current key resharing attempt.
    /// After aborting, another call to start() is necessary to start a new attempt.
    /// Returns error if there is no active attempt, or if the signer is not a proposed participant.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        let Some(resharing_process) = &mut self.resharing_process else {
            return Err(InvalidState::ProtocolRunningStateIsNotResharing.into());
        };

        resharing_process.resharing_key.vote_abort(key_event_id)
    }

    /// Starts a new attempt to reshare the key for the current domain.
    /// Returns an Error if the signer is not the leader (the participant with the lowest ID).
    pub fn start_key_resharing(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let Some(resharing_process) = &mut self.resharing_process else {
            return Err(InvalidState::ProtocolRunningStateIsNotResharing.into());
        };

        resharing_process
            .resharing_key
            .start(key_event_id, key_event_timeout_blocks)
    }
}

#[cfg(test)]
pub mod running_tests {
    use core::panic;
    use std::collections::BTreeSet;

    use super::*;
    use crate::primitives::{
        domain::{tests::gen_domain_registry, AddDomainsVotes},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantId, Participants},
        test_utils::{bogus_ed25519_public_key_extended, gen_participant, gen_threshold_params},
        thresholds::{Threshold, ThresholdParameters},
        votes::ThresholdParametersVotes,
    };
    use crate::state::key_event::tests::{find_leader, Environment};
    use crate::state::key_event::KeyEvent;
    use assert_matches::assert_matches;
    use near_sdk::AccountId;
    use rand::Rng;

    /// Generates a Running state that contains this many domains.
    pub fn gen_running_state(num_domains: usize) -> RunningContractState {
        let epoch_id = EpochId::new(rand::thread_rng().gen());
        let domains = gen_domain_registry(num_domains);

        let mut keys = Vec::new();
        for domain in domains.domains() {
            let mut attempt = AttemptId::default();
            let x: usize = rand::thread_rng().gen();
            let x = x % 800;
            for _ in 0..x {
                attempt = attempt.next();
            }
            keys.push(KeyForDomain {
                attempt,
                domain_id: domain.id,
                key: bogus_ed25519_public_key_extended(),
            });
        }
        let max_n = 30;
        let threshold_parameters = gen_threshold_params(max_n);
        RunningContractState::new(domains, Keyset::new(epoch_id, keys), threshold_parameters)
    }

    pub fn gen_valid_params_proposal(params: &ThresholdParameters) -> ThresholdParameters {
        let mut rng = rand::thread_rng();
        let current_k = params.threshold().value() as usize;
        let current_n = params.participants().len();
        let n_old_participants: usize = rng.gen_range(current_k..current_n + 1);
        let current_participants = params.participants();
        let mut old_ids: BTreeSet<ParticipantId> = current_participants
            .participants()
            .iter()
            .map(|(_, id, _)| id.clone())
            .collect();
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

        let threshold = ((new_participants.len() as f64) * 0.6).ceil() as u64;
        ThresholdParameters::new(new_participants, Threshold::new(threshold)).unwrap()
    }

    fn test_running_for(num_domains: usize) {
        let mut state = gen_running_state(num_domains);
        println!(
            "Participants: {}, threshold: {}",
            state.parameters.participants().len(),
            state.parameters.threshold().value()
        );
        let mut env = Environment::new(None, None, None);
        let participants = state.parameters.participants().clone();
        // Assert that random proposals get rejected.
        for (account_id, _, _) in participants.participants() {
            let ksp = gen_threshold_params(30);
            env.set_signer(account_id);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next(), &ksp)
                .is_err());
        }
        // Assert that proposals of the wrong epoch ID get rejected.
        {
            let ksp = gen_valid_params_proposal(&state.parameters);
            env.set_signer(&participants.participants()[0].0);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id, &ksp)
                .is_err());
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next().next(), &ksp)
                .is_err());
        }
        // Assert that disagreeing proposals do not reach consensus.
        // Generate an extra proposal for the next step.
        let mut proposals = Vec::new();
        for i in 0..participants.participants().len() + 1 {
            loop {
                let proposal = gen_valid_params_proposal(&state.parameters);
                if proposals.contains(&proposal) {
                    continue;
                }
                if i < participants.participants().len()
                    && !proposal
                        .participants()
                        .is_participant(&participants.participants()[i].0)
                {
                    continue;
                }
                proposals.push(proposal.clone());
                break;
            }
        }

        for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
            env.set_signer(account_id);
            state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposals[i])
                .unwrap();
            assert_matches!(state.resharing_process, None, "{:?}", i)
        }

        // Now let's vote for agreeing proposals.
        let proposal = proposals.last().unwrap().clone();

        let original_epoch_id = state.keyset.epoch_id;
        // existing participants vote
        let mut n_votes = 0;
        for (account_id, _, _) in participants.participants().iter() {
            if !proposal.participants().is_participant(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert_matches!(
                    state.resharing_process,
                    None,
                    "votes {n_votes} domains: {num_domains}"
                )
            }
        }
        // candidates vote
        for (account_id, _, _) in proposal.participants().participants().iter() {
            if participants.is_participant(account_id) {
                continue;
            }
            n_votes += 1;
            env.set_signer(account_id);
            state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if n_votes < proposal.participants().len() || num_domains == 0 {
                assert_matches!(
                    state.resharing_process,
                    None,
                    "votes {n_votes} domains: {num_domains}"
                )
            }
        }
        if num_domains == 0 {
            // If there are no domains, we should transition directly to Running with a higher
            // epoch ID, not resharing.
            assert_eq!(state.keyset.epoch_id, original_epoch_id.next());
            assert_eq!(state.parameters_votes, ThresholdParametersVotes::default());
            assert_eq!(state.add_domains_votes, AddDomainsVotes::default());
        } else {
            let resharing = state.expect_resharing_state();
            assert_eq!(
                resharing.prospective_epoch_id(),
                state.keyset.epoch_id.next(),
            );
            assert_eq!(resharing.resharing_key.proposed_parameters(), &proposal);
        }
    }

    #[test]
    fn test_running_0() {
        test_running_for(0);
    }

    #[test]
    fn test_running_1() {
        test_running_for(1);
    }

    #[test]
    fn test_running_2() {
        test_running_for(2);
    }

    #[test]
    fn test_running_3() {
        test_running_for(3);
    }

    #[test]
    fn test_running_4() {
        test_running_for(4);
    }

    fn start_resharing_process_for_running_state(
        running_state: &mut RunningContractState,
    ) -> Environment {
        let mut env = Environment::new(Some(100), None, None);
        let proposal = gen_valid_params_proposal(&running_state.parameters);

        for (account, _, _) in proposal.participants().participants() {
            env.set_signer(account);
            assert!(
                running_state.resharing_process.is_none(),
                "Running state should not start before all participants have voted."
            );
            env.set_signer(account);
            let next_epoch = running_state.keyset.epoch_id.next();

            running_state
                .vote_new_parameters(next_epoch, &proposal)
                .unwrap();
        }

        assert_matches!(running_state.resharing_process, Some(_));
        env
    }

    use crate::primitives::domain::DomainId;
    use crate::primitives::test_utils::gen_account_id;

    impl RunningContractState {
        fn resharing_key(&self) -> &KeyEvent {
            &self.resharing_process.as_ref().unwrap().resharing_key
        }

        fn expect_resharing_state(&self) -> &ResharingState {
            self.resharing_process
                .as_ref()
                .expect("Running state has started resharing process when all votes are casted.")
        }
    }

    impl ResharingState {
        /// Returns the epoch ID that we would transition into if resharing were completed successfully.
        /// This would increment if we end up voting for a re-proposal.
        fn prospective_epoch_id(&self) -> EpochId {
            self.resharing_key.epoch_id()
        }
    }

    fn test_resharing_contract_state_for(num_domains: usize) {
        println!("Testing with {} domains", num_domains);
        let mut running_state = gen_running_state(num_domains);
        let expected_epoch_id_after_resharing = running_state.keyset.epoch_id.next();

        let mut env = start_resharing_process_for_running_state(&mut running_state);

        let original_keyset = running_state.keyset.clone();

        let candidates: BTreeSet<AccountId> = running_state
            .resharing_key()
            .proposed_parameters()
            .participants()
            .participants()
            .iter()
            .map(|(aid, _, _)| aid.clone())
            .collect();

        for i in 0..num_domains {
            println!("Testing domain {}", i);
            assert!(!running_state.resharing_key().is_active());
            let first_key_event_id = KeyEventId {
                attempt_id: AttemptId::new(),
                domain_id: running_state.domains.get_domain_by_index(i).unwrap().id,
                epoch_id: running_state.resharing_key().epoch_id(),
            };

            let leader = find_leader(running_state.resharing_key());
            for c in &candidates {
                env.set_signer(c);
                // verify that no votes can be cast before the resharing started.
                assert!(running_state.vote_reshared(first_key_event_id).is_err());
                assert!(running_state.vote_abort(first_key_event_id).is_err());
                if *c != leader.0 {
                    assert!(running_state
                        .start_key_resharing(first_key_event_id, 1)
                        .is_err());
                } else {
                    // Also check that starting with the wrong KeyEventId fails.
                    assert!(running_state
                        .start_key_resharing(first_key_event_id.next_attempt(), 1)
                        .is_err());
                }
            }
            // start the resharing; verify that the resharing is for the right epoch and domain ID.
            env.set_signer(&leader.0);
            assert!(running_state
                .start_key_resharing(first_key_event_id, 0)
                .is_ok());

            let key_event = running_state
                .resharing_key()
                .current_key_event_id()
                .unwrap();
            assert_eq!(key_event, first_key_event_id);

            // check that randos can't vote.
            for _ in 0..20 {
                env.set_signer(&gen_account_id());
                assert!(running_state.vote_reshared(key_event).is_err());
                assert!(running_state.vote_abort(key_event).is_err());
            }

            // check that timing out will abort the instance
            env.advance_block_height(1);
            assert!(!running_state.resharing_key().is_active());

            for c in &candidates {
                env.set_signer(c);
                assert!(running_state.vote_reshared(key_event).is_err());
                assert!(running_state.vote_abort(key_event).is_err());
                assert!(!running_state.resharing_key().is_active());
            }

            // assert that votes for a different resharings do not count
            env.set_signer(&leader.0);
            assert!(running_state
                .start_key_resharing(first_key_event_id.next_attempt(), 0)
                .is_ok());
            let key_event = running_state
                .resharing_key()
                .current_key_event_id()
                .unwrap();

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
                    assert!(running_state.vote_reshared(bad_key_event).is_err());
                    assert!(running_state.vote_abort(bad_key_event).is_err());
                }
            }
            assert_eq!(
                running_state
                    .expect_resharing_state()
                    .resharing_key
                    .num_completed(),
                0
            );

            // check that vote_abort immediately causes failure.
            env.advance_block_height(1);
            env.set_signer(&leader.0);

            let start_result = running_state.start_key_resharing(key_event.next_attempt(), 0);
            assert_matches!(start_result, Ok(_));

            let key_event = running_state
                .expect_resharing_state()
                .resharing_key
                .current_key_event_id()
                .unwrap();
            env.set_signer(candidates.iter().next().unwrap());
            assert!(running_state.vote_abort(key_event).is_ok());
            assert!(!running_state
                .expect_resharing_state()
                .resharing_key
                .is_active());

            // assert that valid votes get counted correctly
            env.set_signer(&leader.0);
            let start_result = running_state.start_key_resharing(key_event.next_attempt(), 0);
            assert_matches!(start_result, Ok(_));

            let key_event = running_state
                .expect_resharing_state()
                .resharing_key
                .current_key_event_id()
                .unwrap();
            for (i, c) in candidates.clone().into_iter().enumerate() {
                env.set_signer(&c);

                assert_matches!(running_state.resharing_process, Some(_));
                assert_eq!(running_state.resharing_key().num_completed(), i);
                assert_matches!(running_state.vote_reshared(key_event), Ok(()));
                assert_matches!(running_state.vote_abort(key_event), Err(_));
            }
        }

        let new_keyset = running_state.keyset.clone();

        assert_eq!(new_keyset.epoch_id, expected_epoch_id_after_resharing);

        assert_matches!(
            running_state.resharing_process,
            None,
            "Resharing field is set to None when it is completed.",
        );

        assert!(new_keyset.domains.iter().all(|d| d.attempt.get() == 3));

        let new_key_domain_mapping: Vec<_> = new_keyset
            .domains
            .iter()
            .map(|domain| (domain.key.clone(), domain.domain_id))
            .collect();

        let original_key_domain_mapping: Vec<_> = original_keyset
            .domains
            .iter()
            .map(|domain| (domain.key.clone(), domain.domain_id))
            .collect();

        assert_eq!(new_key_domain_mapping, original_key_domain_mapping);
        assert_eq!(new_keyset.domains.len(), num_domains);
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
        let mut running_state = gen_running_state(3);
        let mut env = start_resharing_process_for_running_state(&mut running_state);

        // Vote for first domain's key.
        let leader = find_leader(running_state.resharing_key());
        env.set_signer(&leader.0);
        let first_key_event_id = KeyEventId {
            attempt_id: AttemptId::new(),
            domain_id: running_state.domains.get_domain_by_index(0).unwrap().id,
            epoch_id: running_state.keyset.epoch_id.next(),
        };
        assert!(running_state
            .start_key_resharing(first_key_event_id, 0)
            .is_ok());

        let old_participants = running_state.parameters.participants().clone();
        {
            let new_participants = running_state
                .resharing_key()
                .proposed_parameters()
                .participants()
                .participants()
                .clone();

            for (account, _, _) in new_participants {
                env.set_signer(&account);
                running_state.vote_reshared(first_key_event_id).unwrap();
            }
        }
        assert!(running_state.expect_resharing_state().reshared_keys.len() == 1);

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
        assert!(running_state
            .parameters
            .validate_incoming_proposal(&new_params_1)
            .is_ok());
        assert!(new_params_1
            .validate_incoming_proposal(&new_params_2)
            .is_ok());
        assert!(running_state
            .parameters
            .validate_incoming_proposal(&new_params_2)
            .is_err());

        let current_resharing_epoch_id = running_state
            .expect_resharing_state()
            .prospective_epoch_id();
        // Reproposing with invalid epoch ID should fail.
        {
            env.set_signer(&old_participants.participants()[0].0);
            assert!(running_state
                .vote_new_parameters(current_resharing_epoch_id, &new_params_1)
                .is_err());
            assert!(running_state
                .vote_new_parameters(current_resharing_epoch_id.next().next(), &new_params_1)
                .is_err());
        }

        // Repropose with new_params_1.
        for (account, _, _) in new_params_1.participants().participants() {
            env.set_signer(account);
            assert_matches!(
                running_state.resharing_process,
                Some(_),
                "Resharing is some wile not completed."
            );
            running_state
                .vote_new_parameters(current_resharing_epoch_id.next(), &new_params_1)
                .unwrap();
        }

        assert_matches!(
            running_state.resharing_process,
            Some(_),
            "Resharing is some wile not completed."
        );

        assert_eq!(
            running_state.expect_resharing_state().reshared_keys.len(),
            0,
            "New state should start from the beginning, with the epoch ID bumped."
        );

        assert_eq!(
            running_state
                .expect_resharing_state()
                .prospective_epoch_id(),
            running_state.keyset.epoch_id.next().next(),
        );

        assert_eq!(
            running_state
                .expect_resharing_state()
                .resharing_key
                .proposed_parameters(),
            &new_params_1
        );
        assert_eq!(
            running_state.resharing_key().domain_id(),
            running_state.domains.get_domain_by_index(0).unwrap().id
        );

        // Repropose with new_params_2. That should fail.
        env.set_signer(&old_participants.participants()[0].0);
        assert!(running_state
            .vote_new_parameters(
                running_state
                    .expect_resharing_state()
                    .prospective_epoch_id()
                    .next(),
                &new_params_2
            )
            .is_err());
    }
}
