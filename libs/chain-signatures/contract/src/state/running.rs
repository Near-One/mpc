use super::initializing::InitializingContractState;
use super::key_event::KeyEvent;
use super::resharing::ResharingContractState;
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidParameters};
use crate::legacy_contract_state;
use crate::primitives::domain::{AddDomainsVotes, DomainConfig, DomainId, DomainRegistry};
use crate::primitives::key_state::{
    AttemptId, AuthenticatedParticipantId, EpochId, KeyForDomain, Keyset,
};
use crate::primitives::thresholds::ThresholdParameters;
use crate::primitives::votes::ThresholdParametersVotes;
use near_sdk::near;
use std::collections::BTreeSet;

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
    pub resharing_process: Option<ResharingContractState>,
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

    /// Casts a vote for `proposal` to the current state, propagating any errors.
    /// Returns ResharingContractState if the proposal is accepted.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposal: &ThresholdParameters,
    ) -> Result<Option<ResharingContractState>, Error> {
        if prospective_epoch_id != self.keyset.epoch_id.next() {
            return Err(InvalidParameters::EpochMismatch.into());
        }
        let first_domain = self.domains.get_domain_by_index(0);

        // ensure the signer is a participant
        let participant = AuthenticatedParticipantId::new(self.parameters.participants())?;

        // ensure the proposal is valid against the current parameters
        self.parameters.validate_incoming_proposal(proposal)?;

        // finally, vote. Propagate any errors
        let n_votes = self.parameters_votes.vote(proposal, &participant);

        enum ProposalVoteStatus {
            ProposalAccepted,
            ProposalCandidate,
        }

        let proposal_status = match self.parameters.threshold().value() <= n_votes {
            true => ProposalVoteStatus::ProposalAccepted,
            false => ProposalVoteStatus::ProposalCandidate,
        };

        match (proposal_status, first_domain) {
            (ProposalVoteStatus::ProposalAccepted, Some(first_domain)) => {
                return Ok(Some(ResharingContractState {
                    reshared_keys: Vec::new(),
                    resharing_key: KeyEvent::new(
                        self.keyset.epoch_id.next(),
                        first_domain.clone(),
                        proposal.clone(),
                    ),
                }));
            }
            // A new ThresholdParameters was proposed, but we have no keys, so directly
            // transition into Running state but bump the EpochId.
            (ProposalVoteStatus::ProposalAccepted, None) => {
                *self = RunningContractState::new(
                    self.domains.clone(),
                    Keyset::new(self.keyset.epoch_id.next(), Vec::new()),
                    proposal.clone(),
                );
            }
            _ => {}
        }

        Ok(None)
    }

    /// Casts a vote for the signer participant to add new domains, replacing any previous vote.
    /// If this causes a threshold number of participants to vote for the same set of new domains,
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
        if self.parameters.threshold().value() <= n_votes {
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

    pub(super) fn successful_key_resharing(
        &mut self,
        new_keyset: Keyset,
        new_threshold_parameters: ThresholdParameters,
    ) {
        self.keyset = new_keyset;
        self.parameters = new_threshold_parameters;
        self.resharing_process = None;
    }
}

#[cfg(test)]
pub mod running_tests {
    use std::collections::BTreeSet;

    use super::RunningContractState;
    use crate::primitives::domain::tests::gen_domain_registry;
    use crate::primitives::domain::AddDomainsVotes;
    use crate::primitives::key_state::{AttemptId, EpochId, KeyForDomain, Keyset};
    use crate::primitives::participants::{ParticipantId, Participants};
    use crate::primitives::test_utils::{
        bogus_ed25519_public_key_extended, gen_participant, gen_threshold_params,
    };
    use crate::primitives::thresholds::{Threshold, ThresholdParameters};
    use crate::primitives::votes::ThresholdParametersVotes;
    use crate::state::key_event::tests::Environment;
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
        // Assert that disagreeing proposals do not reach concensus.
        // Generate an extra proposal for the next step.
        let mut proposals = Vec::new();
        for _ in 0..participants.participants().len() + 1 {
            loop {
                let proposal = gen_valid_params_proposal(&state.parameters);
                if proposals.contains(&proposal) {
                    continue;
                }
                proposals.push(proposal.clone());
                break;
            }
        }
        for (i, (account_id, _, _)) in participants.participants().iter().enumerate() {
            env.set_signer(account_id);
            assert!(state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposals[i])
                .unwrap()
                .is_none());
        }

        // Now let's vote for agreeing proposals.
        let proposal = proposals.last().unwrap().clone();

        let original_epoch_id = state.keyset.epoch_id;
        let mut resharing = None;
        for (i, (account_id, _, _)) in participants
            .participants()
            .iter()
            .enumerate()
            .take(state.parameters.threshold().value() as usize)
        {
            env.set_signer(account_id);
            let res = state
                .vote_new_parameters(state.keyset.epoch_id.next(), &proposal)
                .unwrap();
            if i + 1 < state.parameters.threshold().value() as usize || num_domains == 0 {
                assert!(res.is_none());
            } else {
                resharing = Some(res.unwrap());
            }
        }
        if num_domains == 0 {
            // If there are no domains, we should transition directly to Running with a higher
            // epoch ID, not resharing.
            assert_eq!(state.keyset.epoch_id, original_epoch_id.next());
            assert_eq!(state.parameters_votes, ThresholdParametersVotes::default());
            assert_eq!(state.add_domains_votes, AddDomainsVotes::default());
        } else {
            let resharing = resharing.unwrap();
            assert_eq!(
                resharing.previous_running_state.parameters,
                state.parameters
            );
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
}
