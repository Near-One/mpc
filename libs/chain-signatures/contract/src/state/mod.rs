pub mod initializing;
pub mod key_event;
pub mod resharing;
pub mod running;

use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidState};
use crate::primitives::{
    domain::{DomainConfig, DomainId, DomainRegistry, SignatureScheme},
    key_state::{AuthenticatedParticipantId, EpochId, KeyEventId},
    thresholds::{Threshold, ThresholdParameters},
};
use initializing::InitializingContractState;
use near_sdk::near;
use running::RunningContractState;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    // Resharing(ResharingContractState),
}

impl ProtocolContractState {
    pub fn domain_registry(&self) -> Result<&DomainRegistry, Error> {
        let domain_registry = match self {
            ProtocolContractState::Running(state) => &state.domains,
            _ => return Err(InvalidState::ProtocolStateNotRunning.into()),
        };

        Ok(domain_registry)
    }
    pub fn public_key(&self, domain_id: DomainId) -> Result<PublicKeyExtended, Error> {
        match self {
            ProtocolContractState::Running(state) => state.keyset.public_key(domain_id),
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
    }
    pub fn threshold(&self) -> Result<Threshold, Error> {
        match self {
            ProtocolContractState::Initializing(state) => {
                Ok(state.generating_key.proposed_parameters().threshold())
            }
            ProtocolContractState::Running(state) => Ok(state.parameters.threshold()),
            ProtocolContractState::NotInitialized => {
                Err(InvalidState::UnexpectedProtocolState.into())
            }
        }
    }
    pub fn start_keygen_instance(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotInitializing.into());
        };
        state.start(key_event_id, key_event_timeout_blocks)
    }
    pub fn start_reshare_instance(
        &mut self,
        key_event_id: KeyEventId,
        key_event_timeout_blocks: u64,
    ) -> Result<(), Error> {
        let resharing_process = match self {
            ProtocolContractState::Running(RunningContractState {
                resharing_process: Some(resharing_process),
                ..
            }) => resharing_process,
            _ => return Err(InvalidState::ProtocolStateNotRunning.into()),
        };

        resharing_process.start(key_event_id, key_event_timeout_blocks)
    }
    pub fn vote_reshared(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        let ProtocolContractState::Running(running_protocol_state) = self else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };

        let Some(resharing_process) = &mut running_protocol_state.resharing_process else {
            return Err(InvalidState::ProtocolRunningStateIsNotResharing.into());
        };

        let state = resharing_process.vote_reshared(
            key_event_id,
            &running_protocol_state.keyset,
            &running_protocol_state.domains,
        )?;

        if let Some((new_keyset, new_threshold_parameters)) = state {
            running_protocol_state.successful_key_resharing(new_keyset, new_threshold_parameters)
        }

        Ok(())
    }
    /// Casts a vote for `public_key` in `key_event_id` during Initializtion.
    /// Fails if the protocol is not in `Initializing` state.
    /// Returns the new protocol state if enough votes have been submitted.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKeyExtended,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };
        state
            .vote_pk(key_event_id, public_key)
            .map(|x| x.map(ProtocolContractState::Running))
    }

    /// Casts a vote for `proposed_parameters`, returns [`Ok`] the new protocol state if the proposal is
    /// accepted.
    /// Returns an error if the protocol is not in running state.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposed_parameters: &ThresholdParameters,
    ) -> Result<(), Error> {
        let ProtocolContractState::Running(running_state) = self else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };

        let vote_outcome =
            running_state.vote_new_parameters(prospective_epoch_id, proposed_parameters)?;

        if let Some(vote_outcome) = vote_outcome {
            running_state.resharing_process = Some(vote_outcome);
        }

        Ok(())
    }

    pub fn vote_add_domains(
        &mut self,
        domains: Vec<DomainConfig>,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Running(state) => state.vote_add_domains(domains),
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
        .map(|x| x.map(ProtocolContractState::Initializing))
    }

    pub fn vote_abort_key_event_instance(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        match self {
            ProtocolContractState::Initializing(state) => state.vote_abort(key_event_id),
            ProtocolContractState::Running(RunningContractState {
                resharing_process: Some(resharing_process),
                ..
            }) => resharing_process.vote_abort(key_event_id),
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
    }

    pub fn vote_cancel_keygen(
        &mut self,
        next_domain_id: u64,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Initializing(state) => state.vote_cancel(next_domain_id),
            _ => Err(InvalidState::ProtocolStateNotInitializing.into()),
        }
        .map(|x| x.map(ProtocolContractState::Running))
    }

    pub fn most_recent_domain_for_signature_scheme(
        &self,
        signature_scheme: SignatureScheme,
    ) -> Result<DomainId, Error> {
        self.domain_registry()?
            .most_recent_domain_for_signature_scheme(signature_scheme)
            .ok_or_else(|| DomainError::NoSuchDomain.into())
    }
}

impl From<&super::legacy_contract_state::ProtocolContractState> for ProtocolContractState {
    fn from(protocol_state: &super::legacy_contract_state::ProtocolContractState) -> Self {
        // can this be simplified?
        match &protocol_state {
            super::legacy_contract_state::ProtocolContractState::NotInitialized => {
                ProtocolContractState::NotInitialized
            }
            super::legacy_contract_state::ProtocolContractState::Initializing(state) => {
                ProtocolContractState::Initializing(state.into())
            }
            super::legacy_contract_state::ProtocolContractState::Running(state) => {
                ProtocolContractState::Running(state.into())
            }
            super::legacy_contract_state::ProtocolContractState::Resharing(_) => {
                unimplemented!("Migration of running state will not happen.")
            }
        }
    }
}

impl ProtocolContractState {
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolContractState::NotInitialized => "NotInitialized",
            ProtocolContractState::Initializing(_) => "Initializing",
            ProtocolContractState::Running(_) => "Running",
        }
    }
    pub fn is_running(&self) -> bool {
        if let ProtocolContractState::Running(_) = self {
            return true;
        }
        false
    }
    pub fn authenticate_update_vote(&self) -> Result<(), Error> {
        match &self {
            ProtocolContractState::Initializing(state) => {
                AuthenticatedParticipantId::new(
                    state.generating_key.proposed_parameters().participants(),
                )?;
            }
            ProtocolContractState::Running(state) => {
                AuthenticatedParticipantId::new(state.parameters.participants())?;
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        };
        Ok(())
    }
}
