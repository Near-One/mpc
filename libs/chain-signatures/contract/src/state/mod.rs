pub mod initializing;
pub mod key_event;
pub mod resharing;
pub mod running;

use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidState};
use crate::primitives::code_hash::CodeHash;
use crate::primitives::{
    domain::{DomainConfig, DomainId, DomainRegistry, SignatureScheme},
    key_state::{AuthenticatedParticipantId, EpochId, KeyEventId},
    thresholds::{Threshold, ThresholdParameters},
};
use crate::v0_state;
use initializing::InitializingContractState;
use near_sdk::{env, near};
use resharing::ResharingContractState;
use running::RunningContractState;

#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

impl From<v0_state::ProtocolContractState> for ProtocolContractState {
    fn from(value: v0_state::ProtocolContractState) -> Self {
        match value {
            v0_state::ProtocolContractState::Running(running) => {
                ProtocolContractState::Running(running.into())
            }
            _ => env::panic_str("not supported"),
        }
    }
}

impl ProtocolContractState {
    pub fn domain_registry(&self) -> Result<&DomainRegistry, Error> {
        let domain_registry = match self {
            ProtocolContractState::Running(state) => &state.domains,
            ProtocolContractState::Resharing(state) => &state.previous_running_state.domains,
            _ => return Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        };

        Ok(domain_registry)
    }
    pub fn public_key(&self, domain_id: DomainId) -> Result<PublicKeyExtended, Error> {
        match self {
            ProtocolContractState::Running(state) => state.keyset.public_key(domain_id),
            ProtocolContractState::Resharing(state) => {
                state.previous_keyset().public_key(domain_id)
            }
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
    }
    pub fn threshold(&self) -> Result<Threshold, Error> {
        match self {
            ProtocolContractState::Initializing(state) => {
                Ok(state.generating_key.proposed_parameters().threshold())
            }
            ProtocolContractState::Running(state) => Ok(state.parameters.threshold()),
            ProtocolContractState::Resharing(state) => {
                Ok(state.previous_running_state.parameters.threshold())
            }
            ProtocolContractState::NotInitialized => {
                Err(InvalidState::UnexpectedProtocolState.into())
            }
        }
    }
    pub fn proposed_code_hashes_count_votes(&self, code_hash: CodeHash) -> Result<u64, Error> {
        match self {
            ProtocolContractState::Running(state) => {
                Ok(state.proposed_code_hashes.count_votes(&code_hash))
            }
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
    }
    pub fn clear_code_hashes_votes(&mut self) -> Result<(), Error> {
        match self {
            ProtocolContractState::Running(state) => {
                state.proposed_code_hashes.clear_votes();
                Ok(())
            }
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
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
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state.start(key_event_id, key_event_timeout_blocks)
    }
    pub fn vote_reshared(
        &mut self,
        key_event_id: KeyEventId,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Resharing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state
            .vote_reshared(key_event_id)
            .map(|x| x.map(ProtocolContractState::Running))
    }
    /// Casts a vote for `public_key` in `key_event_id` during Initialization.
    /// Fails if the protocol is not in `Initializing` state.
    /// Returns the new protocol state if enough votes have been submitted.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKeyExtended,
    ) -> Result<Option<ProtocolContractState>, Error> {
        let ProtocolContractState::Initializing(state) = self else {
            return Err(InvalidState::ProtocolStateNotResharing.into());
        };
        state
            .vote_pk(key_event_id, public_key)
            .map(|x| x.map(ProtocolContractState::Running))
    }
    /// Casts a vote for `proposed_parameters`, returning the new protocol state if the proposal is
    /// accepted.
    /// Returns an error if the protocol is not in running resharing.
    pub fn vote_new_parameters(
        &mut self,
        prospective_epoch_id: EpochId,
        proposed_parameters: &ThresholdParameters,
    ) -> Result<Option<ProtocolContractState>, Error> {
        match self {
            ProtocolContractState::Running(state) => {
                state.vote_new_parameters(prospective_epoch_id, proposed_parameters)
            }
            ProtocolContractState::Resharing(state) => {
                state.vote_new_parameters(prospective_epoch_id, proposed_parameters)
            }
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
        }
        .map(|x| x.map(ProtocolContractState::Resharing))
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

    pub fn vote_code_hash(&mut self, code_hash: CodeHash) -> Result<(), Error> {
        // TODO: Verify TEE quote here. See GitHub issue #378: https://github.com/Near-One/mpc/issues/378
        if let ProtocolContractState::Running(state) = self {
            state.vote_code_hash(code_hash)
        } else {
            Err(InvalidState::ProtocolStateNotRunning.into())
        }
    }

    pub fn vote_abort_key_event_instance(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        match self {
            ProtocolContractState::Resharing(state) => state.vote_abort(key_event_id),
            ProtocolContractState::Initializing(state) => state.vote_abort(key_event_id),
            _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
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
                Self::NotInitialized
            }
            super::legacy_contract_state::ProtocolContractState::Initializing(state) => {
                Self::Initializing(state.into())
            }
            super::legacy_contract_state::ProtocolContractState::Running(state) => {
                Self::Running(state.into())
            }
            super::legacy_contract_state::ProtocolContractState::Resharing(state) => {
                Self::Resharing(state.into())
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
            ProtocolContractState::Resharing(_) => "Resharing",
        }
    }
    pub fn is_running(&self) -> bool {
        matches!(self, ProtocolContractState::Running(_))
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
            ProtocolContractState::Resharing(state) => {
                AuthenticatedParticipantId::new(
                    state.previous_running_state.parameters.participants(),
                )?;
            }
            ProtocolContractState::NotInitialized => {
                return Err(InvalidState::UnexpectedProtocolState.message(self.name()));
            }
        };
        Ok(())
    }
}
