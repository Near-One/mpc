//! ## Overview
//! This module stores the previous contract state—the one you want to migrate from.
//! The goal is to describe the data layout _exactly_ as it existed before.
//!
//! ## Guideline
//! In theory, you could copy-paste every struct from the specific commit you're migrating from.
//! However, this approach (a) requires manual effort from a developer and (b) increases the binary size.
//! A better approach: only copy the structures that have changed and import the rest from the existing codebase.
use near_account_id::AccountId;
use near_sdk::store::IterableMap;
use near_sdk::{env, near, store::LookupMap};
use std::collections::{BTreeMap, HashSet};

use crate::legacy_contract_state::ConfigV1;
use crate::primitives::code_hash::CodeHashesVotes;
use crate::primitives::domain::{AddDomainsVotes, DomainRegistry};
use crate::primitives::key_state::{AuthenticatedParticipantId, KeyForDomain, Keyset};
use crate::primitives::thresholds::ThresholdParameters;
use crate::state::initializing::InitializingContractState;
use crate::state::key_event::KeyEvent;
use crate::update::UpdateId;
use crate::{
    config::Config,
    primitives::signature::{SignatureRequest, YieldIndex},
    AllowedCodeHashes, MpcContract, TeeState,
};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ResharingContractState {
    pub previous_running_state: RunningContractState,
    pub reshared_keys: Vec<KeyForDomain>,
    pub resharing_key: KeyEvent,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Default, PartialEq)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub struct ThresholdParametersVotes {
    proposal_by_account: BTreeMap<AuthenticatedParticipantId, ThresholdParameters>,
}

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
}
#[near(serializers=[borsh, json])]
#[derive(Debug)]
#[cfg_attr(feature = "dev-utils", derive(Clone))]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

#[allow(clippy::large_enum_variant)]
#[near(serializers=[borsh])]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum Update {
    Config(Config),
    Contract(Vec<u8>),
    ConfigV1(ConfigV1),
}

#[near(serializers=[borsh])]
#[derive(Debug)]
struct UpdateEntry {
    updates: Vec<Update>,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct ProposedUpdates {
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MpcContractV0 {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    pub proposed_updates: ProposedUpdates,
    pub config: Config,
}

impl From<RunningContractState> for crate::RunningContractState {
    fn from(value: RunningContractState) -> Self {
        Self {
            domains: value.domains,
            keyset: value.keyset,
            parameters: value.parameters,
            parameters_votes: crate::primitives::votes::ThresholdParametersVotes::default(),
            add_domains_votes: value.add_domains_votes,
        }
    }
}

impl From<ProtocolContractState> for crate::ProtocolContractState {
    fn from(value: ProtocolContractState) -> Self {
        match value {
            ProtocolContractState::Running(running) => {
                crate::ProtocolContractState::Running(running.into())
            }
            _ => env::panic_str("not supported"),
        }
    }
}

impl From<MpcContractV0> for MpcContract {
    fn from(value: MpcContractV0) -> Self {
        Self {
            protocol_state: value.protocol_state.into(),
            pending_requests: value.pending_requests,
            proposed_updates: crate::ProposedUpdates::default(),
            config: value.config,
            tee_state: TeeState {
                allowed_code_hashes: AllowedCodeHashes::default(),
                historical_code_hashes: vec![],
                votes: CodeHashesVotes::default(),
            },
        }
    }
}
