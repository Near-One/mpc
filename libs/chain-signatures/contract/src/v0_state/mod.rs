use std::collections::BTreeMap;

use near_sdk::{near, store::LookupMap};

use crate::{
    config::Config,
    primitives::{
        domain::{AddDomainsVotes, DomainRegistry},
        key_state::{AuthenticatedParticipantId, KeyForDomain, Keyset},
        signature::{SignatureRequest, YieldIndex},
        thresholds::ThresholdParameters,
    },
    state::{initializing::InitializingContractState, key_event::KeyEvent},
    update::ProposedUpdates,
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
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MpcContractV0 {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    pub proposed_updates: ProposedUpdates,
    pub config: Config,
}
