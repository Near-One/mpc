use super::participants::ParticipantInfoV2;
use crate::errors::{Error, InvalidState, InvalidThreshold};
use near_sdk::{env, near, AccountId, PublicKey};
use std::collections::BTreeMap;

const MIN_THRESHOLD_ABSOLUTE: u64 = 2;
/// Identifier for a key event:
/// `epoch_id` the epoch for which the key is supposed to be active
/// `start_block_id`: the block during which the key event startet
/// `random_uid`: a random u64 generated via env::random_seed() during `start_block_id`
/// `leader`: the leader for this key event.
///
/// # Example usage:
/// ```
/// use mpc_contract::state::key_state::KeyEventId;
/// let ke = KeyEventId::new(0, "leader.account.near".parse().unwrap());
/// assert!(ke.next_epoch_id() == 1);
/// ```
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyEventId {
    epoch_id: u64,
    start_block_id: u64,
    random_uid: u64,
    leader: AccountId,
}

impl KeyEventId {
    /// Returns the unique id associated with this key event.
    pub fn uid(&self) -> u64 {
        self.random_uid
    }
    /// Returns self.epoch_id + 1.
    pub fn next_epoch_id(&self) -> u64 {
        self.epoch_id + 1
    }
    /// Returns true if `timeout_in_blocks` blocks have passed since the start of this key event.
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        self.start_block_id + timeout_in_blocks < env::block_height()
    }
    // Construct a new KeyEventId for `epoch_id` and `leader`.
    pub fn new(epoch_id: u64, leader: AccountId) -> Self {
        fn p_rand64() -> u64 {
            let mut bytes = [0u8; 8];
            let seed = env::random_seed();
            bytes.copy_from_slice(&seed[..8]);
            u64::from_le_bytes(bytes)
        }
        KeyEventId {
            epoch_id,
            start_block_id: env::block_height(),
            random_uid: p_rand64(),
            leader,
        }
    }
    // for migrating from V1 to V2
    fn migrated_key(epoch_id: u64) -> Self {
        KeyEventId {
            epoch_id,
            start_block_id: 0,
            random_uid: 0,
            leader: "migrated_key".parse().unwrap(),
        }
    }
}

/// Stores the cryptographig threshold for a distributed key.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Threshold(u64);
impl Threshold {
    pub fn new(val: u64) -> Self {
        Threshold(val)
    }
    pub fn value(&self) -> u64 {
        self.0
    }
}
/// Stores information about the threshold key parameters:
/// - owners of key shares
/// - cryptographic threshold
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ThresholdParameters {
    participants: BTreeMap<AccountId, ParticipantInfoV2>,
    threshold: Threshold,
}
pub fn validate_threshold(n_shares: u64, k: Threshold) -> Result<(), Error> {
    if k.value() > n_shares {
        return Err(InvalidThreshold::MaxRequirementFailed.into());
    }
    if k.value() < MIN_THRESHOLD_ABSOLUTE {
        return Err(InvalidThreshold::MinAbsRequirementFailed.into());
    }
    let percentage_bound = (3 * n_shares + 4) / 5; // minimum 60%
    if k.value() < percentage_bound {
        return Err(InvalidThreshold::MinRelRequirementFailed.into());
    }
    Ok(())
}
impl ThresholdParameters {
    /// Constructs Threshold parameters from `participants` and `threshold` ensures that the
    /// threshold is sensible meets the validation criteria (c.f. [`ThresholdParameters::is_valid`]).
    pub fn new(
        participants: BTreeMap<AccountId, ParticipantInfoV2>,
        threshold: Threshold,
    ) -> Result<Self, Error> {
        let ret = ThresholdParameters {
            participants,
            threshold,
        };
        match ret.is_valid() {
            Ok(_) => Ok(ret),
            Err(err) => Err(err),
        }
    }

    /// Ensures that the threshold is sensible and meets the absolute and minimum requirements.
    /// That is:
    /// - threshold must be at least `MIN_THRESHOLD_ABSOLUTE`
    /// - threshold can not exceed the number of participants.
    /// - threshold must be at least 60% of the number of participants (rounded upwards).
    pub fn is_valid(&self) -> Result<(), Error> {
        validate_threshold(self.n_participants() as u64, self.threshold())
    }
    /// Returns true if `account_id` holds a key share.
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }
    /// Returns the number of key share.
    pub fn n_participants(&self) -> u64 {
        self.participants.len() as u64
    }
    /// Returns the map of Participants.
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
        &self.participants
    }
    /// Returns the AccountId at position `idx` in the BTreeMap.
    pub fn participant_by_idx(&self, idx: u64) -> Result<AccountId, Error> {
        match self.participants.iter().nth(idx as usize) {
            Some(p) => Ok(p.0.clone()),
            None => Err(InvalidState::ParticipantIndexOutOfRange.into()),
        }
    }
    /// Returns the index of participant with `AccountId`
    pub fn participant_idx(&self, account_id: &AccountId) -> Result<u64, Error> {
        for (idx, (key, _)) in self.participants.iter().enumerate() {
            if key == account_id {
                return Ok(idx as u64);
            }
        }
        Err(InvalidState::NotParticipant.into())
    }
    pub fn threshold(&self) -> Threshold {
        self.threshold.clone()
    }
}
/* Migration helpers */
impl From<(Threshold, &legacy_contract::primitives::Candidates)> for ThresholdParameters {
    fn from(
        (threshold, candidates): (Threshold, &legacy_contract::primitives::Candidates),
    ) -> ThresholdParameters {
        let mut participants = BTreeMap::<AccountId, ParticipantInfoV2>::new();
        candidates.candidates.iter().for_each(|(account, info)| {
            participants.insert(account.clone(), info.into());
        });
        ThresholdParameters {
            participants,
            threshold,
        }
    }
}
impl From<(Threshold, &legacy_contract::primitives::Participants)> for ThresholdParameters {
    fn from(
        (threshold, participants): (Threshold, &legacy_contract::primitives::Participants),
    ) -> ThresholdParameters {
        let mut migrated_participants = BTreeMap::<AccountId, ParticipantInfoV2>::new();
        participants
            .participants
            .iter()
            .for_each(|(account, info)| {
                migrated_participants.insert(account.clone(), info.into());
            });
        ThresholdParameters {
            participants: migrated_participants,
            threshold,
        }
    }
}

/// Distributed key state:
/// - the public key
/// - the key event that resulted in the key shares
/// - threshold parameters
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct DKState {
    pub public_key: PublicKey,
    pub key_event_id: KeyEventId,
    pub threshold_parameters: ThresholdParameters,
}

impl DKState {
    pub fn participant_by_idx(&self, idx: u64) -> Result<AccountId, Error> {
        self.threshold_parameters.participant_by_idx(idx)
    }
    pub fn participant_idx(&self, account_id: &AccountId) -> Result<u64, Error> {
        self.threshold_parameters.participant_idx(account_id)
    }
    pub fn epoch_id(&self) -> u64 {
        self.key_event_id.epoch_id
    }
    pub fn next_epoch_id(&self) -> u64 {
        self.key_event_id.next_epoch_id()
    }
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.threshold_parameters.is_participant(account_id)
    }
    pub fn threshold(&self) -> Threshold {
        self.threshold_parameters.threshold()
    }
    pub fn n_participants(&self) -> u64 {
        self.threshold_parameters.n_participants()
    }
    pub fn uid(&self) -> u64 {
        self.key_event_id.random_uid
    }
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
        self.threshold_parameters.participants()
    }
    pub fn validate(&self) -> Result<(), Error> {
        validate_threshold(self.n_participants(), self.threshold())
    }
}

impl From<(&KeyStateProposal, &PublicKey, &KeyEventId)> for DKState {
    fn from(
        (proposal, public_key, key_event_id): (&KeyStateProposal, &PublicKey, &KeyEventId),
    ) -> Self {
        DKState {
            public_key: public_key.clone(),
            key_event_id: key_event_id.clone(),
            threshold_parameters: proposal.proposed_threshold_parameters.clone(),
        }
    }
}

/// Stores the success threshold for distributed key generation and resharing.
/// ```
/// use mpc_contract::state::key_state::DKGThreshold;
/// let dt = DKGThreshold::new(8);
/// assert!(dt.value() == 8);
/// ```
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DKGThreshold(u64);
impl DKGThreshold {
    pub fn new(val: u64) -> Self {
        Self(val)
    }
    pub fn value(&self) -> u64 {
        self.0
    }
}
/// Proposal for changing the Key state.
/// The proposal specifies the desired key state and the threshold that must be reached in order to
/// initiate the resharing / keygen process.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyStateProposal {
    proposed_threshold_parameters: ThresholdParameters,
    key_event_threshold: DKGThreshold,
}
impl KeyStateProposal {
    pub fn new(
        proposed_threshold_parameters: ThresholdParameters,
        key_event_threshold: DKGThreshold,
    ) -> Result<Self, Error> {
        let res = KeyStateProposal {
            proposed_threshold_parameters,
            key_event_threshold,
        };
        match res.validate() {
            Ok(_) => Ok(res),
            Err(err) => Err(err),
        }
    }
    pub fn is_proposed(&self, account_id: &AccountId) -> bool {
        self.proposed_threshold_parameters
            .is_participant(account_id)
    }
    pub fn candidates(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
        self.proposed_threshold_parameters.participants()
    }
    pub fn candidate_by_index(&self, idx: u64) -> Result<AccountId, Error> {
        self.proposed_threshold_parameters.participant_by_idx(idx)
    }
    pub fn proposed_threshold(&self) -> Threshold {
        self.proposed_threshold_parameters.threshold()
    }
    pub fn n_proposed_participants(&self) -> u64 {
        self.proposed_threshold_parameters.n_participants()
    }
    pub fn key_event_threshold(&self) -> DKGThreshold {
        self.key_event_threshold.clone()
    }
    pub fn validate(&self) -> Result<(), Error> {
        validate_thresholds(
            self.n_proposed_participants(),
            self.proposed_threshold(),
            self.key_event_threshold(),
        )
    }
}
pub fn validate_thresholds(
    n_shares: u64,
    k: Threshold,
    dkg_threshold: DKGThreshold,
) -> Result<(), Error> {
    if dkg_threshold.value() > n_shares {
        return Err(InvalidThreshold::MaxDKGThresholdFailed.into());
    }
    if dkg_threshold.value() < k.value() {
        return Err(InvalidThreshold::MinDKGThresholdFailed.into());
    }
    validate_threshold(n_shares, k)
}
/* Migration helpers. Test it. Or delete it and ensure migrate() is never called while in resharing */
impl From<&legacy_contract::ResharingContractState> for DKState {
    fn from(state: &legacy_contract::ResharingContractState) -> Self {
        DKState {
            public_key: state.public_key.clone(),
            key_event_id: KeyEventId::migrated_key(state.old_epoch),
            threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                &state.old_participants,
            )),
        }
    }
}
impl From<&legacy_contract::RunningContractState> for DKState {
    fn from(state: &legacy_contract::RunningContractState) -> Self {
        DKState {
            public_key: state.public_key.clone(),
            key_event_id: KeyEventId::migrated_key(state.epoch),
            threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                &state.participants,
            )),
        }
    }
}
impl From<&legacy_contract::ResharingContractState> for KeyStateProposal {
    fn from(state: &legacy_contract::ResharingContractState) -> Self {
        KeyStateProposal {
            proposed_threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                &state.new_participants,
            )),
            key_event_threshold: DKGThreshold::new(state.threshold as u64),
        }
    }
}
impl From<&legacy_contract::InitializingContractState> for KeyStateProposal {
    fn from(state: &legacy_contract::InitializingContractState) -> KeyStateProposal {
        KeyStateProposal {
            proposed_threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                &state.candidates,
            )),
            key_event_threshold: DKGThreshold::new(state.threshold as u64),
        }
    }
}
