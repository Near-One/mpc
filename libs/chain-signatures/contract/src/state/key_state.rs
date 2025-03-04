use super::participants::ParticipantInfo;
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
/// assert!(ke.leader() == "leader.account.near");
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
    pub fn leader(&self) -> &AccountId {
        &self.leader
    }
    pub fn start_block_id(&self) -> u64 {
        self.start_block_id
    }
    // for migrating from V1 to V2
    pub fn migrated_key(epoch_id: u64) -> Self {
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
    participants: BTreeMap<AccountId, ParticipantInfo>,
    threshold: Threshold,
}
/// Ensures that the threshold `k` is sensible and meets the absolute and minimum requirements.
/// That is:
/// - threshold must be at least `MIN_THRESHOLD_ABSOLUTE`
/// - threshold can not exceed the number of shares `n_shares`.
/// - threshold must be at least 60% of the number of shares (rounded upwards).
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
    /// Constructs Threshold parameters from `participants` and `threshold` if the
    /// threshold meets the absolute and relavite validation criteria.
    pub fn new(
        participants: BTreeMap<AccountId, ParticipantInfo>,
        threshold: Threshold,
    ) -> Result<Self, Error> {
        match validate_threshold(participants.len() as u64, threshold.clone()) {
            Ok(_) => Ok(ThresholdParameters {
                participants,
                threshold,
            }),
            Err(err) => Err(err),
        }
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
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfo> {
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
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::state::{
        key_state::{DKGThreshold, KeyEventId, KeyStateProposal, ThresholdParameters},
        tests::test_utils::{gen_participants, gen_rand_account_id},
    };
    use near_sdk::{log, test_utils::VMContextBuilder, testing_env, AccountId};
    use rand::Rng;
    fn get_random_seed_and_uid() -> ([u8; 32], u64) {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        (seed, u64::from_le_bytes(bytes))
    }
    #[test]
    fn test_key_event_id() {
        let leader_account: AccountId = gen_rand_account_id();
        let (seed1, uid1) = get_random_seed_and_uid();
        let expected_block_height: u64 = 80;
        let context = VMContextBuilder::new()
            .random_seed(seed1)
            .block_height(expected_block_height)
            .build();
        testing_env!(context);
        let key_event_id = KeyEventId::new(1, leader_account.clone());
        assert_eq!(leader_account, *key_event_id.leader());
        assert_eq!(2, key_event_id.next_epoch_id());
        assert_eq!(uid1, key_event_id.uid());
        assert!(!key_event_id.timed_out(0));
        log!("{:?}", key_event_id);
        let context = VMContextBuilder::new()
            .random_seed(seed1)
            .block_height(expected_block_height + 1000)
            .build();
        testing_env!(context);
        assert!(key_event_id.timed_out(999));
    }
    use crate::state::key_state::Threshold;

    // Better safe than sorry
    #[test]
    fn test_threshold() {
        for _ in 0..20 {
            let v = rand::thread_rng().gen::<u64>();
            let x = Threshold::new(v);
            assert_eq!(v, x.value());
        }
    }
    #[test]
    fn test_threshold_parameters() {
        let n = 40;
        let min_threshold = 24; // 60%
        let participant_set_a = gen_participants(n);
        for k in 1..min_threshold {
            let invalid_threshold = Threshold::new(k as u64);
            assert!(
                ThresholdParameters::new(participant_set_a.clone(), invalid_threshold).is_err()
            );
        }
        for k in min_threshold..(n + 1) {
            let valid_threshold = Threshold::new(k as u64);
            assert!(ThresholdParameters::new(participant_set_a.clone(), valid_threshold).is_ok());
        }

        let tpt = min_threshold;
        let tp = ThresholdParameters::new(participant_set_a.clone(), Threshold::new(tpt as u64))
            .unwrap();
        assert!(tp.threshold().value() == (tpt as u64));
        assert!(tp.n_participants() == (n as u64));
        for account_id in participant_set_a.keys() {
            assert!(tp.is_participant(account_id));
        }
        let mut res = BTreeMap::new();
        for i in 0..n {
            let p = tp.participant_by_idx(i as u64).unwrap();
            assert!(tp.participant_idx(&p).unwrap() == (i as u64));
            let info = tp.participants().get(&p).unwrap();
            assert!(res.insert(p, info.clone()).is_none());
        }
        assert!(res == *tp.participants());
        for ket in tpt..(n + 1) {
            assert!(KeyStateProposal::new(tp.clone(), DKGThreshold::new(ket as u64)).is_ok());
        }
    }
    fn gen_rand_threshold_params(n: usize, k: usize) -> ThresholdParameters {
        ThresholdParameters::new(gen_participants(n), Threshold::new(k as u64)).unwrap()
    }
}
/* Migration helpers */
impl From<(Threshold, &legacy_contract::primitives::Candidates)> for ThresholdParameters {
    fn from(
        (threshold, candidates): (Threshold, &legacy_contract::primitives::Candidates),
    ) -> ThresholdParameters {
        let mut participants = BTreeMap::<AccountId, ParticipantInfo>::new();
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
        let mut migrated_participants = BTreeMap::<AccountId, ParticipantInfo>::new();
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
    pub fn uid(&self) -> u64 {
        self.key_event_id.random_uid
    }
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfo> {
        self.threshold_parameters.participants()
    }
    pub fn validate(&self) -> Result<(), Error> {
        validate_threshold(self.participants().len() as u64, self.threshold())
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
    pub fn candidates(&self) -> &BTreeMap<AccountId, ParticipantInfo> {
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
