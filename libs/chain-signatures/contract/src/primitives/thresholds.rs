use super::participants::ParticipantInfo;
use crate::errors::{Error, InvalidState, InvalidThreshold};
use near_sdk::{near, AccountId};
use std::collections::BTreeMap;

const MIN_THRESHOLD_ABSOLUTE: u64 = 2;
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
    pub fn validate(&self) -> Result<(), Error> {
        validate_threshold(self.n_participants(), self.threshold())
    }
}

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

/* Migration helpers */
//impl From<(Threshold, &legacy_contract::primitives::Candidates)> for ThresholdParameters {
//    fn from(
//        (threshold, candidates): (Threshold, &legacy_contract::primitives::Candidates),
//    ) -> ThresholdParameters {
//        let mut participants = BTreeMap::<AccountId, ParticipantInfo>::new();
//        candidates.candidates.iter().for_each(|(account, info)| {
//            participants.insert(account.clone(), info.into());
//        });
//        ThresholdParameters {
//            participants,
//            threshold,
//        }
//    }
//}
//impl From<(Threshold, &legacy_contract::primitives::Participants)> for ThresholdParameters {
//    fn from(
//        (threshold, participants): (Threshold, &legacy_contract::primitives::Participants),
//    ) -> ThresholdParameters {
//        let mut migrated_participants = BTreeMap::<AccountId, ParticipantInfo>::new();
//        participants
//            .participants
//            .iter()
//            .for_each(|(account, info)| {
//                migrated_participants.insert(account.clone(), info.into());
//            });
//        ThresholdParameters {
//            participants: migrated_participants,
//            threshold,
//        }
//    }
//}
