use super::participants::{ParticipantId, Participants};
use crate::errors::{Error, InvalidThreshold};
use near_sdk::{near, AccountId};

/// Minimum absolute threshold required.
const MIN_THRESHOLD_ABSOLUTE: u64 = 2;

/// Stores the cryptographig threshold for a distributed key.
/// ```
/// use mpc_contract::primitives::thresholds::Threshold;
/// let dt = Threshold::new(8);
/// assert!(dt.value() == 8);
/// ```
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

/// Stores the success threshold for distributed key generation and resharing.
/// ```
/// use mpc_contract::primitives::thresholds::DKGThreshold;
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
    pub fn validate(&self, n_shares: u64, k: Threshold) -> Result<(), Error> {
        if self.value() > n_shares {
            return Err(InvalidThreshold::MaxDKGThresholdFailed.into());
        }
        if self.value() < k.value() {
            return Err(InvalidThreshold::MinDKGThresholdFailed.into());
        }
        ThresholdParameters::validate_threshold(n_shares, k)
    }
}

/// Stores information about the threshold key parameters:
/// - owners of key shares
/// - cryptographic threshold
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ThresholdParameters {
    participants: Participants,
    threshold: Threshold,
}

impl ThresholdParameters {
    /// Constructs Threshold parameters from `participants` and `threshold` if the
    /// threshold meets the absolute and relavite validation criteria.
    pub fn new(participants: Participants, threshold: Threshold) -> Result<Self, Error> {
        match Self::validate_threshold(participants.count(), threshold.clone()) {
            Ok(_) => Ok(ThresholdParameters {
                participants,
                threshold,
            }),
            Err(err) => Err(err),
        }
    }
    /// Ensures that the threshold `k` is sensible and meets the absolute and minimum requirements.
    /// That is:
    /// - threshold must be at least `MIN_THRESHOLD_ABSOLUTE`
    /// - threshold can not exceed the number of shares `n_shares`.
    /// - threshold must be at least 60% of the number of shares (rounded upwards).
    pub fn validate_threshold(n_shares: u64, k: Threshold) -> Result<(), Error> {
        if k.value() > n_shares {
            return Err(InvalidThreshold::MaxRequirementFailed
                .message(format!("cannot exceed {}, found {:?}", n_shares, k)));
        }
        if k.value() < MIN_THRESHOLD_ABSOLUTE {
            return Err(InvalidThreshold::MinAbsRequirementFailed.into());
        }
        let percentage_bound = (3 * n_shares + 4) / 5; // minimum 60%
        if k.value() < percentage_bound {
            return Err(InvalidThreshold::MinRelRequirementFailed.message(format!(
                "require at least {}, found {:?}",
                percentage_bound, k
            )));
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), Error> {
        Self::validate_threshold(self.n_participants(), self.threshold())?;
        self.participants.validate()
    }
    pub fn threshold(&self) -> Threshold {
        self.threshold.clone()
    }
    /// Returns the number of key share.
    pub fn n_participants(&self) -> u64 {
        self.participants.count()
    }
    /// Returns the map of Participants.
    pub fn participants(&self) -> &Participants {
        &self.participants
    }
    /// Returns true if `account_id` holds a key share.
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants.is_participant(account_id)
    }
    /// Returns the AccountId for the participant `id`.
    pub fn participant_by_idx(&self, id: &ParticipantId) -> Result<AccountId, Error> {
        self.participants.account_id(id)
    }
    /// Returns the index of participant with `AccountId`
    pub fn participant_idx(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
        self.participants.id(account_id)
    }
}

// The previous implementation did not impose restrictions on the threshold.
// Any migration call must succeed, even with invalid thresholds.
impl From<(Threshold, legacy_contract::primitives::Candidates)> for ThresholdParameters {
    fn from(
        (threshold, candidates): (Threshold, legacy_contract::primitives::Candidates),
    ) -> ThresholdParameters {
        ThresholdParameters {
            participants: candidates.into(),
            threshold,
        }
    }
}
// The previous implementation did not impose restrictions on the threshold.
// Any migration call must succeed, even with invalid thresholds.
impl From<(Threshold, legacy_contract::primitives::Participants)> for ThresholdParameters {
    fn from(
        (threshold, participants): (Threshold, legacy_contract::primitives::Participants),
    ) -> ThresholdParameters {
        ThresholdParameters {
            participants: participants.into(),
            threshold,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::primitives::participants::tests::{
        assert_candidate_migration, assert_participant_migration,
    };
    use crate::primitives::thresholds::{DKGThreshold, Threshold, ThresholdParameters};
    use crate::state::tests::test_utils::{
        gen_legacy_candidates, gen_legacy_participants, gen_participants,
    };
    use rand::Rng;

    #[test]
    fn test_threshold() {
        for _ in 0..20 {
            let v = rand::thread_rng().gen::<u64>();
            let x = Threshold::new(v);
            assert_eq!(v, x.value());
        }
    }
    #[test]
    fn test_dkg_threshold() {
        for _ in 0..20 {
            let v = rand::thread_rng().gen::<u64>();
            let x = DKGThreshold::new(v);
            assert_eq!(v, x.value());
        }
    }
    #[test]
    fn test_validate_threshold() {
        let n = rand::thread_rng().gen_range(2..600) as u64;
        let min_threshold = ((n as f64) * 0.6).ceil() as u64;
        for k in 0..min_threshold {
            assert!(ThresholdParameters::validate_threshold(n, Threshold::new(k)).is_err());
        }
        for k in min_threshold..(n + 1) {
            assert!(ThresholdParameters::validate_threshold(n, Threshold::new(k)).is_ok());
        }
        assert!(ThresholdParameters::validate_threshold(n, Threshold::new(n + 1)).is_err());
    }
    #[test]
    fn test_threshold_parameters_constructor() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let min_threshold = ((n as f64) * 0.6).ceil() as usize;

        let participants = gen_participants(n);
        for k in 1..min_threshold {
            let invalid_threshold = Threshold::new(k as u64);
            assert!(ThresholdParameters::new(participants.clone(), invalid_threshold).is_err());
        }
        assert!(
            ThresholdParameters::new(participants.clone(), Threshold::new((n + 1) as u64)).is_err()
        );
        for k in min_threshold..(n + 1) {
            let threshold = Threshold::new(k as u64);
            let tp = ThresholdParameters::new(participants.clone(), threshold.clone());
            assert!(tp.is_ok(), "{:?}", tp);
            let tp = tp.unwrap();
            assert!(tp.validate().is_ok());
            assert_eq!(tp.threshold(), threshold);
            assert_eq!(tp.n_participants(), participants.count());
            assert_eq!(participants, *tp.participants());
            // porbably overkill to test below
            for account_id in participants.participants().keys() {
                assert!(tp.is_participant(account_id));
                let expected_id = participants.id(account_id).unwrap();
                assert_eq!(expected_id, tp.participant_idx(account_id).unwrap());
                assert_eq!(tp.participant_by_idx(&expected_id).unwrap(), *account_id);
            }
        }
    }

    #[test]
    fn test_migration_candidates() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let candidates = gen_legacy_candidates(n);
        // migration has to work for now invalid thresholds as well.
        let threshold = Threshold::new(rand::thread_rng().gen::<u64>());
        let tp: ThresholdParameters = (threshold.clone(), candidates.clone()).into();
        assert_eq!(threshold, tp.threshold());
        let participants = tp.participants();
        assert_eq!(participants.count(), n as u64);
        assert_candidate_migration(&candidates, participants);
    }
    #[test]
    fn test_migration_participants() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let legacy_participants = gen_legacy_participants(n);
        // migration has to work for now invalid thresholds as well.
        let threshold = Threshold::new(rand::thread_rng().gen::<u64>());
        let tp: ThresholdParameters = (threshold.clone(), legacy_participants.clone()).into();
        assert_eq!(threshold, tp.threshold());
        let participants = tp.participants();
        assert_eq!(participants.count(), n as u64);
        assert_participant_migration(&legacy_participants, participants);
    }
}
