use super::participants::ParticipantInfo;
use crate::errors::{Error, InvalidState, InvalidThreshold};
use near_sdk::{near, AccountId};
use std::collections::BTreeMap;

/// Minimum absolute threshold required.
const MIN_THRESHOLD_ABSOLUTE: u64 = 2;

/// Stores the cryptographig threshold for a distributed key.
/// ```
/// use mpc_contract::state::key_state::Threshold;
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

/// Stores information about the threshold key parameters:
/// - owners of key shares
/// - cryptographic threshold
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ThresholdParameters {
    participants: BTreeMap<AccountId, ParticipantInfo>,
    threshold: Threshold,
}

impl ThresholdParameters {
    /// Constructs Threshold parameters from `participants` and `threshold` if the
    /// threshold meets the absolute and relavite validation criteria.
    pub fn new(
        participants: BTreeMap<AccountId, ParticipantInfo>,
        threshold: Threshold,
    ) -> Result<Self, Error> {
        match Self::validate_threshold(participants.len() as u64, threshold.clone()) {
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
        Self::validate_threshold(self.n_participants(), self.threshold())
    }
    pub fn threshold(&self) -> Threshold {
        self.threshold.clone()
    }
    /// Returns the number of key share.
    pub fn n_participants(&self) -> u64 {
        self.participants.len() as u64
    }
    /// Returns the map of Participants.
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfo> {
        &self.participants
    }
    /// Returns true if `account_id` holds a key share.
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
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
// todo: test that index is preserved.
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
#[cfg(test)]
mod tests {
    use crate::primitives::thresholds::{DKGThreshold, Threshold, ThresholdParameters};
    use crate::state::tests::test_utils::{
        gen_legacy_candidates, gen_legacy_participants, gen_participants,
    };
    use rand::Rng;
    use std::collections::BTreeMap;

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
            assert!(
                ThresholdParameters::new(participants.clone(), Threshold::new(k as u64)).is_err()
            );
        }
        assert!(
            ThresholdParameters::new(participants.clone(), Threshold::new((n + 1) as u64)).is_err()
        );
        for k in min_threshold..(n + 1) {
            let threshold = Threshold::new(k as u64);
            let params = ThresholdParameters::new(participants.clone(), threshold.clone());
            assert!(params.is_ok(), "{:?}", params);
            let params = params.unwrap();
            assert!(params.validate().is_ok());
            assert_eq!(params.threshold(), threshold);
            assert_eq!(params.n_participants(), participants.len() as u64);
            assert!(*params.participants() == participants);
            for account_id in participants.keys() {
                assert!(params.is_participant(account_id));
            }
            let mut observed_participants = BTreeMap::new();
            for i in 0u64..(n as u64) {
                let account_id = params.participant_by_idx(i);
                assert!(account_id.is_ok());
                let account_id = account_id.unwrap();
                let idx = params.participant_idx(&account_id);
                assert!(idx.is_ok());
                assert_eq!(idx.unwrap(), i);
                observed_participants.insert(
                    account_id.clone(),
                    params.participants().get(&account_id).unwrap().clone(),
                );
            }
            assert_eq!(observed_participants, participants);
        }
    }
    #[test]
    fn test_migration_candidates() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let candidates = gen_legacy_candidates(n);
        // migratin has to work for now invalid thresholds as well.
        let threshold = Threshold::new(rand::thread_rng().gen::<u64>());
        let tp: ThresholdParameters = (threshold.clone(), &candidates).into();
        assert_eq!(threshold, tp.threshold());
        let participants = tp.participants();
        assert_eq!(participants.len(), n);
        for (account_id, info) in participants {
            let candidate = candidates.get(account_id);
            assert!(candidate.is_some());
            let candidate = candidate.unwrap();
            assert_eq!(candidate.account_id, *account_id);
            assert_eq!(candidate.url, info.url);
            assert_eq!(candidate.cipher_pk, info.cipher_pk);
            assert_eq!(candidate.sign_pk, info.sign_pk);
        }
    }
    #[test]
    fn test_migration_participants() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let legacy_participants = gen_legacy_participants(n);
        // migratin has to work for now invalid thresholds as well.
        let threshold = Threshold::new(rand::thread_rng().gen::<u64>());
        let tp: ThresholdParameters = (threshold.clone(), &legacy_participants).into();
        assert_eq!(threshold, tp.threshold());
        let participants = tp.participants();
        assert_eq!(participants.len(), n);
        for (account_id, info) in participants {
            let legacy_participant = legacy_participants.get(account_id);
            assert!(legacy_participant.is_some());
            let legacy_participant = legacy_participant.unwrap();
            assert_eq!(legacy_participant.account_id, *account_id);
            assert_eq!(legacy_participant.url, info.url);
            assert_eq!(legacy_participant.cipher_pk, info.cipher_pk);
            assert_eq!(legacy_participant.sign_pk, info.sign_pk);
            let legacy_idx = *legacy_participants
                .account_to_participant_id
                .get(account_id)
                .unwrap() as u64;
            assert_eq!(tp.participant_idx(account_id).unwrap(), legacy_idx)
        }
    }
}
