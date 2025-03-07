use super::participants::{ParticipantId, Participants};
use super::thresholds::{DKGThreshold, Threshold, ThresholdParameters};
use crate::errors::Error;
use near_sdk::{near, AccountId, PublicKey};

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EpochId(u64);
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyEventAttempt(u64);
/// Identifier for a key event:
/// `epoch_id` the epoch for which the key is supposed to be active
/// `start_block_id`: the block during which the key event startet
/// `uid`: a random u64 generated via env::random_seed() during `start_block_id`
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
    epoch_id: EpochId,
    attempt: KeyEventAttempt,
}
pub struct KeyId(u128);

impl KeyEventId {
    /// Returns the unique id associated with this key event.
    pub fn attempt(&self) -> u64 {
        self.attempt.0
    }
    /// Returns the unique id associated with this key event.
    pub fn next_attempt(&self) -> u64 {
        self.attempt.0 + 1
    }
    /// Returns self.epoch_id + 1.
    pub fn epoch_id(&self) -> u64 {
        self.epoch_id.0
    }
    /// Returns self.epoch_id + 1.
    pub fn next_epoch_id(&self) -> u64 {
        self.epoch_id.0 + 1
    }
    //pub fn id(&self) -> KeyId {
    //    KeyId(((self.epoch_id.0 as u128) << 64) ^ (self.attempt.0 as u128))
    //}
    ///// Returns true if `timeout_in_blocks` blocks have passed since the start of this key event.
    //pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
    //    self.start_block_id + timeout_in_blocks < env::block_height()
    //}
    // Construct a new KeyEventId for `epoch_id` and `leader`.
    //pub fn next_event(epoch_id: EpochId, attempt: AttemptId) -> Self {
    //    KeyEventId { epoch_id, attempt }
    //}

    // for migrating from V1 to V2
    pub fn new_migrated_key(epoch_id: u64) -> Self {
        KeyEventId {
            epoch_id: EpochId(epoch_id),
            attempt: KeyEventAttempt(0),
        }
    }
}

///Distributed key state:
/// - the public key
/// - the key event that resulted in the key shares
/// - threshold parameters
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct DKState {
    public_key: PublicKey,
    key_event_id: KeyEventId,
    threshold_parameters: ThresholdParameters,
}

impl DKState {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn epoch_id(&self) -> EpochId {
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
    pub fn id(&self) -> u64 {
        self.key_event_id.id
    }
    pub fn participants(&self) -> &Participants {
        self.threshold_parameters.participants()
    }
    pub fn validate(&self) -> Result<(), Error> {
        ThresholdParameters::validate_threshold(self.participants().count(), self.threshold())
    }
    pub fn new(
        public_key: PublicKey,
        key_event_id: KeyEventId,
        threshold_parameters: ThresholdParameters,
    ) -> Result<Self, Error> {
        threshold_parameters.validate()?;
        Ok(DKState {
            public_key,
            key_event_id,
            threshold_parameters,
        })
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
    pub fn proposed_threshold_parameters(&self) -> &ThresholdParameters {
        &self.proposed_threshold_parameters
    }
    pub fn new(
        proposed_threshold_parameters: ThresholdParameters,
        key_event_threshold: DKGThreshold,
    ) -> Result<Self, Error> {
        key_event_threshold.validate(
            proposed_threshold_parameters.n_participants(),
            proposed_threshold_parameters.threshold(),
        )?;
        Ok(KeyStateProposal {
            proposed_threshold_parameters,
            key_event_threshold,
        })
    }
    pub fn is_proposed(&self, account_id: &AccountId) -> bool {
        self.proposed_threshold_parameters
            .is_participant(account_id)
    }
    pub fn candidates(&self) -> &Participants {
        self.proposed_threshold_parameters.participants()
    }
    pub fn candidate(&self, idx: &ParticipantId) -> Result<AccountId, Error> {
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
        self.key_event_threshold()
            .validate(self.n_proposed_participants(), self.proposed_threshold())?;
        self.candidates().validate()
    }
}

/* Migration helpers. Test it. Or delete it and ensure migrate() is never called while in resharing */
impl From<&legacy_contract::ResharingContractState> for DKState {
    fn from(state: &legacy_contract::ResharingContractState) -> Self {
        DKState {
            public_key: state.public_key.clone(),
            key_event_id: KeyEventId::new_migrated_key(state.old_epoch),
            threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                state.old_participants.clone(),
            )),
        }
    }
}
impl From<&legacy_contract::RunningContractState> for DKState {
    fn from(state: &legacy_contract::RunningContractState) -> Self {
        DKState {
            public_key: state.public_key.clone(),
            key_event_id: KeyEventId::new_migrated_key(state.epoch),
            threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                state.participants.clone(),
            )),
        }
    }
}
impl From<&legacy_contract::ResharingContractState> for KeyStateProposal {
    fn from(state: &legacy_contract::ResharingContractState) -> Self {
        KeyStateProposal {
            proposed_threshold_parameters: ThresholdParameters::from((
                Threshold::new(state.threshold as u64),
                state.new_participants.clone(),
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
                state.candidates.clone(),
            )),
            key_event_threshold: DKGThreshold::new(state.threshold as u64),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::DKState;
    use crate::primitives::key_state::KeyEventId;
    use crate::primitives::key_state::KeyStateProposal;
    use crate::primitives::participants::tests::assert_candidate_migration;
    use crate::primitives::participants::tests::assert_participant_migration;
    use crate::primitives::thresholds::DKGThreshold;
    use crate::state::tests::test_utils::gen_legacy_initializing_state;
    use crate::state::tests::test_utils::gen_legacy_resharing_state;
    use crate::state::tests::test_utils::gen_legacy_running_state;
    use crate::state::tests::test_utils::min_thrershold;
    use crate::state::tests::test_utils::{gen_key_event_id, gen_pk, gen_threshold_params};
    use rand::Rng;

    const MAX_N: usize = 900;

    #[test]
    fn test_key_event_id() {
        //let leader_account: AccountId = gen_account_id();
        //let (seed1, uid1) = gen_seed_uid();
        //let expected_block_height: u64 = 80;
        //let context = VMContextBuilder::new()
        //    .random_seed(seed1)
        //    .block_height(expected_block_height)
        //    .build();
        //testing_env!(context);
        let epoch_id = rand::thread_rng().gen();
        let id = rand::thread_rng().gen();
        let key_event_id = KeyEventId::new(epoch_id, id);
        assert_eq!(id + 1, key_event_id.next_epoch_id());
        assert_eq!(id, key_event_id.id());
        //log!("{:?}", key_event_id);
        //let (seed2, uid2) = gen_seed_uid();
        //let context = VMContextBuilder::new()
        //    .random_seed(seed2)
        //    .block_height(expected_block_height + 1000)
        //    .build();
        //testing_env!(context);
        //let key_event_id = KeyEventId::new(0, leader_account.clone());
        //assert_eq!(uid2, key_event_id.uid());
        assert_eq!(KeyEventId::new_migrated_key(5).next_epoch_id(), 6);
        assert_eq!(KeyEventId::new_migrated_key(5).id(), 0);
    }

    #[test]
    fn test_dk_state() {
        let public_key = gen_pk();
        let key_event_id = gen_key_event_id();
        let threshold_params = gen_threshold_params(MAX_N);
        let dk_state = DKState::new(public_key.clone(), key_event_id, threshold_params).unwrap();
        assert_eq!(*dk_state.public_key(), public_key);
        assert!(dk_state.validate().is_ok());
    }
    pub fn gen_key_state_proposal() -> KeyStateProposal {
        let proposed_threshold_parameters = gen_threshold_params(MAX_N);
        let key_event_threshold =
            DKGThreshold::new(proposed_threshold_parameters.threshold().value());
        KeyStateProposal::new(
            proposed_threshold_parameters.clone(),
            key_event_threshold.clone(),
        )
        .unwrap()
    }
    #[test]
    fn test_key_state_proposal() {
        let proposed_threshold_parameters = gen_threshold_params(MAX_N);
        for i in 0..proposed_threshold_parameters.threshold().value() {
            let key_event_threshold = DKGThreshold::new(i);
            assert!(KeyStateProposal::new(
                proposed_threshold_parameters.clone(),
                key_event_threshold
            )
            .is_err());
        }
        for i in proposed_threshold_parameters.threshold().value()
            ..proposed_threshold_parameters.n_participants() + 1
        {
            let key_event_threshold = DKGThreshold::new(i);
            let ksp =
                KeyStateProposal::new(proposed_threshold_parameters.clone(), key_event_threshold);
            assert!(ksp.is_ok());
            let ksp = ksp.unwrap();
            assert!(ksp.validate().is_ok());
            assert_eq!(ksp.key_event_threshold().value(), i);
        }
    }

    #[test]
    fn test_key_state_proposal_migration_initializing() {
        let n = rand::thread_rng().gen_range(2..MAX_N);
        let min_k = min_thrershold(n);
        // we must allow previously invalid paramters as well
        let k_invalid = rand::thread_rng().gen_range(1..min_k);
        let k_valid = rand::thread_rng().gen_range(min_k..n + 1);
        for k in [k_invalid, k_valid] {
            let legacy_state = gen_legacy_initializing_state(n, k);
            let migrated_ksp: KeyStateProposal = (&legacy_state).into();
            assert_eq!(migrated_ksp.key_event_threshold().value(), k as u64);
            assert_eq!(migrated_ksp.proposed_threshold().value(), k as u64);
            assert_eq!(migrated_ksp.n_proposed_participants(), n as u64);
            assert_candidate_migration(&legacy_state.candidates, migrated_ksp.candidates());
        }
    }

    #[test]
    fn test_dkstate_migration_running() {
        let n = rand::thread_rng().gen_range(2..MAX_N);
        let min_k = min_thrershold(n);
        // we must allow previously invalid paramters as well
        let k_invalid = rand::thread_rng().gen_range(1..min_k);
        let k_valid = rand::thread_rng().gen_range(min_k..n + 1);
        for k in [k_invalid, k_valid] {
            let legacy_state = gen_legacy_running_state(n, k);
            let migrated_dkg: DKState = (&legacy_state).into();
            assert_eq!(migrated_dkg.threshold().value(), k as u64);
            assert_eq!(*migrated_dkg.public_key(), legacy_state.public_key);
            assert_eq!(migrated_dkg.epoch_id(), legacy_state.epoch);
            assert_participant_migration(&legacy_state.participants, migrated_dkg.participants());
        }
    }

    #[test]
    fn test_dkstate_key_state_proposal_migration_resharing() {
        let n = rand::thread_rng().gen_range(2..MAX_N);
        let min_k = min_thrershold(n);
        // we must allow previously invalid paramters as well
        let k_invalid = rand::thread_rng().gen_range(1..min_k);
        let k_valid = rand::thread_rng().gen_range(min_k..n + 1);
        for k in [k_invalid, k_valid] {
            let legacy_state = gen_legacy_resharing_state(n, k);
            let migrated_dkg: DKState = (&legacy_state).into();
            assert_eq!(migrated_dkg.threshold().value(), k as u64);
            assert_eq!(*migrated_dkg.public_key(), legacy_state.public_key);
            assert_eq!(migrated_dkg.epoch_id(), legacy_state.old_epoch);
            assert_participant_migration(
                &legacy_state.old_participants,
                migrated_dkg.participants(),
            );
            let migrated_ksp: KeyStateProposal = (&legacy_state).into();
            assert_eq!(migrated_ksp.proposed_threshold().value(), k as u64);
            assert_eq!(migrated_ksp.key_event_threshold().value(), k as u64);
            assert_eq!(migrated_ksp.n_proposed_participants(), n as u64);
            assert_participant_migration(&legacy_state.new_participants, migrated_ksp.candidates());
        }
    }
}
