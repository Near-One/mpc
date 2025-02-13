use crate::errors::Error;
use crate::errors::InvalidState;
use crate::errors::InvalidThreshold;
use crate::errors::VoteError;
use crate::InitializingContractState;
use crate::ResharingContractState;
use crate::RunningContractState;
use crypto_shared::{derive_epsilon, SerializableScalar};
use k256::Scalar;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::env;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{AccountId, BorshStorageKey, CryptoHash, NearToken, PublicKey};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReshareInstance {
    pub key_event_id: KeyEventId,
    pub participants_completed: BTreeSet<AccountId>,
    pub active: bool,
}

impl ReshareInstance {
    pub fn active(&self, timeout_in_blocks: u64) -> bool {
        self.active && !self.key_event_id.timed_out(timeout_in_blocks)
    }
    pub fn new(key_event_id: KeyEventId) -> Self {
        ReshareInstance {
            key_event_id,
            participants_completed: BTreeSet::new(),
            active: true,
        }
    }
    /// Adds `account_id` to the current set of votes and returns the number of votes collected.
    pub fn vote_completed(&mut self, account_id: AccountId) -> u64 {
        self.participants_completed.insert(account_id);
        self.participants_completed.len() as u64
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize)]
pub struct KeygenInstance {
    pub key_event_id: KeyEventId,
    pub participants_completed: BTreeMap<AccountId, PublicKey>,
    pub pk_votes: PkVotes,
    pub active: bool,
}
impl KeygenInstance {
    pub fn active(&self, timeout_in_blocks: u64) -> bool {
        self.active && !self.key_event_id.timed_out(timeout_in_blocks)
    }
    pub fn new(key_event_id: KeyEventId) -> Self {
        KeygenInstance {
            key_event_id,
            participants_completed: BTreeMap::new(),
            pk_votes: PkVotes::new(),
            active: true,
        }
    }
    /// Adds `account_id` to the current set of votes and returns the number of votes collected.
    pub fn vote_completed(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<u64, Error> {
        if self
            .participants_completed
            .insert(account_id.clone(), public_key.clone())
            .is_some()
        {
            return Err(VoteError::VoteAlreadySubmitted.into()); // todo: should we just remove?
        }
        self.pk_votes.entry(public_key.clone()).insert(account_id);
        Ok(self.pk_votes.entry(public_key).len() as u64)
    }
}
#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyEventId {
    pub epoch_id: u64,
    pub start_block_id: u64,
    pub random_uid: u64,
    pub leader: AccountId,
}

impl KeyEventId {
    pub fn next_epoch_id(&self) -> u64 {
        self.epoch_id + 1
    }
    pub fn timed_out(&self, timeout_in_blocks: u64) -> bool {
        return self.start_block_id + timeout_in_blocks < env::block_height();
    }
    pub fn new(epoch_id: u64, leader: AccountId) -> Self {
        let seed = env::random_seed();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&seed[..8]);
        let uid = u64::from_le_bytes(bytes);

        KeyEventId {
            epoch_id,
            start_block_id: env::block_height(),
            random_uid: uid,
            leader,
        }
    }
}

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
)]
pub struct ParticipantInfoV2 {
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

impl From<&CandidateInfo> for ParticipantInfoV2 {
    fn from(info: &CandidateInfo) -> ParticipantInfoV2 {
        ParticipantInfoV2 {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk.clone(),
            sign_pk: info.sign_pk.clone(),
        }
    }
}
impl From<&ParticipantInfo> for ParticipantInfoV2 {
    fn from(info: &ParticipantInfo) -> ParticipantInfoV2 {
        ParticipantInfoV2 {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk.clone(),
            sign_pk: info.sign_pk.clone(),
        }
    }
}
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
)]
pub struct ThresholdParameters {
    pub participants: BTreeMap<AccountId, ParticipantInfoV2>,
    pub threshold: u64,
}

impl From<(usize, &Participants)> for ThresholdParameters {
    fn from((threshold, participants): (usize, &Participants)) -> ThresholdParameters {
        let mut migrated_participants = BTreeMap::<AccountId, ParticipantInfoV2>::new();
        participants
            .participants
            .iter()
            .map(|(account, info)| migrated_participants.insert(account.clone(), info.into()));
        ThresholdParameters {
            participants: migrated_participants,
            threshold: threshold as u64,
        }
    }
}
impl From<(usize, &Candidates)> for ThresholdParameters {
    fn from((threshold, candidates): (usize, &Candidates)) -> ThresholdParameters {
        let mut participants = BTreeMap::<AccountId, ParticipantInfoV2>::new();
        candidates
            .candidates
            .iter()
            .map(|(account, info)| participants.insert(account.clone(), info.into()));
        ThresholdParameters {
            participants,
            threshold: threshold as u64,
        }
    }
}
impl ThresholdParameters {
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }
    pub fn n_participants(&self) -> u64 {
        self.participants.len() as u64
    }
    pub fn participant_by_index(&self, idx: u64) -> Result<AccountId, Error> {
        match self.participants.iter().nth(idx as usize) {
            Some(p) => Ok(p.0.clone()),
            None => Err(InvalidState::ParticipantIndexOutOfRange.into()),
        }
    }
    pub fn participant_id(&self, account_id: &AccountId) -> Result<u64, Error> {
        for (idx, (key, _)) in self.participants.iter().enumerate() {
            if key == account_id {
                return Ok(idx as u64);
            }
        }
        Err(InvalidState::NotParticipant.into())
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize, Clone)]
pub struct KeyState {
    // maybe you want Vector and map to index?
    pub public_key: PublicKey,
    pub key_event_id: KeyEventId,
    pub threshold_parameters: ThresholdParameters,
}
// todo: probably a lot of this is not safe. test it or delete it and ensure migrate() is never
// called while in resharing
impl From<&ResharingContractState> for KeyState {
    fn from(state: &ResharingContractState) -> Self {
        KeyState {
            public_key: state.public_key.clone(),
            key_event_id: KeyEventId {
                epoch_id: state.old_epoch,
                start_block_id: 0,
                random_uid: 0,
                leader: "migration".parse().unwrap(),
            },
            threshold_parameters: ThresholdParameters::from((
                state.threshold,
                &state.old_participants,
            )),
        }
    }
}
impl From<&RunningContractState> for KeyState {
    fn from(state: &RunningContractState) -> Self {
        KeyState {
            public_key: state.public_key.clone(),
            key_event_id: KeyEventId {
                epoch_id: state.epoch,
                start_block_id: 0,
                random_uid: 0,
                leader: "migration".parse().unwrap(),
            },
            threshold_parameters: ThresholdParameters::from((state.threshold, &state.participants)),
        }
    }
}

impl From<(&KeyStateProposal, &PublicKey, &KeyEventId)> for KeyState {
    fn from(
        (proposal, public_key, key_event_id): (&KeyStateProposal, &PublicKey, &KeyEventId),
    ) -> Self {
        KeyState {
            public_key: public_key.clone(),
            key_event_id: key_event_id.clone(),
            threshold_parameters: proposal.proposed_threshold_parameters.clone(),
        }
    }
}
impl KeyState {
    pub fn participant_by_index(&self, idx: u64) -> Result<AccountId, Error> {
        self.threshold_parameters.participant_by_index(idx)
    }
    pub fn participant_id(&self, account_id: &AccountId) -> Result<u64, Error> {
        self.threshold_parameters.participant_id(account_id)
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
    pub fn threshold(&self) -> u64 {
        self.threshold_parameters.threshold
    }
    pub fn n_participants(&self) -> u64 {
        self.threshold_parameters.n_participants()
    }
    pub fn uid(&self) -> u64 {
        self.key_event_id.random_uid
    }
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
        &self.threshold_parameters.participants
    }
}

/// returns the seed%len(participants)-th in the participants set.
pub fn get_account_from_seed(seed: u64, participants: &BTreeSet<AccountId>) -> &AccountId {
    let leader_idx = seed % (participants.len() as u64);
    match participants.iter().nth(leader_idx as usize) {
        Some(account) => account,
        None => {
            env::panic_str("Index out of range. This should never happen");
        }
    }
}
const MIN_THRESHOLD_ABSOLUTE: u64 = 2;
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Clone,
)]
pub struct KeyStateProposal {
    pub proposed_threshold_parameters: ThresholdParameters,
    pub key_event_threshold: u64,
}
impl From<&ResharingContractState> for KeyStateProposal {
    fn from(state: &ResharingContractState) -> Self {
        KeyStateProposal {
            proposed_threshold_parameters: ThresholdParameters::from((
                state.threshold,
                &state.new_participants,
            )),
            key_event_threshold: state.threshold as u64,
        }
    }
}
impl From<&InitializingContractState> for KeyStateProposal {
    fn from(state: &InitializingContractState) -> KeyStateProposal {
        KeyStateProposal {
            proposed_threshold_parameters: ThresholdParameters::from((
                state.threshold,
                &state.candidates,
            )),
            key_event_threshold: state.threshold as u64,
        }
    }
}
impl KeyStateProposal {
    pub fn is_proposed(&self, account_id: &AccountId) -> bool {
        self.proposed_threshold_parameters
            .is_participant(account_id)
    }
    pub fn candidate_by_index(&self, idx: u64) -> Result<AccountId, Error> {
        self.proposed_threshold_parameters.participant_by_index(idx)
    }
    pub fn proposed_threshold(&self) -> u64 {
        self.proposed_threshold_parameters.threshold
    }
    pub fn n_proposed_participants(&self) -> u64 {
        self.proposed_threshold_parameters.n_participants()
    }
    pub fn proposed_participants(&self) -> &BTreeMap<AccountId, ParticipantInfoV2> {
        &self.proposed_threshold_parameters.participants
    }
    pub fn threshold_is_valid(&self) -> Result<(), Error> {
        let n = self.proposed_threshold_parameters.participants.len() as u64;
        let k = self.proposed_threshold_parameters.threshold;
        if k > n {
            return Err(InvalidThreshold::MaxRequirementFailed.into());
        }
        if k < MIN_THRESHOLD_ABSOLUTE {
            // todo: in a separate file?
            return Err(InvalidThreshold::MinAbsRequirementFailed.into());
        }
        let percentage_bound = (3 * n + 4) / 5; // minimum 60%
        if k < percentage_bound {
            return Err(InvalidThreshold::MinRelRequirementFailed.into());
        }
        let k_event = self.key_event_threshold;
        if k_event < k {
            return Err(InvalidThreshold::MinKeyEventFailed.into());
        }
        if k_event > n {
            return Err(InvalidThreshold::MaxKeyEventFailed.into());
        }
        return Ok(());
    }
}
#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum StorageKey {
    // for backwards compatibility, ensure the order is preserved and only append to this list
    PendingRequests,
    ProposedUpdatesEntries,
    RequestsByTimestamp,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[borsh(crate = "near_sdk::borsh")]
pub struct SignatureRequest {
    pub epsilon: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ContractSignatureRequest {
    pub request: SignatureRequest,
    pub requester: AccountId,
    pub deposit: NearToken,
    pub required_deposit: NearToken,
}

impl SignatureRequest {
    pub fn new(payload_hash: Scalar, predecessor_id: &AccountId, path: &str) -> Self {
        let epsilon = derive_epsilon(predecessor_id, path);
        let epsilon = SerializableScalar { scalar: epsilon };
        let payload_hash = SerializableScalar {
            scalar: payload_hash,
        };
        SignatureRequest {
            epsilon,
            payload_hash,
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct ParticipantInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

impl From<CandidateInfo> for ParticipantInfo {
    fn from(candidate_info: CandidateInfo) -> Self {
        ParticipantInfo {
            account_id: candidate_info.account_id,
            url: candidate_info.url,
            cipher_pk: candidate_info.cipher_pk,
            sign_pk: candidate_info.sign_pk,
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
)]
pub struct CandidateInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    pub next_id: u32,
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
    pub account_to_participant_id: HashMap<AccountId, u32>,
}

impl Default for Participants {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Candidates> for Participants {
    fn from(candidates: Candidates) -> Self {
        let mut participants = Participants::new();
        for (account_id, candidate_info) in candidates.iter() {
            participants.insert(account_id.clone(), candidate_info.clone().into());
        }
        participants
    }
}

impl Participants {
    pub fn new() -> Self {
        Participants {
            next_id: 0u32,
            participants: BTreeMap::new(),
            account_to_participant_id: HashMap::new(),
        }
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, participant_info: ParticipantInfo) {
        if !self.account_to_participant_id.contains_key(&account_id) {
            self.account_to_participant_id
                .insert(account_id.clone(), self.next_id);
            self.next_id += 1;
        }
        self.participants.insert(account_id, participant_info);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.participants.remove(account_id);
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &ParticipantInfo)> {
        self.participants.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &AccountId> {
        self.participants.keys()
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Candidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

impl Default for Candidates {
    fn default() -> Self {
        Self::new()
    }
}

impl Candidates {
    pub fn new() -> Self {
        Candidates {
            candidates: BTreeMap::new(),
        }
    }

    pub fn contains_key(&self, account_id: &AccountId) -> bool {
        self.candidates.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, candidate: CandidateInfo) {
        self.candidates.insert(account_id, candidate);
    }

    pub fn remove(&mut self, account_id: &AccountId) {
        self.candidates.remove(account_id);
    }

    pub fn get(&self, account_id: &AccountId) -> Option<&CandidateInfo> {
        self.candidates.get(account_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &CandidateInfo)> {
        self.candidates.iter()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct Votes {
    pub votes: BTreeMap<AccountId, HashSet<AccountId>>,
}

impl Default for Votes {
    fn default() -> Self {
        Self::new()
    }
}

impl Votes {
    pub fn new() -> Self {
        Votes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, account_id: AccountId) -> &mut HashSet<AccountId> {
        self.votes.entry(account_id).or_default()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, HashSet<AccountId>>,
}

impl Default for PkVotes {
    fn default() -> Self {
        Self::new()
    }
}

impl PkVotes {
    pub fn new() -> Self {
        PkVotes {
            votes: BTreeMap::new(),
        }
    }

    pub fn entry(&mut self, public_key: PublicKey) -> &mut HashSet<AccountId> {
        self.votes.entry(public_key).or_default()
    }
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignatureResult<T, E> {
    Ok(T),
    Err(E),
}

#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub enum SignaturePromiseError {
    Failed,
}
