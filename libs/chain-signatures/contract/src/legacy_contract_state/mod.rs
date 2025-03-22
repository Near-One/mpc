mod impls;

use std::collections::{BTreeMap, HashMap, HashSet};

use borsh::{self, BorshDeserialize, BorshSerialize};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, PrimeField},
    Scalar, U256,
};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    collections::LookupMap,
    store::{IterableMap, Vector},
    AccountId, CryptoHash, PublicKey,
};

pub mod hpke {
    pub type PublicKey = [u8; 32];
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
pub struct Candidates {
    pub candidates: BTreeMap<AccountId, CandidateInfo>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
pub struct Participants {
    pub next_id: u32,
    pub participants: BTreeMap<AccountId, ParticipantInfo>,
    pub account_to_participant_id: HashMap<AccountId, u32>,
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

impl Default for Participants {
    fn default() -> Self {
        Self::new()
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

impl Default for PkVotes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct PkVotes {
    pub votes: BTreeMap<PublicKey, HashSet<AccountId>>,
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

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct InitializingContractState {
    pub candidates: Candidates,
    pub threshold: usize,
    pub pk_votes: PkVotes,
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
pub struct RunningContractState {
    pub epoch: u64,
    pub participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub candidates: Candidates,
    pub join_votes: Votes,
    pub leave_votes: Votes,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub struct ResharingContractState {
    pub old_epoch: u64,
    pub old_participants: Participants,
    pub new_participants: Participants,
    pub threshold: usize,
    pub public_key: PublicKey,
    pub finished_votes: HashSet<AccountId>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug)]
pub enum ProtocolContractState {
    NotInitialized,
    Initializing(InitializingContractState),
    Running(RunningContractState),
    Resharing(ResharingContractState),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, PartialOrd, Ord)]
pub struct SerializableScalar {
    pub scalar: Scalar,
}

impl BorshSerialize for SerializableScalar {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_ser: [u8; 32] = self.scalar.to_bytes().into();
        BorshSerialize::serialize(&to_ser, writer)
    }
}

impl BorshDeserialize for SerializableScalar {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        let from_ser: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
        let scalar = Scalar::from_bytes(from_ser).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Scalar bytes are not in the k256 field",
        ))?;
        Ok(SerializableScalar { scalar })
    }
}

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    /// When the user can't directly select the value, this will always work
    /// Use cases are things that we know have been hashed
    fn from_non_biased(hash: [u8; 32]) -> Self {
        // This should never happen.
        // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
        // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
        Scalar::from_bytes(hash).expect("Derived tweak value falls outside of the field")
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct SignatureRequest {
    pub tweak: SerializableScalar,
    pub payload_hash: SerializableScalar,
}

/// The index into calling the YieldResume feature of NEAR. This will allow to resume
/// a yield call after the contract has been called back via this index.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[borsh(crate = "near_sdk::borsh")]
pub struct YieldIndex {
    pub data_id: CryptoHash,
}

#[derive(
    Copy,
    Clone,
    Default,
    Debug,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct UpdateId(pub(crate) u64);

/// Dynamic value is used to store any kind of value in the contract state. These values
/// can be deserialized on the fly to get the actual configurations, but the contract will
/// not be the ones directly utilizing these values unless they are concrete types.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicValue(serde_json::Value);

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct TripleConfig {
    /// Minimum amount of triples that is owned by each node.
    pub min_triples: u32,
    /// Maximum amount of triples that is in the whole network.
    pub max_triples: u32,
    /// Timeout for triple generation in milliseconds.
    pub generation_timeout: u64,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// Message timeout in milliseconds for any protocol message that gets sent over the wire.
    /// This can be overriden by more specific timeouts in each protocol.
    pub message_timeout: u64,
    /// Garbage collection timeout in milliseconds for any protocol message. This is the timeout
    /// used for when any protocols have either been spent or failed, their IDs are kept to keep
    /// track of the state of the protocol until this timeout reaches.
    pub garbage_timeout: u64,
    /// Maximum amount of concurrent protocol generation that can be introduced by this node.
    /// This only includes protocols that generate triples and presignatures.
    pub max_concurrent_introduction: u32,
    /// Maximum amount of concurrent protocol generation that can be done per node.
    /// This only includes protocols that generate triples and presignatures.
    pub max_concurrent_generation: u32,
    /// Configuration for triple generation.
    pub triple: TripleConfig,
    /// Configuration for presignature generation.
    pub presignature: PresignatureConfig,
    /// Configuration for signature generation.
    pub signature: SignatureConfig,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct PresignatureConfig {
    /// Minimum amount of presignatures that is owned by each node.
    pub min_presignatures: u32,
    /// Maximum amount of presignatures that is in the whole network.
    pub max_presignatures: u32,
    /// Timeout for presignature generation in milliseconds.
    pub generation_timeout: u64,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct SignatureConfig {
    /// Timeout for signature generation in milliseconds.
    pub generation_timeout: u64,
    /// Timeout for signature generation in milliseconds. This is the total timeout for
    /// the signature generation process. Mainly used to include the whole generation of
    /// signatures including their retries up till this timeout.
    pub generation_timeout_total: u64,
    /// Garbage collection timeout in milliseconds for signatures generated.
    pub garbage_timeout: u64,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[derive(
    Clone, Default, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq,
)]
pub struct Config {
    pub protocol: ProtocolConfig,

    /// The remaining entries that can be present in future forms of the configuration.
    #[serde(flatten)]
    pub other: HashMap<String, DynamicValue>,
}

#[allow(clippy::large_enum_variant)] // TODO: Config is big
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum Update {
    Config(Config),
    Contract(Vec<u8>),
    ConfigV1(ConfigV1),
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ConfigV1 {
    pub max_num_requests_to_remove: u32,
    pub request_timeout_blocks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct InitConfigV1 {
    pub max_num_requests_to_remove: Option<u32>,
    pub request_timeout_blocks: Option<u64>,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct UpdateEntry {
    updates: Vec<Update>,
    votes: HashSet<AccountId>,
    bytes_used: u128,
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct ProposedUpdates {
    entries: IterableMap<UpdateId, UpdateEntry>,
    id: UpdateId,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContractV1 {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    pub request_by_block_height: Vector<(u64, SignatureRequest)>,
    pub proposed_updates: ProposedUpdates,
    pub config: ConfigV1,
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContractV0;

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub enum VersionedMpcContract {
    V0(MpcContractV0),
    V1(MpcContractV1),
}
