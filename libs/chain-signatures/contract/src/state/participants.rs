use crate::primitives::hpke;
use near_sdk::{near, AccountId, PublicKey};
use std::collections::{BTreeMap, HashMap};

#[near(serializers=[borsh, json])]
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CandidateInfo {
    pub account_id: AccountId,
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

#[near(serializers=[borsh, json])]
#[derive(PartialEq, Eq, Debug, Clone)]
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

#[near(serializers=[borsh])]
#[derive(Debug, Clone)]
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

#[near(serializers=[borsh, json])]
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfoV2 {
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}
/* Migration helpers */
impl From<&CandidateInfo> for ParticipantInfoV2 {
    fn from(info: &CandidateInfo) -> ParticipantInfoV2 {
        ParticipantInfoV2 {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk,
            sign_pk: info.sign_pk.clone(),
        }
    }
}
impl From<&ParticipantInfo> for ParticipantInfoV2 {
    fn from(info: &ParticipantInfo) -> ParticipantInfoV2 {
        ParticipantInfoV2 {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk,
            sign_pk: info.sign_pk.clone(),
        }
    }
}
