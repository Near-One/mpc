use crate::errors::{Error, InvalidCandidateSet, InvalidParameters, InvalidState};
use near_sdk::{env, log, near, AccountId, PublicKey};
use std::collections::{BTreeMap, BTreeSet};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfo {
    pub url: String,
    /// The public key used for encrypting messages.
    pub cipher_pk: hpke::PublicKey,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
}

/* Migration helper */
impl From<&legacy_contract::primitives::ParticipantInfo> for ParticipantInfo {
    fn from(info: &legacy_contract::primitives::ParticipantInfo) -> ParticipantInfo {
        ParticipantInfo {
            url: info.url.clone(),
            cipher_pk: info.cipher_pk,
            sign_pk: info.sign_pk.clone(),
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthenticatedCandidateId(ParticipantId);
impl AuthenticatedCandidateId {
    pub fn get(&self) -> ParticipantId {
        self.0.clone()
    }
    pub fn new(candidates: &Participants) -> Result<Self, Error> {
        let signer = env::signer_account_id();
        let id = candidates.id(&signer)?;
        Ok(AuthenticatedCandidateId(id))
    }
}
//}
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantId(u32);
impl ParticipantId {
    pub fn get(&self) -> u32 {
        self.0
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Participants {
    next_id: ParticipantId,
    participants: BTreeMap<AccountId, ParticipantInfo>,
    id_by_participant: BTreeMap<AccountId, ParticipantId>,
    participant_by_id: BTreeMap<ParticipantId, AccountId>,
}

impl Default for Participants {
    fn default() -> Self {
        Self::new()
    }
}

impl Participants {
    pub fn new() -> Self {
        Participants {
            next_id: ParticipantId(0),
            participants: BTreeMap::new(),
            id_by_participant: BTreeMap::new(),
            participant_by_id: BTreeMap::new(),
        }
    }
    pub fn count(&self) -> u64 {
        self.participants.len() as u64
    }
    pub fn info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants.get(account_id)
    }
    pub fn id(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
        match self.id_by_participant.get(account_id) {
            Some(id) => Ok(id.clone()),
            None => Err(InvalidState::NotParticipant.into()),
        }
    }
    pub fn account_id(&self, id: &ParticipantId) -> Result<AccountId, Error> {
        match self.participant_by_id.get(id) {
            Some(p) => Ok(p.clone()),
            None => Err(InvalidState::ParticipantIndexOutOfRange.into()),
        }
    }
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants.contains_key(account_id)
    }
    pub fn insert_with_id(
        &mut self,
        account_id: AccountId,
        info: ParticipantInfo,
        id: ParticipantId,
    ) -> Result<(), Error> {
        if self.participants.contains_key(&account_id) {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }
        if id < self.next_id() {
            return Err(InvalidParameters::ParticipantAlreadyUsed.into());
        }
        self.participants.insert(account_id.clone(), info);
        self.participant_by_id
            .insert(id.clone(), account_id.clone());
        self.id_by_participant
            .insert(account_id.clone(), id.clone());
        self.next_id.0 = id.0 + 1;
        Ok(())
    }
    pub fn insert(&mut self, account_id: AccountId, info: ParticipantInfo) -> Result<(), Error> {
        self.insert_with_id(account_id, info, self.next_id.clone())
    }
    pub fn participants(&self) -> &BTreeMap<AccountId, ParticipantInfo> {
        &self.participants
    }
    pub fn ids(&self) -> BTreeSet<ParticipantId> {
        self.participants
            .keys()
            .map(|account_id| self.id(account_id).unwrap())
            .collect()
    }
    pub fn next_id(&self) -> ParticipantId {
        self.next_id.clone()
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.participant_by_id.len() != self.id_by_participant.len() {
            return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
        }
        for account_id in self.participants.keys() {
            let Some(id) = self.id_by_participant.get(account_id) else {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            };
            if self.next_id.get() <= id.get() {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            }
            let Some(participant) = self.participant_by_id.get(id) else {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            };
            if *participant != *account_id {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            };
        }
        Ok(())
    }
}

/* Migration helpers */
/// hopefully not required
fn migrate_inconsistent_participants(
    participants: legacy_contract::primitives::Participants,
) -> Participants {
    log!("migrating inconsistent participant state!");
    let mut migrated_participants = Participants::new();
    for (account_id, info) in &participants.participants {
        // if an error occurs here, there is no help.
        let _ = migrated_participants.insert(account_id.clone(), info.into());
    }
    migrated_participants
}

impl From<legacy_contract::primitives::Participants> for Participants {
    fn from(legacy_participants: legacy_contract::primitives::Participants) -> Participants {
        let mut participants: BTreeMap<AccountId, ParticipantInfo> = BTreeMap::new();
        let mut id_by_participant: BTreeMap<AccountId, ParticipantId> = BTreeMap::new();
        let mut participant_by_id: BTreeMap<ParticipantId, AccountId> = BTreeMap::new();
        let next_id = ParticipantId(legacy_participants.next_id);
        for (account_id, info) in &legacy_participants.participants {
            participants.insert(account_id.clone(), info.into());
            let id = legacy_participants
                .account_to_participant_id
                .get(account_id);
            if id.is_none() {
                return migrate_inconsistent_participants(legacy_participants);
            }

            let id = ParticipantId(*id.unwrap());
            if next_id.get() <= id.get() {
                return migrate_inconsistent_participants(legacy_participants);
            }
            if participant_by_id
                .insert(id.clone(), account_id.clone())
                .is_some()
            {
                return migrate_inconsistent_participants(legacy_participants);
            }
            if id_by_participant
                .insert(account_id.clone(), id.clone())
                .is_some()
            {
                return migrate_inconsistent_participants(legacy_participants);
            }
        }
        Participants {
            next_id: ParticipantId(legacy_participants.next_id),
            participants,
            id_by_participant,
            participant_by_id,
        }
    }
}

impl From<legacy_contract::primitives::Candidates> for Participants {
    fn from(candidates: legacy_contract::primitives::Candidates) -> Participants {
        let legacy_participants: legacy_contract::primitives::Participants = candidates.into();
        legacy_participants.into()
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeSet;

    use crate::primitives::participants::{ParticipantId, Participants};
    use crate::state::tests::test_utils::{
        gen_accounts_and_info, gen_legacy_candidates, gen_legacy_participants,
    };
    use rand::Rng;

    #[test]
    fn test_participants() {
        let n = rand::thread_rng().gen_range(1..800);
        let expected = gen_accounts_and_info(n);
        let mut participants = Participants::new();
        for (idx, (account_id, info)) in expected.iter().enumerate() {
            participants
                .insert(account_id.clone(), info.clone())
                .unwrap();
            assert_eq!(*participants.info(account_id).unwrap(), info.clone());
            assert_eq!(
                participants.account_id(&ParticipantId(idx as u32)).unwrap(),
                *account_id
            );
            assert_eq!(
                participants.id(account_id).unwrap(),
                ParticipantId(idx as u32)
            );
            assert!(participants.is_participant(account_id));
        }
        assert_eq!(participants.count(), n as u64);
        let expected: BTreeSet<ParticipantId> = (0..n).map(|i| ParticipantId(i as u32)).collect();
        assert_eq!(expected, participants.ids());
        assert!(participants.validate().is_ok());
    }

    pub fn assert_candidate_migration(
        legacy_candidates: &legacy_contract::primitives::Candidates,
        migrated_participants: &Participants,
    ) {
        assert_eq!(
            migrated_participants.count(),
            legacy_candidates.candidates.len() as u64
        );
        for (account_id, info) in &legacy_candidates.candidates {
            assert!(migrated_participants.is_participant(account_id));
            let mp_info = migrated_participants.info(account_id).unwrap();
            assert_eq!(mp_info.url, info.url);
            assert_eq!(mp_info.cipher_pk, info.cipher_pk);
            assert_eq!(mp_info.sign_pk, info.sign_pk);
            assert_eq!(
                *account_id,
                migrated_participants
                    .account_id(&migrated_participants.id(account_id).unwrap())
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_migration_candidates() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let candidates = gen_legacy_candidates(n);
        let mp: Participants = candidates.clone().into();
        assert_candidate_migration(&candidates, &mp);
        assert!(mp.validate().is_ok());
    }

    pub fn assert_participant_migration(
        legacy_participants: &legacy_contract::primitives::Participants,
        migrated_participants: &Participants,
    ) {
        assert_eq!(
            legacy_participants.participants.len() as u64,
            migrated_participants.count(),
        );
        assert_eq!(
            legacy_participants.next_id,
            migrated_participants.next_id().get(),
        );
        for (account_id, info) in migrated_participants.participants() {
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
                .unwrap();
            assert_eq!(
                migrated_participants.id(account_id).unwrap().get(),
                legacy_idx
            )
        }
    }

    #[test]
    fn test_migration_participants() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let legacy_participants = gen_legacy_participants(n);
        let participants: Participants = legacy_participants.clone().into();
        assert_participant_migration(&legacy_participants, &participants);
        assert!(participants.validate().is_ok());
    }
}
