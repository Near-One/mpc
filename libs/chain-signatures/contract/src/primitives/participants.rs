use crate::{
    errors::{Error, InvalidCandidateSet, InvalidParameters},
    legacy_contract_state,
};
use dcap_qvl::verify::{self, VerifiedReport};
use near_sdk::{log, near, AccountId, PublicKey};
use std::{
    collections::BTreeSet,
    fmt::{self, Display},
    time::SystemTime,
};

use super::tee::quote::get_collateral;

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[near(serializers=[borsh, json])]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfo {
    pub url: String,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
    /// TEE Remote Attestation Quote that proves the participant's identity.
    pub tee_quote: Vec<u8>,
    /// Supplemental data for the TEE quote, including Intel certificates to verify it came from
    /// genuine Intel hardware, along with details about the Trusted Computing Base (TCB)
    /// versioning, status, and other relevant info.
    pub quote_collateral: String,
}

/// We do not use #[derive(Debug)] for ParticipantInfo because TEE quote and collateral fields are
/// long and can cause HostError(TotalLogLengthExceeded { length: 120461, limit: 16384 }) errors.
impl fmt::Debug for ParticipantInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParticipantInfo")
            .field("url", &self.url)
            .field("sign_pk", &self.sign_pk)
            .finish()
    }
}

impl ParticipantInfo {
    pub fn verify_quote(&self) -> Result<VerifiedReport, Error> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get current time")
            .as_secs();
        let tee_collateral = get_collateral(self.quote_collateral.clone());
        let verification_result = verify::verify(&self.tee_quote, &tee_collateral, now);
        verification_result.map_err(|_| InvalidCandidateSet::InvalidParticipantsTeeQuote.into())
    }
}

/// Migration helper
impl From<&legacy_contract_state::ParticipantInfo> for ParticipantInfo {
    fn from(info: &legacy_contract_state::ParticipantInfo) -> ParticipantInfo {
        ParticipantInfo {
            url: info.url.clone(),
            sign_pk: info.sign_pk.clone(),
            tee_quote: vec![],
            quote_collateral: "".to_string(),
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantId(pub u32);
impl ParticipantId {
    pub fn get(&self) -> u32 {
        self.0
    }
    pub fn next(&self) -> Self {
        ParticipantId(self.0 + 1)
    }
}

impl Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Participants {
    next_id: ParticipantId,
    participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
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
            participants: Vec::new(),
        }
    }
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.participants.len()
    }
    pub fn insert_with_id(
        &mut self,
        account_id: AccountId,
        info: ParticipantInfo,
        id: ParticipantId,
    ) -> Result<(), Error> {
        if self
            .participants
            .iter()
            .any(|(a_id, p_id, _)| *a_id == account_id || *p_id == id)
        {
            return Err(InvalidParameters::ParticipantAlreadyInSet.into());
        }
        if id < self.next_id() {
            return Err(InvalidParameters::ParticipantAlreadyUsed.into());
        }
        self.participants
            .push((account_id.clone(), id.clone(), info));
        self.next_id.0 = id.0 + 1;
        Ok(())
    }
    pub fn insert(&mut self, account_id: AccountId, info: ParticipantInfo) -> Result<(), Error> {
        self.insert_with_id(account_id, info, self.next_id.clone())
    }
    pub fn participants(&self) -> &Vec<(AccountId, ParticipantId, ParticipantInfo)> {
        &self.participants
    }
    pub fn next_id(&self) -> ParticipantId {
        self.next_id.clone()
    }

    /// Validates that the fields are coherent:
    ///  - All participant IDs are unique.
    ///  - All account IDs are unique.
    ///  - The next_id is greater than all participant IDs.
    ///  - All participant TEE quotes are valid.
    pub fn validate(&self) -> Result<(), Error> {
        let mut ids: BTreeSet<ParticipantId> = BTreeSet::new();
        let mut accounts: BTreeSet<AccountId> = BTreeSet::new();
        for (acc_id, pid, pinfo) in &self.participants {
            accounts.insert(acc_id.clone());
            ids.insert(pid.clone());
            if self.next_id.get() <= pid.get() {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
            }
            if pinfo.verify_quote().is_err() {
                return Err(InvalidCandidateSet::InvalidParticipantsTeeQuote.into());
            }
        }
        if ids.len() != self.len() {
            return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
        }
        if accounts.len() != self.len() {
            return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Participants {
    pub fn init(
        next_id: ParticipantId,
        participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
    ) -> Self {
        Self {
            next_id,
            participants,
        }
    }

    pub fn id(&self, account_id: &AccountId) -> Result<ParticipantId, Error> {
        self.participants
            .iter()
            .find(|(a_id, _, _)| a_id == account_id)
            .map(|(_, p_id, _)| p_id.clone())
            .ok_or_else(|| crate::errors::InvalidState::NotParticipant.into())
    }
    pub fn info(&self, account_id: &AccountId) -> Option<&ParticipantInfo> {
        self.participants
            .iter()
            .find(|(a_id, _, _)| a_id == account_id)
            .map(|(_, _, info)| info)
    }
    pub fn account_id(&self, id: &ParticipantId) -> Result<AccountId, Error> {
        self.participants
            .iter()
            .find(|(_, p_id, _)| p_id == id)
            .map(|(a_id, _, _)| a_id.clone())
            .ok_or_else(|| crate::errors::InvalidState::ParticipantIndexOutOfRange.into())
    }
    pub fn is_participant(&self, account_id: &AccountId) -> bool {
        self.participants
            .iter()
            .any(|(a_id, _, _)| a_id == account_id)
    }
    /// Returns a subset of the participants according to the given range of indices.
    pub fn subset(&self, range: std::ops::Range<usize>) -> Participants {
        let participants = self.participants[range]
            .iter()
            .map(|(a, p, i)| (a.clone(), p.clone(), i.clone()));
        Participants {
            next_id: self.next_id.clone(),
            participants: participants.collect(),
        }
    }
    pub fn add_random_participants_till_n(&mut self, n: usize) {
        let mut rng = rand::thread_rng();
        while self.len() < n {
            let (account, pinfo) =
                crate::primitives::test_utils::gen_participant(rand::Rng::gen(&mut rng));
            self.insert(account, pinfo).unwrap();
        }
    }
    pub fn remove(&mut self, account: &AccountId) {
        if let Some(pos) = self
            .participants
            .iter()
            .position(|(a_id, _, _)| a_id == account)
        {
            self.participants.remove(pos);
        }
    }
}

/// Migration helpers - hopefully not required
fn migrate_inconsistent_participants(
    participants: legacy_contract_state::Participants,
) -> Participants {
    log!("migrating inconsistent participant state!");
    let mut migrated_participants = Participants::new();
    for (account_id, info) in &participants.participants {
        // if an error occurs here, there is no help.
        let _ = migrated_participants.insert(account_id.clone(), info.into());
    }
    migrated_participants
}

impl From<legacy_contract_state::Participants> for Participants {
    fn from(legacy_participants: legacy_contract_state::Participants) -> Participants {
        let mut participants: Vec<(AccountId, ParticipantId, ParticipantInfo)> = Vec::new();
        let mut ids: BTreeSet<ParticipantId> = BTreeSet::new();
        let next_id = ParticipantId(legacy_participants.next_id);
        for (account_id, info) in &legacy_participants.participants {
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
            if !ids.insert(id.clone()) {
                return migrate_inconsistent_participants(legacy_participants);
            }

            participants.push((account_id.clone(), id.clone(), info.into()));
        }
        Participants {
            next_id: ParticipantId(legacy_participants.next_id),
            participants,
        }
    }
}

impl From<legacy_contract_state::Candidates> for Participants {
    fn from(candidates: legacy_contract_state::Candidates) -> Participants {
        let legacy_participants: legacy_contract_state::Participants = candidates.into();
        legacy_participants.into()
    }
}

#[cfg(test)]
pub mod tests {
    use crate::legacy_contract_state;
    use crate::primitives::{
        participants::{ParticipantId, Participants},
        test_utils::{gen_accounts_and_info, gen_legacy_candidates, gen_legacy_participants},
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
        assert_eq!(participants.len(), n);
        for i in 0..n {
            assert!(participants.account_id(&ParticipantId(i as u32)).is_ok());
        }
        assert!(participants.validate().is_ok());
    }

    pub fn assert_candidate_migration(
        legacy_candidates: &legacy_contract_state::Candidates,
        migrated_participants: &Participants,
    ) {
        assert_eq!(
            migrated_participants.len(),
            legacy_candidates.candidates.len()
        );
        for (account_id, info) in &legacy_candidates.candidates {
            assert!(migrated_participants.is_participant(account_id));
            let mp_info = migrated_participants.info(account_id).unwrap();
            assert_eq!(mp_info.url, info.url);
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
    #[should_panic(expected = "Invalid quote collateral JSON")]
    fn test_migration_candidates() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let candidates = gen_legacy_candidates(n);
        let mp: Participants = candidates.clone().into();
        assert_candidate_migration(&candidates, &mp);
        // Validation is expected to panic since legacy candidates do not have a notion of TEE quote
        // collateral, so the new participants have it empty
        let _ = mp.validate();
    }

    pub fn assert_participant_migration(
        legacy_participants: &legacy_contract_state::Participants,
        migrated_participants: &Participants,
    ) {
        assert_eq!(
            legacy_participants.participants.len(),
            migrated_participants.len(),
        );
        assert_eq!(
            legacy_participants.next_id,
            migrated_participants.next_id().get(),
        );
        for (account_id, _, info) in migrated_participants.participants() {
            let legacy_participant = legacy_participants.get(account_id);
            assert!(legacy_participant.is_some());
            let legacy_participant = legacy_participant.unwrap();
            assert_eq!(legacy_participant.account_id, *account_id);
            assert_eq!(legacy_participant.url, info.url);
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
    #[should_panic(expected = "Invalid quote collateral JSON")]
    fn test_migration_participants() {
        let n: usize = rand::thread_rng().gen_range(2..600);
        let legacy_participants = gen_legacy_participants(n);
        let participants: Participants = legacy_participants.clone().into();
        assert_participant_migration(&legacy_participants, &participants);
        // Validation is expected to panic since legacy candidates do not have a notion of TEE quote
        // collateral, so the new participants have it empty
        let _ = participants.validate();
    }
}
