use crate::errors::{Error, InvalidCandidateSet, InvalidParameters};
use near_sdk::{near, AccountId, PublicKey};
use std::{collections::BTreeSet, fmt::Display};

pub mod hpke {
    pub type PublicKey = [u8; 32];
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ParticipantInfo {
    pub url: String,
    /// The public key used for verifying messages.
    pub sign_pk: PublicKey,
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
    pub fn validate(&self) -> Result<(), Error> {
        let mut ids: BTreeSet<ParticipantId> = BTreeSet::new();
        let mut accounts: BTreeSet<AccountId> = BTreeSet::new();
        for (acc_id, pid, _) in &self.participants {
            accounts.insert(acc_id.clone());
            ids.insert(pid.clone());
            if self.next_id.get() <= pid.get() {
                return Err(InvalidCandidateSet::IncoherentParticipantIds.into());
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
    pub fn init(
        next_id: ParticipantId,
        participants: Vec<(AccountId, ParticipantId, ParticipantInfo)>,
    ) -> Self {
        Self {
            next_id,
            participants,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Participants {
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

#[cfg(test)]
pub mod tests {
    use crate::primitives::{
        participants::{ParticipantId, Participants},
        test_utils::gen_accounts_and_info,
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
}
