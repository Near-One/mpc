use super::domain::DomainId;
use super::participants::{ParticipantId, Participants};
use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::{DomainError, Error, InvalidState};
use near_sdk::{env, near, AccountId};
use std::fmt::Display;

/// An EpochId uniquely identifies a ThresholdParameters (but not vice-versa).
/// Every time we change the ThresholdParameters (participants and threshold),
/// we increment EpochId.
/// Locally on each node, each keyshare is uniquely identified by the tuple
/// (EpochId, DomainId, AttemptId).
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct EpochId(u64);

impl EpochId {
    pub fn next(&self) -> Self {
        EpochId(self.0 + 1)
    }
    pub fn new(epoch_id: u64) -> Self {
        EpochId(epoch_id)
    }
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Display for EpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct AttemptId(u64);

impl AttemptId {
    pub fn new() -> Self {
        AttemptId(0)
    }
    pub fn next(&self) -> Self {
        AttemptId(&self.0 + 1)
    }
    pub fn get(&self) -> u64 {
        self.0
    }
    pub fn legacy_attempt_id() -> Self {
        AttemptId(0)
    }
}

impl Default for AttemptId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for AttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A unique identifier for a key event (generation or resharing):
/// `epoch_id`: identifies the ThresholdParameters that this key is intended to function in.
/// `domain_id`: the domain this key is intended for.
/// `attempt_id`: identifies a particular attempt for this key event, in case multiple attempts
///               yielded partially valid results. This is incremented for each attempt within the
///               same epoch and domain.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct KeyEventId {
    pub epoch_id: EpochId,
    pub domain_id: DomainId,
    pub attempt_id: AttemptId,
}

impl KeyEventId {
    pub fn new(epoch_id: EpochId, domain_id: DomainId, attempt_id: AttemptId) -> Self {
        KeyEventId {
            epoch_id,
            domain_id,
            attempt_id,
        }
    }

    #[cfg(test)]
    pub fn next_attempt(&self) -> Self {
        KeyEventId {
            epoch_id: self.epoch_id,
            domain_id: self.domain_id,
            attempt_id: self.attempt_id.next(),
        }
    }
}

/// The identification of a specific distributed key, based on which a node would know exactly what
/// keyshare it has corresponds to this distributed key. (A distributed key refers to a specific set
/// of keyshares that nodes have which can be pieced together to form the secret key.)
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyForDomain {
    /// Identifies the domain this key is intended for.
    pub domain_id: DomainId,
    /// Identifies the public key. Although technically redundant given that we have the AttemptId,
    /// we keep it here in the contract so that it can be verified against and queried.
    pub key: PublicKeyExtended,
    /// The attempt ID that generated (initially or as a result of resharing) this distributed key.
    /// Nodes may have made multiple attempts to generate the distributed key, and this uniquely
    /// identifies which one should ultimately be used.
    pub attempt: AttemptId,
}

/// Represents a key for every domain in a specific epoch.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Keyset {
    pub epoch_id: EpochId,
    pub domains: Vec<KeyForDomain>,
}

impl Keyset {
    pub fn new(epoch_id: EpochId, domains: Vec<KeyForDomain>) -> Self {
        Keyset { epoch_id, domains }
    }

    pub fn public_key(&self, domain_id: DomainId) -> Result<PublicKeyExtended, Error> {
        Ok(self
            .domains
            .iter()
            .find(|k| k.domain_id == domain_id)
            .ok_or(DomainError::NoSuchDomain)?
            .key
            .clone())
    }
}
/// This struct is supposed to contain the participant id associated to the account `env::signer_account_id()`,
/// but is only constructible given a set of participants that includes the signer, thus acting as
/// a typesystem-based enforcement mechanism (albeit a best-effort one) for authenticating the
/// signer.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthenticatedParticipantId(ParticipantId);
impl AuthenticatedParticipantId {
    pub fn get(&self) -> ParticipantId {
        self.0.clone()
    }
    pub fn new(participants: &Participants) -> Result<Self, Error> {
        let signer = env::signer_account_id();
        participants
            .participants()
            .iter()
            .find(|(a_id, _, _)| *a_id == signer)
            .map(|(_, p_id, _)| AuthenticatedParticipantId(p_id.clone()))
            .ok_or_else(|| InvalidState::NotParticipant.into())
    }
}

/// This struct contains the account `env::signer_account_id()`, but is only constructible given a
/// set of participants that include the signer, thus acting as a typesystem-based enforcement
/// mechanism (albeit a best-effort one) for authenticating the signer.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthenticatedAccountId(AccountId);
impl AuthenticatedAccountId {
    pub fn get(&self) -> &AccountId {
        &self.0
    }
    pub fn new(participants: &Participants) -> Result<Self, Error> {
        let signer = env::signer_account_id();
        if participants
            .participants()
            .iter()
            .any(|(a_id, _, _)| *a_id == signer)
        {
            Ok(AuthenticatedAccountId(signer))
        } else {
            Err(InvalidState::NotParticipant.into())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::primitives::{
        domain::DomainId,
        key_state::{
            AttemptId, AuthenticatedAccountId, AuthenticatedParticipantId, EpochId, KeyForDomain,
            Keyset,
        },
        test_utils::{bogus_ed25519_public_key_extended, gen_account_id, gen_threshold_params},
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env};
    use rand::Rng;

    const MAX_N: usize = 900;

    #[test]
    fn test_epoch_id() {
        let id = rand::thread_rng().gen();
        let epoch_id = EpochId::new(id);
        assert_eq!(epoch_id.get(), id);
        assert_eq!(epoch_id.next().get(), id + 1);
    }

    #[test]
    fn test_attempt_id() {
        let attempt_id = AttemptId::new();
        assert_eq!(attempt_id.get(), 0);
        assert_eq!(attempt_id.next().get(), 1);
    }

    #[test]
    fn test_keyset() {
        let domain_id0 = DomainId(0);
        let domain_id1 = DomainId(3);
        let key0 = bogus_ed25519_public_key_extended();
        let key1 = bogus_ed25519_public_key_extended();
        let keyset = Keyset::new(
            EpochId::new(5),
            vec![
                KeyForDomain {
                    domain_id: domain_id0,
                    key: key0.clone(),
                    attempt: AttemptId::new(),
                },
                KeyForDomain {
                    domain_id: domain_id1,
                    key: key1.clone(),
                    attempt: AttemptId::new(),
                },
            ],
        );
        assert_eq!(keyset.public_key(domain_id0).unwrap(), key0);
        assert_eq!(keyset.public_key(domain_id1).unwrap(), key1);
        assert!(keyset.public_key(DomainId(1)).is_err());
    }

    #[test]
    fn test_authenticated_participant_id() {
        let proposed_parameters = gen_threshold_params(MAX_N);
        assert!(proposed_parameters.validate().is_ok());
        for (account_id, _, _) in proposed_parameters.participants().participants() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            testing_env!(context.build());
            assert!(AuthenticatedParticipantId::new(proposed_parameters.participants()).is_ok());
            let mut context = VMContextBuilder::new();
            context.signer_account_id(gen_account_id());
            testing_env!(context.build());
            assert!(AuthenticatedParticipantId::new(proposed_parameters.participants()).is_err());
        }
    }

    #[test]
    fn test_authenticated_account_id() {
        let proposed_parameters = gen_threshold_params(MAX_N);
        assert!(proposed_parameters.validate().is_ok());
        for (account_id, _, _) in proposed_parameters.participants().participants() {
            let mut context = VMContextBuilder::new();
            context.signer_account_id(account_id.clone());
            testing_env!(context.build());
            assert!(AuthenticatedAccountId::new(proposed_parameters.participants()).is_ok());
            let mut context = VMContextBuilder::new();
            context.signer_account_id(gen_account_id());
            testing_env!(context.build());
            assert!(AuthenticatedAccountId::new(proposed_parameters.participants()).is_err());
        }
    }
}
