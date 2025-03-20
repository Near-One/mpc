pub mod gcp;
pub mod local;

use cait_sith::KeygenOutput;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_contract::primitives::{
    domain::DomainId,
    key_state::{AttemptId, EpochId, KeyEventId},
};
use serde::{Deserialize, Serialize};

use crate::indexer::participants::ContractKeyset;
#[derive(Clone, Serialize, Deserialize)]
pub struct Secp256k1Data {
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}
#[derive(Clone, Serialize, Deserialize)]
pub enum KeyShareData {
    Secp256k1(Secp256k1Data),
}

// The keystore is a mess right now, because changes will depend on PR #278.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub key_id: KeyEventId,
    pub data: KeyShareData,
}
impl KeyShare {
    //pub fn domain_id(&self) -> DomainId {
    //    self.key_id.domain_id
    //}
    pub fn epoch_id(&self) -> EpochId {
        self.key_id.epoch_id
    }
    pub fn attempt_id(&self) -> AttemptId {
        self.key_id.attempt_id
    }
    pub fn keygen_output(&self) -> KeygenOutput<Secp256k1> {
        KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        }
    }
    pub fn new(key_id: KeyEventId, keygen_output: KeygenOutput<Secp256k1>) -> Self {
        Self {
            key_id,
            private_share: keygen_output.private_share,
            public_key: keygen_output.public_key,
        }
    }
}
pub fn migrate_root_key_share_data(root_keyshare: RootKeyshareData) -> KeyShare {
    KeyShare {
        key_id: KeyEventId::new(
            EpochId::new(root_keyshare.epoch),
            DomainId::legacy_ecdsa_id(),
            AttemptId::legacy_attempt_id(),
        ),
        private_share: root_keyshare.private_share,
        public_key: root_keyshare.public_key,
    }
}
/// The root keyshare data along with an epoch. The epoch is incremented
/// for each key resharing. This is the format stored in the old MPC
/// implementation, and we're keeping it the same to ease migration.
/// Deprecated
#[derive(Clone, Serialize, Deserialize)]
pub struct RootKeyshareData {
    pub epoch: u64,
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}
#[cfg(test)]
impl RootKeyshareData {
    //pub fn keygen_output(&self) -> KeygenOutput<Secp256k1> {
    //    KeygenOutput {
    //        private_share: self.private_share,
    //        public_key: self.public_key,
    //    }
    //}

    pub fn new(epoch: u64, keygen_output: KeygenOutput<Secp256k1>) -> Self {
        Self {
            epoch,
            private_share: keygen_output.private_share,
            public_key: keygen_output.public_key,
        }
    }
}

/// Abstracts away the storage of the root keyshare data.
#[async_trait::async_trait]
pub trait KeyshareStorage: Send {
    /// Loads the most recent root keyshare data. Returns an error if the data
    /// cannot be read. Returns Ok(None) if the data does not exist (i.e. we've
    /// never participated successfully in a key generation).
    /// todo: add epoch_id as argument?
    async fn load(&self) -> anyhow::Result<Option<KeyShare>>;

    /// Stores the most recent root keyshare data. This can only succeed if the
    /// keyshare didn't exist before or if the new data has a higher epoch.
    async fn store(&self, key_share: &KeyShare) -> anyhow::Result<()>;

    async fn load_keyset(&self, keyset: &ContractKeyset) -> anyhow::Result<Vec<KeyShare>>;
}

/// Factory to construct a KeyshareStorage implementation.
pub enum KeyshareStorageFactory {
    Gcp {
        project_id: String,
        secret_id: String,
    },
    Local {
        home_dir: std::path::PathBuf,
        encryption_key: [u8; 16],
    },
}

impl KeyshareStorageFactory {
    pub async fn create(&self) -> anyhow::Result<Box<dyn KeyshareStorage>> {
        match self {
            Self::Gcp {
                project_id,
                secret_id,
            } => {
                let storage =
                    gcp::GcpKeyshareStorage::new(project_id.clone(), secret_id.clone()).await?;
                Ok(Box::new(storage))
            }
            Self::Local {
                home_dir,
                encryption_key,
            } => {
                let storage = local::LocalKeyshareStorage::new(home_dir.clone(), *encryption_key);
                Ok(Box::new(storage))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use mpc_contract::primitives::key_state::AttemptId;
    use rand::Rng;

    use crate::{
        keyshare::{migrate_root_key_share_data, RootKeyshareData},
        tests::TestGenerators,
    };

    #[test]
    fn test_migration() {
        let generated_key = TestGenerators::new(2, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;
        let epoch_id = rand::thread_rng().gen();
        let expected = RootKeyshareData::new(epoch_id, generated_key.clone());
        let migrated = migrate_root_key_share_data(expected.clone());
        assert_eq!(migrated.attempt_id(), AttemptId::legacy_attempt_id());
        assert_eq!(migrated.epoch_id().get(), epoch_id);
        assert_eq!(migrated.private_share, expected.private_share);
        assert_eq!(migrated.public_key, expected.public_key);
    }
}
