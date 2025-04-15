use super::Keyshare;
use anyhow::Context;
use k256::{AffinePoint, Scalar};
use mpc_contract::primitives::key_state::EpochId;
use serde::{Deserialize, Serialize};

/// The single object we persist to permanent key storage.
/// Corresponds to a Keyset in the contract side (i.e. one keyshare per domain).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermanentKeyshareData {
    pub epoch_id: EpochId,
    /// These keyshares are in the exact same order as the domains in the Keyset.
    pub keyshares: Vec<Keyshare>,
}

impl PermanentKeyshareData {
    pub fn from_legacy(legacy: &LegacyRootKeyshareData) -> Self {
        Self {
            epoch_id: EpochId::new(legacy.epoch),
            keyshares: vec![Keyshare::from_legacy(legacy)],
        }
    }
}

/// Backend for storing the permanent keyshare data.
#[async_trait::async_trait]
pub trait PermanentKeyStorageBackend: Send + Sync + std::fmt::Debug {
    /// Loads the latest stored data; or None if no data was ever stored.
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>>;
    /// Stores the data, making it the latest. The identifier is used for the local backend to write
    /// the data to a separate file and then linking it to the main file (acting as a backup
    /// mechanism).
    async fn store(&self, data: &[u8], identifier: &str) -> anyhow::Result<()>;
}

/// Manages permanent keyshares. These are the keyshares we see from the Running state.
/// When we generate or reshare a key, that key goes into temporary key storage first,
/// and only when we transition to Running do we move it to permanent key storage.
#[derive(Debug)]
pub struct PermanentKeyStorage {
    backend: Box<dyn PermanentKeyStorageBackend>,
}

impl PermanentKeyStorage {
    pub async fn new(backend: Box<dyn PermanentKeyStorageBackend>) -> anyhow::Result<Self> {
        let ret = Self { backend };

        // Migrate legacy data if necessary.
        let existing_data = ret.backend.load().await?;
        if let Some(data) = existing_data {
            if serde_json::from_slice::<PermanentKeyshareData>(&data).is_err() {
                tracing::info!("Existing permanent keyshare data is not in the expected format, attempting to migrate...");
                let legacy_data = serde_json::from_slice::<LegacyRootKeyshareData>(&data)?;
                let new_data = PermanentKeyshareData::from_legacy(&legacy_data);
                ret.store_unchecked(&new_data).await?;
            }
        }
        Ok(ret)
    }

    pub async fn load(&self) -> anyhow::Result<Option<PermanentKeyshareData>> {
        let data = self.backend.load().await?;
        Ok(data.map(|data| serde_json::from_slice(&data)).transpose()?)
    }

    pub async fn store(&self, keyshare_data: &PermanentKeyshareData) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            if existing.epoch_id.get() > keyshare_data.epoch_id.get() {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing permanent keyshare of epoch {} with new permanent keyshare of older epoch {}",
                    existing.epoch_id.get(),
                    keyshare_data.epoch_id.get(),
                ));
            } else if existing.epoch_id.get() == keyshare_data.epoch_id.get()
                && existing.keyshares.len() >= keyshare_data.keyshares.len()
            {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing permanent keyshare of epoch {} with new permanent keyshare of same epoch but equal or fewer domains",
                    existing.epoch_id.get(),
                ));
            }
        }

        self.store_unchecked(keyshare_data).await
    }

    async fn store_unchecked(&self, keyshare_data: &PermanentKeyshareData) -> anyhow::Result<()> {
        let data_json = serde_json::to_vec(keyshare_data)?;
        let identifier = format!(
            "epoch_{}_with_{}_domains",
            keyshare_data.epoch_id.get(),
            keyshare_data.keyshares.len()
        );
        self.backend.store(&data_json, &identifier).await
    }
}

/// Old version of the permanent keyshare data, for migration only.
#[derive(Clone, Serialize, Deserialize)]
pub struct LegacyRootKeyshareData {
    pub epoch: u64,
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

#[cfg(test)]
mod tests {
    use super::PermanentKeyshareData;
    use crate::keyshare::local::LocalPermanentKeyStorageBackend;
    use crate::keyshare::permanent::{
        LegacyRootKeyshareData, PermanentKeyStorage, PermanentKeyStorageBackend,
    };
    use crate::keyshare::test_utils::{generate_dummy_keyshare, KeysetBuilder};
    use crate::keyshare::KeyshareData;
    use cait_sith::frost_secp256k1::keys::SigningShare;
    use cait_sith::frost_secp256k1::VerifyingKey;
    use k256::elliptic_curve::Field;
    use k256::{AffinePoint, Scalar};
    use mpc_contract::primitives::key_state::EpochId;

    #[tokio::test]
    async fn test_load_store() {
        let temp = tempfile::tempdir().unwrap();
        let encryption_key = [2; 16];
        let backend =
            LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), encryption_key)
                .await
                .unwrap();
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();
        assert!(storage.load().await.unwrap().is_none());

        let keys = vec![
            generate_dummy_keyshare(1, 0, 1),
            generate_dummy_keyshare(1, 2, 4),
        ];
        let permanent_keyshare = PermanentKeyshareData {
            epoch_id: EpochId::new(1),
            keyshares: keys.clone(),
        };

        storage.store(&permanent_keyshare).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded, permanent_keyshare);

        // Cannot store the same permanent keyshare twice.
        assert!(storage.store(&permanent_keyshare).await.is_err());
        // Cannot store current epoch with fewer domains.
        let keys = vec![generate_dummy_keyshare(1, 0, 1)];
        let permanent_keyshare = KeysetBuilder::from_keyshares(1, &keys).permanent_key_data();
        assert!(storage.store(&permanent_keyshare).await.is_err());
        // Cannot store older epoch than current.
        let keys = vec![
            generate_dummy_keyshare(0, 0, 1),
            generate_dummy_keyshare(0, 2, 2),
        ];
        let permanent_keyshare = KeysetBuilder::from_keyshares(0, &keys).permanent_key_data();
        assert!(storage.store(&permanent_keyshare).await.is_err());

        // Can store newer epoch than current.
        let keys = vec![
            generate_dummy_keyshare(2, 0, 1),
            generate_dummy_keyshare(2, 2, 2),
        ];
        let permanent_keyshare = KeysetBuilder::from_keyshares(2, &keys).permanent_key_data();
        storage.store(&permanent_keyshare).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded, permanent_keyshare);

        // Can store current epoch with more domains.
        let keys = vec![
            generate_dummy_keyshare(2, 0, 1),
            generate_dummy_keyshare(2, 2, 2),
            generate_dummy_keyshare(2, 3, 5),
        ];
        let permanent_keyshare = KeysetBuilder::from_keyshares(2, &keys).permanent_key_data();
        storage.store(&permanent_keyshare).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded, permanent_keyshare);
    }

    #[tokio::test]
    async fn test_legacy_migration() {
        let temp = tempfile::tempdir().unwrap();
        let encryption_key = [2; 16];
        let backend =
            LocalPermanentKeyStorageBackend::new(temp.path().to_path_buf(), encryption_key)
                .await
                .unwrap();
        // Write a legacy keyshare.
        let private_share = Scalar::random(&mut rand::thread_rng());
        let public_key = AffinePoint::GENERATOR * private_share;
        let legacy_data = LegacyRootKeyshareData {
            epoch: 1,
            private_share,
            // Do some computation to get non-identity public key
            public_key: public_key.to_affine(),
        };
        let legacy_data_json = serde_json::to_vec(&legacy_data).unwrap();
        let identifier = "whatever";
        backend.store(&legacy_data_json, identifier).await.unwrap();

        // Make the storage. The storage should upgrade the legacy keyshare to the new format.
        let storage = PermanentKeyStorage::new(Box::new(backend)).await.unwrap();
        let loaded = storage.load().await.unwrap().unwrap();
        assert_eq!(loaded.epoch_id.get(), 1);
        assert_eq!(loaded.keyshares.len(), 1);
        assert_eq!(loaded.keyshares[0].key_id.epoch_id.get(), 1);
        assert_eq!(loaded.keyshares[0].key_id.domain_id.0, 0);
        assert_eq!(loaded.keyshares[0].key_id.attempt_id.get(), 0);
        assert_eq!(
            loaded.keyshares[0].data,
            KeyshareData::Secp256k1(cait_sith::ecdsa::KeygenOutput {
                private_share: SigningShare::new(legacy_data.private_share),
                public_key: VerifyingKey::new(legacy_data.public_key.into()),
            })
        );
    }
}
