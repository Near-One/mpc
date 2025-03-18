use super::{migrate_root_key_share_data, KeyShare, KeyshareStorage, RootKeyshareData};
use crate::db;
use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::Context;
use sha3::digest::generic_array::GenericArray;
use std::path::PathBuf;

/// Stores the root keyshare in a local encrypted file.
pub struct LocalKeyshareStorage {
    home_dir: PathBuf,
    encryption_key: [u8; 16],
}

impl LocalKeyshareStorage {
    pub fn new(home_dir: PathBuf, key: [u8; 16]) -> Self {
        Self {
            home_dir,
            encryption_key: key,
        }
    }
}

#[async_trait::async_trait]
impl KeyshareStorage for LocalKeyshareStorage {
    async fn load(&self) -> anyhow::Result<Option<KeyShare>> {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.encryption_key));
        let keyfile = self.home_dir.join("key");
        if !keyfile.exists() {
            return Ok(None);
        }
        let data = tokio::fs::read(keyfile)
            .await
            .context("Failed to read keygen file")?;
        let decrypted = db::decrypt(&cipher, &data).context("Failed to decrypt keygen")?;

        if let Ok(keyshare) =
            serde_json::from_slice::<RootKeyshareData>(&decrypted).context("Failed to parse keygen")
        {
            Ok(Some(migrate_root_key_share_data(keyshare)))
        } else if let Ok(keyshare) = serde_json::from_slice::<KeyShare>(&decrypted) {
            Ok(Some(keyshare))
        } else {
            anyhow::bail!("Failed to pare keygen")
        }
    }

    async fn store(&self, key_share: &KeyShare) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            if existing.epoch_id().get() > key_share.epoch_id().get()
                || (existing.epoch_id() == key_share.epoch_id()
                    && existing.attempt_id().get() >= key_share.attempt_id().get())
            {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing keyshare of id {:?} with new keyshare of older id {:?}",
                    existing.key_id,
                    key_share.key_id,
                ));
            }
        }
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.encryption_key));
        let data = serde_json::to_vec(&key_share).context("Failed to serialize keygen")?;
        let encrypted = db::encrypt(&cipher, &data);
        // Write the new key to a separate file, and then create a link to it.
        // That way there is no risk of corrupting the previous keyshare if the write is interrupted.
        let keyfile_for_epoch = self.home_dir.join(format!(
            "key_{:?}_{:?}",
            key_share.epoch_id(),
            key_share.attempt_id()
        ));
        tokio::fs::write(&keyfile_for_epoch, &encrypted)
            .await
            .context("Failed to write keygen file")?;
        let keyfile = self.home_dir.join("key");
        tokio::fs::remove_file(&keyfile).await.ok();
        tokio::fs::hard_link(&keyfile_for_epoch, &keyfile)
            .await
            .context("Failed to link keygen file")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mpc_contract::primitives::domain::DomainId;
    use mpc_contract::primitives::key_state::{AttemptId, EpochId, KeyEventId};

    use crate::keyshare::local::LocalKeyshareStorage;
    use crate::keyshare::{KeyShare, KeyshareStorage};
    use crate::tests::TestGenerators;

    #[tokio::test]
    async fn test_local_keyshare_storage() {
        let dir = tempfile::tempdir().unwrap();
        let encryption_key = [1; 16];
        let generated_key = TestGenerators::new(2, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;
        let attempt_0 = AttemptId::new();
        let key_event_id = KeyEventId::new(
            EpochId::new(1),
            DomainId::legacy_ecdsa_id(),
            attempt_0.next(),
        );

        let storage = LocalKeyshareStorage::new(dir.path().to_path_buf(), encryption_key);
        assert!(storage.load().await.unwrap().is_none());
        storage
            .store(&KeyShare::new(key_event_id.clone(), generated_key.clone()))
            .await
            .unwrap();
        let loaded_key = storage.load().await.unwrap().unwrap();
        assert_eq!(generated_key.private_share, loaded_key.private_share);
        assert_eq!(generated_key.public_key, loaded_key.public_key);

        let generated_key_2 = TestGenerators::new(3, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;
        // Can't store if attempt is lower:
        let key_event_id = KeyEventId::new(
            EpochId::new(1),
            DomainId::legacy_ecdsa_id(),
            AttemptId::new(),
        );
        assert!(storage
            .store(&KeyShare::new(
                key_event_id.clone(),
                generated_key_2.clone(),
            ))
            .await
            .is_err());

        // Can store if attempt is higher.
        let key_event_id = KeyEventId::new(
            EpochId::new(1),
            DomainId::legacy_ecdsa_id(),
            AttemptId::new().next().next(),
        );
        storage
            .store(&KeyShare::new(
                key_event_id.clone(),
                generated_key_2.clone(),
            ))
            .await
            .unwrap();
        let loaded_key_2 = storage.load().await.unwrap().unwrap();
        assert_eq!(generated_key_2.private_share, loaded_key_2.private_share);
        assert_eq!(generated_key_2.public_key, loaded_key_2.public_key);

        let generated_key_3 = TestGenerators::new(3, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;

        // Can't store if epoch is lower:
        let key_event_id = KeyEventId::new(
            EpochId::new(0),
            DomainId::legacy_ecdsa_id(),
            key_event_id.attempt_id.next(),
        );
        assert!(storage
            .store(&KeyShare::new(
                key_event_id.clone(),
                generated_key_3.clone(),
            ))
            .await
            .is_err());

        // Can store if epoch is higher.
        let key_event_id = KeyEventId::new(
            EpochId::new(2),
            DomainId::legacy_ecdsa_id(),
            AttemptId::new(),
        );
        storage
            .store(&KeyShare::new(
                key_event_id.clone(),
                generated_key_3.clone(),
            ))
            .await
            .unwrap();
        let loaded_key_3 = storage.load().await.unwrap().unwrap();
        assert_eq!(generated_key_3.private_share, loaded_key_3.private_share);
        assert_eq!(generated_key_3.public_key, loaded_key_3.public_key);
    }
}
