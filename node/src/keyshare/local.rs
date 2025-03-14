use super::{KeyshareStorage, RootKeyshareData};
use crate::{config::AesEncryptionKey, db};
use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::Context;
use sha3::digest::generic_array::GenericArray;
use std::path::PathBuf;

/// Stores the root keyshare in a local encrypted file.
pub struct LocalKeyshareStorage {
    home_dir: PathBuf,
    encryption_key: AesEncryptionKey,
}

impl LocalKeyshareStorage {
    pub fn new(home_dir: PathBuf, key: AesEncryptionKey) -> Self {
        Self {
            home_dir,
            encryption_key: key,
        }
    }
}

#[async_trait::async_trait]
impl KeyshareStorage for LocalKeyshareStorage {
    async fn load(&self) -> anyhow::Result<Option<RootKeyshareData>> {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.encryption_key.as_bytes()));
        let keyfile = self.home_dir.join("key");
        if !keyfile.exists() {
            return Ok(None);
        }
        let data = tokio::fs::read(keyfile)
            .await
            .context("Failed to read keygen file")?;
        let decrypted = db::decrypt(&cipher, &data).context("Failed to decrypt keygen")?;
        let keyshare: RootKeyshareData =
            serde_json::from_slice(&decrypted).context("Failed to parse keygen")?;
        Ok(Some(keyshare))
    }

    async fn store(&self, root_keyshare: &RootKeyshareData) -> anyhow::Result<()> {
        let existing = self.load().await.context("Checking existing keyshare")?;
        if let Some(existing) = existing {
            if existing.epoch >= root_keyshare.epoch {
                return Err(anyhow::anyhow!(
                    "Refusing to overwrite existing keyshare of epoch {} with new keyshare of older epoch {}",
                    existing.epoch,
                    root_keyshare.epoch,
                ));
            }
        }
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.encryption_key.as_bytes()));
        let data = serde_json::to_vec(&root_keyshare).context("Failed to serialize keygen")?;
        let encrypted = db::encrypt(&cipher, &data);
        // Write the new key to a separate file, and then create a link to it.
        // That way there is no risk of corrupting the previous keyshare if the write is interrupted.
        let keyfile_for_epoch = self.home_dir.join(format!("key_{}", root_keyshare.epoch));
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
    use crate::keyshare::local::LocalKeyshareStorage;
    use crate::keyshare::{KeyshareStorage, RootKeyshareData};
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

        let storage = LocalKeyshareStorage::new(dir.path().to_path_buf(), encryption_key.into());
        assert!(storage.load().await.unwrap().is_none());
        storage
            .store(&RootKeyshareData::new(0, generated_key.clone()))
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
        // Can't store unless epoch is higher.
        assert!(storage
            .store(&RootKeyshareData::new(0, generated_key_2.clone()))
            .await
            .is_err());

        // Can store if epoch is higher.
        storage
            .store(&RootKeyshareData::new(1, generated_key_2.clone()))
            .await
            .unwrap();
        let loaded_key_2 = storage.load().await.unwrap().unwrap();
        assert_eq!(generated_key_2.private_share, loaded_key_2.private_share);
        assert_eq!(generated_key_2.public_key, loaded_key_2.public_key);

        // Can't store unless epoch is higher.
        assert!(storage
            .store(&RootKeyshareData::new(1, generated_key.clone()))
            .await
            .is_err());
        assert!(storage
            .store(&RootKeyshareData::new(0, generated_key))
            .await
            .is_err());
    }
}
