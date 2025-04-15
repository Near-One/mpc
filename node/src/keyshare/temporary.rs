use super::Keyshare;
use crate::db::{decrypt, encrypt};
use aes_gcm::{Aes128Gcm, KeyInit};
use mpc_contract::primitives::key_state::{EpochId, KeyEventId};
use sha3::digest::generic_array::GenericArray;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Stores keyshares that we generated (from keygen or resharing) but which have not yet been
/// definitively included in a Running state by the contract. Each locally successful keygen
/// or resharing attempt is stored here before voting for its success on the contract; that way
/// if the contract then tells us that we should be using the keyshare from a specific attempt,
/// we are sure to have persisted them in temporary key storage.
#[derive(Debug)]
pub struct TemporaryKeyStorage {
    storage_dir: PathBuf,
    local_encryption_key: [u8; 16],
}

impl TemporaryKeyStorage {
    pub fn new(home_dir: PathBuf, local_encryption_key: [u8; 16]) -> anyhow::Result<Self> {
        let storage_dir = home_dir.join("temporary_keys");
        std::fs::create_dir_all(&storage_dir)?;
        Ok(Self {
            storage_dir,
            local_encryption_key,
        })
    }

    fn keyshare_path(&self, key_id: KeyEventId) -> PathBuf {
        let filename = format!(
            "keyshare_{}_{}_{}",
            key_id.epoch_id.get(),
            key_id.domain_id.0,
            key_id.attempt_id.get()
        );
        self.storage_dir.join(filename)
    }

    fn keyshare_started_path(&self, key_id: KeyEventId) -> PathBuf {
        let filename = format!(
            "started_{}_{}_{}",
            key_id.epoch_id.get(),
            key_id.domain_id.0,
            key_id.attempt_id.get()
        );
        self.storage_dir.join(filename)
    }

    /// Persists the fact that we're starting to generate the keyshare with the given key ID.
    /// This can only succeed at most once per key ID, ensuring that we do not attempt to generate
    /// the same key twice.
    pub async fn start_generating_keyshare(
        &self,
        key_id: KeyEventId,
    ) -> anyhow::Result<PendingKeyshareStorageHandle> {
        let file = tokio::fs::File::create_new(self.keyshare_started_path(key_id)).await?;
        file.sync_all().await?;
        let path = self.keyshare_path(key_id);
        Ok(PendingKeyshareStorageHandle {
            path,
            key_id,
            local_encryption_key: self.local_encryption_key,
        })
    }

    /// Loads the keyshare with the given key ID from temporary storage, returning None if it
    /// doesn't exist.
    pub async fn load_keyshare(&self, key_id: KeyEventId) -> anyhow::Result<Option<Keyshare>> {
        let path = self.keyshare_path(key_id);
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }

        let data = tokio::fs::read(&path).await?;
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.local_encryption_key));
        let decrypted = decrypt(&cipher, &data)?;
        let keyshare: Keyshare = serde_json::from_slice(&decrypted)?;
        if keyshare.key_id != key_id {
            anyhow::bail!(
                "Keyshare loaded from {:?} has unexpected key ID {:?}",
                path,
                keyshare.key_id
            );
        }
        Ok(Some(keyshare))
    }

    fn get_epoch_id_from_filename(filename: &str) -> anyhow::Result<Option<EpochId>> {
        let parts: Vec<&str> = filename.split('_').collect();
        if parts.len() != 4 {
            anyhow::bail!("Invalid keyshare filename: {:?}", filename);
        }
        let epoch_id: u64 = parts[1].parse()?;
        Ok(Some(EpochId::new(epoch_id)))
    }

    /// Deletes all keyshares and started markers stored in temporary storage that have an epoch ID
    /// less than the given.
    ///
    /// This must only be called when the permanent keyshare has already advanced to the given
    /// epoch. This is because once we do this, we lose the protection that each key ID can only be
    /// generated once. But if the permanent keyshare has advanced
    pub async fn delete_keyshares_prior_to_epoch_id(
        &self,
        epoch_id: EpochId,
    ) -> anyhow::Result<()> {
        let mut readdir = tokio::fs::read_dir(&self.storage_dir).await?;
        while let Some(entry) = readdir.next_entry().await? {
            let filename = entry.file_name().to_string_lossy().to_string();
            let Some(existing_epoch_id) = Self::get_epoch_id_from_filename(&filename)? else {
                continue;
            };
            if existing_epoch_id.get() < epoch_id.get() {
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
        Ok(())
    }
}

/// Handle to write a completed Keyshare to temporary key storage.
pub struct PendingKeyshareStorageHandle {
    pub path: PathBuf,
    key_id: KeyEventId,
    local_encryption_key: [u8; 16],
}

impl PendingKeyshareStorageHandle {
    /// Commits the keyshare to temporary key storage. This can only succeed once per key ID.
    /// It should always succeed, since we already performed the only-once check in
    /// `TemporaryKeyStorage::start_generating_keyshare`, but we still check here just in case.
    pub async fn commit_keyshare(self, keyshare: Keyshare) -> anyhow::Result<()> {
        anyhow::ensure!(
            keyshare.key_id == self.key_id,
            "Keyshare has unexpected key ID {:?}",
            keyshare.key_id
        );
        let data = serde_json::to_vec(&keyshare)?;
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&self.local_encryption_key));
        let encrypted = encrypt(&cipher, &data);

        let mut file = tokio::fs::File::create_new(&self.path).await?;
        file.write_all(&encrypted).await?;
        file.sync_all().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::keyshare::temporary::TemporaryKeyStorage;
    use crate::keyshare::test_utils::generate_dummy_keyshare;
    use mpc_contract::primitives::key_state::EpochId;

    #[tokio::test]
    async fn test_temporary_key_storage() {
        let home_dir = tempfile::tempdir().unwrap();
        let local_encryption_key = [3; 16];
        let storage =
            TemporaryKeyStorage::new(home_dir.path().to_path_buf(), local_encryption_key).unwrap();

        let key1 = generate_dummy_keyshare(1, 2, 1);
        let key2 = generate_dummy_keyshare(1, 2, 2);
        let key3 = generate_dummy_keyshare(1, 2, 3);
        let key4 = generate_dummy_keyshare(1, 3, 2);
        let key5 = generate_dummy_keyshare(2, 1, 1);
        let key6 = generate_dummy_keyshare(2, 2, 1);
        let key7 = generate_dummy_keyshare(3, 1, 7);

        assert!(storage.load_keyshare(key1.key_id).await.unwrap().is_none());

        let handle1 = storage
            .start_generating_keyshare(key1.key_id)
            .await
            .unwrap();
        assert!(storage
            .start_generating_keyshare(key1.key_id)
            .await
            .is_err());
        handle1.commit_keyshare(key1.clone()).await.unwrap();

        let handle2 = storage
            .start_generating_keyshare(key2.key_id)
            .await
            .unwrap();
        handle2.commit_keyshare(key2.clone()).await.unwrap();

        let handle3 = storage
            .start_generating_keyshare(key3.key_id)
            .await
            .unwrap();
        handle3.commit_keyshare(key3.clone()).await.unwrap();

        let handle4 = storage
            .start_generating_keyshare(key4.key_id)
            .await
            .unwrap();
        handle4.commit_keyshare(key4.clone()).await.unwrap();

        let handle5 = storage
            .start_generating_keyshare(key5.key_id)
            .await
            .unwrap();
        handle5.commit_keyshare(key5.clone()).await.unwrap();

        let handle6 = storage
            .start_generating_keyshare(key6.key_id)
            .await
            .unwrap();
        handle6.commit_keyshare(key6.clone()).await.unwrap();

        let handle7 = storage
            .start_generating_keyshare(key7.key_id)
            .await
            .unwrap();
        handle7.commit_keyshare(key7.clone()).await.unwrap();

        let loaded1 = storage.load_keyshare(key1.key_id).await.unwrap().unwrap();
        assert_eq!(loaded1, key1);
        let loaded2 = storage.load_keyshare(key2.key_id).await.unwrap().unwrap();
        assert_eq!(loaded2, key2);
        let loaded3 = storage.load_keyshare(key3.key_id).await.unwrap().unwrap();
        assert_eq!(loaded3, key3);
        let loaded4 = storage.load_keyshare(key4.key_id).await.unwrap().unwrap();
        assert_eq!(loaded4, key4);
        let loaded5 = storage.load_keyshare(key5.key_id).await.unwrap().unwrap();
        assert_eq!(loaded5, key5);
        let loaded6 = storage.load_keyshare(key6.key_id).await.unwrap().unwrap();
        assert_eq!(loaded6, key6);
        let loaded7 = storage.load_keyshare(key7.key_id).await.unwrap().unwrap();
        assert_eq!(loaded7, key7);

        storage
            .delete_keyshares_prior_to_epoch_id(EpochId::new(2))
            .await
            .unwrap();
        assert!(storage.load_keyshare(key1.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(key2.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(key3.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(key4.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(key5.key_id).await.unwrap().is_some());
        assert!(storage.load_keyshare(key6.key_id).await.unwrap().is_some());
        assert!(storage.load_keyshare(key7.key_id).await.unwrap().is_some());

        storage
            .delete_keyshares_prior_to_epoch_id(EpochId::new(3))
            .await
            .unwrap();

        assert!(storage.load_keyshare(key5.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(key6.key_id).await.unwrap().is_none());
        assert!(storage.load_keyshare(key7.key_id).await.unwrap().is_some());
    }
}
