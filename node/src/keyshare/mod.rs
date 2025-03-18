pub mod compat;
mod gcp;
pub mod local;
pub mod permanent;
mod temporary;
#[cfg(test)]
pub mod test_utils;

use crate::hkdf::affine_point_to_public_key;
use anyhow::Context;
use k256::{AffinePoint, Scalar};
use mpc_contract::primitives::key_state::Keyset;
use mpc_contract::primitives::key_state::{EpochId, KeyEventId, KeyForDomain};
use permanent::{PermanentKeyStorage, PermanentKeyStorageBackend, PermanentKeyshareData};
use serde::{Deserialize, Serialize};
use temporary::TemporaryKeyStorage;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Secp256k1KeyshareData {
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}
#[derive(Clone, Serialize, Deserialize)]
pub enum KeyShareData {
    Secp256k1(Secp256k1Data),
}

/// A single keyshare, corresponding to one epoch, one domain, one attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keyshare {
    pub key_id: KeyEventId,
    pub data: KeyshareData,
}

impl Keyshare {
    pub fn public_key(&self) -> anyhow::Result<near_sdk::PublicKey> {
        match &self.data {
            KeyshareData::Secp256k1(secp256k1_data) => {
                let public_key = affine_point_to_public_key(secp256k1_data.public_key)?;
                Ok(public_key.to_string().parse()?)
            }
        }
    }

    pub fn check_consistency(&self, epoch_id: EpochId, key: &KeyForDomain) -> anyhow::Result<()> {
        let key_id = KeyEventId::new(epoch_id, key.domain_id, key.attempt);
        if self.key_id != key_id {
            anyhow::bail!(
                "Keyshare has incorrect key ID {:?}, should be {:?}",
                self.key_id,
                key_id
            );
        }
        if self.public_key()? != key.key {
            anyhow::bail!(
                "Keyshare has incorrect public key {:?}, should be {:?}",
                self.public_key()?,
                key.key
            );
        }
        Ok(())
    }
}

/// Abstracts away the storage of the keyshares.
///
/// The keyshares are stored in "permanent key storage" and "temporary key storage":
///  - Permanent key storage is a single object that lives either on GCP or locally.
///  - Temporary key storage is a collection of keyshares that are persisted as individual files.
///    Each keyshare is identified by (epoch ID, domain ID, attempt ID).
///
/// Important: although "temporary key storage" uses the word "temporary", files must still be
/// strongly persisted and it is not acceptable to delete the local files. The persistence
/// requirements of the temporary and permanent key storages are the same (i.e. node operators
/// must not lose them, for doing so is the same as permanently leaving the MPC network).
///
/// Keyshares persisted into temporary key storage are not guaranteed to be used; rather, the
/// voting mechanism (vote_pk and vote_reshared) on the contract ultimately decides which
/// keyshare to use for each domain (in case multiple attempts were made to generate or reshare
/// the key).
///
/// Whenever the contract transitions into the Running state (which certifies the exact key to
/// use for each domain), the keyshares are promoted from temporary key storage to permanent key
/// storage. This is done by calling `load_keyset` when handling the Running state.
///
/// A subtle detail is that we may miss the Running state if it quickly transitions into
/// another state (Initializing or Resharing). For the initializing state we do not actually need
/// the existing keyshares, but for the resharing state we do. And that's not a problem:
/// in the resharing state we also need to call `load_keyset`, and that will promote the keys into
/// permanent storage if needed.
pub struct KeyshareStorage {
    temporary: TemporaryKeyStorage,
    permanent: PermanentKeyStorage,
}

impl KeyshareStorage {
    /// Stores a single keyshare into temporary key storage. The keyshare's KeyEventId must be
    /// unique. This must be called before sending in a vote_pk or vote_reshared.
    pub async fn store_key(&self, key_share: Keyshare) -> anyhow::Result<()> {
        self.temporary.store_keyshare(key_share).await
    }

    /// Before generating a key, we must call `ensure_can_generate_key` to check that we are able
    /// to generate that key and use it afterwards. This requires:
    ///  - The already generated keys exist either in permanent or temporary storage.
    ///  - The current permanent key storage is either
    ///    - In the same epoch as the key generation attempt, and whose keys are a prefix of the
    ///      already generated keys.
    ///    - In an older epoch. This can happen if we missed the previous transition from Resharing
    ///      to Running before it transitions again into Initializing. This is fine.
    ///
    /// This function will never fail as long as the node is not buggy and the storage is not messed
    /// with. Therefore it is intended to only be a sanity check.
    pub async fn ensure_can_generate_key(
        &self,
        epoch_id: EpochId,
        already_generated_keys: &[KeyForDomain],
    ) -> anyhow::Result<()> {
        let permanent = self.permanent.load().await?;
        let num_permanent_keys_same_epoch = if let Some(permanent) = permanent {
            if permanent.epoch_id == epoch_id {
                self.verify_existing_keyshares_are_prefix_of_keyset(
                    &permanent.keyshares,
                    epoch_id,
                    already_generated_keys,
                )
                .await?;
                permanent.keyshares.len()
            } else if permanent.epoch_id.get() > epoch_id.get() {
                anyhow::bail!(
                    "Permanent key storage has epoch ID {} which is newer than {}",
                    permanent.epoch_id.get(),
                    epoch_id.get()
                );
            } else {
                0
            }
        } else {
            0
        };
        for domain in &already_generated_keys[num_permanent_keys_same_epoch..] {
            self.load_keyshare_from_temporary(epoch_id, domain).await?;
        }
        Ok(())
    }

    /// Before resharing a key, we must call this to ensure that we're able to reshare the key
    /// and use it afterwards. This requires:
    ///   - The already reshared keys exist in temporary storage.
    ///   - The current permanent key storage has an older epoch.
    ///
    /// This function will never fail as long as the node is not buggy and the storage is not messed
    /// with. Therefore it is intended to only be a sanity check.
    pub async fn ensure_can_reshare_key(
        &self,
        epoch_id: EpochId,
        already_reshared_keys: &[KeyForDomain],
    ) -> anyhow::Result<()> {
        let permanent = self.permanent.load().await?;
        if let Some(permanent) = permanent {
            if permanent.epoch_id.get() >= epoch_id.get() {
                anyhow::bail!(
                    "Permanent key storage has epoch ID {} which is not older than {}",
                    permanent.epoch_id.get(),
                    epoch_id.get()
                );
            }
        }
        for domain in already_reshared_keys {
            self.load_keyshare_from_temporary(epoch_id, domain).await?;
        }
        Ok(())
    }

    /// Ensures that the given keyset is in permanent key storage, and then returns them. The order
    /// the keys are given and returned are both in increasing order of DomainId.
    ///
    /// Since this is only expected to be called when we already know which attempt to use, this
    /// function also deletes keyshares in temporary storage that are below the keyset's epoch ID.
    /// (We could also delete attempts in the same epoch ID but this is not necessary from a
    /// security perspective, since the same epoch ID corresponds to the same set of participants
    /// and the threshold value.)
    pub async fn load_keyset(&self, keyset: &Keyset) -> anyhow::Result<Vec<Keyshare>> {
        let permanent = self.permanent.load().await?;
        let existing_keyshares = if let Some(permanent) = permanent {
            if permanent.epoch_id == keyset.epoch_id {
                permanent.keyshares
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        self.verify_existing_keyshares_are_prefix_of_keyset(
            &existing_keyshares,
            keyset.epoch_id,
            &keyset.domains,
        )
        .await?;

        if existing_keyshares.len() == keyset.domains.len() {
            return Ok(existing_keyshares);
        }

        let mut new_keyshares = existing_keyshares;
        for domain in keyset.domains.iter().skip(new_keyshares.len()) {
            let key_id = KeyEventId::new(keyset.epoch_id, domain.domain_id, domain.attempt);
            let keyshare = self
                .temporary
                .load_keyshare(&key_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Missing temporary keyshare {:?}", key_id))?;
            new_keyshares.push(keyshare);
        }
        let new_permanent_keyshare = PermanentKeyshareData {
            epoch_id: keyset.epoch_id,
            keyshares: new_keyshares.clone(),
        };
        self.permanent.store(&new_permanent_keyshare).await?;
        self.temporary
            .delete_keyshares_prior_to_epoch_id(keyset.epoch_id)
            .await?;
        Ok(new_keyshares)
    }

    /// Helper function to verify that the keyshares we have from permanent storage is a prefix
    /// of the expected keyset, i.e. there are no extra keys, and each key is consistent with the
    /// expected keyset.
    async fn verify_existing_keyshares_are_prefix_of_keyset(
        &self,
        existing_keyshares: &[Keyshare],
        epoch_id: EpochId,
        expected_keys: &[KeyForDomain],
    ) -> anyhow::Result<()> {
        if existing_keyshares.len() > expected_keys.len() {
            anyhow::bail!(
                "Existing permanent keyshare for epoch {:?} has more domains {} than expected {}",
                epoch_id,
                existing_keyshares.len(),
                expected_keys.len()
            );
        }
        for (i, existing_keyshare) in existing_keyshares.iter().enumerate() {
            let domain = &expected_keys[i];
            existing_keyshare
                .check_consistency(epoch_id, domain)
                .with_context(|| {
                    format!(
                        "Existing permanent keyshare epoch {:?} index {}",
                        epoch_id, i
                    )
                })?;
        }
        Ok(())
    }

    /// Loads a keyshare from temporary storage and verifies that it is consistent with the given
    /// key's key ID and public key.
    async fn load_keyshare_from_temporary(
        &self,
        epoch_id: EpochId,
        key: &KeyForDomain,
    ) -> anyhow::Result<Keyshare> {
        let key_id = KeyEventId::new(epoch_id, key.domain_id, key.attempt);
        let keyshare = self
            .temporary
            .load_keyshare(&key_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Missing temporary keyshare {:?}", key_id))?;
        keyshare
            .check_consistency(epoch_id, key)
            .with_context(|| format!("Keyshare loaded from temporary storage for {:?}", key_id))?;
        Ok(keyshare)
    }
}

pub struct GcpPermanentKeyStorageConfig {
    pub project_id: String,
    pub secret_id: String,
}

/// Config for how to construct a KeyshareStorage.
pub struct KeyStorageConfig {
    pub home_dir: std::path::PathBuf,
    pub local_encryption_key: [u8; 16],
    pub gcp: Option<GcpPermanentKeyStorageConfig>,
}

impl KeyStorageConfig {
    pub async fn create(&self) -> anyhow::Result<KeyshareStorage> {
        let permanent_backend: Box<dyn PermanentKeyStorageBackend> = if let Some(gcp) = &self.gcp {
            let backend = gcp::GcpPermanentKeyStorageBackend::new(
                gcp.project_id.clone(),
                gcp.secret_id.clone(),
            )
            .await?;
            Box::new(backend)
        } else {
            let backend = local::LocalPermanentKeyStorageBackend::new(
                self.home_dir.clone(),
                self.local_encryption_key,
            )
            .await?;
            Box::new(backend)
        };
        let permanent = PermanentKeyStorage::new(permanent_backend).await?;
        let temporary = TemporaryKeyStorage::new(self.home_dir.clone(), self.local_encryption_key)?;
        Ok(KeyshareStorage {
            temporary,
            permanent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::KeyStorageConfig;
    use crate::keyshare::test_utils::{
        generate_dummy_keyshare, keyset_from_permanent_keyshare, permanent_keyshare_from_keyshares,
    };

    #[tokio::test]
    async fn test_key_storage() {
        let tempdir = tempfile::tempdir().unwrap();
        let home_dir = tempdir.path().to_path_buf();
        let local_encryption_key = [3; 16];
        let storage = KeyStorageConfig {
            home_dir,
            local_encryption_key,
            gcp: None,
        }
        .create()
        .await
        .unwrap();

        // Load an empty keyset; this should succeed.
        let permanent0 = permanent_keyshare_from_keyshares(0, &[]);
        let keyset0 = keyset_from_permanent_keyshare(&permanent0);
        let loaded0 = storage.load_keyset(&keyset0).await.unwrap();
        assert!(&loaded0.is_empty());

        // Store some keyshares.
        let key1 = generate_dummy_keyshare(0, 1, 1);
        let key2 = generate_dummy_keyshare(0, 1, 2);
        let key3 = generate_dummy_keyshare(0, 2, 1);
        let key4 = generate_dummy_keyshare(0, 2, 2);

        storage.store_key(key1.clone()).await.unwrap();
        storage.store_key(key2.clone()).await.unwrap();
        storage.store_key(key3.clone()).await.unwrap();
        storage.store_key(key4.clone()).await.unwrap();

        // Finalize two keys from epoch 0.
        let permanent1 = permanent_keyshare_from_keyshares(0, &[key2.clone(), key3.clone()]);
        let keyset1 = keyset_from_permanent_keyshare(&permanent1);
        let loaded1 = storage.load_keyset(&keyset1).await.unwrap();
        assert_eq!(&loaded1, &permanent1.keyshares);

        // Load a conflicting keyset; this should fail.
        let permanent2 = permanent_keyshare_from_keyshares(0, &[key1.clone(), key4.clone()]);
        let keyset2 = keyset_from_permanent_keyshare(&permanent2);
        assert!(storage.load_keyset(&keyset2).await.is_err());

        // Load the same keyset again; this should succeed.
        let loaded1 = storage.load_keyset(&keyset1).await.unwrap();
        assert_eq!(&loaded1, &permanent1.keyshares);

        // Store some more keyshares for epoch 1.
        let key5 = generate_dummy_keyshare(1, 1, 1);
        let key6 = generate_dummy_keyshare(1, 1, 2);
        let key7 = generate_dummy_keyshare(1, 2, 1);
        let key8 = generate_dummy_keyshare(1, 2, 2);
        storage.store_key(key5.clone()).await.unwrap();
        storage.store_key(key6.clone()).await.unwrap();
        storage.store_key(key7.clone()).await.unwrap();
        storage.store_key(key8.clone()).await.unwrap();

        // Finalize two keys from epoch 1.
        let permanent3 = permanent_keyshare_from_keyshares(1, &[key5.clone(), key8.clone()]);
        let keyset3 = keyset_from_permanent_keyshare(&permanent3);
        let loaded3 = storage.load_keyset(&keyset3).await.unwrap();
        assert_eq!(&loaded3, &permanent3.keyshares);

        // Cannot load the old keyset anymore.
        assert!(storage.load_keyset(&keyset1).await.is_err());

        // Add another key to the same epoch; this is fine.
        let key9 = generate_dummy_keyshare(1, 3, 1);
        storage.store_key(key9.clone()).await.unwrap();
        let permanent4 = permanent_keyshare_from_keyshares(1, &[key5.clone(), key8.clone(), key9]);
        let keyset4 = keyset_from_permanent_keyshare(&permanent4);
        let loaded4 = storage.load_keyset(&keyset4).await.unwrap();
        assert_eq!(&loaded4, &permanent4.keyshares);
    }
}
