use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes128Gcm, AesGcm, KeyInit};
use std::path::Path;
use std::sync::Arc;

/// Key-value store that encrypts all values with AES-GCM.
/// The keys of the key-value store are NOT encrypted.
pub struct SecretDB {
    db: rocksdb::DB,
    cipher: Aes128Gcm,
}

/// Each DBCol corresponds to a column family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DBCol {
    GeneratedKey,
    Triple,
    Presignature,
}

impl DBCol {
    fn as_str(&self) -> &'static str {
        match self {
            DBCol::GeneratedKey => "key",
            DBCol::Triple => "triple",
            DBCol::Presignature => "presignature",
        }
    }

    fn all() -> [DBCol; 3] {
        [DBCol::GeneratedKey, DBCol::Triple, DBCol::Presignature]
    }
}

/// Encrypts a single value with AES-GCM. This encryption is randomized.
fn encrypt(cipher: &Aes128Gcm, plaintext: &[u8]) -> Vec<u8> {
    let nonce = aes_gcm::Aes128Gcm::generate_nonce(&mut rand::thread_rng());
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    [nonce.as_slice(), &ciphertext].concat()
}

/// Decrypts a single value with AES-GCM.
fn decrypt(cipher: &Aes128Gcm, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    const NONCE_LEN: usize = 12; // dictated by the aes-gcm library.
    if ciphertext.len() < NONCE_LEN {
        return Err(anyhow::anyhow!("ciphertext is too short"));
    }
    let nonce = &ciphertext[..12];
    let ciphertext = &ciphertext[12..];
    let data = cipher
        .decrypt(GenericArray::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed"))?;
    Ok(data)
}

impl SecretDB {
    pub fn new(path: &Path, encryption_key: [u8; 16]) -> anyhow::Result<Arc<Self>> {
        let cipher = AesGcm::new(GenericArray::from_slice(&encryption_key));
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let db = rocksdb::DB::open_cf(&options, path, DBCol::all().iter().map(|col| col.as_str()))?;
        Ok(Self { db, cipher }.into())
    }

    fn cf_handle(&self, cf: DBCol) -> rocksdb::ColumnFamilyRef {
        self.db.cf_handle(cf.as_str()).unwrap()
    }

    /// Gets the specified value from the database.
    /// The value is decrypted before being returned.
    pub fn get(&self, col: DBCol, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let value = self.db.get_cf(&self.cf_handle(col), key)?;
        value.map(|v| decrypt(&self.cipher, &v)).transpose()
    }

    /// Returns the undecrypted ciphertext, for testing.
    #[cfg(test)]
    pub fn get_ciphertext(&self, col: DBCol, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let value = self.db.get_cf(&self.cf_handle(col), key)?;
        value.map(|v| Ok(v)).transpose()
    }

    /// Returns an iterator for all values in the given range.
    /// The values are decrypted before being returned.
    pub fn iter_range(
        &self,
        col: DBCol,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = anyhow::Result<(Box<[u8]>, Vec<u8>)>> + '_ {
        let iter_mode = rocksdb::IteratorMode::From(start, rocksdb::Direction::Forward);
        let mut iter_opt = rocksdb::ReadOptions::default();
        iter_opt.set_iterate_upper_bound(end);
        let iter = self
            .db
            .iterator_cf_opt(&self.cf_handle(col), iter_opt, iter_mode);
        iter.map(move |result| {
            let (key, value) = result?;
            let value = decrypt(&self.cipher, &value)?;
            anyhow::Ok((key, value))
        })
    }

    pub fn update(self: &Arc<Self>) -> SecretDBUpdate {
        SecretDBUpdate {
            db: self.clone(),
            batch: rocksdb::WriteBatch::default(),
        }
    }
}

pub struct SecretDBUpdate {
    db: Arc<SecretDB>,
    batch: rocksdb::WriteBatch,
}

impl SecretDBUpdate {
    /// Puts a key-value pair into the database, overwriting if the key
    /// already exists. Encrypts the value before persisting it.
    pub fn put(&mut self, col: DBCol, key: &[u8], value: &[u8]) {
        let value = encrypt(&self.db.cipher, value);
        self.batch.put_cf(&self.db.cf_handle(col), key, &value);
    }

    pub fn delete(&mut self, col: DBCol, key: &[u8]) {
        self.batch.delete_cf(&self.db.cf_handle(col), key);
    }

    pub fn commit(self) -> anyhow::Result<()> {
        self.db.db.write(self.batch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1; 16];
        let cipher = AesGcm::new(GenericArray::from_slice(&key));
        let plaintext = b"hello world";
        let ciphertext = encrypt(&cipher, plaintext);
        let decrypted = decrypt(&cipher, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
        for i in 0..ciphertext.len() {
            let mut corrupted = ciphertext.clone();
            corrupted[i] ^= 1;
            assert!(decrypt(&cipher, &corrupted).is_err());
        }
        let incorrect_key = [2; 16];
        let cipher = AesGcm::new(GenericArray::from_slice(&incorrect_key));
        assert!(decrypt(&cipher, &ciphertext).is_err());
    }

    #[test]
    fn test_db() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let db = SecretDB::new(dir.path(), [1; 16])?;
        let mut update = db.update();
        update.put(DBCol::GeneratedKey, b"key", b"value");
        update.put(DBCol::Triple, b"triple1", b"tripledata");
        update.put(
            DBCol::Triple,
            b"triple2",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        update.put(DBCol::Triple, b"triple3", b"");
        update.commit()?;
        assert_eq!(db.get(DBCol::GeneratedKey, b"key")?.unwrap(), b"value");
        assert_eq!(db.get(DBCol::Triple, b"triple1")?.unwrap(), b"tripledata");
        assert_eq!(
            db.get(DBCol::Triple, b"triple2")?.unwrap(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(db.get(DBCol::Triple, b"triple3")?.unwrap(), b"");

        let mut iter = db.iter_range(DBCol::Triple, b"triple1", b"triple3");
        assert_eq!(
            iter.next().unwrap().unwrap(),
            (
                b"triple1".to_vec().into_boxed_slice(),
                b"tripledata".to_vec()
            )
        );
        assert_eq!(
            iter.next().unwrap().unwrap(),
            (
                b"triple2".to_vec().into_boxed_slice(),
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec()
            )
        );
        let mut update = db.update();
        update.delete(DBCol::Triple, b"triple1");
        update.commit()?;
        assert_eq!(db.get(DBCol::Triple, b"triple1")?, None);

        // Sanity check that the DB does encrypt the value.
        assert!(!db
            .get_ciphertext(DBCol::Triple, b"triple2")
            .unwrap()
            .unwrap()
            .is_ascii());

        Ok(())
    }
}
