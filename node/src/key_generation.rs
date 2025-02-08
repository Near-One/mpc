use crate::config::Config;
use crate::db;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{MpcTaskId, ParticipantId};
use crate::protocol::run_protocol;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, KeyInit};
use anyhow::Context;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{Secp256k1};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use rand::rngs::OsRng;
use tokio::sync::mpsc;

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub async fn run_key_generation_ecdsa(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<KeygenOutput<Secp256k1>> {
    let cs_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::keygen::<Secp256k1>(&cs_participants, me.into(), threshold)?;
    run_protocol("key generation ecdsa", channel, me, protocol).await
}

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub async fn run_key_generation_eddsa(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<crate::frost::KeygenOutput> {
    let cs_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();

    let protocol = crate::frost::dkg(
        OsRng,
        cs_participants,
        me.into(),
        threshold as u16
    )?;

    run_protocol("key generation eddsa", channel, me, protocol).await
}

trait WithStorageSuffix {
    fn suffix() -> String;
}

/// The root keyshare data along with an epoch. The epoch is incremented
/// for each key resharing. This is the format stored in the old MPC
/// implementation, and we're keeping it the same to ease migration.
#[derive(Clone, Serialize, Deserialize)]
pub struct EcdsaKeyshareData {
    pub epoch: u64,
    pub private_share: k256::Scalar,
    pub public_key: k256::AffinePoint,
}

impl EcdsaKeyshareData {
    pub fn keygen_output(&self) -> KeygenOutput<Secp256k1> {
        KeygenOutput {
            private_share: self.private_share,
            public_key: self.public_key,
        }
    }

    pub fn of_epoch_zero(keygen_output: KeygenOutput<Secp256k1>) -> Self {
        Self {
            epoch: 0,
            private_share: keygen_output.private_share,
            public_key: keygen_output.public_key,
        }
    }
}

impl WithStorageSuffix for EcdsaKeyshareData { fn suffix() -> String { "ecdsa".to_string() } }

#[derive(Clone, Serialize, Deserialize)]
pub struct EddsaKeyshareData {
    pub epoch: u64,
    pub private_share: frost_ed25519::keys::KeyPackage,
    pub public_key: frost_ed25519::keys::PublicKeyPackage,
}

impl From<EddsaKeyshareData> for crate::frost::KeygenOutput {
    fn from(value: EddsaKeyshareData) -> Self {
        Self {
            key_package: value.private_share,
            public_key_package: value.public_key,
        }
    }
}

impl WithStorageSuffix for EddsaKeyshareData { fn suffix() -> String { "eddsa".to_string() } }

#[derive(Clone)]
pub struct RootKeyshareData {
    pub ecdsa: EcdsaKeyshareData,
    pub eddsa: EddsaKeyshareData,
}

/// Reads the root keyshare (keygen output) from disk.
pub fn load_keyshare<T: serde::de::DeserializeOwned + WithStorageSuffix>(
    home_dir: &Path,
    encryption_key: [u8; 16],
    root_keyshare_override: &Option<String>,
) -> anyhow::Result<T> {
    if let Some(override_key) = root_keyshare_override {
        return serde_json::from_str(override_key)
            .with_context(|| format!("Failed to parse root keyshare: {}", override_key));
    }
    let key_path = home_dir.join(format!("key-{}", T::suffix()));
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
    let data = std::fs::read(key_path).context("Failed to read keygen file")?;
    let decrypted = db::decrypt(&cipher, &data).context("Failed to decrypt keygen")?;
    serde_json::from_slice(&decrypted).context("Failed to parse keygen")
}

/// Saves the root keyshare (keygen output) to disk.
pub fn save_root_keyshare<T: serde::Serialize + WithStorageSuffix>(
    home_dir: &Path,
    encryption_key: [u8; 16],
    root_keyshare: &T,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist::<T>(home_dir);
    let key_path = home_dir.join(format!("key-{}", T::suffix()));
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
    let data = serde_json::to_vec(&root_keyshare).context("Failed to serialize keygen")?;
    let encrypted = db::encrypt(&cipher, &data);
    std::fs::write(key_path, &encrypted).context("Failed to write keygen file")
}

/// Panics if the root keyshare file already exists.
fn assert_root_key_does_not_exist<T: WithStorageSuffix>(home_dir: &Path) {
    if home_dir.join(format!("key-{}", T::suffix())).exists() {
        panic!("Root keyshare file already exists; refusing to overwrite");
    }
}

/// Performs the key generation protocol, saving the keyshare to disk.
/// Returns when the key generation is complete or runs into an error.
/// This is expected to only succeed if all participants are online
/// and running this function.
pub async fn run_key_generation_client_ecdsa(
    home_dir: PathBuf,
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist::<EcdsaKeyshareData>(&home_dir);
    let my_participant_id = client.my_participant_id();
    let is_leader = my_participant_id
        == config
            .mpc
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .unwrap();

    let channel = if is_leader {
        client.new_channel_for_task(MpcTaskId::KeyGenerationEcdsa, client.all_participant_ids())?
    } else {
        let channel = channel_receiver.recv().await.unwrap();
        if channel.task_id != MpcTaskId::KeyGenerationEcdsa {
            anyhow::bail!(
                "Received task ID is not key generation: {:?}",
                channel.task_id
            );
        }
        channel
    };
    let key = run_key_generation_ecdsa(
        channel,
        my_participant_id,
        config.mpc.participants.threshold as usize,
    )
    .await?;
    let keyshare = EcdsaKeyshareData {
        epoch: 0,
        private_share: key.private_share,
        public_key: key.public_key,
    };
    save_root_keyshare(
        &home_dir,
        config.secrets.local_storage_aes_key,
        &keyshare,
    )?;
    tracing::info!("Key ecdsa generation completed");

    // TODO(#75): Send vote_pk transaction to vote for the public key on the contract.
    // For now, just print it out so integration test can look at it.
    let public_key = affine_point_to_public_key(key.public_key)?;
    println!("Public key: {:?}", public_key);
    Ok(())
}

pub async fn run_key_generation_client_eddsa(
    home_dir: PathBuf,
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist::<EddsaKeyshareData>(&home_dir);

    let my_participant_id = client.my_participant_id();
    let is_leader = my_participant_id
        == config
        .mpc
        .participants
        .participants
        .iter()
        .map(|p| p.id)
        .min()
        .unwrap();

    let channel = if is_leader {
        client.new_channel_for_task(MpcTaskId::KeyGenerationEddsa, client.all_participant_ids())?
    } else {
        let channel = channel_receiver.recv().await.unwrap();
        if channel.task_id != MpcTaskId::KeyGenerationEddsa {
            anyhow::bail!(
                "Received task ID is not key generation: {:?}",
                channel.task_id
            );
        }
        channel
    };

    let key = run_key_generation_eddsa(
        channel,
        my_participant_id,
        config.mpc.participants.threshold as usize,
    )
        .await?;
    let keyshare = EddsaKeyshareData {
        epoch: 0,
        private_share: key.key_package,
        public_key: key.public_key_package,
    };
    save_root_keyshare(
        &home_dir,
        config.secrets.local_storage_aes_key,
        &keyshare,
    )?;
    tracing::info!("Key eddsa generation completed");

    Ok(())
}

pub fn affine_point_to_public_key(point: k256::AffinePoint) -> anyhow::Result<near_crypto::PublicKey> {
    Ok(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(&point.to_encoded_point(false).as_bytes()[1..65])
            .context("Failed to convert affine point to public key")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{load_keyshare, run_key_generation_ecdsa, run_key_generation_eddsa, save_root_keyshare, EcdsaKeyshareData, EddsaKeyshareData};
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use cait_sith::KeygenOutput;
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_key_generation_ecdsa() {
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(4, run_keygen_client_ecdsa).await.unwrap();
            println!("{:?}", results);
        })
            .await;
    }

    async fn run_keygen_client_ecdsa(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();

        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(MpcTaskId::KeyGenerationEcdsa, client.all_participant_ids())?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key = run_key_generation_ecdsa(channel, participant_id, 3).await?;

        Ok(key)
    }

    #[tokio::test]
    async fn test_key_generation_eddsa() {
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(4, run_keygen_client_eddsa).await.unwrap();
            println!("{:?}", results);
        })
            .await;
    }

    async fn run_keygen_client_eddsa(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<crate::frost::KeygenOutput> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();

        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(MpcTaskId::KeyGenerationEddsa, client.all_participant_ids())?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key = run_key_generation_eddsa(channel, participant_id, 3).await?;

        Ok(key)
    }

    #[test]
    fn test_keygen_store_ecdsa() {
        let dir = tempfile::tempdir().unwrap();
        let encryption_key = [1; 16];
        let generated_key = TestGenerators::new(2, 2)
            .make_ecdsa_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;

        let share = EcdsaKeyshareData {
            epoch: 0,
            private_share: generated_key.private_share,
            public_key: generated_key.public_key,
        };

        save_root_keyshare(
            dir.path(),
            encryption_key,
            &share,
        )
            .unwrap();
        let loaded_key: EcdsaKeyshareData = load_keyshare(dir.path(), encryption_key, &None).unwrap();
        assert_eq!(generated_key.private_share, loaded_key.private_share);
        assert_eq!(generated_key.public_key, loaded_key.public_key);
    }

    #[test]
    fn test_keygen_store_eddsa() {
        let dir = tempfile::tempdir().unwrap();
        let encryption_key = [1; 16];
        let generated_key = TestGenerators::new(2, 2)
            .make_eddsa_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;

        let share = EddsaKeyshareData {
            epoch: 0,
            private_share: generated_key.key_package.clone(),
            public_key: generated_key.public_key_package.clone(),
        };

        save_root_keyshare(
            dir.path(),
            encryption_key,
            &share,
        )
            .unwrap();
        let loaded_key: EddsaKeyshareData = load_keyshare(dir.path(), encryption_key, &None).unwrap();
        assert_eq!(generated_key.key_package, loaded_key.private_share);
        assert_eq!(generated_key.public_key_package, loaded_key.public_key);
    }
}
