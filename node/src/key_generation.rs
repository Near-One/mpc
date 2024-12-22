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
use k256::{AffinePoint, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub async fn run_key_generation(
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
    run_protocol("key generation", channel, me, protocol).await
}

/// The root keyshare data along with an epoch. The epoch is incremented
/// for each key resharing. This is the format stored in the old MPC
/// implementation, and we're keeping it the same to ease migration.
#[derive(Clone, Serialize, Deserialize)]
pub struct RootKeyshareData {
    pub epoch: u64,
    pub private_share: Scalar,
    pub public_key: AffinePoint,
}

impl RootKeyshareData {
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

/// Reads the root keyshare (keygen output) from disk.
pub fn load_root_keyshare(
    home_dir: &Path,
    encryption_key: [u8; 16],
    root_keyshare_override: &Option<String>,
) -> anyhow::Result<RootKeyshareData> {
    if let Some(override_key) = root_keyshare_override {
        return serde_json::from_str(override_key)
            .with_context(|| format!("Failed to parse root keyshare: {}", override_key));
    }
    let key_path = home_dir.join("key");
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
    let data = std::fs::read(key_path).context("Failed to read keygen file")?;
    let decrypted = db::decrypt(&cipher, &data).context("Failed to decrypt keygen")?;
    serde_json::from_slice(&decrypted).context("Failed to parse keygen")
}

/// Saves the root keyshare (keygen output) to disk.
pub fn save_root_keyshare(
    home_dir: &Path,
    encryption_key: [u8; 16],
    root_keyshare: &RootKeyshareData,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist(home_dir);
    let key_path = home_dir.join("key");
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&encryption_key));
    let data = serde_json::to_vec(&root_keyshare).context("Failed to serialize keygen")?;
    let encrypted = db::encrypt(&cipher, &data);
    std::fs::write(key_path, &encrypted).context("Failed to write keygen file")
}

/// Panics if the root keyshare file already exists.
fn assert_root_key_does_not_exist(home_dir: &Path) {
    if home_dir.join("key").exists() {
        panic!("Root keyshare file already exists; refusing to overwrite");
    }
}

/// Performs the key generation protocol, saving the keyshare to disk.
/// Returns when the key generation is complete or runs into an error.
/// This is expected to only succeed if all participants are online
/// and running this function.
pub async fn run_key_generation_client(
    home_dir: PathBuf,
    config: Arc<Config>,
    client: Arc<MeshNetworkClient>,
    mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    assert_root_key_does_not_exist(&home_dir);
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
        client.new_channel_for_task(MpcTaskId::KeyGeneration, client.all_participant_ids())?
    } else {
        let channel = channel_receiver.recv().await.unwrap();
        if channel.task_id != MpcTaskId::KeyGeneration {
            anyhow::bail!(
                "Received task ID is not key generation: {:?}",
                channel.task_id
            );
        }
        channel
    };
    let key = run_key_generation(
        channel,
        my_participant_id,
        config.mpc.participants.threshold as usize,
    )
    .await?;
    save_root_keyshare(
        &home_dir,
        config.secrets.local_storage_aes_key,
        &RootKeyshareData::of_epoch_zero(key.clone()),
    )?;
    tracing::info!("Key generation completed");

    // TODO(#75): Send vote_pk transaction to vote for the public key on the contract.
    // For now, just print it out so integration test can look at it.
    let public_key = affine_point_to_public_key(key.public_key)?;
    println!("Public key: {:?}", public_key);
    Ok(())
}

pub fn affine_point_to_public_key(point: AffinePoint) -> anyhow::Result<near_crypto::PublicKey> {
    Ok(near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(&point.to_encoded_point(false).as_bytes()[1..65])
            .context("Failed to convert affine point to public key")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{run_key_generation, save_root_keyshare};
    use crate::key_generation::RootKeyshareData;
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
    async fn test_key_generation() {
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(4, run_keygen_client).await.unwrap();
            println!("{:?}", results);
        })
        .await;
    }

    async fn run_keygen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();

        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(MpcTaskId::KeyGeneration, client.all_participant_ids())?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key = run_key_generation(channel, participant_id, 3).await?;

        Ok(key)
    }

    #[test]
    fn test_keygen_store() {
        let dir = tempfile::tempdir().unwrap();
        let encryption_key = [1; 16];
        let generated_key = TestGenerators::new(2, 2)
            .make_keygens()
            .into_iter()
            .next()
            .unwrap()
            .1;

        save_root_keyshare(
            dir.path(),
            encryption_key,
            &RootKeyshareData::of_epoch_zero(generated_key.clone()),
        )
        .unwrap();
        let loaded_key = super::load_root_keyshare(dir.path(), encryption_key, &None).unwrap();
        assert_eq!(generated_key.private_share, loaded_key.private_share);
        assert_eq!(generated_key.public_key, loaded_key.public_key);
    }
}
