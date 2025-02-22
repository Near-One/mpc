use crate::config::MpcConfig;
use crate::keyshare::{KeyshareStorage, RootKeyshareData};
use crate::network::{MeshNetworkClient, NetworkTaskChannel, NetworkTaskChannelWrapper};
use crate::primitives::{MpcTaskId, ParticipantId};
use crate::protocol::run_protocol;
use anyhow::Context;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use futures::FutureExt;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, Secp256k1};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub async fn run_key_generation(
    channel: &mut NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<KeygenOutput<Secp256k1>> {
    let cs_participants = channel
        .participants()
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::keygen::<Secp256k1>(&cs_participants, me.into(), threshold)?;
    run_protocol("key generation", channel, protocol).await
}

/// Performs the key generation protocol, saving the keyshare to disk.
/// Returns when the key generation is complete or runs into an error.
/// This is expected to only succeed if all participants are online
/// and running this function.
pub async fn run_key_generation_client(
    config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    keyshare_storage: Box<dyn KeyshareStorage>,
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
) -> anyhow::Result<()> {
    if keyshare_storage.load().await?.is_some() {
        anyhow::bail!("Keyshare already exists, refusing to run key generation");
    }
    let my_participant_id = client.my_participant_id();
    let is_leader = my_participant_id
        == config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .unwrap();

    let channel = if is_leader {
        client.new_channel_for_task(MpcTaskId::KeyGeneration, client.all_participant_ids())?
    } else {
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            if channel.task_id() != MpcTaskId::KeyGeneration {
                tracing::info!(
                    "Received task ID is not key generation: {:?}; ignoring.",
                    channel.task_id()
                );
                continue;
            }
            break channel;
        }
    };
    let key = channel
        .perform_leader_centric_computation(false, move |channel| {
            run_key_generation(
                channel,
                my_participant_id,
                config.participants.threshold as usize,
            )
            .boxed()
        })
        .await?;
    keyshare_storage
        .store(&RootKeyshareData::new(0, key.clone()))
        .await?;
    tracing::info!("Key generation completed");

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
    use super::run_key_generation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannelWrapper};
    use crate::primitives::MpcTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use cait_sith::KeygenOutput;
    use futures::FutureExt;
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_key_generation() {
        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(
                TestGenerators::new(4, 3).participant_ids(),
                run_keygen_client,
            )
            .await
            .unwrap();
            println!("{:?}", results);
        })
        .await;
    }

    async fn run_keygen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
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
        let key = channel
            .perform_leader_centric_computation(false, move |channel| {
                run_key_generation(channel, participant_id, 3).boxed()
            })
            .await?;

        Ok(key)
    }
}
