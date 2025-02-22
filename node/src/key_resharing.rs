use crate::config::MpcConfig;
use crate::indexer::participants::ContractResharingState;
use crate::keyshare::{KeyshareStorage, RootKeyshareData};
use crate::network::{MeshNetworkClient, NetworkTaskChannel, NetworkTaskChannelWrapper};
use crate::primitives::{MpcTaskId, ParticipantId};
use crate::protocol::run_protocol;
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use futures::FutureExt;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, Scalar, Secp256k1};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Runs the key resharing protocol.
/// This protocol is identical for the leader and the followers.
/// When the set of old participants is the same as the set of new participants
/// then this is equivalent to "key refreshing".
/// This function would not succeed if:
///     - the number of participants common between old and new is smaller than
///       the old threshold; or
///     - the threshold is larger than the number of participants.
pub async fn run_key_resharing(
    channel: &mut NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
    old_participants: &[ParticipantId],
    old_threshold: usize,
    my_share: Option<Scalar>,
    public_key: AffinePoint,
) -> anyhow::Result<Scalar> {
    let new_participants = channel
        .participants()
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();

    let old_participants = old_participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();

    let protocol = cait_sith::reshare::<Secp256k1>(
        &old_participants,
        old_threshold,
        &new_participants,
        threshold,
        me.into(),
        my_share,
        public_key,
    )?;
    run_protocol("key resharing", channel, protocol).await
}

/// Performs the key resharing protocol. Retrieves the current keyshare
/// from storage, performs the resharing, and upon success, updates the storage
/// with the newly generated keyshare. This can only succeed if all new
/// participants are online.
pub async fn run_key_resharing_client(
    config: Arc<MpcConfig>,
    client: Arc<MeshNetworkClient>,
    state: ContractResharingState,
    my_share: Option<Scalar>,
    keyshare_storage: Box<dyn KeyshareStorage>,
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannelWrapper>,
) -> anyhow::Result<()> {
    let my_participant_id = client.my_participant_id();
    let is_leader = my_participant_id
        == config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .min()
            .unwrap();

    let task_id = MpcTaskId::KeyResharing {
        new_epoch: state.old_epoch + 1,
    };
    let channel = if is_leader {
        client.new_channel_for_task(task_id, client.all_participant_ids())?
    } else {
        loop {
            let channel = channel_receiver.recv().await.unwrap();
            if channel.task_id() != task_id {
                tracing::info!(
                    "Received task ID is not key resharing: {:?}; ignoring.",
                    channel.task_id()
                );
                continue;
            }
            break channel;
        }
    };
    let public_key = public_key_to_affine_point(state.public_key)?;
    let new_keyshare = channel
        .perform_leader_centric_computation(false, move |channel| {
            async move {
                run_key_resharing(
                    channel,
                    my_participant_id,
                    config.participants.threshold as usize,
                    &state
                        .old_participants
                        .participants
                        .iter()
                        .map(|p| p.id)
                        .collect::<Vec<_>>(),
                    state.old_participants.threshold as usize,
                    my_share,
                    public_key,
                )
                .await
            }
            .boxed()
        })
        .await?;
    keyshare_storage
        .store(&RootKeyshareData::new(
            state.old_epoch + 1,
            KeygenOutput {
                private_share: new_keyshare,
                public_key,
            },
        ))
        .await?;
    tracing::info!("Key resharing completed");

    Ok(())
}

pub fn public_key_to_affine_point(key: near_crypto::PublicKey) -> anyhow::Result<AffinePoint> {
    match key {
        near_crypto::PublicKey::SECP256K1(key) => {
            let mut bytes = [0u8; 65];
            bytes[0] = 0x04;
            bytes[1..65].copy_from_slice(key.as_ref());
            match Option::from(AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(
                bytes,
            )?)) {
                Some(result) => Ok(result),
                None => anyhow::bail!("Failed to convert public key to affine point"),
            }
        }
        _ => anyhow::bail!("Unsupported public key type"),
    }
}

#[cfg(test)]
mod tests {
    use super::run_key_resharing;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannelWrapper};
    use crate::primitives::{MpcTaskId, ParticipantId};
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use futures::FutureExt;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_key_resharing() {
        const THRESHOLD: usize = 3;
        const NUM_PARTICIPANTS: usize = 4;
        let gen = TestGenerators::new(NUM_PARTICIPANTS, THRESHOLD);
        let keygens = gen.make_keygens();
        let pubkey = keygens.iter().next().unwrap().1.public_key;
        let old_participants = gen.participant_ids();
        let mut new_participants = gen.participant_ids();
        new_participants.push(ParticipantId::from_raw(rand::random()));

        let key_resharing_client_runner = move |client: Arc<MeshNetworkClient>,
                                                mut channel_receiver: mpsc::UnboundedReceiver<
            NetworkTaskChannelWrapper,
        >| {
            let client = client.clone();
            let participant_id = client.my_participant_id();
            let all_participant_ids = client.all_participant_ids();
            let keyshare = keygens.get(&participant_id.into()).map(|k| k.private_share);
            let old_participants = old_participants.clone();

            async move {
                // We'll have the first participant be the leader.
                let channel = if participant_id == all_participant_ids[0] {
                    client.new_channel_for_task(
                        MpcTaskId::KeyGeneration,
                        client.all_participant_ids(),
                    )?
                } else {
                    channel_receiver
                        .recv()
                        .await
                        .ok_or_else(|| anyhow::anyhow!("No channel"))?
                };
                let key = channel
                    .perform_leader_centric_computation(false, move |channel| {
                        async move {
                            run_key_resharing(
                                channel,
                                participant_id,
                                THRESHOLD,
                                &old_participants,
                                THRESHOLD,
                                keyshare,
                                pubkey,
                            )
                            .await
                        }
                        .boxed()
                    })
                    .await?;

                anyhow::Ok(key)
            }
        };

        start_root_task_with_periodic_dump(async move {
            let results = run_test_clients(new_participants, key_resharing_client_runner)
                .await
                .unwrap();
            println!("{:?}", results);
        })
        .await;
    }
}
