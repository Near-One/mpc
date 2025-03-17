use crate::config::MpcConfig;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::protocol::run_protocol;
use crate::providers::ecdsa::{EcdsaSignatureProvider, EcdsaTaskId};
use cait_sith::protocol::Participant;
use cait_sith::KeygenOutput;
use k256::Secp256k1;
use std::sync::Arc;

impl EcdsaSignatureProvider {
    pub(super) async fn run_key_generation_client_internal(
        mpc_config: MpcConfig,
        network_client: Arc<MeshNetworkClient>,
        channel_receiver: &mut tokio::sync::mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let channel = if mpc_config.is_leader_for_keygen() {
            network_client.new_channel_for_task(
                EcdsaTaskId::KeyGeneration,
                network_client.all_participant_ids(),
            )?
        } else {
            MeshNetworkClient::wait_for_task(channel_receiver, EcdsaTaskId::KeyGeneration).await
        };

        let threshold = mpc_config.participants.threshold as usize;
        let key = KeyGenerationComputation { threshold }
            .perform_leader_centric_computation(
                channel,
                // TODO(#195): Move timeout here instead of in Coordinator.
                std::time::Duration::from_secs(60),
            )
            .await?;
        tracing::info!("Ecdsa secp256k1 key generation completed");

        Ok(key)
    }
}

/// Runs the key generation protocol, returning the key generated.
/// This protocol is identical for the leader and the followers.
pub struct KeyGenerationComputation {
    threshold: usize,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<KeygenOutput<Secp256k1>> for KeyGenerationComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = cait_sith::keygen::<Secp256k1>(&cs_participants, me.into(), self.threshold)?;
        run_protocol("key generation", channel, protocol).await
    }

    fn leader_waits_for_success(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::providers::ecdsa::key_generation::KeyGenerationComputation;
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::tests::TestGenerators;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use cait_sith::KeygenOutput;
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
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<KeygenOutput<Secp256k1>> {
        let participant_id = client.my_participant_id();
        let all_participant_ids = client.all_participant_ids();

        // We'll have the first participant be the leader.
        let channel = if participant_id == all_participant_ids[0] {
            client.new_channel_for_task(EcdsaTaskId::KeyGeneration, client.all_participant_ids())?
        } else {
            channel_receiver
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("No channel"))?
        };
        let key = KeyGenerationComputation { threshold: 3 }
            .perform_leader_centric_computation(channel, std::time::Duration::from_secs(60))
            .await?;

        Ok(key)
    }
}
