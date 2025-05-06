use crate::assets::DistributedAssetStorage;
use crate::background::InFlightGenerationTracker;
use crate::config::PresignatureConfig;
use crate::db::SecretDB;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{participants_from_triples, ParticipantId, UniqueId};
use crate::protocol::run_protocol;
use crate::providers::ecdsa::{EcdsaSignatureProvider, EcdsaTaskId, KeygenOutput, TripleStorage};
use crate::providers::HasParticipants;
use crate::tracking::AutoAbortTaskCollection;
use crate::{metrics, tracking};
use cait_sith::ecdsa::presign::{presign, PresignArguments, PresignOutput};
use cait_sith::ecdsa::triples::TripleGenerationOutput;
use cait_sith::protocol::Participant;
use k256::Secp256k1;
use mpc_contract::primitives::domain::DomainId;
use near_time::Clock;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::time::Duration;

pub struct PresignatureStorage(DistributedAssetStorage<PresignOutputWithParticipants>);

impl PresignatureStorage {
    pub fn new(
        clock: Clock,
        db: Arc<SecretDB>,
        my_participant_id: ParticipantId,
        alive_participant_ids_query: Arc<dyn Fn() -> Vec<ParticipantId> + Send + Sync>,
        domain_id: DomainId,
    ) -> anyhow::Result<Self> {
        Ok(Self(DistributedAssetStorage::<
            PresignOutputWithParticipants,
        >::new(
            clock,
            db,
            crate::db::DBCol::Presignature,
            Some(domain_id),
            my_participant_id,
            |participants, presignature| {
                presignature.is_subset_of_active_participants(participants)
            },
            alive_participant_ids_query,
        )?))
    }
}

impl Deref for PresignatureStorage {
    type Target = DistributedAssetStorage<PresignOutputWithParticipants>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EcdsaSignatureProvider {
    /// Continuously generates presignatures, trying to maintain the desired number of
    /// presignatures available, using the desired number of concurrent computations as
    /// specified in the config. Most of the time, this process would be waiting for
    /// more triples to be generated, as presignature generation is significantly faster
    /// than triple generation.
    ///
    /// Generated triples will be written to `presignature_store` as owned triples. Note
    /// that this function does not take care of the passive side of presignature
    /// generation (i.e. other participants of the computations this function initiates),
    /// so that needs to be separately handled.
    pub(super) async fn run_background_presignature_generation(
        client: Arc<MeshNetworkClient>,
        threshold: usize,
        config: Arc<PresignatureConfig>,
        triple_store: Arc<TripleStorage>,
        domain_id: DomainId,
        presignature_store: Arc<PresignatureStorage>,
        keygen_out: KeygenOutput,
    ) -> anyhow::Result<()> {
        let in_flight_generations = InFlightGenerationTracker::new();
        let progress_tracker = Arc::new(PresignatureGenerationProgressTracker {
            desired_presignatures_to_buffer: config.desired_presignatures_to_buffer,
            presignature_store: presignature_store.clone(),
            in_flight_generations: in_flight_generations.num_in_flight_atomic(),
            waiting_for_triples: AtomicBool::new(false),
        });
        let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            progress_tracker.update_progress();
            metrics::MPC_OWNED_NUM_PRESIGNATURES_ONLINE
                .set(presignature_store.num_owned_ready() as i64);
            metrics::MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT
                .set(presignature_store.num_owned_offline() as i64);
            let my_presignatures_count: usize = presignature_store.num_owned();
            metrics::MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE.set(my_presignatures_count as i64);
            let should_generate = my_presignatures_count + in_flight_generations.num_in_flight()
                < config.desired_presignatures_to_buffer;
            if should_generate
                // There's no point to issue way too many in-flight computations, as they
                // will just be limited by the concurrency anyway.
                && in_flight_generations.num_in_flight()
                < config.concurrency * 2
            {
                let id = presignature_store.generate_and_reserve_id();
                progress_tracker.set_waiting_for_triples(true);
                let (paired_triple_id, (triple0, triple1)) = triple_store.take_owned().await;
                progress_tracker.set_waiting_for_triples(false);
                let participants = participants_from_triples(&triple0, &triple1);
                let task_id = EcdsaTaskId::Presignature {
                    id,
                    domain_id,
                    paired_triple_id,
                };
                let channel = client.new_channel_for_task(task_id, participants.clone())?;
                let in_flight = in_flight_generations.in_flight(1);
                let parallelism_limiter = parallelism_limiter.clone();
                let presignature_store = presignature_store.clone();
                let config_clone = config.clone();
                let keygen_out = keygen_out.clone();
                tasks.spawn_checked(&format!("{:?}", task_id), async move {
                    let _in_flight = in_flight;
                    let _semaphore_guard = parallelism_limiter.acquire().await?;
                    let presignature = PresignComputation {
                        threshold,
                        triple0,
                        triple1,
                        keygen_out,
                    }
                    .perform_leader_centric_computation(
                        channel,
                        Duration::from_secs(config_clone.timeout_sec),
                    )
                    .await?;
                    presignature_store.add_owned(
                        id,
                        PresignOutputWithParticipants {
                            presignature,
                            participants,
                        },
                    );

                    anyhow::Ok(())
                });
                continue;
            }

            // If the store is full, try to discard some presignatures which cannot be used right now
            if my_presignatures_count == config.desired_presignatures_to_buffer {
                presignature_store.maybe_discard_owned(1).await;
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    pub(super) async fn run_presignature_generation_follower(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
        id: UniqueId,
        domain_id: DomainId,
        paired_triple_id: UniqueId,
    ) -> anyhow::Result<()> {
        let domain_data = self.domain_data(domain_id)?;

        FollowerPresignComputation {
            threshold: self.mpc_config.participants.threshold as usize,
            keygen_out: domain_data.keyshare,
            triple_store: self.triple_store.clone(),
            paired_triple_id,
            out_presignature_store: domain_data.presignature_store,
            out_presignature_id: id,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.presignature.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutputWithParticipants {
    pub presignature: PresignOutput<Secp256k1>,
    pub participants: Vec<ParticipantId>,
}

impl HasParticipants for PresignOutputWithParticipants {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
        self.participants
            .iter()
            .all(|p| active_participants.contains(p))
    }
}

/// Performs an MPC presignature operation. This is shared for the initiator
/// and for passive participants.
pub struct PresignComputation {
    threshold: usize,
    triple0: TripleGenerationOutput<Secp256k1>,
    triple1: TripleGenerationOutput<Secp256k1>,
    keygen_out: KeygenOutput,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<PresignOutput<Secp256k1>> for PresignComputation {
    async fn compute(
        self,
        channel: &mut NetworkTaskChannel,
    ) -> anyhow::Result<PresignOutput<Secp256k1>> {
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = presign(
            &cs_participants,
            me.into(),
            &cs_participants,
            me.into(),
            PresignArguments {
                triple0: self.triple0,
                triple1: self.triple1,
                keygen_out: self.keygen_out,
                threshold: self.threshold,
            },
        )?;
        let _timer = metrics::MPC_PRE_SIGNATURE_TIME_ELAPSED.start_timer();
        let presignature = run_protocol("presign", channel, protocol).await?;
        Ok(presignature)
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

/// Performs an MPC presignature operation as a follower.
/// The difference is: we need to read the triples from the triple store (which may fail),
/// and we need to write the presignature to the presignature store before completing.
pub struct FollowerPresignComputation {
    pub threshold: usize,
    pub paired_triple_id: UniqueId,
    pub keygen_out: KeygenOutput,
    pub triple_store: Arc<TripleStorage>,

    pub out_presignature_store: Arc<PresignatureStorage>,
    pub out_presignature_id: UniqueId,
}

#[async_trait::async_trait]
impl MpcLeaderCentricComputation<()> for FollowerPresignComputation {
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let (triple0, triple1) = self.triple_store.take_unowned(self.paired_triple_id)?;
        let presignature = PresignComputation {
            threshold: self.threshold,
            triple0,
            triple1,
            keygen_out: self.keygen_out,
        }
        .compute(channel)
        .await?;
        self.out_presignature_store.add_unowned(
            self.out_presignature_id,
            PresignOutputWithParticipants {
                presignature,
                participants: channel.participants().to_vec(),
            },
        );
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

struct PresignatureGenerationProgressTracker {
    desired_presignatures_to_buffer: usize,
    presignature_store: Arc<PresignatureStorage>,
    in_flight_generations: Arc<AtomicUsize>,
    waiting_for_triples: AtomicBool,
}

impl PresignatureGenerationProgressTracker {
    pub fn set_waiting_for_triples(&self, waiting: bool) {
        self.waiting_for_triples
            .store(waiting, std::sync::atomic::Ordering::Relaxed);
        self.update_progress();
    }

    pub fn update_progress(&self) {
        tracking::set_progress(&format!(
            "Presignatures: available: {}/{}; generating: {}{}",
            self.presignature_store.num_owned(),
            self.desired_presignatures_to_buffer,
            self.in_flight_generations
                .load(std::sync::atomic::Ordering::Relaxed),
            if self
                .waiting_for_triples
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                " (waiting for triples)"
            } else {
                ""
            }
        ))
    }
}
