use cait_sith::{protocol::Participant, triples::TripleGenerationOutput};
use k256::Secp256k1;

use crate::config::TripleConfig;
use crate::network::MeshNetworkClient;
use crate::protocol::run_protocol;
use crate::{metrics, tracking};
use crate::{network::NetworkTaskChannel, primitives::ParticipantId};
use anyhow::Context;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

/// Generates a cait-sith triple.
pub async fn run_triple_generation(
    channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<TripleGenerationOutput<Secp256k1>> {
    let cs_participants = participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol =
        cait_sith::triples::generate_triple::<Secp256k1>(&cs_participants, me.into(), threshold)?;
    run_protocol("triple gen", channel, participants, me, protocol).await
}

/// Generates a random ID to identify a triple. It has no meaning beyond being
/// an identifier. It is generated in a way such that each participant will
/// generate different IDs. This is useful to ensure that IDs from different
/// participants will not collide.
///
/// There is, however, a chance that the same participant generates an ID that
/// already existed before, so the existence of a triple of such an ID must be
/// checked before using it.
pub fn generate_triple_id(me: ParticipantId) -> u64 {
    (rand::random::<u64>() >> 12) | ((me.0 as u64) << 52)
}

/// Generates a cait-sith triple.
pub async fn run_many_triple_generation<const N: usize>(
    channel: NetworkTaskChannel,
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<Vec<TripleGenerationOutput<Secp256k1>>> {
    let cs_participants = participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::triples::generate_triple_many::<Secp256k1, N>(
        &cs_participants,
        me.into(),
        threshold,
    )?;
    let triples = run_protocol("many triple gen", channel, participants, me, protocol).await?;
    metrics::MPC_NUM_TRIPLES_GENERATED.inc_by(N as u64);
    Ok(triples)
}

pub struct SimpleTripleStore {
    my_triples_receiver: flume::Receiver<(u64, TripleGenerationOutput<Secp256k1>)>,
    my_triples_sender: flume::Sender<(u64, TripleGenerationOutput<Secp256k1>)>,
    their_triples: Mutex<HashMap<u64, TripleGenerationOutput<Secp256k1>>>,
}

impl SimpleTripleStore {
    pub fn new() -> Self {
        let (my_triples_sender, my_triples_receiver) = flume::unbounded();
        Self {
            my_triples_receiver,
            my_triples_sender,
            their_triples: Mutex::new(HashMap::new()),
        }
    }

    pub fn my_triples_count(&self) -> usize {
        self.my_triples_receiver.len()
    }

    pub fn take_their_triple(&self, id: u64) -> anyhow::Result<TripleGenerationOutput<Secp256k1>> {
        self.their_triples
            .lock()
            .unwrap()
            .remove(&id)
            .ok_or_else(|| anyhow::anyhow!("Triple with ID {} not found in the triple store", id))
    }

    pub async fn take_my_triple(&self) -> anyhow::Result<(u64, TripleGenerationOutput<Secp256k1>)> {
        Ok(self
            .my_triples_receiver
            .recv_async()
            .await
            .context("Receiving triple from triple store")?)
    }

    pub fn add_my_triple(&self, id: u64, triple: TripleGenerationOutput<Secp256k1>) {
        self.my_triples_sender
            .send((id, triple))
            .expect("Sending triple to triple store");
    }

    pub fn add_their_triple(&self, id: u64, triple: TripleGenerationOutput<Secp256k1>) {
        self.their_triples.lock().unwrap().insert(id, triple);
    }
}

pub const SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE: usize = 64;

pub async fn run_background_triple_generation(
    client: Arc<MeshNetworkClient>,
    threshold: usize,
    config: Arc<TripleConfig>,
    triple_store: Arc<SimpleTripleStore>,
) -> anyhow::Result<()> {
    // Start with unix epoch millis timestamp as the ID, as that is unlikely to
    // collide with what we've used so far.
    let mut next_id_to_use = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH")
        .as_millis() as u64
        + ((client.my_participant_id().0 as u64) << 52);
    let in_flight_generations = InFlightGenerationTracker::new();
    let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    loop {
        let my_triples_count = triple_store.my_triples_count();
        metrics::MPC_OWNED_NUM_TRIPLES_AVAILABLE.set(my_triples_count as i64);
        if my_triples_count + in_flight_generations.num_in_flight()
            < config.desired_triples_to_buffer
        {
            let id_start = next_id_to_use;
            let id_end = next_id_to_use + SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u64;
            next_id_to_use = id_end;
            let task_id = crate::primitives::MpcTaskId::ManyTriples {
                start: id_start,
                end: id_end,
            };
            let channel = client.new_channel_for_task(task_id)?;
            let in_flight = in_flight_generations.in_flight(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE);
            let client = client.clone();
            let parallelism_limiter = parallelism_limiter.clone();
            let triple_store = triple_store.clone();
            tracking::spawn_checked(&format!("{:?}", task_id), async move {
                let _in_flight = in_flight;
                let _semaphore_guard = parallelism_limiter.acquire().await?;
                let triples = run_many_triple_generation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE>(
                    channel,
                    client.all_participant_ids(),
                    client.my_participant_id(),
                    threshold,
                )
                .await?;
                for (i, triple) in triples.into_iter().enumerate() {
                    triple_store.add_my_triple(id_start + i as u64, triple);
                }

                anyhow::Ok(())
            });
        } else {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

struct InFlightGenerationTracker {
    generations_in_flight: Arc<AtomicUsize>,
}

impl InFlightGenerationTracker {
    pub fn new() -> Self {
        Self {
            generations_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn in_flight(&self, count: usize) -> InFlightGenerations {
        InFlightGenerations::new(self.generations_in_flight.clone(), count)
    }

    pub fn num_in_flight(&self) -> usize {
        self.generations_in_flight
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

struct InFlightGenerations {
    generations_in_flight: Arc<AtomicUsize>,
    count: usize,
}

impl InFlightGenerations {
    pub fn new(generations_in_flight: Arc<AtomicUsize>, count: usize) -> Self {
        generations_in_flight.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        Self {
            generations_in_flight,
            count,
        }
    }
}

impl Drop for InFlightGenerations {
    fn drop(&mut self) {
        self.generations_in_flight
            .fetch_sub(self.count, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tracing::init_logging;
    use cait_sith::triples::TripleGenerationOutput;
    use futures::{stream, StreamExt, TryStreamExt};
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    use super::{generate_triple_id, run_triple_generation};
    use crate::tracking;

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_TO_GENERATE_PER_CLIENT: usize = 10;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_triple_generation() {
        init_logging();
        tracking::testing::start_root_task_with_periodic_dump(async {
            run_test_clients(NUM_PARTICIPANTS, run_triple_gen_client)
                .await
                .unwrap();
        })
        .await;
    }

    async fn run_triple_gen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<Vec<TripleGenerationOutput<Secp256k1>>> {
        {
            let client = client.clone();
            let participant_id = client.my_participant_id();
            let all_participant_ids = client.all_participant_ids();
            tracking::spawn("monitor passive channels", async move {
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    tracking::spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        run_triple_generation(
                            channel,
                            all_participant_ids.clone(),
                            participant_id,
                            THRESHOLD,
                        ),
                    );
                }
            });
        }

        let triples = stream::iter(0..TRIPLES_TO_GENERATE_PER_CLIENT)
            .map(move |_| {
                let client = client.clone();
                async move {
                    let participant_id = client.my_participant_id();
                    let all_participant_ids = client.all_participant_ids();
                    let task_id = MpcTaskId::Triple(generate_triple_id(participant_id));
                    let result = tracking::spawn_checked(
                        &format!("task {:?}", task_id),
                        run_triple_generation(
                            client.new_channel_for_task(task_id)?,
                            all_participant_ids.clone(),
                            participant_id,
                            THRESHOLD,
                        ),
                    )
                    .await??;
                    anyhow::Ok(result)
                }
            })
            .buffered(PARALLELISM_PER_CLIENT)
            .try_collect::<Vec<_>>()
            .await?;

        Ok(triples)
    }
}

#[cfg(test)]
mod tests_many {
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::tracing::init_logging;
    use cait_sith::triples::TripleGenerationOutput;
    use futures::{stream, StreamExt, TryStreamExt};
    use k256::Secp256k1;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    use super::{generate_triple_id, run_many_triple_generation};
    use crate::tracking;

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_PER_BATCH: usize = 10;
    const BATCHES_TO_GENERATE_PER_CLIENT: usize = 10;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_many_triple_generation() {
        init_logging();
        tracking::testing::start_root_task_with_periodic_dump(async {
            run_test_clients(NUM_PARTICIPANTS, run_triple_gen_client)
                .await
                .unwrap();
        })
        .await;
    }

    async fn run_triple_gen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<Vec<TripleGenerationOutput<Secp256k1>>> {
        {
            let client = client.clone();
            let participant_id = client.my_participant_id();
            let all_participant_ids = client.all_participant_ids();
            tracking::spawn("monitor passive channels", async move {
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    tracking::spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        run_many_triple_generation::<TRIPLES_PER_BATCH>(
                            channel,
                            all_participant_ids.clone(),
                            participant_id,
                            THRESHOLD,
                        ),
                    );
                }
            });
        }

        let triples = stream::iter(0..BATCHES_TO_GENERATE_PER_CLIENT)
            .map(move |_| {
                let client = client.clone();
                async move {
                    let participant_id = client.my_participant_id();
                    let all_participant_ids = client.all_participant_ids();
                    let task_id = MpcTaskId::Triple(generate_triple_id(participant_id));
                    let result = tracking::spawn_checked(
                        &format!("task {:?}", task_id),
                        run_many_triple_generation::<TRIPLES_PER_BATCH>(
                            client.new_channel_for_task(task_id)?,
                            all_participant_ids.clone(),
                            participant_id,
                            THRESHOLD,
                        ),
                    )
                    .await??;
                    anyhow::Ok(result)
                }
            })
            .buffered(PARALLELISM_PER_CLIENT)
            .try_collect::<Vec<_>>()
            .await?;

        Ok(triples.into_iter().flatten().collect())
    }
}
