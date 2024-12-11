use crate::assets::{ProtocolsStorage, UniqueId};
use crate::background::InFlightGenerationTracker;
use crate::config::PresignatureConfig;
use crate::hkdf::{derive_public_key, derive_randomness};
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{participants_from_triples, ParticipantId, PresignOutputWithParticipants};
use crate::protocol::run_protocol;
use crate::tracking::AutoAbortTaskCollection;
use crate::triple::TripleStorage;
use crate::{metrics, tracking};
use cait_sith::protocol::Participant;
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::{FullSignature, KeygenOutput, PresignArguments, PresignOutput};
use k256::{Scalar, Secp256k1};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

/// Performs an MPC presignature operation. This is shared for the initiator
/// and for passive participants.
pub async fn pre_sign(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
    triple0: TripleGenerationOutput<Secp256k1>,
    triple1: TripleGenerationOutput<Secp256k1>,
    keygen_out: KeygenOutput<Secp256k1>,
) -> anyhow::Result<PresignOutput<Secp256k1>> {
    let cs_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::presign::<Secp256k1>(
        &cs_participants,
        me.into(),
        &cs_participants,
        me.into(),
        PresignArguments {
            triple0,
            triple1,
            keygen_out,
            threshold,
        },
    )?;
    let presignature = run_protocol("presign", channel, me, protocol).await?;
    metrics::MPC_NUM_PRESIGNATURES_GENERATED.inc();
    Ok(presignature)
}

/// Performs an MPC presignature operation. This is a helper function for the unowned
/// code path that also includes awaiting for the triples to be available.
#[allow(clippy::too_many_arguments)]
pub async fn pre_sign_unowned(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
    keygen_out: KeygenOutput<Secp256k1>,
    triple_store: Arc<TripleStorage>,
    paired_triple_id: UniqueId,
) -> anyhow::Result<PresignOutput<Secp256k1>> {
    let (triple0, triple1) = triple_store.take_unowned(paired_triple_id).await?;
    pre_sign(channel, me, threshold, triple0, triple1, keygen_out).await
}

/// Performs an MPC signature operation. This is the same for the initiator
/// and for passive participants.
/// The entropy is used to rerandomize the presignature (inspired by [GS21])
/// The tweak allows key derivation
pub async fn sign(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    keygen_out: KeygenOutput<Secp256k1>,
    presign_out: PresignOutput<Secp256k1>,
    msg_hash: Scalar,
    tweak: Scalar,
    entropy: [u8; 32],
) -> anyhow::Result<FullSignature<Secp256k1>> {
    let cs_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();

    let public_key = derive_public_key(keygen_out.public_key, tweak);

    // rerandomize the presignature: a variant of [GS21]
    let PresignOutput { big_r, k, sigma } = presign_out;
    let delta = derive_randomness(
        public_key,
        msg_hash,
        big_r,
        channel.participants.clone(),
        entropy,
    );
    // we use the default inversion: it is absolutely fine to use a
    // variable time inversion since delta is a public value
    let inverted_delta = delta.invert().unwrap();
    let presign_out = PresignOutput {
        // R' = [delta] R
        big_r: (big_r * delta).to_affine(),
        // k' = k/delta
        k: k * inverted_delta,
        // sigma = sigma/delta + k tweak/delta
        sigma: (sigma + tweak * k) * inverted_delta,
    };

    let protocol = cait_sith::sign::<Secp256k1>(
        &cs_participants,
        me.into(),
        public_key,
        presign_out,
        msg_hash,
    )?;
    let signature = run_protocol("sign", channel, me, protocol).await?;
    metrics::MPC_NUM_SIGNATURES_GENERATED.inc();
    Ok(signature)
}

pub type PresignatureStorage = ProtocolsStorage<PresignOutputWithParticipants>;

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
pub async fn run_background_presignature_generation(
    client: Arc<MeshNetworkClient>,
    threshold: usize,
    config: Arc<PresignatureConfig>,
    triple_store: Arc<TripleStorage>,
    presignature_store: Arc<PresignatureStorage>,
    keygen_out: KeygenOutput<Secp256k1>,
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
        let my_presignatures_count: usize = presignature_store.num_owned();
        metrics::MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE.set(my_presignatures_count as i64);
        if my_presignatures_count + in_flight_generations.num_in_flight()
            < config.desired_presignatures_to_buffer
            // There's no point to issue way too many in-flight computations, as they
            // will just be limited by the concurrency anyway.
            && in_flight_generations.num_in_flight()
                < config.concurrency * 2
        {
            let current_active_participants_ids = client.all_alive_participant_ids();
            if current_active_participants_ids.len() < threshold {
                // that should not happen often, so sleeping here is okay
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let id = presignature_store.generate_and_reserve_id();
            progress_tracker.set_waiting_for_triples(true);
            let (paired_triple_id, (triple0, triple1)) = triple_store
                .take_owned(&current_active_participants_ids)
                .await;
            progress_tracker.set_waiting_for_triples(false);
            let participants = participants_from_triples(&triple0, &triple1);
            let task_id = crate::primitives::MpcTaskId::Presignature {
                id,
                paired_triple_id,
            };
            let channel = client.new_channel_for_task(task_id, participants.clone())?;
            let in_flight = in_flight_generations.in_flight(1);
            let client = client.clone();
            let parallelism_limiter = parallelism_limiter.clone();
            let presignature_store = presignature_store.clone();
            let config_clone = config.clone();
            let keygen_out = keygen_out.clone();
            tasks.spawn_checked(&format!("{:?}", task_id), async move {
                let _in_flight = in_flight;
                let _semaphore_guard = parallelism_limiter.acquire().await?;
                let presignature = timeout(
                    Duration::from_secs(config_clone.timeout_sec),
                    pre_sign(
                        channel,
                        client.my_participant_id(),
                        threshold,
                        triple0,
                        triple1,
                        keygen_out,
                    ),
                )
                .await??;
                presignature_store.add_owned(
                    id,
                    PresignOutputWithParticipants {
                        presignature,
                        participants,
                    },
                );

                anyhow::Ok(())
            });
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
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

/// Simple ID generator for signatures. Generates monotonically increasing IDs.
/// Does not persist state across restarts, so if the clock rewinds then the
/// generated IDs can conflict with previously generated IDs.
#[allow(dead_code)]
pub struct SignatureIdGenerator {
    last_id: Mutex<UniqueId>,
}

#[allow(dead_code)]
impl SignatureIdGenerator {
    pub fn new(my_participant_id: ParticipantId) -> Self {
        Self {
            last_id: Mutex::new(UniqueId::generate(my_participant_id)),
        }
    }

    pub fn generate_signature_id(&self) -> UniqueId {
        let mut last_id = self.last_id.lock().unwrap();
        let new_id = last_id.pick_new_after();
        *last_id = new_id;
        new_id
    }
}
