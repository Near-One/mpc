use crate::primitives::ParticipantId;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;

/// Tracks the block height of the indexer of each participant.
pub struct IndexerHeightTracker {
    /// Keys are readonly; values are updated atomically.
    pub heights: HashMap<ParticipantId, AtomicU64>,
}

impl IndexerHeightTracker {
    pub fn new(participants: &[ParticipantId]) -> Self {
        let mut heights = HashMap::new();
        for participant in participants {
            heights.insert(*participant, AtomicU64::new(0));
        }
        Self { heights }
    }

    pub fn set_height(&self, participant: ParticipantId, height: u64) {
        let atomic = self.heights.get(&participant).unwrap();
        let current = atomic.load(std::sync::atomic::Ordering::Relaxed);
        if height > current {
            atomic.store(height, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn get_heights(&self) -> HashMap<ParticipantId, u64> {
        self.heights
            .iter()
            .map(|(participant, height)| {
                (
                    *participant,
                    height.load(std::sync::atomic::Ordering::Relaxed),
                )
            })
            .collect()
    }
}
