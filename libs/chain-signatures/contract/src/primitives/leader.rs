use super::participants::{ParticipantId, Participants};
use k256::sha2::{Digest, Sha256};

/// Computes the leader selection order for a given signature request.
/// This will be a different pseudorandom order for each signature request.
pub fn leader(participants: &Participants, uid: u64) -> ParticipantId {
    let mut leader_selection_hashes = participants
        .ids()
        .iter()
        .map(|p| (leader_selection_hash(p, uid), p.clone()))
        .collect::<Vec<_>>();
    leader_selection_hashes.sort();
    let res: Vec<ParticipantId> = leader_selection_hashes
        .into_iter()
        .map(|(_, p)| p)
        .collect();
    res[0].clone()
}

fn leader_selection_hash(participant_id: &ParticipantId, uid: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(participant_id.get().to_le_bytes());
    h.update(uid.to_le_bytes());
    let hash: [u8; 32] = h.finalize().into();
    u64::from_le_bytes(hash[0..8].try_into().unwrap())
}
