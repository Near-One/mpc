use super::participants::{ParticipantId, Participants};
use k256::sha2::{Digest, Sha256};

/// Computes the leader selection order for a given signature request.
/// This will be a different pseudorandom order for each signature request.
pub fn leaders(participants: &Participants, uid: u64) -> Vec<ParticipantId> {
    let mut leader_selection_hashes = participants
        .ids()
        .iter()
        .map(|p| (leader_selection_hash(p, uid), p.clone()))
        .collect::<Vec<_>>();
    leader_selection_hashes.sort();
    leader_selection_hashes
        .into_iter()
        .map(|(_, p)| p)
        .collect()
}

fn leader_selection_hash(participant_id: &ParticipantId, uid: u64) -> u64 {
    let mut h = Sha256::new();
    h.update(participant_id.get().to_le_bytes());
    h.update(uid.to_le_bytes());
    let hash: [u8; 32] = h.finalize().into();
    u64::from_le_bytes(hash[0..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use crate::primitives::participants::ParticipantId;
    use crate::primitives::test_utils::gen_participants;
    use rand::{thread_rng, Rng};
    use std::collections::BTreeSet;

    use super::leaders;
    #[test]
    fn test_leaders() {
        let n = thread_rng().gen_range(2..800);
        let participants = gen_participants(n);
        let uid = thread_rng().gen();
        let leaders_1 = leaders(&participants, uid);
        let mut considered: BTreeSet<ParticipantId> = BTreeSet::new();
        for id in &leaders_1 {
            assert!(participants.account_id(id).is_ok());
            considered.insert(id.clone());
        }
        assert_eq!(considered.len(), n);
        let leaders_2 = leaders(&participants, uid + 1);
        assert_ne!(leaders_1, leaders_2);
    }
}
