use crate::primitives::key_state::{AttemptId, EpochId};
use crate::primitives::participants::{ParticipantInfo, Participants};
use crate::primitives::thresholds::Threshold;
use crate::primitives::{key_state::KeyEventId, thresholds::ThresholdParameters};
use legacy_contract::primitives::CandidateInfo;
use near_sdk::{AccountId, CurveType, PublicKey};
use rand::{distributions::Uniform, Rng};
use std::collections::{BTreeMap, HashSet};

pub fn gen_pk() -> PublicKey {
    let mut rng = rand::thread_rng();
    let key_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect(); // Generate 32 random bytes
    PublicKey::from_parts(CurveType::ED25519, key_bytes).unwrap()
}

#[test]
fn test_random_public_key() {
    let pk1 = gen_pk();
    let pk2 = gen_pk();
    assert_ne!(pk1, pk2, "Random keys should be different");
}

pub fn gen_account_id() -> AccountId {
    let lower_case = Uniform::new_inclusive(b'a', b'z');
    let random_string: String = rand::thread_rng()
        .sample_iter(&lower_case)
        .take(12)
        .map(char::from)
        .collect();
    let account_id: String = format!("dummy.account.{}", random_string);
    account_id.parse().unwrap()
}

#[test]
fn test_random_account_id() {
    let acc1 = gen_account_id();
    let acc2 = gen_account_id();
    assert_ne!(acc1, acc2, "Random keys should be different");
}

pub fn gen_participant(i: usize) -> (AccountId, ParticipantInfo) {
    (
        gen_account_id(),
        ParticipantInfo {
            url: format!("near{}", i),
            cipher_pk: [0u8; 32],
            sign_pk: gen_pk(),
        },
    )
}

pub fn min_thrershold(n: usize) -> usize {
    ((n as f64) * 0.6).ceil() as usize
}

pub fn gen_accounts_and_info(n: usize) -> BTreeMap<AccountId, ParticipantInfo> {
    (0..n).map(gen_participant).collect()
}

pub fn gen_participants(n: usize) -> Participants {
    let mut participants = Participants::new();
    for i in 0..n {
        let (account_id, info) = gen_participant(i);
        let _ = participants.insert(account_id, info);
    }
    participants
}

pub fn gen_legacy_participants(n: usize) -> legacy_contract::primitives::Participants {
    // ensure random indices
    let mut legacy_participants = legacy_contract::primitives::Participants::new();
    legacy_participants.next_id = rand::thread_rng().gen_range(0..1000000);
    let legacy_candidate = gen_legacy_candidates(n);
    for (i, (account_id, info)) in legacy_candidate.candidates.iter().enumerate() {
        if i % 2 == 1 {
            legacy_participants.insert(account_id.clone(), info.clone().into());
        }
    }
    for (i, (account_id, info)) in legacy_candidate.candidates.iter().enumerate() {
        if i % 2 != 1 {
            legacy_participants.insert(account_id.clone(), info.clone().into());
        }
    }
    legacy_participants
}

pub fn gen_legacy_candidates(n: usize) -> legacy_contract::primitives::Candidates {
    pub fn candidates(names: Vec<AccountId>) -> BTreeMap<AccountId, CandidateInfo> {
        let mut candidates: BTreeMap<AccountId, CandidateInfo> = BTreeMap::new();
        for (i, account_id) in names.iter().enumerate() {
            candidates.insert(
                account_id.clone(),
                CandidateInfo {
                    account_id: account_id.clone(),
                    url: format!("127.0.0.1:{}", i),
                    cipher_pk: [0; 32],
                    sign_pk: gen_pk(),
                },
            );
        }
        candidates
    }
    let accounts: Vec<AccountId> = (0..n).map(|_| gen_account_id()).collect();
    legacy_contract::primitives::Candidates {
        candidates: candidates(accounts),
    }
}

pub fn gen_seed() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    seed
}

pub fn gen_key_event_id() -> KeyEventId {
    let epoch_id: u64 = rand::thread_rng().gen();
    KeyEventId::new(EpochId::new(epoch_id), AttemptId::new())
}

pub fn gen_threshold_params(max_n: usize) -> ThresholdParameters {
    let n = rand::thread_rng().gen_range(2..max_n + 1);
    let k_min = min_thrershold(n);
    let k = rand::thread_rng().gen_range(k_min..n + 1);
    ThresholdParameters::new(gen_participants(n), Threshold::new(k as u64)).unwrap()
}

pub fn gen_legacy_initializing_state(
    n: usize,
    k: usize,
) -> legacy_contract::InitializingContractState {
    let candidates = gen_legacy_candidates(n);
    let mut pk_votes = legacy_contract::primitives::PkVotes::new();
    let n_pk_votes = rand::thread_rng().gen_range(0..k);
    let n_pks = match n_pk_votes {
        0 => 0,
        1 => 1,
        _ => rand::thread_rng().gen_range(1..n_pk_votes),
    };
    let pks: Vec<PublicKey> = (0..n_pks).map(|_| gen_pk()).collect();
    for i in 0..n_pk_votes {
        let pk_id = i % n_pks;
        let pk = pks[pk_id].clone();
        let (account_id, _) = candidates.candidates.iter().nth(i).unwrap();
        pk_votes.entry(pk).insert(account_id.clone());
    }
    legacy_contract::InitializingContractState {
        candidates,
        threshold: (k),
        pk_votes,
    }
}
pub fn gen_legacy_running_state(n: usize, k: usize) -> legacy_contract::RunningContractState {
    legacy_contract::RunningContractState {
        epoch: rand::thread_rng().gen(),
        participants: gen_legacy_participants(n),
        threshold: k,
        public_key: gen_pk(),
        candidates: gen_legacy_candidates(rand::thread_rng().gen_range(0..n + 5)),
        join_votes: legacy_contract::primitives::Votes::default(),
        leave_votes: legacy_contract::primitives::Votes::default(),
    }
}
pub fn gen_legacy_resharing_state(n: usize, k: usize) -> legacy_contract::ResharingContractState {
    legacy_contract::ResharingContractState {
        old_epoch: rand::thread_rng().gen(),
        old_participants: gen_legacy_participants(n),
        new_participants: gen_legacy_participants(n),
        threshold: k,
        public_key: gen_pk(),
        finished_votes: HashSet::new(),
    }
}
