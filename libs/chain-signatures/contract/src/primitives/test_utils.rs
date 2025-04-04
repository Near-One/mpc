use crate::crypto_shared::types::PublicKeyExtended;
use crate::legacy_contract_state::{self, CandidateInfo};
use crate::primitives::{
    participants::{ParticipantInfo, Participants},
    thresholds::{Threshold, ThresholdParameters},
};
use curve25519_dalek::EdwardsPoint;
use k256::elliptic_curve::Group;
use near_sdk::{AccountId, CurveType, PublicKey};
use rand::{distributions::Uniform, Rng};
use std::collections::{BTreeMap, HashSet};

pub fn bogus_edd25519_public_key_extended() -> PublicKeyExtended {
    let rng = rand::thread_rng();

    let edwards_point = EdwardsPoint::random(rng);
    let compressed_edwards_point = edwards_point.compress();
    let near_public_key_compressed = PublicKey::from_parts(
        CurveType::ED25519,
        compressed_edwards_point.as_bytes().into(),
    )
    .unwrap();

    PublicKeyExtended::Ed25519 {
        near_public_key_compressed,
        edwards_point,
    }
}

pub fn bogus_edd25519_near_public_key() -> PublicKey {
    bogus_edd25519_public_key_extended().into()
}

#[test]
fn test_random_public_key() {
    let pk1 = bogus_edd25519_near_public_key();
    let pk2 = bogus_edd25519_near_public_key();
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
            sign_pk: bogus_edd25519_near_public_key(),
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

pub fn gen_legacy_participants(n: usize) -> legacy_contract_state::Participants {
    // ensure random indices
    let mut legacy_participants = legacy_contract_state::Participants::new();
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

pub fn gen_legacy_candidates(n: usize) -> legacy_contract_state::Candidates {
    pub fn candidates(names: Vec<AccountId>) -> BTreeMap<AccountId, CandidateInfo> {
        let mut candidates: BTreeMap<AccountId, CandidateInfo> = BTreeMap::new();
        for (i, account_id) in names.iter().enumerate() {
            candidates.insert(
                account_id.clone(),
                CandidateInfo {
                    account_id: account_id.clone(),
                    url: format!("127.0.0.1:{}", i),
                    cipher_pk: [0; 32],
                    sign_pk: bogus_edd25519_near_public_key(),
                },
            );
        }
        candidates
    }
    let accounts: Vec<AccountId> = (0..n).map(|_| gen_account_id()).collect();
    legacy_contract_state::Candidates {
        candidates: candidates(accounts),
    }
}

pub fn gen_seed() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    seed
}

pub fn gen_threshold_params(max_n: usize) -> ThresholdParameters {
    let n: usize = rand::thread_rng().gen_range(2..max_n + 1);
    let k_min = min_thrershold(n);
    let k = rand::thread_rng().gen_range(k_min..n + 1);
    ThresholdParameters::new(gen_participants(n), Threshold::new(k as u64)).unwrap()
}

pub fn gen_legacy_initializing_state(
    n: usize,
    k: usize,
) -> legacy_contract_state::InitializingContractState {
    let candidates = gen_legacy_candidates(n);
    let mut pk_votes = legacy_contract_state::PkVotes::new();
    let n_pk_votes = rand::thread_rng().gen_range(0..k);
    let n_pks = match n_pk_votes {
        0 => 0,
        1 => 1,
        _ => rand::thread_rng().gen_range(1..n_pk_votes),
    };
    let pks: Vec<PublicKey> = (0..n_pks)
        .map(|_| bogus_edd25519_near_public_key())
        .collect();
    for i in 0..n_pk_votes {
        let pk_id = i % n_pks;
        let pk = pks[pk_id].clone();
        let (account_id, _) = candidates.candidates.iter().nth(i).unwrap();
        pk_votes.entry(pk).insert(account_id.clone());
    }
    legacy_contract_state::InitializingContractState {
        candidates,
        threshold: (k),
        pk_votes,
    }
}
pub fn gen_legacy_running_state(n: usize, k: usize) -> legacy_contract_state::RunningContractState {
    legacy_contract_state::RunningContractState {
        epoch: rand::thread_rng().gen(),
        participants: gen_legacy_participants(n),
        threshold: k,
        public_key: bogus_edd25519_near_public_key(),
        candidates: gen_legacy_candidates(rand::thread_rng().gen_range(0..n + 5)),
        join_votes: legacy_contract_state::Votes::default(),
        leave_votes: legacy_contract_state::Votes::default(),
    }
}
pub fn gen_legacy_resharing_state(
    n: usize,
    k: usize,
) -> legacy_contract_state::ResharingContractState {
    legacy_contract_state::ResharingContractState {
        old_epoch: rand::thread_rng().gen(),
        old_participants: gen_legacy_participants(n),
        new_participants: gen_legacy_participants(n),
        threshold: k,
        public_key: bogus_edd25519_near_public_key(),
        finished_votes: HashSet::new(),
    }
}
