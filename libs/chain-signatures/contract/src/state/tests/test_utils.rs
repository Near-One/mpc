use crate::primitives::participants::{ParticipantInfo, Participants};
use legacy_contract::primitives::CandidateInfo;
use near_sdk::{AccountId, CurveType, PublicKey};
use rand::{distributions::Uniform, Rng};
use std::collections::BTreeMap;

pub fn gen_rand_pk() -> PublicKey {
    let mut rng = rand::thread_rng();
    let key_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect(); // Generate 32 random bytes
    PublicKey::from_parts(CurveType::ED25519, key_bytes).unwrap()
}
#[test]
fn test_random_public_key() {
    let pk1 = gen_rand_pk();
    let pk2 = gen_rand_pk();
    assert_ne!(pk1, pk2, "Random keys should be different");
}
pub fn gen_rand_account_id() -> AccountId {
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
    let acc1 = gen_rand_account_id();
    let acc2 = gen_rand_account_id();
    assert_ne!(acc1, acc2, "Random keys should be different");
}

pub fn gen_participant(i: usize) -> (AccountId, ParticipantInfo) {
    (
        gen_rand_account_id(),
        ParticipantInfo {
            url: format!("near{}", i),
            cipher_pk: [0u8; 32],
            sign_pk: gen_rand_pk(),
        },
    )
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
                    sign_pk: gen_rand_pk(),
                },
            );
        }
        candidates
    }
    let accounts: Vec<AccountId> = (0..n).map(|_| gen_rand_account_id()).collect();
    legacy_contract::primitives::Candidates {
        candidates: candidates(accounts),
    }
}
