use crate::{
    crypto_shared::types::PublicKeyExtended,
    primitives::{
        participants::{ParticipantInfo, Participants},
        thresholds::{Threshold, ThresholdParameters},
    },
};
use curve25519_dalek::EdwardsPoint;
use k256::elliptic_curve::Group;
use near_sdk::{AccountId, CurveType, PublicKey};
use rand::{distributions::Uniform, Rng};
use std::collections::BTreeMap;

pub fn bogus_ed25519_public_key_extended() -> PublicKeyExtended {
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

pub fn bogus_ed25519_near_public_key() -> PublicKey {
    bogus_ed25519_public_key_extended().into()
}

#[test]
fn test_random_public_key() {
    let pk1 = bogus_ed25519_near_public_key();
    let pk2 = bogus_ed25519_near_public_key();
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
            sign_pk: bogus_ed25519_near_public_key(),
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
