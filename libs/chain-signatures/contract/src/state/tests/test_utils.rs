use crate::state::participants::ParticipantInfo;
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

pub fn gen_participants(n: usize) -> BTreeMap<AccountId, ParticipantInfo> {
    (0..n).map(gen_participant).collect()
}
