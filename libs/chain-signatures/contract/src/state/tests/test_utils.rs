use crate::state::participants::ParticipantInfoV2;
use near_sdk::{AccountId, PublicKey};
use rand::{distributions::Uniform, Rng};
use std::collections::BTreeMap;

fn dummy_participant(i: usize) -> (AccountId, ParticipantInfoV2) {
    let lower_case = Uniform::new_inclusive(b'a', b'z');
    let random_string: String = rand::thread_rng()
        .sample_iter(&lower_case)
        .take(12)
        .map(char::from)
        .collect();
    let ed: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
        .parse()
        .unwrap();
    let account_id: String = format!("dummy_participant.{}.account.{}", i, random_string);
    let account_id: AccountId = account_id.parse().unwrap();
    (
        account_id,
        ParticipantInfoV2 {
            url: format!("near{}", i),
            cipher_pk: [0u8; 32],
            sign_pk: ed,
        },
    )
}

pub fn dummy_participants(n: usize) -> BTreeMap<AccountId, ParticipantInfoV2> {
    (0..n).map(dummy_participant).collect()
}
