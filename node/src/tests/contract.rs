use super::TestGenerators;
use crate::hkdf::derive_public_key;
use crate::indexer::response::ChainRespondArgs;
use crypto_shared::kdf::check_ec_signature;
use crypto_shared::ScalarExt;
use k256::Scalar;
use rand::thread_rng;

#[test]
fn test_recover_with_contract() {
    let mut success = 0;
    for _ in 0..100 {
        let gen = TestGenerators::new(3, 2);
        let keygens = gen.make_keygens();
        let triple0s = gen.make_triples();
        let triple1s = gen.make_triples();
        let presignatures = gen.make_presignatures(&triple0s, &triple1s, &keygens);
        let tweak = Scalar::generate_vartime(&mut thread_rng());

        let root_pubkey = keygens.iter().next().unwrap().1.public_key;
        let hash: [u8; 32] = rand::random();
        let signature = gen.make_signature(
            &presignatures,
            root_pubkey,
            tweak,
            Scalar::from_bytes(hash).unwrap(),
        );
        // let recovery_id =
        //     ChainRespondArgs::ecdsa_recovery_from_big_r(&signature.big_r, &signature.s);

        let msg_hash = Scalar::from_bytes(hash).unwrap();
        let pubkey = derive_public_key(root_pubkey, tweak);

        let recovery_id =
            ChainRespondArgs::brute_force_recovery_id(&pubkey, &signature, &msg_hash).unwrap();

        if check_ec_signature(
            &pubkey,
            &signature.big_r,
            &signature.s,
            msg_hash,
            recovery_id,
        )
        .is_ok()
        {
            success += 1;
        }
    }
    assert_eq!(success, 100);
}
