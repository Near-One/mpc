use crate::primitives::ParticipantId;
use hex_literal::hex;
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_contract::crypto_shared::ScalarExt;
use sha3::Sha3_256;

/// The following salt is picked by hashing with sha256
/// "NEAR 6.4478$ 7:20pm CEST 2024-11-24"
/// Based on [Krawczyk10] paper:
/// ``[...] in most applications the extractor key (or salt) can be used
/// repeatedly with many (independent) samples from the same source [...]''
const SALT: [u8; 32] = hex!("328a47c2b8794445255c1647608df5db85c68bb0e7170abec534df2764a45831");

/// Derives a random string from the public key, message hash, presignature R,
/// set of participants and the entropy
pub fn derive_randomness(
    pk: AffinePoint,
    msg_hash: Scalar,
    big_r: AffinePoint,
    mut participants: Vec<ParticipantId>,
    entropy: [u8; 32],
) -> Scalar {
    // create a string containing (pk, msg_hash, big_r, sorted(participants))
    let pk_encoded_point = pk.to_encoded_point(true);
    let encoded_pk: &[u8] = pk_encoded_point.as_bytes();
    let encoded_msg_hash: &[u8] = &msg_hash.to_bytes()[..];
    let big_r_encoded_point = big_r.to_encoded_point(true);
    let encoded_big_r: &[u8] = big_r_encoded_point.as_bytes();
    participants.sort_by_key(|p| p.raw()); // sort participants

    // concatenate all the bytes
    let mut concatenation = Vec::new();
    concatenation.extend_from_slice(encoded_pk);
    concatenation.extend_from_slice(encoded_msg_hash);
    concatenation.extend_from_slice(encoded_big_r);
    // Append each ParticipantId's
    for participant in participants {
        let participant_bytes = participant.raw().to_be_bytes();
        concatenation.extend_from_slice(&participant_bytes);
    }

    // initiate hkdf with the salt and with some `good' entropy
    let hk = Hkdf::<Sha3_256>::new(Some(&SALT), &entropy);

    let mut delta: Scalar = Scalar::ZERO;
    // If the randomness created is 0 then we want to generate a new randomness
    while bool::from(delta.is_zero()) {
        // Generate randomization out of HKDF(entropy, pk, msg_hash, big_r, participants, nonce)
        // where entropy is a public but unpredictable random string
        // the nonce is a succession of appended ones of growing length depending on the number of times
        // we enter into this loop
        let mut okm = [0u8; 32];

        // append an extra 0 at the end of the concatenation everytime delta hits zero
        concatenation.extend_from_slice(&[0u8, 1]);
        hk.expand(&concatenation, &mut okm).unwrap();

        // derive the randomness delta
        delta = Scalar::from_bytes(okm).unwrap_or(
            // if delta falls outside the field
            // probability is negligible: in the order of 1/2^224
            Scalar::ZERO,
        )
    }
    delta
}

/// Derives a public key from a tweak and a master public key by computing PK + [tweak] G
pub fn derive_public_key(public_key: AffinePoint, tweak: Scalar) -> AffinePoint {
    (AffinePoint::GENERATOR * tweak + public_key).to_affine()
}

// Test with a couple of different input values the randomness are also different.
#[cfg(test)]
mod derive_tests {
    use super::*;
    use rand::{rngs::OsRng, seq::SliceRandom, thread_rng, Rng};
    use std::collections::HashSet;

    fn compute_random_outputs(
        num_participants: usize,
    ) -> (
        AffinePoint,
        AffinePoint,
        Scalar,
        Vec<ParticipantId>,
        [u8; 32],
        Scalar,
    ) {
        let sk = Scalar::generate_vartime(&mut OsRng);
        let pk = AffinePoint::from(AffinePoint::GENERATOR * sk);
        let r = Scalar::generate_vartime(&mut OsRng);
        let big_r = AffinePoint::from(AffinePoint::GENERATOR * r);
        let msg_hash = Scalar::generate_vartime(&mut OsRng);
        // Generate unique ten ParticipantId values
        let mut rng = thread_rng();
        let mut participants_set = HashSet::new();
        while participants_set.len() < num_participants {
            participants_set.insert(ParticipantId::from_raw(rng.gen()));
        }
        let participants: Vec<ParticipantId> = participants_set.into_iter().collect();
        let entropy: [u8; 32] = rng.gen();

        let delta = derive_randomness(pk, msg_hash, big_r, participants.clone(), entropy);

        (pk, big_r, msg_hash, participants, entropy, delta)
    }

    #[test]
    fn test_different_msg_hash() {
        let num_participants = 10;
        let (pk, big_r, _, participants, entropy, delta) = compute_random_outputs(num_participants);

        // different msg_hash
        let msg_hash_prime = Scalar::generate_vartime(&mut OsRng);
        let delta_prime =
            derive_randomness(pk, msg_hash_prime, big_r, participants.clone(), entropy);

        assert!(delta != delta_prime);
    }

    #[test]
    fn test_different_big_r() {
        let num_participants = 10;
        let (pk, _, msg_hash, participants, entropy, delta) =
            compute_random_outputs(num_participants);
        // different big_r
        let r_prime = Scalar::generate_vartime(&mut OsRng);
        let big_r_prime = AffinePoint::from(AffinePoint::GENERATOR * r_prime);
        let delta_prime =
            derive_randomness(pk, msg_hash, big_r_prime, participants.clone(), entropy);
        assert!(delta != delta_prime);
    }

    #[test]
    fn test_different_pk() {
        let num_participants = 10;
        let (_, big_r, msg_hash, participants, entropy, delta) =
            compute_random_outputs(num_participants);
        // different pk
        let sk_prime = Scalar::generate_vartime(&mut OsRng);
        let pk_prime = AffinePoint::from(AffinePoint::GENERATOR * sk_prime);
        let delta_prime =
            derive_randomness(pk_prime, msg_hash, big_r, participants.clone(), entropy);
        assert!(delta != delta_prime);
    }

    #[test]
    fn test_different_participants() {
        let num_participants = 10;
        let (pk, big_r, msg_hash, _, entropy, delta) = compute_random_outputs(num_participants);
        // different participants set
        let mut rng = thread_rng();
        let mut participants_set_prime = HashSet::new();
        while participants_set_prime.len() < num_participants {
            participants_set_prime.insert(ParticipantId::from_raw(rng.gen()));
        }
        let participants_prime: Vec<ParticipantId> = participants_set_prime.into_iter().collect();
        let delta_prime =
            derive_randomness(pk, msg_hash, big_r, participants_prime.clone(), entropy);
        assert!(delta != delta_prime);
    }

    #[test]
    fn test_different_entropy() {
        let num_participants = 10;
        let (pk, big_r, msg_hash, participants, _, delta) =
            compute_random_outputs(num_participants);

        // different entropy
        let mut rng = thread_rng();
        let entropy_prime: [u8; 32] = rng.gen();
        let delta_prime =
            derive_randomness(pk, msg_hash, big_r, participants.clone(), entropy_prime);
        print!("{:?}", delta);
        print!("{:?}", delta_prime);
        assert!(delta != delta_prime);
    }

    // Test that with different order of participants, the randomness is the same.
    #[test]
    fn test_same_randomness() {
        let num_participants = 10;
        let (pk, big_r, msg_hash, mut participants, entropy, delta) =
            compute_random_outputs(num_participants);

        let mut rng = thread_rng();
        participants.shuffle(&mut rng);
        let delta_prime = derive_randomness(pk, msg_hash, big_r, participants, entropy);
        assert!(delta == delta_prime);
    }
}
