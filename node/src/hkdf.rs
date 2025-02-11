use crate::primitives::ParticipantId;
use hex_literal::hex;
use hkdf::Hkdf;
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, sec1::ToEncodedPoint, PrimeField},
    AffinePoint, U256,
};
use near_indexer_primitives::types::AccountId;
use sha3::{Digest, Sha3_256};

// taken from previous implementation
pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
}

impl ScalarExt for k256::Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare (probability around 1/2^224) with random bytes as the field size is
    /// 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        k256::Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }
}

// The following salt is picked by hashing with sha256
// "NEAR 6.4478$ 7:20pm CEST 2024-11-24"
// Based on [Krawczyk10] paper:
// ``[...] in most applications the extractor key (or salt) can be used
// repeatedly with many (independent) samples from the same source [...]''

const SALT: [u8; 32] = hex!("328a47c2b8794445255c1647608df5db85c68bb0e7170abec534df2764a45831");

/// Derives a random string from the public key, message hash, presignature R,
/// set of participants and the entropy
pub fn derive_randomness(
    pk: AffinePoint,
    msg_hash: k256::Scalar,
    big_r: AffinePoint,
    mut participants: Vec<ParticipantId>,
    entropy: [u8; 32],
) -> k256::Scalar {
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

    let mut delta: k256::Scalar = k256::Scalar::ZERO;
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
        delta = match k256::Scalar::from_bytes(okm) {
            Some(delta) => delta,
            // if delta falls outside the field
            // probability is negligible: in the order of 1/2^224
            None => k256::Scalar::ZERO,
        }
    }
    delta
}

// TODO: Modify the following function and use instead hkdf.
// WARNING: DO NOT change anything before making sure that the legacy secret/public keys are also changed
// and stored signatures could still be verified.
const TWEAK_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

pub fn derive_tweak(predecessor_id: &AccountId, path: &str) -> k256::Scalar {
    // ',' is ACCOUNT_DATA_SEPARATOR from nearcore that indicate the end
    // of the accound id in the trie key. We reuse the same constant to
    // indicate the end of the account id in derivation path.
    // Do not reuse this hash function on anything that isn't an account
    // ID or it'll be vunerable to Hash Melleability/extention attacks.
    let derivation_path = format!("{TWEAK_DERIVATION_PREFIX}{},{}", predecessor_id, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path);
    let hash: [u8; 32] = hasher.finalize().into();
    k256::Scalar::from_bytes(hash).expect(
        "Expected hash of derived key to be in the
        field of size 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 ",
    )
}

/// Derives a public key from a tweak and a master public key by computing PK + [tweak] G
pub fn derive_public_key(public_key: AffinePoint, tweak: k256::Scalar) -> AffinePoint {
    (AffinePoint::GENERATOR * tweak + public_key).to_affine()
}

mod frost {
    /// The only difference between cait_sith format kdf is that secret shares also have `frost_ed25519::keys::VerifiableSecretSharingCommitment`.
    /// Which is used inside frost to test the following invariant: 
    /// ```
    ///     let f_result = <C::Group>::generator() * self.signing_share.to_scalar();
    ///     let result = evaluate_vss(self.identifier, &self.commitment);
    ///     assert!(f_result == result);
    /// ```
    ///
    /// VSSC – is coefficients of a polynomial `G * f(x)`.
    /// After adding a tweak, `f_result` is now `G * f(x_i) + G * tweak`.
    /// Thus, to hold the mentioned property we have to adjust the constant term of a polynomial:
    /// `VSSC[0] += G * tweak`
    use frost_core::Group;
    use std::collections::BTreeMap;
    type Tweak = [u8; 32];

    pub fn derive_secret_share(
        secret_share: &frost_ed25519::keys::SecretShare,
        tweak: Tweak,
    ) -> frost_ed25519::keys::SecretShare {
        let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak);
        frost_ed25519::keys::SecretShare::new(
            *secret_share.identifier(),
            derive_signing_share(*secret_share.signing_share(), tweak),
            derive_vssc(secret_share.commitment().clone(), tweak),
        )
    }

    pub fn derive_public_key_package(
        pubkey_package: &frost_ed25519::keys::PublicKeyPackage,
        tweak: Tweak,
    ) -> frost_ed25519::keys::PublicKeyPackage {
        let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak);

        let verifying_shares: BTreeMap<
            frost_ed25519::Identifier,
            frost_ed25519::keys::VerifyingShare,
        > = pubkey_package
            .verifying_shares()
            .iter()
            .map(|(&identifier, &share)| (identifier, derive_verifying_share(share, tweak)))
            .collect();
        let verifying_key: frost_ed25519::VerifyingKey =
            derive_verifying_key(*pubkey_package.verifying_key(), tweak);
        frost_ed25519::keys::PublicKeyPackage::new(verifying_shares, verifying_key)
    }

    fn add_tweak(
        point: curve25519_dalek::EdwardsPoint,
        tweak: curve25519_dalek::Scalar,
    ) -> curve25519_dalek::EdwardsPoint {
        point + frost_ed25519::Ed25519Group::generator() * tweak
    }

    fn derive_vssc(
        vssc: frost_ed25519::keys::VerifiableSecretSharingCommitment,
        tweak: curve25519_dalek::Scalar,
    ) -> frost_ed25519::keys::VerifiableSecretSharingCommitment {
        let mut result = vssc.coefficients().to_vec();
        result[0] =
            frost_core::keys::CoefficientCommitment::new(add_tweak(result[0].value(), tweak));
        frost_ed25519::keys::VerifiableSecretSharingCommitment::new(result)
    }

    fn derive_signing_share(
        signing_share: frost_ed25519::keys::SigningShare,
        tweak: curve25519_dalek::Scalar,
    ) -> frost_ed25519::keys::SigningShare {
        frost_ed25519::keys::SigningShare::new(tweak + signing_share.to_scalar())
    }

    fn derive_verifying_share(
        verifying_share: frost_ed25519::keys::VerifyingShare,
        tweak: curve25519_dalek::Scalar,
    ) -> frost_ed25519::keys::VerifyingShare {
        frost_ed25519::keys::VerifyingShare::new(add_tweak(verifying_share.to_element(), tweak))
    }

    fn derive_verifying_key(
        verifying_key: frost_ed25519::VerifyingKey,
        tweak: curve25519_dalek::Scalar,
    ) -> frost_ed25519::VerifyingKey {
        frost_ed25519::VerifyingKey::new(add_tweak(verifying_key.to_element(), tweak))
    }
}

#[cfg(test)]
mod frost_kdf_tests {
    use aes_gcm::aead::rand_core::RngCore;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    #[test]
    fn proof_of_concept() {
        // 1. Generate fresh Frost Keys
        // 2. Apply kdf
        // 3. Check that messsage can be signed (thus triggering all internal invariants checks)

        let mut rng = thread_rng();
        let max_signers = 9;
        let min_signers = 6;
        let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost_ed25519::keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

        let mut tweak = [0u8; 32];
        rng.fill_bytes(&mut tweak);

        let derived_pubkey_package =
            crate::hkdf::frost::derive_public_key_package(&pubkey_package, tweak);
        let derived_shares: BTreeMap<frost_ed25519::Identifier, frost_ed25519::keys::SecretShare> =
            shares
                .into_iter()
                .map(|(id, share)| (id, crate::hkdf::frost::derive_secret_share(&share, tweak)))
                .collect();

        let mut derived_key_packages: BTreeMap<_, _> = BTreeMap::new();

        for (identifier, secret_share) in derived_shares.clone() {
            let key_package = frost_ed25519::keys::KeyPackage::try_from(secret_share).unwrap();
            derived_key_packages.insert(identifier, key_package);
        }

        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for participant_index in 1..=min_signers {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let key_package = &derived_shares[&participant_identifier];
            let (nonces, commitments) =
                frost_ed25519::round1::commit(key_package.signing_share(), &mut rng);
            nonces_map.insert(participant_identifier, nonces);
            commitments_map.insert(participant_identifier, commitments);
        }

        let mut signature_shares = BTreeMap::new();
        let message = "message to sign".as_bytes();
        let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message);

        for participant_identifier in nonces_map.keys() {
            let key_package = &derived_key_packages[participant_identifier];
            let nonces = &nonces_map[participant_identifier];
            let signature_share =
                frost_ed25519::round2::sign(&signing_package, nonces, key_package).unwrap();
            signature_shares.insert(*participant_identifier, signature_share);
        }

        let group_signature =
            frost_ed25519::aggregate(&signing_package, &signature_shares, &derived_pubkey_package)
                .unwrap();

        let is_signature_valid = derived_pubkey_package
            .verifying_key()
            .verify(message, &group_signature)
            .is_ok();
        assert!(is_signature_valid);

        assert_ne!(
            pubkey_package.verifying_key(),
            derived_pubkey_package.verifying_key()
        )
    }
}

// Test with a couple of different input values the randomness are also different.
#[cfg(test)]
mod derive_tests {
    use super::*;
    use k256::Scalar;
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
