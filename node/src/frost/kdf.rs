//! Key Derivation Function for Frost keys.
//!
//! The general idea is that we have a `tweak` – some value, e.g. associated with a user.
//! This value can be translated into Field scalar.
//! Then the mapping functions are following:
//! ```
//! secret_key' = kdf(secret_key, tweak) = secret_key + tweak
//! public_key' = kdf(public_key) = public_key + G * tweak
//! ```
//! Where G – group generator.
//!
//! The only difference between cait_sith format kdf is that
//! secret shares also have `frost_ed25519::keys::VerifiableSecretSharingCommitment`.
//! Which is used inside frost to test the following invariant:
//! ```
//!     let f_result = <C::Group>::generator() * self.signing_share.to_scalar();
//!     let result = evaluate_vss(self.identifier, &self.commitment);
//!     assert!(f_result == result);
//! ```
//!
//! VSSC – is coefficients of a polynomial `G * f(x)`.
//! After adding a tweak, `f_result` is now `G * f(x_i) + G * tweak`.
//! Thus, to hold the mentioned property we have to adjust the constant term of a polynomial:
//! `VSSC[0] += G * tweak`
use frost_core::Group;
use std::collections::BTreeMap;
use crate::frost;

pub fn derive_keygen_output(keygen_output: &frost::KeygenOutput, tweak: [u8; 32]) -> frost::KeygenOutput {
    frost::KeygenOutput {
        key_package: derive_key_package(&keygen_output.key_package, tweak),
        public_key_package: derive_public_key_package(&keygen_output.public_key_package, tweak),
    }
}

fn derive_key_package(
    key_package: &frost_ed25519::keys::KeyPackage,
    tweak: [u8; 32],
) -> frost_ed25519::keys::KeyPackage {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak);
    frost_ed25519::keys::KeyPackage::new(
        *key_package.identifier(),
        derive_signing_share(*key_package.signing_share(), tweak),
        derive_verifying_share(*key_package.verifying_share(), tweak),
        derive_verifying_key(*key_package.verifying_key(), tweak),
        *key_package.min_signers(),
    )
}

pub fn derive_public_key_package(
    pubkey_package: &frost_ed25519::keys::PublicKeyPackage,
    tweak: [u8; 32],
) -> frost_ed25519::keys::PublicKeyPackage {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak);
    let verifying_shares: BTreeMap<frost_ed25519::Identifier, frost_ed25519::keys::VerifyingShare> =
        pubkey_package
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

#[cfg(test)]
mod tests {
    use crate::frost::kdf::{derive_key_package, derive_public_key_package};
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
        // let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak);

        let derived_pubkey_package =
            derive_public_key_package(&pubkey_package, tweak);
        let derived_key_packages: BTreeMap<frost_ed25519::Identifier, frost_ed25519::keys::KeyPackage> =
            shares
                .into_iter()
                .map(|(id, share)| {
                    let key_package = frost_ed25519::keys::KeyPackage::try_from(share).unwrap();
                    (id, derive_key_package(&key_package, tweak))
                })
                .collect();
        
        let mut nonces_map = BTreeMap::new();
        let mut commitments_map = BTreeMap::new();

        for participant_index in 1..=min_signers {
            let participant_identifier = participant_index.try_into().expect("should be nonzero");
            let key_package = &derived_key_packages[&participant_identifier];
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
