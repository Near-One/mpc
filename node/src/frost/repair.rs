//! Wrapper for Frost `repair` algorithm:
//! Any subset of `>= threshold` participants can generate a secret share for another participant.
//! It's useful when:
//!     (a) participant lost their share
//!     (b) a new participant is introduced to the set (which after all the same as (a))
//!
//! Participants who help generate a share we call `helpers`.
//! Participant whose share is being repaired we call `target_participant`.
//!
//! As a result `target_participant` receives an instance of `KeygenOutput`.
//! As a result `helpers` receive updated `PublicKeyPackage`. Group's public key stays the same,
//!  but we have to update internally stored `verifying_shares` mapping which is updated with the new entry.
//!
//! Other participants, who didn't participate in repairing, have to update their `PublicKeyPackage` too.
//!
//! Algorithm:
//!     # Round 1. Helpers send deltas to each other, in order for each to generate a sigma value.
//!     # Round 2.
//!         1. Each helper send their sigma to the target.
//!         2. Target collects sigmas and build their `KeyPackage` (secret share).
//!     # Round 3.
//!         1. Each helper send their public package.
//!         3. Target collects it and builds `PublicKeyPackage`.
//!         2. Target sends updated `PublicKeyPackage` to helpers.
//!

use crate::frost::common::{collect_packages, distribute_packages};
use crate::frost::{to_frost_identifier, KeygenOutput};
use cait_sith::protocol::{Participant, ProtocolError, SharedChannel};
use frost_core::serialization::SerializableScalar;
use frost_core::Field;
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost_ed25519::{Group, Identifier};
use rand::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) mod target {
    use super::*;
    pub async fn do_repair(
        mut channel: SharedChannel,
        me: Participant,
        helpers: Vec<Participant>,
        threshold: usize,
    ) -> Result<KeygenOutput, ProtocolError> {
        // Round 2.

        let (signing_share, verifying_share) =
            handle_round2(&mut channel, helpers.as_slice()).await?;

        // Round 3.

        let mut public_key_package = collect_public_keys(&mut channel, helpers.as_slice())
            .await
            .map_err(|e| ProtocolError::AssertionFailed(format!("collect_public_keys: {:?}", e)))?;

        // Do verification and build a key pair.

        let frost_identifier_me = to_frost_identifier(me);

        verify_share_consistency(
            frost_identifier_me,
            verifying_share,
            public_key_package.verifying_shares(),
        )
        .map_err(|e| {
            ProtocolError::AssertionFailed(format!("verify_share_consistency: {:?}", e))
        })?;

        public_key_package = build_pubkey_with_updated_verifying_shares(
            &public_key_package,
            frost_identifier_me,
            verifying_share,
        );

        let verifying_key = *public_key_package.verifying_key();
        let key_package = KeyPackage::new(
            frost_identifier_me,
            signing_share,
            verifying_share,
            verifying_key,
            threshold as u16,
        );

        {
            let waitpoint = channel.next_waitpoint();
            channel.send_many(waitpoint, &verifying_share).await;
        }

        Ok(KeygenOutput {
            key_package,
            public_key_package,
        })
    }

    async fn handle_round2(
        channel: &mut SharedChannel,
        helpers: &[Participant],
    ) -> Result<(SigningShare, VerifyingShare), ProtocolError> {
        let sigmas: BTreeMap<Identifier, SerializableScalar<frost_ed25519::Ed25519Sha512>> = {
            let waitpoint = channel.next_waitpoint();
            collect_packages(channel, helpers, waitpoint).await?
        };

        let mut share = frost_ed25519::Ed25519ScalarField::zero();
        for &s in sigmas.values() {
            share += s.0;
        }
        let signing_share = SigningShare::new(share);
        let verifying_share = VerifyingShare::from(signing_share);

        Ok((signing_share, verifying_share))
    }
}

pub(crate) mod helper {
    use super::*;

    pub async fn do_repair<RNG: CryptoRng + RngCore + 'static + Send>(
        mut channel: SharedChannel,
        mut rng: RNG,
        helpers: Vec<Participant>,
        me: Participant,
        target_participant: Participant,
        mut keygen_output: KeygenOutput,
    ) -> Result<KeygenOutput, ProtocolError> {
        // Round 1.

        let round1_packages = handle_round1(
            // Create sub-channel for helpers only. `child(0)` is safe to use since there is no `Participant(0)`
            &mut channel.child(0),
            helpers.as_slice(),
            me,
            target_participant,
            &keygen_output,
            &mut rng,
        )
        .await
        .map_err(|e| ProtocolError::AssertionFailed(format!("repair:round1: {:?}", e)))?;

        // Round 2.

        handle_round2(&mut channel, &round1_packages, target_participant)
            .await
            .map_err(|e| ProtocolError::AssertionFailed(format!("repair:round2: {:?}", e)))?;

        // Round 3.

        let target_verifying_share = handle_round3(
            &mut channel,
            target_participant,
            keygen_output.public_key_package.clone(),
        )
        .await
        .map_err(|e| ProtocolError::AssertionFailed(format!("repair:round3: {:?}", e)))?;

        // Do verification and update key pair.

        verify_share_consistency(
            to_frost_identifier(target_participant),
            target_verifying_share,
            keygen_output.public_key_package.verifying_shares(),
        )
        .map_err(|e| {
            ProtocolError::AssertionFailed(format!("verify_share_consistency: {:?}", e))
        })?;

        keygen_output.public_key_package = build_pubkey_with_updated_verifying_shares(
            &keygen_output.public_key_package,
            to_frost_identifier(target_participant),
            target_verifying_share,
        );

        Ok(keygen_output)
    }

    async fn handle_round1<RNG: CryptoRng + RngCore + 'static + Send>(
        channel: &mut SharedChannel,
        helpers: &[Participant],
        me: Participant,
        target_participant: Participant,
        keygen_output: &KeygenOutput,
        rng: &mut RNG,
    ) -> anyhow::Result<BTreeMap<Identifier, SerializableScalar<frost_ed25519::Ed25519Sha512>>>
    {
        let frost_identifier_me = to_frost_identifier(me);
        let frost_identifiers = helpers
            .iter()
            .map(|&p| to_frost_identifier(p))
            .collect::<Vec<_>>();

        let mut packages_to_send = frost_core::keys::repairable::repair_share_step_1(
            frost_identifiers.as_slice(),
            frost_identifier_me,
            keygen_output.key_package.signing_share(),
            rng,
            to_frost_identifier(target_participant),
        )?
        .iter()
        .map(|(identifier, delta)| {
            (
                *identifier,
                SerializableScalar::<frost_ed25519::Ed25519Sha512>(*delta),
            )
        })
        .collect::<BTreeMap<_, _>>();

        let my_package = packages_to_send
            .remove(&frost_identifier_me)
            .ok_or(anyhow::anyhow!("Missing package for me"))?;

        let mut received_packages: BTreeMap<_, _> = {
            let waitpoint = channel.next_waitpoint();
            let other_helpers = helpers
                .iter()
                .filter(|&&x| x != me)
                .cloned()
                .collect::<Vec<_>>();

            distribute_packages(
                channel,
                other_helpers.as_slice(),
                &packages_to_send,
                waitpoint,
            )
            .await;

            collect_packages(channel, other_helpers.as_slice(), waitpoint).await?
        };

        received_packages.insert(frost_identifier_me, my_package);
        if received_packages.len() != helpers.len() {
            anyhow::bail!(
                "Expected {} packages, got {}",
                helpers.len(),
                received_packages.len()
            );
        }

        Ok(received_packages)
    }

    async fn handle_round2(
        channel: &mut SharedChannel,
        round1_packages: &BTreeMap<Identifier, SerializableScalar<frost_ed25519::Ed25519Sha512>>,
        target_participant: Participant,
    ) -> anyhow::Result<()> {
        let deltas = round1_packages
            .values()
            .copied()
            .map(|s| s.0)
            .collect::<Vec<_>>();
        let sigma = frost_core::keys::repairable::repair_share_step_2::<frost_ed25519::Ed25519Sha512>(
            deltas.as_slice(),
        );

        let waitpoint = channel.next_waitpoint();

        channel
            .send_private(
                waitpoint,
                target_participant,
                &SerializableScalar::<frost_ed25519::Ed25519Sha512>(sigma),
            )
            .await;

        Ok(())
    }

    async fn handle_round3(
        channel: &mut SharedChannel,
        target_participant: Participant,
        public_key_package: PublicKeyPackage,
    ) -> anyhow::Result<VerifyingShare> {
        {
            let waitpoint = channel.next_waitpoint();
            channel
                .send_private(waitpoint, target_participant, &public_key_package)
                .await;
        }

        let (from, verifying_share): (_, VerifyingShare) = {
            let waitpoint = channel.next_waitpoint();
            channel.recv(waitpoint).await?
        };

        if from != target_participant {
            anyhow::bail!("Received a message from an unexpected participant");
        }

        Ok(verifying_share)
    }
}

async fn collect_public_keys(
    channel: &mut SharedChannel,
    participants: &[Participant],
) -> Result<PublicKeyPackage, ProtocolError> {
    let wait_point = channel.next_waitpoint();

    let public_keys: BTreeMap<_, PublicKeyPackage> =
        collect_packages(channel, participants, wait_point).await?;

    let Some((_, public_key)) = public_keys.first_key_value() else {
        return Err(ProtocolError::AssertionFailed(
            "No public keys received".to_string(),
        ));
    };

    if public_keys
        .iter()
        .any(|(_, other_public_key)| other_public_key != public_key)
    {
        return Err(ProtocolError::AssertionFailed(
            "Received different public key packages".to_string(),
        ));
    }

    Ok(public_key.clone())
}

fn build_pubkey_with_updated_verifying_shares(
    public_key_package: &PublicKeyPackage,
    identifier: Identifier,
    verifying_share: VerifyingShare,
) -> PublicKeyPackage {
    let mut verifying_shares = public_key_package.verifying_shares().clone();
    verifying_shares.insert(identifier, verifying_share);
    PublicKeyPackage::new(verifying_shares, *public_key_package.verifying_key())
}

/// Verify that the repaired secret share matches the secret polynomial.
/// Normally, this would involve using the `VerifiableSecretSharingCommitment` from the FROST library,
/// which provides the coefficients of `Big_f = f(x) * G`. However, this is not available from the current DKG implementation.
/// To verify, we instead use participants' verifying shares (`s_i * G`) and interpolate them
/// at the target participant's identifier (the share being repaired),
/// then confirm that the computed and actual values match.
fn verify_share_consistency(
    identifier: Identifier,
    verifying_share: VerifyingShare,
    other_verifying_shares: &BTreeMap<Identifier, VerifyingShare>,
) -> anyhow::Result<()> {
    let mut expected = frost_ed25519::Ed25519Group::identity();

    let x_set = other_verifying_shares
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for (&other_identifier, other_verifying_share) in other_verifying_shares {
        let phi_i =
            frost_core::compute_lagrange_coefficient(&x_set, Some(identifier), other_identifier)?;
        expected += phi_i * other_verifying_share.to_element()
    }

    if verifying_share.to_element() != expected {
        anyhow::bail!("Verifying share does not match expected value");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::frost::repair::{helper, target};
    use crate::frost::tests::{
        assert_public_key_invariant, assert_signing_schema_threshold_holds,
        build_key_packages_with_dealer, reconstruct_signing_key,
    };
    use crate::frost::KeygenOutput;
    use aes_gcm::aead::OsRng;
    use cait_sith::protocol::{make_protocol, Context, Participant, Protocol};
    use rand::RngCore;
    use std::collections::BTreeMap;

    fn build_and_run_repair_protocols(
        helpers: &[(Participant, KeygenOutput)],
        target_participant: Participant,
        threshold: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        use cait_sith::protocol::run_protocol;

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(helpers.len() + 1);

        let helpers_list = helpers.iter().map(|(x, _)| *x).collect::<Vec<_>>();

        for (participant, key_pair) in helpers {
            let ctx = Context::new();
            let fut = helper::do_repair(
                ctx.shared_channel(),
                OsRng,
                helpers_list.clone(),
                *participant,
                target_participant,
                key_pair.clone(),
            );
            let protocol = make_protocol(ctx, fut);
            let protocol: Box<dyn Protocol<Output = KeygenOutput>> = Box::new(protocol);
            protocols.push((*participant, protocol));
        }

        {
            let ctx = Context::new();
            let fut = target::do_repair(
                ctx.shared_channel(),
                target_participant,
                helpers_list,
                threshold,
            );
            let protocol = make_protocol(ctx, fut);
            let protocol: Box<dyn Protocol<Output = KeygenOutput>> = Box::new(protocol);
            protocols.push((target_participant, protocol));
        }

        Ok(run_protocol(protocols)?)
    }

    fn do_test(
        participants: Option<Vec<(Participant, KeygenOutput)>>,
        participants_count: usize,
        threshold: usize,
        helpers_count: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        let participants = participants
            .unwrap_or_else(|| build_key_packages_with_dealer(participants_count, threshold));
        let signing_key = reconstruct_signing_key(participants.as_slice())?;

        let helpers = participants
            .iter()
            .take(helpers_count)
            .cloned()
            .collect::<Vec<_>>();
        let target_participant = Participant::from(OsRng.next_u32());

        let new_participants =
            build_and_run_repair_protocols(&helpers, target_participant, threshold)?;
        {
            let new_participants = new_participants.iter().cloned().collect::<BTreeMap<_, _>>();
            if !new_participants.contains_key(&target_participant) {
                anyhow::bail!("Target was not added during repair");
            }
        };

        if helpers_count == participants.len() {
            // We didn't update pubkey on other participants, so the check will fail otherwise
            assert_public_key_invariant(new_participants.as_slice())?;
        }
        assert_signing_schema_threshold_holds(signing_key, threshold, new_participants.as_slice())?;

        Ok(new_participants)
    }

    #[test]
    fn repair_one_participant() -> anyhow::Result<()> {
        let participants_count = 5;
        let threshold = 3;
        let helpers_count = 5;
        do_test(None, participants_count, threshold, helpers_count)?;
        Ok(())
    }

    #[test]
    fn repair_one_participant_with_subset_helpers() -> anyhow::Result<()> {
        let participants_count = 5;
        let threshold = 3;
        let helpers_count = 4;
        do_test(None, participants_count, threshold, helpers_count)?;
        Ok(())
    }

    #[test]
    fn repair_sequentially() -> anyhow::Result<()> {
        let max_participants = 6;
        let participants_count = 3;
        let threshold = 3;

        let mut participants = None;

        for i in 1..=max_participants - participants_count {
            let new_participants = do_test(
                participants,
                participants_count,
                threshold,
                participants_count + i, // Taking all participants as helpers
            )?;

            participants = Some(new_participants);
        }

        Ok(())
    }
}
