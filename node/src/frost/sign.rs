use crate::frost::{to_frost_identifier, KeygenOutput};
use cait_sith::participants::{ParticipantCounter, ParticipantList};
use cait_sith::protocol::{
    make_protocol, Context, Participant, Protocol, ProtocolError, SharedChannel,
};
use frost_ed25519::{round1, round2, Signature};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

pub(crate) fn sign_internal_coordinator<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    keygen_output: KeygenOutput,
    msg_hash: Vec<u8>,
) -> anyhow::Result<impl Protocol<Output = Signature>> {
    if participants.len() < 2 {
        anyhow::bail!("participant count cannot be < 2, found: {}", participants.len());
    };
    let Some(participants) = ParticipantList::new(&participants) else {
        anyhow::bail!("Participants list contains duplicates")
    };

    let ctx = Context::new();
    let fut = do_sign_coordinator(
        ctx.shared_channel(),
        rng,
        participants,
        me,
        keygen_output,
        msg_hash,
    );
    let protocol = make_protocol(ctx, fut);
    Ok(protocol)
}

pub(crate) fn sign_internal_passive<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    keygen_output: KeygenOutput,
    msg_hash: Vec<u8>,
) -> anyhow::Result<impl Protocol<Output = ()>> {
    let ctx = Context::new();
    let fut = do_sign_participant(ctx.shared_channel(), rng, keygen_output, msg_hash);
    let protocol = make_protocol(ctx, fut);
    Ok(protocol)
}

/// Coordinator sends this message to other participants to:
///     (a) indicate the start of the protocol
///     (b) claim `Coordinator` role
#[derive(serde::Serialize, serde::Deserialize)]
struct InitMessage();

pub(crate) async fn do_sign_coordinator<RNG: CryptoRng + RngCore + 'static + Send>(
    mut chan: SharedChannel,
    mut rng: RNG,
    participants: ParticipantList,
    me: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<Signature, ProtocolError> {
    let mut seen = ParticipantCounter::new(&participants);

    // --- Round 1.
    // * Send acknowledgment to other participants.
    // * Wait for their commitments.

    let mut commitments_map: BTreeMap<frost_ed25519::Identifier, round1::SigningCommitments> =
        BTreeMap::new();

    let r1_wait_point = chan.next_waitpoint();
    {
        chan.send_many(r1_wait_point, &InitMessage()).await;
    }

    let (nonces, commitments) = round1::commit(
        keygen_output.key_package.signing_share(),
        &mut rng,
    );
    commitments_map.insert(to_frost_identifier(me), commitments);
    seen.put(me);

    while !seen.full() {
        let (from, commitment): (_, round1::SigningCommitments) = chan.recv(r1_wait_point).await?;
        if !seen.put(from) {
            continue;
        }
        commitments_map.insert(to_frost_identifier(from), commitment);
    }

    let signing_package = frost_ed25519::SigningPackage::new(commitments_map, message.as_slice());

    // --- Round 2.
    // * Convert collected commitments into the signing package.
    // * Send it to all participants.
    // * Wait for each other's signature share

    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    let r2_wait_point = chan.next_waitpoint();
    {
        chan.send_many(r2_wait_point, &signing_package).await;
    }

    let signature_share = round2::sign(&signing_package, &nonces, &keygen_output.key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;
    signature_shares.insert(to_frost_identifier(me), signature_share);
    seen.clear();
    seen.put(me);

    while !seen.full() {
        let (from, signature_share): (_, round2::SignatureShare) = chan.recv(r2_wait_point).await?;
        if !seen.put(from) {
            continue;
        }
        signature_shares.insert(to_frost_identifier(from), signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    let signature = frost_ed25519::aggregate(&signing_package, &signature_shares, &keygen_output.public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(signature)
}

pub(crate) async fn do_sign_participant<RNG: CryptoRng + RngCore + 'static>(
    mut chan: SharedChannel,
    mut rng: RNG,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
) -> Result<(), ProtocolError> {
    let (nonces, commitments) = round1::commit(
        keygen_output.key_package.signing_share(),
        &mut rng,
    );

    // --- Round 1.
    // * Wait for an initial message from a coordinator.
    // * Send coordinator our commitment.

    let r1_wait_point = chan.next_waitpoint();
    let (coordinator, _): (_, InitMessage) = chan.recv(r1_wait_point).await?;
    chan.send_private(r1_wait_point, coordinator, &commitments)
        .await;

    // --- Round 2.
    // * Wait for a signing package.
    // * Send our signature share.

    let r2_wait_point = chan.next_waitpoint();
    let signing_package = loop {
        let (from, signing_package): (_, frost_ed25519::SigningPackage) =
            chan.recv(r2_wait_point).await?;
        if from != coordinator {
            continue;
        }
        break signing_package;
    };

    if signing_package.message() != message.as_slice() {
        return Err(ProtocolError::AssertionFailed(
            "Expected message doesn't match with the actual message received in a signing package"
                .to_string(),
        ));
    }

    let signature_share = round2::sign(&signing_package, &nonces, &keygen_output.key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    {
        chan.send_private(r2_wait_point, coordinator, &signature_share)
            .await;
    }

    // ---

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::frost::tests::{build_and_run_signature_protocols, build_key_packages_with_dealer, SignatureOutput};
    use cait_sith::protocol::Participant;

    fn assert_single_coordinator_result(data: Vec<(Participant, SignatureOutput)>) {
        let count = data
            .iter()
            .filter(|(_, output)| {
                if let SignatureOutput::Coordinator(_) = output {
                    true
                } else {
                    false
                }
            })
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn basic_two_participants() {
        let max_signers = 2;
        let min_signers = 2;
        let actual_signers = 2;
        let coordinators = 1;

        let key_packages = build_key_packages_with_dealer(max_signers, min_signers);
        let data = build_and_run_signature_protocols(&key_packages, min_signers, coordinators).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    #[should_panic]
    fn multiple_coordinators() {
        let max_signers = 3;
        let min_signers = 2;
        let actual_signers = 2;
        let coordinators = 2;

        let key_packages = build_key_packages_with_dealer(max_signers, min_signers);
        let data = build_and_run_signature_protocols(&key_packages, min_signers, coordinators).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    fn stress() {
        let max_signers = 7;
        let coordinators = 1;
        for min_signers in 2..max_signers {
            for actual_signers in min_signers..=max_signers {
                let key_packages = build_key_packages_with_dealer(max_signers, min_signers);
                let data = build_and_run_signature_protocols(&key_packages, actual_signers, coordinators).unwrap();
                assert_single_coordinator_result(data);
            }
        }
    }
}
