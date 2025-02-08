use crate::frost::{to_frost_identifier, SignatureOutput};
use cait_sith::participants::{ParticipantCounter, ParticipantList};
use cait_sith::protocol::{
    make_protocol, Context, Participant, Protocol, ProtocolError, SharedChannel,
};
use frost_ed25519::{round1, round2};
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

pub(crate) fn sign_internal<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    is_coordinator: bool,
    participants: Vec<Participant>,
    me: Participant,
    key_package: frost_ed25519::keys::KeyPackage,
    pubkeys: frost_ed25519::keys::PublicKeyPackage,
    msg_hash: Vec<u8>,
) -> anyhow::Result<Box<dyn Protocol<Output = SignatureOutput>>> {
    let Some(participants) = ParticipantList::new(&participants) else {
        anyhow::bail!("Participants list contains duplicates")
    };
    let ctx = Context::new();
    let protocol: Box<dyn Protocol<Output = SignatureOutput>> = if is_coordinator {
        let fut = do_sign_coordinator(
            ctx.shared_channel(),
            rng,
            participants,
            me,
            key_package,
            pubkeys,
            msg_hash,
        );
        Box::new(make_protocol(ctx, fut))
    } else {
        let fut = do_sign_participant(ctx.shared_channel(), rng, key_package, msg_hash);
        Box::new(make_protocol(ctx, fut))
    };
    Ok(protocol)
}

/// Coordinator sends this message to other participants to:
///     (a) indicate the start of the protocol
///     (b) claim `Coordinator` role
#[derive(serde::Serialize, serde::Deserialize)]
struct InitMessage();

async fn do_sign_coordinator<RNG: CryptoRng + RngCore + 'static + Send>(
    mut chan: SharedChannel,
    mut rng: RNG,
    participants: ParticipantList,
    me: Participant,
    key_package: frost_ed25519::keys::KeyPackage,
    pubkeys: frost_ed25519::keys::PublicKeyPackage,
    message: Vec<u8>,
) -> Result<SignatureOutput, ProtocolError> {
    let mut seen = ParticipantCounter::new(&participants);
    let mut commitments_map: BTreeMap<frost_ed25519::Identifier, round1::SigningCommitments> =
        BTreeMap::new();
    let mut signature_shares: BTreeMap<frost_ed25519::Identifier, round2::SignatureShare> =
        BTreeMap::new();

    // --- Round 1.
    // * Send acknowledgment to other participants.
    // * Wait for their commitments.

    let r1_wait_point = chan.next_waitpoint();
    {
        chan.send_many(r1_wait_point, &InitMessage()).await;
    }

    let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);
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

    let r2_wait_point = chan.next_waitpoint();
    {
        chan.send_many(r2_wait_point, &signing_package).await;
    }

    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
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

    let signature = frost_ed25519::aggregate(&signing_package, &signature_shares, &pubkeys)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(SignatureOutput::Coordinator(signature))
}

async fn do_sign_participant<RNG: CryptoRng + RngCore + 'static>(
    mut chan: SharedChannel,
    mut rng: RNG,
    key_package: frost_ed25519::keys::KeyPackage,
    message: Vec<u8>,
) -> Result<SignatureOutput, ProtocolError> {
    let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);

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

    let signature_share = round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    {
        chan.send_private(r2_wait_point, coordinator, &signature_share)
            .await;
    }
    
    // ---

    Ok(SignatureOutput::Participant {})
}

#[cfg(test)]
mod tests {
    use crate::frost::sign::sign_internal;
    use crate::frost::{to_frost_identifier, SignatureOutput};
    use cait_sith::protocol::{run_protocol, Participant, Protocol};
    use frost_ed25519::rand_core::SeedableRng;
    use frost_ed25519::Identifier;
    use near_indexer::near_primitives::hash::hash;
    use rand::prelude::{SliceRandom, StdRng};
    use rand::thread_rng;
    use std::collections::BTreeMap;

    fn build_protocols(
        max_signers: usize,
        min_signers: usize,
        actual_signers: usize,
        coordinators: usize,
    ) -> Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> {
        let mut identifiers = Vec::with_capacity(max_signers);
        for i in 0..max_signers {
            // from 1 to avoid assigning 0 to a ParticipantId
            identifiers.push(Participant::from((10 * i + 123) as u32))
        }

        let frost_identifiers = identifiers
            .iter()
            .map(|&x| to_frost_identifier(x.into()))
            .collect::<Vec<_>>();

        let mut rng: StdRng = StdRng::seed_from_u64(42u64);
        let (shares, pubkey_package) = frost_ed25519::keys::generate_with_dealer(
            max_signers as u16,
            min_signers as u16,
            frost_ed25519::keys::IdentifierList::Custom(&frost_identifiers),
            &mut rng,
        )
        .unwrap();

        let key_packages = shares
            .iter()
            .map(|(id, share)| {
                (
                    id,
                    frost_ed25519::keys::KeyPackage::try_from(share.clone()).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let msg = "hello_near";
        let msg_hash = hash(msg.as_bytes());

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> =
            Vec::with_capacity(max_signers);

        for i in 0..actual_signers {
            protocols.push((
                identifiers[i].into(),
                sign_internal(
                    rng.clone(),
                    i >= actual_signers - coordinators,
                    identifiers.iter().take(actual_signers).cloned().collect(),
                    identifiers[i],
                    key_packages[&frost_identifiers[i]].clone(),
                    pubkey_package.clone(),
                    msg_hash.as_bytes().to_vec(),
                )
                .unwrap(),
            ))
        }

        protocols
    }

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

        let protocols = build_protocols(max_signers, min_signers, actual_signers, coordinators);
        let data = run_protocol(protocols).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    #[should_panic]
    fn multiple_coordinators() {
        let max_signers = 3;
        let min_signers = 2;
        let actual_signers = 2;
        let coordinators = 2;

        let protocols = build_protocols(max_signers, min_signers, actual_signers, coordinators);
        let data = run_protocol(protocols).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    #[should_panic]
    fn threshold_not_met() {
        let max_signers = 3;
        let min_signers = 2;
        let actual_signers = 1;
        let coordinators = 1;

        let protocols = build_protocols(max_signers, min_signers, actual_signers, coordinators);
        let data = run_protocol(protocols).unwrap();
        assert_single_coordinator_result(data);
    }

    #[test]
    fn stress() {
        let max_signers = 7;
        let coordinators = 1;
        for min_signers in 2..max_signers {
            for actual_signers in min_signers..=max_signers {
                let mut protocols =
                    build_protocols(max_signers, min_signers, actual_signers, coordinators);

                let mut rng = thread_rng();
                protocols.shuffle(&mut rng);

                let data = run_protocol(protocols).unwrap();
                assert_single_coordinator_result(data);
            }
        }
    }

    #[test]
    fn verify_stability_of_identifier_derivation() {
        let participant = Participant::from(1e9 as u32);
        let identifier = Identifier::derive(participant.bytes().as_slice()).unwrap();
        assert_eq!(
            identifier.serialize(),
            vec![
                96, 203, 29, 92, 230, 35, 120, 169, 19, 185, 45, 28, 48, 68, 84, 190, 12, 186, 169,
                192, 196, 21, 238, 181, 134, 181, 203, 236, 162, 68, 212, 4
            ]
        );
    }
}
