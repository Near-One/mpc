#[cfg(test)]
use crate::frost::sign::{do_sign_coordinator, do_sign_participant};
#[cfg(test)]
use crate::frost::KeygenOutput;
#[cfg(test)]
use cait_sith::participants::ParticipantList;
#[cfg(test)]
use cait_sith::protocol::{make_protocol, Context, Participant, Protocol};
#[cfg(test)]
use frost_ed25519::Signature;
#[cfg(test)]
use futures::FutureExt;

#[cfg(test)]
pub(crate) enum SignatureOutput {
    Coordinator(Signature),
    Participant,
}

#[cfg(test)]
pub(crate) fn build_sign_protocols(
    participants: &Vec<(Participant, KeygenOutput)>,
    threshold: usize,
    coordinator_distribution: impl Fn(usize) -> bool,
) -> Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> {
    use near_indexer::near_primitives::hash::hash;
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOutput>>)> =
        Vec::with_capacity(participants.len());

    let threshold_identifiers = participants
        .iter()
        .take(threshold)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let threshold_identifiers = ParticipantList::new(&threshold_identifiers).unwrap();

    let msg = "hello_near";
    let msg_hash = hash(msg.as_bytes());

    for (idx, (participant, key_pair)) in participants.iter().take(threshold).enumerate() {
        let rng: StdRng = StdRng::seed_from_u64(protocols.len() as u64);

        let ctx = Context::new();
        let protocol: Box<dyn Protocol<Output = SignatureOutput>> = if coordinator_distribution(idx)
        {
            let fut = do_sign_coordinator(
                ctx.shared_channel(),
                rng,
                threshold_identifiers.clone(),
                *participant,
                key_pair.clone(),
                msg_hash.as_bytes().to_vec(),
            )
            .map(|x| x.map(|y| SignatureOutput::Coordinator(y)));
            let protocol = make_protocol(ctx, fut);
            Box::new(protocol)
        } else {
            let fut = do_sign_participant(
                ctx.shared_channel(),
                rng,
                key_pair.clone(),
                msg_hash.as_bytes().to_vec(),
            )
            .map(|x| x.map(|y| SignatureOutput::Participant));
            let protocol = make_protocol(ctx, fut);
            Box::new(protocol)
        };

        protocols.push((*participant, protocol))
    }

    protocols
}

#[cfg(test)]
mod tests {
    use crate::frost::dkg::build_dkg_protocols;
    use crate::frost::tests::{build_sign_protocols, SignatureOutput};
    use cait_sith::protocol::{run_protocol, Participant};
    use frost_ed25519::Identifier;
    use near_indexer::near_primitives::hash::hash;

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

    #[test]
    fn dkg_and_sign() {
        let max_signers = 9;
        let threshold = 6;

        let dkg_protocols = build_dkg_protocols(max_signers, threshold);
        let keys = run_protocol(dkg_protocols).unwrap();

        let group_public_key = keys.first().unwrap().1.public_key_package.verifying_key();

        let sign_protocols = build_sign_protocols(&keys, threshold, |idx| idx == 0);
        let signature = run_protocol(sign_protocols)
            .unwrap()
            .into_iter()
            .filter_map(|(_, s)| match s {
                SignatureOutput::Coordinator(signature) => Some(signature),
                SignatureOutput::Participant => None,
            })
            .next()
            .unwrap();

        let msg = "hello_near";
        let msg_hash = hash(msg.as_bytes());

        group_public_key
            .verify(msg_hash.as_bytes(), &signature)
            .unwrap();
    }
}
