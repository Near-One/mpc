use crate::frost::{to_frost_identifier, KeygenOutput};
use cait_sith::participants::{ParticipantCounter, ParticipantList};
use cait_sith::protocol::{
    make_protocol, Context, Participant, Protocol, ProtocolError, SharedChannel,
};
use frost_ed25519::keys::dkg::{round1, round2};
use frost_ed25519::Identifier;
use rand::{CryptoRng, RngCore, SeedableRng};
use std::collections::BTreeMap;

pub(crate) fn dkg_internal<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    threshold: u16,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    let ctx = Context::new();
    let fut = dkg(ctx.shared_channel(), rng, participants, me, threshold);
    Ok(make_protocol(ctx, fut))
}

async fn dkg<RNG: CryptoRng + RngCore + 'static + Send>(
    mut chan: SharedChannel,
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    threshold: u16,
) -> Result<KeygenOutput, ProtocolError> {
    let from_frost_identifiers = participants
        .iter()
        .map(|&p| (to_frost_identifier(p), p))
        .collect::<BTreeMap<_, _>>();
    let participants = ParticipantList::new(participants.as_slice())
        .ok_or_else(|| ProtocolError::Other("Participants contain duplicates".into()))?;
    let max_signers = participants.len() as u16;

    let mut seen = ParticipantCounter::new(&participants);

    // --- Round 1.
    // * Generate round1 package pair, and distribute the same public part to all participants.
    // * Wait all parts from the others.

    // We don't add our public package into the map by design.
    let mut round1_packages: BTreeMap<Identifier, round1::Package> = BTreeMap::new();
    let (round1_secret, my_round1_package) =
        frost_ed25519::keys::dkg::part1(to_frost_identifier(me), max_signers, threshold, rng)
            .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part1: {:?}", e)))?;

    let r1_wait_point = chan.next_waitpoint();
    {
        chan.send_many(r1_wait_point, &my_round1_package).await;
    }

    seen.put(me);
    while !seen.full() {
        let (from, round1_package): (_, round1::Package) = chan.recv(r1_wait_point).await?;
        if !seen.put(from) {
            continue;
        }
        round1_packages.insert(to_frost_identifier(from), round1_package);
    }

    // --- Round 2.
    // * Generate round2 package pair, and distribute to each participant dedicated public part.
    // * Wait all parts from the others.

    // We don't add our public package into the map by design.
    let mut round2_packages: BTreeMap<Identifier, round2::Package> = BTreeMap::new();
    let (round2_secret, my_round2_packages) =
        frost_ed25519::keys::dkg::part2(round1_secret, &round1_packages)
            .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part2: {:?}", e)))?;

    let r2_wait_point = chan.next_waitpoint();
    {
        for (identifier, round2_package) in my_round2_packages {
            chan.send_private(
                r2_wait_point,
                from_frost_identifiers[&identifier],
                &round2_package,
            )
            .await;
        }
    }

    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, round2_package): (_, round2::Package) = chan.recv(r2_wait_point).await?;
        if !seen.put(from) {
            continue;
        }
        round2_packages.insert(to_frost_identifier(from), round2_package);
    }

    // --- Round 3.
    // * Aggregate packages and build the key pair.

    let (key_package, public_key_package) =
        frost_ed25519::keys::dkg::part3(&round2_secret, &round1_packages, &round2_packages)
            .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part3: {:?}", e)))?;

    Ok(KeygenOutput {
        key_package,
        public_key_package,
    })
}

#[cfg(test)]
pub(crate) fn build_dkg_protocols(
    max_signers: usize,
    threshold: usize,
) -> Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> {
    use rand::prelude::StdRng;

    let mut participants = Vec::with_capacity(max_signers);
    for i in 0..max_signers {
        participants.push(Participant::from((10 * i + 123) as u32))
    }

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(max_signers);
    for participant in &participants {
        let rng: StdRng = StdRng::seed_from_u64(protocols.len() as u64);
        let protocol =
            dkg_internal(rng, participants.clone(), *participant, threshold as u16).unwrap();
        protocols.push((*participant, Box::new(protocol)));
    }

    protocols
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::KeygenOutput;
    use cait_sith::protocol::run_protocol;

    fn assert_public_packages(data: Vec<(Participant, KeygenOutput)>) {
        let expected = &data.first().unwrap().1.public_key_package;
        for item in &data {
            assert_eq!(expected, &item.1.public_key_package);
        }
    }

    #[test]
    fn simple_dkg_3_2() {
        let max_signers = 3;
        let threshold = 2;

        let protocols = build_dkg_protocols(max_signers, threshold);
        let data = run_protocol(protocols).unwrap();
        assert_public_packages(data);
    }

    #[test]
    fn stress() {
        for max_signers in 2..7 {
            for threshold in 2..max_signers {
                let protocols = build_dkg_protocols(max_signers, threshold);
                let data = run_protocol(protocols).unwrap();
                assert_public_packages(data);
            }
        }
    }
}
