use crate::frost::{to_frost_identifier, KeygenOutput};
use cait_sith::participants::{ParticipantCounter, ParticipantList};
use cait_sith::protocol::{
    make_protocol, Context, Participant, Protocol, ProtocolError, SharedChannel,
};
use frost_ed25519::keys::dkg::{round1, round2};
use frost_ed25519::Identifier;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::ops::Index;

pub(crate) fn dkg_internal<RNG: CryptoRng + RngCore + 'static + Send>(
    rng: RNG,
    participants: Vec<Participant>,
    me: Participant,
    threshold: usize,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    if participants.len() < 2 {
        anyhow::bail!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        );
    };

    if threshold > participants.len() {
        anyhow::bail!(
            "threshold must be <= participant count, found: {}",
            threshold
        );
    }

    let Some(participants) = ParticipantList::new(&participants) else {
        anyhow::bail!("Participants list contains duplicates")
    };

    if !participants.contains(me) {
        anyhow::bail!("Participant list must contain this participant");
    }

    let ctx = Context::new();
    let fut = do_dkg(ctx.shared_channel(), rng, participants, me, threshold);
    Ok(make_protocol(ctx, fut))
}

async fn do_dkg<RNG: CryptoRng + RngCore + 'static + Send>(
    mut chan: SharedChannel,
    rng: RNG,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<KeygenOutput, ProtocolError> {
    // --- Round 1.
    // * Generate round1 package pair, and distribute the same public part to all participants via reliable broadcast.
    // * Wait all parts from the others.

    let (round1_secret, round1_packages) =
        handle_round1(&mut chan, rng, &participants, me, threshold)
            .await
            .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part1: {:?}", e)))?;

    // --- Round 2.
    // * Generate round2 package pair, and distribute to each participant dedicated public part.
    // * Wait all parts from the others.

    let (round2_secret, round2_packages) = handle_round2(
        &mut chan,
        &participants,
        me,
        round1_secret,
        &round1_packages,
    )
    .await
    .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part2: {:?}", e)))?;

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

async fn handle_round1<RNG: CryptoRng + RngCore + 'static + Send>(
    chan: &mut SharedChannel,
    rng: RNG,
    participants: &ParticipantList,
    me: Participant,
    threshold: usize,
) -> anyhow::Result<(round1::SecretPackage, BTreeMap<Identifier, round1::Package>)> {
    let (round1_secret, my_round1_package) = frost_ed25519::keys::dkg::part1(
        to_frost_identifier(me),
        participants.len() as u16,
        threshold as u16,
        rng,
    )
    .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part1: {:?}", e)))?;

    let round1_packages =
        cait_sith::echo_broadcast::do_broadcast(chan, participants, &me, my_round1_package.clone())
            .await?;

    // Convert values received via Cait-Sith broadcast into the Frost BTreeMap representation
    let round1_packages = Vec::from(participants.clone())
        .into_iter()
        .filter(|&p| p != me) // We should store only others package. By `cait_sith::dkg` API design.
        .map(|p| (to_frost_identifier(p), round1_packages.index(p).clone()))
        .collect::<BTreeMap<_, _>>();

    Ok((round1_secret, round1_packages))
}

async fn handle_round2(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    round1_secret: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
) -> anyhow::Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>)> {
    let from_frost_identifiers = Vec::from(participants.clone())
        .iter()
        .map(|&p| (to_frost_identifier(p), p))
        .collect::<BTreeMap<_, _>>();

    let (round2_secret, my_round2_packages) =
        frost_ed25519::keys::dkg::part2(round1_secret, round1_packages)
            .map_err(|e| ProtocolError::AssertionFailed(format!("dkg::part2: {:?}", e)))?;

    let r2_wait_point = chan.next_waitpoint();
    for (identifier, round2_package) in my_round2_packages {
        chan.send_private(
            r2_wait_point,
            from_frost_identifiers[&identifier],
            &round2_package,
        )
        .await;
    }

    let mut seen = ParticipantCounter::new(participants);
    seen.put(me);
    let round2_packages: BTreeMap<Identifier, round2::Package> =
        wait_for_packages(chan, &mut seen, r2_wait_point).await?;

    Ok((round2_secret, round2_packages))
}

pub(crate) async fn wait_for_packages<P: Clone + DeserializeOwned>(
    chan: &mut SharedChannel,
    seen: &mut ParticipantCounter<'_>,
    wait_point: u64,
) -> Result<BTreeMap<Identifier, P>, ProtocolError> {
    let mut packages = BTreeMap::new();
    while !seen.full() {
        let (from, package): (_, P) = chan.recv(wait_point).await?;
        if seen.put(from) {
            packages.insert(to_frost_identifier(from), package);
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::tests::{
        assert_public_key_invariant, assert_signing_schema_threshold_holds, reconstruct_signing_key,
    };
    use cait_sith::protocol::run_protocol;

    pub(crate) fn build_and_run_dkg_protocols(
        max_signers: usize,
        threshold: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        use rand::prelude::{SeedableRng, StdRng};

        let mut participants = Vec::with_capacity(max_signers);
        for i in 0..max_signers {
            participants.push(Participant::from((10 * i + 123) as u32))
        }

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(max_signers);
        for participant in &participants {
            let rng: StdRng = StdRng::seed_from_u64(protocols.len() as u64);
            let protocol =
                dkg_internal(rng, participants.clone(), *participant, threshold).unwrap();
            protocols.push((*participant, Box::new(protocol)));
        }

        Ok(run_protocol(protocols)?)
    }

    fn do_test(max_signers: usize, threshold: usize) -> anyhow::Result<()> {
        let participants = build_and_run_dkg_protocols(max_signers, threshold)?;
        let signing_key = reconstruct_signing_key(&participants)?;

        assert_public_key_invariant(&participants)?;
        assert_signing_schema_threshold_holds(signing_key, threshold, &participants)?;

        Ok(())
    }

    #[test]
    fn simple_dkg_3_2() -> anyhow::Result<()> {
        let max_signers = 3;
        let threshold = 2;
        do_test(max_signers, threshold)?;
        Ok(())
    }

    #[test]
    fn stress() -> anyhow::Result<()> {
        for max_signers in 2..7 {
            for threshold in 2..max_signers {
                do_test(max_signers, threshold)?;
            }
        }
        Ok(())
    }
}
