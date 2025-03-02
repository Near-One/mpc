//!
//! Composition of `repair ∘ refresh`
//!
//!

use crate::frost::refresh::do_refresh;
use crate::frost::repair::{do_repair_helper, do_repair_target};
use crate::frost::KeygenOutput;
use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use cait_sith::participants::ParticipantList;
use cait_sith::protocol::{
    make_protocol, Context, InitializationError, Participant, Protocol, ProtocolError,
};
use itertools::Itertools;

pub(crate) fn reshare_old_participant_internal<
    RNG: CryptoRng + RngCore + 'static + Send + Clone,
>(
    rng: RNG,
    old_participants: &[Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
    my_share: KeygenOutput,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    let (old_subset, new_subset) = get_subsets(
        old_participants,
        old_threshold,
        new_participants,
        new_threshold,
        me,
    )?;

    if !old_subset.contains(&me) {
        anyhow::bail!("old participant list must contain this participant");
    }

    let ctx = Context::new();
    let fut = do_reshare_old_participant(
        ctx.clone(),
        rng,
        old_subset,
        new_subset,
        new_threshold,
        me,
        my_share,
    );
    let protocol = make_protocol(ctx, fut);

    Ok(protocol)
}

pub(crate) fn reshare_new_participant_internal<
    RNG: CryptoRng + RngCore + 'static + Send + Clone,
>(
    rng: RNG,
    old_participants: &[Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> anyhow::Result<impl Protocol<Output = KeygenOutput>> {
    let (old_subset, new_subset) = get_subsets(
        old_participants,
        old_threshold,
        new_participants,
        new_threshold,
        me,
    )?;

    if !new_subset.contains(&me) {
        anyhow::bail!("old participant list must contain this participant");
    }

    let ctx = Context::new();
    let fut =
        do_reshare_new_participant(ctx.clone(), rng, old_subset, new_subset, new_threshold, me);
    let protocol = make_protocol(ctx, fut);

    Ok(protocol)
}

/// TODO: explain
fn get_subsets(
    old_participants: &[Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
) -> anyhow::Result<(Vec<Participant>, Vec<Participant>)> {
    if new_threshold != old_threshold {
        // TODO(#119)
        anyhow::bail!("threshold adjusting is not supported at the moment");
    }

    if new_participants.len() < 2 {
        anyhow::bail!(
            "participant count cannot be < 2, found: {}",
            new_participants.len()
        );
    };
    if new_threshold > new_participants.len() {
        anyhow::bail!(
            "threshold must be <= participant count, found: {}",
            new_threshold
        );
    }

    let new_participants = ParticipantList::new(new_participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "new participant list cannot contain duplicates".to_string(),
        )
    })?;

    if !new_participants.contains(me) {
        anyhow::bail!("new participant list must contain this participant");
    }

    let old_participants = ParticipantList::new(old_participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "old participant list cannot contain duplicates".to_string(),
        )
    })?;

    let old_subset = old_participants.intersection(&new_participants);
    if old_subset.len() < old_threshold {
        anyhow::bail!("not enough old participants to reconstruct private key for resharing");
    };

    let new_subset = Vec::from(new_participants)
        .iter()
        .filter(|&&x| !old_subset.contains(x))
        .cloned()
        .collect::<Vec<_>>();

    let old_subset = Vec::from(old_subset);
    Ok((old_subset, new_subset))
}

async fn do_reshare_new_participant<RNG: CryptoRng + RngCore + 'static + Send + Clone>(
    ctx: Context<'_>,
    rng: RNG,
    old_subset: Vec<Participant>,
    new_subset: Vec<Participant>,
    threshold: usize,
    me: Participant,
) -> Result<KeygenOutput, ProtocolError> {
    let mut helpers = new_subset
        .iter()
        .sorted()
        .cloned()
        .filter(|&x| x < me)
        .chain(old_subset.iter().cloned())
        .collect::<Vec<_>>();

    let channel = ctx.shared_channel().child(u32::from(me) as u64);

    let keygen_output = do_repair_target(channel, me, helpers.clone(), threshold).await?;

    //

    helpers.push(me);
    let targets = new_subset
        .iter()
        .filter(|&&x| x > me)
        .sorted()
        .cloned()
        .collect::<Vec<_>>();

    let keygen_output =
        repair_for_targets(ctx, rng.clone(), helpers, targets, me, keygen_output).await?;

    Ok(keygen_output)
}

async fn do_reshare_old_participant<RNG: CryptoRng + RngCore + 'static + Send + Clone>(
    ctx: Context<'_>,
    rng: RNG,
    old_subset: Vec<Participant>,
    new_subset: Vec<Participant>,
    threshold: usize,
    me: Participant,
    mut keygen_output: KeygenOutput,
) -> Result<KeygenOutput, ProtocolError> {
    keygen_output = do_refresh(
        ctx.shared_channel().child(0), // TODO: use of zero safety?
        rng.clone(),
        old_subset.clone(),
        me,
        keygen_output,
        threshold,
    )
    .await?;

    keygen_output = repair_for_targets(ctx, rng, old_subset, new_subset, me, keygen_output).await?;

    Ok(keygen_output)
}

async fn repair_for_targets<RNG: CryptoRng + RngCore + 'static + Send + Clone>(
    ctx: Context<'_>,
    rng: RNG,
    mut helpers: Vec<Participant>,
    targets: Vec<Participant>,
    me: Participant,
    mut keygen_output: KeygenOutput,
) -> Result<KeygenOutput, ProtocolError> {
    for &target in targets.iter().sorted() {
        let chan = ctx.shared_channel().child(u32::from(target) as u64);
        keygen_output = do_repair_helper(
            chan,
            rng.clone(),
            helpers.clone(),
            me,
            target,
            keygen_output.clone(),
        )
        .await?;
        helpers.push(target);
    }

    Ok(keygen_output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::tests::{
        assert_public_key_invariant, assert_signing_schema_threshold_holds,
        build_key_packages_with_dealer, reconstruct_signing_key,
    };
    use aes_gcm::aead::OsRng;
    use rand::Rng;
    use std::collections::BTreeMap;

    pub(crate) fn build_and_run_reshare_protocols(
        old_participants: &[(Participant, KeygenOutput)],
        old_threshold: usize,
        new_participants: &[Participant],
        new_threshold: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        use cait_sith::protocol::run_protocol;

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
            Vec::with_capacity(new_participants.len());

        let old_participants_map = old_participants.iter().cloned().collect::<BTreeMap<_, _>>();
        let old_participants = old_participants_map.keys().cloned().collect::<Vec<_>>();

        for new_participant in new_participants {
            match old_participants_map.get(new_participant) {
                None => {
                    let protocol = reshare_new_participant_internal(
                        OsRng,
                        old_participants.clone().as_slice(),
                        old_threshold,
                        new_participants,
                        new_threshold,
                        *new_participant,
                    )?;
                    let protocol: Box<dyn Protocol<Output = KeygenOutput>> = Box::new(protocol);
                    protocols.push((*new_participant, protocol));
                }
                Some(keygen_output) => {
                    let protocol = reshare_old_participant_internal(
                        OsRng,
                        old_participants.clone().as_slice(),
                        old_threshold,
                        new_participants,
                        new_threshold,
                        *new_participant,
                        keygen_output.clone(),
                    )?;
                    let protocol: Box<dyn Protocol<Output = KeygenOutput>> = Box::new(protocol);
                    protocols.push((*new_participant, protocol));
                }
            }
        }

        Ok(run_protocol(protocols)?)
    }

    fn do_test(
        old_participants: Option<Vec<(Participant, KeygenOutput)>>,
        old_participant_count: usize,
        old_threshold: usize,
        added_participant_count: usize,
        removed_participant_count: usize,
        new_threshold: usize,
    ) -> anyhow::Result<Vec<(Participant, KeygenOutput)>> {
        let old_participants = old_participants.unwrap_or_else(|| {
            build_key_packages_with_dealer(old_participant_count, old_threshold)
        });
        let signing_key = reconstruct_signing_key(old_participants.as_slice())?;

        let new_participants = old_participants
            .iter()
            .map(|(x, _)| x)
            .skip(removed_participant_count)
            .cloned()
            .chain((0..added_participant_count).map(|_| Participant::from(OsRng.next_u32())))
            .collect::<Vec<_>>();

        let result = build_and_run_reshare_protocols(
            old_participants.as_slice(),
            old_threshold,
            new_participants.as_slice(),
            new_threshold,
        )?;

        assert_public_key_invariant(result.as_slice())?;
        assert_signing_schema_threshold_holds(signing_key, new_threshold, result.as_slice())?;

        Ok(result)
    }

    #[test]
    fn remove_one_participant() -> Result<(), anyhow::Error> {
        let old_participant_count = 4;
        let old_threshold = 3;
        let added_participant_count = 0;
        let removed_participant_count = 1;
        let new_threshold = old_threshold;
        do_test(
            None,
            old_participant_count,
            old_threshold,
            added_participant_count,
            removed_participant_count,
            new_threshold,
        )?;
        Ok(())
    }

    #[test]
    fn add_one_participant() -> Result<(), anyhow::Error> {
        let old_participant_count = 4;
        let old_threshold = 3;
        let added_participant_count = 1;
        let removed_participant_count = 0;
        let new_threshold = old_threshold;
        do_test(
            None,
            old_participant_count,
            old_threshold,
            added_participant_count,
            removed_participant_count,
            new_threshold,
        )?;
        Ok(())
    }

    #[test]
    fn add_one_remove_one_participant() -> Result<(), anyhow::Error> {
        let old_participant_count = 4;
        let old_threshold = 3;
        let added_participant_count = 1;
        let removed_participant_count = 1;
        let new_threshold = old_threshold;
        do_test(
            None,
            old_participant_count,
            old_threshold,
            added_participant_count,
            removed_participant_count,
            new_threshold,
        )?;
        Ok(())
    }

    #[test]
    fn sequential_reshare() -> Result<(), anyhow::Error> {
        let old_participant_count = 4;
        let old_threshold = 3;
        let new_threshold = old_threshold;
        let max_number_of_participants = 7;
        let iterations = 10;

        let mut old_participants = build_key_packages_with_dealer(old_participant_count, old_threshold);

        for _ in 0..iterations {
            let removed_participants = OsRng.gen_range(0..=old_participants.len() - old_threshold);
            let added_participants = {
                let can_be_added_count =
                    max_number_of_participants - (old_participants.len() - removed_participants);
                OsRng.gen_range(0..=can_be_added_count)
            };

            let new_participants = do_test(
                Some(old_participants),
                old_participant_count,
                old_threshold,
                added_participants,
                removed_participants,
                new_threshold,
            )?;

            old_participants = new_participants;
        }

        Ok(())
    }
}
