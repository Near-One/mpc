use crate::frost::to_frost_identifier;
use cait_sith::participants::{ParticipantCounter, ParticipantList};
use cait_sith::protocol::{Participant, ProtocolError, SharedChannel};
use frost_ed25519::Identifier;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;

pub(crate) async fn distribute_packages<T>(
    chan: &mut SharedChannel,
    participants: &[Participant],
    packages: &BTreeMap<Identifier, T>,
    waitpoint: u64,
) where
    T: Clone + Serialize,
{
    let from_frost_identifiers = participants
        .iter()
        .map(|&p| (to_frost_identifier(p), p))
        .collect::<BTreeMap<_, _>>();

    for (identifier, package) in packages {
        chan.send_private(waitpoint, from_frost_identifiers[identifier], &package)
            .await;
    }
}

pub(crate) async fn collect_packages<P: Clone + DeserializeOwned>(
    chan: &SharedChannel,
    participants: &[Participant],
    wait_point: u64,
) -> Result<BTreeMap<Identifier, P>, ProtocolError> {
    let participants_list = ParticipantList::new(participants).ok_or(
        ProtocolError::AssertionFailed("Participants contain duplicates".to_string()),
    )?;
    let mut seen = { ParticipantCounter::new(&participants_list) };
    let mut packages = BTreeMap::new();
    while !seen.full() {
        let (from, package): (_, P) = chan.recv(wait_point).await?;
        if seen.put(from) {
            packages.insert(to_frost_identifier(from), package);
        }
    }
    Ok(packages)
}
