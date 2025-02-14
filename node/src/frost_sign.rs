use std::collections::btree_map::Iter;
use crate::primitives::ParticipantId;
use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use anyhow::Context;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::{Action, MessageData, Participant, Protocol, ProtocolError};
use std::collections::BTreeMap;

/// This implementation is valid in the context where we can choose a Leader (Coordinator)
/// node for a signature generation. That means only Coordinator ends up with a generated signature.
/// It comes with a benefit of O(n) messages in a network.
///
/// If one wants to get rid of a such distinction, it will make the number of messages in the system O(n^2).
///
/// TODO: Can we precompute the first round in advance (just like presigns in ECDSA)?
///     The answer depends on whether we can do KDF on SigningPackage/SigningShare.

#[derive(Debug)]
pub enum FrostOutput {
    Coordinator(frost_ed25519::Signature),
    Participant,
}

pub fn frost_sign<RNG: CryptoRng + RngCore + 'static>(
    rng: RNG,
    is_coordinator: bool,
    me: ParticipantId,
    key_package: frost_ed25519::keys::KeyPackage,
    public_key_package: frost_ed25519::keys::PublicKeyPackage,
    threshold: usize,
    msg_hash: Vec<u8>,
) -> Box<dyn Protocol<Output = FrostOutput>> {
    if is_coordinator {
        Box::new(FrostSignProtocolCoordinator::new(
            rng,
            me,
            key_package,
            public_key_package,
            threshold,
            msg_hash,
        ))
    } else {
        Box::new(FrostSignProtocolParticipant::new(rng, key_package))
    }
}

#[derive(Debug)]
enum CoordinatorState {
    Started,
    WaitForCommitments,
    WaitForSigningShares,
    Finished,
}

#[derive(Debug)]
enum ParticipantState {
    ReadyToSendCommitment,
    ReadyToSendSigningShare,
    Finished,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum CoordinatorMessage {
    FirstRoundInit,
    SigningPackage(Vec<u8>),
}

#[derive(BorshSerialize, BorshDeserialize)]
enum ParticipantMessage {
    Commitment(Vec<u8>),
    SignatureShare(Vec<u8>),
}

pub trait BorshMessage: BorshSerialize + BorshDeserialize {
    fn from_data(data: &impl AsRef<[u8]>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        BorshDeserialize::try_from_slice(data.as_ref())
            .context(format!("Failed to deserialize {}", std::any::type_name::<Self>()))
    }

    fn into_data(self) -> anyhow::Result<Vec<u8>> {
        borsh::to_vec(&self)
            .context(format!("Failed to serialize {}", std::any::type_name::<Self>()))
    }
}

impl BorshMessage for CoordinatorMessage {}
impl BorshMessage for ParticipantMessage {}

fn to_frost_identifier(participant: Participant) -> frost_ed25519::Identifier {
    frost_ed25519::Identifier::derive(participant.bytes().as_slice())
        .expect("Identifier derivation must succeed: cipher suite is guaranteed to be implemented")
}

// A structure to enforce invariant on waiting on exactly `threshold` objects, skip others
struct ThresholdMap {
    threshold: usize,
    map: BTreeMap<frost_ed25519::Identifier, Vec<u8>>,
}

impl ThresholdMap {
    fn new(threshold: usize) -> Self {
        Self {
            threshold,
            map: BTreeMap::new(),
        }
    }

    fn is_complete(&self) -> bool {
        self.map.len() == self.threshold
    }

    fn add(&mut self, key: Participant, value: Vec<u8>) {
        if self.map.len() >= self.threshold {
            return;
        }
        let key = to_frost_identifier(key);
        if self.map.contains_key(&key) {
            return;
        }
        self.map.insert(key, value);
    }

    fn iter(&self) -> Iter<'_, frost_ed25519::Identifier, Vec<u8>> {
        self.map.iter()
    }
}

struct FrostSignProtocolCoordinator {
    key_package: frost_ed25519::keys::KeyPackage,
    public_key_package: frost_ed25519::keys::PublicKeyPackage,
    state: CoordinatorState,

    my_identifier: Participant,
    threshold: usize,
    msg_hash: Vec<u8>,
    signing_package: Option<frost_ed25519::SigningPackage>,

    commitments: ThresholdMap,
    signature_shares: ThresholdMap,
    my_signing_nonce: frost_ed25519::round1::SigningNonces,
}

impl FrostSignProtocolCoordinator {
    pub fn new<RNG: CryptoRng + RngCore>(
        mut rng: RNG,
        my_identifier: ParticipantId,
        key_package: frost_ed25519::keys::KeyPackage,
        public_key_package: frost_ed25519::keys::PublicKeyPackage,
        threshold: usize,
        msg_hash: Vec<u8>,
    ) -> Self {
        let (nonces, commitments) =
            frost_ed25519::round1::commit(key_package.signing_share(), &mut rng);
        let signing_commitments = commitments.serialize().expect(
            "Commitment is always expected to be serialized if used directly from round1::commit()",
        );

        let mut commitments = ThresholdMap::new(threshold);
        commitments.add(my_identifier.into(), signing_commitments);

        Self {
            key_package,
            public_key_package,
            state: CoordinatorState::Started,
            my_identifier: my_identifier.into(),
            threshold,
            msg_hash,
            signing_package: None,
            commitments,
            signature_shares: ThresholdMap::new(threshold),
            my_signing_nonce: nonces,
        }
    }

    fn handle_message(&mut self, from: Participant, msg: ParticipantMessage) {
        match msg {
            ParticipantMessage::Commitment(data) => {
                self.commitments.add(from, data);
            }
            ParticipantMessage::SignatureShare(data) => {
                if let Some(signing_package) = &self.signing_package {
                    // We must use only those participant, who are included in the formed `commitments_map`.
                    // Some nodes may not be present in `commitments_map` even though they may have sent their commitment.
                    // That's because they weren't fast enough to get included into first `threshold` commitments.
                    if signing_package
                        .signing_commitment(&to_frost_identifier(from))
                        .is_some()
                    {
                        self.signature_shares.add(from, data);
                    }
                }
            }
        }
    }
}

impl FrostSignProtocolCoordinator {
    fn handle_started_state(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        self.state = CoordinatorState::WaitForCommitments;
        let data = CoordinatorMessage::FirstRoundInit.into_data()?;
        Ok(Action::SendMany(data))
    }

    fn handle_waiting_commitments_state(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        if !self.commitments.is_complete() {
            return Ok(Action::Wait);
        }

        let commitments_map = self
            .commitments
            .iter()
            .map(|(&key, data)| {
                frost_ed25519::round1::SigningCommitments::deserialize(data.as_slice())
                    .context(format!("Couldn't deserialize commitment from {:?}", key))
                    .map(|commitment| (key, commitment))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        
        assert!(self.signing_package.is_none());
        let signing_package =
            frost_ed25519::SigningPackage::new(commitments_map, self.msg_hash.as_slice());
        
        let signature_share = frost_ed25519::round2::sign(
            &signing_package,
            &self.my_signing_nonce,
            &self.key_package,
        )?;

        self.signature_shares
            .add(self.my_identifier, signature_share.serialize());

        self.state = CoordinatorState::WaitForSigningShares;

        let data = signing_package.serialize()?;
        let data = CoordinatorMessage::SigningPackage(data).into_data()?;
        self.signing_package = Some(signing_package);
        Ok(Action::SendMany(data))
    }

    fn handle_waiting_signing_shares_state(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        if self.signature_shares.is_complete() {
            self.state = CoordinatorState::Finished;
            self.handle_finished_state()
        } else {
            Ok(Action::Wait)
        }
    }

    fn handle_finished_state(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        let signature_shares = self
            .signature_shares
            .iter()
            .map(|(&key, data)| {
                frost_ed25519::round2::SignatureShare::deserialize(data.as_slice())
                    .context(format!(
                        "Couldn't deserialize signature share from {:?}",
                        key
                    ))
                    .map(|share| (key, share))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let signing_package = self
            .signing_package
            .as_ref()
            .expect("Signing package must exist at the stage where we have all signature shares");
        let group_signature =
            frost_ed25519::aggregate(signing_package, &signature_shares, &self.public_key_package)?;
        Ok(Action::Return(FrostOutput::Coordinator(group_signature)))
    }

    fn poke_state_machine(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        match &self.state {
            CoordinatorState::Started => self.handle_started_state(),
            CoordinatorState::WaitForCommitments => self.handle_waiting_commitments_state(),
            CoordinatorState::WaitForSigningShares => self.handle_waiting_signing_shares_state(),
            CoordinatorState::Finished => self.handle_finished_state(),
        }
    }
}

impl Protocol for FrostSignProtocolCoordinator {
    type Output = FrostOutput;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        self.poke_state_machine()
            .map_err(|e| ProtocolError::Other(e.into()))
    }

    fn message(&mut self, from: Participant, data: MessageData) {
        match ParticipantMessage::from_data(&data) {
            Ok(msg) => self.handle_message(from, msg),
            Err(e) => {
                tracing::error!("Failed to deserialize message: {:?}", e);
            }
        }
    }
}

struct FrostSignProtocolParticipant {
    key_package: frost_ed25519::keys::KeyPackage,
    state: ParticipantState,

    my_signing_nonce: frost_ed25519::round1::SigningNonces,
    my_commitment: frost_ed25519::round1::SigningCommitments,

    coordinator: Option<Participant>,
    signing_package: Option<Vec<u8>>,
}

impl FrostSignProtocolParticipant {
    pub fn new<RNG: CryptoRng + RngCore>(
        mut rng: RNG,
        key_package: frost_ed25519::keys::KeyPackage,
    ) -> Self {
        let (my_signing_nonce, my_commitment) =
            frost_ed25519::round1::commit(key_package.signing_share(), &mut rng);

        Self {
            key_package,
            state: ParticipantState::ReadyToSendCommitment,
            my_signing_nonce,
            my_commitment,
            coordinator: None,
            signing_package: None,
        }
    }
}

impl FrostSignProtocolParticipant {
    fn handle_ready_to_send_commitment_state(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        let coordinator = if let Some(coordinator) = self.coordinator {
            coordinator
        } else {
            return Ok(Action::Wait);
        };

        self.state = ParticipantState::ReadyToSendSigningShare;

        let data = self.my_commitment.serialize()?;
        let data = ParticipantMessage::Commitment(data).into_data()?;
        Ok(Action::SendPrivate(coordinator, data))
    }

    fn handle_ready_to_send_signing_share_state(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        let coordinator = if let Some(coordinator) = self.coordinator {
            coordinator
        } else {
            return Ok(Action::Wait);
        };

        let signing_package = if let Some(signing_package) = self.signing_package.as_ref() {
            signing_package
        } else {
            return Ok(Action::Wait);
        };

        let signing_package =
            frost_ed25519::SigningPackage::deserialize(signing_package.as_slice())?;

        if signing_package
            .signing_commitment(self.key_package.identifier())
            .is_none()
        {
            // We were not fast enough to get included into first `threshold` participants.
            self.state = ParticipantState::Finished;
            return self.poke_state_machine();
        }

        let signature_share = frost_ed25519::round2::sign(
            &signing_package,
            &self.my_signing_nonce,
            &self.key_package,
        )?;

        self.state = ParticipantState::Finished;
        let data = ParticipantMessage::SignatureShare(signature_share.serialize());
        let data = data.into_data()?;
        Ok(Action::SendPrivate(coordinator, data))
    }

    fn poke_state_machine(&mut self) -> anyhow::Result<Action<FrostOutput>> {
        match self.state {
            ParticipantState::ReadyToSendCommitment => self.handle_ready_to_send_commitment_state(),
            ParticipantState::ReadyToSendSigningShare => {
                self.handle_ready_to_send_signing_share_state()
            }
            ParticipantState::Finished => Ok(Action::Return(FrostOutput::Participant)),
        }
    }
    fn handle_message(&mut self, from: Participant, msg: CoordinatorMessage) {
        match msg {
            CoordinatorMessage::FirstRoundInit => {
                if self.coordinator.is_none() {
                    self.coordinator = Some(from)
                }
            }
            CoordinatorMessage::SigningPackage(signing_package) => {
                if Some(from) == self.coordinator {
                    self.signing_package = Some(signing_package);
                } else {
                    self.state = ParticipantState::Finished
                }
            }
        }
    }
}

impl Protocol for FrostSignProtocolParticipant {
    type Output = FrostOutput;

    fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
        self.poke_state_machine()
            .map_err(|e| ProtocolError::Other(e.into()))
    }

    fn message(&mut self, from: Participant, data: MessageData) {
        match CoordinatorMessage::from_data(&data) {
            Ok(msg) => self.handle_message(from, msg),
            Err(e) => {
                tracing::error!("Failed to deserialize message: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::frost_sign::{frost_sign, to_frost_identifier, FrostOutput};
    use crate::primitives::ParticipantId;
    use cait_sith::protocol::{
        run_protocol, Action, MessageData, Participant, Protocol, ProtocolError,
    };
    use frost_ed25519::Identifier;
    use near_indexer::near_primitives::hash::hash;
    use rand::thread_rng;
    use std::collections::BTreeMap;
    use rand::prelude::SliceRandom;

    struct NonActiveParticipant {}
    impl Protocol for NonActiveParticipant {
        type Output = FrostOutput;
        fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
            Ok(Action::Wait)
        }
        fn message(&mut self, _: Participant, _: MessageData) {}
    }

    fn build_protocols(
        max_signers: usize,
        min_signers: usize,
        non_active_participant: usize,
        coordinators: usize,
    ) -> Vec<(Participant, Box<dyn Protocol<Output = FrostOutput>>)> {
        let active_participants = max_signers - non_active_participant;
        assert!(active_participants >= min_signers);
        let msg = "hello_near";
        let msg_hash = hash(msg.as_bytes());

        let mut identifiers = Vec::with_capacity(max_signers);
        for i in 1..max_signers + 1 {
            // from 1 to avoid assigning 0 to a ParticipantId
            identifiers.push(ParticipantId::from_raw((10 * i) as u32))
        }

        let frost_identifiers = identifiers
            .iter()
            .map(|&x| to_frost_identifier(x.into()))
            .collect::<Vec<_>>();

        let mut rng = thread_rng();
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

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = FrostOutput>>)> =
            Vec::with_capacity(max_signers);

        for i in 0..non_active_participant {
            protocols.push((identifiers[i].into(), Box::new(NonActiveParticipant {})))
        }

        for i in non_active_participant..max_signers {
            protocols.push((
                identifiers[i].into(),
                frost_sign(
                    rng.clone(),
                    i >= max_signers - coordinators,
                    identifiers[i],
                    key_packages[&frost_identifiers[i]].clone(),
                    pubkey_package.clone(),
                    min_signers,
                    msg_hash.as_bytes().to_vec(),
                ),
            ))
        }

        protocols
    }

    #[test]
    fn basic_two_participants() {
        let max_signers = 2;
        let min_signers = 2;
        let non_active_participants = 0;
        let coordinators = 1;

        let protocols = build_protocols(
            max_signers,
            min_signers,
            non_active_participants,
            coordinators,
        );
        run_protocol(protocols).unwrap();
    }

    #[test]
    fn with_non_active_participants() {
        let max_signers = 9;
        let min_signers = 6;
        let non_active_participants = 3;
        let coordinators = 1;

        let protocols = build_protocols(
            max_signers,
            min_signers,
            non_active_participants,
            coordinators,
        );
        run_protocol(protocols).unwrap();
    }

    #[test]
    fn stress() {
        let max_signers = 7;
        for min_signers in 2..max_signers {
            for non_active in 0..max_signers - min_signers + 1 {
                let mut protocols = build_protocols(max_signers, min_signers, non_active, 1);

                let mut rng = thread_rng();
                protocols.shuffle(&mut rng);

                run_protocol(protocols).unwrap();
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
