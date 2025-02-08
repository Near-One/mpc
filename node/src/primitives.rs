use crate::assets::UniqueId;
use crate::sign_request::SignatureId;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::Participant;
use cait_sith::triples::TripleGenerationOutput;
use cait_sith::PresignOutput;
use k256::Secp256k1;
use rand::prelude::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ParticipantId(u32);

impl From<Participant> for ParticipantId {
    fn from(participant: Participant) -> Self {
        ParticipantId(participant.into())
    }
}

impl From<ParticipantId> for Participant {
    fn from(participant_id: ParticipantId) -> Self {
        Participant::from(participant_id.0)
    }
}

impl ParticipantId {
    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn from_raw(raw: u32) -> Self {
        ParticipantId(raw)
    }
}

impl Display for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for ParticipantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A batched list of multiple cait-sith protocol messages.
pub type BatchedMessages = Vec<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcMessage {
    pub task_id: MpcTaskId,
    pub data: BatchedMessages,
    pub participants: Vec<ParticipantId>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskSignatureType {
    EDDSA,
    ECDSA {
        presignature_id: UniqueId,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    KeyGenerationEcdsa,
    KeyGenerationEddsa,
    ManyTriples {
        start: UniqueId,
        count: u32,
    },
    Presignature {
        id: UniqueId,
        paired_triple_id: UniqueId,
    },
    Signature {
        id: SignatureId,
        signature_type: MpcTaskSignatureType
    },
}

pub trait HasParticipants {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool;
}

pub type PairedTriple = (
    TripleGenerationOutput<Secp256k1>,
    TripleGenerationOutput<Secp256k1>,
);

impl HasParticipants for PairedTriple {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
        let triple_participants = participants_from_triples(&self.0, &self.1);
        triple_participants
            .iter()
            .all(|p| active_participants.contains(p))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutputWithParticipants {
    pub presignature: PresignOutput<Secp256k1>,
    pub participants: Vec<ParticipantId>,
}

impl HasParticipants for PresignOutputWithParticipants {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
        self.participants
            .iter()
            .all(|p| active_participants.contains(p))
    }
}

pub fn choose_random_participants(
    participants: Vec<ParticipantId>,
    me: ParticipantId,
    threshold: usize,
) -> Vec<ParticipantId> {
    assert!(participants.len() >= threshold);
    let mut res = participants
        .into_iter()
        .filter(|p| p != &me)
        .choose_multiple(&mut rand::thread_rng(), threshold - 1);
    res.push(me);
    res
}

pub fn participants_from_triples(
    triple0: &TripleGenerationOutput<Secp256k1>,
    triple1: &TripleGenerationOutput<Secp256k1>,
) -> Vec<ParticipantId> {
    triple0
        .1
        .participants
        .iter()
        .copied()
        .filter(|p| triple1.1.participants.contains(p))
        .map(|p| p.into())
        .collect()
}
