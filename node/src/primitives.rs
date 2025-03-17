use crate::providers::EcdsaTaskId;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::Participant;
use cait_sith::triples::TripleGenerationOutput;
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
    pub kind: MpcMessageKind,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MpcMessageKind {
    Start(MpcStartMessage),
    Computation(Vec<Vec<u8>>),
    Abort(String),
    Success,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcStartMessage {
    pub participants: Vec<ParticipantId>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    EcdsaTaskId(EcdsaTaskId),
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

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IndexerHeightMessage {
    pub height: u64,
}

pub struct PeerIndexerHeightMessage {
    pub from: ParticipantId,
    pub message: IndexerHeightMessage,
}

pub enum PeerMessage {
    Mpc(MpcPeerMessage),
    IndexerHeight(PeerIndexerHeightMessage),
}
