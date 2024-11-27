use crate::assets::UniqueId;
use borsh::{BorshDeserialize, BorshSerialize};
use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ParticipantId(pub u32);

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

impl Display for ParticipantId {
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
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MpcPeerMessage {
    pub from: ParticipantId,
    pub message: MpcMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum MpcTaskId {
    KeyGeneration,
    ManyTriples {
        start: UniqueId,
        count: u32,
    },
    Presignature {
        id: u64,
        triple0_id: UniqueId,
        triple1_id: UniqueId,
    },
    Signature {
        id: u64,
        presignature_id: u64,
        // TODO(#9): We need a proof for any signature requests
        msg_hash: [u8; 32],
        tweak: [u8; 32],
        entropy: [u8; 32],
    },
}
