use std::borrow::Cow;
mod impls;
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("Signature request has timed out.")]
    Timeout,
    #[error("Signature request has already been submitted. Please try again later.")]
    PayloadCollision,
    #[error(
        "This key version is not supported. Call latest_key_version() to get the latest supported version."
    )]
    UnsupportedKeyVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RespondError {
    #[error("The provided signature is invalid.")]
    InvalidSignature,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Derived key conversion failed.")]
    DerivedKeyConversionFailed,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum KeyEventError {
    #[error("Epoch Id must be incremented by one.")]
    EpochMismatch,
    #[error("Key event Id mismatch")]
    KeyEventIdMismatch,
    #[error("Can not start a new reshare or keygen instance while the current instance is still active.")]
    ActiveKeyEvent,
    #[error("Expected ongoing reshare")]
    NoActiveKeyEvent,
}
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum VoteError {
    #[error("Voting account is not a participant.")]
    VoterNotParticipant,
    #[error("Voting account is neither a participant, nor a proposed participant.")]
    VoterNotParticipantNorProposedParticipant,
    #[error("This participant already registered a vote.")]
    ParticipantVoteAlreadyRegistered,
    #[error("Voting account is not the leader of the current reshare or keygen instance.")]
    VoterNotLeader,
    #[error("Inconsistent voting state")]
    InconsistentVotingState,
    #[error("Voter already aborted the current key event.")]
    VoterAlreadyAborted,
    #[error("Vote already casted.")]
    VoteAlreadySubmitted,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidParameters {
    #[error("Malformed payload.")]
    MalformedPayload,
    #[error("Attached deposit is lower than required.")]
    InsufficientDeposit,
    #[error("Provided gas is lower than required.")]
    InsufficientGas,
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
    #[error("Update not found.")]
    UpdateNotFound,
    #[error("Participant already in set.")]
    ParticipantAlreadyInSet,
    #[error("Participant id already used.")]
    ParticipantAlreadyUsed,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidState {
    #[error("The protocol is not Running.")]
    ProtocolStateNotRunning,
    #[error("Protocol state is not resharing.")]
    ProtocolStateNotResharing,
    #[error("Protocol state is not initializing.")]
    ProtocolStateNotInitializing,
    #[error("Protocol state is not running, nor resharing.")]
    ProtocolStateNotRunningNorResharing,
    #[error("Unexpected protocol state.")]
    UnexpectedProtocolState,
    #[error("Cannot load in contract due to missing state")]
    ContractStateIsMissing,
    #[error("Participant index out of range")]
    ParticipantIndexOutOfRange,
    #[error("Not a participant")]
    NotParticipant,
}
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidThreshold {
    #[error("Threshold does not meet the minimum absolute requirement")]
    MinAbsRequirementFailed,
    #[error("Threshold does not meet the minimum relative requirement")]
    MinRelRequirementFailed,
    #[error("Threshold must not exceed number of participants")]
    MaxRequirementFailed,
    #[error("Key event threshold must not be less than voting threshold")]
    MinDKGThresholdFailed,
    #[error("Key event threshold must not exceeed number of participants")]
    MaxDKGThresholdFailed,
}
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidCandidateSet {
    #[error("Set of proposed participants must contain at least `threshold` old participants.")]
    InsufficientOldParticipants,
    #[error("Participant ids are not coherent.")]
    IncoherentParticipantIds,
}
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ConversionError {
    #[error("Data conversion error.")]
    DataConversion,
}

/// A list specifying general categories of MPC Contract errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// An error occurred while user is performing sign request.
    #[error("{0}")]
    Sign(#[from] SignError),
    /// An error occurred while node is performing respond call.
    #[error("{0}")]
    Respond(#[from] RespondError),
    /// An error occurred while user is performing public_key_* call.
    #[error("{0}")]
    PublicKey(#[from] PublicKeyError),
    /// An error occurred while node is performing vote_* call.
    #[error("{0}")]
    Vote(#[from] VoteError),
    // Invalid parameters errors
    #[error("{0}")]
    InvalidParameters(#[from] InvalidParameters),
    // Invalid state errors
    #[error("{0}")]
    InvalidState(#[from] InvalidState),
    // Conversion errors
    #[error("{0}")]
    ConversionError(#[from] ConversionError),
    // Invalid state errors
    #[error("{0}")]
    InvalidThreshold(#[from] InvalidThreshold),
    // Invalid Candidate errors
    #[error("{0}")]
    InvalidCandidateSet(#[from] InvalidCandidateSet),
    // Key event errors
    #[error("{0}")]
    KeyEventError(#[from] KeyEventError),
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("{0}")]
    Simple(ErrorKind),
    #[error("{message}")]
    Message {
        kind: ErrorKind,
        message: Cow<'static, str>,
    },
}

/// Error type that this contract will make use of for all the errors
/// returned from this library
#[derive(Debug)]
pub struct Error {
    repr: ErrorRepr,
}

impl near_sdk::FunctionError for Error {
    fn panic(&self) -> ! {
        crate::env::panic_str(&self.to_string())
    }
}
