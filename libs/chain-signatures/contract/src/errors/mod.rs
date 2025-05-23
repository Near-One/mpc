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
    #[error("The provided signature scheme does not match the requestued key's scheme")]
    SignatureSchemeMismatch,
    #[error("The provided domain was not found.")]
    DomainNotFound,
    #[error("The provided tweak is not on the curve of the public key.")]
    TweakNotOnCurve,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Derived key conversion failed.")]
    DerivedKeyConversionFailed,
    #[error("The provided domain was not found.")]
    DomainNotFound,
    #[error("The provided tweak is not on the curve of the public key.")]
    TweakNotOnCurve,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum KeyEventError {
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
    #[error(
        "Candidates can only cast a vote after `threshold` participants casted one to admit them"
    )]
    VoterPending,
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
    #[error("The provided domain was not found.")]
    DomainNotFound,
    #[error("Provided Epoch Id does not match expected.")]
    EpochMismatch,
    #[error("Next domain ID mismatch")]
    NextDomainIdMismatch,
    #[error("Invalid domain ID.")]
    InvalidDomainId,
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
    #[error("Key event threshold must match the number of participants")]
    DKGThresholdFailed,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidCandidateSet {
    #[error("Set of proposed participants must contain at least `threshold` old participants.")]
    InsufficientOldParticipants,
    #[error("Participant ids are not coherent.")]
    IncoherentParticipantIds,
    #[error("New Participant ids need to be unique and contiguous.")]
    NewParticipantIdsNotContiguous,
    #[error("New Participant ids need to not skip any unused participant ids.")]
    NewParticipantIdsTooHigh,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum ConversionError {
    #[error("Data conversion error.")]
    DataConversion,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum DomainError {
    #[error("No such domain.")]
    NoSuchDomain,
    #[error("Newly proposed domain IDs are not contiguous.")]
    NewDomainIdsNotContiguous,
    #[error("vote_add_domains must add at least one domain")]
    AddDomainsMustAddAtLeastOneDomain,
    #[error("Invalid list of domains provided")]
    InvalidDomains,
    #[error("Domains from keyset do not match the provided domains")]
    DomainsMismatch,
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
    // Domain errors
    #[error("{0}")]
    DomainError(#[from] DomainError),
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
