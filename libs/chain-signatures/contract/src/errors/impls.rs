use std::borrow::Cow;
use std::fmt;

use super::{
    ConversionError, Error, ErrorKind, ErrorRepr, InvalidCandidateSet, InvalidParameters,
    InvalidState, InvalidThreshold, KeyEventError, PublicKeyError, RespondError, SignError,
    VoteError,
};

impl Error {
    /// Construct a contract [`Error`] with the details of an error which includes
    /// the custom error message with further context and the [`ErrorKind`] that
    /// represents the category of error.
    pub fn message<T>(kind: ErrorKind, msg: T) -> Self
    where
        T: Into<Cow<'static, str>>,
    {
        Self {
            repr: ErrorRepr::Message {
                kind,
                message: msg.into(),
            },
        }
    }

    /// Construct a contract [`Error`] with the details of an error which only
    /// includes the [`ErrorKind`] that represents the category of error.
    pub fn simple(kind: ErrorKind) -> Self {
        Self {
            repr: ErrorRepr::Simple(kind),
        }
    }

    /// Returns the corresponding [`ErrorKind`] for this error.
    pub fn kind(&self) -> &ErrorKind {
        match &self.repr {
            ErrorRepr::Simple(kind) => kind,
            ErrorRepr::Message { kind, .. } => kind,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.repr {
            ErrorRepr::Simple(kind) => write!(f, "{}", kind),
            ErrorRepr::Message { kind, message } => write!(f, "{}: {}", kind, message),
        }
    }
}

impl From<SignError> for Error {
    fn from(code: SignError) -> Self {
        Self::simple(ErrorKind::Sign(code))
    }
}

impl From<RespondError> for Error {
    fn from(code: RespondError) -> Self {
        Self::simple(ErrorKind::Respond(code))
    }
}

impl From<PublicKeyError> for Error {
    fn from(code: PublicKeyError) -> Self {
        Self::simple(ErrorKind::PublicKey(code))
    }
}

impl From<VoteError> for Error {
    fn from(code: VoteError) -> Self {
        Self::simple(ErrorKind::Vote(code))
    }
}

impl From<InvalidParameters> for Error {
    fn from(code: InvalidParameters) -> Self {
        Self::simple(ErrorKind::InvalidParameters(code))
    }
}

impl InvalidParameters {
    pub(crate) fn message<T>(self, msg: T) -> Error
    where
        T: Into<Cow<'static, str>>,
    {
        Error::message(ErrorKind::InvalidParameters(self), msg)
    }
}

impl From<InvalidState> for Error {
    fn from(code: InvalidState) -> Self {
        Self::simple(ErrorKind::InvalidState(code))
    }
}

impl InvalidState {
    pub(crate) fn message<T>(self, msg: T) -> Error
    where
        T: Into<Cow<'static, str>>,
    {
        Error::message(ErrorKind::InvalidState(self), msg)
    }
}

impl From<ConversionError> for Error {
    fn from(code: ConversionError) -> Self {
        Self::simple(ErrorKind::ConversionError(code))
    }
}
impl ConversionError {
    pub(crate) fn message<T>(self, msg: T) -> Error
    where
        T: Into<Cow<'static, str>>,
    {
        Error::message(ErrorKind::ConversionError(self), msg)
    }
}

impl From<KeyEventError> for Error {
    fn from(code: KeyEventError) -> Self {
        Self::simple(ErrorKind::KeyEventError(code))
    }
}
//impl KeyEventError {
//    pub(crate) fn message<T>(self, msg: T) -> Error
//    where
//        T: Into<Cow<'static, str>>,
//    {
//        Error::message(ErrorKind::KeyEventError(self), msg)
//    }
//}

impl InvalidThreshold {
    pub(crate) fn message<T>(self, msg: T) -> Error
    where
        T: Into<Cow<'static, str>>,
    {
        Error::message(ErrorKind::InvalidThreshold(self), msg)
    }
}
impl From<InvalidThreshold> for Error {
    fn from(code: InvalidThreshold) -> Self {
        Self::simple(ErrorKind::InvalidThreshold(code))
    }
}
impl From<InvalidCandidateSet> for Error {
    fn from(code: InvalidCandidateSet) -> Self {
        Self::simple(ErrorKind::InvalidCandidateSet(code))
    }
}
