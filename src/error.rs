//! All error types used by Snow operations.

use core::fmt;

/// All errors in snow will include an `ErrorKind`.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    /// The noise pattern failed to parse.
    Pattern(PatternProblem),

    /// Initialization failure, at a provided stage.
    Init(InitStage),

    /// Missing prerequisite.
    Prereq(Prerequisite),

    /// A state error.
    State(StateProblem),

    /// Invalid input.
    Input,

    /// Diffie-hellman failed.
    Dh,

    /// Decryption failed.
    Decrypt,


    /// This enum may grow additional variants, so this makes sure clients
    /// don't count on exhaustive matching. (Otherwise, adding a new variant
    /// could break existing code.)
    #[doc(hidden)]
    __Nonexhaustive,
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum PatternProblem {
    TooFewParameters,
    UnsupportedHandshakeType,
    UnsupportedBaseType,
    UnsupportedHashType,
    UnsupportedDhType,
    UnsupportedCipherType,
    InvalidPsk,
    UnsupportedModifier,
}

impl From<PatternProblem> for Error {
    fn from(reason: PatternProblem) -> Self {
        Error::Pattern(reason)
    }
}

/// The various stages of initialization used to help identify
/// the specific cause of an `Init` error.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum InitStage {
    ValidateKeyLengths,
    ValidatePskLengths,
    ValidateCipherTypes,
    GetRngImpl,
    GetDhImpl,
    GetCipherImpl,
    GetHashImpl,
    ValidatePskPosition,
}

impl From<InitStage> for Error {
    fn from(reason: InitStage) -> Self {
        Error::Init(reason)
    }
}

/// A prerequisite that may be missing.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Prerequisite {
    LocalPrivateKey,
    RemotePublicKey,
}

impl From<Prerequisite> for Error {
    fn from(reason: Prerequisite) -> Self {
        Error::Prereq(reason)
    }
}

/// Specific errors in the state machine.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum StateProblem {
    MissingKeyMaterial,
    MissingPsk,
    NotTurnToWrite,
    NotTurnToRead,
    HandshakeNotFinished,
    HandshakeAlreadyFinished,
    OneWay,
    StatelessTransportMode,
}

impl From<StateProblem> for Error {
    fn from(reason: StateProblem) -> Self {
        Error::State(reason)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Pattern(reason) => write!(f, "pattern error: {:?}", reason),
            Error::Init(reason) => write!(f, "initialization error: {:?}", reason),
            Error::Prereq(reason) => write!(f, "prerequisite error: {:?}", reason),
            Error::State(reason) => write!(f, "state error: {:?}", reason),
            Error::Input => write!(f, "input error"),
            Error::Dh => write!(f, "diffie-hellman error"),
            Error::Decrypt => write!(f, "decrypt error"),
            Error::__Nonexhaustive => write!(f, "Nonexhaustive"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
