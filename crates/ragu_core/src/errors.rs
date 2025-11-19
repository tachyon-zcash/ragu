use alloc::boxed::Box;
use core::{error, result};

/// Alias for [`core::result::Result<T, Error>`].
pub type Result<T> = result::Result<T, Error>;

/// Represents the possible errors that might occur during circuit synthesis.
///
/// This type captures all errors that can occur during circuit synthesis in the
/// presence of a driver. There are numerous possible errors that can occur at
/// various nesting levels of a protocol due to the complexity of recursive
/// proofs, and so this is a catch-all error type for Ragu.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Backends may fail to synthesize circuits that demand too many
    /// multiplication constraints to be enforced.
    #[error("exceeded the maximum number of multiplication constraints ({0})")]
    MultiplicationBoundExceeded(usize),

    /// Backends may fail to synthesize circuits that demand too many linear
    /// constraints to be enforced.
    #[error("exceeded the maximum number of linear constraints ({0})")]
    LinearBoundExceeded(usize),

    /// Backends may fail if too many individual circuits are being created
    /// within a larger context, such as a computational graph for
    /// proof-carrying data.
    #[error("exceeded the maximum number of circuits ({0})")]
    CircuitBoundExceeded(usize),

    /// Polynomials that exceed some degree bound will trigger this error.
    #[error("exceeded the maximum degree of a polynomial ({0})")]
    DegreeBoundExceeded(usize),

    /// Circuits may fail if they're asked to process, construct or verify
    /// witness data without (known) satisfiability.
    #[error("invalid witness: {0}")]
    InvalidWitness(Box<dyn error::Error + Send + Sync + 'static>),

    /// Synthesis can fail if data cannot be decoded from a stream like a proof
    /// string
    #[error("malformed encoding: {0}")]
    MalformedEncoding(Box<dyn error::Error + Send + Sync + 'static>),

    /// Violation of length constraint for a fixed-length vector
    #[error("vector does not have the expected length: (expected {expected}, actual {actual})")]
    VectorLengthMismatch {
        /// Expected length enforced by static (compile-time) requirement
        expected: usize,
        /// Actual length observed at runtime
        actual: usize,
    },

    /// Failure in the process of performing setup or other initialization steps.
    #[error("initialization failed: {0}")]
    Initialization(Box<dyn error::Error + Send + Sync + 'static>),
}

#[test]
fn test_error_display() {
    use alloc::format;

    assert_eq!(
        format!("{}", Error::MultiplicationBoundExceeded(1024)),
        "exceeded the maximum number of multiplication constraints (1024)"
    );
    assert_eq!(
        format!("{}", Error::LinearBoundExceeded(4096)),
        "exceeded the maximum number of linear constraints (4096)"
    );
    assert_eq!(
        format!("{}", Error::CircuitBoundExceeded(256)),
        "exceeded the maximum number of circuits (256)"
    );
    assert_eq!(
        format!("{}", Error::DegreeBoundExceeded(64)),
        "exceeded the maximum degree of a polynomial (64)"
    );
    assert_eq!(
        format!("{}", Error::InvalidWitness("division by zero".into())),
        "invalid witness: division by zero"
    );
    assert_eq!(
        format!("{}", Error::MalformedEncoding("stream ended".into())),
        "malformed encoding: stream ended"
    );
    assert_eq!(
        format!(
            "{}",
            Error::VectorLengthMismatch {
                expected: 10,
                actual: 5
            }
        ),
        "vector does not have the expected length: (expected 10, actual 5)"
    );
    assert_eq!(
        format!(
            "{}",
            Error::Initialization("mesh registration failed".into())
        ),
        "initialization failed: mesh registration failed"
    );
}
