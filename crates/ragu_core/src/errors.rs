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
///
/// The [`InvalidWitness`](Error::InvalidWitness),
/// [`MalformedEncoding`](Error::MalformedEncoding), and
/// [`Initialization`](Error::Initialization) variants chain their inner error
/// via [`source()`](error::Error::source).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Backends may fail to synthesize circuits that demand too many
    /// multiplication constraints to be enforced.
    #[error("exceeded the maximum number of multiplication constraints ({limit})")]
    MultiplicationBoundExceeded {
        /// The maximum number of multiplication constraints allowed by the backend.
        limit: usize,
    },

    /// Backends may fail to synthesize circuits that demand too many linear
    /// constraints to be enforced.
    #[error("exceeded the maximum number of linear constraints ({limit})")]
    LinearBoundExceeded {
        /// The maximum number of linear constraints allowed by the backend.
        limit: usize,
    },

    /// Backends may fail if too many individual circuits are being created
    /// within a larger context, such as a computational graph for
    /// proof-carrying data.
    #[error("exceeded the maximum number of circuits ({limit})")]
    CircuitBoundExceeded {
        /// The maximum number of circuits allowed within the context.
        limit: usize,
    },

    /// Polynomials that exceed some degree bound will trigger this error.
    #[error("exceeded the maximum degree of a polynomial ({limit})")]
    DegreeBoundExceeded {
        /// The maximum polynomial degree allowed.
        limit: usize,
    },

    /// Circuits may fail if they're asked to process, construct or verify
    /// witness data without (known) satisfiability.
    #[error("invalid witness: {0}")]
    InvalidWitness(#[source] Box<dyn error::Error + Send + Sync + 'static>),

    /// Synthesis can fail if data cannot be decoded from a stream like a proof
    /// string
    #[error("malformed encoding: {0}")]
    MalformedEncoding(#[source] Box<dyn error::Error + Send + Sync + 'static>),

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
    Initialization(#[source] Box<dyn error::Error + Send + Sync + 'static>),
}

#[test]
fn test_error_display() {
    use alloc::format;

    assert_eq!(
        format!("{}", Error::MultiplicationBoundExceeded { limit: 1024 }),
        "exceeded the maximum number of multiplication constraints (1024)"
    );
    assert_eq!(
        format!("{}", Error::LinearBoundExceeded { limit: 4096 }),
        "exceeded the maximum number of linear constraints (4096)"
    );
    assert_eq!(
        format!("{}", Error::CircuitBoundExceeded { limit: 256 }),
        "exceeded the maximum number of circuits (256)"
    );
    assert_eq!(
        format!("{}", Error::DegreeBoundExceeded { limit: 64 }),
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
            Error::Initialization("registry registration failed".into())
        ),
        "initialization failed: registry registration failed"
    );
}

/// Verifies that `source()` returns `Some` for wrapping variants and `None` for
/// non-wrapping variants, confirming that `#[source]` annotations and
/// `#[non_exhaustive]` are correctly applied.
#[test]
fn test_error_source() {
    use error::Error as _;

    // Wrapping variants should chain the inner error via source().
    let err = Error::InvalidWitness("inner".into());
    assert!(
        err.source().is_some(),
        "InvalidWitness should have a source"
    );

    let err = Error::MalformedEncoding("inner".into());
    assert!(
        err.source().is_some(),
        "MalformedEncoding should have a source"
    );

    let err = Error::Initialization("inner".into());
    assert!(
        err.source().is_some(),
        "Initialization should have a source"
    );

    // Bound variants and VectorLengthMismatch should not chain an inner error.
    let err = Error::MultiplicationBoundExceeded { limit: 1 };
    assert!(err.source().is_none());

    let err = Error::LinearBoundExceeded { limit: 1 };
    assert!(err.source().is_none());

    let err = Error::CircuitBoundExceeded { limit: 1 };
    assert!(err.source().is_none());

    let err = Error::DegreeBoundExceeded { limit: 1 };
    assert!(err.source().is_none());

    let err = Error::VectorLengthMismatch {
        expected: 3,
        actual: 2,
    };
    assert!(err.source().is_none());
}
