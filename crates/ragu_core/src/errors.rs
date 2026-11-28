use alloc::boxed::Box;
use core::{error, result};

/// Alias for [`core::result::Result<T, Error>`].
pub type Result<T> = result::Result<T, Error>;

/// Represents errors that can occur while running circuit code or related
/// protocol code.
///
/// This type captures witness-generation errors, input errors, encoding errors,
/// capacity errors, setup errors, structural errors, and local check errors that
/// can occur at various nesting levels of a protocol.
///
/// The [`InvalidWitness`](Error::InvalidWitness),
/// [`MalformedEncoding`](Error::MalformedEncoding), and
/// [`Initialization`](Error::Initialization) variants chain their inner error
/// via [`source()`](error::Error::source).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Capacity error: emitted constraints demand too many gates.
    #[error("exceeded the maximum number of gates ({limit})")]
    GateBoundExceeded {
        /// The maximum number of gates allowed by the backend.
        limit: usize,
    },

    /// Capacity error: emitted constraints demand too many linear constraints.
    #[error("exceeded the maximum number of constraints ({limit})")]
    ConstraintBoundExceeded {
        /// The maximum number of constraints allowed by the backend.
        limit: usize,
    },

    /// Capacity error: too many individual circuits are being created within a
    /// larger context, such as a computational graph for proof-carrying data.
    #[error("exceeded the maximum number of circuits ({limit})")]
    CircuitBoundExceeded {
        /// The maximum number of circuits allowed within the context.
        limit: usize,
    },

    /// Capacity error: a polynomial exceeded a configured degree bound.
    #[error("exceeded the maximum degree of a polynomial ({limit})")]
    DegreeBoundExceeded {
        /// The maximum polynomial degree allowed.
        limit: usize,
    },

    /// Legacy catch-all for witness-generation, local-check, input, or structural
    /// errors.
    ///
    /// This variant is retained for compatibility. Documentation should describe
    /// the concrete failure category and condition instead of referring to it as
    /// an "invalid witness."
    ///
    /// Code that constructs this variant may box a dedicated error type so that
    /// callers can identify a specific failure condition. A caller probes for
    /// such a condition with
    /// [`invalid_witness_source`](Error::invalid_witness_source) or by
    /// downcasting the boxed source directly. The `Display` output of this
    /// variant is not a stable contract; the typed source is.
    #[error("invalid witness: {0}")]
    InvalidWitness(#[source] Box<dyn error::Error + Send + Sync + 'static>),

    /// Encoding error: serialized or encoded data is malformed.
    #[error("malformed encoding: {0}")]
    MalformedEncoding(#[source] Box<dyn error::Error + Send + Sync + 'static>),

    /// Input or encoding error: a fixed-length vector was given the wrong
    /// length, or two gadgets of run-time length that are paired wire by
    /// wire do not have the same length.
    #[error("vector does not have the expected length: (expected {expected}, actual {actual})")]
    VectorLengthMismatch {
        /// Expected length: the one the type-level length requires, or the
        /// length of the first of the two gadgets.
        expected: usize,
        /// Actual length observed at runtime.
        actual: usize,
    },

    /// Setup error: registration, initialization, or configuration failed.
    #[error("initialization failed: {0}")]
    Initialization(#[source] Box<dyn error::Error + Send + Sync + 'static>),
}

impl Error {
    /// Returns the boxed source of an [`Error::InvalidWitness`] downcast to
    /// `T`.
    ///
    /// Returns `None` when this error is a different variant or when the
    /// source is not a `T`. A caller that expects a specific
    /// witness-generation failure for some inputs uses this to detect that
    /// condition and retry with a different input.
    pub fn invalid_witness_source<T: error::Error + 'static>(&self) -> Option<&T> {
        match self {
            Self::InvalidWitness(source) => source.downcast_ref::<T>(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        use alloc::format;

        assert_eq!(
            format!("{}", Error::GateBoundExceeded { limit: 1024 }),
            "exceeded the maximum number of gates (1024)"
        );
        assert_eq!(
            format!("{}", Error::ConstraintBoundExceeded { limit: 4096 }),
            "exceeded the maximum number of constraints (4096)"
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
        let err = Error::GateBoundExceeded { limit: 1 };
        assert!(err.source().is_none());

        let err = Error::ConstraintBoundExceeded { limit: 1 };
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

    /// Verifies that `invalid_witness_source` downcasts the boxed source of
    /// `InvalidWitness` and returns `None` for a mismatched source type and
    /// for other variants.
    #[test]
    fn test_invalid_witness_source() {
        #[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
        #[error("marker")]
        struct Marker;

        let err = Error::InvalidWitness(Box::new(Marker));
        assert_eq!(err.invalid_witness_source::<Marker>(), Some(&Marker));

        let err = Error::InvalidWitness("inner".into());
        assert!(err.invalid_witness_source::<Marker>().is_none());

        let err = Error::GateBoundExceeded { limit: 1 };
        assert!(err.invalid_witness_source::<Marker>().is_none());
    }
}
