//! Mock PCD header — mirrors `ragu_pcd::Header`.

use alloc::vec::Vec;

/// Number of internal header suffixes reserved by mock_ragu.
///
/// Mirrors real ragu's `InternalStepIndex` layout:
/// - Slot 0: `Rerandomize` (reserved; mock rerandomize is a transformation, not
///   a Step, but the slot stays reserved for migration parity).
/// - Slot 1: trivial header [`()`].
pub(crate) const NUM_INTERNAL_SUFFIXES: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum HeaderSuffix {
    Internal(usize),
    Application(usize),
}

/// Mirrors `ragu_pcd::header::Suffix`.
///
/// Variants are crate-private. Construct via [`Suffix::new`] for application
/// headers; only mock_ragu itself constructs internal-header suffixes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Suffix {
    suffix: HeaderSuffix,
}

impl Suffix {
    #[must_use]
    pub const fn new(value: usize) -> Self {
        Self {
            suffix: HeaderSuffix::Application(value),
        }
    }

    pub(crate) const fn internal(value: usize) -> Self {
        assert!(
            value < NUM_INTERNAL_SUFFIXES,
            "invalid internal header suffix index"
        );
        Self {
            suffix: HeaderSuffix::Internal(value),
        }
    }

    /// Returns the encoded value mapping internal vs application into a
    /// single `u64` namespace. Internal values occupy
    /// `0..NUM_INTERNAL_SUFFIXES` and application values follow.
    #[expect(
        clippy::expect_used,
        reason = "usize fits in u64 on all supported targets"
    )]
    pub(crate) fn get(self) -> u64 {
        let value_usize = match self.suffix {
            HeaderSuffix::Internal(value) => value,
            HeaderSuffix::Application(value) => value + NUM_INTERNAL_SUFFIXES,
        };
        u64::try_from(value_usize).expect("suffix value fits in u64")
    }
}

/// Mirrors `ragu_pcd::Header`.
pub trait Header: Send + Sync + 'static {
    const SUFFIX: Suffix;
    type Data: Send + Clone;
    fn encode(data: &Self::Data) -> Vec<u8>;
}

/// Trivial header for seed steps.
impl Header for () {
    type Data = ();

    const SUFFIX: Suffix = Suffix::internal(1);

    fn encode(_data: &()) -> Vec<u8> {
        Vec::new()
    }
}
