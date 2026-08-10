//! Mock PCD header — mirrors `ragu_pcd::Header`.

use alloc::vec::Vec;

use ragu_pasta::{Ep, Eq, Fp, Fq};

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
    /// Creates a new application-defined [`Header`] suffix.
    ///
    /// # Panics
    ///
    /// Panics if `value` is large enough that adding the internal suffix
    /// offset would overflow `usize`, which would alias reserved internal
    /// suffixes.
    #[must_use]
    pub const fn new(value: usize) -> Self {
        assert!(
            value <= usize::MAX - NUM_INTERNAL_SUFFIXES,
            "application suffix too large; would alias internal suffixes",
        );

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

#[test]
fn test_suffix_max_application_value() {
    let max = usize::MAX - NUM_INTERNAL_SUFFIXES;
    let suffix = Suffix::new(max);
    assert_eq!(suffix.get(), usize::MAX as u64);
}

#[test]
#[should_panic(expected = "would alias internal suffixes")]
fn test_suffix_wrapping_panics() {
    let _ = Suffix::new(usize::MAX - NUM_INTERNAL_SUFFIXES + 1);
}

/// Mirrors `ragu_pcd::Header`.
pub trait Header: Send + Sync + 'static {
    const SUFFIX: Suffix;
    type Data: Send + Clone;

    /// Decomposes header data into the in-circuit values it would carry, as
    /// `(Fp elements, Fq elements, Pallas points, Vesta points)`. Pass points
    /// as points, not coordinates: like real ragu's in-circuit `encode`, the
    /// identity is rejected when these are hashed.
    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>);
}

/// Trivial header for seed steps.
impl Header for () {
    type Data = ();

    const SUFFIX: Suffix = Suffix::internal(1);

    fn encode(_data: &()) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    }
}
