//! Mock PCD header — mirrors `ragu_pcd::Header`.

use alloc::vec::Vec;

use ragu_pasta::{Ep, Eq, Fp, Fq};

/// Number of internal header suffixes reserved by mock_ragu.
///
/// Mirrors real ragu's header suffix namespace:
/// - Slot 0: fixed-ID circuits used internally for recursion (reserved; mock
///   rerandomize is a transformation, not a Step, but the slot stays reserved
///   for migration parity).
/// - Slot 1: unit header `()`.
/// - Slot 2: dummy header, carried by the proofs the bootstrap step consumes
///   (reserved; the mock does not model recursion bootstrapping, but the slot
///   stays reserved for encoding parity).
pub(crate) const NUM_INTERNAL_SUFFIXES: usize = 3;

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
    /// Panics if `value` is large enough that offsetting it past the internal
    /// suffixes would overflow and alias a reserved internal suffix.
    #[must_use]
    pub const fn new(value: usize) -> Self {
        assert!(
            value <= usize::MAX - NUM_INTERNAL_SUFFIXES,
            "application header suffix would overflow onto a reserved internal suffix"
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
    pub(crate) fn get(self) -> u64 {
        match self.suffix {
            HeaderSuffix::Internal(value) => value as u64,
            HeaderSuffix::Application(value) => (value + NUM_INTERNAL_SUFFIXES) as u64,
        }
    }
}

#[test]
fn application_suffix_namespace_matches_ragu_pcd() {
    assert_eq!(Suffix::internal(0).get(), 0);
    assert_eq!(Suffix::internal(1).get(), 1);
    assert_eq!(Suffix::internal(2).get(), 2);
    assert_eq!(Suffix::new(0).get(), 3);
    assert_eq!(Suffix::new(1).get(), 4);
    assert_eq!(
        Suffix::new(usize::MAX - NUM_INTERNAL_SUFFIXES).get(),
        usize::MAX as u64
    );
}

#[test]
#[should_panic(expected = "overflow onto a reserved internal suffix")]
fn application_suffix_cannot_wrap_onto_a_reserved_suffix() {
    let _ = Suffix::new(usize::MAX);
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

/// Header that encodes no data.
///
/// Mirrors `ragu_pcd`: the bootstrap proof and application steps may carry
/// this ordinary header, while the private dummy suffix alone marks the base
/// case.
impl Header for () {
    type Data = ();

    const SUFFIX: Suffix = Suffix::internal(1);

    fn encode(_data: &()) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    }
}
