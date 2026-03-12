//! Headers are succinct representations of data used to represent the current
//! state of a computation.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
use ragu_primitives::io::Write;

use core::any::Any;

/// The number of suffixes used internally by Ragu.
///
/// * `0` is reserved for all circuits that have a fixed ID, used internally for
///   recursion. This is not used by actual [`Header`] implementations.
/// * `1` is reserved for the trivial header.
const NUM_INTERNAL_SUFFIXES: u8 = 2;

/// Internal representation of a [`Suffix`] distinguishing internal vs.
/// application suffixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
enum HeaderSuffix {
    Internal(usize),
    Application(usize),
}

/// The unique suffix for a [`Header`].
///
/// All steps register an `Output` header that represents their computational
/// state. In order to distinguish headers (regardless of the step that produced
/// them) a suffix is appended to each header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct Suffix {
    suffix: HeaderSuffix,
}

impl Suffix {
    /// Creates a new application-defined [`Header`] suffix.
    pub const fn new(value: usize) -> Self {
        Suffix {
            suffix: HeaderSuffix::Application(value),
        }
    }

    /// Obtain this suffix's `u64` value based on whether this represents an
    /// internal or application [`Header`] suffix.
    pub(crate) fn get(&self) -> u64 {
        match self.suffix {
            HeaderSuffix::Internal(i) => i as u64,
            HeaderSuffix::Application(i) => (i + NUM_INTERNAL_SUFFIXES as usize) as u64,
        }
    }

    /// Creates a new internal-defined [`Header`] suffix. Only called internally
    /// by Ragu.
    pub(crate) const fn internal(value: usize) -> Self {
        assert!(
            value < NUM_INTERNAL_SUFFIXES as usize,
            "invalid internal header suffix index"
        );

        Suffix {
            suffix: HeaderSuffix::Internal(value),
        }
    }
}

#[test]
fn test_suffix_map() {
    assert_eq!(Suffix::internal(0).get(), 0);
    assert_eq!(Suffix::internal(1).get(), 1);
    assert_eq!(Suffix::new(0).get(), 2);
    assert_eq!(Suffix::new(1).get(), 3);
}

/// Headers are succinct representations of data, essentially used as public
/// inputs to recursive proofs in order to represent the current state of the
/// computation.
///
/// See the [Writing Circuits](https://tachyon.z.cash/guide/writing_circuits.html)
/// guide for usage patterns and examples.
pub trait Header<F: Field>: Send + Sync + Any {
    /// Each header should use a unique suffix to distinguish itself from other
    /// headers.
    const SUFFIX: Suffix;

    /// The data needed to encode a header.
    type Data<'source>: Send + Clone;

    /// The output gadget that encodes the data for this header.
    type Output: Write<F>;

    /// Encode some data into a gadget representing this header.
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>;
}

/// Trivial header that encodes no data.
impl<F: Field> Header<F> for () {
    const SUFFIX: Suffix = Suffix::internal(1);

    type Data<'source> = ();
    type Output = ();

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }
}
