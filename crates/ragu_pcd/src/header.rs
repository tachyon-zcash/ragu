//! Headers are succinct representations of data used to represent the current
//! state of a computation.

use core::any::Any;

use ragu_arithmetic::ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
use ragu_primitives::{allocator::Allocator, io::Write};

/// The number of suffixes used internally by Ragu.
///
/// * `0` is reserved for all circuits that have a fixed ID, used internally for
///   recursion. This is not used by actual [`Header`] implementations.
/// * `1` is reserved for the unit header, `()`.
/// * `2` is reserved for the [`Dummy`] header, the input type of the
///   internal [`Bootstrap`] step. It is the only suffix that triggers the base
///   case; no application [`Step`] can declare it as an input, and the one
///   internal circuit whose input suffix is a witness constrains it away, which
///   is what confines the base case to genuine bootstrapping.
///
/// [`Bootstrap`]: crate::step::internal::bootstrap::Bootstrap
/// [`Step`]: crate::step::Step
const NUM_INTERNAL_SUFFIXES: u8 = 3;

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
    ///
    /// # Panics
    ///
    /// Panics if `value` is large enough that offsetting it past the internal
    /// suffixes would overflow and alias a reserved internal suffix.
    #[must_use]
    pub const fn new(value: usize) -> Self {
        assert!(
            value <= usize::MAX - NUM_INTERNAL_SUFFIXES as usize,
            "application header suffix would overflow onto a reserved internal suffix"
        );

        Suffix {
            suffix: HeaderSuffix::Application(value),
        }
    }

    /// Obtain this suffix's `u64` value based on whether this represents an
    /// internal or application [`Header`] suffix.
    pub(crate) const fn get(&self) -> u64 {
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

/// Headers are succinct representations of data, essentially used as public
/// inputs to recursive proofs in order to represent the current state of the
/// computation.
///
/// See the [Writing Circuits](https://tachyon.z.cash/ragu/guide/writing_circuits.html)
/// guide for usage patterns and examples.
pub trait Header<F: Field>: Send + Sync + Any {
    /// Each header should use a unique suffix to distinguish itself from other
    /// headers.
    const SUFFIX: Suffix;

    /// The witness input needed to encode a header.
    type Data: Send + Clone;

    /// The output gadget that encodes the data for this header.
    type Output: Write<F>;

    /// Encodes witness input into a gadget representing this header.
    ///
    /// Implementations should pass `allocator` through to all allocation
    /// calls rather than substituting a different allocator.
    ///
    /// # Constraints
    ///
    /// The implementation of this method and the allocator's behavior and state
    /// determine the constraints emitted while constructing `Output`. The
    /// `Output` implementation determines any constraints emitted when callers
    /// serialize it.
    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>;
}

/// Header that encodes no data.
///
/// This is an ordinary header that happens to carry nothing. The internal
/// bootstrap step outputs it, and application steps may consume or produce it.
/// Its suffix does not trigger the base case; only the private `Dummy` header
/// does.
impl<F: Field> Header<F> for () {
    const SUFFIX: Suffix = Suffix::internal(1);

    type Data = ();
    type Output = ();

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }
}

/// The header of the synthesized proofs the bootstrap step consumes.
///
/// It encodes no data and exists only for its suffix: a step declaring it for
/// both inputs takes the base case, and only the internal
/// [`Bootstrap`](crate::step::internal::bootstrap) step does. Nothing else can
/// — application headers cannot encode to a reserved suffix, and
/// [`finalize`](crate::ApplicationBuilder::finalize) rejects any other internal
/// step that tries.
pub(crate) struct Dummy;

impl<F: Field> Header<F> for Dummy {
    const SUFFIX: Suffix = Suffix::internal(2);

    type Data = ();
    type Output = ();

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suffix_map() {
        assert_eq!(Suffix::internal(0).get(), 0);
        assert_eq!(Suffix::internal(1).get(), 1);
        assert_eq!(Suffix::internal(2).get(), 2);
        assert_eq!(Suffix::new(0).get(), 3);
        assert_eq!(Suffix::new(1).get(), 4);
        assert_eq!(
            Suffix::new(usize::MAX - NUM_INTERNAL_SUFFIXES as usize).get(),
            usize::MAX as u64
        );
    }

    #[test]
    #[should_panic(expected = "overflow onto a reserved internal suffix")]
    fn application_suffix_cannot_wrap_onto_a_reserved_suffix() {
        let first_invalid = usize::MAX - NUM_INTERNAL_SUFFIXES as usize + 1;
        let _ = Suffix::new(first_invalid);
    }
}
