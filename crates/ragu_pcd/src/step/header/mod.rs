//! Headers are succinct representations of data used to represent the current
//! state of a computation.

use core::any::Any;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
use ragu_primitives::{allocator::Allocator, io::Write};
use udon::field::Field;

#[cfg(all(test, not(ragu_pcd_targeted_tests)))]
#[path = "../../../tests/header_injectivity.rs"]
mod injectivity_tests;
mod online;

pub(crate) use self::online::slot;
pub use self::online::{
    Has, NUM_ONLINE_FP_POLYS, OnlinePoly, OnlinePolyCommit, OnlinePolySlot, Padding,
};
#[doc(hidden)]
pub use self::online::{Slot0, Slot1};

/// The number of suffixes used internally by Ragu.
///
/// * `0` is reserved for all circuits that have a fixed ID, used internally for
///   recursion. This is not used by actual [`Header`] implementations.
/// * `1` is reserved for the unit header, `()`.
/// * `2` is reserved for the [`Dummy`] header, the input type of the
///   internal [`Bootstrap`] step. It is the only suffix that triggers the base
///   case; no application [`Step`] can declare it as an input, and the one
///   internal circuit whose input suffix is a witness constrains it away. A
///   step's circuit is not enforced in the base case, so the `collapse`
///   circuit also holds a step that takes the base case to be the bootstrap
///   step, which is what confines the base case to genuine bootstrapping.
///
/// [`Bootstrap`]: crate::step::internal::bootstrap::Bootstrap
/// [`Step`]: crate::step::Step
pub(crate) const NUM_INTERNAL_SUFFIXES: u8 = 3;

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
/// This trait defines the field encoding of the application data and
/// names the online polynomials the header's proofs carry. The polynomials
/// and their commitments are stored in [`Proof`](crate::Proof), separately
/// from [`Data`](Self::Data) and [`Output`](Self::Output).
///
/// See the [Writing Circuits](https://tachyon.z.cash/ragu/guide/writing_circuits.html)
/// guide for usage patterns and examples.
///
/// # Injectivity
///
/// A proof commits only to the field elements of its header, the public inputs
/// it speaks in terms of. Verifiers bind the data a [`Pcd`](crate::Pcd)
/// carries to those elements by recomputing [`encode`](Self::encode) from it,
/// so the encoding must be injective: no two distinct [`Data`](Self::Data)
/// values may encode to the same field elements. A header whose encoding is
/// lossy in this way is buggy. An honest proof of one value also verifies when
/// it carries the other, an adaptive soundness attack on the protocol built on
/// top.
///
/// Ragu cannot check this; it is an obligation of the application. The
/// constraints `encode` emits do not discharge it. They hold a prover's
/// witness to the invariants of `Data` inside the circuit, and verifiers
/// recompute the encoding natively without checking them, taking any routine's
/// [`Known`](ragu_core::routines::Prediction::Known) prediction in place of
/// executing it. Instead, `Data` should be a type that cannot hold values the
/// encoding would confuse. A flag and an amount encoded as `2 * amount + flag`
/// should be a `bool` and a `u64`, not two field elements: in the field,
/// `(1, 1000)` and `(0, 1000 + 1/2)` encode to the same element although both
/// flags are boolean, where `1/2` is the inverse of 2.
pub trait Header<F: Field>: Send + Sync + Any {
    /// Each header should use a unique suffix to distinguish itself from other
    /// headers. Application headers must use [`Suffix::new`]; only `()` may
    /// use a reserved internal suffix.
    const SUFFIX: Suffix;

    /// The online polynomials this header's proofs carry, one
    /// [`OnlinePolySlot`] per slot in slot order: `(TachygramSet, ActionSet)`,
    /// `(Padding, TachygramSet)`, or `(Padding, Padding)` for a header whose
    /// proofs carry only padding. See [`OnlinePolyCommit`].
    type OnlinePolyCommit: OnlinePolyCommit;

    /// The witness input needed to encode a header.
    ///
    /// It must not be able to hold two values that [`encode`](Self::encode)
    /// maps to the same field elements; see [Injectivity](Header#injectivity).
    type Data: Send + Clone;

    /// The output gadget that encodes the data for this header.
    type Output: Write<F>;

    /// Encodes witness input into a gadget representing this header.
    ///
    /// The encoding must be injective in [`Data`](Self::Data), and the
    /// constraints it emits do not make it so; see
    /// [Injectivity](Header#injectivity).
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

    type OnlinePolyCommit = (Padding, Padding);
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
/// [`Bootstrap`](crate::step::internal::bootstrap) step does. No other step
/// can declare it: application headers cannot encode to a reserved suffix,
/// and [`finalize`](crate::ApplicationBuilder::finalize) rejects any other
/// internal step that tries. A prover that witnesses the suffix without
/// declaring it is held to the bootstrap step by the `collapse` circuit.
pub(crate) struct Dummy;

impl<F: Field> Header<F> for Dummy {
    const SUFFIX: Suffix = Suffix::internal(2);

    type OnlinePolyCommit = (Padding, Padding);
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
        const MAX_APPLICATION_SUFFIX: Suffix =
            Suffix::new(usize::MAX - NUM_INTERNAL_SUFFIXES as usize);

        assert_eq!(Suffix::internal(0).get(), 0);
        assert_eq!(Suffix::internal(1).get(), 1);
        assert_eq!(Suffix::internal(2).get(), 2);
        assert_eq!(Suffix::new(0).get(), 3);
        assert_eq!(Suffix::new(1).get(), 4);
        assert_eq!(MAX_APPLICATION_SUFFIX.get(), usize::MAX as u64);
    }

    #[test]
    #[should_panic(
        expected = "application header suffix would overflow onto a reserved internal suffix"
    )]
    fn application_suffix_cannot_wrap_onto_a_reserved_suffix() {
        let _ = Suffix::new(usize::MAX - NUM_INTERNAL_SUFFIXES as usize + 1);
    }

    #[test]
    #[should_panic(
        expected = "application header suffix would overflow onto a reserved internal suffix"
    )]
    fn test_suffix_rejects_usize_max() {
        let _ = Suffix::new(usize::MAX);
    }
}
