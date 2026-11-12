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
pub(crate) const NUM_INTERNAL_SUFFIXES: u8 = 3;

/// The number of online polynomial slots stored in each [`Proof`](crate::Proof).
/// Their commitments are associated with the output header and exposed by
/// [`Pcd::commitments`](crate::Pcd::commitments); the [`Header`] trait
/// defines the field encoding separately.
///
/// This is a parameter of the protocol, not of a header type: every proof
/// stores exactly this many polynomials, every step commits this many for
/// its output through [`Step::polynomials`](crate::step::Step::polynomials)
/// and may open its own or either child's through
/// [`Oracles`](crate::step::Oracles). A step's six online slots are the
/// polynomials in left, right, output order; they are opened
/// by the step's own batch, so every step pays for all of them whether its
/// headers use them or not.
///
/// What a slot holds is the application's convention for that header, as
/// the meaning of its fields is: a step whose output needs fewer
/// polynomials puts the constant one in the rest, and a step that relies on
/// a slot's content relies on the circuits of the steps that produce the
/// header, which are registered. Ragu proves only that every opening is of
/// the polynomial the producing step committed; no header type can change
/// how many a proof carries or which its slots are.
///
/// Ragu does not hold a slot to the constant one, or to anything else: a
/// slot whose opening the producing step's circuit leaves unconstrained
/// holds a polynomial of the prover's choosing. A header whose convention
/// makes a slot padding needs every step that outputs it to open that slot
/// at its challenge and hold the value to one.
///
/// The polynomial commitments are unblinded and deterministic for their
/// coefficients; opening points and values are public. Values intended to
/// stay out of the public instance belong in
/// [`Step::staged`](crate::step::Step::staged), whose stage commitment is
/// blinded; public openings can still reveal those values.
///
/// A compressed proof's statement carries only the header's fields, so a
/// header type registered at a suffix a decompressed statement can land on
/// must treat its slots as padding: the decompression step holds them to
/// the constant one, and a step that opens them expecting the polynomial
/// the fields describe checks the wrong polynomial. Binding those slots to
/// the compressed proof's own online commitments would be a change to the
/// statement extension's contract.
pub const NUM_ONLINE_POLYNOMIALS: usize = 2;

/// A kind of online polynomial, identified by a unit type.
///
/// A header lists the kinds its proofs carry in [`Header::OnlinePolyCommit`],
/// and a step reads an input's polynomial, prepares its output's and opens
/// either by its kind. The same kind is the same type in every header that
/// carries it; where a header keeps it is stated once, in the header's list.
///
/// # Examples
///
/// ```
/// use ragu_pcd::header::OnlinePoly;
///
/// /// The polynomial whose roots are a tachygram set.
/// #[derive(Clone, Copy, Debug)]
/// pub struct TachygramSet;
///
/// impl OnlinePoly for TachygramSet {}
/// ```
pub trait OnlinePoly: Copy + Send + Sync + 'static {}

/// A slot a header leaves unused.
///
/// Listed in [`Header::OnlinePolyCommit`] in the slot's place. The header's
/// proofs hold the constant one there, and no step can name the slot,
/// because `Padding` is not an [`OnlinePoly`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Padding;

/// An entry of a header's [`OnlinePolyCommit`] list: a kind of polynomial,
/// or [`Padding`].
pub trait OnlinePolySlot: Copy + Send + Sync + 'static {}

impl<P: OnlinePoly> OnlinePolySlot for P {}

impl OnlinePolySlot for Padding {}

/// The online polynomials a header's proofs carry, one entry per slot.
///
/// Implemented for tuples of [`NUM_ONLINE_POLYNOMIALS`] [`OnlinePolySlot`]s
/// in slot order, as [`Header::OnlinePolyCommit`]: `(TachygramSet, ActionSet)`
/// fills both slots, `(Padding, TachygramSet)` keeps a set polynomial in
/// the last slot alone, the one whose commitment the bridge hash digests,
/// and `(Padding, Padding)` carries nothing of the header's own. A slot
/// that does not exist cannot be listed, and a kind the list does not hold
/// cannot be named: [`Has`] finds a kind's slot at compile time.
///
/// # Examples
///
/// ```compile_fail
/// use ragu_pcd::header::{Has, OnlinePoly, Padding};
///
/// #[derive(Clone, Copy, Debug)]
/// struct TachygramSet;
/// impl OnlinePoly for TachygramSet {}
///
/// fn slot<L: Has<P, I>, P, I>(_: P) -> usize {
///     L::INDEX
/// }
///
/// assert_eq!(slot::<(Padding, TachygramSet), _, _>(TachygramSet), 1);
/// slot::<(Padding, TachygramSet), _, _>(Padding); // error: expected `TachygramSet`, found `Padding`
/// ```
pub trait OnlinePolyCommit: sealed::Sealed + Send + Sync + 'static {}

impl<A: OnlinePolySlot, B: OnlinePolySlot> OnlinePolyCommit for (A, B) {}

impl<A: OnlinePolySlot, B: OnlinePolySlot> sealed::Sealed for (A, B) {}

mod sealed {
    pub trait Sealed {}
}

/// A list that keeps the kind `P` in the slot marked by `I`.
///
/// `(A, B)` keeps `A` at index zero and `B` at index one. `I` is [`Slot0`]
/// or [`Slot1`]; the compiler infers it from `P`, so a call names only the
/// kind: `input.polynomial(TachygramSet)`. A list keeping `P` in both slots
/// cannot name it, and [`Padding`] is never found.
pub trait Has<P, I>: OnlinePolyCommit {
    /// The index of the slot, below [`NUM_ONLINE_POLYNOMIALS`].
    const INDEX: usize;
}

/// The marker of the first slot, for [`Has`].
#[derive(Clone, Copy, Debug)]
pub struct Slot0;

/// The marker of the second slot, for [`Has`].
#[derive(Clone, Copy, Debug)]
pub struct Slot1;

impl<A: OnlinePoly, B: OnlinePolySlot> Has<A, Slot0> for (A, B) {
    const INDEX: usize = 0;
}

impl<A: OnlinePolySlot, B: OnlinePoly> Has<B, Slot1> for (A, B) {
    const INDEX: usize = 1;
}

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
/// [`Bootstrap`](crate::step::internal::bootstrap) step does. Nothing else can
/// — application headers cannot encode to a reserved suffix, and
/// [`finalize`](crate::ApplicationBuilder::finalize) rejects any other internal
/// step that tries.
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

    #[derive(Clone, Copy, Debug)]
    struct First;
    impl OnlinePoly for First {}

    #[derive(Clone, Copy, Debug)]
    struct Second;
    impl OnlinePoly for Second {}

    fn index_of<L: Has<P, I>, P, I>(_: P) -> usize {
        L::INDEX
    }

    #[test]
    fn a_kind_is_found_at_its_slot() {
        assert_eq!(index_of::<(First, Second), _, _>(First), 0);
        assert_eq!(index_of::<(First, Second), _, _>(Second), 1);
        assert_eq!(index_of::<(Padding, Second), _, _>(Second), 1);
        assert_eq!(index_of::<(First, Padding), _, _>(First), 0);
    }

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
