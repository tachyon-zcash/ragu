//! The online polynomials a header's proofs carry: how many there are, and
//! how a header lists them.

use core::any::TypeId;

/// The number of online polynomial slots over the circuit field stored in
/// each [`Proof`](crate::Proof).
/// Their commitments are associated with the output header and exposed by
/// [`Pcd::commitments`](crate::Pcd::commitments); the [`Header`] trait
/// defines the field encoding separately.
///
/// This is a parameter of the protocol, not of a header type: every proof
/// stores exactly this many polynomials, every step commits this many for
/// its output through [`Step::prepare`](crate::step::Step::prepare)
/// and may open its own or either child's through
/// [`Oracles`](crate::step::Oracles). A step's six online slots are the
/// polynomials in left, right, output order; they are opened
/// by the step's own batch, so every step pays for all of them whether its
/// headers use them or not.
///
/// What a slot holds is the application's convention for that header, as
/// the meaning of its fields is: a step whose output needs fewer
/// polynomials leaves the rest alone, and a step that relies on a slot's
/// content relies on the circuits of the steps that produce the header,
/// which are registered. Ragu proves only that every opening is of the
/// polynomial the producing step committed; no header type can change how
/// many a proof carries or which its slots are.
///
/// An output slot a step opens is held only by the constraints its
/// circuit places on the opening: one opened without a constraint holds a
/// polynomial of the prover's choosing. An output slot a step does not
/// open is padding, which Ragu holds to the constant one after the step's
/// circuit; a header whose convention makes a slot padding needs nothing
/// from the steps that output it.
///
/// The polynomial commitments are unblinded and deterministic for their
/// coefficients; opening points and values are public. Values intended to
/// stay out of the public instance belong in
/// the application stage, staged by
/// [`Step::prepare`](crate::step::Step::prepare), whose commitment is
/// blinded; public openings can still reveal those values.
///
/// A compressed proof's statement carries only the header's fields, so a
/// header type registered at a suffix a decompressed statement can land on
/// must treat its slots as padding: the decompression step holds them to
/// the constant one, and a step that opens them expecting the polynomial
/// the fields describe checks the wrong polynomial. Binding those slots to
/// the compressed proof's own online commitments would be a change to the
/// statement extension's contract.
///
/// [`Header`]: super::Header
pub const NUM_ONLINE_FP_POLYS: usize = 2;

/// The maximum number of online polynomials over the scalar field that a
/// step commits.
///
/// Such a polynomial belongs to the step that commits it. The step commits
/// it before its challenge is drawn, and the step's nested batch opens it.
/// The step does not export it, so a parent never opens it. Only a profile
/// that asks for the slot has it; see
/// [`Profile::ONLINE_FQ_POLYS`](crate::profile::Profile::ONLINE_FQ_POLYS),
/// whose slots hold a placeholder until decompression lands.
pub const NUM_ONLINE_FQ_POLYS: usize = 1;

/// A kind of online polynomial, identified by a unit type.
///
/// A header lists the kinds its proofs carry in
/// [`Header::OnlinePolyCommit`], and a step reads an input's polynomial,
/// prepares its output's and opens either by its kind. The same kind is the
/// same type in every header that carries it; where a header keeps it is
/// stated once, in the header's list.
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
///
/// [`Header::OnlinePolyCommit`]: super::Header::OnlinePolyCommit
pub trait OnlinePoly: Copy + Send + Sync + 'static {}

/// A slot a header leaves unused.
///
/// Listed in [`Header::OnlinePolyCommit`] in the slot's place. The
/// header's proofs hold the constant one there, and no step can name the
/// slot, because `Padding` is not an [`OnlinePoly`]. See
/// [`OnlinePolyCommit`] for where to put it.
///
/// [`Header::OnlinePolyCommit`]: super::Header::OnlinePolyCommit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Padding;

/// An entry of a header's [`OnlinePolyCommit`] list: a kind of polynomial,
/// or [`Padding`].
///
/// This trait is sealed: implement [`OnlinePoly`] for an application's
/// polynomial kind, or use [`Padding`] for an unused slot.
pub trait OnlinePolySlot: slot_sealed::Sealed + Copy + Send + Sync + 'static {}

impl<P: OnlinePoly> OnlinePolySlot for P {}

impl OnlinePolySlot for Padding {}

mod slot_sealed {
    use super::{OnlinePoly, Padding};

    pub trait Sealed {}

    impl<P: OnlinePoly> Sealed for P {}

    impl Sealed for Padding {}
}

/// The online polynomials a header's proofs carry, one entry per slot.
///
/// Implemented for tuples of [`NUM_ONLINE_FP_POLYS`] [`OnlinePolySlot`]s,
/// as [`Header::OnlinePolyCommit`].
///
/// # Reading a list
///
/// Read the tuple from left to right as slot 0, then slot 1. Each entry
/// states what the header's proofs hold in that slot: the polynomial of a
/// kind, or, for [`Padding`], the constant one.
///
/// | List                        | Slot 0           | Slot 1           |
/// |-----------------------------|------------------|------------------|
/// | `(TachygramSet, ActionSet)` | `TachygramSet`   | `ActionSet`      |
/// | `(TachygramSet, Padding)`   | `TachygramSet`   | the constant one |
/// | `(Padding, TachygramSet)`   | the constant one | `TachygramSet`   |
/// | `(Padding, Padding)`        | the constant one | the constant one |
///
/// # Slot order
///
/// A step names a polynomial by its kind, not by its slot, so the order
/// usually has no effect on the steps. It has an effect in these cases:
///
/// - The bridge hash digests the commitment in the last slot only (see
///   [`Oracles::bridge_hash`](crate::step::Oracles::bridge_hash)). If the
///   steps of a header read the bridge hash, put the hashed kind last, as
///   `(Padding, TachygramSet)` does.
/// - A proof stores, commits and opens the slots in this order. A change to
///   the order changes the header's proofs, but not the code of its steps.
///
/// # Errors at compile time
///
/// The tuple has one entry per slot, so a list cannot name a slot that
/// does not exist. [`Has`] finds the slot of a kind at compile time, so a
/// step cannot name a kind that the list does not hold, and it cannot name
/// [`Padding`]:
///
/// ```compile_fail,E0277
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
/// // error[E0277]: the trait bound `(Padding, TachygramSet): Has<Padding, _>`
/// // is not satisfied, because `Padding` is not an `OnlinePoly`.
/// slot::<(Padding, TachygramSet), _, _>(Padding);
/// ```
///
/// `Has` is sealed too: an application cannot forge a lookup for a kind the
/// list does not hold.
///
/// ```compile_fail,E0277
/// use ragu_pcd::header::{Has, OnlinePoly, Padding};
///
/// #[derive(Clone, Copy)]
/// struct TachygramSet;
/// impl OnlinePoly for TachygramSet {}
///
/// struct ForgedSlot;
/// impl Has<TachygramSet, ForgedSlot> for (Padding, Padding) {
///     const INDEX: usize = 0;
/// }
/// ```
///
/// A list that holds the same kind in two slots makes the lookup of that
/// kind ambiguous, and application registration rejects it.
///
/// [`Header::OnlinePolyCommit`]: super::Header::OnlinePolyCommit
pub trait OnlinePolyCommit: sealed::Sealed + Send + Sync + 'static {
    /// Whether every non-padding kind occurs at most once.
    #[doc(hidden)]
    fn has_unique_kinds() -> bool;
}

// The tuple impls below and the `Has` impls give one entry per slot. They
// must change together with `NUM_ONLINE_FP_POLYS`.
const _: () = assert!(
    NUM_ONLINE_FP_POLYS == 2,
    "OnlinePolyCommit and Has are implemented for pairs only"
);

impl<A: OnlinePolySlot, B: OnlinePolySlot> OnlinePolyCommit for (A, B) {
    fn has_unique_kinds() -> bool {
        TypeId::of::<A>() != TypeId::of::<B>() || TypeId::of::<A>() == TypeId::of::<Padding>()
    }
}

impl<A: OnlinePolySlot, B: OnlinePolySlot> sealed::Sealed for (A, B) {}

mod sealed {
    pub trait Sealed {}
}

/// A list that keeps the kind `P` in the slot marked by `I`.
///
/// `(A, B)` keeps `A` at index zero and `B` at index one. `I` is a slot
/// marker the compiler infers from `P`, so a call names only the kind:
/// `input.polynomial(TachygramSet)`. Application registration rejects a list
/// keeping the same non-padding kind in both slots, and [`Padding`] is never
/// found. The sealed trait prevents callers from inventing a lookup.
pub trait Has<P, I>: has_sealed::Sealed<P, I> + OnlinePolyCommit {
    /// The index of the slot, below [`NUM_ONLINE_FP_POLYS`].
    const INDEX: usize;
}

#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct Slot0;

#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct Slot1;

mod has_sealed {
    use super::{OnlinePoly, OnlinePolySlot, Slot0, Slot1};

    pub trait Sealed<P, I> {}

    impl<A: OnlinePoly, B: OnlinePolySlot> Sealed<A, Slot0> for (A, B) {}

    impl<A: OnlinePolySlot, B: OnlinePoly> Sealed<B, Slot1> for (A, B) {}
}

impl<A: OnlinePoly, B: OnlinePolySlot> Has<A, Slot0> for (A, B) {
    const INDEX: usize = 0;
}

impl<A: OnlinePolySlot, B: OnlinePoly> Has<B, Slot1> for (A, B) {
    const INDEX: usize = 1;
}

/// Returns the index of the slot `L` keeps `kind` in.
pub(crate) fn slot<L: Has<P, I>, P, I>(_kind: P) -> usize {
    L::INDEX
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

    #[test]
    fn a_kind_is_found_at_its_slot() {
        assert_eq!(slot::<(First, Second), _, _>(First), 0);
        assert_eq!(slot::<(First, Second), _, _>(Second), 1);
        assert_eq!(slot::<(Padding, Second), _, _>(Second), 1);
        assert_eq!(slot::<(First, Padding), _, _>(First), 0);
    }

    #[test]
    fn a_non_padding_kind_may_occupy_only_one_slot() {
        assert!(<(First, Second) as OnlinePolyCommit>::has_unique_kinds());
        assert!(<(Padding, Padding) as OnlinePolyCommit>::has_unique_kinds());
        assert!(!<(First, First) as OnlinePolyCommit>::has_unique_kinds());
    }
}
