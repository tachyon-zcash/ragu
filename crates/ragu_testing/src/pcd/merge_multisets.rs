//! Test fixture: a Step that merges two [`Multiset`]s.
//!
//! Each node in the PCD tree carries a [`Multiset`] — a polynomial paired with
//! an in-circuit commitment to it. The [`MergeMultisets`] step takes the left
//! and right child multisets and outputs their merge: the product polynomial
//! with a prover-supplied commitment, tied back to the inputs by the
//! Schwartz–Zippel check inside [`Multiset::merge`].
//!
//! The challenge driving that check comes from the framework via
//! [`StepCtx::derive_challenge`]; this fixture never instantiates a Poseidon
//! sponge. The commitment is the only part of a multiset exposed to the circuit
//! (via [`Header::encode`]); the polynomial travels alongside the proof as
//! unstructured [`MultisetData`], reachable from `fuse(...)` through
//! [`Pcd::data`](ragu_pcd::Pcd::data).

use core::marker::PhantomData;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{Point, allocator::Allocator};

use super::multiset::Multiset;

/// Data carried by a [`MultisetHeader`].
///
/// `commitment` is the in-circuit part (allocated as a [`Point`] by
/// [`Header::encode`]); `polynomial` is unstructured PCD data that flows
/// through the tree alongside the proof but is never seen by the circuit.
pub struct MultisetData<C: CurveAffine, R: Rank> {
    pub commitment: C,
    pub polynomial: sparse::Polynomial<C::Base, R>,
}

impl<C: CurveAffine, R: Rank> Clone for MultisetData<C, R> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            polynomial: self.polynomial.clone(),
        }
    }
}

/// Header representing a [`Multiset`]: it exposes the commitment to the circuit
/// and carries the polynomial as accompanying data.
pub struct MultisetHeader<C, R>(PhantomData<(C, R)>);

impl<C: Cycle, R: Rank> Header<C::CircuitField> for MultisetHeader<C, R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = MultisetData<C::NestedCurve, R>;
    type Output = Kind![C::CircuitField; Point<'_, _, C::NestedCurve>];

    fn encode<'dr, D: Driver<'dr, F = C::CircuitField>, A: Allocator<'dr, D>>(
        dr: &mut D,
        _allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Point::alloc(dr, witness.map(|d| d.commitment))
    }
}

/// A step that merges the left and right child [`Multiset`]s into their product.
pub struct MergeMultisets<C, R>(PhantomData<(C, R)>);

impl<C, R> MergeMultisets<C, R> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C, R> Default for MergeMultisets<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for MergeMultisets<C, R> {
    const INDEX: Index = Index::new(0);
    /// The prover's commitment to the product polynomial.
    type Witness<'source> = C::NestedCurve;
    type Aux<'source> = ();
    type Left = MultisetHeader<C, R>;
    type Right = MultisetHeader<C, R>;
    type Output = MultisetHeader<C, R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C::NestedCurve>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, MultisetData<C::NestedCurve, R>>,
        right: DriverValue<D, MultisetData<C::NestedCurve, R>>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        // Allocate each child's commitment as an in-circuit point and split off
        // the prover-only polynomial. The same point gadget is shared between the
        // encoded header and the reassembled multiset, so the header commits to
        // exactly the multiset that gets merged.
        let left_commitment = Point::alloc(ctx.dr, left.as_ref().map(|d| d.commitment))?;
        let right_commitment = Point::alloc(ctx.dr, right.as_ref().map(|d| d.commitment))?;
        let left_poly = left.map(|d| d.polynomial);
        let right_poly = right.map(|d| d.polynomial);

        let left_encoded = Encoded::from_gadget(left_commitment.clone());
        let right_encoded = Encoded::from_gadget(right_commitment.clone());

        let left_multiset = Multiset::new(left_commitment, left_poly);
        let right_multiset = Multiset::new(right_commitment, right_poly);

        // Merge. The framework derives the Schwartz–Zippel challenge bound to the
        // three commitments — no sponge here. `witness` is the prover's
        // commitment to the product polynomial.
        let merged = left_multiset.merge(right_multiset, ctx, witness)?;

        // Output the merged multiset: its commitment is exposed to the circuit,
        // its polynomial rides along as data.
        let output_data = merged.commitment.value().and_then(|commitment| {
            merged.polynomial.map(|polynomial| MultisetData {
                commitment,
                polynomial,
            })
        });
        let output_encoded = Encoded::from_gadget(merged.commitment);

        Ok((
            (left_encoded, right_encoded, output_encoded),
            output_data,
            D::unit(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::ProductionRank;
    use ragu_pasta::Pasta;
    use ragu_pcd::ApplicationBuilder;

    use super::*;

    type R = ProductionRank;
    const HEADER_SIZE: usize = 4;

    /// Registering a step that derives a challenge exercises the full
    /// registration-time staging path: the dry run discovers the induced
    /// stage layout, the corresponding well-formedness masks are registered,
    /// and the step circuit synthesizes (reservation + binding + deferred
    /// output allocation) through keygen.
    #[test]
    fn registration_discovers_induced_stage_and_registers_masks() {
        let pasta = Pasta::baked();

        let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
            .register(MergeMultisets::<Pasta, R>::new())
            .expect("registration should succeed")
            .finalize(pasta)
            .expect("finalization should succeed");

        // `MergeMultisets` calls `derive_challenge` once with three `Point`s
        // (6 wires), inducing one stage. The registry therefore holds the 13
        // internal circuits, 2 internal steps, 1 application step, plus 2
        // application masks (the stage mask and the final mask).
        assert_eq!(app.native_registry().num_circuits(), 13 + 2 + 1 + 2);
    }
}
