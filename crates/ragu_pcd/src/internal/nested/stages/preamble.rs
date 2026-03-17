//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;

use crate::Proof;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write};

use core::marker::PhantomData;

/// Number of curve points in this stage.
pub const NUM_POINTS: usize = 13;

/// Witness data for a single child proof in the preamble bridge stage.
///
/// Contains commitments from the child proof's circuits component.
pub struct ChildWitness<C: CurveAffine> {
    /// Commitment from the child's application circuit.
    pub application: C,
    /// Commitment from the child's first hashes circuit.
    pub hashes_1: C,
    /// Commitment from the child's second hashes circuit.
    pub hashes_2: C,
    /// Commitment from the child's partial collapse circuit.
    pub partial_collapse: C,
    /// Commitment from the child's full collapse circuit.
    pub full_collapse: C,
    /// Commitment from the child's compute_v circuit.
    pub compute_v: C,
}

impl<C: CurveAffine> ChildWitness<C> {
    /// Construct from a child proof's commitments.
    pub fn from_proof<CC: Cycle<HostCurve = C>, R: Rank>(proof: &Proof<CC, R>) -> Self {
        use crate::internal::native::RxIndex;
        Self {
            application: proof[RxIndex::Application].commitment,
            hashes_1: proof[RxIndex::Hashes1].commitment,
            hashes_2: proof[RxIndex::Hashes2].commitment,
            partial_collapse: proof[RxIndex::PartialCollapse].commitment,
            full_collapse: proof[RxIndex::FullCollapse].commitment,
            compute_v: proof[RxIndex::ComputeV].commitment,
        }
    }
}

/// Witness data for the preamble bridge stage.
pub struct Witness<C: CurveAffine> {
    /// Commitment from the native preamble stage.
    pub native_preamble: C,
    /// Witness data from the left child proof.
    pub left: ChildWitness<C>,
    /// Witness data from the right child proof.
    pub right: ChildWitness<C>,
}

/// Output gadget for a single child proof in the preamble bridge stage.
#[derive(Gadget, Write)]
pub struct ChildOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Point commitment from the child's application circuit.
    #[ragu(gadget)]
    pub application: Point<'dr, D, C>,
    /// Point commitment from the child's first hashes circuit.
    #[ragu(gadget)]
    pub hashes_1: Point<'dr, D, C>,
    /// Point commitment from the child's second hashes circuit.
    #[ragu(gadget)]
    pub hashes_2: Point<'dr, D, C>,
    /// Point commitment from the child's partial collapse circuit.
    #[ragu(gadget)]
    pub partial_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's full collapse circuit.
    #[ragu(gadget)]
    pub full_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's compute_v circuit.
    #[ragu(gadget)]
    pub compute_v: Point<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildWitness<C>>) -> Result<Self> {
        Ok(ChildOutput {
            application: Point::alloc(dr, witness.as_ref().map(|w| w.application))?,
            hashes_1: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_1))?,
            hashes_2: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_2))?,
            partial_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.partial_collapse))?,
            full_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.full_collapse))?,
            compute_v: Point::alloc(dr, witness.as_ref().map(|w| w.compute_v))?,
        })
    }
}

/// Prover-internal output gadget for the preamble bridge stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Point commitment from the native preamble stage.
    #[ragu(gadget)]
    pub native_preamble: Point<'dr, D, C>,
    /// Output gadget for the left child proof.
    #[ragu(gadget)]
    pub left: ChildOutput<'dr, D, C>,
    /// Output gadget for the right child proof.
    #[ragu(gadget)]
    pub right: ChildOutput<'dr, D, C>,
}

#[derive(Default)]
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = ();
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        NUM_POINTS * 2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Output {
            native_preamble: Point::alloc(dr, witness.as_ref().map(|w| w.native_preamble))?,
            left: ChildOutput::alloc(dr, witness.as_ref().map(|w| &w.left))?,
            right: ChildOutput::alloc(dr, witness.as_ref().map(|w| &w.right))?,
        })
    }
}
