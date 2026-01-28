//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;

use crate::Proof;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Point, io::Write};

use core::marker::PhantomData;

/// Number of curve point fields in this stage.
pub const NUM: usize = 13;

/// Witness data for a single child proof in the nested preamble stage.
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
        Self {
            application: proof.application.commitment,
            hashes_1: proof.circuits.hashes_1_commitment,
            hashes_2: proof.circuits.hashes_2_commitment,
            partial_collapse: proof.circuits.partial_collapse_commitment,
            full_collapse: proof.circuits.full_collapse_commitment,
            compute_v: proof.circuits.compute_v_commitment,
        }
    }
}

/// Witness data for the nested preamble stage.
pub struct Witness<C: CurveAffine> {
    /// Commitment from the native preamble stage.
    pub native_preamble: C,
    /// Witness data from the left child proof.
    pub left: ChildWitness<C>,
    /// Witness data from the right child proof.
    pub right: ChildWitness<C>,
}

/// Output gadget for a single child proof in the nested preamble stage.
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
            application: Point::alloc(dr, witness.view().map(|w| w.application))?,
            hashes_1: Point::alloc(dr, witness.view().map(|w| w.hashes_1))?,
            hashes_2: Point::alloc(dr, witness.view().map(|w| w.hashes_2))?,
            partial_collapse: Point::alloc(dr, witness.view().map(|w| w.partial_collapse))?,
            full_collapse: Point::alloc(dr, witness.view().map(|w| w.full_collapse))?,
            compute_v: Point::alloc(dr, witness.view().map(|w| w.compute_v))?,
        })
    }
}

/// Output gadget for the nested preamble stage.
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
        NUM * 2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Ok(Output {
            native_preamble: Point::alloc(dr, witness.view().map(|w| w.native_preamble))?,
            left: ChildOutput::alloc(dr, witness.view().map(|w| &w.left))?,
            right: ChildOutput::alloc(dr, witness.view().map(|w| &w.right))?,
        })
    }
}
