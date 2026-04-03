//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;

use crate::internal::{endoscalar::PointsStage, nested::NUM_ENDOSCALING_POINTS};

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
pub const NUM_POINTS: usize = 31;

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
    /// Commitment from the child's inner collapse circuit.
    pub inner_collapse: C,
    /// Commitment from the child's outer collapse circuit.
    pub outer_collapse: C,
    /// Commitment from the child's compute_v circuit.
    pub compute_v: C,
    /// Commitment from the child's preamble stage.
    pub preamble: C,
    /// Commitment from the child's inner error stage.
    pub inner_error: C,
    /// Commitment from the child's outer error stage.
    pub outer_error: C,
    /// Commitment from the child's query rx stage.
    pub query_rx: C,
    /// Commitment from the child's eval stage.
    pub eval: C,
    /// Commitment `a` from the child's AB component.
    pub a: C,
    /// Commitment `b` from the child's AB component.
    pub b: C,
    /// Commitment `registry_xy` from the child's query component.
    pub registry_xy: C,
    /// Commitment from the child's P component.
    pub p: C,
}

impl<C: CurveAffine> ChildWitness<C> {
    /// Construct from a child proof's commitments.
    pub fn from_proof<CC: Cycle<HostCurve = C>, R: Rank>(proof: &Proof<CC, R>) -> Self {
        use crate::internal::native::RxIndex;
        Self {
            application: proof[RxIndex::Application].commitment,
            hashes_1: proof[RxIndex::Hashes1].commitment,
            hashes_2: proof[RxIndex::Hashes2].commitment,
            inner_collapse: proof[RxIndex::InnerCollapse].commitment,
            outer_collapse: proof[RxIndex::OuterCollapse].commitment,
            compute_v: proof[RxIndex::ComputeV].commitment,
            preamble: proof[RxIndex::Preamble].commitment,
            inner_error: proof[RxIndex::InnerError].commitment,
            outer_error: proof[RxIndex::OuterError].commitment,
            query_rx: proof[RxIndex::Query].commitment,
            eval: proof[RxIndex::Eval].commitment,
            a: proof.ab.native.a_commitment,
            b: proof.ab.native.b_commitment,
            registry_xy: proof.query.native.registry_xy_commitment,
            p: proof.p.native.commitment,
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
    /// Point commitment from the child's inner collapse circuit.
    #[ragu(gadget)]
    pub inner_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's outer collapse circuit.
    #[ragu(gadget)]
    pub outer_collapse: Point<'dr, D, C>,
    /// Point commitment from the child's compute_v circuit.
    #[ragu(gadget)]
    pub compute_v: Point<'dr, D, C>,
    /// Point commitment from the child's preamble stage.
    #[ragu(gadget)]
    pub preamble: Point<'dr, D, C>,
    /// Point commitment from the child's inner error stage.
    #[ragu(gadget)]
    pub inner_error: Point<'dr, D, C>,
    /// Point commitment from the child's outer error stage.
    #[ragu(gadget)]
    pub outer_error: Point<'dr, D, C>,
    /// Point commitment from the child's query rx stage.
    #[ragu(gadget)]
    pub query_rx: Point<'dr, D, C>,
    /// Point commitment from the child's eval stage.
    #[ragu(gadget)]
    pub eval: Point<'dr, D, C>,
    /// Point commitment `a` from the child's AB component.
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    /// Point commitment `b` from the child's AB component.
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
    /// Point commitment `registry_xy` from the child's query component.
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    /// Point commitment from the child's P component.
    #[ragu(gadget)]
    pub p: Point<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    /// Returns the point commitment for the given [`RxIndex`](crate::internal::native::RxIndex).
    ///
    /// The field order matches [`RxIndex::ALL`](crate::internal::native::RxIndex::ALL).
    pub(crate) fn rx(&self, idx: crate::internal::native::RxIndex) -> &Point<'dr, D, C> {
        use crate::internal::native::RxIndex;
        match idx {
            RxIndex::Application => &self.application,
            RxIndex::Hashes1 => &self.hashes_1,
            RxIndex::Hashes2 => &self.hashes_2,
            RxIndex::InnerCollapse => &self.inner_collapse,
            RxIndex::OuterCollapse => &self.outer_collapse,
            RxIndex::ComputeV => &self.compute_v,
            RxIndex::Preamble => &self.preamble,
            RxIndex::InnerError => &self.inner_error,
            RxIndex::OuterError => &self.outer_error,
            RxIndex::Query => &self.query_rx,
            RxIndex::Eval => &self.eval,
        }
    }

    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildWitness<C>>) -> Result<Self> {
        Ok(ChildOutput {
            application: Point::alloc(dr, witness.as_ref().map(|w| w.application))?,
            hashes_1: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_1))?,
            hashes_2: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_2))?,
            inner_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.inner_collapse))?,
            outer_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.outer_collapse))?,
            compute_v: Point::alloc(dr, witness.as_ref().map(|w| w.compute_v))?,
            preamble: Point::alloc(dr, witness.as_ref().map(|w| w.preamble))?,
            inner_error: Point::alloc(dr, witness.as_ref().map(|w| w.inner_error))?,
            outer_error: Point::alloc(dr, witness.as_ref().map(|w| w.outer_error))?,
            query_rx: Point::alloc(dr, witness.as_ref().map(|w| w.query_rx))?,
            eval: Point::alloc(dr, witness.as_ref().map(|w| w.eval))?,
            a: Point::alloc(dr, witness.as_ref().map(|w| w.a))?,
            b: Point::alloc(dr, witness.as_ref().map(|w| w.b))?,
            registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.registry_xy))?,
            p: Point::alloc(dr, witness.as_ref().map(|w| w.p))?,
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
    type Parent = PointsStage<C, NUM_ENDOSCALING_POINTS>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::tests::{R, assert_stage_values};
    use ragu_pasta::EqAffine;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R>::default());
    }
}
