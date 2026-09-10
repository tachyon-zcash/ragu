//! Preamble stage for nested fuse operations.
//!
//! Collects child proof commitments for cross-curve accumulation.

use core::marker::PhantomData;

use ragu_arithmetic::{CurveAffine, Cycle};
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    io::Write,
    vec::{ConstLen, FixedVec},
};

use crate::{
    Proof,
    internal::{
        endoscalar::PointsStage,
        native::{NUM_BINDERS, RxIndex},
        nested::{NUM_ENDOSCALING_POINTS, unified},
    },
};

/// Number of curve points in this stage.
pub const NUM_POINTS: usize = 31 + 2 * (NUM_BINDERS + 1);

/// Witness data for a single child proof in the preamble bridge stage.
///
/// The initial fields (application through compute_v) are the primary
/// introduction of child circuit commitments into the nested transcript.
/// The remaining `stashed_*` fields are copies of values the child's nested
/// unified instance exports, placed here so that loading can enforce them
/// against [`PointsStage`] and so that this step can compute the child's
/// nested $k(y_n)$ from them, which binds the copies to the child's export
/// circuit.
#[derive(Clone)]
pub struct ChildWitness<C: CurveAffine> {
    // Field order matches the `_10_p` accumulation order.
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
    /// Commitments from the child's nested challenge binding circuits.
    pub bind_challenges: [C; NUM_BINDERS],
    /// Commitment from the child's nested beta binding circuit.
    pub bind_beta: C,

    /// Stashed commitment from the child's preamble bridge stage.
    pub stashed_preamble: C,
    /// Stashed commitment from the child's inner error bridge stage.
    pub stashed_inner_error: C,
    /// Stashed commitment from the child's outer error bridge stage.
    pub stashed_outer_error: C,
    /// Stashed commitment from the child's query bridge stage.
    pub stashed_query: C,
    /// Stashed commitment from the child's eval bridge stage.
    pub stashed_eval: C,
    /// Stashed `a` commitment from the child's AB bridge stage.
    pub stashed_ab_a: C,
    /// Stashed `b` commitment from the child's AB bridge stage.
    pub stashed_ab_b: C,
    /// Stashed registry XY commitment from the child.
    pub stashed_registry_xy: C,
    /// Stashed accumulated P commitment from the child.
    pub stashed_p: C,

    /// The scalars of the child's nested unified instance: its nested
    /// accumulator value and batch evaluation, and the lifts of its $x$, $y$
    /// and $u$. With the stashed commitments above these make up the child's
    /// nested instance.
    pub nested: NestedValues<C::Base>,
}

/// The scalar half of a child's nested unified instance (see
/// [`unified`](crate::internal::nested::unified)).
#[derive(Clone, Copy)]
pub struct NestedValues<F> {
    pub c: F,
    pub v: F,
    pub x: F,
    pub y: F,
    pub u: F,
}

impl<C: CurveAffine> ChildWitness<C> {
    /// Construct from a child proof's commitments and nested instance.
    ///
    /// # Errors
    ///
    /// Fails if a challenge of the child lies outside the endoscalar range,
    /// which an honest transcript output does with negligible probability.
    pub fn from_proof<CC: Cycle<HostCurve = C>, R: Rank>(proof: &Proof<CC, R>) -> Result<Self> {
        use crate::internal::native::RxComponent;
        let instance = proof.nested_instance()?;
        Ok(Self {
            application: proof.native_rx_commitment(RxIndex::Application),
            hashes_1: proof.native_rx_commitment(RxIndex::Hashes1),
            hashes_2: proof.native_rx_commitment(RxIndex::Hashes2),
            inner_collapse: proof.native_rx_commitment(RxIndex::InnerCollapse),
            outer_collapse: proof.native_rx_commitment(RxIndex::OuterCollapse),
            compute_v: proof.native_rx_commitment(RxIndex::ComputeV),
            bind_challenges: core::array::from_fn(|k| {
                proof.native_rx_commitment(RxIndex::BindChallenges(k as u32))
            }),
            bind_beta: proof.native_rx_commitment(RxIndex::BindBeta),
            stashed_preamble: proof.native_rx_commitment(RxIndex::Preamble),
            stashed_inner_error: proof.native_rx_commitment(RxIndex::InnerError),
            stashed_outer_error: proof.native_rx_commitment(RxIndex::OuterError),
            stashed_query: proof.native_rx_commitment(RxIndex::Query),
            stashed_eval: proof.native_rx_commitment(RxIndex::Eval),
            stashed_ab_a: proof.native_commitment(RxComponent::AbA),
            stashed_ab_b: proof.native_commitment(RxComponent::AbB),
            stashed_registry_xy: proof.native_registry_xy_commitment(),
            stashed_p: proof.native_p_commitment(),
            nested: NestedValues {
                c: instance.c,
                v: instance.v,
                x: instance.x,
                y: instance.y,
                u: instance.u,
            },
        })
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
    // Field order matches `_10_p` accumulation order.
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
    /// Point commitments from the child's nested challenge binding circuits.
    #[ragu(gadget)]
    pub bind_challenges: FixedVec<Point<'dr, D, C>, ConstLen<NUM_BINDERS>>,
    /// Point commitment from the child's nested beta binding circuit.
    #[ragu(gadget)]
    pub bind_beta: Point<'dr, D, C>,

    /// Stashed commitment from the child's preamble bridge stage.
    #[ragu(gadget)]
    pub stashed_preamble: Point<'dr, D, C>,
    /// Stashed commitment from the child's inner error bridge stage.
    #[ragu(gadget)]
    pub stashed_inner_error: Point<'dr, D, C>,
    /// Stashed commitment from the child's outer error bridge stage.
    #[ragu(gadget)]
    pub stashed_outer_error: Point<'dr, D, C>,
    /// Stashed commitment from the child's query bridge stage.
    #[ragu(gadget)]
    pub stashed_query: Point<'dr, D, C>,
    /// Stashed commitment from the child's eval bridge stage.
    #[ragu(gadget)]
    pub stashed_eval: Point<'dr, D, C>,
    /// Stashed `a` commitment from the child's AB bridge stage.
    #[ragu(gadget)]
    pub stashed_ab_a: Point<'dr, D, C>,
    /// Stashed `b` commitment from the child's AB bridge stage.
    #[ragu(gadget)]
    pub stashed_ab_b: Point<'dr, D, C>,
    /// Stashed registry XY commitment from the child.
    #[ragu(gadget)]
    pub stashed_registry_xy: Point<'dr, D, C>,
    /// Stashed accumulated P commitment from the child.
    #[ragu(gadget)]
    pub stashed_p: Point<'dr, D, C>,

    /// The scalars of the child's nested unified instance.
    #[ragu(gadget)]
    pub nested: NestedValuesOutput<'dr, D>,
}

/// Gadget for the scalar half of a child's nested unified instance.
#[derive(Gadget, Write)]
pub struct NestedValuesOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub c: Element<'dr, D>,
    #[ragu(gadget)]
    pub v: Element<'dr, D>,
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
    #[ragu(gadget)]
    pub u: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    /// The child's nested unified instance, assembled from the values this
    /// stage holds, in the order the child's circuits serialize it.
    pub fn nested_instance(&self) -> unified::Output<'dr, D, C> {
        unified::Output {
            c: self.nested.c.clone(),
            v: self.nested.v.clone(),
            x: self.nested.x.clone(),
            y: self.nested.y.clone(),
            u: self.nested.u.clone(),
            exported: FixedVec::new(alloc::vec![
                self.stashed_preamble.clone(),
                self.stashed_inner_error.clone(),
                self.stashed_outer_error.clone(),
                self.stashed_query.clone(),
                self.stashed_eval.clone(),
                self.stashed_ab_a.clone(),
                self.stashed_ab_b.clone(),
                self.stashed_registry_xy.clone(),
                self.stashed_p.clone(),
            ])
            .expect("NUM_EXPORTED commitments"),
        }
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> core::ops::Index<RxIndex>
    for ChildOutput<'dr, D, C>
{
    type Output = Point<'dr, D, C>;

    fn index(&self, idx: RxIndex) -> &Point<'dr, D, C> {
        use RxIndex::*;
        match idx {
            Application => &self.application,
            Hashes1 => &self.hashes_1,
            Hashes2 => &self.hashes_2,
            InnerCollapse => &self.inner_collapse,
            OuterCollapse => &self.outer_collapse,
            ComputeV => &self.compute_v,
            BindChallenges(k) => &self.bind_challenges[k as usize],
            BindBeta => &self.bind_beta,
            Preamble => &self.stashed_preamble,
            InnerError => &self.stashed_inner_error,
            OuterError => &self.stashed_outer_error,
            Query => &self.stashed_query,
            Eval => &self.stashed_eval,
        }
    }
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> ChildOutput<'dr, D, C> {
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildWitness<C>>) -> Result<Self> {
        Ok(ChildOutput {
            application: Point::alloc(dr, witness.as_ref().map(|w| w.application))?,
            hashes_1: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_1))?,
            hashes_2: Point::alloc(dr, witness.as_ref().map(|w| w.hashes_2))?,
            inner_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.inner_collapse))?,
            outer_collapse: Point::alloc(dr, witness.as_ref().map(|w| w.outer_collapse))?,
            compute_v: Point::alloc(dr, witness.as_ref().map(|w| w.compute_v))?,
            bind_challenges: FixedVec::try_from_fn(|k| {
                Point::alloc(dr, witness.as_ref().map(|w| w.bind_challenges[k]))
            })?,
            bind_beta: Point::alloc(dr, witness.as_ref().map(|w| w.bind_beta))?,
            stashed_preamble: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_preamble))?,
            stashed_inner_error: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_inner_error))?,
            stashed_outer_error: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_outer_error))?,
            stashed_query: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_query))?,
            stashed_eval: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_eval))?,
            stashed_ab_a: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_ab_a))?,
            stashed_ab_b: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_ab_b))?,
            stashed_registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_registry_xy))?,
            stashed_p: Point::alloc(dr, witness.as_ref().map(|w| w.stashed_p))?,
            nested: {
                let value = |dr: &mut D, f: fn(&NestedValues<D::F>) -> D::F| {
                    Element::alloc(dr, &mut (), witness.as_ref().map(|w| f(&w.nested)))
                };
                NestedValuesOutput {
                    c: value(dr, |n| n.c)?,
                    v: value(dr, |n| n.v)?,
                    x: value(dr, |n| n.x)?,
                    y: value(dr, |n| n.y)?,
                    u: value(dr, |n| n.u)?,
                }
            },
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
        // (x, y) per point, then the five nested scalars of each child.
        NUM_POINTS * 2 + 2 * 5
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
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R>::default());
    }
}
