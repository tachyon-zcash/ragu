//! Eval stage for fuse operations.

use ff::PrimeField;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, io::Write};

use core::marker::PhantomData;

use crate::Proof;

pub(crate) use crate::circuits::native::InternalCircuitIndex::EvalStage as STAGING_ID;

/// Pre-computed polynomial evaluations at $u$ (from the parent fuse operation)
/// for a child proof.
pub struct ChildEvaluationsWitness<F> {
    pub application: F,
    pub preamble: F,
    pub error_n: F,
    pub error_m: F,
    pub a_poly: F,
    pub b_poly: F,
    pub query: F,
    pub registry_xy_poly: F,
    pub eval: F,
    pub p_poly: F,
    pub hashes_1: F,
    pub hashes_2: F,
    pub partial_collapse: F,
    pub full_collapse: F,
    pub compute_v: F,
    pub endoscale_challenges: F,
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Create child evaluations witness from a proof evaluated at point u.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank>(proof: &Proof<C, R>, u: F) -> Self {
        ChildEvaluationsWitness {
            application: proof.application.rx.eval(u),
            preamble: proof.preamble.native_rx.eval(u),
            error_n: proof.error_n.native_rx.eval(u),
            error_m: proof.error_m.native_rx.eval(u),
            a_poly: proof.ab.a_poly.eval(u),
            b_poly: proof.ab.b_poly.eval(u),
            query: proof.query.native_rx.eval(u),
            registry_xy_poly: proof.query.registry_xy_poly.eval(u),
            eval: proof.eval.native_rx.eval(u),
            p_poly: proof.p.poly.eval(u),
            hashes_1: proof.circuits.hashes_1_rx.eval(u),
            hashes_2: proof.circuits.hashes_2_rx.eval(u),
            partial_collapse: proof.circuits.partial_collapse_rx.eval(u),
            full_collapse: proof.circuits.full_collapse_rx.eval(u),
            compute_v: proof.circuits.compute_v_rx.eval(u),
            endoscale_challenges: proof.circuits.endoscale_challenges_rx.eval(u),
        }
    }
}

/// Pre-computed polynomial evaluations at u for the current step.
pub struct CurrentStepWitness<F> {
    pub registry_wx0: F,
    pub registry_wx1: F,
    pub registry_wy: F,
    pub a_poly: F,
    pub b_poly: F,
    pub registry_xy: F,
}

/// Witness for the eval stage.
pub struct Witness<F> {
    pub left: ChildEvaluationsWitness<F>,
    pub right: ChildEvaluationsWitness<F>,
    pub current: CurrentStepWitness<F>,
}

/// Committed (claimed) polynomial evaluations at $u$ (from the parent fuse
/// operation) for an individual child proof.
///
/// Note: The order of elements in this struct affects the expected evaluation
/// of $v = p(u)$, via the [`Write`] implementation, since it defines the order
/// of the coefficients for the weighted sum with $\beta$ via
/// [`Horner`](crate::components::horner::Horner) evaluation.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub application: Element<'dr, D>,
    #[ragu(gadget)]
    pub preamble: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_n: Element<'dr, D>,
    #[ragu(gadget)]
    pub error_m: Element<'dr, D>,
    #[ragu(gadget)]
    pub a_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub query: Element<'dr, D>,
    #[ragu(gadget)]
    pub registry_xy_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub eval: Element<'dr, D>,
    #[ragu(gadget)]
    pub p_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub hashes_1: Element<'dr, D>,
    #[ragu(gadget)]
    pub hashes_2: Element<'dr, D>,
    #[ragu(gadget)]
    pub partial_collapse: Element<'dr, D>,
    #[ragu(gadget)]
    pub full_collapse: Element<'dr, D>,
    #[ragu(gadget)]
    pub compute_v: Element<'dr, D>,
    #[ragu(gadget)]
    pub endoscale_challenges: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> ChildEvaluations<'dr, D> {
    /// Allocate child evaluations from pre-computed witness values.
    pub fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>,
    ) -> Result<Self> {
        Ok(ChildEvaluations {
            application: Element::alloc(dr, witness.view().map(|w| w.application))?,
            preamble: Element::alloc(dr, witness.view().map(|w| w.preamble))?,
            error_n: Element::alloc(dr, witness.view().map(|w| w.error_n))?,
            error_m: Element::alloc(dr, witness.view().map(|w| w.error_m))?,
            a_poly: Element::alloc(dr, witness.view().map(|w| w.a_poly))?,
            b_poly: Element::alloc(dr, witness.view().map(|w| w.b_poly))?,
            query: Element::alloc(dr, witness.view().map(|w| w.query))?,
            registry_xy_poly: Element::alloc(dr, witness.view().map(|w| w.registry_xy_poly))?,
            eval: Element::alloc(dr, witness.view().map(|w| w.eval))?,
            p_poly: Element::alloc(dr, witness.view().map(|w| w.p_poly))?,
            hashes_1: Element::alloc(dr, witness.view().map(|w| w.hashes_1))?,
            hashes_2: Element::alloc(dr, witness.view().map(|w| w.hashes_2))?,
            partial_collapse: Element::alloc(dr, witness.view().map(|w| w.partial_collapse))?,
            full_collapse: Element::alloc(dr, witness.view().map(|w| w.full_collapse))?,
            compute_v: Element::alloc(dr, witness.view().map(|w| w.compute_v))?,
            endoscale_challenges: Element::alloc(
                dr,
                witness.view().map(|w| w.endoscale_challenges),
            )?,
        })
    }
}

/// Prover-internal output gadget for the eval stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D>,
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D>,
    #[ragu(gadget)]
    pub registry_wx0: Element<'dr, D>,
    #[ragu(gadget)]
    pub registry_wx1: Element<'dr, D>,
    #[ragu(gadget)]
    pub registry_wy: Element<'dr, D>,
    #[ragu(gadget)]
    pub a_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub registry_xy: Element<'dr, D>,
}

/// The eval stage of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = super::query::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source Witness<C::CircuitField>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _>];

    fn values() -> usize {
        // 2 * ChildEvaluations (16 each) + current step elements (6)
        2 * 16 + 6
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let left = ChildEvaluations::alloc(dr, witness.view().map(|w| &w.left))?;
        let right = ChildEvaluations::alloc(dr, witness.view().map(|w| &w.right))?;
        let registry_wx0 = Element::alloc(dr, witness.view().map(|w| w.current.registry_wx0))?;
        let registry_wx1 = Element::alloc(dr, witness.view().map(|w| w.current.registry_wx1))?;
        let registry_wy = Element::alloc(dr, witness.view().map(|w| w.current.registry_wy))?;
        let a_poly = Element::alloc(dr, witness.view().map(|w| w.current.a_poly))?;
        let b_poly = Element::alloc(dr, witness.view().map(|w| w.current.b_poly))?;
        let registry_xy = Element::alloc(dr, witness.view().map(|w| w.current.registry_xy))?;
        Ok(Output {
            left,
            right,
            registry_wx0,
            registry_wx1,
            registry_wy,
            a_poly,
            b_poly,
            registry_xy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::native::stages::tests::{HEADER_SIZE, R, assert_stage_values};
    use ragu_pasta::Pasta;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
