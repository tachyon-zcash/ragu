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
use crate::internal::native::RxValues;

/// Pre-computed polynomial evaluations at $u$ (from the parent fuse operation)
/// for a child proof.
pub struct ChildEvaluationsWitness<F> {
    pub rx: RxValues<F>,
    pub a_poly: F,
    pub b_poly: F,
    pub registry_xy_poly: F,
    pub p_poly: F,
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Create child evaluations witness from a proof evaluated at point u.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank>(proof: &Proof<C, R>, u: F) -> Self {
        ChildEvaluationsWitness {
            rx: RxValues::from_fn(|id| proof.native_rx_poly(id).eval(u)),
            a_poly: proof.ab.native.a_poly.eval(u),
            b_poly: proof.ab.native.b_poly.eval(u),
            registry_xy_poly: proof.query.native.registry_xy_poly.eval(u),
            p_poly: proof.p.native.poly.eval(u),
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
/// [`Horner`](ragu_circuits::horner::Horner) evaluation.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub rx: RxValues<Element<'dr, D>>,
    #[ragu(gadget)]
    pub a_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub registry_xy_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub p_poly: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> ChildEvaluations<'dr, D> {
    /// Allocate child evaluations from pre-computed witness values.
    pub fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>,
    ) -> Result<Self> {
        let rx = RxValues::try_from_fn(|id| {
            Element::alloc(dr, witness.as_ref().map(|w| *w.rx.get(id)))
        })?;
        Ok(ChildEvaluations {
            rx,
            a_poly: Element::alloc(dr, witness.as_ref().map(|w| w.a_poly))?,
            b_poly: Element::alloc(dr, witness.as_ref().map(|w| w.b_poly))?,
            registry_xy_poly: Element::alloc(dr, witness.as_ref().map(|w| w.registry_xy_poly))?,
            p_poly: Element::alloc(dr, witness.as_ref().map(|w| w.p_poly))?,
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
        // 2 * ChildEvaluations (15 each) + current step elements (6)
        2 * 15 + 6
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let left = ChildEvaluations::alloc(dr, witness.as_ref().map(|w| &w.left))?;
        let right = ChildEvaluations::alloc(dr, witness.as_ref().map(|w| &w.right))?;
        let registry_wx0 = Element::alloc(dr, witness.as_ref().map(|w| w.current.registry_wx0))?;
        let registry_wx1 = Element::alloc(dr, witness.as_ref().map(|w| w.current.registry_wx1))?;
        let registry_wy = Element::alloc(dr, witness.as_ref().map(|w| w.current.registry_wy))?;
        let a_poly = Element::alloc(dr, witness.as_ref().map(|w| w.current.a_poly))?;
        let b_poly = Element::alloc(dr, witness.as_ref().map(|w| w.current.b_poly))?;
        let registry_xy = Element::alloc(dr, witness.as_ref().map(|w| w.current.registry_xy))?;
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
    use crate::internal::native::stages::tests::{HEADER_SIZE, R, assert_stage_values};
    use ragu_pasta::Pasta;

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
