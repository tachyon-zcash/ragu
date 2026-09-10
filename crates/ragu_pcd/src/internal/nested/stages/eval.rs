//! Eval stage for nested fuse operations.
//!
//! Alongside the host-curve commitment it bridges, this stage carries the
//! nested evaluations at $u_n$ of every polynomial the nested batch folds
//! into $p_n$, in the order [`Batch::evaluated`] fixes; the nested $v_n$ is
//! the $\beta_n$-weighted sum of $f_n(u_n)$ and these values. They ride here
//! because this bridge stage's commitment is absorbed before $\beta$ is
//! squeezed.
//!
//! [`Batch::evaluated`]: crate::internal::nested::pcs::Batch::evaluated

use core::marker::PhantomData;

use ragu_arithmetic::{CurveAffine, Cycle, ff::PrimeField};
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
    vec::{FixedVec, Len},
};

use crate::{
    Proof,
    internal::nested::{RxComponent, RxIndex, pcs::OwnRxLen},
};

/// Number of curve points in this stage.
const NUM: usize = 1;

/// A child proof's nested polynomial evaluations at $u_n$.
#[derive(Clone)]
pub struct ChildEvaluationsWitness<F> {
    /// The child's nested rx polynomials, in [`RxIndex::ALL`] order.
    pub rx: FixedVec<F, OwnRxLen>,
    /// The child's nested $a$ polynomial.
    pub a_poly: F,
    /// The child's nested $b$ polynomial.
    pub b_poly: F,
    /// The child's `registry_xy` polynomial.
    pub registry_xy_poly: F,
    /// The child's nested $p$ polynomial.
    pub p_poly: F,
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Evaluates a child proof's nested polynomials at $u_n$.
    pub fn from_proof<C: Cycle<ScalarField = F>, R: Rank, B: ragu_backend::Backend>(
        proof: &Proof<C, R>,
        u: F,
    ) -> Self {
        ChildEvaluationsWitness {
            rx: FixedVec::from_fn(|i| B::sparse_eval(&proof[RxIndex::ALL[i]], u)),
            a_poly: B::sparse_eval(&proof[RxComponent::AbA], u),
            b_poly: B::sparse_eval(&proof[RxComponent::AbB], u),
            registry_xy_poly: B::sparse_eval(proof.nested_registry_xy_poly(), u),
            p_poly: B::sparse_eval(proof.nested_p_poly(), u),
        }
    }
}

/// The current step's nested polynomial evaluations at $u_n$.
#[derive(Clone)]
pub struct CurrentStepWitness<F> {
    pub registry_wx0: F,
    pub registry_wx1: F,
    pub registry_wy: F,
    pub a_poly: F,
    pub b_poly: F,
    pub registry_xy: F,
}

/// The nested evaluations carried by this stage.
#[derive(Clone)]
pub struct Evaluations<F> {
    pub left: ChildEvaluationsWitness<F>,
    pub right: ChildEvaluationsWitness<F>,
    pub current: CurrentStepWitness<F>,
}

impl<F: PrimeField> Evaluations<F> {
    /// All-zero values, for proofs that open nothing (the trivial proof).
    pub fn zero() -> Self {
        let child = || ChildEvaluationsWitness {
            rx: FixedVec::from_fn(|_| F::ZERO),
            a_poly: F::ZERO,
            b_poly: F::ZERO,
            registry_xy_poly: F::ZERO,
            p_poly: F::ZERO,
        };
        Evaluations {
            left: child(),
            right: child(),
            current: CurrentStepWitness {
                registry_wx0: F::ZERO,
                registry_wx1: F::ZERO,
                registry_wy: F::ZERO,
                a_poly: F::ZERO,
                b_poly: F::ZERO,
                registry_xy: F::ZERO,
            },
        }
    }
}

/// Witness data for this bridge stage.
pub struct Witness<C: CurveAffine> {
    pub native_eval: C,
    /// The nested evaluations at $u_n$.
    pub nested: Evaluations<C::Base>,
}

/// Gadget for a child proof's nested evaluations at $u_n$.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub rx: FixedVec<Element<'dr, D>, OwnRxLen>,
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
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>) -> Result<Self> {
        let allocator = &mut ();
        Ok(ChildEvaluations {
            rx: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.rx[i]))
            })?,
            a_poly: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.a_poly))?,
            b_poly: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.b_poly))?,
            registry_xy_poly: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.registry_xy_poly),
            )?,
            p_poly: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.p_poly))?,
        })
    }
}

/// Gadget for the nested evaluations at $u_n$.
///
/// The [`Write`] order is the order [`Batch::evaluated`] fixes, and so the
/// order of the coefficients in the $\beta_n$-weighted sum that defines
/// $v_n$.
///
/// [`Batch::evaluated`]: crate::internal::nested::pcs::Batch::evaluated
#[derive(Gadget, Write)]
pub struct EvaluationsOutput<'dr, D: Driver<'dr>> {
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

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    /// The nested evaluations at $u_n$.
    #[ragu(gadget)]
    pub nested: EvaluationsOutput<'dr, D>,
}

#[derive(Default)]
pub struct Stage<C: CurveAffine, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
    type Parent = super::f::Stage<C, R>;
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _, C>];

    fn values() -> usize {
        // (x, y) per point + 2 children + current step elements (6)
        NUM * 2 + 2 * (OwnRxLen::len() + 4) + 6
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let native_eval = Point::alloc(dr, witness.as_ref().map(|w| w.native_eval))?;
        let current = |dr: &mut D, f: fn(&CurrentStepWitness<D::F>) -> D::F| {
            Element::alloc(dr, &mut (), witness.as_ref().map(|w| f(&w.nested.current)))
        };
        let nested = EvaluationsOutput {
            left: ChildEvaluations::alloc(dr, witness.as_ref().map(|w| &w.nested.left))?,
            right: ChildEvaluations::alloc(dr, witness.as_ref().map(|w| &w.nested.right))?,
            registry_wx0: current(dr, |c| c.registry_wx0)?,
            registry_wx1: current(dr, |c| c.registry_wx1)?,
            registry_wy: current(dr, |c| c.registry_wy)?,
            a_poly: current(dr, |c| c.a_poly)?,
            b_poly: current(dr, |c| c.b_poly)?,
            registry_xy: current(dr, |c| c.registry_xy)?,
        };

        Ok(Output {
            native_eval,
            nested,
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
