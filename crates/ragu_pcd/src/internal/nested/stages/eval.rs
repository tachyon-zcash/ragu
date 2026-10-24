//! Eval stage for nested fuse operations.
//!
//! Alongside the host-curve commitment it bridges, this stage carries the
//! current step's witnessed-polynomial commitments, which the
//! [`export`](crate::internal::nested::circuits::export) circuit pins for a
//! parent to walk, and the nested evaluations at $u_n$ of every polynomial
//! the nested batch folds into $p_n$, in the order [`Batch::evaluated`]
//! fixes; the nested $v_n$ is the $\beta_n$-weighted sum of $f_n(u_n)$ and
//! these values.
//!
//! The child evaluations have no individual opening constraints in this
//! stage; [`compute_v`] accumulates them into $v_n$. The bridge commitment
//! is absorbed before `pre_beta` is squeezed, so these values are committed
//! before its nested counterpart $\beta_n$ is derived. Changing these
//! values requires recomputing the commitment and challenge; a cancellation
//! computed with $\beta_n$ held fixed does not by itself establish a valid
//! change to the proof.
//!
//! At the decider, [`Proof::nested_v`] derives $v_n$ from the retained
//! polynomial $p_n$. The nested revdot claims bind this value to the
//! `compute_v` trace, and the commitment checks bind $p_n$ to $P_n$.
//! Preserve this aggregate binding, the commitment's position before
//! `pre_beta`, and the ordering shared with [`Batch::evaluated`].
//!
//! [`Batch::evaluated`]: crate::internal::nested::pcs::Batch::evaluated
//! [`compute_v`]: crate::internal::nested::circuits::compute_v

use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    io::Write,
    vec::{FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use crate::{
    Proof,
    internal::nested::{RxComponent, RxIndex, pcs::OwnRxLen},
};

/// Number of curve points in this stage.
const NUM: usize = 1;

/// A child proof's nested polynomial evaluations at $u_n$, for a poly count
/// `L`.
pub struct ChildEvaluationsWitness<F, L: Len> {
    /// The child's nested rx polynomials, in [`RxIndex::all`] order.
    pub rx: FixedVec<F, OwnRxLen<L>>,
    /// The child's nested $a$ polynomial.
    pub a_poly: F,
    /// The child's nested $b$ polynomial.
    pub b_poly: F,
    /// The child's `registry_xy` polynomial.
    pub registry_xy_poly: F,
    /// The child's nested $p$ polynomial.
    pub p_poly: F,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<F: Clone, L: Len> Clone for ChildEvaluationsWitness<F, L> {
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
            a_poly: self.a_poly.clone(),
            b_poly: self.b_poly.clone(),
            registry_xy_poly: self.registry_xy_poly.clone(),
            p_poly: self.p_poly.clone(),
        }
    }
}

impl<F: Field, L: Len> ChildEvaluationsWitness<F, L> {
    /// Evaluates a child proof's nested polynomials at $u_n$.
    pub fn from_proof<C: Cycle<ScalarField = F>, R: Rank, B: ragu_backend::Backend>(
        proof: &Proof<C, R>,
        u: F,
    ) -> Self {
        let ids: alloc::vec::Vec<RxIndex> = RxIndex::all(L::len()).collect();
        ChildEvaluationsWitness {
            rx: FixedVec::from_fn(|i| B::sparse_eval(&proof[ids[i]], u)),
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
pub struct Evaluations<F, L: Len> {
    pub left: ChildEvaluationsWitness<F, L>,
    pub right: ChildEvaluationsWitness<F, L>,
    pub current: CurrentStepWitness<F>,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<F: Clone, L: Len> Clone for Evaluations<F, L> {
    fn clone(&self) -> Self {
        Self {
            left: self.left.clone(),
            right: self.right.clone(),
            current: self.current.clone(),
        }
    }
}

impl<F: Field, L: Len> Evaluations<F, L> {
    /// All-zero values, for proofs that open nothing (the dummy proof).
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
pub struct Witness<C: Affine, L: Len> {
    pub native_eval: C,
    /// The current step's witness-poly host commitments.
    pub witness_polys: FixedVec<C, L>,
    /// The nested evaluations at $u_n$.
    pub nested: Evaluations<C::Base, L>,
}

/// Gadget for a child proof's nested evaluations at $u_n$.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>, L: Len> {
    #[ragu(gadget)]
    pub rx: FixedVec<Element<'dr, D>, OwnRxLen<L>>,
    #[ragu(gadget)]
    pub a_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub registry_xy_poly: Element<'dr, D>,
    #[ragu(gadget)]
    pub p_poly: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>, L: Len> ChildEvaluations<'dr, D, L> {
    fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F, L>>,
    ) -> Result<Self> {
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
pub struct EvaluationsOutput<'dr, D: Driver<'dr>, L: Len> {
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D, L>,
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D, L>,
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
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub native_eval: Point<'dr, D, C>,
    /// The current step's witness-poly host commitments.
    #[ragu(gadget)]
    pub witness_polys: FixedVec<Point<'dr, D, C>, L>,
    /// The nested evaluations at $u_n$.
    #[ragu(gadget)]
    pub nested: EvaluationsOutput<'dr, D, L>,
}

pub struct Stage<C: Affine, R, L> {
    _marker: PhantomData<(C, R, L)>,
}

impl<C: Affine, R, L> Default for Stage<C, R, L> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, L: Len> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, L> {
    type Parent = super::f::Stage<C, R, L>;
    type Witness<'source> = &'source Witness<C, L>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, L>];

    fn values() -> usize {
        // (x, y) per point, the native eval and each witnessed polynomial's
        // commitment, + 2 children + current step elements (6)
        (NUM + L::len()) * 2 + 2 * (OwnRxLen::<L>::len() + 4) + 6
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
        let witness_polys = FixedVec::try_from_fn(|i| {
            Point::alloc(dr, witness.as_ref().map(|w| w.witness_polys[i]))
        })?;
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
            witness_polys,
            nested,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        use ragu_primitives::vec::ConstLen;
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<0>>::default());
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<4>>::default());
        assert_stage_values(&Stage::<EqAffine, R, ConstLen<8>>::default());
    }
}
