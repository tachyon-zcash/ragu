//! Query stage for nested fuse operations.
//!
//! Alongside the two host-curve commitments it bridges, this stage carries
//! the nested query values: the claimed evaluations, at the nested $x_n z_n$,
//! $x_n$ and $w_n$, that the nested [`compute_v`] circuit folds into the
//! nested quotient polynomial's evaluation. They ride here because this
//! bridge stage's commitment is absorbed before $\alpha$ is squeezed.
//!
//! [`compute_v`]: crate::internal::nested::circuits::compute_v

use core::marker::PhantomData;

use ragu_circuits::polynomials::{Rank, sparse};
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
    internal::nested::{
        self, RxComponent, RxIndex,
        pcs::{InternalLen, OwnRxLen},
    },
};

/// Number of curve points in this stage.
const NUM: usize = 2;

/// Witness for a child proof's nested polynomial evaluations, for a poly
/// count `L`.
pub struct ChildEvaluationsWitness<F, L: Len> {
    /// The child's nested rx polynomials at $x_n z_n$, in
    /// [`RxIndex::all`] order.
    pub rx: FixedVec<F, OwnRxLen<L>>,
    /// The child's nested $a$ polynomial at $x_n z_n$.
    pub a_poly_at_xz: F,
    /// The child's nested $b$ polynomial at $x_n$.
    pub b_poly_at_x: F,
    /// The child's `registry_xy` polynomial at the current $w_n$.
    pub child_registry_xy_at_current_w: F,
    /// The current `registry_wy` polynomial at the child's $x_n$.
    pub current_registry_wy_at_child_x: F,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<F: Clone, L: Len> Clone for ChildEvaluationsWitness<F, L> {
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
            a_poly_at_xz: self.a_poly_at_xz.clone(),
            b_poly_at_x: self.b_poly_at_x.clone(),
            child_registry_xy_at_current_w: self.child_registry_xy_at_current_w.clone(),
            current_registry_wy_at_child_x: self.current_registry_wy_at_child_x.clone(),
        }
    }
}

impl<F: Field, L: Len> ChildEvaluationsWitness<F, L> {
    /// Evaluates a child proof's nested polynomials at the given nested
    /// points.
    pub fn from_proof<C: Cycle<ScalarField = F>, R: Rank, B: ragu_backend::Backend>(
        proof: &Proof<C, R>,
        w: F,
        x: F,
        xz: F,
        registry_wy: &sparse::Polynomial<F, R>,
    ) -> Result<Self> {
        let child_x = nested::challenge::<C>(proof.x())?;
        let ids: alloc::vec::Vec<RxIndex> = RxIndex::all(L::len()).collect();
        Ok(ChildEvaluationsWitness {
            rx: FixedVec::from_fn(|i| B::sparse_eval(&proof[ids[i]], xz)),
            a_poly_at_xz: B::sparse_eval(&proof[RxComponent::AbA], xz),
            b_poly_at_x: B::sparse_eval(&proof[RxComponent::AbB], x),
            child_registry_xy_at_current_w: B::sparse_eval(proof.nested_registry_xy_poly(), w),
            current_registry_wy_at_child_x: B::sparse_eval(registry_wy, child_x),
        })
    }
}

/// The nested query values carried by this stage, for a poly count `L`.
pub struct Evaluations<F, L: Len> {
    /// The current `registry_xy` at each nested internal circuit's
    /// $\omega^j$, in [`InternalCircuitIndex::all`] order.
    ///
    /// [`InternalCircuitIndex::all`]: nested::InternalCircuitIndex::all
    pub fixed_registry: FixedVec<F, InternalLen<L>>,
    /// $m_n(w_n, x_n, y_n)$.
    pub registry_wxy: F,
    /// Left child proof evaluations.
    pub left: ChildEvaluationsWitness<F, L>,
    /// Right child proof evaluations.
    pub right: ChildEvaluationsWitness<F, L>,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<F: Clone, L: Len> Clone for Evaluations<F, L> {
    fn clone(&self) -> Self {
        Self {
            fixed_registry: self.fixed_registry.clone(),
            registry_wxy: self.registry_wxy.clone(),
            left: self.left.clone(),
            right: self.right.clone(),
        }
    }
}

impl<F: Field, L: Len> Evaluations<F, L> {
    /// All-zero values, for proofs that open nothing (the dummy proof).
    pub fn zero() -> Self {
        let child = || ChildEvaluationsWitness {
            rx: FixedVec::from_fn(|_| F::ZERO),
            a_poly_at_xz: F::ZERO,
            b_poly_at_x: F::ZERO,
            child_registry_xy_at_current_w: F::ZERO,
            current_registry_wy_at_child_x: F::ZERO,
        };
        Evaluations {
            fixed_registry: FixedVec::from_fn(|_| F::ZERO),
            registry_wxy: F::ZERO,
            left: child(),
            right: child(),
        }
    }
}

/// Witness data for this bridge stage.
pub struct Witness<C: Affine, L: Len> {
    pub native_query: C,
    pub registry_xy: C,
    /// The nested query values.
    pub nested: Evaluations<C::Base, L>,
}

/// Gadget for a child proof's nested polynomial evaluations.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>, L: Len> {
    #[ragu(gadget)]
    pub rx: FixedVec<Element<'dr, D>, OwnRxLen<L>>,
    #[ragu(gadget)]
    pub a_poly_at_xz: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly_at_x: Element<'dr, D>,
    #[ragu(gadget)]
    pub child_registry_xy_at_current_w: Element<'dr, D>,
    #[ragu(gadget)]
    pub current_registry_wy_at_child_x: Element<'dr, D>,
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
            a_poly_at_xz: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.a_poly_at_xz))?,
            b_poly_at_x: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.b_poly_at_x))?,
            child_registry_xy_at_current_w: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.child_registry_xy_at_current_w),
            )?,
            current_registry_wy_at_child_x: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.current_registry_wy_at_child_x),
            )?,
        })
    }
}

/// Gadget for the nested query values.
#[derive(Gadget, Write)]
pub struct EvaluationsOutput<'dr, D: Driver<'dr>, L: Len> {
    #[ragu(gadget)]
    pub fixed_registry: FixedVec<Element<'dr, D>, InternalLen<L>>,
    #[ragu(gadget)]
    pub registry_wxy: Element<'dr, D>,
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D, L>,
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D, L>,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub native_query: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    /// The nested query values.
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
    type Parent = super::ab::Stage<C, R, L>;
    type Witness<'source> = &'source Witness<C, L>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, L>];

    fn values() -> usize {
        // (x, y) per point + fixed registry + registry_wxy + 2 children
        NUM * 2 + InternalLen::<L>::len() + 1 + 2 * (OwnRxLen::<L>::len() + 4)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        let native_query = Point::alloc(dr, witness.as_ref().map(|w| w.native_query))?;
        let registry_xy = Point::alloc(dr, witness.as_ref().map(|w| w.registry_xy))?;
        let nested = EvaluationsOutput {
            fixed_registry: FixedVec::try_from_fn(|i| {
                Element::alloc(
                    dr,
                    allocator,
                    witness.as_ref().map(|w| w.nested.fixed_registry[i]),
                )
            })?,
            registry_wxy: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.nested.registry_wxy),
            )?,
            left: ChildEvaluations::alloc(dr, witness.as_ref().map(|w| &w.nested.left))?,
            right: ChildEvaluations::alloc(dr, witness.as_ref().map(|w| &w.nested.right))?,
        };

        Ok(Output {
            native_query,
            registry_xy,
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
        assert_stage_values(&Stage::<EqAffine, R, ragu_primitives::vec::ConstLen<0>>::default());
    }
}
