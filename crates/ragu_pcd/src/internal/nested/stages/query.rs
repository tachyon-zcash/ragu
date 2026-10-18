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
    profile::{Profile, ProfiledCycle},
};

/// Number of curve points in this stage.
const NUM: usize = 2;

/// Witness for a child proof's nested polynomial evaluations.
#[derive(Clone)]
pub struct ChildEvaluationsWitness<F, P: Profile> {
    /// The child's nested rx polynomials at $x_n z_n$, in
    /// [`RxIndex::all`] order.
    pub rx: FixedVec<F, OwnRxLen<P>>,
    /// The child's nested $a$ polynomial at $x_n z_n$.
    pub a_poly_at_xz: F,
    /// The child's nested $b$ polynomial at $x_n$.
    pub b_poly_at_x: F,
    /// The child's `registry_xy` polynomial at the current $w_n$.
    pub child_registry_xy_at_current_w: F,
    /// The current `registry_wy` polynomial at the child's $x_n$.
    pub current_registry_wy_at_child_x: F,
}

impl<F: Field, P: Profile> ChildEvaluationsWitness<F, P> {
    /// Evaluates a child proof's nested polynomials at the given nested
    /// points.
    pub fn from_proof<
        C: Cycle<ScalarField = F> + ProfiledCycle<Profile = P>,
        R: Rank,
        B: ragu_backend::Backend,
    >(
        proof: &Proof<C, R>,
        w: F,
        x: F,
        xz: F,
        registry_wy: &sparse::Polynomial<F, R>,
    ) -> Result<Self> {
        let child_x = nested::challenge::<C>(proof.x())?;
        Ok(ChildEvaluationsWitness {
            rx: {
                let all = RxIndex::all::<P>();
                FixedVec::from_fn(|i| B::sparse_eval(&proof[all[i]], xz))
            },
            a_poly_at_xz: B::sparse_eval(&proof[RxComponent::AbA], xz),
            b_poly_at_x: B::sparse_eval(&proof[RxComponent::AbB], x),
            child_registry_xy_at_current_w: B::sparse_eval(proof.nested_registry_xy_poly(), w),
            current_registry_wy_at_child_x: B::sparse_eval(registry_wy, child_x),
        })
    }
}

/// The nested query values carried by this stage.
#[derive(Clone)]
pub struct Evaluations<F, P: Profile> {
    /// The current `registry_xy` at each nested internal circuit's
    /// $\omega^j$, in [`InternalCircuitIndex::all`] order.
    ///
    /// [`InternalCircuitIndex::all`]: nested::InternalCircuitIndex::all
    pub fixed_registry: FixedVec<F, InternalLen<P>>,
    /// $m_n(w_n, x_n, y_n)$.
    pub registry_wxy: F,
    /// Left child proof evaluations.
    pub left: ChildEvaluationsWitness<F, P>,
    /// Right child proof evaluations.
    pub right: ChildEvaluationsWitness<F, P>,
}

impl<F: Field, P: Profile> Evaluations<F, P> {
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
pub struct Witness<C: Affine, P: Profile> {
    pub native_query: C,
    pub registry_xy: C,
    /// The nested query values.
    pub nested: Evaluations<C::Base, P>,
}

/// Gadget for a child proof's nested polynomial evaluations.
#[derive(Gadget, Write)]
pub struct ChildEvaluations<'dr, D: Driver<'dr>, P: Profile> {
    #[ragu(gadget)]
    pub rx: FixedVec<Element<'dr, D>, OwnRxLen<P>>,
    #[ragu(gadget)]
    pub a_poly_at_xz: Element<'dr, D>,
    #[ragu(gadget)]
    pub b_poly_at_x: Element<'dr, D>,
    #[ragu(gadget)]
    pub child_registry_xy_at_current_w: Element<'dr, D>,
    #[ragu(gadget)]
    pub current_registry_wy_at_child_x: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>, P: Profile> ChildEvaluations<'dr, D, P> {
    fn alloc(
        dr: &mut D,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F, P>>,
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
pub struct EvaluationsOutput<'dr, D: Driver<'dr>, P: Profile> {
    #[ragu(gadget)]
    pub fixed_registry: FixedVec<Element<'dr, D>, InternalLen<P>>,
    #[ragu(gadget)]
    pub registry_wxy: Element<'dr, D>,
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D, P>,
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D, P>,
}

/// Prover-internal output gadget for this bridge stage.
///
/// This is stage communication data, not part of the circuit's
/// public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub native_query: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    /// The nested query values.
    #[ragu(gadget)]
    pub nested: EvaluationsOutput<'dr, D, P>,
}

#[derive(Default)]
pub struct Stage<C: Affine, R, P> {
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R, P> {
    type Parent = super::ab::Stage<C, R, P>;
    type Witness<'source> = &'source Witness<C, P>;
    type OutputKind = Kind![C::Base; Output<'_, _, C, P>];

    fn values() -> usize {
        // (x, y) per point + fixed registry + registry_wxy + 2 children
        NUM * 2 + InternalLen::<P>::len() + 1 + 2 * (OwnRxLen::<P>::len() + 4)
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
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::Standard,
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<EqAffine, R, Standard>::default());
    }
}
