//! Native evaluation stage for fuse operations.
//!
//! The prover claims that $f(X)$ is a (low degree) non-rational polynomial in
//! $X$ in order to demonstrate that their claimed queries in the `query` stage
//! were correct. This is achieved by committing to $f(X)$ and then opening it
//! at a random point $u$ (a challenge determined after the commitment to
//! $f(X)$) to its expected evaluation; by the definition of $f(X)$, this is
//! fully determined by quotients involving the claimed evaluations, the
//! evaluations of the various queried polynomials at $u$ and by the various
//! points they were queried at.
//!
//! In order to obtain the real evaluations of the various queried polynomials,
//! the prover will commit to _claims_ about them and these claims are then
//! accumulated together with the claim about $f(u)$.
//!
//! This stage contains the committed claims of all evaluations (other than
//! $f(X)$) at $u$ for all the queried polynomials.

use core::marker::PhantomData;

use ragu_arithmetic::{Cycle, ff::PrimeField};
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    allocator::Allocator,
    io::Write,
    vec::{CollectFixed, FixedVec, Len},
};

use crate::{
    Proof,
    framework_hooks::HookConfig,
    internal::{
        native::{RxComponent, RxValues},
        nested::child_endoscaling_points,
    },
};

/// Polynomial evaluations at $u$ (from the parent fuse operation) for a child
/// proof. Supplied by the prover to construct the `eval` stage witness.
pub struct ChildEvaluationsWitness<F, L: Len> {
    /// All of the child proof's Rx components are evaluated at $u$.
    pub rx: RxValues<F>,

    /// The child proof's A polynomial is evaluated at $u$.
    pub a_poly: F,

    /// The child proof's B polynomial is evaluated at $u$.
    pub b_poly: F,

    /// The child proof's `registry_xy_poly` is evaluated at $u$.
    ///
    /// This polynomial is queried only to relate the committed polynomial with
    /// another commitment at a different restriction.
    pub registry_xy_poly: F,

    /// The child proof's P polynomial is evaluated at $u$.
    ///
    /// This polynomial is queried only to insert the claim about $p(X)$ from
    /// the child proof into the accumulator for the fuse step.
    pub p_poly: F,

    /// The child proof's witnessed polynomials, each evaluated at $u$.
    pub witness_poly_evals: FixedVec<F, L>,
}

impl<F: PrimeField, L: Len> ChildEvaluationsWitness<F, L> {
    /// Create child evaluations witness from a proof evaluated at point u.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank>(
        proof: &Proof<C, R>,
        u: F,
    ) -> Result<Self> {
        Ok(ChildEvaluationsWitness {
            rx: RxValues::from_fn(|id| proof[id].eval(u)),
            a_poly: proof[RxComponent::AbA].eval(u),
            b_poly: proof[RxComponent::AbB].eval(u),
            registry_xy_poly: proof.native_registry_xy_poly().eval(u),
            p_poly: proof.native_p_poly().eval(u),
            witness_poly_evals: proof
                .witness_polys()
                .iter()
                .map(|p| p.eval(u))
                .collect_fixed()?,
        })
    }
}

/// The number of components the current fuse step contributes to an
/// accumulation — one per field of [`CurrentStepWitness`]. This stage's width
/// and the nested side's endoscaling-point count are both built from it.
pub const CURRENT_STEP_COMPONENTS: usize = 6;

/// Pre-computed polynomial evaluations at $u$ for the current step.
pub struct CurrentStepWitness<F> {
    /// Evaluation of the committed $m(w, x_0, Y)$ at $u$, where $x\_{0}$ is
    /// from the left child proof. This polynomial is committed in the
    /// `_03_s_prime` step of the fuse operation, within the _nested_ `s_prime`
    /// stage.
    pub registry_wx0: F,

    /// Evaluation of the committed $m(w, x_1, Y)$ at $u$, where $x\_{1}$ is
    /// from the right child proof. This polynomial is committed in the
    /// `_03_s_prime` step of the fuse operation, within the _nested_ `s_prime`
    /// stage.
    pub registry_wx1: F,

    /// Evaluation of the committed $m(w, X, y)$ at $u$. This polynomial is
    /// committed in the `_04_inner_error` step of the fuse operation, within
    /// the _nested_ `inner_error` stage.
    pub registry_wy: F,

    /// Evaluation of the committed $a(X)$ at $u$. This polynomial is committed
    /// in the `_06_ab` step of the fuse operation, within the _nested_ `ab`
    /// stage.
    pub a_poly: F,

    /// Evaluation of the committed $b(X)$ at $u$. This polynomial is committed
    /// in the `_06_ab` step of the fuse operation, within the _nested_ `ab`
    /// stage.
    pub b_poly: F,

    /// Evaluation of the committed $m(W, x, y)$ at $u$. This polynomial is
    /// committed in the `_07_query` step of the fuse operation, within the
    /// _nested_ `query` stage.
    pub registry_xy: F,
}

/// Witness for the eval stage.
pub struct Witness<F, L: Len> {
    /// Left proof's evaluations at $u$.
    pub left: ChildEvaluationsWitness<F, L>,

    /// Right proof's evaluations at $u$.
    pub right: ChildEvaluationsWitness<F, L>,

    /// Current fuse step's evaluations at $u$.
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
pub struct ChildEvaluations<'dr, D: Driver<'dr>, J: HookConfig> {
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
    /// The child's witnessed-polynomial evaluations at $u$
    /// (the [`Write`] order must match the `_10_p` accumulation order).
    #[ragu(gadget)]
    pub witness_poly_evals: FixedVec<Element<'dr, D>, J::PolyWitnesses>,
}

impl<'dr, D: Driver<'dr>, J: HookConfig> ChildEvaluations<'dr, D, J> {
    /// Allocate child evaluations from pre-computed witness values.
    pub fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F, J::PolyWitnesses>>,
    ) -> Result<Self> {
        let rx = RxValues::try_from_fn(|id| {
            Element::alloc(dr, allocator, witness.as_ref().map(|w| *w.rx.get(id)))
        })?;
        Ok(ChildEvaluations {
            rx,
            a_poly: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.a_poly))?,
            b_poly: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.b_poly))?,
            registry_xy_poly: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|w| w.registry_xy_poly),
            )?,
            p_poly: Element::alloc(dr, allocator, witness.as_ref().map(|w| w.p_poly))?,
            witness_poly_evals: J::PolyWitnesses::range()
                .map(|i| {
                    Element::alloc(
                        dr,
                        allocator,
                        witness.as_ref().map(|w| w.witness_poly_evals[i]),
                    )
                })
                .try_collect_fixed()?,
        })
    }
}

/// Prover-internal output gadget for the eval stage.
///
/// This is stage communication data, not part of the circuit's public instance.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, J: HookConfig> {
    #[ragu(gadget)]
    pub left: ChildEvaluations<'dr, D, J>,
    #[ragu(gadget)]
    pub right: ChildEvaluations<'dr, D, J>,
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
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig> {
    _marker: PhantomData<(C, R, J)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig> Default for Stage<C, R, HEADER_SIZE, J> {
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE, J>
{
    type Parent = super::query::Stage<C, R, HEADER_SIZE, J>;
    type Witness<'source> = &'source Witness<C::CircuitField, J::PolyWitnesses>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, J>];

    fn values() -> usize {
        2 * child_endoscaling_points(J::PolyWitnesses::len()) + CURRENT_STEP_COMPONENTS
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        let left = ChildEvaluations::alloc(dr, allocator, witness.as_ref().map(|w| &w.left))?;
        let right = ChildEvaluations::alloc(dr, allocator, witness.as_ref().map(|w| &w.right))?;
        let registry_wx0 = Element::alloc(
            dr,
            allocator,
            witness.as_ref().map(|w| w.current.registry_wx0),
        )?;
        let registry_wx1 = Element::alloc(
            dr,
            allocator,
            witness.as_ref().map(|w| w.current.registry_wx1),
        )?;
        let registry_wy = Element::alloc(
            dr,
            allocator,
            witness.as_ref().map(|w| w.current.registry_wy),
        )?;
        let a_poly = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.current.a_poly))?;
        let b_poly = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.current.b_poly))?;
        let registry_xy = Element::alloc(
            dr,
            allocator,
            witness.as_ref().map(|w| w.current.registry_xy),
        )?;
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
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{
        AppHooks,
        internal::tests::{HEADER_SIZE, R, assert_stage_values},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        fn check<const POLYS: usize>() {
            assert_stage_values(
                &Stage::<Pasta, R, { HEADER_SIZE }, AppHooks<POLYS>>::default(),
            );
        }
        check::<0>();
        check::<1>();
        check::<4>();
        check::<8>();
    }
}
