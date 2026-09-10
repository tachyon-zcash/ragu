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
//!
//! It also carries the running sums of the nested challenge binding: the
//! `bind_challenges` circuits each endoscale two nested-curve generators by
//! two challenges and check the sum so far against the partial this stage
//! witnessed. The last partial is the nested challenge stage's commitment.

use core::marker::PhantomData;

use ragu_arithmetic::{Cycle, ff::PrimeField};
use ragu_circuits::{
    polynomials::Rank,
    staging::{self, StageExt},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    allocator::Allocator,
    io::Write,
    vec::{ConstLen, FixedVec},
};

use crate::{
    Proof,
    internal::{
        native::{RxComponent, RxIndex, RxValues, circuits::bind_challenges::NUM_BINDERS},
        nested,
    },
};

/// Length type for the binding partial sums, one per `bind_challenges`
/// circuit.
pub type PartialsLen = ConstLen<NUM_BINDERS>;

/// The running sums of the nested challenge binding: partial $k$ is the sum
/// of the first $2(k+1)$ terms of the nested challenge stage's commitment,
/// $\sum_{i < 2(k+1)} \mathrm{lift}(\mathrm{ch}_i) \cdot G_{\mathrm{idx}(i)}$.
#[derive(Clone)]
pub struct BindingPartials<P> {
    pub partials: FixedVec<P, PartialsLen>,
}

impl<P: ragu_arithmetic::CurveAffine> BindingPartials<P> {
    /// Computes the partials of the given lifts (the first ten challenges,
    /// `w` through `u`, in stage order) over the nested-curve generators the
    /// challenge stage commits them with.
    pub fn compute<C: Cycle<NestedCurve = P, ScalarField = P::ScalarExt>, R: Rank, B>(
        params: &C::Params,
        lifts: &[C::ScalarField],
    ) -> Self
    where
        B: ragu_backend::Backend,
    {
        use ragu_arithmetic::FixedGenerators;

        assert_eq!(lifts.len(), 2 * NUM_BINDERS);
        let generators = C::nested_generators(params);
        let bases: alloc::vec::Vec<P> = (0..lifts.len())
            .map(|i| generators.g()[generator_index::<C, R>(i)])
            .collect();
        let partials =
            ragu_arithmetic::batch_to_affine(core::array::from_fn::<_, NUM_BINDERS, _>(|k| {
                let n = 2 * (k + 1);
                B::msm(lifts[..n].iter(), bases[..n].iter())
            }));
        Self {
            partials: FixedVec::new(partials.into()).expect("NUM_BINDERS partials"),
        }
    }
}

/// The nested-curve generator index the challenge stage commits its `i`-th
/// lift with (see [`StageExt::generator_index_for_a`]).
pub fn generator_index<C: Cycle, R: Rank>(i: usize) -> usize {
    <nested::stages::challenges::Stage<C::HostCurve, R> as StageExt<C::ScalarField, R>>::generator_index_for_a(i)
}

/// Polynomial evaluations at $u$ (from the parent fuse operation) for a child
/// proof. Supplied by the prover to construct the `eval` stage witness.
pub struct ChildEvaluationsWitness<F> {
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
}

impl<F: PrimeField> ChildEvaluationsWitness<F> {
    /// Create child evaluations witness from a proof evaluated at point u.
    pub fn from_proof<C: Cycle<CircuitField = F>, R: Rank, B: ragu_backend::Backend>(
        proof: &Proof<C, R>,
        u: F,
    ) -> Self {
        ChildEvaluationsWitness {
            rx: RxValues::from_fn(|id| B::sparse_eval(&proof[id], u)),
            a_poly: B::sparse_eval(&proof[RxComponent::AbA], u),
            b_poly: B::sparse_eval(&proof[RxComponent::AbB], u),
            registry_xy_poly: B::sparse_eval(proof.native_registry_xy_poly(), u),
            p_poly: B::sparse_eval(proof.native_p_poly(), u),
        }
    }
}

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
pub struct Witness<C: Cycle> {
    /// Left proof's evaluations at $u$.
    pub left: ChildEvaluationsWitness<C::CircuitField>,

    /// Right proof's evaluations at $u$.
    pub right: ChildEvaluationsWitness<C::CircuitField>,

    /// Current fuse step's evaluations at $u$.
    pub current: CurrentStepWitness<C::CircuitField>,

    /// The nested challenge binding's running sums.
    pub partials: BindingPartials<C::NestedCurve>,
}

impl<C: Cycle> Witness<C> {
    /// The all-zero evaluations of a proof that opens nothing, with the
    /// given binding partials.
    pub fn trivial(partials: BindingPartials<C::NestedCurve>) -> Self {
        use ragu_arithmetic::ff::Field;
        let child = || ChildEvaluationsWitness {
            rx: RxValues::from_fn(|_| C::CircuitField::ZERO),
            a_poly: C::CircuitField::ZERO,
            b_poly: C::CircuitField::ZERO,
            registry_xy_poly: C::CircuitField::ZERO,
            p_poly: C::CircuitField::ZERO,
        };
        Witness {
            left: child(),
            right: child(),
            current: CurrentStepWitness {
                registry_wx0: C::CircuitField::ZERO,
                registry_wx1: C::CircuitField::ZERO,
                registry_wy: C::CircuitField::ZERO,
                a_poly: C::CircuitField::ZERO,
                b_poly: C::CircuitField::ZERO,
                registry_xy: C::CircuitField::ZERO,
            },
            partials,
        }
    }
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
    /// Allocates child evaluations from pre-computed witness input values.
    pub fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, &ChildEvaluationsWitness<D::F>>,
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
        })
    }
}

/// The committed evaluations at $u$.
///
/// The [`Write`] order defines the coefficient order of the $\beta$-weighted
/// sum that computes $v = p(u)$, so it must match `compute_p`'s accumulation
/// order.
#[derive(Gadget, Write)]
pub struct Evaluations<'dr, D: Driver<'dr>> {
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

/// Prover-internal output gadget for the eval stage.
///
/// This is stage communication data, not part of the circuit's public instance.
/// The binding partials are kept apart from the evaluations so that writing
/// the evaluations into the $v$ Horner sum never includes them.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    pub evaluations: Evaluations<'dr, D>,
    #[ragu(gadget)]
    pub partials: FixedVec<Point<'dr, D, C::NestedCurve>, PartialsLen>,
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
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, C>];

    fn values() -> usize {
        // 2 * ChildEvaluations (rx + 4 each) + current step elements (6)
        // + (x, y) per binding partial
        2 * (RxIndex::NUM + 4) + 6 + 2 * NUM_BINDERS
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
        let partials = FixedVec::try_from_fn(|k| {
            Point::alloc(dr, witness.as_ref().map(|w| w.partials.partials[k]))
        })?;
        Ok(Output {
            evaluations: Evaluations {
                left,
                right,
                registry_wx0,
                registry_wx1,
                registry_wy,
                a_poly,
                b_poly,
                registry_xy,
            },
            partials,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
