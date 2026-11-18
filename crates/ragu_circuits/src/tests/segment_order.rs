//! Property tests verifying that [`crate::metrics::eval`] and [`crate::trace::eval`]
//! agree on segment count and per-segment gate counts, confirming
//! that both evaluators traverse the routine call tree in identical DFS order.

use alloc::{format, vec, vec::Vec};

use proptest::prelude::*;
use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::Bound,
    pasta::{Fp, Fq},
    routines::{Prediction, Routine},
};
use ragu_primitives::allocator::Allocator;
use ragu_testing::strategies::prime_field_element;
use udon::field::Field;

use crate::{
    Circuit, WithAux,
    polynomials::{WalletRank, Rank, TestRank},
    wiring::compiled::tests::{assert_matches_interpreted, assert_matches_interpreted_at},
};

/// Maximum number of wire allocations generated at any one point in a scope.
const MAX_ALLOCS: usize = 6;
/// Maximum number of child routine calls per scope.
const MAX_CHILDREN: u32 = 4;
/// Maximum nesting depth of the generated routine tree.
const MAX_DEPTH: u32 = 4;
/// Target total number of `RoutineTree` nodes across the whole tree (passed as
/// `expected_branch_count` to `prop_recursive`; proptest uses this as a
/// generation budget, not a hard cap).
const MAX_TREE_SIZE: u32 = 30;

/// A `RoutineTree` describes the structure of a single routine scope: how many
/// wire allocations happen before any sub-routine is called, what sub-routines
/// are called, and whether this routine's `predict()` returns `Known` or
/// `Unknown`.
///
/// When `prediction_is_known` is `true` the routine takes the deferred path in
/// [`crate::trace`] (returning `Known` from `predict`); when `false` it takes the
/// synchronous path (returning `Unknown`). Proptest exercises both values at
/// every nesting level, covering all combinations of outer and inner prediction
/// modes that arise in generated trees.
///
/// The execution order within one scope is:
///
/// ```text
/// ├─ [pre_allocs]  alloc alloc …
/// ├─ call children[0]
/// │   └─ (children[0] scope, recursively)
/// ├─ [children[0].post_allocs]  alloc alloc …
/// ├─ call children[1]
/// │   └─ (children[1] scope, recursively)
/// ├─ [children[1].post_allocs]  alloc alloc …
/// ⋮
/// ├─ call children[n]
/// │   └─ (children[n] scope, recursively)
/// └─ [children[n].post_allocs]  alloc alloc …
/// ```
#[derive(Debug, Clone)]
struct RoutineTree {
    /// Wire allocations emitted before the first child routine call.
    pre_allocs: usize,
    /// Child routines in call order. Each child is paired with
    /// `post_allocs`: the number of wire allocations emitted in this scope
    /// immediately after that child returns.
    children: Vec<(RoutineTree, usize)>,
    /// When `true`, `predict()` returns `Known` (deferred parallel path).
    /// When `false`, `predict()` returns `Unknown` (synchronous path).
    ///
    /// Note: only meaningful when this `RoutineTree` is used as a child
    /// (wrapped in `TreeRoutine`). The root node's `prediction_is_known` is
    /// never consulted because `TreeCircuit` synthesizes directly without
    /// dispatching through `Routine::predict`.
    prediction_is_known: bool,
}

fn arb_tree() -> impl Strategy<Value = RoutineTree> {
    let leaf =
        (0usize..=MAX_ALLOCS, any::<bool>()).prop_map(|(n, prediction_is_known)| RoutineTree {
            pre_allocs: n,
            children: vec![],
            prediction_is_known,
        });
    leaf.prop_recursive(MAX_DEPTH, MAX_TREE_SIZE, MAX_CHILDREN, |inner| {
        (
            0usize..=MAX_ALLOCS,
            proptest::collection::vec((inner, 0usize..=MAX_ALLOCS), 0..=MAX_CHILDREN as usize),
            any::<bool>(),
        )
            .prop_map(|(pre_allocs, children, prediction_is_known)| RoutineTree {
                pre_allocs,
                children,
                prediction_is_known,
            })
    })
}

fn drive_tree<'dr, D: Driver<'dr>>(dr: &mut D, tree: &RoutineTree) -> Result<()> {
    alloc_chain(dr, tree.pre_allocs)?;
    for (child, post_allocs) in &tree.children {
        dr.routine(TreeRoutine(child.clone()), ())?;
        alloc_chain(dr, *post_allocs)?;
    }
    Ok(())
}

/// Allocates `count` wires, constraining each after the first to equal its
/// predecessor, so that every segment contributes constraints to the wiring
/// polynomial at its own offset. Every allocated value is one, so the
/// constraints hold whatever their scale; the scales rotate through each
/// coefficient form the compiled wiring encodes differently.
fn alloc_chain<'dr, D: Driver<'dr>>(dr: &mut D, count: usize) -> Result<()> {
    let five = D::F::ONE.double().double() + D::F::ONE;
    let mut previous = None;
    for i in 0..count {
        let wire = ().alloc(dr, || Ok(Coeff::One))?;
        if let Some(previous) = &previous {
            let (scale, negated) = match i % 3 {
                0 => (Coeff::One, Coeff::NegativeOne),
                1 => (Coeff::Two, Coeff::Arbitrary(-D::F::ONE.double())),
                _ => (Coeff::Arbitrary(five), Coeff::Arbitrary(-five)),
            };
            dr.enforce_zero(|lc| lc.add_term(&wire, scale).add_term(previous, negated))?;
        }
        previous = Some(wire);
    }
    Ok(())
}

#[derive(Clone)]
struct TreeRoutine(RoutineTree);

impl<F: Field> Routine<F> for TreeRoutine {
    type Input = ();
    type Output = ();
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        drive_tree(dr, &self.0)?;
        Ok(())
    }

    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        if self.0.prediction_is_known {
            Ok(Prediction::Known((), D::unit()))
        } else {
            Ok(Prediction::Unknown(D::unit()))
        }
    }
}

struct TreeCircuit(RoutineTree);

impl<F: Field> Circuit<F> for TreeCircuit {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        drive_tree(dr, &self.0)?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// Whether `circuit` fits within rank `R`'s gate and constraint bounds.
fn fits<R: Rank>(circuit: &TreeCircuit) -> bool {
    crate::metrics::eval::<Fp, _>(circuit).is_ok_and(|metrics| {
        metrics.num_gates <= R::n() && metrics.num_constraints < R::num_coeffs()
    })
}

proptest! {
    /// Cross-evaluator polynomial consistency: verifies that all three
    /// independent evaluators (sxy, sx, sy) agree on the polynomial value
    /// for random routine trees, and that the polynomial written out as
    /// monomials, which the registry hashes into its tag, agrees with them.
    ///
    /// Each evaluator computes the wiring polynomial via a different
    /// strategy (full-point Horner, partial-X coefficients, partial-Y
    /// structured form). Agreement confirms that all of them correctly
    /// handle routine scope jumps, segment offsets, and Horner
    /// accumulation across arbitrary nesting topologies.
    ///
    /// The compiled wiring the registry evaluates must match those
    /// interpreters, with and without shared powers: at fixed points, and
    /// at drawn points on both Pasta fields at the test and production
    /// ranks.
    #[test]
    fn polynomial_consistency(
        tree in arb_tree(),
        (fp_x, fp_y) in (prime_field_element::<Fp>(), prime_field_element::<Fp>()),
        (fq_x, fq_y) in (prime_field_element::<Fq>(), prime_field_element::<Fq>()),
    ) {
        let circuit = TreeCircuit(tree);
        if fits::<TestRank>(&circuit) {
            assert_matches_interpreted::<_, TestRank>(&circuit);
            assert_matches_interpreted_at::<Fp, _, TestRank>(&circuit, &[fp_x], &[fp_y]);
            assert_matches_interpreted_at::<Fq, _, TestRank>(&circuit, &[fq_x], &[fq_y]);
        }
        if fits::<WalletRank>(&circuit) {
            assert_matches_interpreted_at::<Fp, _, WalletRank>(&circuit, &[fp_x], &[fp_y]);
            assert_matches_interpreted_at::<Fq, _, WalletRank>(&circuit, &[fq_x], &[fq_y]);
        }
        // Skip trees that exceed TestRank's multiplication bound.
        let circuit_obj = match crate::into_wiring_object::<Fp, _, TestRank>(circuit) {
            Ok(obj) => obj,
            Err(_) => return Ok(()),
        };
        super::consistency_checks(&*circuit_obj);
    }

    /// Checks that [`crate::metrics::eval`] and [`crate::trace::eval`] agree on
    /// segment count and per-segment gate counts, and that
    /// [`crate::metrics::eval`] constraint counts agree with the floor
    /// plan derived from its own segment records (which the sxy evaluator
    /// asserts against during [`polynomial_consistency`]).
    ///
    /// The two evaluators are implemented independently. Agreement confirms
    /// that both traverse the routine call tree in the same DFS order and
    /// apply consistent segment-boundary rules.
    #[test]
    fn proptest_segment_dfs_order(tree in arb_tree()) {
        let circuit = TreeCircuit(tree);

        let metrics = crate::metrics::eval::<Fp, _>(&circuit)
            .map_err(|e| TestCaseError::fail(format!("metrics: {e:?}")))?;
        let trace = crate::trace::eval::<Fp, _>(&circuit, ())
            .map_err(|e| TestCaseError::fail(format!("trace: {e:?}")))?.into_output();

        prop_assert_eq!(
            metrics.segments.len(),
            trace.segments.len(),
            "segment count mismatch"
        );

        let plan = crate::floor_planner::floor_plan(&metrics.segments);

        for (i, ((m, t), fp)) in metrics.segments.iter()
            .zip(trace.segments.iter())
            .zip(plan.iter())
            .enumerate()
        {
            prop_assert_eq!(
                m.num_gates(),
                t.a.len(),
                "segment {}: gate count mismatch (metrics={}, trace={})",
                i,
                m.num_gates(),
                t.a.len(),
            );
            prop_assert_eq!(
                m.num_constraints(),
                fp.num_constraints,
                "segment {}: constraint count mismatch (metrics={}, floor_plan={})",
                i,
                m.num_constraints(),
                fp.num_constraints,
            );
        }
    }
}
