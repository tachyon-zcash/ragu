//! Property tests verifying that [`crate::metrics::eval`] and [`crate::trace::eval`]
//! agree on segment count and per-segment gate counts, confirming
//! that both evaluators traverse the routine call tree in identical DFS order.

use alloc::{format, vec, vec::Vec};
use proptest::prelude::*;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    routines::{Prediction, Routine},
};
use ragu_pasta::Fp;

use crate::{Circuit, WithAux};

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

fn drive_tree<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, tree: &RoutineTree) -> Result<()> {
    for _ in 0..tree.pre_allocs {
        dr.alloc(|| Ok(Coeff::One))?;
    }
    for (child, post_allocs) in &tree.children {
        dr.routine(TreeRoutine(child.clone()), ())?;
        for _ in 0..*post_allocs {
            dr.alloc(|| Ok(Coeff::One))?;
        }
    }
    Ok(())
}

#[derive(Clone)]
struct TreeRoutine(RoutineTree);

impl Routine<Fp> for TreeRoutine {
    type Input = ();
    type Output = ();
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        drive_tree(dr, &self.0)?;
        Ok(())
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
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

impl Circuit<Fp> for TreeCircuit {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
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

proptest! {
    /// Checks that [`crate::metrics::eval`] and [`crate::trace::eval`] agree on
    /// segment count and per-segment gate counts.
    ///
    /// The two evaluators are implemented independently. Agreement confirms
    /// that both traverse the routine call tree in the same DFS order and
    /// apply consistent segment-boundary rules.
    #[test]
    fn segment_dfs_order(tree in arb_tree()) {
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

        for (i, (m, t)) in metrics.segments.iter().zip(trace.segments.iter()).enumerate() {
            prop_assert_eq!(
                m.num_gates(),
                t.a.len(),
                "segment {}: mul count mismatch (metrics={}, trace={})",
                i,
                m.num_gates(),
                t.a.len(),
            );
        }
    }
}
