//! Routine placement within the polynomial layout.
//!
//! Converts per-routine constraint records (from the `metrics` module) into
//! absolute offsets that the `s(X, Y)` evaluators use to position each
//! routine's constraints.
//!
//! # DFS-order indexing convention
//!
//! The floor plan is indexed by DFS synthesis order: `floor_plan[i]` describes
//! where the *i*-th routine (in DFS order) is placed in the polynomial. A
//! reordering floor planner changes the **values** (offsets), not the
//! **indices**. All consumers — the three `s(X, Y)` evaluators, the `rx`
//! evaluator, and `assemble_with_key` — depend on this convention.
//!
//! The root routine (index 0) is always pinned at offset 0; see the
//! [`floor_plan`] function for details.

use alloc::vec::Vec;

use super::metrics::RoutineRecord;

/// A routine's placement in the polynomial layout.
///
/// Each routine in a circuit occupies a contiguous range of multiplication
/// gates and linear constraints. The floor plan assigns absolute positions
/// (offsets) and sizes to each routine in DFS order.
///
/// The floor plan is indexed by DFS synthesis order: `floor_plan[i]`
/// corresponds to the *i*-th routine encountered during synthesis. A reordering
/// floor planner may assign different offset values but must preserve index
/// correspondence. The root routine (index 0) must always be placed at the
/// polynomial origin (both offsets zero).
///
/// Currently, routines keep their synthesis (DFS) order and positions are
/// computed by a trivial prefix sum over per-routine constraint counts. A
/// future floor planner could reorder routines for alignment or packing, but
/// the current implementation does not.
pub struct RoutineSlot {
    /// Gate index where this routine's multiplication constraints begin.
    pub multiplication_start: usize,
    /// Y-power index where this routine's linear constraints begin.
    pub linear_start: usize,
    /// Number of multiplication constraints in this routine.
    pub num_multiplication_constraints: usize,
    /// Number of linear constraints in this routine.
    pub num_linear_constraints: usize,
}

/// Computes a floor plan from per-routine constraint records.
///
/// Converts per-routine constraint counts into absolute offsets via prefix
/// sum, preserving synthesis (DFS) order.
pub fn floor_plan(routine_records: &[RoutineRecord]) -> Vec<RoutineSlot> {
    let mut result = Vec::with_capacity(routine_records.len());
    let mut multiplication_start = 0usize;
    let mut linear_start = 0usize;
    for record in routine_records {
        result.push(RoutineSlot {
            multiplication_start,
            linear_start,
            num_multiplication_constraints: record.num_multiplication_constraints,
            num_linear_constraints: record.num_linear_constraints,
        });
        multiplication_start += record.num_multiplication_constraints;
        linear_start += record.num_linear_constraints;
    }

    assert!(
        result
            .first()
            .is_none_or(|r| r.multiplication_start == 0 && r.linear_start == 0),
        "root routine must be placed at the polynomial origin"
    );

    result
}
