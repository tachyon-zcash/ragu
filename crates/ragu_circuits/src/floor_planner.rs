//! Segment placement within the polynomial layout.
//!
//! Converts per-segment constraint records (from the `metrics` module) into
//! absolute offsets that the `s(X, Y)` evaluators use to position each
//! segment's constraints within the polynomial.
//!
//! # DFS-order indexing convention
//!
//! The floor plan is indexed by DFS synthesis order: `floor_plan[i]` describes
//! where the *i*-th segment (in DFS order) is placed in the polynomial. A
//! reordering floor planner changes the **values** (offsets), not the
//! **indices**. All consumers — the three `s(X, Y)` evaluators, the `rx`
//! evaluator, and `assemble_with_key` — depend on this convention.
//!
//! The root segment (index 0) is always pinned at offset 0; see the
//! [`floor_plan`] function for details.
//!
//! ```text
//!  Synthesis trace              Seg
//!  ────────────────────────     ───
//!  ├─ c0 ······················ [0]  (root)
//!  ├─ call RoutineA
//!  │   └─ ···················── [1]
//!  ├─ c1 ······················ [0]  (root)
//!  ├─ call RoutineB
//!  │   ├─ b0 ·················· [2]
//!  │   ├─ call RoutineC
//!  │   │   └─ ················· [3]
//!  │   └─ b1 ·················· [2]
//!  └─ c2 ······················ [0]  (root)
//!
//!  floor_plan indices are DFS encounter order:
//!    [0]  root ── c0 + c1 + c2  (everything outside routines)
//!    [1]  A    ── A's own constraints
//!    [2]  B    ── b0 + b1       (RoutineC excluded)
//!    [3]  C    ── C's own constraints
//! ```
//!
//! See [`SegmentRecord`] for a fully worked example with concrete numbers.

use alloc::vec::Vec;

use super::metrics::SegmentRecord;

/// A segment's placement in a constraint system.
///
/// Each segment in a circuit occupies a contiguous range of multiplication
/// gates and linear constraints. The primary segment boundaries are [`Routine`]
/// calls; index 0 is the root segment (not backed by any [`Routine`]).
/// The floor plan assigns absolute positions (offsets) and sizes to each
/// segment in DFS order.
///
/// The floor plan is indexed by DFS synthesis order: `floor_plan[i]`
/// corresponds to the *i*-th segment encountered during synthesis. A reordering
/// floor planner may assign different offset values but must preserve index
/// correspondence. The root segment (index 0) must always be placed at
/// the polynomial origin (both offsets zero).
///
/// Currently, segments keep their synthesis (DFS) order and positions are
/// computed by a trivial prefix sum over per-segment constraint counts. A
/// future floor planner could reorder segments for alignment or packing, but
/// the current implementation does not.
///
/// [`Routine`]: ragu_core::routines::Routine
#[derive(Debug, Clone, Copy)]
pub struct ConstraintSegment {
    /// Gate index where this segment's multiplication constraints begin.
    pub multiplication_start: usize,
    /// Y-power index where this segment's linear constraints begin.
    pub linear_start: usize,
    /// Number of multiplication constraints in this segment.
    pub num_multiplication_constraints: usize,
    /// Number of linear constraints in this segment.
    pub num_linear_constraints: usize,
}

/// Computes a floor plan from per-segment constraint records.
///
/// Converts per-segment constraint counts into absolute offsets via prefix
/// sum, preserving synthesis (DFS) order.
pub fn floor_plan(segment_records: &[SegmentRecord]) -> Vec<ConstraintSegment> {
    let mut result = Vec::with_capacity(segment_records.len());
    let mut multiplication_start = 0usize;
    let mut linear_start = 0usize;
    for record in segment_records {
        result.push(ConstraintSegment {
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
        "root segment must be placed at the polynomial origin"
    );

    result
}
