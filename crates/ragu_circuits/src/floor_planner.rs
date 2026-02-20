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
//! The root routine (index 0) is always pinned at offset 0.

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
#[derive(Clone)]
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
