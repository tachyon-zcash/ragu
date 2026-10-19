//! Segment placement within the polynomial layout.
//!
//! Converts per-segment constraint records (from the `metrics` module) into
//! absolute offsets that the `s(X, Y)` evaluators use to position each
//! segment's constraints within the polynomial.
//!
//! # DFS-order indexing convention
//!
//! The floor plan is indexed by DFS emission order: `floor_plan[i]` describes
//! where the *i*-th segment (in DFS order) is placed in the polynomial. A
//! reordering floor planner changes the **values** (offsets), not the
//! **indices**. All consumers — the three `s(X, Y)` evaluators, the `rx`
//! evaluator, and `assemble` — depend on this convention.
//!
//! The root segment (index 0) is always pinned at offset 0; see the
//! [`floor_plan`] function for details.
//!
//! ```text
//!  Emission trace               Seg
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
//!
//! # Two planners
//!
//! [`floor_plan`] places one circuit's segments by prefix sum in DFS order:
//! compact, and the fallback when alignment does not fit.
//!
//! [`plan_registry`] places every circuit of a registry together. A routine
//! invoked at circuit scope in several circuits is given one **aligned slot**
//! — the same gate and constraint offsets in every circuit — so that its
//! contribution to each wiring polynomial is literally the same polynomial
//! piece, which lets the registry share it across circuits. Gates and
//! constraints are two independent one-dimensional resources, so a slot is a
//! gate interval plus a constraint interval, and alignment pads each
//! circuit's layout with unused indices in both. Padded regions never appear
//! in the sparse polynomials, but they do consume the circuit's capacity,
//! which is why alignment is skipped whenever it would not fit.

use alloc::{collections::BTreeMap, vec::Vec};

use super::metrics::{DeepFingerprint, RoutineIdentity, SegmentRecord};

/// A segment's placement in a constraint system.
///
/// Each segment in a circuit occupies a contiguous range of gates and
/// constraints. The primary segment boundaries are [`Routine`]
/// calls; index 0 is the root segment (not backed by any [`Routine`]).
/// The floor plan assigns absolute positions (offsets) and sizes to each
/// segment in DFS order.
///
/// The floor plan is indexed by DFS emission order: `floor_plan[i]`
/// corresponds to the *i*-th segment encountered during constraint emission. A
/// reordering floor planner may assign different offset values but must
/// preserve index correspondence. The root segment (index 0) must always be
/// placed at the polynomial origin (both offsets zero).
///
/// [`Routine`]: ragu_core::routines::Routine
#[derive(Debug, Clone, Copy)]
pub struct ConstraintSegment {
    /// Gate index where this segment's gates begin.
    pub(crate) gate_start: usize,
    /// Y-power index where this segment's constraints begin.
    pub(crate) constraint_start: usize,
    /// Number of gates in this segment.
    pub(crate) num_gates: usize,
    /// Number of constraints in this segment.
    pub(crate) num_constraints: usize,
}

/// Computes a floor plan from per-segment constraint records.
///
/// Converts per-segment constraint counts into absolute offsets via prefix
/// sum, preserving emission (DFS) order.
pub fn floor_plan(segment_records: &[SegmentRecord]) -> Vec<ConstraintSegment> {
    let mut result = Vec::with_capacity(segment_records.len());
    let mut gate_start = 0usize;
    let mut constraint_start = 0usize;
    for record in segment_records {
        result.push(ConstraintSegment {
            gate_start,
            constraint_start,
            num_gates: record.num_gates(),
            num_constraints: record.num_constraints(),
        });
        gate_start += record.num_gates();
        constraint_start += record.num_constraints();
    }

    assert!(
        result
            .first()
            .is_none_or(|r| r.gate_start == 0 && r.constraint_start == 0),
        "root segment must be placed at the polynomial origin"
    );

    result
}

/// A routine invoked at circuit scope, together with its nested
/// sub-routines: the DFS range `start..start + len` of the segment records.
struct Block {
    start: usize,
    len: usize,
    gates: usize,
    constraints: usize,
    fingerprint: DeepFingerprint,
}

/// Splits a circuit's records into its top-level routine blocks.
fn blocks(records: &[SegmentRecord]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut start = 1;
    while start < records.len() {
        debug_assert_eq!(records[start].depth(), 1, "blocks begin at depth 1");
        let fingerprint = match records[start].identity() {
            RoutineIdentity::Routine(fp) => *fp,
            RoutineIdentity::Root => unreachable!("only segment 0 is the root"),
        };
        let mut end = start + 1;
        while end < records.len() && records[end].depth() > 1 {
            end += 1;
        }
        let members = &records[start..end];
        blocks.push(Block {
            start,
            len: end - start,
            gates: members.iter().map(SegmentRecord::num_gates).sum(),
            constraints: members.iter().map(SegmentRecord::num_constraints).sum(),
            fingerprint,
        });
        start = end;
    }
    blocks
}

/// An aligned slot: offsets of the first invocation and the block size, so
/// the `k`-th invocation in a circuit sits `k` block sizes further along.
#[derive(Clone, Copy)]
struct Slot {
    gate_start: usize,
    constraint_start: usize,
    gates: usize,
    constraints: usize,
}

/// Plans every circuit of a registry, aligning routines that recur across
/// circuits.
///
/// `max_gates` and `max_constraints` bound the layout of each circuit (the
/// rank's gate count and its constraint slots minus the one reserved for the
/// registry tag). Each circuit's layout is:
///
/// 1. the root segment at the origin;
/// 2. aligned slots, reserved once for the whole registry after the largest
///    root segment, in decreasing order of benefit (`circuits × gates`) and
///    sized for the most invocations any one circuit makes;
/// 3. the circuit's remaining routines, packed after its root and after the
///    aligned slots it uses.
///
/// A circuit whose aligned layout would exceed the bounds falls back to
/// [`floor_plan`] on its own; the other circuits keep their slots. Within a
/// block, nested segments follow the block's origin by prefix sum, so a
/// subtree keeps the same relative layout wherever its block is placed.
pub fn plan_registry(
    circuits: &[&[SegmentRecord]],
    max_gates: usize,
    max_constraints: usize,
) -> Vec<Vec<ConstraintSegment>> {
    let circuit_blocks: Vec<Vec<Block>> = circuits.iter().map(|r| blocks(r)).collect();

    // (circuits using it, most invocations in one circuit, gates, constraints)
    let mut stats: BTreeMap<DeepFingerprint, (usize, usize, usize, usize)> = BTreeMap::new();
    for blocks in &circuit_blocks {
        let mut invocations: BTreeMap<DeepFingerprint, usize> = BTreeMap::new();
        for block in blocks {
            *invocations.entry(block.fingerprint).or_default() += 1;
        }
        for block in blocks {
            let entry =
                stats
                    .entry(block.fingerprint)
                    .or_insert((0, 0, block.gates, block.constraints));
            entry.1 = entry.1.max(invocations[&block.fingerprint]);
        }
        for fingerprint in invocations.keys() {
            stats.get_mut(fingerprint).expect("inserted above").0 += 1;
        }
    }

    let mut candidates: Vec<_> = stats
        .into_iter()
        .filter(|(_, (circuits, _, _, _))| *circuits >= 2)
        .collect();
    candidates.sort_by_key(|(fingerprint, (circuits, _, gates, _))| {
        (core::cmp::Reverse(circuits * gates), *fingerprint)
    });

    let root_gates = circuits
        .iter()
        .filter_map(|r| r.first().map(SegmentRecord::num_gates))
        .max()
        .unwrap_or(0);
    let root_constraints = circuits
        .iter()
        .filter_map(|r| r.first().map(SegmentRecord::num_constraints))
        .max()
        .unwrap_or(0);

    let mut slots: BTreeMap<DeepFingerprint, Slot> = BTreeMap::new();
    let (mut next_gate, mut next_constraint) = (root_gates, root_constraints);
    for (fingerprint, (_, invocations, gates, constraints)) in candidates {
        let span_gates = gates * invocations;
        let span_constraints = constraints * invocations;
        if next_gate + span_gates > max_gates
            || next_constraint + span_constraints > max_constraints
        {
            continue;
        }
        slots.insert(
            fingerprint,
            Slot {
                gate_start: next_gate,
                constraint_start: next_constraint,
                gates,
                constraints,
            },
        );
        next_gate += span_gates;
        next_constraint += span_constraints;
    }

    circuits
        .iter()
        .zip(&circuit_blocks)
        .map(|(records, blocks)| place(records, blocks, &slots, max_gates, max_constraints))
        .collect()
}

/// Places one circuit against the registry's aligned slots.
fn place(
    records: &[SegmentRecord],
    blocks: &[Block],
    slots: &BTreeMap<DeepFingerprint, Slot>,
    max_gates: usize,
    max_constraints: usize,
) -> Vec<ConstraintSegment> {
    let Some(root) = records.first() else {
        return Vec::new();
    };

    // Aligned blocks take their slots; everything else is packed after the
    // root and after the aligned blocks this circuit uses.
    let mut origins: Vec<Option<(usize, usize)>> = Vec::with_capacity(blocks.len());
    let mut invocations: BTreeMap<DeepFingerprint, usize> = BTreeMap::new();
    let mut cursor = (root.num_gates(), root.num_constraints());
    for block in blocks {
        let Some(slot) = slots.get(&block.fingerprint) else {
            origins.push(None);
            continue;
        };
        let k = invocations.entry(block.fingerprint).or_default();
        let origin = (
            slot.gate_start + *k * slot.gates,
            slot.constraint_start + *k * slot.constraints,
        );
        *k += 1;
        origins.push(Some(origin));
        cursor.0 = cursor.0.max(origin.0 + block.gates);
        cursor.1 = cursor.1.max(origin.1 + block.constraints);
    }
    for (block, origin) in blocks.iter().zip(&mut origins) {
        if origin.is_none() {
            *origin = Some(cursor);
            cursor.0 += block.gates;
            cursor.1 += block.constraints;
        }
    }

    if cursor.0 > max_gates || cursor.1 > max_constraints {
        return floor_plan(records);
    }

    let mut plan = Vec::with_capacity(records.len());
    plan.push(ConstraintSegment {
        gate_start: 0,
        constraint_start: 0,
        num_gates: root.num_gates(),
        num_constraints: root.num_constraints(),
    });
    for (block, origin) in blocks.iter().zip(origins) {
        let (mut gate_start, mut constraint_start) = origin.expect("every block was placed");
        for record in &records[block.start..block.start + block.len] {
            plan.push(ConstraintSegment {
                gate_start,
                constraint_start,
                num_gates: record.num_gates(),
                num_constraints: record.num_constraints(),
            });
            gate_start += record.num_gates();
            constraint_start += record.num_constraints();
        }
    }
    debug_assert_eq!(plan.len(), records.len());
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(gates: usize, constraints: usize) -> SegmentRecord {
        SegmentRecord::test(gates, constraints, RoutineIdentity::Root, 0)
    }

    fn routine(id: u64, gates: usize, constraints: usize, depth: usize) -> SegmentRecord {
        let fp = DeepFingerprint::test(id, gates, constraints);
        SegmentRecord::test(gates, constraints, RoutineIdentity::Routine(fp), depth)
    }

    /// Every pair of segments in a plan occupies disjoint gate ranges and
    /// disjoint constraint ranges, and the root is at the origin.
    fn assert_well_formed(plan: &[ConstraintSegment], max_gates: usize, max_constraints: usize) {
        assert_eq!((plan[0].gate_start, plan[0].constraint_start), (0, 0));
        for (i, a) in plan.iter().enumerate() {
            assert!(a.gate_start + a.num_gates <= max_gates);
            assert!(a.constraint_start + a.num_constraints <= max_constraints);
            for b in &plan[i + 1..] {
                let gates_disjoint = a.gate_start + a.num_gates <= b.gate_start
                    || b.gate_start + b.num_gates <= a.gate_start
                    || a.num_gates == 0
                    || b.num_gates == 0;
                let constraints_disjoint = a.constraint_start + a.num_constraints
                    <= b.constraint_start
                    || b.constraint_start + b.num_constraints <= a.constraint_start
                    || a.num_constraints == 0
                    || b.num_constraints == 0;
                assert!(gates_disjoint && constraints_disjoint, "segments overlap");
            }
        }
    }

    #[test]
    fn single_circuit_is_prefix_sum() {
        let records = [root(3, 2), routine(1, 4, 5, 1), routine(1, 4, 5, 1)];
        let plans = plan_registry(&[&records], 100, 100);
        let expected = floor_plan(&records);
        for (a, b) in plans[0].iter().zip(&expected) {
            assert_eq!(
                (a.gate_start, a.constraint_start),
                (b.gate_start, b.constraint_start)
            );
        }
    }

    #[test]
    fn shared_routine_is_aligned_across_circuits() {
        // Circuit A calls routine 1 right after a small root; circuit B calls
        // routine 2 first and then routine 1 after a larger root.
        let a = [root(2, 2), routine(1, 4, 6, 1)];
        let b = [root(5, 3), routine(2, 3, 3, 1), routine(1, 4, 6, 1)];
        let plans = plan_registry(&[&a, &b], 100, 100);

        assert_eq!(plans[0][1].gate_start, plans[1][2].gate_start);
        assert_eq!(plans[0][1].constraint_start, plans[1][2].constraint_start);
        // The slot sits after the largest root.
        assert_eq!(plans[0][1].gate_start, 5);
        assert_eq!(plans[0][1].constraint_start, 3);
        for plan in &plans {
            assert_well_formed(plan, 100, 100);
        }
    }

    #[test]
    fn repeated_invocations_get_consecutive_slots() {
        let a = [root(1, 2), routine(1, 4, 6, 1), routine(1, 4, 6, 1)];
        let b = [root(1, 2), routine(1, 4, 6, 1)];
        let plans = plan_registry(&[&a, &b], 100, 100);
        assert_eq!(plans[0][1].gate_start, plans[1][1].gate_start);
        assert_eq!(plans[0][2].gate_start, plans[0][1].gate_start + 4);
        assert_eq!(
            plans[0][2].constraint_start,
            plans[0][1].constraint_start + 6
        );
        for plan in &plans {
            assert_well_formed(plan, 100, 100);
        }
    }

    #[test]
    fn nested_block_keeps_relative_layout() {
        // Routine 1 nests routine 3; routine 2 is unaligned filler.
        let a = [
            root(1, 2),
            routine(2, 1, 1, 1),
            routine(1, 2, 2, 1),
            routine(3, 3, 3, 2),
        ];
        let b = [root(1, 2), routine(1, 2, 2, 1), routine(3, 3, 3, 2)];
        let plans = plan_registry(&[&a, &b], 100, 100);

        let (pa, pb) = (&plans[0], &plans[1]);
        assert_eq!(pa[2].gate_start, pb[1].gate_start);
        assert_eq!(pa[3].gate_start, pa[2].gate_start + 2);
        assert_eq!(pa[3].constraint_start, pa[2].constraint_start + 2);
        assert_eq!(pb[2].gate_start, pb[1].gate_start + 2);
        // The unaligned routine 2 is packed after the aligned block.
        assert_eq!(pa[1].gate_start, pa[3].gate_start + 3);
        for plan in &plans {
            assert_well_formed(plan, 100, 100);
        }
    }

    #[test]
    fn falls_back_to_prefix_sum_when_alignment_does_not_fit() {
        let a = [root(2, 2), routine(1, 4, 6, 1)];
        let b = [root(5, 3), routine(2, 3, 3, 1), routine(1, 4, 6, 1)];
        // Circuit B needs 12 gates for root + both routines; with alignment
        // it would need 5 + 4 (slot) + 3 (tail) = 12 too, so bound it at 11
        // for gates: the slot is reserved (5 + 4 <= 11) but B overflows.
        let plans = plan_registry(&[&a, &b], 11, 100);
        let expected = floor_plan(&b);
        for (x, y) in plans[1].iter().zip(&expected) {
            assert_eq!(
                (x.gate_start, x.constraint_start),
                (y.gate_start, y.constraint_start)
            );
        }
        // A still uses the slot.
        assert_eq!(plans[0][1].gate_start, 5);
        assert_well_formed(&plans[0], 11, 100);
    }

    #[test]
    fn empty_records_plan_to_nothing() {
        let a: [SegmentRecord; 0] = [];
        let b = [root(1, 1)];
        let plans = plan_registry(&[&a, &b], 10, 10);
        assert!(plans[0].is_empty());
        assert_eq!(plans[1].len(), 1);
    }
}
