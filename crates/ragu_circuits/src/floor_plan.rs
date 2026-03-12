//! Floor planning for optimal routine placement in the constraint polynomial.
//!
//! Routines occupy rectangular regions in the 2D constraint space where:
//! - **X dimension**: multiplication gate indices (grows with each `mul` constraint)
//! - **Y dimension**: linear constraint indices (grows with each `enforce_zero`)
//!
//! The floor planner assigns deterministic positions to routine types so that:
//! - **Inter-circuit memoization**: Same routine type at same position across circuits
//!   allows combining Lagrange coefficients instead of separate evaluation.
//! - **Intra-circuit memoization**: Subsequent calls scale by `X^N * Y^M` offsets.
//!
//! Placement uses row-major packing: routines fill left-to-right (increasing X)
//! until `max_width` is reached, then wrap to a new row (increasing Y).
//!
//! See issues #58 and #59 for the memoization design.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::floor_planner::ConstraintSegment;
use crate::{RoutineFingerprint, RoutineIdentity, SegmentRecord};

/// A position in the constraint polynomial: multiplication gate index (X dimension)
/// and linear constraint index (Y dimension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryPosition {
    /// Multiplication gate index.
    pub x: usize,
    /// Linear constraint index.
    pub y: usize,
}

impl RegistryPosition {
    /// Creates a new registry position.
    pub const fn new(x: usize, y: usize) -> Self {
        Self { x, y }
    }
}

/// Placement for a routine type in the constraint polynomial.
#[derive(Debug, Clone, Copy)]
struct Placement {
    /// The routine's structural fingerprint.
    fingerprint: RoutineFingerprint,
    /// The segment's position and dimensions.
    segment: ConstraintSegment,
}

/// Floor plan mapping routine types to deterministic positions in the constraint polynomial.
///
/// All circuits using a routine type should place it at the same position
/// to maximize inter-circuit memoization.
#[derive(Debug, Default)]
pub struct FloorPlan {
    placements: Vec<Placement>,
    /// Next available X position (multiplication gate index).
    next_x: usize,
    /// Current row's Y position (linear constraint index).
    next_y: usize,
    /// Maximum Y extent of routines in the current row.
    row_height: usize,
    /// Maximum X extent before wrapping to a new row.
    max_width: usize,
}

impl FloorPlan {
    /// Creates a new floor plan with the given maximum X extent.
    pub fn new(max_width: usize) -> Self {
        Self {
            max_width,
            ..Default::default()
        }
    }

    /// Builds a floor plan from multiple circuits' segment records.
    ///
    /// Routines used by more circuits get priority placement (higher memoization benefit).
    /// Space is reserved for the maximum invocation count across all circuits.
    pub fn from_segment_records(all_segments: &[&[SegmentRecord]], max_width: usize) -> Self {
        let mut plan = Self::new(max_width);

        // Collect routine fingerprints with circuit count and max invocations.
        // (num_mul, num_lc, circuit_count, max_invocations)
        let mut routine_stats: BTreeMap<RoutineFingerprint, (usize, usize, usize, usize)> =
            BTreeMap::new();
        for segments in all_segments {
            // Count invocations per fingerprint within this circuit.
            let mut per_circuit: BTreeMap<RoutineFingerprint, usize> = BTreeMap::new();
            for seg in segments.iter() {
                if let RoutineIdentity::Routine(fp) = seg.identity {
                    *per_circuit.entry(fp).or_default() += 1;
                }
            }
            for (fp, invocations) in per_circuit {
                routine_stats
                    .entry(fp)
                    .and_modify(|(_, _, circuit_count, max_inv)| {
                        *circuit_count += 1;
                        *max_inv = (*max_inv).max(invocations);
                    })
                    .or_insert((
                        fp.num_multiplication_constraints(),
                        fp.num_linear_constraints(),
                        1,
                        invocations,
                    ));
            }
        }

        // Sort by memoization benefit: circuit_count * max_invocations * area.
        let mut routines: Vec<_> = routine_stats.into_iter().collect();
        routines.sort_by_key(|(_, (num_mul, num_lc, circuit_count, max_inv))| {
            core::cmp::Reverse(circuit_count * max_inv * num_mul * num_lc)
        });

        // Assign canonical positions, reserving space for max invocations.
        for (fp, (num_mul, num_lc, _, max_inv)) in routines {
            plan.place(fp, num_mul, num_lc, max_inv);
        }

        plan
    }

    /// Place a routine type at the next available position, reserving space for `count` invocations.
    fn place(
        &mut self,
        fingerprint: RoutineFingerprint,
        num_mul: usize,
        num_lc: usize,
        count: usize,
    ) {
        let reserved_width = num_mul * count;

        if self.next_x + reserved_width > self.max_width && self.next_x > 0 {
            self.next_y += self.row_height;
            self.next_x = 0;
            self.row_height = 0;
        }

        let segment = ConstraintSegment {
            multiplication_start: self.next_x,
            linear_start: self.next_y,
            num_multiplication_constraints: num_mul,
            num_linear_constraints: num_lc,
        };
        self.placements.push(Placement {
            fingerprint,
            segment,
        });

        self.next_x += reserved_width;
        self.row_height = self.row_height.max(num_lc);
    }

    /// Gets the position for a specific invocation of a routine type.
    pub fn get_invocation(
        &self,
        fingerprint: &RoutineFingerprint,
        invocation_index: usize,
    ) -> Option<RegistryPosition> {
        self.placements
            .iter()
            .find(|p| p.fingerprint == *fingerprint)
            .map(|p| {
                RegistryPosition::new(
                    p.segment.multiplication_start
                        + invocation_index * p.segment.num_multiplication_constraints,
                    p.segment.linear_start,
                )
            })
    }

    /// Gets the shape for a routine type, if it exists in the floor plan.
    pub fn get_shape(&self, fingerprint: &RoutineFingerprint) -> Option<ConstraintSegment> {
        self.placements
            .iter()
            .find(|p| p.fingerprint == *fingerprint)
            .map(|p| p.segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a segment record with a unique routine fingerprint.
    fn routine_seg(eval: u64, muls: usize, lcs: usize) -> SegmentRecord {
        SegmentRecord {
            num_multiplication_constraints: muls,
            num_linear_constraints: lcs,
            identity: RoutineIdentity::Routine(RoutineFingerprint::test(eval, muls, lcs)),
        }
    }

    /// Root segment (index 0) — ignored by the floor planner.
    fn root_seg() -> SegmentRecord {
        SegmentRecord {
            num_multiplication_constraints: 0,
            num_linear_constraints: 0,
            identity: RoutineIdentity::Root,
        }
    }

    const POSEIDON: u64 = 1;
    const MERKLE: u64 = 2;

    #[test]
    fn floor_plan_single_circuit() {
        let segments = [
            root_seg(),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(MERKLE, 5, 10),
        ];
        let plan = FloorPlan::from_segment_records(&[&segments], 100);

        let poseidon_fp = RoutineFingerprint::test(POSEIDON, 10, 20);
        let merkle_fp = RoutineFingerprint::test(MERKLE, 5, 10);

        assert!(plan.get_invocation(&poseidon_fp, 0).is_some());
        assert!(plan.get_invocation(&merkle_fp, 0).is_some());
    }

    #[test]
    fn floor_plan_frequent_routines() {
        // Poseidon in 3 circuits, Merkle in 1
        let seg_a = [root_seg(), routine_seg(POSEIDON, 10, 20)];
        let seg_b = [
            root_seg(),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(MERKLE, 5, 10),
        ];
        let seg_c = [root_seg(), routine_seg(POSEIDON, 10, 20)];

        let plan = FloorPlan::from_segment_records(&[&seg_a, &seg_b, &seg_c], 100);

        let poseidon_fp = RoutineFingerprint::test(POSEIDON, 10, 20);
        let poseidon_pos = plan.get_invocation(&poseidon_fp, 0).unwrap();
        assert_eq!(poseidon_pos, RegistryPosition::new(0, 0));
    }

    #[test]
    fn floor_plan_wraps_to_new_row() {
        let segments = [
            root_seg(),
            routine_seg(POSEIDON, 60, 20),
            routine_seg(MERKLE, 60, 10),
        ];
        let plan = FloorPlan::from_segment_records(&[&segments], 100);

        let poseidon_fp = RoutineFingerprint::test(POSEIDON, 60, 20);
        let merkle_fp = RoutineFingerprint::test(MERKLE, 60, 10);

        let poseidon_pos = plan.get_invocation(&poseidon_fp, 0).unwrap();
        let merkle_pos = plan.get_invocation(&merkle_fp, 0).unwrap();

        assert_eq!(poseidon_pos.x, 0);
        assert_eq!(merkle_pos.y, 20);
    }

    #[test]
    fn floor_plan_reserves_space_for_multiple_invocations() {
        // Circuit calls Poseidon 3 times, then Merkle once
        let segments = [
            root_seg(),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(MERKLE, 5, 10),
        ];
        let plan = FloorPlan::from_segment_records(&[&segments], 100);

        let poseidon_fp = RoutineFingerprint::test(POSEIDON, 10, 20);
        let merkle_fp = RoutineFingerprint::test(MERKLE, 5, 10);

        // Poseidon at (0,0), reserves 3×10=30 width
        assert_eq!(
            plan.get_invocation(&poseidon_fp, 0),
            Some(RegistryPosition::new(0, 0))
        );
        // Merkle starts after reserved space
        assert_eq!(
            plan.get_invocation(&merkle_fp, 0),
            Some(RegistryPosition::new(30, 0))
        );
    }

    #[test]
    fn floor_plan_get_invocation_positions() {
        let segments = [
            root_seg(),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(POSEIDON, 10, 20),
            routine_seg(POSEIDON, 10, 20),
        ];
        let plan = FloorPlan::from_segment_records(&[&segments], 100);

        let poseidon_fp = RoutineFingerprint::test(POSEIDON, 10, 20);

        assert_eq!(
            plan.get_invocation(&poseidon_fp, 0),
            Some(RegistryPosition::new(0, 0))
        );
        assert_eq!(
            plan.get_invocation(&poseidon_fp, 1),
            Some(RegistryPosition::new(10, 0))
        );
        assert_eq!(
            plan.get_invocation(&poseidon_fp, 2),
            Some(RegistryPosition::new(20, 0))
        );
    }
}
