//! Floor planning for optimal routine placement in the circuit registry.
//!
//! The floor planner assigns canonical positions to routine types so that:
//! - **Inter-circuit memoization**: Same routine type at same position across circuits
//!   allows combining Lagrange coefficients instead of separate evaluation.
//! - **Intra-circuit memoization**: Subsequent calls scale by `X^N * Y^M` offsets.
//!
//! See issues #58 and #59 for the memoization design.

use alloc::{collections::BTreeMap, vec::Vec};

use crate::routines::{RoutineId, RoutineRegistry, RoutineShape};

/// A position in the circuit registry: multiplication gate index (X dimension) and
/// constraint index (Y dimension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryPosition {
    /// Multiplication gate index.
    pub x: usize,
    /// Constraint index.
    pub y: usize,
}

impl RegistryPosition {
    /// Creates a new registry position.
    pub const fn new(x: usize, y: usize) -> Self {
        Self { x, y }
    }
}

/// Canonical placement for a routine type.
#[derive(Debug, Clone, Copy)]
struct Placement {
    /// The routine type.
    id: RoutineId,
    /// The routine's shape (dimensions).
    shape: RoutineShape,
    /// Assigned position in the registry.
    position: RegistryPosition,
}

/// Floor plan mapping routine types to canonical registry positions.
///
/// All circuits using a routine type should place it at the canonical position
/// to maximize inter-circuit memoization.
#[derive(Debug, Default)]
pub struct FloorPlan {
    placements: Vec<Placement>,
    next_x: usize,
    next_y: usize,
    row_height: usize,
    max_width: usize,
}

impl FloorPlan {
    /// Creates a new floor plan with the given registry width constraint.
    pub fn new(max_width: usize) -> Self {
        Self {
            max_width,
            ..Default::default()
        }
    }

    /// Builds a floor plan from multiple circuit registries.
    ///
    /// Routines used by more circuits get priority placement (higher memoization benefit).
    /// Space is reserved for the maximum invocation count across all circuits.
    pub fn from_registries(registries: &[&RoutineRegistry], max_width: usize) -> Self {
        let mut plan = Self::new(max_width);

        // Collect routine types with circuit count and max invocations.
        // (shape, circuit_count, max_invocations)
        let mut routine_stats: BTreeMap<RoutineId, (RoutineShape, usize, usize)> = BTreeMap::new();
        for registry in registries {
            for (id, infos) in registry.iter() {
                if let Some(first) = infos.first() {
                    let invocations = infos.len();
                    routine_stats
                        .entry(*id)
                        .and_modify(|(_, circuit_count, max_inv)| {
                            *circuit_count += 1;
                            *max_inv = (*max_inv).max(invocations);
                        })
                        .or_insert((first.shape, 1, invocations));
                }
            }
        }

        // Sort by memoization benefit: circuit_count * max_invocations * area.
        let mut routines: Vec<_> = routine_stats.into_iter().collect();
        routines.sort_by_key(|(_, (shape, circuit_count, max_inv))| {
            core::cmp::Reverse(
                circuit_count * max_inv * shape.num_multiplications * shape.num_constraints,
            )
        });

        // Assign canonical positions, reserving space for max invocations.
        for (id, (shape, _, max_inv)) in routines {
            plan.place(id, shape, max_inv);
        }

        plan
    }

    /// Place a routine type at the next available position, reserving space for `count` invocations.
    fn place(&mut self, id: RoutineId, shape: RoutineShape, count: usize) {
        let reserved_width = shape.num_multiplications * count;

        if self.next_x + reserved_width > self.max_width && self.next_x > 0 {
            self.next_y += self.row_height;
            self.next_x = 0;
            self.row_height = 0;
        }

        let position = RegistryPosition::new(self.next_x, self.next_y);
        self.placements.push(Placement {
            id,
            shape,
            position,
        });

        self.next_x += reserved_width;
        self.row_height = self.row_height.max(shape.num_constraints);
    }

    /// Gets the position for a specific invocation of a routine type.
    pub fn get_invocation(
        &self,
        id: &RoutineId,
        invocation_index: usize,
    ) -> Option<RegistryPosition> {
        self.placements.iter().find(|p| p.id == *id).map(|p| {
            RegistryPosition::new(
                p.position.x + invocation_index * p.shape.num_multiplications,
                p.position.y,
            )
        })
    }

    /// Gets the shape for a routine type, if it exists in the floor plan.
    pub fn get_shape(&self, id: &RoutineId) -> Option<RoutineShape> {
        self.placements
            .iter()
            .find(|p| p.id == *id)
            .map(|p| p.shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Poseidon;
    struct Merkle;

    #[test]
    fn floor_plan_single_registry() {
        let mut registry = RoutineRegistry::new();
        registry.register::<Poseidon>(RoutineShape::new(10, 20));
        registry.register::<Merkle>(RoutineShape::new(5, 10));

        let plan = FloorPlan::from_registries(&[&registry], 100);

        assert!(
            plan.get_invocation(&RoutineId::of::<Poseidon>(), 0)
                .is_some()
        );
        assert!(plan.get_invocation(&RoutineId::of::<Merkle>(), 0).is_some());
    }

    #[test]
    fn floor_plan_frequent_routines() {
        let mut reg_a = RoutineRegistry::new();
        reg_a.register::<Poseidon>(RoutineShape::new(10, 20));

        let mut reg_b: RoutineRegistry = RoutineRegistry::new();
        reg_b.register::<Poseidon>(RoutineShape::new(10, 20));
        reg_b.register::<Merkle>(RoutineShape::new(5, 10));

        let mut reg_c = RoutineRegistry::new();
        reg_c.register::<Poseidon>(RoutineShape::new(10, 20));

        let plan = FloorPlan::from_registries(&[&reg_a, &reg_b, &reg_c], 100);

        let poseidon_pos = plan
            .get_invocation(&RoutineId::of::<Poseidon>(), 0)
            .unwrap();
        assert_eq!(poseidon_pos, RegistryPosition::new(0, 0));
    }

    #[test]
    fn floor_plan_wraps_to_new_row() {
        let mut registry = RoutineRegistry::new();
        registry.register::<Poseidon>(RoutineShape::new(60, 20));
        registry.register::<Merkle>(RoutineShape::new(60, 10));

        let plan = FloorPlan::from_registries(&[&registry], 100);

        let poseidon_pos = plan
            .get_invocation(&RoutineId::of::<Poseidon>(), 0)
            .unwrap();
        let merkle_pos = plan.get_invocation(&RoutineId::of::<Merkle>(), 0).unwrap();

        assert_eq!(poseidon_pos.x, 0);
        assert_eq!(merkle_pos.y, 20);
    }

    #[test]
    fn floor_plan_reserves_space_for_multiple_invocations() {
        // Circuit calls Poseidon 3 times, then Merkle once
        let mut registry = RoutineRegistry::new();
        let poseidon_shape = RoutineShape::new(10, 20);
        registry.register::<Poseidon>(poseidon_shape);
        registry.register::<Poseidon>(poseidon_shape);
        registry.register::<Poseidon>(poseidon_shape);
        registry.register::<Merkle>(RoutineShape::new(5, 10));

        let plan = FloorPlan::from_registries(&[&registry], 100);

        let poseidon_pos = plan
            .get_invocation(&RoutineId::of::<Poseidon>(), 0)
            .unwrap();
        let merkle_pos = plan.get_invocation(&RoutineId::of::<Merkle>(), 0).unwrap();

        // Poseidon at (0,0), reserves 3×10=30 width
        assert_eq!(poseidon_pos, RegistryPosition::new(0, 0));
        // Merkle starts after reserved space
        assert_eq!(merkle_pos, RegistryPosition::new(30, 0));
    }

    #[test]
    fn floor_plan_get_invocation_positions() {
        let mut registry = RoutineRegistry::new();
        let poseidon_shape = RoutineShape::new(10, 20);
        registry.register::<Poseidon>(poseidon_shape);
        registry.register::<Poseidon>(poseidon_shape);
        registry.register::<Poseidon>(poseidon_shape);

        let plan = FloorPlan::from_registries(&[&registry], 100);
        let poseidon_id = RoutineId::of::<Poseidon>();

        assert_eq!(
            plan.get_invocation(&poseidon_id, 0),
            Some(RegistryPosition::new(0, 0))
        );
        assert_eq!(
            plan.get_invocation(&poseidon_id, 1),
            Some(RegistryPosition::new(10, 0))
        );
        assert_eq!(
            plan.get_invocation(&poseidon_id, 2),
            Some(RegistryPosition::new(20, 0))
        );
    }
}
