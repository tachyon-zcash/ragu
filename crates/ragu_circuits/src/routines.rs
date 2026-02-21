//! Routine identification and registry for circuit analysis.
//!
//! This module provides infrastructure for tracking routine invocations during
//! circuit discovery, enabling memoization and floor planning optimizations.
//!
//! - [`RoutineId`]: Uniquely identifies a routine type using [`core::any::type_name`]
//! - [`RoutineShape`]: Describes resource consumption (multiplication gates, constraints)
//! - [`RoutineInfo`]: Captures invocation details including nesting level
//! - [`RoutineRegistry`]: Collects routine invocations during discovery passes

use alloc::{collections::BTreeMap, vec::Vec};

/// Uniquely identifies a routine type for memoization and floor planning.
///
/// Uses [`core::any::type_name`] internally, which works for all types including
/// those with lifetime parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutineId(&'static str);

impl RoutineId {
    /// Creates a `RoutineId` for the given routine type.
    pub fn of<R>() -> Self {
        Self(core::any::type_name::<R>())
    }
}

/// Describes the circuit resources consumed by a routine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutineShape {
    /// Number of multiplication gates consumed by this routine.
    pub num_multiplications: usize,
    /// Number of linear constraints enforced by this routine.
    pub num_constraints: usize,
}

impl RoutineShape {
    /// Creates a new routine shape.
    pub const fn new(num_multiplications: usize, num_constraints: usize) -> Self {
        Self {
            num_multiplications,
            num_constraints,
        }
    }
}

/// Information about a single routine invocation, captured during discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutineInfo {
    /// The shape (dimensions) of this routine invocation.
    pub shape: RoutineShape,
    /// The nesting level at which this routine was invoked (0 = top-level).
    pub nesting_level: usize,
}

impl RoutineInfo {
    /// Creates a new routine info with the given shape and nesting level.
    pub const fn new(shape: RoutineShape, nesting_level: usize) -> Self {
        Self {
            shape,
            nesting_level,
        }
    }
}

/// Registry for tracking routine invocations during circuit discovery.
///
/// The `RoutineRegistry` collects information about all routine invocations
/// during a discovery pass over circuits. This information is used for:
///
/// - **Structural analysis**: Identifying which circuits use the same routines
/// - **Floor planning**: Determining optimal routine placement within the registry
/// - **Memoization**: Enabling reuse of polynomial evaluations for identical routines
#[derive(Debug, Clone, Default)]
pub struct RoutineRegistry {
    entries: BTreeMap<RoutineId, Vec<RoutineInfo>>,
    current_nesting_level: usize,
}

impl RoutineRegistry {
    /// Creates a new, empty routine registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a routine invocation with the given shape.
    pub fn register<R: 'static>(&mut self, shape: RoutineShape) {
        let id = RoutineId::of::<R>();
        let info = RoutineInfo::new(shape, self.current_nesting_level);
        self.entries.entry(id).or_default().push(info);
    }

    /// Increments the nesting level when entering a routine.
    pub fn enter_routine(&mut self) {
        self.current_nesting_level += 1;
    }

    /// Decrements the nesting level when exiting a routine.
    pub fn exit_routine(&mut self) {
        self.current_nesting_level = self.current_nesting_level.saturating_sub(1);
    }

    /// Returns an iterator over registered routine types and their invocations.
    pub fn iter(&self) -> impl Iterator<Item = (&RoutineId, &[RoutineInfo])> {
        self.entries.iter().map(|(k, v)| (k, v.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RoutineA;
    struct RoutineB;
    struct Generic<const N: usize>;

    #[test]
    fn routine_id_same_type_equal() {
        assert_eq!(RoutineId::of::<RoutineA>(), RoutineId::of::<RoutineA>());
    }

    #[test]
    fn routine_id_different_types_not_equal() {
        assert_ne!(RoutineId::of::<RoutineA>(), RoutineId::of::<RoutineB>());
    }

    #[test]
    fn routine_id_generic_params_differ() {
        assert_ne!(
            RoutineId::of::<Generic<10>>(),
            RoutineId::of::<Generic<13>>()
        );
        assert_eq!(
            RoutineId::of::<Generic<10>>(),
            RoutineId::of::<Generic<10>>()
        );
    }

    #[test]
    fn routine_shape_new() {
        let shape = RoutineShape::new(10, 20);
        assert_eq!(shape.num_multiplications, 10);
        assert_eq!(shape.num_constraints, 20);
    }

    #[test]
    fn routine_registry_tracks_nesting() {
        let mut registry = RoutineRegistry::new();
        let shape = RoutineShape::new(5, 10);

        registry.register::<RoutineA>(shape);
        registry.enter_routine();
        registry.register::<RoutineB>(shape);
        registry.exit_routine();

        assert_eq!(registry.entries.len(), 2);
        assert_eq!(
            registry.entries[&RoutineId::of::<RoutineA>()][0].nesting_level,
            0
        );
        assert_eq!(
            registry.entries[&RoutineId::of::<RoutineB>()][0].nesting_level,
            1
        );
    }
}
