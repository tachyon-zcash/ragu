//! Functions that take [gadgets](crate::gadgets) as input and produce gadgets
//! as output.
//!
//! Routines are intended for portions of the circuit that are either invoked
//! multiple times (and so drivers can memoize their synthesis) or have
//! efficiently predictable outputs (and so drivers can parallelize their
//! synthesis).
//!
//! Routines are reusable circuit components identified by [`RoutineId`], which wraps
//! [`TypeId`]. Different type parameters yield different identities (e.g., `Evaluate<R<10>>`
//! and `Evaluate<R<13>>` are distinct routines).
//!
//! Routines must be **fungible by type**: all instances of a concrete routine type produce
//! identical constraints. Encode constraint-affecting parameters as type parameters, not
//! runtime fields.
//!
//! [`RoutineShape`] describes resource consumption (multiplication gates, linear constraints)
//! for floor planning. [`RoutineRegistry`] tracks invocations during circuit discovery,
//! mapping each [`RoutineId`] to its [`RoutineInfo`] entries for structural analysis.
//!
//! ## Design Decisions
//!
//! - **Type-based identity**: [`RoutineId`] uses [`TypeId`] because routines are fungible
//!   by type. [`TypeId`] is known before synthesis, whereas a constraint hash would require
//!   synthesizing first.
//!
//! - **G/H polynomial split**: Routines have internal (G) and external (H) polynomial
//!   parts. G depends on routine structure and is cacheable, whereas H depends on witness
//!   values and varies per proof.
//!
//! - **Discovery vs. synthesis**: [`RoutineRegistry`] captures structural information
//!   during discovery (via [`Emulator::counter`](crate::drivers::emulator::Emulator::counter)).
//!   Memoization eligibility (input patterns) is determined at synthesis time.

use core::any::TypeId;

use alloc::{collections::BTreeMap, vec::Vec};
use ff::Field;

use crate::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};

/// Uniquely identifies a routine type for memoization and floor planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutineId(TypeId);

impl RoutineId {
    /// Creates a `RoutineId` for the given routine type.
    pub fn of<R: 'static>() -> Self {
        Self(TypeId::of::<R>())
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
/// - **Floor planning**: Determining optimal routine placement within the mesh
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
}

/// Sections of a circuit that take a [`Gadget`](crate::gadgets::Gadget) as
/// input and produce a [`Gadget`](crate::gadgets::Gadget) as output.
///
/// Routines provide a [`predict`](Routine::predict) method so that drivers can
/// optionally ask the routine implementor to predict the output gadget value by
/// returning a [`Prediction`]. If the gadget output cannot be efficiently
/// predicted then at least any auxiliary data that may be useful for execution
/// can be returned.
///
/// The actual synthesis of a routine is performed in the
/// [`execute`](Routine::execute) method. Drivers can leverage predictions to
/// execute routines in parallel (for witness generation) or skip execution if
/// synthesis is memoized.
pub trait Routine<F: Field>: Clone + Send {
    /// The kind of a gadget that this routine expects as input
    type Input: GadgetKind<F>;

    /// The kind of a gadget that this routine expects as output
    type Output: GadgetKind<F>;

    /// The auxiliary data that may be provided by the
    /// [`predict`](Routine::predict) method to be used during actual execution,
    /// to avoid redundant computations.
    type Aux<'dr>: Send + Clone;

    /// Returns the shape of this routine in terms of circuit resources.
    fn shape(&self) -> RoutineShape;

    /// Execute the routine with a driver given the designated input, returning
    /// the designated output.
    fn execute<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: <Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
        aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>;

    /// Routines can offer to predict their outputs given their inputs, which
    /// drivers can leverage to skip actual execution or perform it in a
    /// background thread. In any event, the prediction process produces some
    /// routine-specific auxiliary data that can be leveraged during actual
    /// execution to avoid duplicated effort.
    fn predict<'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        input: &<Self::Input as GadgetKind<F>>::Rebind<'dr, D>,
    ) -> Result<
        Prediction<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>, DriverValue<D, Self::Aux<'dr>>>,
    >;
}

/// Describes the result of a routine's [`predict`](Routine::predict) method.
///
/// `Known(T, A)` represents a known prediction of output `T` and `Unknown(A)`
/// represents an unpredictable result, in either case `A` represents auxiliary
/// data that may be useful for execution.
pub enum Prediction<T, A> {
    /// The routine has provided the resulting `T` value and some auxiliary
    /// information that may be useful for actual execution.
    Known(T, A),

    /// The routine cannot (efficiently) predict the result of execution, and
    /// the driver should simply execute it to obtain the result.
    Unknown(A),
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
