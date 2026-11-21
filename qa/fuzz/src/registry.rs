//! Registry construction shared by the targets that register circuits.
//!
//! A generated program can be too large for the rank, which is a skip.
//! Any other failure to register or finalize is a finding: in particular,
//! `RegistryBuilder::finalize` returns `Error::Initialization` when a
//! circuit's hashed monomials and its evaluations disagree, and a target
//! that skipped every error would discard exactly that.

use ragu_circuits::{polynomials::Rank, registry::Registry};
use ragu_core::{Error, Result};
use udon::field::Field;

/// The value of a registration or finalization, or `None` when the circuits
/// exceed a capacity of the rank.
///
/// # Panics
///
/// Panics on any error other than a capacity error.
pub fn fits<T>(result: Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(
            Error::GateBoundExceeded { .. }
            | Error::ConstraintBoundExceeded { .. }
            | Error::CircuitBoundExceeded { .. }
            | Error::DegreeBoundExceeded { .. },
        ) => None,
        Err(error) => panic!("registry construction failed other than by capacity: {error}"),
    }
}

/// Asserts that each circuit's hashed polynomial is the one an independent
/// walk of the circuit writes down.
///
/// The registry hashes, and every evaluation runs, the wiring one walk of
/// each circuit recorded. The walk this compares it with, by the
/// `wiring::monomials` driver, shares no code with the recording.
///
/// # Panics
///
/// Panics if any registered circuit's recording differs from its walk.
pub fn assert_recorded_as_walked<F: Field, R: Rank>(registry: &Registry<'_, F, R>) {
    let mismatches = registry.walk_mismatches();
    assert!(
        mismatches.is_empty(),
        "circuits {mismatches:?}: the wiring the registry recorded, hashed and evaluates \
         differs from an independent walk of the circuit at rank {}",
        R::RANK
    );
}
