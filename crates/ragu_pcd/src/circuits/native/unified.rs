//! Unified instance/output interface for internal verification circuits.
//!
//! Internal circuits share a common set of public inputs defined by [`Output`].
//! This avoids redundant evaluations of the public input polynomial $k(Y)$,
//! which encodes the circuit's public inputs, and simplifies circuit
//! reconfiguration.
//!
//! ## Substitution Attack Prevention
//!
//! Internal circuit outputs are wrapped in [`WithSuffix`] with a zero element.
//! This ensures the linear term of $k(Y)$ is zero, distinguishing internal
//! circuits from application circuits (which never have a zero linear term).
//! This prevents substitution attacks where an application might try to use
//! an internal circuit proof in place of an application circuit proof. Since
//! internal circuits are fixed by the protocol while application circuits
//! vary, this distinction is critical for soundness.
//!
//! [`hashes_1`]: super::hashes_1
//! [`hashes_2`]: super::hashes_2

use arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Consistent, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, io::Write};

use crate::{components::suffix::WithSuffix, proof::Proof};

/// The gadget kind for internal circuit outputs.
///
/// Internal circuits output [`Output`] wrapped in [`WithSuffix`] to ensure
/// the linear term of $k(Y)$ is zero.
#[allow(type_alias_bounds)]
pub type InternalOutputKind<C: Cycle> = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C>>];

/// The number of wires in an [`Output`] gadget.
///
/// Used for allocation sizing and verified by tests.
pub const NUM_WIRES: usize = 29;

// Generate three related types from the unified instance specification:
//
// - `Output<'dr, D, C>`: Circuit gadget implementing `Gadget`, `Write`, and
//   `Consistent`. Contains Point and Element gadgets for each field. Used as
//   the public input representation in internal verification circuits.
//
// - `Instance<C>`: Native value representation containing raw curve points and
//   field elements. Used for witness data and native computation.
//
// - `OutputBuilder<'a, 'dr, D, C>`: Lazy builder with slot-based allocation.
//   Each field is a `Slot` that can either pre-compute values (via `set`) or
//   allocate on-demand (via `get`). This avoids redundant wire allocations when
//   the same value is computed by multiple code paths. The builder provides
//   `new()`, `finish_no_suffix()`, and `finish()` methods.
//
// Fields are annotated with `#[point]` for curve points or `#[element]` for
// field elements. Documentation and field order are preserved in all generated
// types.
ragu_macros::unified_instance! {
    /// Commitment from the preamble proof component.
    #[point]
    pub nested_preamble_commitment: C::NestedCurve,

    /// Fiat-Shamir challenge $w$.
    #[element]
    pub w: C::CircuitField,

    /// Commitment from the s_prime proof component.
    #[point]
    pub nested_s_prime_commitment: C::NestedCurve,

    /// Fiat-Shamir challenge $y$.
    #[element]
    pub y: C::CircuitField,

    /// Fiat-Shamir challenge $z$.
    #[element]
    pub z: C::CircuitField,

    /// Commitment from the error_m proof component.
    #[point]
    pub nested_error_m_commitment: C::NestedCurve,

    /// First folding layer challenge $\mu$.
    #[element]
    pub mu: C::CircuitField,

    /// First folding layer challenge $\nu$.
    #[element]
    pub nu: C::CircuitField,

    /// Commitment from the error_n proof component.
    #[point]
    pub nested_error_n_commitment: C::NestedCurve,

    /// Second folding layer challenge $\mu'$.
    #[element]
    pub mu_prime: C::CircuitField,

    /// Second folding layer challenge $\nu'$.
    #[element]
    pub nu_prime: C::CircuitField,

    /// Final revdot claim value from the ab proof component.
    #[element]
    pub c: C::CircuitField,

    /// Commitment from the ab proof component.
    #[point]
    pub nested_ab_commitment: C::NestedCurve,

    /// Polynomial commitment challenge $x$.
    #[element]
    pub x: C::CircuitField,

    /// Commitment from the query proof component.
    #[point]
    pub nested_query_commitment: C::NestedCurve,

    /// Query polynomial challenge $\alpha$.
    #[element]
    pub alpha: C::CircuitField,

    /// Commitment from the f proof component.
    #[point]
    pub nested_f_commitment: C::NestedCurve,

    /// Final polynomial challenge $u$.
    #[element]
    pub u: C::CircuitField,

    /// Commitment from the eval proof component.
    #[point]
    pub nested_eval_commitment: C::NestedCurve,

    /// Pre-endoscalar beta challenge. Effective beta is derived in compute_v.
    #[element]
    pub pre_beta: C::CircuitField,

    /// Expected evaluation at the challenge point for consistency verification.
    #[element]
    pub v: C::CircuitField,
}

/// A lazy-allocation slot for a single field in the unified output.
///
/// Slots enable circuits to either pre-compute values (via [`set`](Self::set))
/// or allocate on-demand (via [`get`](Self::get)). This avoids redundant wire
/// allocations when the same value is computed by multiple code paths.
///
/// Each slot stores an allocation function that knows how to extract and
/// allocate its field from an [`Instance`].
pub struct Slot<'a, 'dr, D: Driver<'dr>, T, C: Cycle> {
    value: Option<T>,
    alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> Result<T>,
    _marker: core::marker::PhantomData<&'dr ()>,
}

impl<'a, 'dr, D: Driver<'dr>, T: Clone, C: Cycle> Slot<'a, 'dr, D, T, C> {
    /// Creates a new slot with the given allocation function.
    pub(super) fn new(alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> Result<T>) -> Self {
        Slot {
            value: None,
            alloc,
            _marker: core::marker::PhantomData,
        }
    }

    /// Allocates the value using the stored allocation function.
    ///
    /// # Panics
    ///
    /// Panics if the slot has already been filled (via `get` or `set`).
    pub fn get(&mut self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> Result<T> {
        assert!(self.value.is_none(), "Slot::get: slot already filled");
        let value = (self.alloc)(dr, instance)?;
        self.value = Some(value.clone());
        Ok(value)
    }

    /// Directly provides a pre-computed value for this slot.
    ///
    /// Use this when the value has already been computed elsewhere and
    /// should not be re-allocated.
    ///
    /// # Panics
    ///
    /// Panics if the slot has already been filled (via `get` or `set`).
    pub fn set(&mut self, value: T) {
        assert!(self.value.is_none(), "Slot::set: slot already filled");
        self.value = Some(value);
    }

    /// Consumes the slot and returns the stored value, allocating if needed.
    ///
    /// Used during finalization to build the [`Output`] gadget.
    fn take(self, dr: &mut D, instance: &DriverValue<D, &'a Instance<C>>) -> Result<T> {
        self.value
            .map(Result::Ok)
            .unwrap_or_else(|| (self.alloc)(dr, instance))
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> Output<'dr, D, C> {
    /// Allocates an [`Output`] directly from a current proof reference.
    ///
    /// This is a convenience method that extracts all fields from the current
    /// proof's components and challenges. Useful for testing or when the full
    /// proof structure is available.
    pub fn alloc_from_proof<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
    ) -> Result<Self> {
        let nested_preamble_commitment =
            Point::alloc(dr, proof.view().map(|p| p.preamble.nested_commitment))?;
        let w = Element::alloc(dr, proof.view().map(|p| p.challenges.w))?;
        let nested_s_prime_commitment = Point::alloc(
            dr,
            proof.view().map(|p| p.s_prime.nested_s_prime_commitment),
        )?;
        let y = Element::alloc(dr, proof.view().map(|p| p.challenges.y))?;
        let z = Element::alloc(dr, proof.view().map(|p| p.challenges.z))?;
        let nested_error_m_commitment =
            Point::alloc(dr, proof.view().map(|p| p.error_m.nested_commitment))?;
        let mu = Element::alloc(dr, proof.view().map(|p| p.challenges.mu))?;
        let nu = Element::alloc(dr, proof.view().map(|p| p.challenges.nu))?;
        let nested_error_n_commitment =
            Point::alloc(dr, proof.view().map(|p| p.error_n.nested_commitment))?;
        let mu_prime = Element::alloc(dr, proof.view().map(|p| p.challenges.mu_prime))?;
        let nu_prime = Element::alloc(dr, proof.view().map(|p| p.challenges.nu_prime))?;
        let c = Element::alloc(dr, proof.view().map(|p| p.ab.c))?;
        let nested_ab_commitment = Point::alloc(dr, proof.view().map(|p| p.ab.nested_commitment))?;
        let x = Element::alloc(dr, proof.view().map(|p| p.challenges.x))?;
        let nested_query_commitment =
            Point::alloc(dr, proof.view().map(|p| p.query.nested_commitment))?;
        let alpha = Element::alloc(dr, proof.view().map(|p| p.challenges.alpha))?;
        let nested_f_commitment = Point::alloc(dr, proof.view().map(|p| p.f.nested_commitment))?;
        let u = Element::alloc(dr, proof.view().map(|p| p.challenges.u))?;
        let nested_eval_commitment =
            Point::alloc(dr, proof.view().map(|p| p.eval.nested_commitment))?;
        let pre_beta = Element::alloc(dr, proof.view().map(|p| p.challenges.pre_beta))?;
        let v = Element::alloc(dr, proof.view().map(|p| p.p.v))?;

        Ok(Output {
            nested_preamble_commitment,
            w,
            nested_s_prime_commitment,
            y,
            z,
            nested_error_m_commitment,
            mu,
            nu,
            nested_error_n_commitment,
            mu_prime,
            nu_prime,
            c,
            nested_ab_commitment,
            x,
            nested_query_commitment,
            alpha,
            nested_f_commitment,
            u,
            nested_eval_commitment,
            pre_beta,
            v,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_circuits::polynomials::R;
    use ragu_core::{drivers::emulator::Emulator, maybe::Empty};
    use ragu_pasta::Pasta;

    #[test]
    fn num_wires_constant_is_correct() {
        // Use a wireless emulator with Empty witness - the emulator never reads witness values.
        let mut emulator = Emulator::counter();
        let output = Output::<'_, _, Pasta>::alloc_from_proof::<R<16>>(&mut emulator, Empty)
            .expect("allocation should succeed");

        assert_eq!(
            output.num_wires(),
            NUM_WIRES,
            "NUM_WIRES constant does not match actual wire count"
        );
    }
}
