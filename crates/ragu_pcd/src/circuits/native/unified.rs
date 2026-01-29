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
    gadgets::{Consistent, Gadget, GadgetKind, Kind},
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

/// Shared public inputs for internal verification circuits.
///
/// This gadget contains the commitments, Fiat-Shamir challenges, and final
/// values that internal circuits consume as public inputs. The nested curve
/// (`C::NestedCurve`) is the other curve in the cycle, whose base field equals
/// the circuit's scalar field.
///
/// # Field Organization
///
/// Fields are ordered to match the current proof's transcript:
///
/// - **Commitments**: Points on the nested curve from current proof components
/// - **Challenges**: Fiat-Shamir challenges computed by [`hashes_1`] and [`hashes_2`]
/// - **Final values**: The revdot claim $c$ and expected evaluation $v$
///
/// [`hashes_1`]: super::hashes_1
/// [`hashes_2`]: super::hashes_2
#[derive(Gadget, Write, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    // Commitments from current proof components (on the nested curve)
    /// Commitment from the preamble proof component.
    #[ragu(gadget)]
    pub nested_preamble_commitment: Point<'dr, D, C::NestedCurve>,

    // Challenge from hashes_1
    /// Fiat-Shamir challenge $w$.
    #[ragu(gadget)]
    pub w: Element<'dr, D>,

    /// Commitment from the s_prime proof component.
    #[ragu(gadget)]
    pub nested_s_prime_commitment: Point<'dr, D, C::NestedCurve>,

    // Challenges from hashes_1
    /// Fiat-Shamir challenge $y$.
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
    /// Fiat-Shamir challenge $z$.
    #[ragu(gadget)]
    pub z: Element<'dr, D>,

    /// Commitment from the error_m proof component.
    #[ragu(gadget)]
    pub nested_error_m_commitment: Point<'dr, D, C::NestedCurve>,

    // First folding layer challenges from hashes_2
    /// First folding layer challenge $\mu$.
    #[ragu(gadget)]
    pub mu: Element<'dr, D>,
    /// First folding layer challenge $\nu$.
    #[ragu(gadget)]
    pub nu: Element<'dr, D>,

    /// Commitment from the error_n proof component.
    #[ragu(gadget)]
    pub nested_error_n_commitment: Point<'dr, D, C::NestedCurve>,

    // Second folding layer challenges from hashes_2
    /// Second folding layer challenge $\mu'$.
    #[ragu(gadget)]
    pub mu_prime: Element<'dr, D>,
    /// Second folding layer challenge $\nu'$.
    #[ragu(gadget)]
    pub nu_prime: Element<'dr, D>,

    // Final values
    /// Final revdot claim value from the ab proof component.
    #[ragu(gadget)]
    pub c: Element<'dr, D>,

    /// Commitment from the ab proof component.
    #[ragu(gadget)]
    pub nested_ab_commitment: Point<'dr, D, C::NestedCurve>,

    // Polynomial commitment challenge from hashes_2
    /// Polynomial commitment challenge $x$.
    #[ragu(gadget)]
    pub x: Element<'dr, D>,

    /// Commitment from the query proof component.
    #[ragu(gadget)]
    pub nested_query_commitment: Point<'dr, D, C::NestedCurve>,

    /// Query polynomial challenge $\alpha$.
    #[ragu(gadget)]
    pub alpha: Element<'dr, D>,

    /// Commitment from the f proof component.
    #[ragu(gadget)]
    pub nested_f_commitment: Point<'dr, D, C::NestedCurve>,

    /// Final polynomial challenge $u$.
    #[ragu(gadget)]
    pub u: Element<'dr, D>,

    /// Commitment from the eval proof component.
    #[ragu(gadget)]
    pub nested_eval_commitment: Point<'dr, D, C::NestedCurve>,

    /// Pre-endoscalar beta challenge. Effective beta is derived in compute_v.
    #[ragu(gadget)]
    pub pre_beta: Element<'dr, D>,

    /// Expected evaluation at the challenge point for consistency verification.
    #[ragu(gadget)]
    pub v: Element<'dr, D>,
}

/// Native (non-gadget) representation of unified public inputs.
///
/// This struct holds the concrete field values corresponding to [`Output`]
/// fields. It is constructed during proof generation in the fuse pipeline
/// and passed to circuits as witness data for gadget allocation.
///
/// See [`Output`] for field descriptions.
pub struct Instance<C: Cycle> {
    pub nested_preamble_commitment: C::NestedCurve,
    pub w: C::CircuitField,
    pub nested_s_prime_commitment: C::NestedCurve,
    pub y: C::CircuitField,
    pub z: C::CircuitField,
    pub nested_error_m_commitment: C::NestedCurve,
    pub mu: C::CircuitField,
    pub nu: C::CircuitField,
    pub nested_error_n_commitment: C::NestedCurve,
    pub mu_prime: C::CircuitField,
    pub nu_prime: C::CircuitField,
    pub c: C::CircuitField,
    pub nested_ab_commitment: C::NestedCurve,
    pub x: C::CircuitField,
    pub nested_query_commitment: C::NestedCurve,
    pub alpha: C::CircuitField,
    pub nested_f_commitment: C::NestedCurve,
    pub u: C::CircuitField,
    pub nested_eval_commitment: C::NestedCurve,
    pub pre_beta: C::CircuitField,
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

/// Builder for constructing an [`Output`] gadget with flexible allocation.
///
/// Each field is a [`Slot`] that can be filled either eagerly (via `set`) or
/// lazily (via `get` or at finalization). This allows circuits to pre-compute
/// some values during earlier stages while deferring others.
///
/// # Usage
///
/// 1. Create a builder with [`new`](Self::new)
/// 2. Optionally pre-fill slots using `builder.field.set(value)`
/// 3. Optionally allocate slots using `builder.field.get(dr, instance)`
/// 4. Call [`finish`](Self::finish) to build the final output with suffix
///
/// Any slots not explicitly filled will be allocated during finalization.
pub struct OutputBuilder<'a, 'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    pub nested_preamble_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub w: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_s_prime_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub y: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub z: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_error_m_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub mu: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nu: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_error_n_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub mu_prime: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nu_prime: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub c: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_ab_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub x: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_query_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub alpha: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_f_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub u: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub nested_eval_commitment: Slot<'a, 'dr, D, Point<'dr, D, C::NestedCurve>, C>,
    pub pre_beta: Slot<'a, 'dr, D, Element<'dr, D>, C>,
    pub v: Slot<'a, 'dr, D, Element<'dr, D>, C>,
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

impl<'a, 'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> OutputBuilder<'a, 'dr, D, C> {
    /// Creates a new builder with allocation functions for each field.
    ///
    /// All slots start empty and will allocate from the [`Instance`] when
    /// finalized, unless explicitly filled beforehand.
    pub fn new() -> Self {
        macro_rules! point_slot {
            ($field:ident) => {
                Slot::new(|dr, i: &DriverValue<D, &'a Instance<C>>| {
                    Point::alloc(dr, i.view().map(|i| i.$field))
                })
            };
        }
        macro_rules! element_slot {
            ($field:ident) => {
                Slot::new(|dr, i: &DriverValue<D, &'a Instance<C>>| {
                    Element::alloc(dr, i.view().map(|i| i.$field))
                })
            };
        }
        OutputBuilder {
            nested_preamble_commitment: point_slot!(nested_preamble_commitment),
            w: element_slot!(w),
            nested_s_prime_commitment: point_slot!(nested_s_prime_commitment),
            y: element_slot!(y),
            z: element_slot!(z),
            nested_error_m_commitment: point_slot!(nested_error_m_commitment),
            mu: element_slot!(mu),
            nu: element_slot!(nu),
            nested_error_n_commitment: point_slot!(nested_error_n_commitment),
            mu_prime: element_slot!(mu_prime),
            nu_prime: element_slot!(nu_prime),
            c: element_slot!(c),
            nested_ab_commitment: point_slot!(nested_ab_commitment),
            x: element_slot!(x),
            nested_query_commitment: point_slot!(nested_query_commitment),
            alpha: element_slot!(alpha),
            nested_f_commitment: point_slot!(nested_f_commitment),
            u: element_slot!(u),
            nested_eval_commitment: point_slot!(nested_eval_commitment),
            pre_beta: element_slot!(pre_beta),
            v: element_slot!(v),
        }
    }

    /// Finishes building and wraps the output in [`WithSuffix`].
    ///
    /// Appends a zero element as the suffix, ensuring the linear term of
    /// $k(Y)$ is zero. This distinguishes internal circuits (fixed by the
    /// protocol) from application circuits (which vary), preventing an
    /// application from substituting an internal circuit proof for an
    /// application circuit proof.
    pub fn finish(
        self,
        dr: &mut D,
        instance: &DriverValue<D, &'a Instance<C>>,
    ) -> Result<<InternalOutputKind<C> as GadgetKind<D::F>>::Rebind<'dr, D>> {
        let zero = Element::zero(dr);
        Ok(WithSuffix::new(self.finish_no_suffix(dr, instance)?, zero))
    }

    /// Finishes building the output without wrapping in [`WithSuffix`].
    ///
    /// Use this when the circuit needs to include additional data in its
    /// output alongside the unified instance, and will handle the suffix
    /// wrapping separately.
    pub fn finish_no_suffix(
        self,
        dr: &mut D,
        instance: &DriverValue<D, &'a Instance<C>>,
    ) -> Result<Output<'dr, D, C>> {
        Ok(Output {
            nested_preamble_commitment: self.nested_preamble_commitment.take(dr, instance)?,
            w: self.w.take(dr, instance)?,
            nested_s_prime_commitment: self.nested_s_prime_commitment.take(dr, instance)?,
            y: self.y.take(dr, instance)?,
            z: self.z.take(dr, instance)?,
            nested_error_m_commitment: self.nested_error_m_commitment.take(dr, instance)?,
            mu: self.mu.take(dr, instance)?,
            nu: self.nu.take(dr, instance)?,
            nested_error_n_commitment: self.nested_error_n_commitment.take(dr, instance)?,
            mu_prime: self.mu_prime.take(dr, instance)?,
            nu_prime: self.nu_prime.take(dr, instance)?,
            c: self.c.take(dr, instance)?,
            nested_ab_commitment: self.nested_ab_commitment.take(dr, instance)?,
            x: self.x.take(dr, instance)?,
            nested_query_commitment: self.nested_query_commitment.take(dr, instance)?,
            alpha: self.alpha.take(dr, instance)?,
            nested_f_commitment: self.nested_f_commitment.take(dr, instance)?,
            u: self.u.take(dr, instance)?,
            nested_eval_commitment: self.nested_eval_commitment.take(dr, instance)?,
            pre_beta: self.pre_beta.take(dr, instance)?,
            v: self.v.take(dr, instance)?,
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
