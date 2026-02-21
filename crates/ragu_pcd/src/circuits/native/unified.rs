//! Unified instance/output interface for internal verification circuits.
//!
//! Internal circuits share a common instance defined by [`Output`]. This avoids
//! redundant evaluations of the instance polynomial $k(Y)$ and simplifies
//! circuit reconfiguration.
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

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Consistent, Gadget, Kind},
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

/// Maps a field type to its `Output` gadget type.
macro_rules! unified_output_type {
    (Point, $dr:lifetime, $D:ty, $C:ty) => {
        Point<$dr, $D, <$C as Cycle>::NestedCurve>
    };
    (Element, $dr:lifetime, $D:ty, $C:ty) => {
        Element<$dr, $D>
    };
}

/// Maps a field type to its Instance native type.
macro_rules! unified_instance_type {
    (Point, $C:ty) => {
        <$C as Cycle>::NestedCurve
    };
    (Element, $C:ty) => {
        <$C as Cycle>::CircuitField
    };
}

/// Creates a `Slot` initializer for a field (works for both Point and Element).
macro_rules! unified_slot_new {
    ($field_type:ident, $field:ident, $D:ty, $C:ty) => {
        Slot::new(|dr, i: &DriverValue<$D, &'a Instance<$C>>| {
            $field_type::alloc(dr, i.view().map(|i| i.$field))
        })
    };
}

/// Generates the unified instance types: `Output`, `Instance`, `OutputBuilder`.
///
/// This macro reduces boilerplate by generating all related types from a single
/// field definition. Each field is specified with its type (`Point` or `Element`).
macro_rules! define_unified_instance {
    (
        $(
            $(#[$field_meta:meta])*
            $field:ident : $field_type:ident
        ),+ $(,)?
    ) => {
        /// Shared public instance for internal verification circuits.
        ///
        /// Unlike stage [`Output`](super::stages) types (which are prover-internal
        /// communication), this gadget is the verifier-visible instance: its fields
        /// are serialized into the $k(Y)$ instance polynomial that the verifier
        /// checks.
        ///
        /// Contains the commitments, Fiat-Shamir challenges, and final values that
        /// internal circuits expose as instance data. The nested curve
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
            $(
                $(#[$field_meta])*
                #[ragu(gadget)]
                pub $field: unified_output_type!($field_type, 'dr, D, C),
            )+
        }

        /// Native (non-gadget) representation of the unified instance.
        ///
        /// This struct holds the concrete field values corresponding to [`Output`]
        /// fields. It is constructed during proof generation in the fuse pipeline
        /// and passed to circuits as witness data for gadget allocation.
        ///
        /// See [`Output`] for field descriptions.
        pub struct Instance<C: Cycle> {
            $(
                pub $field: unified_instance_type!($field_type, C),
            )+
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
        /// 4. Call [`finish`](Self::finish) or [`finish_no_suffix`](Self::finish_no_suffix)
        ///    to build the final output and obtain this circuit's [`Coverage`]
        ///
        /// Any slots not explicitly filled will be allocated during finalization.
        pub struct OutputBuilder<'a, 'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
            $(
                pub $field: Slot<'a, 'dr, D, unified_output_type!($field_type, 'dr, D, C), C>,
            )+
        }

        impl<'a, 'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> OutputBuilder<'a, 'dr, D, C> {
            /// Creates a new builder with allocation functions for each field.
            ///
            /// All slots start empty and will allocate from the [`Instance`] when
            /// finalized, unless explicitly filled beforehand.
            pub fn new() -> Self {
                OutputBuilder {
                    $(
                        $field: unified_slot_new!($field_type, $field, D, C),
                    )+
                }
            }

            /// Finishes building the output without wrapping in [`WithSuffix`].
            ///
            /// Returns the built [`Output`] and this circuit's [`Coverage`].
            /// Use this when the circuit needs to include additional data in its
            /// output alongside the unified instance, and will handle the suffix
            /// wrapping separately.
            pub fn finish_no_suffix(
                self,
                dr: &mut D,
                instance: &DriverValue<D, &'a Instance<C>>,
            ) -> Result<(Output<'dr, D, C>, Coverage)> {
                let coverage = self.coverage();
                Ok((Output {
                    $(
                        $field: self.$field.take(dr, instance)?,
                    )+
                }, coverage))
            }
        }
    };
}

// Define all unified instance fields in one place.
// Field order is significant: it determines wire ordering in the circuit.
define_unified_instance! {
    /// Commitment from the preamble proof component.
    nested_preamble_commitment: Point,
    /// Fiat-Shamir challenge $w$.
    w: Element,
    /// Commitment from the s_prime proof component.
    nested_s_prime_commitment: Point,
    /// Fiat-Shamir challenge $y$.
    y: Element,
    /// Fiat-Shamir challenge $z$.
    z: Element,
    /// Commitment from the error_m proof component.
    nested_error_m_commitment: Point,
    /// First folding layer challenge $\mu$.
    mu: Element,
    /// First folding layer challenge $\nu$.
    nu: Element,
    /// Commitment from the error_n proof component.
    nested_error_n_commitment: Point,
    /// Second folding layer challenge $\mu'$.
    mu_prime: Element,
    /// Second folding layer challenge $\nu'$.
    nu_prime: Element,
    /// Final revdot claim value from the ab proof component.
    c: Element,
    /// Commitment from the ab proof component.
    nested_ab_commitment: Point,
    /// Polynomial commitment challenge $x$.
    x: Element,
    /// Commitment from the query proof component.
    nested_query_commitment: Point,
    /// Query polynomial challenge $\alpha$.
    alpha: Element,
    /// Commitment from the f proof component.
    nested_f_commitment: Point,
    /// Final polynomial challenge $u$.
    u: Element,
    /// Commitment from the eval proof component.
    nested_eval_commitment: Point,
    /// Pre-endoscalar beta challenge. Effective beta is derived in compute_v.
    pre_beta: Element,
    /// Expected evaluation at the challenge point for consistency verification.
    v: Element,
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
    pub(super) was_set: bool,
    _marker: core::marker::PhantomData<&'dr ()>,
}

impl<'a, 'dr, D: Driver<'dr>, T: Clone, C: Cycle> Slot<'a, 'dr, D, T, C> {
    /// Creates a new slot with the given allocation function.
    pub(super) fn new(alloc: fn(&mut D, &DriverValue<D, &'a Instance<C>>) -> Result<T>) -> Self {
        Slot {
            value: None,
            alloc,
            was_set: false,
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

    /// Directly provides a circuit-derived value for this slot.
    ///
    /// Records the slot as covered so that [`finish`](OutputBuilder::finish)
    /// includes the corresponding positional bit in the returned [`Coverage`].
    /// Use [`set`](Self::set) whenever the circuit derives the value itself
    /// (e.g. from a sponge squeeze) rather than reading it via
    /// [`get`](Self::get).
    ///
    /// # Panics
    ///
    /// Panics if the slot has already been filled (via `get` or `set`).
    pub fn set(&mut self, value: T) {
        assert!(self.value.is_none(), "Slot::set: slot already filled");
        self.value = Some(value);
        self.was_set = true;
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
    ///
    /// Note: Field order follows `define_unified_instance!` for consistency.
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
    // Returns the Coverage of challenge slots filled via Slot::set.
    // Each Element slot contributes its positional bit when marked via Slot::set;
    // slots filled via Slot::get or left for lazy allocation do not contribute.
    fn coverage(&self) -> Coverage {
        let derived = [
            self.w.was_set,
            self.y.was_set,
            self.z.was_set,
            self.mu.was_set,
            self.nu.was_set,
            self.mu_prime.was_set,
            self.nu_prime.was_set,
            self.x.was_set,
            self.alpha.was_set,
            self.u.was_set,
            self.pre_beta.was_set,
            self.v.was_set,
        ];
        Coverage(
            derived
                .iter()
                .enumerate()
                .fold(0u32, |bits, (i, &set)| bits | ((set as u32) << i)),
        )
    }

    /// Finishes building, wraps the output in [`WithSuffix`], and returns
    /// this circuit's [`Coverage`].
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
    ) -> Result<(Bound<'dr, D, InternalOutputKind<C>>, Coverage)> {
        let zero = Element::zero(dr);
        let (output, coverage) = self.finish_no_suffix(dr, instance)?;
        Ok((WithSuffix::new(output, zero), coverage))
    }
}

/// Tracks which unified instance slots have been actively filled (via
/// [`Slot::set`]) by a circuit, rather than read from the witnessed instance.
///
/// Each [`Slot`] in [`OutputBuilder`] sets a positional bit here when filled
/// via [`Slot::set`]. Circuits receive their coverage as the second element of
/// the tuple returned by [`OutputBuilder::finish`] or
/// [`OutputBuilder::finish_no_suffix`] and return it as `Aux`. The fuse layer
/// collects coverage from [`hashes_1`], [`hashes_2`], and [`compute_v`] and
/// calls [`validate`](Self::validate), asserting pairwise disjointness and
/// complete coverage of all 12 required slots (11 Fiat-Shamir challenges plus
/// the computed `v` slot).
///
/// [`hashes_1`]: super::hashes_1
/// [`hashes_2`]: super::hashes_2
/// [`compute_v`]: super::compute_v
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Coverage(u32);

impl Coverage {
    /// The number of derived slots (11 Fiat-Shamir challenges + `v`).
    const NUM_DERIVED: u32 = 12;

    /// Full coverage: all `NUM_DERIVED` slots set.
    const ALL: Self = Self((1 << Self::NUM_DERIVED) - 1);

    /// Validates that the given coverages together cover all required slots
    /// exactly once.
    ///
    /// # Panics
    ///
    /// Panics if any slot is covered by multiple circuits or if any required
    /// slot is unclaimed.
    pub fn validate(coverages: &[Coverage]) {
        let union = coverages.iter().fold(0u32, |acc, c| acc | c.0);
        let total: u32 = coverages.iter().map(|c| c.0.count_ones()).sum();

        assert_eq!(union, Self::ALL.0, "not all required slots were covered");
        assert_eq!(
            total,
            Self::NUM_DERIVED,
            "slot covered by multiple circuits"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::marker::PhantomData;
    use ragu_arithmetic::Cycle;
    use ragu_circuits::polynomials::ProductionRank;
    use ragu_core::{drivers::emulator::Emulator, maybe::Empty};
    use ragu_pasta::Pasta;

    #[test]
    fn num_wires_constant_is_correct() {
        // Use a wireless emulator with Empty witness - the emulator never reads witness values.
        let mut emulator = Emulator::counter();
        let output =
            Output::<'_, _, Pasta>::alloc_from_proof::<ProductionRank>(&mut emulator, Empty)
                .expect("allocation should succeed");

        assert_eq!(
            output.num_wires(),
            NUM_WIRES,
            "NUM_WIRES constant does not match actual wire count"
        );
    }

    #[test]
    fn coverage_all() {
        // Verify that marking every tracked slot as set produces Coverage::ALL.
        // If a slot is added to define_unified_instance! but omitted from
        // coverage() (or Coverage::ALL is wrong), this test fails.
        type D = PhantomData<<Pasta as Cycle>::CircuitField>;
        let mut builder: OutputBuilder<'_, '_, D, Pasta> = OutputBuilder::new();
        builder.w.was_set = true;
        builder.y.was_set = true;
        builder.z.was_set = true;
        builder.mu.was_set = true;
        builder.nu.was_set = true;
        builder.mu_prime.was_set = true;
        builder.nu_prime.was_set = true;
        builder.x.was_set = true;
        builder.alpha.was_set = true;
        builder.u.was_set = true;
        builder.pre_beta.was_set = true;
        builder.v.was_set = true;
        assert_eq!(
            builder.coverage(),
            Coverage::ALL,
            "coverage() does not match Coverage::ALL; update both when slots change"
        );
    }
}
