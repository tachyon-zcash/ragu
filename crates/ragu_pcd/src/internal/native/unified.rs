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
//! [`hashes_1`]: super::circuits::hashes_1
//! [`hashes_2`]: super::circuits::hashes_2

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, consistent::Consistent, io::Write};

use crate::{internal::suffix::WithSuffix, proof::Proof};

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
    ($field_type:ident, $field:ident, $instance:expr) => {
        Slot::new($instance.as_ref().map(|i| i.$field), |dr, w| {
            $field_type::alloc(dr, w)
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
        /// - **Bridge commitments**: Points on the nested curve from current proof components
        /// - **Challenges**: Fiat-Shamir challenges computed by [`hashes_1`] and [`hashes_2`]
        /// - **Final values**: The revdot claim $c$ and expected evaluation $v$
        ///
        /// [`hashes_1`]: super::circuits::hashes_1
        /// [`hashes_2`]: super::circuits::hashes_2
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
        /// Also carries [`Coverage`] so that a single value threads through
        /// all internal circuits, accumulating coverage as it goes.
        ///
        /// See [`Output`] for field descriptions.
        pub struct Instance<C: Cycle> {
            $(
                pub $field: unified_instance_type!($field_type, C),
            )+
            /// Accumulated coverage from prior circuits.
            pub coverage: Coverage,
        }

        impl<C: Cycle> Instance<C> {
            /// Asserts that every slot has been covered by some circuit.
            ///
            /// # Panics
            ///
            /// Panics if any slot has not been covered.
            pub fn assert_complete(self) {
                self.coverage.assert_complete();
            }
        }

        /// Builder for constructing an [`Output`] gadget with flexible allocation.
        ///
        /// Each field is a [`Slot`] that can be filled eagerly (via `provide`),
        /// allocated on demand (via `read` or `receive`), or deferred to
        /// finalization. This allows circuits to pre-compute some values
        /// during earlier stages while deferring others.
        ///
        /// # Usage
        ///
        /// 1. Create a builder with [`new`](Self::new), passing in the
        ///    [`Instance`] (which carries accumulated [`Coverage`])
        /// 2. Optionally pre-fill slots using `builder.field.provide(value)`
        /// 3. Optionally allocate slots using `builder.field.read(dr)` or
        ///    `builder.field.receive(dr)` (which also marks coverage)
        /// 4. Call [`finish`](Self::finish) or [`finish_no_suffix`](Self::finish_no_suffix)
        ///    to build the final output and obtain the updated [`Instance`]
        ///
        /// Any slots not explicitly filled will be allocated during finalization.
        pub struct OutputBuilder<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
            $(
                pub $field: Slot<'dr, D, unified_output_type!($field_type, 'dr, D, C), unified_instance_type!($field_type, C)>,
            )+
            instance: DriverValue<D, Instance<C>>,
        }

        impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> OutputBuilder<'dr, D, C> {
            /// Creates a new builder with allocation functions for each field.
            ///
            /// The `instance` carries both the protocol values (challenges,
            /// commitments) and the accumulated [`Coverage`] from prior
            /// circuits. Coverage is merged with this circuit's contributions
            /// when [`finish`](Self::finish) or
            /// [`finish_no_suffix`](Self::finish_no_suffix) is called.
            pub fn new(instance: DriverValue<D, Instance<C>>) -> Self {
                OutputBuilder {
                    $(
                        $field: unified_slot_new!($field_type, $field, instance),
                    )+
                    instance,
                }
            }

            /// Finishes building the output without wrapping in [`WithSuffix`].
            ///
            /// Returns the built [`Output`] and the updated [`Instance`]
            /// (with this circuit's coverage contributions accumulated).
            /// Use this when the circuit needs to include additional data in
            /// its output alongside the unified instance, and will handle the
            /// suffix wrapping separately.
            pub fn finish_no_suffix(
                self,
                dr: &mut D,
            ) -> Result<(Output<'dr, D, C>, DriverValue<D, Instance<C>>)> {
                $( let $field = self.$field.take(dr)?; )+
                let output = Output {
                    $( $field: $field.0, )+
                };
                let instance = self.instance.map(move |mut inst| {
                    $(
                        if $field.1 {
                            Coverage::cover(&mut inst.coverage.$field, stringify!($field));
                        }
                    )+
                    inst
                });
                Ok((output, instance))
            }
        }

        /// Tracks which unified instance slots have been actively filled
        /// (via [`Slot::provide`] or [`Slot::receive`]) across circuits.
        ///
        /// Generated by `define_unified_instance!` — one `bool` per field.
        #[derive(Debug, Default, PartialEq, Eq)]
        pub struct Coverage {
            $( $field: bool, )+
        }

        impl Coverage {
            /// Marks a coverage flag, panicking on double-cover.
            fn cover(flag: &mut bool, name: &str) {
                assert!(!*flag, "slot `{name}` covered by multiple circuits");
                *flag = true;
            }

            /// Asserts that a coverage flag has been set.
            fn assert_covered(flag: bool, name: &str) {
                assert!(flag, "slot `{name}` not covered by any circuit");
            }

            fn assert_complete(self) {
                $( Self::assert_covered(self.$field, stringify!($field)); )+
            }
        }
    };
}

// Define all unified instance fields in one place.
// Field order is significant: it determines wire ordering in the circuit.
define_unified_instance! {
    /// Bridge commitment from the preamble proof component.
    bridge_preamble_commitment: Point,
    /// Fiat-Shamir challenge $w$.
    w: Element,
    /// Bridge commitment from the s_prime proof component.
    bridge_s_prime_commitment: Point,
    /// Fiat-Shamir challenge $y$.
    y: Element,
    /// Fiat-Shamir challenge $z$.
    z: Element,
    /// Bridge commitment from the inner error proof component.
    bridge_inner_error_commitment: Point,
    /// First folding layer challenge $\mu$.
    mu: Element,
    /// First folding layer challenge $\nu$.
    nu: Element,
    /// Bridge commitment from the outer error proof component.
    bridge_outer_error_commitment: Point,
    /// Second folding layer challenge $\mu'$.
    mu_prime: Element,
    /// Second folding layer challenge $\nu'$.
    nu_prime: Element,
    /// Final revdot claim value from the ab proof component.
    c: Element,
    /// Bridge commitment from the ab proof component.
    bridge_ab_commitment: Point,
    /// Polynomial commitment challenge $x$.
    x: Element,
    /// Bridge commitment from the query proof component.
    bridge_query_commitment: Point,
    /// Query polynomial challenge $\alpha$.
    alpha: Element,
    /// Bridge commitment from the f proof component.
    bridge_f_commitment: Point,
    /// Final polynomial challenge $u$.
    u: Element,
    /// Bridge commitment from the eval proof component.
    bridge_eval_commitment: Point,
    /// Pre-endoscalar beta challenge. Effective beta is derived in compute_v.
    pre_beta: Element,
    /// Expected evaluation at the challenge point for consistency verification.
    v: Element,
}

/// A lazy-allocation slot for a single field in the unified output.
///
/// Slots enable circuits to either pre-compute values (via
/// [`provide`](Self::provide)) or allocate on-demand (via
/// [`read`](Self::read)). This avoids redundant wire allocations when the
/// same value is computed by multiple code paths.
///
/// `W` is the native (non-circuit) value type for the field; `T` is the
/// corresponding circuit gadget type.
///
/// Each slot holds a pre-extracted `W` witness value and an allocation
/// function `W → T`. A circuit fills the slot using one of three methods,
/// or leaves it for `finish` to handle via [`take`](Self::take):
///
/// | Method | Source | Marks covered? | Use case |
/// |--------|--------|----------------|----------|
/// | [`read`](Self::read)       | witness  | no  | Another circuit covers this slot |
/// | [`provide`](Self::provide) | in-circuit | yes | This circuit computed the value |
/// | [`receive`](Self::receive) | witness  | yes | This circuit constrains the witnessed value |
/// | [`take`](Self::take)       | witness  | no  | Internal — used by `finish` |
///
/// Use [`read`](Self::read) when the circuit needs the allocated `T`
/// during synthesis but another circuit is responsible for constraining
/// it. Omit it and let `finish` call [`take`](Self::take) when the circuit
/// does not reference the field at all.
///
/// "Covered" means this circuit takes responsibility for constraining the
/// field's correctness.
pub struct Slot<'dr, D: Driver<'dr>, T, W: Send> {
    value: Option<T>,
    instance: DriverValue<D, W>,
    alloc: fn(&mut D, DriverValue<D, W>) -> Result<T>,
    was_set: bool,
    _marker: core::marker::PhantomData<&'dr ()>,
}

impl<'dr, D: Driver<'dr>, T: Clone, W: Copy + Send + Sync> Slot<'dr, D, T, W> {
    /// Creates a new slot with a pre-extracted instance value and allocation function.
    pub(super) fn new(
        instance: DriverValue<D, W>,
        alloc: fn(&mut D, DriverValue<D, W>) -> Result<T>,
    ) -> Self {
        Slot {
            value: None,
            instance,
            alloc,
            was_set: false,
            _marker: core::marker::PhantomData,
        }
    }

    /// Allocates the value from witness without marking covered.
    ///
    /// Use this when another circuit is responsible for constraining this
    /// slot's correctness. See [`provide`](Self::provide) or
    /// [`receive`](Self::receive)
    /// to mark coverage.
    ///
    /// # Panics
    ///
    /// Panics if the slot has already been filled (via `read`, `provide`, or
    /// `receive`).
    pub fn read(&mut self, dr: &mut D) -> Result<T> {
        assert!(self.value.is_none(), "Slot::read: slot already filled");
        let value = (self.alloc)(dr, self.instance.as_ref().map(|w| *w))?;
        self.value = Some(value.clone());
        Ok(value)
    }

    /// Provides an internally computed value for this slot.
    ///
    /// Use when this circuit **computed** the value (e.g., squeezed a
    /// Fiat-Shamir challenge) and takes responsibility for its correctness.
    /// Marks the slot as covered in [`Coverage`].
    ///
    /// See [`receive`](Self::receive) for the externally-supplied
    /// counterpart.
    ///
    /// # Panics
    ///
    /// Panics if the slot has already been filled.
    pub fn provide(&mut self, value: T) {
        assert!(self.value.is_none(), "Slot::provide: slot already filled");
        self.value = Some(value);
        self.was_set = true;
    }

    /// Receives an externally-supplied value from witness and marks covered.
    ///
    /// Use when this circuit **receives** a value determined outside the
    /// circuit (e.g., a commitment) and takes responsibility for
    /// constraining its correctness via a separate constraint on the
    /// returned value.
    ///
    /// See [`provide`](Self::provide) for the internally-computed
    /// counterpart.
    ///
    /// # Panics
    ///
    /// Panics if the slot has already been filled.
    pub fn receive(&mut self, dr: &mut D) -> Result<T> {
        assert!(self.value.is_none(), "Slot::receive: slot already filled");
        let value = (self.alloc)(dr, self.instance.as_ref().map(|w| *w))?;
        self.value = Some(value.clone());
        self.was_set = true;
        Ok(value)
    }

    /// Consumes the slot and returns the stored value (allocating if
    /// needed) along with the coverage flag.
    ///
    /// Used during finalization to build the [`Output`] gadget.
    fn take(self, dr: &mut D) -> Result<(T, bool)> {
        let value = self
            .value
            .map(Result::Ok)
            .unwrap_or_else(|| (self.alloc)(dr, self.instance.as_ref().map(|w| *w)))?;
        Ok((value, self.was_set))
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
        let bridge_preamble_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.preamble.bridge.commitment))?;
        let w = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.w))?;
        let bridge_s_prime_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.s_prime.bridge.commitment))?;
        let y = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.y))?;
        let z = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.z))?;
        let bridge_inner_error_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.inner_error.bridge.commitment))?;
        let mu = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.mu))?;
        let nu = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.nu))?;
        let bridge_outer_error_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.outer_error.bridge.commitment))?;
        let mu_prime = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.mu_prime))?;
        let nu_prime = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.nu_prime))?;
        let c = Element::alloc(dr, proof.as_ref().map(|p| p.ab.native.c))?;
        let bridge_ab_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.ab.bridge.commitment))?;
        let x = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.x))?;
        let bridge_query_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.query.bridge.commitment))?;
        let alpha = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.alpha))?;
        let bridge_f_commitment = Point::alloc(dr, proof.as_ref().map(|p| p.f.bridge.commitment))?;
        let u = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.u))?;
        let bridge_eval_commitment =
            Point::alloc(dr, proof.as_ref().map(|p| p.eval.bridge.commitment))?;
        let pre_beta = Element::alloc(dr, proof.as_ref().map(|p| p.challenges.pre_beta))?;
        let v = Element::alloc(dr, proof.as_ref().map(|p| p.p.native.v))?;

        Ok(Output {
            bridge_preamble_commitment,
            w,
            bridge_s_prime_commitment,
            y,
            z,
            bridge_inner_error_commitment,
            mu,
            nu,
            bridge_outer_error_commitment,
            mu_prime,
            nu_prime,
            c,
            bridge_ab_commitment,
            x,
            bridge_query_commitment,
            alpha,
            bridge_f_commitment,
            u,
            bridge_eval_commitment,
            pre_beta,
            v,
        })
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> OutputBuilder<'dr, D, C> {
    /// Finishes building, wraps the output in [`WithSuffix`], and returns
    /// the updated [`Instance`] (with this circuit's coverage accumulated).
    ///
    /// Appends a zero element as the suffix, ensuring the linear term of
    /// $k(Y)$ is zero. This distinguishes internal circuits (fixed by the
    /// protocol) from application circuits (which vary), preventing an
    /// application from substituting an internal circuit proof for an
    /// application circuit proof.
    pub fn finish(
        self,
        dr: &mut D,
    ) -> Result<(
        Bound<'dr, D, InternalOutputKind<C>>,
        DriverValue<D, Instance<C>>,
    )> {
        let zero = Element::zero(dr);
        let (output, instance) = self.finish_no_suffix(dr)?;
        Ok((WithSuffix::new(output, zero), instance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            output.num_wires().expect("wire counting should succeed"),
            NUM_WIRES,
            "NUM_WIRES constant does not match actual wire count"
        );
    }

    #[test]
    fn coverage_assert_complete_passes_when_all_set() {
        let cov = Coverage {
            bridge_preamble_commitment: true,
            w: true,
            bridge_s_prime_commitment: true,
            y: true,
            z: true,
            bridge_inner_error_commitment: true,
            mu: true,
            nu: true,
            bridge_outer_error_commitment: true,
            mu_prime: true,
            nu_prime: true,
            c: true,
            bridge_ab_commitment: true,
            x: true,
            bridge_query_commitment: true,
            alpha: true,
            bridge_f_commitment: true,
            u: true,
            bridge_eval_commitment: true,
            pre_beta: true,
            v: true,
        };
        cov.assert_complete();
    }

    #[test]
    #[should_panic(expected = "not covered by any circuit")]
    fn coverage_assert_complete_catches_missing() {
        Coverage {
            w: true,
            ..Coverage::default()
        }
        .assert_complete();
    }

    #[test]
    #[should_panic(expected = "covered by multiple circuits")]
    fn coverage_catches_element_overlap() {
        let mut cov = Coverage::default();
        Coverage::cover(&mut cov.w, "w");
        Coverage::cover(&mut cov.w, "w");
    }

    #[test]
    #[should_panic(expected = "covered by multiple circuits")]
    fn coverage_catches_point_overlap() {
        let mut cov = Coverage::default();
        Coverage::cover(
            &mut cov.bridge_preamble_commitment,
            "bridge_preamble_commitment",
        );
        Coverage::cover(
            &mut cov.bridge_preamble_commitment,
            "bridge_preamble_commitment",
        );
    }

    type Dr = Emulator<ragu_core::drivers::emulator::Wireless<Empty, pasta_curves::Fp>>;
    type Sl = Slot<'static, Dr, Element<'static, Dr>, pasta_curves::Fp>;

    /// Helper: creates two independent element slots and a fresh emulator.
    fn two_element_slots() -> (Dr, Sl, Sl) {
        let dr = Emulator::counter();
        let a = Slot::new(Empty, Element::alloc);
        let b = Slot::new(Empty, Element::alloc);
        (dr, a, b)
    }

    /// `read` allocates from witness, does NOT mark covered.
    #[test]
    fn slot_read_allocates_without_coverage() {
        let (mut dr, mut a, mut b) = two_element_slots();
        a.read(&mut dr).expect("read a");
        b.read(&mut dr).expect("read b");
        let (_, a_set) = a.take(&mut dr).expect("take a");
        let (_, b_set) = b.take(&mut dr).expect("take b");
        assert!(!a_set, "read() must not mark slot a as covered");
        assert!(!b_set, "read() must not mark slot b as covered");
    }

    /// `provide` stores a circuit-computed value and marks covered.
    #[test]
    fn slot_provide_stores_value_and_marks_covered() {
        let (mut dr, mut a, b) = two_element_slots();
        let val_a = Element::alloc(&mut dr, Empty).expect("alloc a");
        a.provide(val_a);
        // b left untouched — should remain uncovered.
        let (_, a_set) = a.take(&mut dr).expect("take a");
        let (_, b_set) = b.take(&mut dr).expect("take b");
        assert!(a_set, "provide() must mark slot a as covered");
        assert!(!b_set, "provide() on a must not affect slot b");
    }

    /// `receive` allocates from witness AND marks covered.
    #[test]
    fn slot_receive_allocates_and_marks_covered() {
        let (mut dr, mut a, mut b) = two_element_slots();
        let _ = a.receive(&mut dr).expect("receive a");
        // b only gets `read` — should remain uncovered.
        b.read(&mut dr).expect("read b");
        let (_, a_set) = a.take(&mut dr).expect("take a");
        let (_, b_set) = b.take(&mut dr).expect("take b");
        assert!(a_set, "receive() must mark slot a as covered");
        assert!(!b_set, "receive() on a must not affect slot b");
    }

    /// `take` on an untouched slot allocates from witness, does NOT mark covered.
    #[test]
    fn slot_take_untouched_allocates_without_coverage() {
        let (mut dr, a, mut b) = two_element_slots();
        // a is never touched by the circuit — finish calls take directly.
        b.receive(&mut dr).expect("receive b");
        let (_, a_set) = a.take(&mut dr).expect("take a");
        let (_, b_set) = b.take(&mut dr).expect("take b");
        assert!(!a_set, "untouched slot a must not be marked as covered");
        assert!(b_set, "received slot b must be marked as covered");
    }
}
