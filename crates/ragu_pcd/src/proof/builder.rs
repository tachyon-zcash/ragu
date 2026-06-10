//! [`ProofBuilder`] for incremental proof construction.
//!
//! Polynomial setters store values immediately. Native commitment caches are
//! computed lazily on first access via [`OnceCell`]-based interior mutability.
//! The four "simple" bridge commitments (outer_error, ab, query, eval) are also
//! lazily computed from [`bridge_alpha`](ProofBuilder::bridge_alpha) and the
//! native commitments already on the builder.

use alloc::vec::Vec;
use core::cell::OnceCell;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_core::Result;

use super::{Cached, Proof};
use crate::internal::nested;

/// Produces `pub(crate) fn $name(&mut self, v: $ty)` that sets an `Option`
/// field, panicking on double-set.
macro_rules! setter {
    ($name:ident, $field:ident, $ty:ty) => {
        pub(crate) fn $name(&mut self, v: $ty) {
            assert!(
                self.$field.is_none(),
                concat!("double-set: ", stringify!($field))
            );
            self.$field = Some(v);
        }
    };
}

/// Produces `pub(crate) fn $getter(&self) -> C::{Host,Nested}Curve` that
/// lazily computes and caches a commitment from a polynomial via
/// `commit_to_affine`. The `native` / `nested` prefix selects the curve type
/// and the corresponding generators source.
macro_rules! lazy_commitment {
    (native, $getter:ident, $cache:ident, $poly:ident) => {
        lazy_commitment!(@impl $getter, $cache, $poly, C::HostCurve, C::host_generators);
    };
    (nested, $getter:ident, $cache:ident, $poly:ident) => {
        lazy_commitment!(@impl $getter, $cache, $poly, C::NestedCurve, C::nested_generators);
    };
    (@impl $getter:ident, $cache:ident, $poly:ident, $curve:ty, $gen:path) => {
        pub(crate) fn $getter(&self) -> $curve {
            *self.$cache.get_or_init(|| {
                self.$poly
                    .as_ref()
                    .expect(concat!(stringify!($poly), " not set"))
                    .commit_to_affine($gen(self.params))
            })
        }
    };
}

/// Produces a [`setter!`] for `sparse::Polynomial<C::CircuitField, R>`,
/// eliding the repeated type.
macro_rules! native_setter {
    ($name:ident, $field:ident) => {
        setter!($name, $field, sparse::Polynomial<C::CircuitField, R>);
    };
}

/// Produces `pub(crate) fn $name(&self) -> $ty` that unwraps an `Option`
/// field by value (for `Copy` types like challenge scalars).
macro_rules! getter {
    ($name:ident, $field:ident, $ty:ty) => {
        pub(crate) fn $name(&self) -> $ty {
            self.$field.expect(concat!(stringify!($field), " not set"))
        }
    };
}

/// Produces `pub(crate) fn $name(&self) -> &$ty` that borrows an `Option`
/// field via `as_ref()`.
macro_rules! ref_getter {
    ($name:ident, $field:ident, $ty:ty) => {
        pub(crate) fn $name(&self) -> &$ty {
            self.$field
                .as_ref()
                .expect(concat!(stringify!($field), " not set"))
        }
    };
}

/// Produces `pub(crate) fn $name(&self) -> &[$ty]` that borrows an
/// `Option<Vec>` field as a slice via `as_deref()`.
macro_rules! slice_getter {
    ($name:ident, $field:ident, $ty:ty) => {
        pub(crate) fn $name(&self) -> &[$ty] {
            self.$field
                .as_deref()
                .expect(concat!(stringify!($field), " not set"))
        }
    };
}

/// Produces two methods:
/// - `pub(crate) fn $setter(&mut self, rx, commitment)` — stores a bridge
///   polynomial and its pre-computed commitment together.
/// - `pub(crate) fn $getter(&self) -> C::NestedCurve` — returns the stored
///   commitment.
macro_rules! bridge_pair {
    ($setter:ident, $getter:ident, $rx:ident, $commitment:ident) => {
        pub(crate) fn $setter(
            &mut self,
            rx: sparse::Polynomial<C::ScalarField, R>,
            commitment: C::NestedCurve,
        ) {
            assert!(self.$rx.is_none(), concat!("double-set: ", stringify!($rx)));
            self.$rx = Some(rx);
            self.$commitment = Some(commitment);
        }

        pub(crate) fn $getter(&self) -> C::NestedCurve {
            self.$commitment
                .expect(concat!(stringify!($commitment), " not set"))
        }
    };
}

/// Produces `pub(crate) fn $name(&mut self, poly, commitment)` that stores a
/// native polynomial in an `Option` field and its pre-computed commitment in a
/// `Cell` cache. Used for a/b/p whose commitments are computed via non-standard
/// techniques rather than lazy evaluation.
macro_rules! native_poly_with_commitment_setter {
    ($name:ident, $poly:ident, $cache:ident) => {
        pub(crate) fn $name(
            &mut self,
            poly: sparse::Polynomial<C::CircuitField, R>,
            commitment: C::HostCurve,
        ) {
            assert!(
                self.$poly.is_none(),
                concat!("double-set: ", stringify!($poly))
            );
            self.$poly = Some(poly);
            assert!(
                self.$cache.set(commitment).is_ok(),
                concat!("double-set: ", stringify!($cache))
            );
        }
    };
}

/// Produces `pub(crate) fn $getter(&self) -> C::HostCurve` that reads a
/// pre-computed native commitment from a `Cell`. Used for a/b/p whose
/// commitments are set explicitly via a special setter rather than lazily.
macro_rules! explicit_commitment_getter {
    ($getter:ident, $cache:ident, $setter:ident) => {
        pub(crate) fn $getter(&self) -> C::HostCurve {
            *self.$cache.get().expect(concat!(
                stringify!($cache),
                " not set (call ",
                stringify!($setter),
                " first)"
            ))
        }
    };
}

/// Produces `pub(crate) fn $rx(&self) -> Result<&sparse::Polynomial<...>>`
/// and `pub(crate) fn $commitment(&self) -> Result<C::NestedCurve>` that
/// lazily derive a cached bridge. On first call, `$rx` builds a
/// `nested::stages::$stage::Witness` from the given getter methods, derives
/// the bridge rx polynomial via `Stage::rx`, and caches it; `$commitment`
/// then commits the rx and caches the result. Subsequent calls return the
/// cached values.
///
/// Witness fields are specified as `field: getter()` pairs — the macro
/// prepends `self.` to each getter call so that the generated function's own
/// `self` is used (avoiding macro hygiene issues with `self` in token trees).
macro_rules! cached_bridge {
    ($rx:ident, $commitment:ident,
     $idx:expr, $stage:ident, { $($wit_field:ident : $getter:ident()),* }) => {
        pub(crate) fn $rx(&self) -> Result<&sparse::Polynomial<C::ScalarField, R>> {
            if let Some(rx) = self.$rx.get() {
                return Ok(rx);
            }
            let rx = nested::stages::$stage::Stage::<C::HostCurve, R>::rx(
                self.bridge_alpha_power($idx),
                &nested::stages::$stage::Witness {
                    $($wit_field: self.$getter()),*
                },
            )?;
            // The early return above guarantees the cell is empty, so
            // `get_or_init` will always run the closure and store `rx`.
            Ok(self.$rx.get_or_init(|| rx))
        }

        pub(crate) fn $commitment(&self) -> Result<C::NestedCurve> {
            let rx = self.$rx()?;
            Ok(*self.$commitment.get_or_init(|| {
                rx.commit_to_affine(C::nested_generators(self.params))
            }))
        }
    };
}

/// Builder for incremental [`Proof`] construction.
///
/// Native commitment caches are computed lazily from polynomials on first
/// access. Special commitments (`a`, `b`, `p`) must be provided explicitly
/// because they are computed via non-standard techniques.
pub(crate) struct ProofBuilder<'params, C: Cycle, R: Rank> {
    params: &'params C::Params,

    /// Shared alpha source for the four cached bridge commitments.
    bridge_alpha: C::ScalarField,

    // Application metadata
    circuit_id: Option<CircuitIndex>,
    left_header: Option<Vec<C::CircuitField>>,
    right_header: Option<Vec<C::CircuitField>>,

    // Native rx polynomials
    native_application_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_preamble_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_inner_error_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_outer_error_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_a_poly: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_b_poly: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_query_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_registry_xy_poly: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_eval_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_p_poly: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_hashes_1_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_hashes_2_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_inner_collapse_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_outer_collapse_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_compute_v_rx: Option<sparse::Polynomial<C::CircuitField, R>>,

    // Bridge rx polynomials + commitments (set together by caller)
    bridge_preamble_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    bridge_preamble_commitment: Option<C::NestedCurve>,
    bridge_s_prime_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    bridge_s_prime_commitment: Option<C::NestedCurve>,
    bridge_inner_error_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    bridge_inner_error_commitment: Option<C::NestedCurve>,
    bridge_f_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    bridge_f_commitment: Option<C::NestedCurve>,

    // Cached bridge rx polynomials (lazily derived from `bridge_alpha` +
    // native commitments). Parallels the native rx/commitment split: the rx
    // slot is populated on first access, and the commitment slot is derived
    // lazily from it.
    bridge_outer_error_rx: OnceCell<sparse::Polynomial<C::ScalarField, R>>,
    bridge_ab_rx: OnceCell<sparse::Polynomial<C::ScalarField, R>>,
    bridge_query_rx: OnceCell<sparse::Polynomial<C::ScalarField, R>>,
    bridge_eval_rx: OnceCell<sparse::Polynomial<C::ScalarField, R>>,

    // Nested endoscaling data
    nested_endoscaling_step_rxs: Option<Vec<sparse::Polynomial<C::ScalarField, R>>>,
    nested_endoscalar_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    nested_points_rx: Option<sparse::Polynomial<C::ScalarField, R>>,

    // Nested endoscaling commitment caches (lazily computed from polynomials)
    nested_endoscaling_step_commitments: OnceCell<Vec<C::NestedCurve>>,
    nested_endoscalar_commitment: OnceCell<C::NestedCurve>,
    nested_points_commitment: OnceCell<C::NestedCurve>,

    // Challenges
    w: Option<C::CircuitField>,
    y: Option<C::CircuitField>,
    z: Option<C::CircuitField>,
    mu: Option<C::CircuitField>,
    nu: Option<C::CircuitField>,
    mu_prime: Option<C::CircuitField>,
    nu_prime: Option<C::CircuitField>,
    x: Option<C::CircuitField>,
    alpha: Option<C::CircuitField>,
    u: Option<C::CircuitField>,
    pre_beta: Option<C::CircuitField>,

    // Native commitment caches (lazily computed from polynomials)
    native_application_commitment: OnceCell<C::HostCurve>,
    native_preamble_commitment: OnceCell<C::HostCurve>,
    native_inner_error_commitment: OnceCell<C::HostCurve>,
    native_outer_error_commitment: OnceCell<C::HostCurve>,
    native_a_commitment: OnceCell<C::HostCurve>,
    native_b_commitment: OnceCell<C::HostCurve>,
    native_query_commitment: OnceCell<C::HostCurve>,
    native_registry_xy_commitment: OnceCell<C::HostCurve>,
    native_eval_commitment: OnceCell<C::HostCurve>,
    native_p_commitment: OnceCell<C::HostCurve>,
    native_hashes_1_commitment: OnceCell<C::HostCurve>,
    native_hashes_2_commitment: OnceCell<C::HostCurve>,
    native_inner_collapse_commitment: OnceCell<C::HostCurve>,
    native_outer_collapse_commitment: OnceCell<C::HostCurve>,
    native_compute_v_commitment: OnceCell<C::HostCurve>,

    // Cached bridge commitment caches (lazily computed from their cached rxs)
    bridge_outer_error_commitment: OnceCell<C::NestedCurve>,
    bridge_ab_commitment: OnceCell<C::NestedCurve>,
    bridge_query_commitment: OnceCell<C::NestedCurve>,
    bridge_eval_commitment: OnceCell<C::NestedCurve>,

    // Children's stage rx (for copying circuit claims)
    child_left_stage_rx: Option<super::ChildStageRx<C::ScalarField, R>>,
    child_right_stage_rx: Option<super::ChildStageRx<C::ScalarField, R>>,
}

impl<'params, C: Cycle, R: Rank> ProofBuilder<'params, C, R> {
    /// Create a new empty builder with the given `bridge_alpha` source for
    /// deriving cached bridge polynomial alphas.
    pub(crate) fn new(params: &'params C::Params, bridge_alpha: C::ScalarField) -> Self {
        Self {
            params,
            bridge_alpha,
            circuit_id: None,
            left_header: None,
            right_header: None,
            native_application_rx: None,
            native_preamble_rx: None,
            native_inner_error_rx: None,
            native_outer_error_rx: None,
            native_a_poly: None,
            native_b_poly: None,
            native_query_rx: None,
            native_registry_xy_poly: None,
            native_eval_rx: None,
            native_p_poly: None,
            native_hashes_1_rx: None,
            native_hashes_2_rx: None,
            native_inner_collapse_rx: None,
            native_outer_collapse_rx: None,
            native_compute_v_rx: None,
            bridge_preamble_rx: None,
            bridge_preamble_commitment: None,
            bridge_s_prime_rx: None,
            bridge_s_prime_commitment: None,
            bridge_inner_error_rx: None,
            bridge_inner_error_commitment: None,
            bridge_f_rx: None,
            bridge_f_commitment: None,
            bridge_outer_error_rx: OnceCell::new(),
            bridge_ab_rx: OnceCell::new(),
            bridge_query_rx: OnceCell::new(),
            bridge_eval_rx: OnceCell::new(),
            nested_endoscaling_step_rxs: None,
            nested_endoscalar_rx: None,
            nested_points_rx: None,
            nested_endoscaling_step_commitments: OnceCell::new(),
            nested_endoscalar_commitment: OnceCell::new(),
            nested_points_commitment: OnceCell::new(),
            w: None,
            y: None,
            z: None,
            mu: None,
            nu: None,
            mu_prime: None,
            nu_prime: None,
            x: None,
            alpha: None,
            u: None,
            pre_beta: None,
            native_application_commitment: OnceCell::new(),
            native_preamble_commitment: OnceCell::new(),
            native_inner_error_commitment: OnceCell::new(),
            native_outer_error_commitment: OnceCell::new(),
            native_a_commitment: OnceCell::new(),
            native_b_commitment: OnceCell::new(),
            native_query_commitment: OnceCell::new(),
            native_registry_xy_commitment: OnceCell::new(),
            native_eval_commitment: OnceCell::new(),
            native_p_commitment: OnceCell::new(),
            native_hashes_1_commitment: OnceCell::new(),
            native_hashes_2_commitment: OnceCell::new(),
            native_inner_collapse_commitment: OnceCell::new(),
            native_outer_collapse_commitment: OnceCell::new(),
            native_compute_v_commitment: OnceCell::new(),
            bridge_outer_error_commitment: OnceCell::new(),
            bridge_ab_commitment: OnceCell::new(),
            bridge_query_commitment: OnceCell::new(),
            bridge_eval_commitment: OnceCell::new(),
            child_left_stage_rx: None,
            child_right_stage_rx: None,
        }
    }

    /// Returns a reference to the params.
    pub(crate) fn params(&self) -> &C::Params {
        self.params
    }

    setter!(set_circuit_id, circuit_id, CircuitIndex);
    setter!(set_left_header, left_header, Vec<C::CircuitField>);
    setter!(set_right_header, right_header, Vec<C::CircuitField>);

    slice_getter!(left_header, left_header, C::CircuitField);
    slice_getter!(right_header, right_header, C::CircuitField);

    native_setter!(set_native_application_rx, native_application_rx);
    native_setter!(set_native_preamble_rx, native_preamble_rx);
    native_setter!(set_native_inner_error_rx, native_inner_error_rx);
    native_setter!(set_native_outer_error_rx, native_outer_error_rx);
    native_setter!(set_native_query_rx, native_query_rx);
    native_setter!(set_native_registry_xy_poly, native_registry_xy_poly);
    native_setter!(set_native_eval_rx, native_eval_rx);
    native_setter!(set_native_hashes_1_rx, native_hashes_1_rx);
    native_setter!(set_native_hashes_2_rx, native_hashes_2_rx);
    native_setter!(set_native_inner_collapse_rx, native_inner_collapse_rx);
    native_setter!(set_native_outer_collapse_rx, native_outer_collapse_rx);
    native_setter!(set_native_compute_v_rx, native_compute_v_rx);

    native_poly_with_commitment_setter!(set_native_a_poly, native_a_poly, native_a_commitment);
    native_poly_with_commitment_setter!(set_native_b_poly, native_b_poly, native_b_commitment);
    native_poly_with_commitment_setter!(set_native_p_poly, native_p_poly, native_p_commitment);

    ref_getter!(native_a_poly, native_a_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(native_b_poly, native_b_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(native_registry_xy_poly, native_registry_xy_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(native_p_poly, native_p_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(nested_points_rx, nested_points_rx, sparse::Polynomial<C::ScalarField, R>);
    ref_getter!(bridge_s_prime_rx, bridge_s_prime_rx, sparse::Polynomial<C::ScalarField, R>);
    ref_getter!(bridge_inner_error_rx, bridge_inner_error_rx, sparse::Polynomial<C::ScalarField, R>);

    lazy_commitment!(
        native,
        native_application_commitment,
        native_application_commitment,
        native_application_rx
    );
    lazy_commitment!(
        native,
        native_preamble_commitment,
        native_preamble_commitment,
        native_preamble_rx
    );
    lazy_commitment!(
        native,
        native_inner_error_commitment,
        native_inner_error_commitment,
        native_inner_error_rx
    );
    lazy_commitment!(
        native,
        native_outer_error_commitment,
        native_outer_error_commitment,
        native_outer_error_rx
    );
    lazy_commitment!(
        native,
        native_query_commitment,
        native_query_commitment,
        native_query_rx
    );
    lazy_commitment!(
        native,
        native_registry_xy_commitment,
        native_registry_xy_commitment,
        native_registry_xy_poly
    );
    lazy_commitment!(
        native,
        native_eval_commitment,
        native_eval_commitment,
        native_eval_rx
    );
    lazy_commitment!(
        native,
        native_hashes_1_commitment,
        native_hashes_1_commitment,
        native_hashes_1_rx
    );
    lazy_commitment!(
        native,
        native_hashes_2_commitment,
        native_hashes_2_commitment,
        native_hashes_2_rx
    );
    lazy_commitment!(
        native,
        native_inner_collapse_commitment,
        native_inner_collapse_commitment,
        native_inner_collapse_rx
    );
    lazy_commitment!(
        native,
        native_outer_collapse_commitment,
        native_outer_collapse_commitment,
        native_outer_collapse_rx
    );
    lazy_commitment!(
        native,
        native_compute_v_commitment,
        native_compute_v_commitment,
        native_compute_v_rx
    );

    explicit_commitment_getter!(native_a_commitment, native_a_commitment, set_native_a_poly);
    explicit_commitment_getter!(native_b_commitment, native_b_commitment, set_native_b_poly);
    explicit_commitment_getter!(native_p_commitment, native_p_commitment, set_native_p_poly);

    bridge_pair!(
        set_bridge_preamble_rx,
        bridge_preamble_commitment,
        bridge_preamble_rx,
        bridge_preamble_commitment
    );
    bridge_pair!(
        set_bridge_s_prime_rx,
        bridge_s_prime_commitment,
        bridge_s_prime_rx,
        bridge_s_prime_commitment
    );
    bridge_pair!(
        set_bridge_inner_error_rx,
        bridge_inner_error_commitment,
        bridge_inner_error_rx,
        bridge_inner_error_commitment
    );
    bridge_pair!(
        set_bridge_f_rx,
        bridge_f_commitment,
        bridge_f_rx,
        bridge_f_commitment
    );

    /// Returns the derived alpha for a cached bridge, as a distinct power of
    /// `bridge_alpha`.
    fn bridge_alpha_power(&self, idx: nested::RxIndex) -> C::ScalarField {
        let n = match idx {
            nested::RxIndex::BridgeOuterError => 1,
            nested::RxIndex::BridgeAB => 2,
            nested::RxIndex::BridgeQuery => 3,
            nested::RxIndex::BridgeEval => 4,
            _ => panic!("not a cached bridge: {idx:?}"),
        };
        self.bridge_alpha.pow_vartime([n])
    }

    cached_bridge!(
        bridge_outer_error_rx,
        bridge_outer_error_commitment,
        nested::RxIndex::BridgeOuterError,
        outer_error,
        { native_outer_error: native_outer_error_commitment() }
    );

    cached_bridge!(
        bridge_ab_rx,
        bridge_ab_commitment,
        nested::RxIndex::BridgeAB,
        ab,
        { a: native_a_commitment(), b: native_b_commitment() }
    );

    cached_bridge!(
        bridge_query_rx,
        bridge_query_commitment,
        nested::RxIndex::BridgeQuery,
        query,
        { native_query: native_query_commitment(), registry_xy: native_registry_xy_commitment() }
    );

    cached_bridge!(
        bridge_eval_rx,
        bridge_eval_commitment,
        nested::RxIndex::BridgeEval,
        eval,
        { native_eval: native_eval_commitment() }
    );

    setter!(
        set_nested_endoscaling_step_rxs,
        nested_endoscaling_step_rxs,
        Vec<sparse::Polynomial<C::ScalarField, R>>
    );
    setter!(set_nested_endoscalar_rx, nested_endoscalar_rx, sparse::Polynomial<C::ScalarField, R>);
    setter!(set_nested_points_rx, nested_points_rx, sparse::Polynomial<C::ScalarField, R>);

    /// Lazily computes and caches commitments for all endoscaling step rx
    /// polynomials. Returns the cached slice.
    pub(crate) fn nested_endoscaling_step_commitments(&self) -> &[C::NestedCurve] {
        self.nested_endoscaling_step_commitments.get_or_init(|| {
            let nested_gen = C::nested_generators(self.params);
            self.nested_endoscaling_step_rxs
                .as_ref()
                .expect("nested_endoscaling_step_rxs not set")
                .iter()
                .map(|rx| rx.commit_to_affine(nested_gen))
                .collect()
        })
    }

    lazy_commitment!(
        nested,
        nested_endoscalar_commitment,
        nested_endoscalar_commitment,
        nested_endoscalar_rx
    );
    lazy_commitment!(
        nested,
        nested_points_commitment,
        nested_points_commitment,
        nested_points_rx
    );

    setter!(set_w, w, C::CircuitField);
    setter!(set_y, y, C::CircuitField);
    setter!(set_z, z, C::CircuitField);
    setter!(set_mu, mu, C::CircuitField);
    setter!(set_nu, nu, C::CircuitField);
    setter!(set_mu_prime, mu_prime, C::CircuitField);
    setter!(set_nu_prime, nu_prime, C::CircuitField);
    setter!(set_x, x, C::CircuitField);
    setter!(set_alpha, alpha, C::CircuitField);
    setter!(set_u, u, C::CircuitField);
    setter!(set_pre_beta, pre_beta, C::CircuitField);

    setter!(
        set_child_left_stage_rx,
        child_left_stage_rx,
        super::ChildStageRx<C::ScalarField, R>
    );
    setter!(
        set_child_right_stage_rx,
        child_right_stage_rx,
        super::ChildStageRx<C::ScalarField, R>
    );

    getter!(w, w, C::CircuitField);
    getter!(y, y, C::CircuitField);
    getter!(z, z, C::CircuitField);
    getter!(mu, mu, C::CircuitField);
    getter!(nu, nu, C::CircuitField);
    getter!(mu_prime, mu_prime, C::CircuitField);
    getter!(nu_prime, nu_prime, C::CircuitField);
    getter!(x, x, C::CircuitField);
    getter!(alpha, alpha, C::CircuitField);
    getter!(u, u, C::CircuitField);
    getter!(pre_beta, pre_beta, C::CircuitField);

    /// Returns the revdot product $c = \text{revdot}(A, B)$.
    pub(crate) fn c(&self) -> C::CircuitField {
        self.native_a_poly().revdot(self.native_b_poly())
    }

    /// Returns the evaluation $v = p(u)$.
    pub(crate) fn v(&self) -> C::CircuitField {
        self.native_p_poly().eval(self.u())
    }

    /// Build the proof. All polynomial fields must have been set. Commitment
    /// caches that haven't been accessed yet are computed now.
    pub(crate) fn build(mut self) -> Result<Proof<C, R>> {
        // Force lazy evaluation of every native commitment cache by invoking
        // its getter. The a/b/p caches are set externally via their explicit
        // setters, so they are not touched here.
        self.native_application_commitment();
        self.native_preamble_commitment();
        self.native_inner_error_commitment();
        self.native_outer_error_commitment();
        self.native_query_commitment();
        self.native_registry_xy_commitment();
        self.native_eval_commitment();
        self.native_hashes_1_commitment();
        self.native_hashes_2_commitment();
        self.native_inner_collapse_commitment();
        self.native_outer_collapse_commitment();
        self.native_compute_v_commitment();

        // Force lazy evaluation of cached bridge commitments.
        self.bridge_outer_error_commitment()?;
        self.bridge_ab_commitment()?;
        self.bridge_query_commitment()?;
        self.bridge_eval_commitment()?;

        // Ensure nested endoscaling commitment caches are populated.
        self.nested_endoscaling_step_commitments();
        self.nested_endoscalar_commitment();
        self.nested_points_commitment();

        macro_rules! take {
            ($field:ident) => {
                self.$field.expect(concat!(stringify!($field), " not set"))
            };
        }

        macro_rules! cached {
            ($field:ident) => {
                Cached(
                    self.$field
                        .take()
                        .expect(concat!(stringify!($field), " not set")),
                )
            };
        }

        Ok(Proof {
            bridge_alpha: self.bridge_alpha,

            circuit_id: take!(circuit_id),
            left_header: take!(left_header),
            right_header: take!(right_header),

            native_application_rx: take!(native_application_rx),
            native_preamble_rx: take!(native_preamble_rx),
            native_inner_error_rx: take!(native_inner_error_rx),
            native_outer_error_rx: take!(native_outer_error_rx),
            native_a_poly: take!(native_a_poly),
            native_b_poly: take!(native_b_poly),
            native_query_rx: take!(native_query_rx),
            native_registry_xy_poly: take!(native_registry_xy_poly),
            native_eval_rx: take!(native_eval_rx),
            native_p_poly: take!(native_p_poly),
            native_hashes_1_rx: take!(native_hashes_1_rx),
            native_hashes_2_rx: take!(native_hashes_2_rx),
            native_inner_collapse_rx: take!(native_inner_collapse_rx),
            native_outer_collapse_rx: take!(native_outer_collapse_rx),
            native_compute_v_rx: take!(native_compute_v_rx),

            bridge_preamble_rx: take!(bridge_preamble_rx),
            bridge_preamble_commitment: take!(bridge_preamble_commitment),
            bridge_s_prime_rx: take!(bridge_s_prime_rx),
            bridge_s_prime_commitment: take!(bridge_s_prime_commitment),
            bridge_inner_error_rx: take!(bridge_inner_error_rx),
            bridge_inner_error_commitment: take!(bridge_inner_error_commitment),
            bridge_f_rx: take!(bridge_f_rx),
            bridge_f_commitment: take!(bridge_f_commitment),

            bridge_outer_error_rx: cached!(bridge_outer_error_rx),
            bridge_outer_error_commitment: cached!(bridge_outer_error_commitment),
            bridge_ab_rx: cached!(bridge_ab_rx),
            bridge_ab_commitment: cached!(bridge_ab_commitment),
            bridge_query_rx: cached!(bridge_query_rx),
            bridge_query_commitment: cached!(bridge_query_commitment),
            bridge_eval_rx: cached!(bridge_eval_rx),
            bridge_eval_commitment: cached!(bridge_eval_commitment),

            nested_endoscaling_step_rxs: take!(nested_endoscaling_step_rxs),
            nested_endoscalar_rx: take!(nested_endoscalar_rx),
            nested_points_rx: take!(nested_points_rx),

            nested_endoscaling_step_commitments: self
                .nested_endoscaling_step_commitments
                .take()
                .expect("nested_endoscaling_step_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            nested_endoscalar_commitment: cached!(nested_endoscalar_commitment),
            nested_points_commitment: cached!(nested_points_commitment),

            w: take!(w),
            y: take!(y),
            z: take!(z),
            mu: take!(mu),
            nu: take!(nu),
            mu_prime: take!(mu_prime),
            nu_prime: take!(nu_prime),
            x: take!(x),
            alpha: take!(alpha),
            u: take!(u),
            pre_beta: take!(pre_beta),

            native_application_commitment: cached!(native_application_commitment),
            native_preamble_commitment: cached!(native_preamble_commitment),
            native_inner_error_commitment: cached!(native_inner_error_commitment),
            native_outer_error_commitment: cached!(native_outer_error_commitment),
            native_a_commitment: cached!(native_a_commitment),
            native_b_commitment: cached!(native_b_commitment),
            native_query_commitment: cached!(native_query_commitment),
            native_registry_xy_commitment: cached!(native_registry_xy_commitment),
            native_eval_commitment: cached!(native_eval_commitment),
            native_p_commitment: cached!(native_p_commitment),
            native_hashes_1_commitment: cached!(native_hashes_1_commitment),
            native_hashes_2_commitment: cached!(native_hashes_2_commitment),
            native_inner_collapse_commitment: cached!(native_inner_collapse_commitment),
            native_outer_collapse_commitment: cached!(native_outer_collapse_commitment),
            native_compute_v_commitment: cached!(native_compute_v_commitment),

            child_left_stage_rx: take!(child_left_stage_rx),
            child_right_stage_rx: take!(child_right_stage_rx),
        })
    }
}
