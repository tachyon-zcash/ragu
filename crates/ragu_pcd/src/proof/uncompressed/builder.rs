//! [`ProofBuilder`] for incremental proof construction.
//!
//! Polynomial setters store values immediately. Native commitment caches are
//! computed lazily on first access via [`OnceCell`]-based interior mutability.
//! The "simple" `ab` bridge commitment is also lazily computed from
//! [`bridge_alpha`](ProofBuilder::bridge_alpha) and the native commitments
//! already on the builder.

use alloc::{sync::Arc, vec::Vec};
use core::cell::OnceCell;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_core::{Cycle, Result};
use ragu_primitives::vec::{FixedVec, Len};
use udon::{curve::Affine, field::Field};

use super::{Cached, Proof};
use crate::{
    backend::committer::Committer,
    header::NUM_ONLINE_FP_POLYS,
    internal::{native::online, nested},
    profile::{
        Profile, ProfiledCycle,
        online::stages::{Native, Nested, Present},
    },
};

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
/// the builder's committer. The `native` / `nested` prefix selects the curve
/// type and the corresponding committer.
macro_rules! lazy_commitment {
    (native, $getter:ident, $cache:ident, $poly:ident) => {
        lazy_commitment!(@impl $getter, $cache, $poly, C::HostCurve, host);
    };
    (nested, $getter:ident, $cache:ident, $poly:ident) => {
        lazy_commitment!(@impl $getter, $cache, $poly, C::NestedCurve, nested);
    };
    (@impl $getter:ident, $cache:ident, $poly:ident, $curve:ty, $committer:ident) => {
        pub(crate) fn $getter(&self) -> $curve {
            *self.$cache.get_or_init(|| {
                self.$committer.commit(
                    self.$poly
                        .as_ref()
                        .expect(concat!(stringify!($poly), " not set")),
                )
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
            self.$rx = Some(Arc::new(rx));
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
/// `OnceCell` cache. Used for a/b/p whose commitments are computed via non-standard
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
/// pre-computed native commitment from a `OnceCell`. Used for a/b/p whose
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

/// Produces `pub(crate) fn $rx(&self) -> Result<&Arc<sparse::Polynomial<...>>>`
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
     $idx:expr, $stage:ident, { $($wit_field:ident : $getter:ident $(::<$phase:literal>)?()),* }) => {
        pub(crate) fn $rx(&self) -> Result<&Arc<sparse::Polynomial<C::ScalarField, R>>> {
            if let Some(rx) = self.$rx.get() {
                return Ok(rx);
            }
            let rx = nested::stages::$stage::Stage::<C::HostCurve, R, C::Profile>::rx(
                self.bridge_alpha_power($idx),
                &nested::stages::$stage::Witness {
                    $($wit_field: self.$getter$(::<$phase>)?()),*
                },
            )?;
            // The early return above guarantees the cell is empty, so
            // `get_or_init` will always run the closure and store `rx`.
            Ok(self.$rx.get_or_init(|| Arc::new(rx)))
        }

        pub(crate) fn $commitment(&self) -> Result<C::NestedCurve> {
            let rx = self.$rx()?;
            Ok(*self.$commitment.get_or_init(|| self.nested.commit(rx)))
        }
    };
}

/// Builder for incremental [`Proof`] construction.
///
/// Native commitment caches are computed lazily from polynomials on first
/// access. Special commitments (`a`, `b`, `p`) must be provided explicitly
/// because they are computed via non-standard techniques.
pub(crate) struct ProofBuilder<'params, C: ProfiledCycle, R: Rank, B: Backend> {
    params: &'params C::Params,
    /// What the proof's host-curve commitments are computed with.
    host: &'params Committer<'params, C::HostCurve, C::HostGenerators, B>,
    /// What the proof's nested-curve commitments are computed with.
    nested: &'params Committer<'params, C::NestedCurve, C::NestedGenerators, B>,

    /// Shared alpha source for the cached `ab` bridge commitment.
    bridge_alpha: C::ScalarField,

    // Application metadata. Only the circuit id goes into the proof: the
    // headers are the step's own, read by its preamble and challenge stage.
    circuit_id: Option<CircuitIndex>,
    left_header: Option<Vec<C::CircuitField>>,
    right_header: Option<Vec<C::CircuitField>>,
    output_header: Option<Vec<C::CircuitField>>,
    /// The header a test's prover stages its left child's bridge $k(y)$
    /// over, in place of its preamble's copy (see
    /// [`forge_left_bridge_header`](Self::forge_left_bridge_header)).
    #[cfg(test)]
    forged_left_bridge_header: Option<Vec<C::CircuitField>>,

    // Native rx polynomials
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
    native_collapse_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_compute_v_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_bind_challenges_rxs: Option<Vec<sparse::Polynomial<C::CircuitField, R>>>,
    native_bind_beta_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_bind_endoscalar_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_endoscaling_step_rxs: Option<Vec<sparse::Polynomial<C::CircuitField, R>>>,
    native_extension_circuit_rxs: Option<Vec<sparse::Polynomial<C::CircuitField, R>>>,
    native_extension_stage_rxs: Option<Vec<sparse::Polynomial<C::CircuitField, R>>>,
    native_points_binding_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_points_preamble_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_points_registry_wx_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_points_ab_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_points_f_rx: Option<sparse::Polynomial<C::CircuitField, R>>,
    native_points_walk_rx: Option<sparse::Polynomial<C::CircuitField, R>>,

    // The step's own online polynomials, with their commitments cached.
    online_polynomials: Option<[sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_POLYS]>,
    online_commitments: OnceCell<[C::HostCurve; NUM_ONLINE_FP_POLYS]>,
    online_openings: Option<online::Queries<C::CircuitField>>,

    // Online polynomial preparation, discarded after this step's PCS fold.
    // The fuse begins both sides' for every profile; the synthetic bootstrap
    // proof has neither.
    native_online: Option<NativeOnline<C, R>>,
    nested_online: Option<NestedOnline<C, R>>,

    // The synthetic bootstrap proof's outgoing source polynomials and
    // explicit commitments, which it has no online prover state to take
    // from. Ordinary proofs take theirs from their state.
    pub(crate) native_source_out: Vec<sparse::Polynomial<C::CircuitField, R>>,
    pub(crate) nested_source_out: Vec<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) dummy_native_online_commitments: Option<Vec<C::HostCurve>>,
    pub(crate) dummy_nested_online_commitments: Option<Vec<C::NestedCurve>>,

    // The step's own online Fq polynomials, with their commitments cached.
    // The proof does not carry the polynomials: only this step's nested
    // batch opens them. It carries the commitments and openings the step
    // exports.
    online_fq_polynomials: Option<Vec<sparse::Polynomial<C::ScalarField, R>>>,
    online_fq_commitments: OnceCell<Vec<C::NestedCurve>>,
    // The openings the step exports of them: the point then the value of
    // each slot the profile's nested binding names.
    online_fq_openings: Option<Vec<C::ScalarField>>,

    // Bridge rx polynomials + commitments (set together by caller)
    bridge_preamble_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_preamble_commitment: Option<C::NestedCurve>,
    bridge_hash_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_hash_commitment: Option<C::NestedCurve>,
    bridge_s_prime_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_s_prime_commitment: Option<C::NestedCurve>,
    bridge_inner_error_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_inner_error_commitment: Option<C::NestedCurve>,
    bridge_outer_error_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_outer_error_commitment: Option<C::NestedCurve>,
    bridge_query_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_query_commitment: Option<C::NestedCurve>,
    bridge_f_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_f_commitment: Option<C::NestedCurve>,
    bridge_eval_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    bridge_eval_commitment: Option<C::NestedCurve>,

    // Cached bridge rx polynomial (lazily derived from `bridge_alpha` +
    // native commitments). Parallels the native rx/commitment split: the rx
    // slot is populated on first access, and the commitment slot is derived
    // lazily from it.
    bridge_ab_rx: OnceCell<Arc<sparse::Polynomial<C::ScalarField, R>>>,

    // Nested endoscaling data
    nested_endoscaling_step_rxs: Option<Vec<sparse::Polynomial<C::ScalarField, R>>>,
    nested_extension_circuit_rxs: Option<Vec<sparse::Polynomial<C::ScalarField, R>>>,
    nested_extension_stage_rxs: Option<Vec<sparse::Polynomial<C::ScalarField, R>>>,
    nested_endoscalar_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    nested_points_rx: Option<Arc<sparse::Polynomial<C::ScalarField, R>>>,
    // The polynomials a nested walk of several segments adds, held between
    // the walk and the extension's prover, which appends them to the
    // extension's stages: empty for a walk of one segment.
    nested_walk_stage_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    // The native walk's, likewise.
    native_walk_stage_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,

    // Nested accumulator polynomials
    nested_a_poly: Option<sparse::Polynomial<C::ScalarField, R>>,
    nested_b_poly: Option<sparse::Polynomial<C::ScalarField, R>>,

    // Nested batch polynomials
    nested_registry_xy_poly: Option<sparse::Polynomial<C::ScalarField, R>>,
    nested_p_poly: Option<sparse::Polynomial<C::ScalarField, R>>,

    // Nested challenge stage, and its commitment without the beta term
    nested_challenges_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    nested_challenges_partial: Option<C::NestedCurve>,

    // Nested instance circuits
    nested_collapse_rx: Option<sparse::Polynomial<C::ScalarField, R>>,
    nested_compute_v_rx: Option<sparse::Polynomial<C::ScalarField, R>>,

    // Nested endoscaling commitment caches (lazily computed from polynomials)
    nested_endoscaling_step_commitments: OnceCell<Vec<C::NestedCurve>>,
    nested_extension_circuit_commitments: OnceCell<Vec<C::NestedCurve>>,
    nested_extension_stage_commitments: OnceCell<Vec<C::NestedCurve>>,
    nested_endoscalar_commitment: OnceCell<C::NestedCurve>,
    nested_points_commitment: OnceCell<C::NestedCurve>,

    // Nested accumulator commitment caches (lazily computed from polynomials)
    nested_a_commitment: OnceCell<C::NestedCurve>,
    nested_b_commitment: OnceCell<C::NestedCurve>,

    // Nested batch commitment caches (lazily computed from polynomials)
    nested_registry_xy_commitment: OnceCell<C::NestedCurve>,
    nested_p_commitment: OnceCell<C::NestedCurve>,

    // Nested challenge stage commitment cache
    nested_challenges_commitment: OnceCell<C::NestedCurve>,

    // Nested instance circuit commitment caches
    nested_collapse_commitment: OnceCell<C::NestedCurve>,
    nested_compute_v_commitment: OnceCell<C::NestedCurve>,

    // Challenges
    w: Option<C::CircuitField>,
    y: Option<C::CircuitField>,
    z: Option<C::CircuitField>,
    mu: Option<C::CircuitField>,
    mu_prime: Option<C::CircuitField>,
    x: Option<C::CircuitField>,
    alpha: Option<C::CircuitField>,
    u: Option<C::CircuitField>,
    pre_beta: Option<C::CircuitField>,

    // Native commitment caches (lazily computed from polynomials)
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
    native_collapse_commitment: OnceCell<C::HostCurve>,
    native_compute_v_commitment: OnceCell<C::HostCurve>,
    native_bind_challenges_commitments: OnceCell<Vec<C::HostCurve>>,
    native_bind_beta_commitment: OnceCell<C::HostCurve>,
    native_bind_endoscalar_commitment: OnceCell<C::HostCurve>,
    native_endoscaling_step_commitments: OnceCell<Vec<C::HostCurve>>,
    native_extension_circuit_commitments: OnceCell<Vec<C::HostCurve>>,
    native_extension_stage_commitments: OnceCell<Vec<C::HostCurve>>,
    native_points_binding_commitment: OnceCell<C::HostCurve>,
    native_points_preamble_commitment: OnceCell<C::HostCurve>,
    native_points_registry_wx_commitment: OnceCell<C::HostCurve>,
    native_points_ab_commitment: OnceCell<C::HostCurve>,
    native_points_f_commitment: OnceCell<C::HostCurve>,
    native_points_walk_commitment: OnceCell<C::HostCurve>,

    // Cached bridge commitment cache (lazily computed from its cached rx)
    bridge_ab_commitment: OnceCell<C::NestedCurve>,
}

/// A step's native online batch.
pub(crate) type NativeOnline<C, R> = crate::profile::online::prover::State<
    <C as Cycle>::HostCurve,
    R,
    <C as ProfiledCycle>::Profile,
    Native,
>;
/// A step's nested online batch.
pub(crate) type NestedOnline<C, R> = crate::profile::online::prover::State<
    <C as Cycle>::NestedCurve,
    R,
    <C as ProfiledCycle>::Profile,
    Nested,
>;

impl<'params, C: ProfiledCycle, R: Rank, B: Backend> ProofBuilder<'params, C, R, B> {
    // A step's online batches. The fuse sets both for every profile; the
    // bootstrap proof sets neither.
    setter!(set_native_online, native_online, NativeOnline<C, R>);
    setter!(set_nested_online, nested_online, NestedOnline<C, R>);
    ref_getter!(native_online, native_online, NativeOnline<C, R>);
    ref_getter!(nested_online, nested_online, NestedOnline<C, R>);

    /// Mutably borrows the step's native online batch.
    pub(crate) fn native_online_mut(&mut self) -> &mut NativeOnline<C, R> {
        self.native_online.as_mut().expect("native_online not set")
    }

    /// Mutably borrows the step's nested online batch.
    pub(crate) fn nested_online_mut(&mut self) -> &mut NestedOnline<C, R> {
        self.nested_online.as_mut().expect("nested_online not set")
    }

    /// The two coordinates fixed in the native query or eval stage.
    pub(crate) fn nested_online_stage_coordinates(
        &self,
        index: usize,
    ) -> ragu_primitives::vec::FixedVec<C::CircuitField, Present<C::Profile, Nested, 2>> {
        ragu_primitives::vec::FixedVec::from_fn(|i| {
            let (x, y) = self
                .nested_online_stage_commitment(index)
                .coordinates()
                .expect("online stage commitment is finite");
            [x, y][i]
        })
    }

    /// The actual online stage commitment, or the synthetic dummy's stored stage.
    pub(crate) fn nested_online_stage_commitment(&self, index: usize) -> C::NestedCurve {
        let point = self.nested_online.as_ref().map_or_else(
            || self.nested_extension_stage_commitments()[index],
            |state| state.stage_commitment(index),
        );
        #[cfg(test)]
        let point = crate::online_batch_tests::mutate_stage_commitment(index, point);
        point
    }

    /// The actual native online polynomial commitment in fold order.
    pub(crate) fn native_online_commitment(&self, index: usize) -> C::HostCurve {
        if let Some(state) = &self.native_online {
            state.commitments()[index]
        } else {
            self.dummy_native_online_commitments
                .as_ref()
                .expect("bootstrap native online commitments must be set")[index]
        }
    }

    /// Native online commitment copies fixed at one transcript deadline.
    pub(crate) fn native_online_phase<const PHASE: usize>(
        &self,
    ) -> FixedVec<
        C::HostCurve,
        crate::profile::online::stages::PhaseLen<
            C::Profile,
            crate::profile::online::stages::Native,
            PHASE,
        >,
    > {
        let points = if let Some(state) = &self.native_online {
            state.commitments()
        } else {
            self.dummy_native_online_commitments
                .as_deref()
                .expect("bootstrap native online commitments")
        };
        let points = crate::profile::online::stages::phase_points::<
            C::Profile,
            crate::profile::online::stages::Native,
            PHASE,
            _,
        >(points);
        #[cfg(test)]
        let points =
            FixedVec::from_fn(|i| crate::online_batch_tests::mutate_native_phase(PHASE, points[i]));
        points
    }

    /// Nested online commitment copies fixed at one transcript deadline.
    pub(crate) fn nested_online_phase<const PHASE: usize>(
        &self,
    ) -> FixedVec<
        C::NestedCurve,
        crate::profile::online::stages::PhaseLen<
            C::Profile,
            crate::profile::online::stages::Nested,
            PHASE,
        >,
    > {
        let points = if let Some(state) = &self.nested_online {
            state.commitments()
        } else {
            self.dummy_nested_online_commitments
                .as_deref()
                .expect("bootstrap nested online commitments")
        };
        let points = crate::profile::online::stages::phase_points::<
            C::Profile,
            crate::profile::online::stages::Nested,
            PHASE,
            _,
        >(points);
        #[cfg(test)]
        let points =
            FixedVec::from_fn(|i| crate::online_batch_tests::mutate_nested_phase(PHASE, points[i]));
        points
    }

    /// Early coordinates of nested auxiliaries, fixed in the query before alpha.
    pub(crate) fn nested_online_auxiliary_coordinates(
        &self,
    ) -> FixedVec<
        C::CircuitField,
        crate::profile::online::stages::PhaseCoordinatesLen<
            C::Profile,
            crate::profile::online::stages::Nested,
            3,
        >,
    > {
        let points = self.nested_online_phase::<3>();
        FixedVec::from_fn(|i| {
            let point = points[i / 2];
            #[cfg(test)]
            let point = crate::online_batch_tests::mutate_nested_auxiliary_query(point);
            let (x, y) = point
                .coordinates()
                .expect("a nonzero online polynomial commits to a finite point");
            [x, y][i % 2]
        })
    }

    /// Native online stage commitment fixed at its transcript deadline.
    pub(crate) fn native_online_stage_commitment(&self, index: usize) -> C::HostCurve {
        let point = self.native_online.as_ref().map_or_else(
            || self.native_extension_stage_commitments()[index],
            |state| state.stage_commitment(index),
        );
        #[cfg(test)]
        let point = crate::online_batch_tests::mutate_native_stage_commitment(index, point);
        point
    }

    /// Create a new empty builder with the given `bridge_alpha` source for
    /// deriving cached bridge polynomial alphas, committing with `host` and
    /// `nested`, which pair `params`'s generators with any tables of them.
    pub(crate) fn new(
        params: &'params C::Params,
        host: &'params Committer<'params, C::HostCurve, C::HostGenerators, B>,
        nested: &'params Committer<'params, C::NestedCurve, C::NestedGenerators, B>,
        bridge_alpha: C::ScalarField,
    ) -> Self {
        Self {
            params,
            host,
            nested,
            bridge_alpha,
            circuit_id: None,
            left_header: None,
            right_header: None,
            output_header: None,
            #[cfg(test)]
            forged_left_bridge_header: None,
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
            native_collapse_rx: None,
            native_compute_v_rx: None,
            native_bind_challenges_rxs: None,
            native_bind_beta_rx: None,
            native_bind_endoscalar_rx: None,
            native_endoscaling_step_rxs: None,
            native_extension_circuit_rxs: None,
            native_extension_stage_rxs: None,
            native_points_binding_rx: None,
            native_points_preamble_rx: None,
            native_points_registry_wx_rx: None,
            native_points_ab_rx: None,
            native_points_f_rx: None,
            native_points_walk_rx: None,
            online_polynomials: None,
            native_source_out: Vec::new(),
            nested_source_out: Vec::new(),
            dummy_nested_online_commitments: None,
            dummy_native_online_commitments: None,
            native_online: None,
            nested_online: None,
            online_fq_polynomials: None,
            online_fq_commitments: OnceCell::new(),
            online_fq_openings: None,
            online_commitments: OnceCell::new(),
            online_openings: None,
            bridge_preamble_rx: None,
            bridge_preamble_commitment: None,
            bridge_hash_rx: None,
            bridge_hash_commitment: None,
            bridge_s_prime_rx: None,
            bridge_s_prime_commitment: None,
            bridge_inner_error_rx: None,
            bridge_inner_error_commitment: None,
            bridge_outer_error_rx: None,
            bridge_outer_error_commitment: None,
            bridge_query_rx: None,
            bridge_query_commitment: None,
            bridge_f_rx: None,
            bridge_f_commitment: None,
            bridge_eval_rx: None,
            bridge_eval_commitment: None,
            bridge_ab_rx: OnceCell::new(),
            nested_endoscaling_step_rxs: None,
            nested_extension_circuit_rxs: None,
            nested_extension_stage_rxs: None,
            nested_endoscalar_rx: None,
            nested_points_rx: None,
            nested_walk_stage_rxs: Vec::new(),
            native_walk_stage_rxs: Vec::new(),
            nested_a_poly: None,
            nested_b_poly: None,
            nested_registry_xy_poly: None,
            nested_p_poly: None,
            nested_challenges_rx: None,
            nested_challenges_partial: None,
            nested_collapse_rx: None,
            nested_compute_v_rx: None,
            nested_endoscaling_step_commitments: OnceCell::new(),
            nested_extension_circuit_commitments: OnceCell::new(),
            nested_extension_stage_commitments: OnceCell::new(),
            nested_endoscalar_commitment: OnceCell::new(),
            nested_points_commitment: OnceCell::new(),
            nested_a_commitment: OnceCell::new(),
            nested_b_commitment: OnceCell::new(),
            nested_registry_xy_commitment: OnceCell::new(),
            nested_p_commitment: OnceCell::new(),
            nested_challenges_commitment: OnceCell::new(),
            nested_collapse_commitment: OnceCell::new(),
            nested_compute_v_commitment: OnceCell::new(),
            w: None,
            y: None,
            z: None,
            mu: None,
            mu_prime: None,
            x: None,
            alpha: None,
            u: None,
            pre_beta: None,
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
            native_collapse_commitment: OnceCell::new(),
            native_compute_v_commitment: OnceCell::new(),
            native_bind_challenges_commitments: OnceCell::new(),
            native_bind_beta_commitment: OnceCell::new(),
            native_bind_endoscalar_commitment: OnceCell::new(),
            native_endoscaling_step_commitments: OnceCell::new(),
            native_extension_circuit_commitments: OnceCell::new(),
            native_extension_stage_commitments: OnceCell::new(),
            native_points_binding_commitment: OnceCell::new(),
            native_points_preamble_commitment: OnceCell::new(),
            native_points_registry_wx_commitment: OnceCell::new(),
            native_points_ab_commitment: OnceCell::new(),
            native_points_f_commitment: OnceCell::new(),
            native_points_walk_commitment: OnceCell::new(),
            bridge_ab_commitment: OnceCell::new(),
        }
    }

    /// Returns a reference to the params.
    pub(crate) fn params(&self) -> &C::Params {
        self.params
    }

    setter!(set_circuit_id, circuit_id, CircuitIndex);
    getter!(circuit_id, circuit_id, CircuitIndex);

    /// Replaces the suffix of both input headers with the `Dummy` suffix,
    /// for a test playing a prover that forges the base case.
    #[cfg(test)]
    pub(crate) fn forge_dummy_inputs(&mut self) {
        use crate::header::{Dummy, Header};
        let dummy = C::CircuitField::from(<Dummy as Header<C::CircuitField>>::SUFFIX.get());
        for header in [&mut self.left_header, &mut self.right_header] {
            *header
                .as_mut()
                .and_then(|header| header.last_mut())
                .expect("input headers are set") = dummy;
        }
    }

    /// Adds `delta` to the first field of the left input header, for a test
    /// playing a prover that witnesses another input header in its preamble
    /// than the one its circuit encoded.
    #[cfg(test)]
    pub(crate) fn forge_left_header_field(&mut self, delta: C::CircuitField) {
        *self
            .left_header
            .as_mut()
            .and_then(|header| header.first_mut())
            .expect("the left input header is set") += delta;
    }

    /// Replaces the circuit id, for a test playing a prover that forges it.
    #[cfg(test)]
    pub(crate) fn forge_circuit_id(&mut self, circuit_id: CircuitIndex) {
        self.circuit_id = Some(circuit_id);
    }

    /// Sets the header the prover stages its left child's bridge $k(y)$
    /// over, for a test playing a prover whose fold targets another output
    /// header for that child than its preamble witnesses.
    #[cfg(test)]
    pub(crate) fn forge_left_bridge_header(&mut self, header: Vec<C::CircuitField>) {
        self.forged_left_bridge_header = Some(header);
    }

    /// The header set by
    /// [`forge_left_bridge_header`](Self::forge_left_bridge_header), if any.
    #[cfg(test)]
    pub(crate) fn forged_left_bridge_header(&self) -> Option<&[C::CircuitField]> {
        self.forged_left_bridge_header.as_deref()
    }

    /// Adds `delta` to the native preamble polynomial and drops its cached
    /// commitment, for a test playing a prover that swaps the stage after
    /// the `s_prime` bridge absorbed its commitment. A `delta` supported on
    /// the alpha coefficient leaves every value the stage holds as it
    /// was.
    #[cfg(test)]
    pub(crate) fn shift_native_preamble(&mut self, delta: &sparse::Polynomial<C::CircuitField, R>) {
        self.native_preamble_rx
            .as_mut()
            .expect("native_preamble_rx not set")
            .add_assign(delta);
        self.native_preamble_commitment = OnceCell::new();
    }
    setter!(set_left_header, left_header, Vec<C::CircuitField>);
    setter!(set_right_header, right_header, Vec<C::CircuitField>);
    setter!(set_output_header, output_header, Vec<C::CircuitField>);

    slice_getter!(left_header, left_header, C::CircuitField);
    slice_getter!(right_header, right_header, C::CircuitField);
    slice_getter!(output_header, output_header, C::CircuitField);

    native_setter!(set_native_preamble_rx, native_preamble_rx);
    native_setter!(set_native_inner_error_rx, native_inner_error_rx);
    native_setter!(set_native_outer_error_rx, native_outer_error_rx);
    native_setter!(set_native_query_rx, native_query_rx);
    native_setter!(set_native_registry_xy_poly, native_registry_xy_poly);
    native_setter!(set_native_eval_rx, native_eval_rx);
    native_setter!(set_native_hashes_1_rx, native_hashes_1_rx);
    native_setter!(set_native_hashes_2_rx, native_hashes_2_rx);
    native_setter!(set_native_collapse_rx, native_collapse_rx);
    native_setter!(set_native_compute_v_rx, native_compute_v_rx);
    setter!(
        set_native_bind_challenges_rxs,
        native_bind_challenges_rxs,
        Vec<sparse::Polynomial<C::CircuitField, R>>
    );

    native_setter!(set_native_bind_beta_rx, native_bind_beta_rx);
    lazy_commitment!(
        native,
        native_bind_beta_commitment,
        native_bind_beta_commitment,
        native_bind_beta_rx
    );

    native_setter!(set_native_bind_endoscalar_rx, native_bind_endoscalar_rx);
    lazy_commitment!(
        native,
        native_bind_endoscalar_commitment,
        native_bind_endoscalar_commitment,
        native_bind_endoscalar_rx
    );
    native_setter!(set_native_points_binding_rx, native_points_binding_rx);
    lazy_commitment!(
        native,
        native_points_binding_commitment,
        native_points_binding_commitment,
        native_points_binding_rx
    );
    native_setter!(set_native_points_preamble_rx, native_points_preamble_rx);
    lazy_commitment!(
        native,
        native_points_preamble_commitment,
        native_points_preamble_commitment,
        native_points_preamble_rx
    );
    native_setter!(
        set_native_points_registry_wx_rx,
        native_points_registry_wx_rx
    );
    lazy_commitment!(
        native,
        native_points_registry_wx_commitment,
        native_points_registry_wx_commitment,
        native_points_registry_wx_rx
    );
    native_setter!(set_native_points_ab_rx, native_points_ab_rx);
    lazy_commitment!(
        native,
        native_points_ab_commitment,
        native_points_ab_commitment,
        native_points_ab_rx
    );
    native_setter!(set_native_points_f_rx, native_points_f_rx);
    lazy_commitment!(
        native,
        native_points_f_commitment,
        native_points_f_commitment,
        native_points_f_rx
    );
    native_setter!(set_native_points_walk_rx, native_points_walk_rx);
    lazy_commitment!(
        native,
        native_points_walk_commitment,
        native_points_walk_commitment,
        native_points_walk_rx
    );
    setter!(
        set_native_endoscaling_step_rxs,
        native_endoscaling_step_rxs,
        Vec<sparse::Polynomial<C::CircuitField, R>>
    );
    setter!(
        set_online_polynomials,
        online_polynomials,
        [sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_POLYS]
    );
    ref_getter!(
        online_polynomials,
        online_polynomials,
        [sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_POLYS]
    );

    setter!(
        set_online_openings,
        online_openings,
        online::Queries<C::CircuitField>
    );
    ref_getter!(
        online_openings,
        online_openings,
        online::Queries<C::CircuitField>
    );

    /// Lazily computes and caches the commitments of the step's own online
    /// polynomials.
    pub(crate) fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_FP_POLYS] {
        *self.online_commitments.get_or_init(|| {
            self.host
                .commit_many(self.online_polynomials())
                .try_into()
                .expect("one commitment per online polynomial")
        })
    }
    setter!(
        set_online_fq_polynomials,
        online_fq_polynomials,
        Vec<sparse::Polynomial<C::ScalarField, R>>
    );
    slice_getter!(
        online_fq_polynomials,
        online_fq_polynomials,
        sparse::Polynomial<C::ScalarField, R>
    );

    /// Lazily computes and caches the commitments of the step's own online
    /// Fq polynomials, deterministic in their coefficients.
    pub(crate) fn online_fq_commitments(&self) -> &[C::NestedCurve] {
        self.online_fq_commitments
            .get_or_init(|| self.nested.commit_many(self.online_fq_polynomials()))
    }
    setter!(
        set_online_fq_openings,
        online_fq_openings,
        Vec<C::ScalarField>
    );
    slice_getter!(online_fq_openings, online_fq_openings, C::ScalarField);

    /// The commitments of the step's online Fq polynomials it exports: the
    /// slots the profile's native binding names, in its order.
    pub(crate) fn exported_online_fq_commitments(&self) -> Vec<C::NestedCurve> {
        let all = self.online_fq_commitments();
        nested::online::bound_commitments::<C::Profile>()
            .iter()
            .map(|&slot| all[slot as usize])
            .collect()
    }
    setter!(
        set_native_extension_circuit_rxs,
        native_extension_circuit_rxs,
        Vec<sparse::Polynomial<C::CircuitField, R>>
    );
    setter!(
        set_native_extension_stage_rxs,
        native_extension_stage_rxs,
        Vec<sparse::Polynomial<C::CircuitField, R>>
    );

    /// Lazily computes and caches the commitments of the native extension
    /// circuits' rx polynomials. Returns the cached slice.
    pub(crate) fn native_extension_circuit_commitments(&self) -> &[C::HostCurve] {
        self.native_extension_circuit_commitments.get_or_init(|| {
            self.host.commit_many(
                self.native_extension_circuit_rxs
                    .as_ref()
                    .expect("native_extension_circuit_rxs not set"),
            )
        })
    }

    /// Lazily computes and caches the commitments of the native extension
    /// stages' rx polynomials. Returns the cached slice.
    pub(crate) fn native_extension_stage_commitments(&self) -> &[C::HostCurve] {
        self.native_extension_stage_commitments.get_or_init(|| {
            self.host.commit_many(
                self.native_extension_stage_rxs
                    .as_ref()
                    .expect("native_extension_stage_rxs not set"),
            )
        })
    }

    /// Lazily computes and caches the commitments of the native endoscaling
    /// steps' rx polynomials. Returns the cached slice.
    pub(crate) fn native_endoscaling_step_commitments(&self) -> &[C::HostCurve] {
        self.native_endoscaling_step_commitments.get_or_init(|| {
            self.host.commit_many(
                self.native_endoscaling_step_rxs
                    .as_ref()
                    .expect("native_endoscaling_step_rxs not set"),
            )
        })
    }

    /// Lazily computes and caches the commitments of the nested challenge
    /// binding circuits' rx polynomials. Returns the cached slice.
    pub(crate) fn native_bind_challenges_commitments(&self) -> &[C::HostCurve] {
        self.native_bind_challenges_commitments.get_or_init(|| {
            self.host.commit_many(
                self.native_bind_challenges_rxs
                    .as_ref()
                    .expect("native_bind_challenges_rxs not set"),
            )
        })
    }

    native_poly_with_commitment_setter!(set_native_a_poly, native_a_poly, native_a_commitment);
    native_poly_with_commitment_setter!(set_native_b_poly, native_b_poly, native_b_commitment);
    native_poly_with_commitment_setter!(set_native_p_poly, native_p_poly, native_p_commitment);

    ref_getter!(native_a_poly, native_a_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(native_b_poly, native_b_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(native_registry_xy_poly, native_registry_xy_poly, sparse::Polynomial<C::CircuitField, R>);
    ref_getter!(native_p_poly, native_p_poly, sparse::Polynomial<C::CircuitField, R>);

    ref_getter!(
        nested_points_rx,
        nested_points_rx,
        Arc<sparse::Polynomial<C::ScalarField, R>>
    );
    ref_getter!(
        bridge_s_prime_rx,
        bridge_s_prime_rx,
        Arc<sparse::Polynomial<C::ScalarField, R>>
    );
    ref_getter!(
        bridge_inner_error_rx,
        bridge_inner_error_rx,
        Arc<sparse::Polynomial<C::ScalarField, R>>
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
        native_collapse_commitment,
        native_collapse_commitment,
        native_collapse_rx
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
        set_bridge_hash_rx,
        bridge_hash_commitment,
        bridge_hash_rx,
        bridge_hash_commitment
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
        set_bridge_outer_error_rx,
        bridge_outer_error_commitment,
        bridge_outer_error_rx,
        bridge_outer_error_commitment
    );
    ref_getter!(
        bridge_outer_error_rx,
        bridge_outer_error_rx,
        Arc<sparse::Polynomial<C::ScalarField, R>>
    );
    bridge_pair!(
        set_bridge_query_rx,
        bridge_query_commitment,
        bridge_query_rx,
        bridge_query_commitment
    );
    ref_getter!(
        bridge_query_rx,
        bridge_query_rx,
        Arc<sparse::Polynomial<C::ScalarField, R>>
    );
    bridge_pair!(
        set_bridge_eval_rx,
        bridge_eval_commitment,
        bridge_eval_rx,
        bridge_eval_commitment
    );
    ref_getter!(
        bridge_eval_rx,
        bridge_eval_rx,
        Arc<sparse::Polynomial<C::ScalarField, R>>
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
        super::bridge_alpha_power(self.bridge_alpha, idx)
    }

    cached_bridge!(
        bridge_ab_rx,
        bridge_ab_commitment,
        nested::RxIndex::BridgeAB,
        ab,
        {
            a: native_a_commitment(),
            b: native_b_commitment(),
            native_points_ab: native_points_ab_commitment(),
            online_points: native_online_phase::<2>()
        }
    );

    setter!(
        set_nested_extension_circuit_rxs,
        nested_extension_circuit_rxs,
        Vec<sparse::Polynomial<C::ScalarField, R>>
    );
    setter!(
        set_nested_extension_stage_rxs,
        nested_extension_stage_rxs,
        Vec<sparse::Polynomial<C::ScalarField, R>>
    );

    /// Lazily computes and caches the commitments of the nested extension
    /// circuits' rx polynomials. Returns the cached slice.
    pub(crate) fn nested_extension_circuit_commitments(&self) -> &[C::NestedCurve] {
        self.nested_extension_circuit_commitments.get_or_init(|| {
            self.nested.commit_many(
                self.nested_extension_circuit_rxs
                    .as_ref()
                    .expect("nested_extension_circuit_rxs not set"),
            )
        })
    }

    /// Lazily computes and caches the commitments of the nested extension
    /// stages' rx polynomials. Returns the cached slice.
    pub(crate) fn nested_extension_stage_commitments(&self) -> &[C::NestedCurve] {
        self.nested_extension_stage_commitments.get_or_init(|| {
            self.nested.commit_many(
                self.nested_extension_stage_rxs
                    .as_ref()
                    .expect("nested_extension_stage_rxs not set"),
            )
        })
    }

    setter!(
        set_nested_endoscaling_step_rxs,
        nested_endoscaling_step_rxs,
        Vec<sparse::Polynomial<C::ScalarField, R>>
    );
    setter!(set_nested_endoscalar_rx, nested_endoscalar_rx, sparse::Polynomial<C::ScalarField, R>);
    pub(crate) fn set_nested_points_rx(&mut self, v: sparse::Polynomial<C::ScalarField, R>) {
        assert!(
            self.nested_points_rx.is_none(),
            "double-set: nested_points_rx"
        );
        self.nested_points_rx = Some(Arc::new(v));
    }

    /// Holds the polynomials a nested walk of several segments adds, for
    /// [`take_nested_walk_stage_rxs`](Self::take_nested_walk_stage_rxs) to
    /// hand to the nested extension's stages.
    pub(crate) fn set_nested_walk_stage_rxs(
        &mut self,
        v: Vec<sparse::Polynomial<C::ScalarField, R>>,
    ) {
        assert!(
            self.nested_walk_stage_rxs.is_empty(),
            "double-set: nested_walk_stage_rxs"
        );
        self.nested_walk_stage_rxs = v;
    }

    /// Takes the polynomials
    /// [`set_nested_walk_stage_rxs`](Self::set_nested_walk_stage_rxs) held:
    /// none for a walk of one segment.
    pub(crate) fn take_nested_walk_stage_rxs(
        &mut self,
    ) -> Vec<sparse::Polynomial<C::ScalarField, R>> {
        core::mem::take(&mut self.nested_walk_stage_rxs)
    }

    /// Holds the polynomials a native walk of several segments adds, for
    /// [`take_native_walk_stage_rxs`](Self::take_native_walk_stage_rxs) to
    /// hand to the native extension's stages.
    pub(crate) fn set_native_walk_stage_rxs(
        &mut self,
        v: Vec<sparse::Polynomial<C::CircuitField, R>>,
    ) {
        assert!(
            self.native_walk_stage_rxs.is_empty(),
            "double-set: native_walk_stage_rxs"
        );
        self.native_walk_stage_rxs = v;
    }

    /// Takes the polynomials
    /// [`set_native_walk_stage_rxs`](Self::set_native_walk_stage_rxs) held:
    /// none for a walk of one segment.
    pub(crate) fn take_native_walk_stage_rxs(
        &mut self,
    ) -> Vec<sparse::Polynomial<C::CircuitField, R>> {
        core::mem::take(&mut self.native_walk_stage_rxs)
    }

    /// Lazily computes and caches commitments for all endoscaling step rx
    /// polynomials. Returns the cached slice.
    pub(crate) fn nested_endoscaling_step_commitments(&self) -> &[C::NestedCurve] {
        self.nested_endoscaling_step_commitments.get_or_init(|| {
            self.nested.commit_many(
                self.nested_endoscaling_step_rxs
                    .as_ref()
                    .expect("nested_endoscaling_step_rxs not set"),
            )
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

    setter!(set_nested_a_poly, nested_a_poly, sparse::Polynomial<C::ScalarField, R>);
    setter!(set_nested_b_poly, nested_b_poly, sparse::Polynomial<C::ScalarField, R>);
    ref_getter!(nested_a_poly, nested_a_poly, sparse::Polynomial<C::ScalarField, R>);
    ref_getter!(nested_b_poly, nested_b_poly, sparse::Polynomial<C::ScalarField, R>);
    lazy_commitment!(
        nested,
        nested_a_commitment,
        nested_a_commitment,
        nested_a_poly
    );
    lazy_commitment!(
        nested,
        nested_b_commitment,
        nested_b_commitment,
        nested_b_poly
    );

    setter!(
        set_nested_registry_xy_poly,
        nested_registry_xy_poly,
        sparse::Polynomial<C::ScalarField, R>
    );
    /// Stores $p_n$ with its commitment $P_n$: the last interstitial of the
    /// native endoscaling walk, rather than a commitment computed from the
    /// polynomial.
    pub(crate) fn set_nested_p_poly(
        &mut self,
        poly: sparse::Polynomial<C::ScalarField, R>,
        commitment: C::NestedCurve,
    ) {
        assert!(self.nested_p_poly.is_none(), "double-set: nested_p_poly");
        self.nested_p_poly = Some(poly);
        assert!(
            self.nested_p_commitment.set(commitment).is_ok(),
            "double-set: nested_p_commitment"
        );
    }

    pub(crate) fn nested_p_commitment(&self) -> C::NestedCurve {
        *self
            .nested_p_commitment
            .get()
            .expect("nested_p_commitment not set (call set_nested_p_poly first)")
    }
    ref_getter!(
        nested_registry_xy_poly,
        nested_registry_xy_poly,
        sparse::Polynomial<C::ScalarField, R>
    );
    ref_getter!(nested_p_poly, nested_p_poly, sparse::Polynomial<C::ScalarField, R>);
    lazy_commitment!(
        nested,
        nested_registry_xy_commitment,
        nested_registry_xy_commitment,
        nested_registry_xy_poly
    );
    setter!(
        set_nested_challenges_rx,
        nested_challenges_rx,
        sparse::Polynomial<C::ScalarField, R>
    );
    ref_getter!(
        nested_challenges_rx,
        nested_challenges_rx,
        sparse::Polynomial<C::ScalarField, R>
    );
    lazy_commitment!(
        nested,
        nested_challenges_commitment,
        nested_challenges_commitment,
        nested_challenges_rx
    );
    setter!(
        set_nested_challenges_partial,
        nested_challenges_partial,
        C::NestedCurve
    );
    getter!(
        nested_challenges_partial,
        nested_challenges_partial,
        C::NestedCurve
    );
    setter!(
        set_nested_collapse_rx,
        nested_collapse_rx,
        sparse::Polynomial<C::ScalarField, R>
    );
    lazy_commitment!(
        nested,
        nested_collapse_commitment,
        nested_collapse_commitment,
        nested_collapse_rx
    );
    setter!(
        set_nested_compute_v_rx,
        nested_compute_v_rx,
        sparse::Polynomial<C::ScalarField, R>
    );
    lazy_commitment!(
        nested,
        nested_compute_v_commitment,
        nested_compute_v_commitment,
        nested_compute_v_rx
    );

    setter!(set_w, w, C::CircuitField);
    setter!(set_y, y, C::CircuitField);
    setter!(set_z, z, C::CircuitField);
    setter!(set_mu, mu, C::CircuitField);
    setter!(set_mu_prime, mu_prime, C::CircuitField);
    setter!(set_x, x, C::CircuitField);
    setter!(set_alpha, alpha, C::CircuitField);
    setter!(set_u, u, C::CircuitField);
    setter!(set_pre_beta, pre_beta, C::CircuitField);

    getter!(w, w, C::CircuitField);
    getter!(y, y, C::CircuitField);
    getter!(z, z, C::CircuitField);
    getter!(mu, mu, C::CircuitField);
    getter!(mu_prime, mu_prime, C::CircuitField);
    getter!(x, x, C::CircuitField);
    getter!(alpha, alpha, C::CircuitField);
    getter!(u, u, C::CircuitField);
    getter!(pre_beta, pre_beta, C::CircuitField);

    /// Returns the revdot product $c = \text{revdot}(A, B)$.
    pub(crate) fn native_c(&self) -> C::CircuitField {
        B::sparse_revdot(self.native_a_poly(), self.native_b_poly())
    }

    /// Returns the evaluation $v = p(u)$.
    pub(crate) fn v(&self) -> C::CircuitField {
        B::sparse_eval(self.native_p_poly(), self.u())
    }

    /// Returns the nested accumulator's revdot product
    /// $c = \text{revdot}(a, b)$ in the scalar field.
    pub(crate) fn nested_c(&self) -> C::ScalarField {
        B::sparse_revdot(self.nested_a_poly(), self.nested_b_poly())
    }

    /// Returns the nested batch's evaluation $v_n = p_n(u_n)$, at the nested
    /// counterpart of $u$.
    pub(crate) fn nested_v(&self) -> Result<C::ScalarField> {
        Ok(B::sparse_eval(
            self.nested_p_poly(),
            nested::challenge::<C>(self.u())?,
        ))
    }

    /// Build the proof. All polynomial fields must have been set. Commitment
    /// caches that haven't been accessed yet are computed now.
    pub(crate) fn build(mut self) -> Result<Proof<C, R>> {
        // Force lazy evaluation of every native commitment cache by invoking
        // its getter. The a/b/p caches are set externally via their explicit
        // setters, so they are not touched here.
        self.native_preamble_commitment();
        self.native_inner_error_commitment();
        self.native_outer_error_commitment();
        self.native_query_commitment();
        self.native_registry_xy_commitment();
        self.native_eval_commitment();
        self.native_hashes_1_commitment();
        self.native_hashes_2_commitment();
        self.native_collapse_commitment();
        self.native_compute_v_commitment();
        self.native_bind_challenges_commitments();
        self.native_bind_beta_commitment();
        self.native_bind_endoscalar_commitment();
        self.native_endoscaling_step_commitments();
        self.native_extension_circuit_commitments();
        self.native_extension_stage_commitments();
        self.native_points_binding_commitment();
        self.native_points_preamble_commitment();
        self.native_points_registry_wx_commitment();
        self.native_points_ab_commitment();
        self.native_points_f_commitment();
        self.native_points_walk_commitment();
        self.online_commitments();

        // Force lazy evaluation of the cached bridge commitment.
        self.bridge_ab_commitment()?;

        // Ensure nested endoscaling commitment caches are populated.
        self.nested_endoscaling_step_commitments();
        self.nested_extension_circuit_commitments();
        self.nested_extension_stage_commitments();
        self.nested_endoscalar_commitment();
        self.nested_points_commitment();

        // Ensure nested accumulator and batch commitment caches are populated.
        self.nested_a_commitment();
        self.nested_b_commitment();
        self.nested_registry_xy_commitment();
        self.nested_p_commitment();
        self.nested_challenges_commitment();
        self.nested_collapse_commitment();
        self.nested_compute_v_commitment();

        let online_fq_commitments = self.exported_online_fq_commitments();
        // What the step exposes of its online openings for the statement
        // claim's step binding: nothing for a profile without a statement
        // circuit. A dummy proof ran no step: its slots are padding, opened
        // at the all-one challenge to its value one.
        let step_binding = match &self.online_openings {
            Some(openings) => online::step_binding::<C::Profile, _>(openings),
            None => alloc::vec![
                C::CircuitField::ONE;
                <online::StepBindingLen<C::Profile> as ragu_primitives::vec::Len>::len()
            ],
        };

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

        // A step's online batches hold what the proof carries of them. The
        // bootstrap proof has none: it carries the commitments and source
        // polynomials it was given, a zero fold, and mesh claims that are one
        // at the coordinates and zero at the shared values.
        let native_online_fold = match &self.native_online {
            Some(state) => state.fold()?.to_vec(),
            None => alloc::vec![C::CircuitField::ZERO; Present::<C::Profile, Native, 2>::len()],
        };
        let nested_online_fold = match &self.nested_online {
            Some(state) => state.fold()?.to_vec(),
            None => alloc::vec![C::ScalarField::ZERO; Present::<C::Profile, Nested, 2>::len()],
        };

        Ok(Proof {
            nested_source_out: match &self.nested_online {
                Some(state) => state.source_out(),
                None => self.nested_source_out,
            },
            native_source_out: match &self.native_online {
                Some(state) => state.source_out(),
                None => self.native_source_out,
            },
            bridge_alpha: self.bridge_alpha,

            circuit_id: take!(circuit_id),
            native_online_commitments: if let Some(state) = &self.native_online {
                state.commitments().to_vec()
            } else {
                self.dummy_native_online_commitments
                    .take()
                    .expect("bootstrap native online commitments must be set")
            },
            nested_online_commitments: if let Some(state) = &self.nested_online {
                state.commitments().to_vec()
            } else {
                self.dummy_nested_online_commitments
                    .take()
                    .expect("bootstrap online commitments must be set")
            },
            native_mesh_claims: if let Some(state) = &self.native_online {
                state.mesh_claims()?
            } else if let Some(mesh) = C::Profile::NATIVE_MESH {
                let mut values = alloc::vec![C::CircuitField::ZERO;mesh.claims_len()];
                values[..mesh.coordinate_indices().len()].fill(C::CircuitField::ONE);
                values
            } else {
                Vec::new()
            },
            native_online_fold,
            nested_mesh_claims: if let Some(state) = &self.nested_online {
                state.mesh_claims()?
            } else if let Some(mesh) = C::Profile::NESTED_MESH {
                let mut values = alloc::vec![C::ScalarField::ZERO;mesh.claims_len()];
                values[..mesh.coordinate_indices().len()].fill(
                    crate::internal::nested::challenge::<C>(C::CircuitField::ONE)?,
                );
                values
            } else {
                Vec::new()
            },
            nested_online_fold,

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
            native_collapse_rx: take!(native_collapse_rx),
            native_compute_v_rx: take!(native_compute_v_rx),
            native_bind_challenges_rxs: take!(native_bind_challenges_rxs),
            native_bind_beta_rx: take!(native_bind_beta_rx),
            native_bind_endoscalar_rx: take!(native_bind_endoscalar_rx),
            native_endoscaling_step_rxs: take!(native_endoscaling_step_rxs),
            native_extension_circuit_rxs: take!(native_extension_circuit_rxs),
            native_extension_stage_rxs: take!(native_extension_stage_rxs),
            native_points_binding_rx: take!(native_points_binding_rx),
            native_points_preamble_rx: take!(native_points_preamble_rx),
            native_points_registry_wx_rx: take!(native_points_registry_wx_rx),
            native_points_ab_rx: take!(native_points_ab_rx),
            native_points_f_rx: take!(native_points_f_rx),
            native_points_walk_rx: take!(native_points_walk_rx),
            online_polynomials: take!(online_polynomials),
            step_binding,
            online_fq_commitments,
            online_fq_openings: take!(online_fq_openings),

            bridge_preamble_rx: take!(bridge_preamble_rx),
            bridge_preamble_commitment: take!(bridge_preamble_commitment),
            bridge_hash_rx: take!(bridge_hash_rx),
            bridge_hash_commitment: take!(bridge_hash_commitment),
            bridge_s_prime_rx: take!(bridge_s_prime_rx),
            bridge_s_prime_commitment: take!(bridge_s_prime_commitment),
            bridge_inner_error_rx: take!(bridge_inner_error_rx),
            bridge_inner_error_commitment: take!(bridge_inner_error_commitment),
            bridge_outer_error_rx: take!(bridge_outer_error_rx),
            bridge_outer_error_commitment: take!(bridge_outer_error_commitment),
            bridge_query_rx: take!(bridge_query_rx),
            bridge_query_commitment: take!(bridge_query_commitment),
            bridge_f_rx: take!(bridge_f_rx),
            bridge_f_commitment: take!(bridge_f_commitment),
            bridge_eval_rx: take!(bridge_eval_rx),
            bridge_eval_commitment: take!(bridge_eval_commitment),

            bridge_ab_rx: cached!(bridge_ab_rx),
            bridge_ab_commitment: cached!(bridge_ab_commitment),

            nested_endoscaling_step_rxs: take!(nested_endoscaling_step_rxs),
            nested_extension_circuit_rxs: take!(nested_extension_circuit_rxs),
            nested_extension_stage_rxs: take!(nested_extension_stage_rxs),
            nested_endoscalar_rx: take!(nested_endoscalar_rx),
            nested_points_rx: take!(nested_points_rx),
            nested_a_poly: take!(nested_a_poly),
            nested_b_poly: take!(nested_b_poly),
            nested_registry_xy_poly: take!(nested_registry_xy_poly),
            nested_p_poly: take!(nested_p_poly),
            nested_challenges_rx: take!(nested_challenges_rx),
            nested_challenges_partial: take!(nested_challenges_partial),
            nested_collapse_rx: take!(nested_collapse_rx),
            nested_compute_v_rx: take!(nested_compute_v_rx),

            nested_endoscaling_step_commitments: self
                .nested_endoscaling_step_commitments
                .take()
                .expect("nested_endoscaling_step_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            nested_extension_circuit_commitments: self
                .nested_extension_circuit_commitments
                .take()
                .expect("nested_extension_circuit_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            nested_extension_stage_commitments: self
                .nested_extension_stage_commitments
                .take()
                .expect("nested_extension_stage_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            nested_endoscalar_commitment: cached!(nested_endoscalar_commitment),
            nested_points_commitment: cached!(nested_points_commitment),
            nested_a_commitment: cached!(nested_a_commitment),
            nested_b_commitment: cached!(nested_b_commitment),
            nested_registry_xy_commitment: cached!(nested_registry_xy_commitment),
            nested_p_commitment: cached!(nested_p_commitment),
            nested_challenges_commitment: cached!(nested_challenges_commitment),
            nested_collapse_commitment: cached!(nested_collapse_commitment),
            nested_compute_v_commitment: cached!(nested_compute_v_commitment),

            w: take!(w),
            y: take!(y),
            z: take!(z),
            mu: take!(mu),
            mu_prime: take!(mu_prime),
            x: take!(x),
            alpha: take!(alpha),
            u: take!(u),
            pre_beta: take!(pre_beta),

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
            native_collapse_commitment: cached!(native_collapse_commitment),
            native_compute_v_commitment: cached!(native_compute_v_commitment),
            native_bind_challenges_commitments: self
                .native_bind_challenges_commitments
                .take()
                .expect("native_bind_challenges_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            native_bind_beta_commitment: cached!(native_bind_beta_commitment),
            native_bind_endoscalar_commitment: cached!(native_bind_endoscalar_commitment),
            native_endoscaling_step_commitments: self
                .native_endoscaling_step_commitments
                .take()
                .expect("native_endoscaling_step_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            native_extension_circuit_commitments: self
                .native_extension_circuit_commitments
                .take()
                .expect("native_extension_circuit_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            native_extension_stage_commitments: self
                .native_extension_stage_commitments
                .take()
                .expect("native_extension_stage_commitments not set")
                .into_iter()
                .map(Cached)
                .collect(),
            native_points_binding_commitment: cached!(native_points_binding_commitment),
            native_points_preamble_commitment: cached!(native_points_preamble_commitment),
            native_points_registry_wx_commitment: cached!(native_points_registry_wx_commitment),
            native_points_ab_commitment: cached!(native_points_ab_commitment),
            native_points_f_commitment: cached!(native_points_f_commitment),
            native_points_walk_commitment: cached!(native_points_walk_commitment),
            online_commitments: self
                .online_commitments
                .take()
                .expect("online_commitments not set")
                .map(Cached),
        })
    }
}
