//! Proof and proof-carrying data structures.
//!
//! Defines the [`Proof`] structure containing trace polynomials, commitments,
//! and accumulated claims, along with [`Pcd`] which bundles a [`Proof`] with
//! the data that a [`Header`] succinctly encodes. Fields are organized by
//! protocol phase (application proof, folding, query/evaluation, and
//! commitment opening) alongside verifier challenges and bridge/nested-curve
//! data, kept flat to make verification and proof transformation explicit.

#![allow(dead_code)]

pub(crate) mod builder;
mod codec;
// Stage regressions recommit edited application polynomials to bypass the
// honest proving API.
#[cfg(test)]
#[path = "../../tests/app_stage.rs"]
mod stage_tests;
// These regression suites edit proof fields directly. Keep their sources
// grouped by subject in tests/ and their access confined to the test build.
// Their properties prove tens of production-rank proofs each, so they are
// `#[ignore]`d in the platform matrix. Rust CI explicitly replays the
// properties with saved recursion failures, and the scheduled heavy-tests
// run picks up the full suites with `cargo test -- --ignored`.
#[cfg(test)]
#[path = "../../tests/base_case_combinations.rs"]
mod base_case_combinations_tests;
#[cfg(test)]
#[path = "../../tests/compress_blinding.rs"]
mod compress_blinding_tests;
#[cfg(test)]
#[path = "../../tests/recursive_bindings.rs"]
mod recursive_binding_tests;
#[cfg(test)]
#[path = "../../tests/recursive_boundaries.rs"]
mod recursive_boundary_tests;
#[cfg(test)]
#[path = "../../tests/recursive_propagation.rs"]
pub(crate) mod recursive_propagation_tests;

// Keep this beneath `proof` so the shared test helper can inspect private
// `Proof` fields.
#[cfg(test)]
#[path = "../../tests/backend_equivalence.rs"]
mod backend_equivalence;
// Golden fixtures of the fuse pipeline and the compressed verifier, under
// `tests/fixtures/fuse/`. Mounted here so the digests destructure `Proof`
// exhaustively: a new field fails to compile until the fixture pins it.
#[cfg(test)]
#[path = "../../tests/fuse_fixtures.rs"]
mod fuse_fixture_tests;
#[cfg(test)]
#[path = "../../tests/profile_substitution.rs"]
mod profile_substitution_tests;
#[cfg(test)]
#[path = "../../tests/proof_shape.rs"]
mod proof_shape_tests;
#[cfg(test)]
#[path = "../../tests/verify_rejections.rs"]
mod verify_rejection_tests;
// Mutable component access for the corruption vocabulary (see
// `crate::fuzzing`). Its source lives with the rest of the fuzzing surface in
// `src/fuzzing/`, but it is mounted here, as a child of `proof`, so it can
// reach the private `Cached` fields without loosening them. The file gates
// itself behind `unstable-fuzzing` with an inner `#![cfg]`, so no feature
// attribute appears here.
// TODO: Revisit this layout; for now, it keeps the fuzzing surface in one
// directory without loosening `Proof`'s privacy or adding a feature
// attribute here.
#[path = "../fuzzing/access.rs"]
mod access;

use alloc::{sync::Arc, vec, vec::Vec};

pub(crate) use builder::ProofBuilder;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::{self, MultiStage, StageExt, StageReader},
};
use ragu_core::{Cycle, Result};
use ragu_primitives::{
    Uendo, extract_endoscalar, lift_endoscalar,
    vec::{FixedVec, Len},
};
use udon::field::Field;

use crate::{
    framework_hooks::HookLayout,
    header::Header,
    internal::{
        endoscalar::EndoscalarStage,
        native::{
            self, RxComponent, RxIndex,
            stages::points::{self as native_points, Inputs},
        },
        nested::{
            self, EndoscalingStep, EndoscalingStepWitness, NumPoints, NumSteps, PointsStage,
            PointsWitness,
        },
    },
    poly_commitment::{self, HANDLE_WIRES},
    profile::{Profile, ProfiledCycle},
};

/// A newtype marking a field as derived/cacheable.
///
/// Wraps a value that can be recomputed from primary proof data. Used to
/// distinguish commitment caches from primary polynomial fields at the type
/// level. Immutable once constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cached<T>(T);

/// Represents proof-carrying data, a recursive proof for the correctness of
/// some accompanying data.
pub struct Pcd<C: Cycle, R: Rank, H: Header<C::CircuitField>> {
    proof: Proof<C, R>,
    data: H::Data,
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Pcd<C, R, H> {
    /// Returns a reference to the data that the proof accompanies.
    pub fn data(&self) -> &H::Data {
        &self.data
    }

    /// Returns a reference to the recursive proof.
    pub fn proof(&self) -> &Proof<C, R> {
        &self.proof
    }

    /// Consumes the proof-carrying data and returns the proof and data
    /// separately.
    pub fn into_parts(self) -> (Proof<C, R>, H::Data) {
        (self.proof, self.data)
    }
}

impl<C: Cycle, R: Rank, H: Header<C::CircuitField>> Clone for Pcd<C, R, H> {
    fn clone(&self) -> Self {
        Pcd {
            proof: self.proof.clone(),
            data: self.data.clone(),
        }
    }
}

/// A polynomial-opening claim $p(x) = y$, identifying the polynomial by its
/// commitment.
///
/// The commitment is the host-curve point itself: a `Proof` is plain data with
/// no circuit to answer to, so nothing here needs the handle the native circuit
/// cannot avoid. `Curve::Scalar` is the circuit field, which is why one
/// parameter fixes all three fields.
#[derive(Clone, Copy, Debug)]
pub struct PolyQuery<Curve: udon::curve::Affine> {
    /// The opened polynomial's commitment.
    pub com: Curve,
    /// The opening point.
    pub x: Curve::Scalar,
    /// The claimed evaluation $p(x) = y$.
    pub y: Curve::Scalar,
}

/// The hook region that witnessed-polynomial `commitments`, their `names`
/// and `queries` encode: each commitment's name, then each poly-query's
/// commitment's name, `x` and `y`, in the order the adapter stages them.
///
/// # Errors
///
/// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if
/// the lists differ in length or a query's commitment is none of
/// `commitments`, which a proof the adapter built never has.
pub(crate) fn hook_region<C: Cycle>(
    commitments: &[C::HostCurve],
    names: &[[C::CircuitField; HANDLE_WIRES]],
    queries: &[PolyQuery<C::HostCurve>],
) -> Result<Vec<C::CircuitField>> {
    if commitments.len() != names.len() {
        return Err(ragu_core::Error::InvalidWitness(
            "one name per witnessed polynomial".into(),
        ));
    }
    let mut region = Vec::new();
    for name in names {
        region.extend(name);
    }
    for query in queries {
        let named = commitments
            .iter()
            .position(|&commitment| commitment == query.com)
            .ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "a poly-query names a commitment the proof does not carry".into(),
                )
            })?;
        region.extend(names[named]);
        region.push(query.x);
        region.push(query.y);
    }
    Ok(region)
}

/// The Horner fold of `polys` under `beta`, the first weighted highest: the
/// batch polynomial whose commitment the endoscaling walk over the
/// polynomials' commitments computes.
fn beta_fold<F: Field, R: Rank>(
    polys: &[&sparse::Polynomial<F, R>],
    beta: F,
) -> sparse::Polynomial<F, R> {
    let (first, rest) = polys.split_first().expect("at least one polynomial");
    rest.iter().fold((*first).clone(), |mut acc, poly| {
        acc.scale(beta);
        acc.add_assign(poly);
        acc
    })
}

/// The blinding of a cached bridge polynomial, as a distinct power of the
/// proof's `bridge_alpha` (see [`bridge_alpha_exponent`]); shared by the
/// builder that derives the bridge and the verifier that rederives it.
pub(crate) fn bridge_alpha_power<F: Field>(bridge_alpha: F, idx: nested::RxIndex) -> F {
    bridge_alpha.pow_u64(bridge_alpha_exponent(idx))
}

/// The exponent of `bridge_alpha` for a cached bridge stage; the single
/// ordering keeps all blinds distinct. Panics on the bridges that carry
/// prover-chosen data, which are blinded at random instead (every bridge but
/// `ab`).
fn bridge_alpha_exponent(idx: nested::RxIndex) -> u64 {
    match idx {
        nested::RxIndex::BridgeAB => 2,
        _ => panic!("not blinded from bridge_alpha: {idx:?}"),
    }
}

/// Represents a recursive proof for the correctness of some computation.
///
/// All fields are flat (no nested component structs). Polynomial fields are
/// primary data; commitment fields are `Cached` values derivable from
/// polynomials, which `Application::verify_uncompressed` rederives rather
/// than trusts. The `ab` bridge polynomial is also `Cached`,
/// derivable from `bridge_alpha` and native commitments; the other seven
/// carry prover-chosen data (the nested fold's error terms and the nested
/// batch's values among them) and are primary.
#[derive(Clone)]
pub struct Proof<C: Cycle, R: Rank> {
    /// Shared alpha source for deriving cached bridge polynomial alphas.
    pub(crate) bridge_alpha: C::ScalarField,

    // Application metadata
    pub(crate) circuit_id: CircuitIndex,
    pub(crate) left_header: Vec<C::CircuitField>,
    pub(crate) right_header: Vec<C::CircuitField>,

    // Native rx polynomials (CircuitField, HostCurve commitment)
    pub(crate) native_application_rx: sparse::Polynomial<C::CircuitField, R>,
    /// The application stage, which the application claim adds to the step's
    /// own polynomial, sized from the registered steps' shared gadgets.
    pub(crate) native_application_stage_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_preamble_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_inner_error_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_outer_error_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_a_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_b_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_query_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_registry_xy_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_eval_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_p_poly: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_hashes_1_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_hashes_2_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_collapse_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_compute_v_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_bind_challenges_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,
    pub(crate) native_bind_beta_rx: sparse::Polynomial<C::CircuitField, R>,
    // The native endoscaling walk over the nested batch's commitments: the
    // endoscalar binding circuit, the steps, the five points stages holding
    // the walk's inputs (see `native::stages::points`) and the walk stage
    // holding the endoscalar's bits and the interstitials.
    pub(crate) native_bind_endoscalar_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_endoscaling_step_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,
    /// The rx polynomials of the circuits of the profile's native extension.
    pub(crate) native_extension_circuit_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,
    /// The rx polynomials of the stages of the profile's native extension.
    pub(crate) native_extension_stage_rxs: Vec<sparse::Polynomial<C::CircuitField, R>>,
    pub(crate) native_points_binding_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_children_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_registry_wx_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_ab_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_f_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_walk_rx: sparse::Polynomial<C::CircuitField, R>,

    // Bridge rx polynomials (non-cached, set by caller)
    pub(crate) bridge_preamble_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_s_prime_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_inner_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_outer_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_query_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_f_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_eval_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,

    // Bridge rx polynomial (cached, derived from bridge_alpha + native commitments)
    bridge_ab_rx: Cached<Arc<sparse::Polynomial<C::ScalarField, R>>>,

    // Nested endoscaling data (ScalarField, NestedCurve commitment)
    pub(crate) nested_endoscaling_step_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    /// The rx polynomials of the circuits of the profile's nested extension.
    pub(crate) nested_extension_circuit_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    /// The rx polynomials of the stages of the profile's nested extension.
    pub(crate) nested_extension_stage_rxs: Vec<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) nested_endoscalar_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_points_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,

    // Nested accumulator polynomials (ScalarField, NestedCurve commitment):
    // the children's nested claims, folded.
    pub(crate) nested_a_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_b_poly: sparse::Polynomial<C::ScalarField, R>,

    // Nested batch polynomials (ScalarField, NestedCurve commitment): the
    // $m_n(W, x_n, y_n)$ restriction, and the batch accumulated into $p_n$.
    pub(crate) nested_registry_xy_poly: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_p_poly: sparse::Polynomial<C::ScalarField, R>,

    // Nested challenge stage (ScalarField, unblinded NestedCurve
    // commitment): the lifts of this step's native challenges, the
    // base-case sign and the lift of `pre_beta`.
    pub(crate) nested_challenges_rx: sparse::Polynomial<C::ScalarField, R>,
    // The challenge stage's commitment without its beta term: the sum the
    // `bind_challenges` circuits recompute from the transcript challenges,
    // carried by the native unified instance so that a parent can complete
    // it and hold it against the stage it walks.
    pub(crate) nested_challenges_partial: C::NestedCurve,

    // Nested instance circuits (ScalarField, NestedCurve commitments): the
    // collapse circuit pins the nested unified instance to the stages and
    // verifies the nested fold; compute-v checks the nested batch evaluation.
    pub(crate) nested_collapse_rx: sparse::Polynomial<C::ScalarField, R>,
    pub(crate) nested_compute_v_rx: sparse::Polynomial<C::ScalarField, R>,

    // Nested endoscaling commitment caches
    nested_endoscaling_step_commitments: Vec<Cached<C::NestedCurve>>,
    nested_extension_circuit_commitments: Vec<Cached<C::NestedCurve>>,
    nested_extension_stage_commitments: Vec<Cached<C::NestedCurve>>,
    nested_endoscalar_commitment: Cached<C::NestedCurve>,
    nested_points_commitment: Cached<C::NestedCurve>,

    // Nested accumulator commitment caches
    nested_a_commitment: Cached<C::NestedCurve>,
    nested_b_commitment: Cached<C::NestedCurve>,

    // Nested batch commitment caches
    nested_registry_xy_commitment: Cached<C::NestedCurve>,
    nested_p_commitment: Cached<C::NestedCurve>,

    // Nested challenge stage commitment cache
    nested_challenges_commitment: Cached<C::NestedCurve>,

    // Nested instance circuit commitment caches
    nested_collapse_commitment: Cached<C::NestedCurve>,
    nested_compute_v_commitment: Cached<C::NestedCurve>,

    // Challenges
    pub(crate) w: C::CircuitField,
    pub(crate) y: C::CircuitField,
    pub(crate) z: C::CircuitField,
    pub(crate) mu: C::CircuitField,
    pub(crate) mu_prime: C::CircuitField,
    pub(crate) x: C::CircuitField,
    pub(crate) alpha: C::CircuitField,
    pub(crate) u: C::CircuitField,
    pub(crate) pre_beta: C::CircuitField,

    // Native commitment caches
    native_application_commitment: Cached<C::HostCurve>,
    native_application_stage_commitment: Cached<C::HostCurve>,
    native_preamble_commitment: Cached<C::HostCurve>,
    native_inner_error_commitment: Cached<C::HostCurve>,
    native_outer_error_commitment: Cached<C::HostCurve>,
    native_a_commitment: Cached<C::HostCurve>,
    native_b_commitment: Cached<C::HostCurve>,
    native_query_commitment: Cached<C::HostCurve>,
    native_registry_xy_commitment: Cached<C::HostCurve>,
    native_eval_commitment: Cached<C::HostCurve>,
    native_p_commitment: Cached<C::HostCurve>,
    native_hashes_1_commitment: Cached<C::HostCurve>,
    native_hashes_2_commitment: Cached<C::HostCurve>,
    native_collapse_commitment: Cached<C::HostCurve>,
    native_compute_v_commitment: Cached<C::HostCurve>,
    native_bind_challenges_commitments: Vec<Cached<C::HostCurve>>,
    native_bind_beta_commitment: Cached<C::HostCurve>,
    native_bind_endoscalar_commitment: Cached<C::HostCurve>,
    native_endoscaling_step_commitments: Vec<Cached<C::HostCurve>>,
    native_extension_circuit_commitments: Vec<Cached<C::HostCurve>>,
    native_extension_stage_commitments: Vec<Cached<C::HostCurve>>,
    native_points_binding_commitment: Cached<C::HostCurve>,
    native_points_children_commitment: Cached<C::HostCurve>,
    native_points_registry_wx_commitment: Cached<C::HostCurve>,
    native_points_ab_commitment: Cached<C::HostCurve>,
    native_points_f_commitment: Cached<C::HostCurve>,
    native_points_walk_commitment: Cached<C::HostCurve>,

    // Bridge commitments (non-cached)
    pub(crate) bridge_preamble_commitment: C::NestedCurve,
    pub(crate) bridge_s_prime_commitment: C::NestedCurve,
    pub(crate) bridge_inner_error_commitment: C::NestedCurve,
    pub(crate) bridge_outer_error_commitment: C::NestedCurve,
    pub(crate) bridge_query_commitment: C::NestedCurve,
    pub(crate) bridge_f_commitment: C::NestedCurve,
    pub(crate) bridge_eval_commitment: C::NestedCurve,

    // Bridge commitment (cached, derived from the cached bridge rx)
    bridge_ab_commitment: Cached<C::NestedCurve>,

    /// Padded to the profile's count. The step binds these to the hook region
    /// of its application stage. Readers go through
    /// [`application_poly_queries`](Self::application_poly_queries).
    pub(crate) application_poly_queries: Vec<PolyQuery<C::HostCurve>>,

    /// The step's witnessed polynomials, carried for one fuse level.
    pub(crate) witness_polys: Vec<sparse::Polynomial<C::CircuitField, R>>,
    /// [`witness_polys`](Self::witness_polys)' commitments, in the same order.
    witness_poly_commitments: Cached<Vec<C::HostCurve>>,
    /// The names of [`witness_poly_commitments`](Self::witness_poly_commitments),
    /// in the same order: what the step was handed and staged.
    witness_poly_names: Cached<Vec<[C::CircuitField; HANDLE_WIRES]>>,

    /// Set by a test that forges the hook lists a parent reads, to stand in
    /// for a fusing prover that skips its own [`has_shape`](Self::has_shape)
    /// check. Only the stage comparison is skipped; the lengths still hold.
    #[cfg(test)]
    pub(crate) skip_stage_check: bool,

    /// Set by a test standing in for a fusing prover whose copy of this
    /// proof's names is not the carried commitments', while its nested stash
    /// still carries those commitments. Read through
    /// [`copied_names`](Self::copied_names) and
    /// [`batched_name_commitments`](Self::batched_name_commitments).
    #[cfg(test)]
    pub(crate) forged_names: Option<ForgedNames<C::HostCurve>>,
}

/// A fusing prover's forged copy of a child's names, slot by slot: the
/// host commitments it names and their names. The child's nested stash keeps
/// the commitments the child carries.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ForgedNames<H: udon::curve::Affine> {
    pub commitments: Vec<H>,
    pub names: Vec<[H::Scalar; HANDLE_WIRES]>,
    /// Whether the prover's nested batch also folds the forged names'
    /// polynomials, so that its $P_n$ matches the walk over the copy and
    /// only $v_n$, computed from the stash, disagrees; or the stash's, as an
    /// honest nested batch does, so that $P_n$ disagrees with the walk.
    pub in_batch: bool,
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    pub(crate) fn application_poly_queries(&self) -> &[PolyQuery<C::HostCurve>] {
        &self.application_poly_queries
    }

    pub(crate) fn witness_polys(&self) -> &[sparse::Polynomial<C::CircuitField, R>] {
        &self.witness_polys
    }

    /// [`witness_polys`](Self::witness_polys)' commitments, in the same order.
    pub(crate) fn witness_poly_commitments(&self) -> &[C::HostCurve] {
        &self.witness_poly_commitments.0
    }

    /// [`witness_poly_commitments`](Self::witness_poly_commitments)' names,
    /// in the same order.
    pub(crate) fn witness_poly_names(&self) -> &[[C::CircuitField; HANDLE_WIRES]] {
        &self.witness_poly_names.0
    }
}

impl<C: ProfiledCycle, R: Rank> Proof<C, R> {
    /// Whether the hook lists are the ones the profile declares, and the
    /// application stage's hook region carries them. `Proof` is checked where
    /// it is *consumed*: at the fuse and at the root.
    pub(crate) fn has_shape(&self) -> bool {
        let layout = HookLayout::of::<C::Profile>();
        self.application_poly_queries.len() == layout.poly_queries
            && self.witness_polys.len() == layout.witness_polys
            && self.witness_poly_commitments.0.len() == layout.witness_polys
            && self.witness_poly_names.0.len() == layout.witness_polys
            && (self.skips_stage_check() || self.stage_carries_hooks(&layout))
    }

    #[cfg(test)]
    fn skips_stage_check(&self) -> bool {
        self.skip_stage_check
    }

    #[cfg(not(test))]
    fn skips_stage_check(&self) -> bool {
        false
    }

    /// Whether the hook region of the application stage holds the handles of
    /// the carried commitments and the carried poly-queries, in the order the
    /// adapter staged them. The fuse reads the points off the stage, so a
    /// proof whose stage and carried hook lists disagree is malformed.
    ///
    /// This is the prover's early refusal, not the binding: a fusing prover
    /// runs it on itself.
    fn stage_carries_hooks(&self, layout: &HookLayout) -> bool {
        let stage = StageReader::<C::CircuitField, R>::new(&self.native_application_stage_rx);
        let Ok(expected) = self.carried_hook_region() else {
            return false;
        };
        expected.len() == layout.poly_query_instance_len()
            && expected
                .iter()
                .enumerate()
                .all(|(index, limb)| stage.read(index) == *limb)
    }

    /// The hook region the carried hook lists encode (see [`hook_region`]).
    fn carried_hook_region(&self) -> Result<Vec<C::CircuitField>> {
        hook_region::<C>(
            self.witness_poly_commitments(),
            self.witness_poly_names(),
            self.application_poly_queries(),
        )
    }

    /// The names a fusing prover copies into its binding stage, slot by slot:
    /// the cached names of the carried commitments. A test may forge them,
    /// standing in for a prover whose copy disagrees with the commitments its
    /// nested stash carries (see `forged_names`).
    pub(crate) fn copied_names(&self) -> &[[C::CircuitField; HANDLE_WIRES]] {
        #[cfg(test)]
        if let Some(forged) = &self.forged_names {
            return &forged.names;
        }
        self.witness_poly_names()
    }

    /// [`copied_names`](Self::copied_names) as the nested-curve points the
    /// parent's walk folds.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness)
    /// for a name that is not a point of the nested curve.
    pub(crate) fn walked_names(&self) -> Result<Vec<C::NestedCurve>> {
        self.copied_names()
            .iter()
            .map(|&[x, y]| {
                <C::NestedCurve as udon::curve::Affine>::from_xy(x, y).ok_or_else(|| {
                    ragu_core::Error::InvalidWitness("a name is not a nested-curve point".into())
                })
            })
            .collect()
    }

    /// The commitments whose name polynomials the parent's nested batch
    /// folds, slot by slot: the carried ones, as the nested stash holds
    /// them. A test's forged copy may replace them (see `forged_names`).
    pub(crate) fn batched_name_commitments(&self) -> &[C::HostCurve] {
        #[cfg(test)]
        if let Some(forged) = self.forged_names.as_ref().filter(|forged| forged.in_batch) {
            return &forged.commitments;
        }
        self.witness_poly_commitments()
    }

    /// The hook region a fusing prover copies: its names (see
    /// [`copied_names`](Self::copied_names)), then each carried poly-query
    /// with the copied name of the slot it opens.
    pub(crate) fn preamble_hook_region(&self) -> Result<Vec<C::CircuitField>> {
        hook_region::<C>(
            self.witness_poly_commitments(),
            self.copied_names(),
            self.application_poly_queries(),
        )
    }

    /// Whether the headers, polynomial vectors and commitment-cache vectors
    /// have exactly the receiving profile's shape. Check before traversing
    /// components so that missing entries cannot panic and trailing ones
    /// cannot be ignored.
    pub(crate) fn well_formed<const HEADER_SIZE: usize>(&self) -> bool {
        let native_steps = native::NumSteps::<C::Profile>::len();
        let nested_steps = nested::NumSteps::<C::Profile>::len();
        let native_extension = C::Profile::native_extension();
        let nested_extension = C::Profile::nested_extension();

        self.left_header.len() == HEADER_SIZE
            && self.right_header.len() == HEADER_SIZE
            && self.native_bind_challenges_rxs.len() == native::NUM_BINDERS
            && self.native_bind_challenges_commitments.len() == native::NUM_BINDERS
            && self.native_endoscaling_step_rxs.len() == native_steps
            && self.native_endoscaling_step_commitments.len() == native_steps
            && self.native_extension_circuit_rxs.len() == native_extension.circuits.len()
            && self.native_extension_circuit_commitments.len() == native_extension.circuits.len()
            && self.native_extension_stage_rxs.len() == native_extension.stages
            && self.native_extension_stage_commitments.len() == native_extension.stages
            && self.nested_endoscaling_step_rxs.len() == nested_steps
            && self.nested_endoscaling_step_commitments.len() == nested_steps
            && self.nested_extension_circuit_rxs.len() == nested_extension.circuits.len()
            && self.nested_extension_circuit_commitments.len() == nested_extension.circuits.len()
            && self.nested_extension_stage_rxs.len() == nested_extension.stages
            && self.nested_extension_stage_commitments.len() == nested_extension.stages
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<RxIndex> for Proof<C, R> {
    type Output = sparse::Polynomial<C::CircuitField, R>;
    fn index(&self, idx: RxIndex) -> &sparse::Polynomial<C::CircuitField, R> {
        use RxIndex::*;
        match idx {
            Preamble => &self.native_preamble_rx,
            InnerError => &self.native_inner_error_rx,
            OuterError => &self.native_outer_error_rx,
            Query => &self.native_query_rx,
            Eval => &self.native_eval_rx,
            Application => &self.native_application_rx,
            ApplicationStage => &self.native_application_stage_rx,
            Hashes1 => &self.native_hashes_1_rx,
            Hashes2 => &self.native_hashes_2_rx,
            Collapse => &self.native_collapse_rx,
            ComputeV => &self.native_compute_v_rx,
            BindChallenges(k) => &self.native_bind_challenges_rxs[k as usize],
            BindBeta => &self.native_bind_beta_rx,
            BindEndoscalar => &self.native_bind_endoscalar_rx,
            EndoscalingStep(step) => &self.native_endoscaling_step_rxs[step as usize],
            ExtensionCircuit(k) => &self.native_extension_circuit_rxs[k as usize],
            ExtensionStage(k) => &self.native_extension_stage_rxs[k as usize],
            PointsBinding => &self.native_points_binding_rx,
            PointsChildren => &self.native_points_children_rx,
            PointsRegistryWx => &self.native_points_registry_wx_rx,
            PointsAb => &self.native_points_ab_rx,
            PointsF => &self.native_points_f_rx,
            PointsWalk => &self.native_points_walk_rx,
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<RxComponent> for Proof<C, R> {
    type Output = sparse::Polynomial<C::CircuitField, R>;
    fn index(&self, component: RxComponent) -> &sparse::Polynomial<C::CircuitField, R> {
        match component {
            RxComponent::AbA => &self.native_a_poly,
            RxComponent::AbB => &self.native_b_poly,
            RxComponent::Rx(idx) => &self[idx],
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<nested::RxIndex> for Proof<C, R> {
    type Output = sparse::Polynomial<C::ScalarField, R>;
    fn index(&self, idx: nested::RxIndex) -> &sparse::Polynomial<C::ScalarField, R> {
        use nested::RxIndex::*;
        match idx {
            EndoscalingStep(step) => &self.nested_endoscaling_step_rxs[step as usize],
            ExtensionCircuit(k) => &self.nested_extension_circuit_rxs[k as usize],
            ExtensionStage(k) => &self.nested_extension_stage_rxs[k as usize],
            Collapse => &self.nested_collapse_rx,
            ComputeV => &self.nested_compute_v_rx,
            EndoscalarStage => &self.nested_endoscalar_rx,
            PointsStage => self.nested_points_rx.as_ref(),
            BridgePreamble => self.bridge_preamble_rx.as_ref(),
            BridgeSPrime => self.bridge_s_prime_rx.as_ref(),
            BridgeInnerError => self.bridge_inner_error_rx.as_ref(),
            BridgeOuterError => self.bridge_outer_error_rx.as_ref(),
            BridgeAB => self.bridge_ab_rx.0.as_ref(),
            BridgeQuery => self.bridge_query_rx.as_ref(),
            BridgeF => self.bridge_f_rx.as_ref(),
            BridgeEval => self.bridge_eval_rx.as_ref(),
            ChallengeStage => &self.nested_challenges_rx,
        }
    }
}

impl<C: Cycle, R: Rank> core::ops::Index<nested::RxComponent> for Proof<C, R> {
    type Output = sparse::Polynomial<C::ScalarField, R>;
    fn index(&self, component: nested::RxComponent) -> &sparse::Polynomial<C::ScalarField, R> {
        match component {
            nested::RxComponent::AbA => &self.nested_a_poly,
            nested::RxComponent::AbB => &self.nested_b_poly,
            nested::RxComponent::Rx(idx) => &self[idx],
        }
    }
}

impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Augment a recursive proof with some data, described by a [`Header`].
    pub fn carry<H: Header<C::CircuitField>>(self, data: H::Data) -> Pcd<C, R, H> {
        Pcd { proof: self, data }
    }

    // TODO: Route this witness-value computation through the selected backend
    // without making `Proof` backend-parametric or threading `c` through the
    // backend-independent stage-witness APIs.
    /// Returns the revdot product $c = \text{revdot}(A, B)$ for witness
    /// generation.
    ///
    /// This computes witness data, not circuit structure. An exact-equivalent
    /// backend implementation would leave the synthesized constraints unchanged.
    pub(crate) fn native_c(&self) -> C::CircuitField {
        self.native_a_poly.revdot(&self.native_b_poly)
    }

    // TODO: Route this witness-value computation through the selected backend
    // without making `Proof` backend-parametric or threading `v` through the
    // backend-independent stage-witness APIs.
    /// Returns the evaluation $v = p(u)$ for witness generation.
    ///
    /// As with [`Self::native_c`], this computes witness data, not circuit structure.
    /// An exact-equivalent backend implementation would leave the synthesized
    /// constraints unchanged.
    pub(crate) fn v(&self) -> C::CircuitField {
        self.native_p_poly.eval(self.u)
    }

    /// Returns the nested accumulator's revdot product
    /// $c = \text{revdot}(a, b)$ in the scalar field.
    ///
    /// As with [`Self::native_c`], this computes witness data, not circuit structure.
    pub(crate) fn nested_c(&self) -> C::ScalarField {
        self.nested_a_poly.revdot(&self.nested_b_poly)
    }

    /// Returns the nested batch's evaluation $v_n = p_n(u_n)$, at the nested
    /// counterpart of $u$.
    ///
    /// As with [`Self::v`], this computes witness data, not circuit structure.
    pub(crate) fn nested_v(&self) -> Result<C::ScalarField> {
        Ok(self.nested_p_poly.eval(nested::challenge::<C>(self.u)?))
    }

    pub(crate) fn nested_registry_xy_poly(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_registry_xy_poly
    }

    pub(crate) fn nested_p_poly(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_p_poly
    }

    pub(crate) fn nested_challenges_rx(&self) -> &sparse::Polynomial<C::ScalarField, R> {
        &self.nested_challenges_rx
    }

    pub(crate) fn nested_challenges_commitment(&self) -> C::NestedCurve {
        self.nested_challenges_commitment.0
    }

    /// The nested challenge stage's commitment without its $\beta$ term, as
    /// the native unified instance carries it.
    pub(crate) fn nested_challenges_partial(&self) -> C::NestedCurve {
        self.nested_challenges_partial
    }

    pub(crate) fn nested_collapse_commitment(&self) -> C::NestedCurve {
        self.nested_collapse_commitment.0
    }

    pub(crate) fn nested_compute_v_commitment(&self) -> C::NestedCurve {
        self.nested_compute_v_commitment.0
    }

    /// This proof's nested unified instance, as its collapse circuit
    /// serialized it: the accumulator value, the batch evaluation, the lifts
    /// of $x$, $y$ and $u$, and the exported host-curve commitments.
    pub(crate) fn nested_instance(&self) -> Result<nested::unified::Instance<C::HostCurve>> {
        Ok(nested::unified::Instance {
            c: self.nested_c(),
            v: self.nested_v()?,
            x: nested::challenge::<C>(self.x)?,
            y: nested::challenge::<C>(self.y)?,
            u: nested::challenge::<C>(self.u)?,
            exported: [
                self.native_rx_commitment(RxIndex::Preamble),
                self.native_rx_commitment(RxIndex::InnerError),
                self.native_rx_commitment(RxIndex::OuterError),
                self.native_rx_commitment(RxIndex::Query),
                self.native_rx_commitment(RxIndex::Eval),
                self.native_commitment(RxComponent::AbA),
                self.native_commitment(RxComponent::AbB),
                self.native_registry_xy_commitment(),
                self.native_p_commitment(),
                self.native_rx_commitment(RxIndex::PointsBinding),
                self.native_rx_commitment(RxIndex::PointsChildren),
                self.native_rx_commitment(RxIndex::PointsRegistryWx),
                self.native_rx_commitment(RxIndex::PointsAb),
                self.native_rx_commitment(RxIndex::PointsF),
            ]
            .into_iter()
            .chain(self.witness_poly_commitments().iter().copied())
            .collect(),
            coverage: Default::default(),
        })
    }

    /// The native challenges of this proof, in challenge-stage order.
    pub(crate) fn challenges(&self) -> nested::Challenges<C::CircuitField> {
        nested::Challenges {
            w: self.w,
            y: self.y,
            z: self.z,
            mu: self.mu,
            mu_prime: self.mu_prime,
            x: self.x,
            alpha: self.alpha,
            u: self.u,
            pre_beta: self.pre_beta,
        }
    }

    pub(crate) fn circuit_id(&self) -> CircuitIndex {
        self.circuit_id
    }

    pub(crate) fn left_header(&self) -> &[C::CircuitField] {
        &self.left_header
    }

    pub(crate) fn right_header(&self) -> &[C::CircuitField] {
        &self.right_header
    }

    pub(crate) fn native_registry_xy_poly(&self) -> &sparse::Polynomial<C::CircuitField, R> {
        &self.native_registry_xy_poly
    }

    pub(crate) fn native_p_poly(&self) -> &sparse::Polynomial<C::CircuitField, R> {
        &self.native_p_poly
    }

    pub(crate) fn w(&self) -> C::CircuitField {
        self.w
    }

    pub(crate) fn y(&self) -> C::CircuitField {
        self.y
    }

    pub(crate) fn z(&self) -> C::CircuitField {
        self.z
    }

    pub(crate) fn mu(&self) -> C::CircuitField {
        self.mu
    }

    pub(crate) fn mu_prime(&self) -> C::CircuitField {
        self.mu_prime
    }

    pub(crate) fn x(&self) -> C::CircuitField {
        self.x
    }

    pub(crate) fn alpha(&self) -> C::CircuitField {
        self.alpha
    }

    pub(crate) fn u(&self) -> C::CircuitField {
        self.u
    }

    pub(crate) fn pre_beta(&self) -> C::CircuitField {
        self.pre_beta
    }

    /// Returns the native commitment for the given [`RxIndex`].
    pub(crate) fn native_rx_commitment(&self, idx: RxIndex) -> C::HostCurve {
        use RxIndex::*;
        match idx {
            Preamble => self.native_preamble_commitment.0,
            InnerError => self.native_inner_error_commitment.0,
            OuterError => self.native_outer_error_commitment.0,
            Query => self.native_query_commitment.0,
            Eval => self.native_eval_commitment.0,
            Application => self.native_application_commitment.0,
            ApplicationStage => self.native_application_stage_commitment.0,
            Hashes1 => self.native_hashes_1_commitment.0,
            Hashes2 => self.native_hashes_2_commitment.0,
            Collapse => self.native_collapse_commitment.0,
            ComputeV => self.native_compute_v_commitment.0,
            BindChallenges(k) => self.native_bind_challenges_commitments[k as usize].0,
            BindBeta => self.native_bind_beta_commitment.0,
            BindEndoscalar => self.native_bind_endoscalar_commitment.0,
            EndoscalingStep(step) => self.native_endoscaling_step_commitments[step as usize].0,
            ExtensionCircuit(k) => self.native_extension_circuit_commitments[k as usize].0,
            ExtensionStage(k) => self.native_extension_stage_commitments[k as usize].0,
            PointsBinding => self.native_points_binding_commitment.0,
            PointsChildren => self.native_points_children_commitment.0,
            PointsRegistryWx => self.native_points_registry_wx_commitment.0,
            PointsAb => self.native_points_ab_commitment.0,
            PointsF => self.native_points_f_commitment.0,
            PointsWalk => self.native_points_walk_commitment.0,
        }
    }

    /// Returns the native commitment for the given [`RxComponent`].
    pub(crate) fn native_commitment(&self, component: RxComponent) -> C::HostCurve {
        match component {
            RxComponent::AbA => self.native_a_commitment.0,
            RxComponent::AbB => self.native_b_commitment.0,
            RxComponent::Rx(idx) => self.native_rx_commitment(idx),
        }
    }

    pub(crate) fn native_registry_xy_commitment(&self) -> C::HostCurve {
        self.native_registry_xy_commitment.0
    }

    pub(crate) fn native_p_commitment(&self) -> C::HostCurve {
        self.native_p_commitment.0
    }

    pub(crate) fn bridge_preamble_commitment(&self) -> C::NestedCurve {
        self.bridge_preamble_commitment
    }

    pub(crate) fn bridge_s_prime_commitment(&self) -> C::NestedCurve {
        self.bridge_s_prime_commitment
    }

    pub(crate) fn bridge_inner_error_commitment(&self) -> C::NestedCurve {
        self.bridge_inner_error_commitment
    }

    pub(crate) fn bridge_f_commitment(&self) -> C::NestedCurve {
        self.bridge_f_commitment
    }

    pub(crate) fn bridge_outer_error_commitment(&self) -> C::NestedCurve {
        self.bridge_outer_error_commitment
    }

    pub(crate) fn bridge_ab_commitment(&self) -> C::NestedCurve {
        self.bridge_ab_commitment.0
    }

    pub(crate) fn bridge_query_commitment(&self) -> C::NestedCurve {
        self.bridge_query_commitment
    }

    pub(crate) fn bridge_eval_commitment(&self) -> C::NestedCurve {
        self.bridge_eval_commitment
    }

    pub(crate) fn nested_endoscaling_step_commitment(&self, step: u32) -> C::NestedCurve {
        self.nested_endoscaling_step_commitments[step as usize].0
    }

    pub(crate) fn nested_endoscalar_commitment(&self) -> C::NestedCurve {
        self.nested_endoscalar_commitment.0
    }

    pub(crate) fn nested_points_commitment(&self) -> C::NestedCurve {
        self.nested_points_commitment.0
    }

    pub(crate) fn nested_a_commitment(&self) -> C::NestedCurve {
        self.nested_a_commitment.0
    }

    pub(crate) fn nested_b_commitment(&self) -> C::NestedCurve {
        self.nested_b_commitment.0
    }

    pub(crate) fn nested_registry_xy_commitment(&self) -> C::NestedCurve {
        self.nested_registry_xy_commitment.0
    }

    pub(crate) fn nested_p_commitment(&self) -> C::NestedCurve {
        self.nested_p_commitment.0
    }

    /// Returns the nested commitment for one of this proof's nested rx
    /// components.
    pub(crate) fn nested_rx_commitment(&self, idx: nested::RxIndex) -> C::NestedCurve {
        use nested::RxIndex::*;
        match idx {
            EndoscalingStep(step) => self.nested_endoscaling_step_commitment(step),
            ExtensionCircuit(k) => self.nested_extension_circuit_commitments[k as usize].0,
            ExtensionStage(k) => self.nested_extension_stage_commitments[k as usize].0,
            EndoscalarStage => self.nested_endoscalar_commitment(),
            PointsStage => self.nested_points_commitment(),
            BridgePreamble => self.bridge_preamble_commitment,
            BridgeSPrime => self.bridge_s_prime_commitment,
            BridgeInnerError => self.bridge_inner_error_commitment,
            BridgeOuterError => self.bridge_outer_error_commitment,
            BridgeAB => self.bridge_ab_commitment.0,
            BridgeQuery => self.bridge_query_commitment,
            BridgeF => self.bridge_f_commitment,
            BridgeEval => self.bridge_eval_commitment,
            ChallengeStage => self.nested_challenges_commitment.0,
            Collapse => self.nested_collapse_commitment.0,
            ComputeV => self.nested_compute_v_commitment.0,
        }
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    crate::Application<'_, C, R, HEADER_SIZE, B>
{
    /// Runs endoscaling over the host-curve commitments that feed
    /// `PointsStage`, in the order `compute_p` (`_10_p.rs`)
    /// accumulates them. Writes `nested_endoscalar_rx`,
    /// `nested_points_rx`, and `nested_endoscaling_step_rxs` onto
    /// `builder`, and returns the accumulated `p` commitment (last
    /// `PointsStage` interstitial) together with the points witness the
    /// nested circuits load.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and by
    /// [`dummy_proof`](Self::dummy_proof), so the nested
    /// endoscaling setup lives in one place.
    pub(crate) fn compute_endoscaling<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        points: &[C::HostCurve],
        endoscalar_alpha: C::ScalarField,
        points_alpha: C::ScalarField,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(C::HostCurve, PointsWitness<C::HostCurve, C::Profile>)> {
        assert_eq!(points.len(), NumPoints::<C::Profile>::len());

        let witness = PointsWitness::<C::HostCurve, C::Profile>::new(beta_endo, points);

        let endoscalar_rx =
            <EndoscalarStage as StageExt<C::ScalarField, R>>::rx(endoscalar_alpha, beta_endo)?;
        let points_rx = <PointsStage<C::HostCurve, C::Profile> as StageExt<C::ScalarField, R>>::rx(
            points_alpha,
            &witness,
        )?;

        let num_steps = NumSteps::<C::Profile>::len();
        let mut step_rxs = Vec::with_capacity(num_steps);
        for step in 0..num_steps {
            let step_circuit = EndoscalingStep::<C::HostCurve, R, C::Profile>::new(step);
            let staged = MultiStage::new(step_circuit);
            let step_trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar: beta_endo,
                    points: &witness,
                })?
                .into_output();
            let step_rx = self.nested_registry.assemble(
                &step_trace,
                nested::InternalCircuitIndex::EndoscalingStep(step as u32)
                    .circuit_index::<C::Profile>(),
                rng,
            )?;
            step_rxs.push(step_rx);
        }

        builder.set_nested_endoscaling_step_rxs(step_rxs);
        builder.set_nested_endoscalar_rx(endoscalar_rx);
        builder.set_nested_points_rx(points_rx);

        let p_commitment = *witness
            .interstitials
            .last()
            .expect("every walk has at least one interstitial");
        Ok((p_commitment, witness))
    }

    /// Commits the native points binding and children stages over the
    /// children's nested commitments, before $w$ is squeezed; the preamble
    /// bridge carries their commitments.
    pub(crate) fn commit_native_points_children<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let (binding, children) = native_points::children_witnesses::<_, C::Profile>(
            &nested::pcs::child_commitments(left).collect::<Vec<_>>(),
            &nested::pcs::child_commitments(right).collect::<Vec<_>>(),
            &left.walked_names()?,
            &right.walked_names()?,
        );
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &binding,
        )?);
        builder.set_native_points_children_rx(<native_points::ChildrenStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &children,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_wx`
    /// commitments, before $y$ is squeezed; the `s_prime` bridge carries its
    /// commitment.
    pub(crate) fn commit_native_points_registry_wx<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wx0: C::NestedCurve,
        registry_wx1: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::RegistryWxWitness {
            registry_wx0,
            registry_wx1,
        };
        builder.set_native_points_registry_wx_rx(<native_points::RegistryWxStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_wy`
    /// commitment, $A_n$ and $B_n$, before $x$ is squeezed; the `ab` bridge
    /// carries its commitment.
    pub(crate) fn commit_native_points_ab<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_wy: C::NestedCurve,
        a: C::NestedCurve,
        b: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::AbWitness { registry_wy, a, b };
        builder.set_native_points_ab_rx(<native_points::AbStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits the native points stage holding the nested `registry_xy`
    /// commitment and $F_n$, before $u$ is squeezed; the `f` bridge carries
    /// its commitment.
    pub(crate) fn commit_native_points_f<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        registry_xy: C::NestedCurve,
        f: C::NestedCurve,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        let witness = native_points::FWitness { registry_xy, f };
        builder.set_native_points_f_rx(<native_points::FStage<C::NestedCurve, C::Profile> as StageExt<
            C::CircuitField,
            R,
        >>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &witness,
        )?);
        Ok(())
    }

    /// Commits every native points input stage at once, for a proof whose
    /// walk needs no transcript schedule: the dummy proof.
    fn commit_native_points_stages<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        inputs: &Inputs<C::NestedCurve, C::Profile>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()> {
        builder.set_native_points_binding_rx(<native_points::BindingStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &inputs.binding,
        )?);
        builder.set_native_points_children_rx(<native_points::ChildrenStage<
            C::NestedCurve,
            C::Profile,
        > as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &inputs.children,
        )?);
        self.commit_native_points_registry_wx(
            rng,
            inputs.registry_wx.registry_wx0,
            inputs.registry_wx.registry_wx1,
            builder,
        )?;
        self.commit_native_points_ab(
            rng,
            inputs.ab.registry_wy,
            inputs.ab.a,
            inputs.ab.b,
            builder,
        )?;
        self.commit_native_points_f(rng, inputs.f.registry_xy, inputs.f.f, builder)
    }

    /// Runs the native endoscaling over the committed inputs: walks them
    /// under `beta_endo`, commits the walk stage, traces the steps, and
    /// writes all of it onto `builder`. Returns $P_n$ (the last
    /// interstitial) with the walk stage's witness.
    ///
    /// Shared by `compute_p` (in `fuse/_10_p.rs`) and
    /// [`dummy_proof`](Self::dummy_proof), like
    /// [`compute_endoscaling`](Self::compute_endoscaling) on the nested side.
    pub(crate) fn compute_native_endoscaling<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        inputs: &Inputs<C::NestedCurve, C::Profile>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<(
        C::NestedCurve,
        native_points::WalkWitness<C::NestedCurve, C::Profile>,
    )> {
        use native_points::{WalkStage, WalkWitness};

        let walk = WalkWitness::new(
            beta_endo,
            crate::internal::endoscalar::PointsWitness::<
                C::NestedCurve,
                native::NumPoints<C::Profile>,
                native::Endoscalings<C::Profile>,
            >::new(beta_endo, &inputs.walk()),
        );

        let walk_rx = <WalkStage<C::NestedCurve, C::Profile> as StageExt<C::CircuitField, R>>::rx(
            C::CircuitField::random(|bytes| rng.fill_bytes(bytes)),
            &walk,
        )?;

        let mut step_rxs = Vec::with_capacity(native::NumSteps::<C::Profile>::len());
        for step in 0..native::NumSteps::<C::Profile>::len() {
            let trace = native::circuits::endoscaling_step::Circuit::<C, R>::new(step)
                .trace(native::circuits::endoscaling_step::Witness {
                    inputs,
                    walk: &walk,
                })?
                .into_output();
            step_rxs.push(
                self.native_registry.assemble(
                    &trace,
                    native::InternalCircuitIndex::EndoscalingStep(step as u32)
                        .circuit_index::<C::Profile>(),
                    &mut *rng,
                )?,
            );
        }

        builder.set_native_points_walk_rx(walk_rx);
        builder.set_native_endoscaling_step_rxs(step_rxs);

        let p_commitment = walk.p();
        Ok((p_commitment, walk))
    }

    /// A synthesized dummy that stands in for the absent predecessors when
    /// bootstrapping.
    ///
    /// This proof does not verify on its own; it is only ever consumed by the
    /// internal [`Bootstrap`](crate::step::internal::bootstrap::Bootstrap) step, whose
    /// fuse is the base case and therefore does not enforce its children's
    /// claims. It carries the [`Dummy`] header so that it can occupy that
    /// step's input slots.
    ///
    /// [`Dummy`]: crate::header::Dummy
    pub(crate) fn dummy_pcd(&self) -> Pcd<C, R, crate::header::Dummy> {
        self.dummy_proof().carry(())
    }

    pub(crate) fn dummy_proof(&self) -> Proof<C, R> {
        let ones_host = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::CircuitField::ONE);
            view.b.push(C::CircuitField::ONE);
            view.c.push(C::CircuitField::ONE);
            view.d.push(C::CircuitField::ONE);
            view.build()
        };
        let host_commitment =
            B::sparse_commit_to_affine(&ones_host, C::host_generators(self.params));
        let ones_nested = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::ScalarField::ONE);
            view.b.push(C::ScalarField::ONE);
            view.c.push(C::ScalarField::ONE);
            view.d.push(C::ScalarField::ONE);
            view.build()
        };

        // registry_xy must be the actual registry evaluation (fuse cross-checks it).
        let registry_xy_poly = B::registry_xy(
            &self.native_registry,
            C::CircuitField::ONE,
            C::CircuitField::ONE,
        );
        // The nested counterpart, at the nested counterparts of the all-one
        // challenges below: a parent opens it at its own nested w.
        let nested_one = nested::challenge::<C>(C::CircuitField::ONE)
            .expect("one is in the endoscalar challenge range");
        let nested_registry_xy_poly = B::registry_xy(&self.nested_registry, nested_one, nested_one);
        // The all-one challenges, and their lifts on the nested side. One is
        // an interpolation node of the quotient fold, so a fold at these
        // challenges selects claim 1 alone. That is harmless: a dummy is never
        // verified on its own, and the bootstrap step that consumes it leaves
        // its c unconstrained.
        let challenges = nested::Challenges {
            w: C::CircuitField::ONE,
            y: C::CircuitField::ONE,
            z: C::CircuitField::ONE,
            mu: C::CircuitField::ONE,
            mu_prime: C::CircuitField::ONE,
            x: C::CircuitField::ONE,
            alpha: C::CircuitField::ONE,
            u: C::CircuitField::ONE,
            pre_beta: C::CircuitField::ONE,
        };
        let lifts = challenges
            .lifts::<C>()
            .expect("one is in the endoscalar challenge range");
        let (challenge_lifts, beta_lift) = lifts.split_at(nested::stages::challenges::NUM);
        // A dummy proof has synthetic traces and a fixed +1 sign. Use the
        // same witness for its binding partials and challenge stage.
        let nested_challenges = nested::stages::challenges::Witness {
            lifts: FixedVec::new(challenge_lifts.to_vec()).expect("NUM challenge lifts"),
            base_case_sign: C::ScalarField::ONE,
            beta: beta_lift[0],
        };

        let mut builder = ProofBuilder::<C, R, B>::new(self.params, C::ScalarField::ONE);

        builder.set_circuit_id(CircuitIndex::new(0));

        builder.set_left_header(vec![C::CircuitField::ZERO; HEADER_SIZE]);
        builder.set_right_header(vec![C::CircuitField::ZERO; HEADER_SIZE]);

        // A dummy proof witnesses nothing itself: every position holds the
        // padding polynomial, the constant 1, as `pad_to_layout` does.
        let layout = HookLayout::of::<C::Profile>();
        let padding_poly = sparse::Polynomial::<_, R>::from_coeffs(vec![C::CircuitField::ONE]);
        let padding_com =
            B::sparse_commit_to_affine(&padding_poly, C::host_generators(self.params));
        let padding_name = poly_commitment::name::<C, R, B>(padding_com, self.params)
            .expect("the padding commitment is a host-curve point");
        builder.set_application_polys(vec![padding_poly.clone(); layout.witness_polys]);
        // Nor does it raise poly-queries: every position holds the padding
        // query, which opens the first polynomial at zero, as the adapter's
        // padding does. The constant 1 evaluates to 1 everywhere.
        let padding_query = PolyQuery {
            com: padding_com,
            x: C::CircuitField::ZERO,
            y: C::CircuitField::ONE,
        };
        builder.set_application_poly_queries(vec![padding_query; layout.poly_queries]);
        // The application stage carries those paddings in its hook region, as
        // the adapter stages them, so the proof's stage and hook lists agree.
        // Without hooks there is no region, and the stage stays the trivial
        // polynomial every other dummy rx is.
        let stage_rx = if layout.poly_query_instance_len() == 0 {
            ones_host.clone()
        } else {
            let hook_region = hook_region::<C>(
                &vec![padding_com; layout.witness_polys],
                &vec![padding_name; layout.witness_polys],
                &vec![padding_query; layout.poly_queries],
            )
            .expect("the padding commitment is a host-curve point");
            staging::stage_rx::<_, R>(C::CircuitField::ONE, 1, self.stage_size(), &hook_region)
                .expect("the hook region fits the application stage")
        };

        // Native rx polynomials (all trivial ones)
        builder.set_native_application_rx(ones_host.clone());
        builder.set_native_application_stage_rx(stage_rx);
        builder.set_native_preamble_rx(ones_host.clone());
        builder.set_native_inner_error_rx(ones_host.clone());
        builder.set_native_outer_error_rx(ones_host.clone());
        builder.set_native_a_poly(ones_host.clone(), host_commitment);
        builder.set_native_b_poly(ones_host.clone(), host_commitment);
        builder.set_native_query_rx(ones_host.clone());
        builder.set_native_registry_xy_poly(registry_xy_poly);
        // The eval stage carries the binding partial sums over the challenge
        // lifts, and the instance their completion; a dummy proof's are
        // those of the all-one challenges.
        let binding = native::stages::eval::BindingPartials::compute::<C, R, B>(
            self.params,
            &nested_challenges,
        );
        builder.set_nested_challenges_partial(binding.binding);
        builder.set_native_eval_rx(
            native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
                C::CircuitField::ONE,
                &native::stages::eval::Witness::<C>::trivial(binding),
            )
            .expect("trivial eval rx"),
        );
        // native_p_poly: deferred until after endoscaling computation,
        // since the real p commitment is the PointsStage last interstitial.
        builder.set_native_hashes_1_rx(ones_host.clone());
        builder.set_native_hashes_2_rx(ones_host.clone());
        builder.set_native_collapse_rx(ones_host.clone());
        builder.set_native_compute_v_rx(ones_host.clone());
        builder.set_native_bind_challenges_rxs(vec![ones_host.clone(); native::NUM_BINDERS]);
        builder.set_native_bind_beta_rx(ones_host.clone());
        builder.set_native_bind_endoscalar_rx(ones_host.clone());
        // The dummy carries the profile's extension polynomials as it does
        // the fuse's own circuits', as all-ones traces.
        let extension = C::Profile::native_extension();
        builder.set_native_extension_circuit_rxs(vec![ones_host.clone(); extension.circuits.len()]);
        builder.set_native_extension_stage_rxs(vec![ones_host.clone(); extension.stages]);

        // Nested accumulator: a trivial claim (all-ones traces), so that a
        // dummy child contributes a well-formed raw claim to its parent's
        // nested fold. The nested batch is trivial too, except for the
        // registry restriction a parent opens. Commitments are computed
        // lazily by the builder, except P_n, which the native walk below
        // computes.
        builder.set_nested_a_poly(ones_nested.clone());
        builder.set_nested_b_poly(ones_nested.clone());
        builder.set_nested_registry_xy_poly(nested_registry_xy_poly);

        let beta_endo = extract_endoscalar(C::CircuitField::ONE)
            .expect("one should satisfy the endoscalar challenge range");
        let mut trivial_rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed([0u8; 32]);

        // The native walk over placeholder nested-curve points, in the
        // nested batch's order, delegated to the real helpers so this
        // trivial setup cannot drift from the prover path. Its result is
        // this proof's P_n.
        // Every placeholder is the commitment of a polynomial this proof
        // holds, so that p_n is their beta-fold and P_n its commitment, as
        // a parent's batch requires of a child.
        let (nested_p_poly, nested_p_commitment) = {
            let nested_commitment =
                B::sparse_commit_to_affine(&ones_nested, C::nested_generators(self.params));
            let registry_xy_commitment = builder.nested_registry_xy_commitment();
            // The names a parent of this placeholder's children walks: the
            // padding polynomial's, in every slot.
            let name_poly = poly_commitment::name_polynomial::<C, R>(padding_com)
                .expect("the padding commitment is a host-curve point");
            let name_point =
                B::sparse_commit_to_affine(&name_poly, C::nested_generators(self.params));
            let mut points = Vec::with_capacity(native::NumPoints::<C::Profile>::len());
            let mut polys: Vec<&sparse::Polynomial<C::ScalarField, R>> =
                Vec::with_capacity(native::NumPoints::<C::Profile>::len());
            let mut push = |point, poly| {
                points.push(point);
                polys.push(poly);
            };
            let registry_xy = builder.nested_registry_xy_poly();
            push(nested_commitment, &ones_nested); // f_n
            for _ in 0..2 {
                for _ in nested::RxIndex::all::<C::Profile>() {
                    push(nested_commitment, &ones_nested);
                }
                push(nested_commitment, &ones_nested); // a
                push(nested_commitment, &ones_nested); // b
                push(registry_xy_commitment, registry_xy); // registry_xy
                push(nested_commitment, &ones_nested); // p placeholder
            }
            push(nested_commitment, &ones_nested); // registry_wx0
            push(nested_commitment, &ones_nested); // registry_wx1
            push(nested_commitment, &ones_nested); // registry_wy
            push(nested_commitment, &ones_nested); // a
            push(nested_commitment, &ones_nested); // b
            push(registry_xy_commitment, registry_xy); // registry_xy
            for _ in 0..2 * layout.witness_polys {
                push(name_point, &name_poly); // a child's name
            }
            let poly = beta_fold(&polys, lift_endoscalar(beta_endo));
            let inputs = Inputs::from_walk(&points);
            self.commit_native_points_stages(&mut trivial_rng, &inputs, &mut builder)
                .expect("trivial native points stages");
            let (commitment, _) = self
                .compute_native_endoscaling(&mut trivial_rng, beta_endo, &inputs, &mut builder)
                .expect("trivial native endoscaling");
            (poly, commitment)
        };
        builder.set_nested_p_poly(nested_p_poly, nested_p_commitment);

        // Commit the same synthetic challenge witness used for the binding
        // partials above, without blinding.
        builder.set_nested_challenges_rx(
            nested::stages::challenges::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ZERO,
                &nested_challenges,
            )
            .expect("trivial challenge stage rx"),
        );
        builder.set_nested_collapse_rx(ones_nested.clone());
        builder.set_nested_compute_v_rx(ones_nested.clone());
        let extension = C::Profile::nested_extension();
        builder
            .set_nested_extension_circuit_rxs(vec![ones_nested.clone(); extension.circuits.len()]);
        builder.set_nested_extension_stage_rxs(vec![ones_nested; extension.stages]);

        // Bridge polynomials: compute via Stage::rx() with trivial witnesses
        // so that traces are valid for their witnesses (not just ones).
        // The cached bridge (ab) is already computed lazily by the builder
        // via cached_bridge! with a proper witness.
        //
        // Order: s_prime, inner_error, outer_error, query, f, eval first
        // (independent of p_commitment), then endoscaling (computes
        // p_commitment), then preamble (needs p_commitment for
        // ChildWitness.p), then native_p_poly.
        let nested_gen = C::nested_generators(self.params);
        {
            let rx = nested::stages::s_prime::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::s_prime::Witness {
                    registry_wx0: host_commitment,
                    registry_wx1: host_commitment,
                    native_points_registry_wx: builder.native_points_registry_wx_commitment(),
                },
            )
            .expect("trivial s_prime rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_s_prime_rx(rx, commitment);
        }
        {
            let rx = nested::stages::inner_error::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::inner_error::Witness {
                    native_inner_error: host_commitment,
                    registry_wy: host_commitment,
                    // A dummy proof folds nothing, so its nested fold has
                    // no error terms.
                    error_terms: FixedVec::from_fn(|_| FixedVec::from_fn(|_| C::ScalarField::ZERO)),
                },
            )
            .expect("trivial inner_error rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_inner_error_rx(rx, commitment);
        }
        {
            let rx = nested::stages::outer_error::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::outer_error::Witness {
                    native_outer_error: builder.native_outer_error_commitment(),
                    error_terms: FixedVec::from_fn(|_| C::ScalarField::ZERO),
                    collapsed: FixedVec::from_fn(|_| C::ScalarField::ZERO),
                },
            )
            .expect("trivial outer_error rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_outer_error_rx(rx, commitment);
        }
        {
            let rx = nested::stages::query::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::query::Witness {
                    native_query: builder.native_query_commitment(),
                    registry_xy: builder.native_registry_xy_commitment(),
                    nested: nested::stages::query::Evaluations::zero(),
                },
            )
            .expect("trivial query rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_query_rx(rx, commitment);
        }
        {
            let rx = nested::stages::f::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::f::Witness {
                    native_f: host_commitment,
                    native_points_f: builder.native_points_f_commitment(),
                },
            )
            .expect("trivial f rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_f_rx(rx, commitment);
        }
        {
            let rx = nested::stages::eval::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::eval::Witness {
                    native_eval: builder.native_eval_commitment(),
                    witness_polys: builder.witness_poly_commitments(),
                    nested: nested::stages::eval::Evaluations::zero(),
                },
            )
            .expect("trivial eval rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_eval_rx(rx, commitment);
        }

        // Build trivial PointsStage inputs in `_10_p` accumulation order
        // and delegate to `compute_endoscaling` so this trivial setup
        // cannot silently drift from the real prover path.
        // As on the nested side: every placeholder is the commitment of a
        // polynomial this proof holds, p is their beta-fold, and P is the
        // walk's result, which is then p's commitment.
        let (p_poly, p_commitment) = {
            let mut points = Vec::with_capacity(NumPoints::<C::Profile>::len());
            let mut polys: Vec<&sparse::Polynomial<C::CircuitField, R>> =
                Vec::with_capacity(NumPoints::<C::Profile>::len());
            let mut push = |point, poly| {
                points.push(point);
                polys.push(poly);
            };
            let registry_xy_commitment = builder.native_registry_xy_commitment();
            let registry_xy = builder.native_registry_xy_poly();

            // Initial: native_f commitment.
            push(host_commitment, &ones_host);

            // Per-child block: all per-child commitments are
            // `host_commitment` (ones_host), except registry_xy which
            // has its own commitment, and the witnessed polynomials, which
            // are padding.
            for _ in 0..2 {
                for _ in RxIndex::all::<C::Profile>() {
                    push(host_commitment, &ones_host);
                }
                push(host_commitment, &ones_host); // AbA
                push(host_commitment, &ones_host); // AbB
                push(registry_xy_commitment, registry_xy); // RegistryXY
                push(host_commitment, &ones_host); // P placeholder
                for _ in 0..layout.witness_polys {
                    push(padding_com, &padding_poly); // witnessed polynomials
                }
            }

            // Current-step bridge inputs.
            push(host_commitment, &ones_host); // registry_wx0
            push(host_commitment, &ones_host); // registry_wx1
            push(host_commitment, &ones_host); // registry_wy
            push(host_commitment, &ones_host); // a
            push(host_commitment, &ones_host); // b
            push(registry_xy_commitment, registry_xy); // native_registry_xy

            let poly = beta_fold(&polys, lift_endoscalar(beta_endo));
            let (commitment, _) = self
                .compute_endoscaling(
                    &mut trivial_rng,
                    beta_endo,
                    &points,
                    C::ScalarField::ONE,
                    C::ScalarField::ONE,
                    &mut builder,
                )
                .expect("trivial endoscaling");
            (poly, commitment)
        };

        // Set native_p_poly with the real accumulated commitment.
        builder.set_native_p_poly(p_poly, p_commitment);

        // Preamble bridge: computed last because ChildWitness.p needs
        // the real p_commitment from endoscaling.
        {
            let registry_xy_commitment = builder.native_registry_xy_commitment();
            let trivial_child_witness = nested::stages::preamble::ChildWitness {
                application: host_commitment,
                application_stage: host_commitment,
                hashes_1: host_commitment,
                hashes_2: host_commitment,
                collapse: host_commitment,
                compute_v: host_commitment,
                bind_challenges: [host_commitment; native::NUM_BINDERS],
                bind_beta: host_commitment,
                bind_endoscalar: host_commitment,
                extension_circuits: FixedVec::from_fn(|_| host_commitment),
                extension_stages: FixedVec::from_fn(|_| host_commitment),
                endoscaling_steps: FixedVec::from_fn(|_| host_commitment),
                points_walk: host_commitment,
                stashed_preamble: host_commitment,
                stashed_inner_error: host_commitment,
                stashed_outer_error: host_commitment,
                stashed_query: host_commitment,
                stashed_eval: host_commitment,
                stashed_ab_a: host_commitment,
                stashed_ab_b: host_commitment,
                stashed_registry_xy: registry_xy_commitment,
                stashed_p: p_commitment,
                stashed_points_binding: host_commitment,
                stashed_points_children: host_commitment,
                stashed_points_registry_wx: host_commitment,
                stashed_points_ab: host_commitment,
                stashed_points_f: host_commitment,
                stashed_witness_polys: FixedVec::from_fn(|_| padding_com),
                // What a parent will read off this proof as its nested
                // instance scalars: a trivial "child" is this proof itself.
                nested: nested::stages::preamble::NestedValues {
                    c: builder.nested_c(),
                    v: B::sparse_eval(builder.nested_p_poly(), nested_one),
                    x: nested_one,
                    y: nested_one,
                    u: nested_one,
                },
            };
            let rx = nested::stages::preamble::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &nested::stages::preamble::Witness {
                    native_preamble: host_commitment,
                    native_points_binding: builder.native_points_binding_commitment(),
                    native_points_children: builder.native_points_children_commitment(),
                    left: trivial_child_witness.clone(),
                    right: trivial_child_witness,
                },
            )
            .expect("trivial preamble rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_preamble_rx(rx, commitment);
        }

        // Challenges (all ones for trivial)
        builder.set_w(C::CircuitField::ONE);
        builder.set_y(C::CircuitField::ONE);
        builder.set_z(C::CircuitField::ONE);
        builder.set_mu(C::CircuitField::ONE);
        builder.set_mu_prime(C::CircuitField::ONE);
        builder.set_x(C::CircuitField::ONE);
        builder.set_alpha(C::CircuitField::ONE);
        builder.set_u(C::CircuitField::ONE);
        builder.set_pre_beta(C::CircuitField::ONE);

        // Commitments are computed lazily by the builder from the polynomials.
        builder.build().expect("dummy proof construction failed")
    }
}

#[cfg(test)]
impl<C: Cycle, R: Rank> Proof<C, R> {
    /// Doubles the native extension polynomial at `index` and recommits it,
    /// so that a test can check that the polynomial itself is bound and not
    /// only its cache.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not an extension circuit's or stage's.
    pub(crate) fn double_native_extension_rx(&mut self, params: &C::Params, index: RxIndex) {
        use ragu_backend::{Backend, ReferenceBackend};

        let (rx, commitment) = match index {
            RxIndex::ExtensionCircuit(k) => (
                &mut self.native_extension_circuit_rxs[k as usize],
                &mut self.native_extension_circuit_commitments[k as usize],
            ),
            RxIndex::ExtensionStage(k) => (
                &mut self.native_extension_stage_rxs[k as usize],
                &mut self.native_extension_stage_commitments[k as usize],
            ),
            _ => panic!("{index:?} is not an extension polynomial"),
        };
        rx.scale(C::CircuitField::ONE + C::CircuitField::ONE);
        commitment.0 = ReferenceBackend::sparse_commit_to_affine(rx, C::host_generators(params));
    }

    /// The nested counterpart of
    /// [`double_native_extension_rx`](Self::double_native_extension_rx).
    ///
    /// # Panics
    ///
    /// Panics if `index` is not an extension circuit's or stage's.
    pub(crate) fn double_nested_extension_rx(
        &mut self,
        params: &C::Params,
        index: nested::RxIndex,
    ) {
        use ragu_backend::{Backend, ReferenceBackend};

        let (rx, commitment) = match index {
            nested::RxIndex::ExtensionCircuit(k) => (
                &mut self.nested_extension_circuit_rxs[k as usize],
                &mut self.nested_extension_circuit_commitments[k as usize],
            ),
            nested::RxIndex::ExtensionStage(k) => (
                &mut self.nested_extension_stage_rxs[k as usize],
                &mut self.nested_extension_stage_commitments[k as usize],
            ),
            _ => panic!("{index:?} is not an extension polynomial"),
        };
        rx.scale(C::ScalarField::ONE + C::ScalarField::ONE);
        commitment.0 = ReferenceBackend::sparse_commit_to_affine(rx, C::nested_generators(params));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the `bridge_alpha` exponent series: no registry tag covers these
    /// prover-side blinds, so a collision would otherwise be silent.
    #[test]
    fn bridge_alpha_exponents_are_the_expected_series() {
        assert_eq!(bridge_alpha_exponent(nested::RxIndex::BridgeAB), 2);
    }

    /// Bridges blinded at random are not on this series.
    #[test]
    #[should_panic(expected = "not blinded from bridge_alpha")]
    fn unblinded_bridges_are_rejected() {
        bridge_alpha_exponent(nested::RxIndex::BridgeF);
    }
}
