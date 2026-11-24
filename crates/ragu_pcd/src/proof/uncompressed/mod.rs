//! The uncompressed proof and its proof-carrying data.
//!
//! Defines the [`Proof`] structure containing trace polynomials, commitments,
//! and accumulated claims, along with [`Pcd`] which bundles a [`Proof`] with
//! the data that a [`Header`] succinctly encodes. Fields are organized by
//! protocol phase (application proof, folding, query/evaluation, and
//! commitment opening) alongside verifier challenges and bridge/nested-curve
//! data, kept flat to make verification and proof transformation explicit.
//!
//! The proof's builder (`builder.rs`), the dummy proof (`dummy.rs`) and the
//! uncompressed verifier (`verifier.rs`, a test oracle behind `test-utils`)
//! are children of this module. Its byte codec is
//! `serialization/uncompressed.rs`.

pub(crate) mod builder;
mod dummy;
// The uncompressed verifier, a test oracle rather than a production path. It
// gates itself behind `test-utils` (or the crate's own tests) with an inner
// `#![cfg]`.
pub(crate) mod verifier;
// Mutable component access for the corruption vocabulary (see
// `crate::fuzzing`). Its source lives with the rest of the fuzzing surface in
// `tests/fuzzing/`, but it is mounted here, beside `Proof`, so it can
// reach the private `Cached` fields without loosening them. The file gates
// itself behind `unstable-fuzzing` with an inner `#![cfg]`, so no feature
// attribute appears here.
// TODO: Revisit this layout; for now, it keeps the fuzzing surface in one
// directory without loosening `Proof`'s privacy or adding a feature
// attribute here.
#[path = "../../../tests/fuzzing/access.rs"]
mod access;

use alloc::{sync::Arc, vec::Vec};

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_core::{Cycle, FixedGenerators, Result};
use ragu_primitives::vec::Len;
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use crate::{
    header::{Header, NUM_ONLINE_FP_POLYS},
    internal::{
        native::{self, RxComponent, RxIndex, online},
        nested::{self},
    },
    profile::{Profile, ProfiledCycle},
};

/// A newtype marking a field as derived/cacheable.
///
/// Wraps a value that can be recomputed from primary proof data. Used to
/// distinguish commitment caches from primary polynomial fields at the type
/// level. Treated as immutable once constructed: the builder and the wire
/// codec construct it, and only the fuzzing hooks edit one in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cached<T>(pub(crate) T);

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

    /// The proof's polynomials associated with its output header, one
    /// coefficient vector in ascending degree per slot, as the step that
    /// produced this proof committed them.
    pub fn polynomials(&self) -> [Vec<C::CircuitField>; NUM_ONLINE_FP_POLYS] {
        online::coefficients(self.proof.online_polynomials())
    }

    /// The commitments of [`polynomials`](Self::polynomials), one per slot:
    /// what a parent opens as its left or right slots, and what
    /// [`Application::commit`](crate::Application::commit) computes from
    /// the coefficients.
    pub fn commitments(&self) -> [C::HostCurve; NUM_ONLINE_FP_POLYS] {
        self.proof.online_commitments()
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

/// The alpha of a cached bridge polynomial, as a distinct power of the
/// proof's `bridge_alpha`; shared by the builder that derives the bridge and
/// the verifier that rederives it.
pub(crate) fn bridge_alpha_power<F: Field>(bridge_alpha: F, idx: nested::RxIndex) -> F {
    let n = match idx {
        nested::RxIndex::BridgeAB => 2,
        _ => panic!("not a cached bridge: {idx:?}"),
    };
    bridge_alpha.pow_u64(n)
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

    // Application metadata. The proof carries no header: its output header
    // is encoded from the data it carries, and its input headers were
    // checked by its own application claim, which it folded.
    pub(crate) circuit_id: CircuitIndex,
    /// The nested source mesh's coordinates and shared intersection values,
    /// empty without a nested mesh.
    pub(crate) nested_mesh_claims: Vec<C::ScalarField>,
    /// The nested helper's quotient and evaluation sums, empty when the
    /// nested online batch is inactive.
    pub(crate) nested_online_fold: Vec<C::ScalarField>,
    /// The native source mesh's coordinates and shared intersection values,
    /// empty without a native mesh.
    pub(crate) native_mesh_claims: Vec<C::CircuitField>,
    /// The native helper's quotient and evaluation sums, empty when the
    /// native online batch is inactive.
    pub(crate) native_online_fold: Vec<C::CircuitField>,
    /// Common claim targets for the actual nested online walk points.
    pub(crate) nested_online_commitments: Vec<C::NestedCurve>,
    /// Common claim targets for the actual native online walk points.
    pub(crate) native_online_commitments: Vec<C::HostCurve>,

    /// The retained source-registry restriction for the next parent, if declared.
    pub(crate) native_source_out: Vec<sparse::Polynomial<C::CircuitField, R>>,

    /// The retained source-registry restriction for the next parent, if declared.
    pub(crate) nested_source_out: Vec<sparse::Polynomial<C::ScalarField, R>>,

    // Native rx polynomials (CircuitField, HostCurve commitment)
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
    pub(crate) native_points_preamble_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_registry_wx_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_ab_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_f_rx: sparse::Polynomial<C::CircuitField, R>,
    pub(crate) native_points_walk_rx: sparse::Polynomial<C::CircuitField, R>,

    /// This step's output polynomials exposed through the polynomial-query API,
    /// padded with the constant one (see `internal::native::online`). Committed
    /// before `w`; the parent opens them as its left or right slots.
    pub(crate) online_polynomials: [sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_POLYS],
    /// In a profile with a statement circuit, the opening point of the
    /// left input's first slot (see [`online::step_binding`]). That point
    /// exposes the staged digest in a decompression step. The step's
    /// `hashes_1` exports the point after the output header and circuit id.
    /// The parent binds its copy to that export. Empty for a profile without
    /// a statement circuit.
    pub(crate) step_binding: Vec<C::CircuitField>,
    /// The commitments of the step's online Fq polynomials the profile's
    /// native binding names, in its order: what the step's
    /// `bind_endoscalar` exports and its binding circuit exposes, which
    /// the parent holds once for both claims. Empty for a profile that
    /// names none.
    pub(crate) online_fq_commitments: Vec<C::NestedCurve>,
    /// The openings of the step's online Fq polynomials the profile's
    /// nested binding names, the point then the value of each, in its
    /// order: what the step's nested `compute_v` exports and its binding
    /// circuit exposes. Empty for a profile that names none.
    pub(crate) online_fq_openings: Vec<C::ScalarField>,

    // Bridge rx polynomials (non-cached, set by caller)
    pub(crate) bridge_preamble_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    /// The bridge-hash stage: the step's own `O1`, constructed with a zero
    /// alpha (see `nested::stages::bridge_hash`).
    pub(crate) bridge_hash_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_s_prime_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_inner_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_outer_error_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_query_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_f_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,
    pub(crate) bridge_eval_rx: Arc<sparse::Polynomial<C::ScalarField, R>>,

    // Bridge rx polynomial (cached, derived from bridge_alpha + native commitments)
    pub(crate) bridge_ab_rx: Cached<Arc<sparse::Polynomial<C::ScalarField, R>>>,

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

    // Nested challenge stage (ScalarField, zero-alpha NestedCurve
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
    pub(crate) nested_endoscaling_step_commitments: Vec<Cached<C::NestedCurve>>,
    pub(crate) nested_extension_circuit_commitments: Vec<Cached<C::NestedCurve>>,
    pub(crate) nested_extension_stage_commitments: Vec<Cached<C::NestedCurve>>,
    pub(crate) nested_endoscalar_commitment: Cached<C::NestedCurve>,
    pub(crate) nested_points_commitment: Cached<C::NestedCurve>,

    // Nested accumulator commitment caches
    pub(crate) nested_a_commitment: Cached<C::NestedCurve>,
    pub(crate) nested_b_commitment: Cached<C::NestedCurve>,

    // Nested batch commitment caches
    pub(crate) nested_registry_xy_commitment: Cached<C::NestedCurve>,
    pub(crate) nested_p_commitment: Cached<C::NestedCurve>,

    // Nested challenge stage commitment cache
    pub(crate) nested_challenges_commitment: Cached<C::NestedCurve>,

    // Nested instance circuit commitment caches
    pub(crate) nested_collapse_commitment: Cached<C::NestedCurve>,
    pub(crate) nested_compute_v_commitment: Cached<C::NestedCurve>,

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
    pub(crate) native_preamble_commitment: Cached<C::HostCurve>,
    pub(crate) native_inner_error_commitment: Cached<C::HostCurve>,
    pub(crate) native_outer_error_commitment: Cached<C::HostCurve>,
    pub(crate) native_a_commitment: Cached<C::HostCurve>,
    pub(crate) native_b_commitment: Cached<C::HostCurve>,
    pub(crate) native_query_commitment: Cached<C::HostCurve>,
    pub(crate) native_registry_xy_commitment: Cached<C::HostCurve>,
    pub(crate) native_eval_commitment: Cached<C::HostCurve>,
    pub(crate) native_p_commitment: Cached<C::HostCurve>,
    pub(crate) native_hashes_1_commitment: Cached<C::HostCurve>,
    pub(crate) native_hashes_2_commitment: Cached<C::HostCurve>,
    pub(crate) native_collapse_commitment: Cached<C::HostCurve>,
    pub(crate) native_compute_v_commitment: Cached<C::HostCurve>,
    pub(crate) native_bind_challenges_commitments: Vec<Cached<C::HostCurve>>,
    pub(crate) native_bind_beta_commitment: Cached<C::HostCurve>,
    pub(crate) native_bind_endoscalar_commitment: Cached<C::HostCurve>,
    pub(crate) native_endoscaling_step_commitments: Vec<Cached<C::HostCurve>>,
    pub(crate) native_extension_circuit_commitments: Vec<Cached<C::HostCurve>>,
    pub(crate) native_extension_stage_commitments: Vec<Cached<C::HostCurve>>,
    pub(crate) native_points_binding_commitment: Cached<C::HostCurve>,
    pub(crate) native_points_preamble_commitment: Cached<C::HostCurve>,
    pub(crate) native_points_registry_wx_commitment: Cached<C::HostCurve>,
    pub(crate) native_points_ab_commitment: Cached<C::HostCurve>,
    pub(crate) native_points_f_commitment: Cached<C::HostCurve>,
    pub(crate) native_points_walk_commitment: Cached<C::HostCurve>,
    /// Commitments to this step's output polynomials.
    /// Nested collapse binds their exported instance values to the points
    /// in this step's prechallenge Preamble. The parent uses those same
    /// exported points as its input polynomial commitments.
    pub(crate) online_commitments: [Cached<C::HostCurve>; NUM_ONLINE_FP_POLYS],

    // Bridge commitments (non-cached)
    pub(crate) bridge_preamble_commitment: C::NestedCurve,
    pub(crate) bridge_hash_commitment: C::NestedCurve,
    pub(crate) bridge_s_prime_commitment: C::NestedCurve,
    pub(crate) bridge_inner_error_commitment: C::NestedCurve,
    pub(crate) bridge_outer_error_commitment: C::NestedCurve,
    pub(crate) bridge_query_commitment: C::NestedCurve,
    pub(crate) bridge_f_commitment: C::NestedCurve,
    pub(crate) bridge_eval_commitment: C::NestedCurve,

    // Bridge commitment (cached, derived from the cached bridge rx)
    pub(crate) bridge_ab_commitment: Cached<C::NestedCurve>,
}

impl<C: ProfiledCycle, R: Rank> Proof<C, R> {
    /// Whether the stored `ab` bridge equals the stage derived from this
    /// proof's native commitments and `bridge_alpha`, with a zero blind gate.
    /// Call after checking the proof's shape with [`Self::well_formed`].
    pub(crate) fn ab_bridge_matches(&self) -> Result<bool> {
        use nested::stages::ab;

        use crate::profile::online::stages::{Native, phase_points};

        let expected = ab::Stage::<C::HostCurve, R, C::Profile>::rx(
            bridge_alpha_power(self.bridge_alpha, nested::RxIndex::BridgeAB),
            &ab::Witness {
                online_points: phase_points::<C::Profile, Native, 2, _>(
                    &self.native_online_commitments,
                ),
                a: self.native_commitment(RxComponent::AbA),
                b: self.native_commitment(RxComponent::AbB),
                native_points_ab: self.native_rx_commitment(RxIndex::PointsAb),
            },
        )?;
        // Sparse blocks may retain explicit zeros, including after decoding
        // changes the block layout. Compare only the nonzero terms.
        let nonzero =
            |&(_, coefficient): &(usize, &C::ScalarField)| *coefficient != C::ScalarField::ZERO;
        Ok(self
            .bridge_ab_rx
            .0
            .iter_stored_coeffs()
            .filter(nonzero)
            .eq(expected.iter_stored_coeffs().filter(nonzero)))
    }

    /// The helper's public values, deriving challenges from the proof transcript.
    pub(crate) fn nested_online_values(&self) -> Result<Vec<C::ScalarField>> {
        crate::internal::ky::nested_online_values::<C>(&self.challenges(), &self.nested_online_fold)
    }

    /// Whether the polynomial vectors and commitment-cache vectors have
    /// exactly the receiving profile's shape. Check before traversing
    /// components so that missing entries cannot panic and trailing ones
    /// cannot be ignored.
    pub(crate) fn well_formed(&self) -> bool {
        let native_steps = native::NumSteps::<C::Profile>::len();
        let nested_steps = nested::NumSteps::<C::Profile>::len();
        let native_extension = crate::profile::native_extension::<C::Profile>();
        let nested_extension = crate::profile::nested_extension::<C::Profile>();

        self.native_source_out.len() == usize::from(C::Profile::NATIVE_MESH.is_some())
            && self.nested_source_out.len() == usize::from(C::Profile::NESTED_MESH.is_some())
            && self.native_mesh_claims.len()
                == C::Profile::NATIVE_MESH.map_or(0, |mesh| mesh.claims_len())
            && self.nested_mesh_claims.len()
                == C::Profile::NESTED_MESH.map_or(0, |mesh| mesh.claims_len())
            && self.native_online_commitments.len() == C::Profile::NATIVE_ONLINE.polynomials.len()
            && self.nested_online_commitments.len() == C::Profile::NESTED_ONLINE.polynomials.len()
            && self.native_online_fold.len()
                == <crate::profile::online::stages::Present<
                    C::Profile,
                    crate::profile::online::stages::Native,
                    2,
                > as ragu_primitives::vec::Len>::len()
            && self.nested_online_fold.len()
                == crate::profile::online::stages::Present::<
                    C::Profile,
                    crate::profile::online::stages::Nested,
                    2,
                >::len()
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
            && self.step_binding.len() == native::online::StepBindingLen::<C::Profile>::len()
            && self.online_fq_commitments.len()
                == nested::online::BoundCommitmentsLen::<C::Profile>::len()
            && self.online_fq_openings.len()
                == nested::online::BoundOpeningsLen::<C::Profile>::len()
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
            PointsPreamble => &self.native_points_preamble_rx,
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
            BridgeHash => self.bridge_hash_rx.as_ref(),
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

/// Whether `commitments` are the commitments of `polys` under `generators`,
/// as one batch: the Horner combination of the polynomials under `r` must
/// commit to the same combination of the points, which a mismatch in any
/// pair breaks unless `r` is a root of the difference. Shared by the
/// uncompressed verifier and the compressor, which both rederive a proof's
/// cached commitments.
pub(crate) fn commitments_match<B, F, P, R, G>(
    polys: &[&sparse::Polynomial<F, R>],
    commitments: &[P],
    r: F,
    generators: &G,
) -> bool
where
    B: Backend,
    F: Field,
    P: Affine<Scalar = F>,
    R: Rank,
    G: FixedGenerators<P>,
{
    assert_eq!(polys.len(), commitments.len());
    let folded = sparse::Polynomial::fold(polys.iter().copied(), r);
    let expected = B::sparse_commit_to_affine(&folded, generators);

    // Polynomial i carries r^{n-1-i}; so does its commitment.
    let n = commitments.len();
    let mut weights = alloc::vec![F::ONE; n];
    for i in (0..n.saturating_sub(1)).rev() {
        weights[i] = weights[i + 1] * r;
    }
    B::msm(weights.iter(), commitments.iter()).to_affine() == expected
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
                self.native_rx_commitment(RxIndex::PointsPreamble),
                self.native_rx_commitment(RxIndex::PointsRegistryWx),
                self.native_rx_commitment(RxIndex::PointsAb),
                self.native_rx_commitment(RxIndex::PointsF),
                self.online_commitments[0].0,
                self.online_commitments[1].0,
            ],
            coverage: Default::default(),
        })
    }

    /// This step's output polynomials exposed through the polynomial-query
    /// API, in slot order, padded with the constant one.
    pub(crate) fn online_polynomials(
        &self,
    ) -> &[sparse::Polynomial<C::CircuitField, R>; NUM_ONLINE_FP_POLYS] {
        &self.online_polynomials
    }

    /// The commitments of [`online_polynomials`](Self::online_polynomials),
    /// which this proof's nested instance exports.
    pub(crate) fn online_commitments(&self) -> [C::HostCurve; NUM_ONLINE_FP_POLYS] {
        self.online_commitments
            .clone()
            .map(|commitment| commitment.0)
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
            PointsPreamble => self.native_points_preamble_commitment.0,
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

    /// $H^{bridge}(O_1)$: the commitment of the bridge-hash stage holding
    /// the step's own `O1`.
    pub(crate) fn bridge_hash_commitment(&self) -> C::NestedCurve {
        self.bridge_hash_commitment
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
            BridgeHash => self.bridge_hash_commitment,
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
