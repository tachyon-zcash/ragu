//! The wire codec of [`Proof`]: every field in declaration order, each with
//! the codec it encodes under. Decoding builds the struct from this list, so a
//! field missing from it is a build error.

#[cfg(test)]
#[path = "../../tests/serialization/malformed_proofs.rs"]
mod malformed_proof_tests;
#[cfg(test)]
#[path = "../../tests/serialization/validation.rs"]
mod wire_validation_tests;

use alloc::vec::Vec;

use ragu_circuits::polynomials::Rank;
use ragu_primitives::vec::ConstLen;

use crate::{
    Proof,
    internal::{native, nested},
    profile::ProfiledCycle,
    proof::uncompressed::Cached,
    serialization::{self, Decode, Encode},
};

/// Generates the codec of [`Proof`] from its fields and their codecs. The
/// field types are inferred from the struct; `encoded_len` alone has no
/// value to infer them from and takes them from a projection.
macro_rules! codec {
    ($($field:ident => $codec:ty),* $(,)?) => {
        /// The fields in wire order, for the fixtures that pin the format.
        #[cfg(test)]
        pub(crate) const WIRE_FIELDS: &[&str] = &[$(stringify!($field)),*];

        impl<C: ProfiledCycle, R: Rank> Encode for Proof<C, R> {
            fn encode(
                &self,
                output: &mut Vec<u8>,
                dims: serialization::Dimensions,
            ) -> core::result::Result<(), serialization::Error<'static>> {
                $( <_ as Encode<$codec>>::encode(&self.$field, output, dims)?; )*
                Ok(())
            }
        }

        impl<C: ProfiledCycle, R: Rank> Decode for Proof<C, R> {
            fn encoded_len(dims: serialization::Dimensions) -> usize {
                0usize $( + serialization::field_len::<Self, _, $codec>(|proof| &proof.$field, dims) )*
            }
            fn decode<'a>(
                reader: &mut serialization::Reader<'a>,
                dims: serialization::Dimensions,
            ) -> core::result::Result<Self, serialization::Error<'a>> {
                Ok(Self {
                    $( $field: <_ as Decode<$codec>>::decode(reader, dims)?, )*
                })
            }
        }
    };
}

codec! {
    bridge_alpha => serialization::Scalar,

    // Application metadata
    circuit_id => serialization::DefaultEncoding,
    nested_mesh_claims => serialization::FixedSequence<serialization::Scalar, crate::profile::online::stages::MeshClaimsLen<C::Profile, crate::profile::online::stages::Nested>>,
    nested_online_fold => serialization::FixedSequence<serialization::Scalar, crate::profile::online::stages::Present<C::Profile, crate::profile::online::stages::Nested, 2>>,
    native_mesh_claims => serialization::FixedSequence<serialization::Scalar, crate::profile::online::stages::MeshClaimsLen<C::Profile, crate::profile::online::stages::Native>>,
    native_online_fold => serialization::FixedSequence<serialization::Scalar, crate::profile::online::stages::Present<C::Profile, crate::profile::online::stages::Native, 2>>,
    nested_online_commitments => serialization::FixedSequence<crate::serialization::Point, crate::profile::online::stages::PolynomialsLen<C::Profile, crate::profile::online::stages::Nested>>,
    native_online_commitments => serialization::FixedSequence<crate::serialization::Point, crate::profile::online::stages::PolynomialsLen<C::Profile, crate::profile::online::stages::Native>>,

    native_source_out => serialization::FixedSequence<serialization::DefaultEncoding, crate::profile::online::stages::MeshPresent<C::Profile,crate::profile::online::stages::Native,1>>,

    nested_source_out => serialization::FixedSequence<serialization::DefaultEncoding, crate::profile::online::stages::MeshPresent<C::Profile,crate::profile::online::stages::Nested,1>>,

    // Native rx polynomials (CircuitField, HostCurve commitment)
    native_preamble_rx => serialization::DefaultEncoding,
    native_inner_error_rx => serialization::DefaultEncoding,
    native_outer_error_rx => serialization::DefaultEncoding,
    native_a_poly => serialization::DefaultEncoding,
    native_b_poly => serialization::DefaultEncoding,
    native_query_rx => serialization::DefaultEncoding,
    native_registry_xy_poly => serialization::DefaultEncoding,
    native_eval_rx => serialization::DefaultEncoding,
    native_p_poly => serialization::DefaultEncoding,
    native_hashes_1_rx => serialization::DefaultEncoding,
    native_hashes_2_rx => serialization::DefaultEncoding,
    native_collapse_rx => serialization::DefaultEncoding,
    native_compute_v_rx => serialization::DefaultEncoding,
    native_bind_challenges_rxs => serialization::FixedSequence<serialization::DefaultEncoding, ConstLen<{ native::NUM_BINDERS }>>,
    native_bind_beta_rx => serialization::DefaultEncoding,
    // The native endoscaling walk over the nested batch's commitments: the
    // endoscalar binding circuit, the steps, the five points stages holding
    // the walk's inputs (see `native::stages::points`) and the walk stage
    // holding the endoscalar's bits and the interstitials.
    native_bind_endoscalar_rx => serialization::DefaultEncoding,
    native_endoscaling_step_rxs => serialization::FixedSequence<serialization::DefaultEncoding, native::NumSteps<C::Profile>>,
    native_extension_circuit_rxs => serialization::FixedSequence<serialization::DefaultEncoding, native::NumExtensionCircuits<C::Profile>>,
    native_extension_stage_rxs => serialization::FixedSequence<serialization::DefaultEncoding, native::NumExtensionStages<C::Profile>>,
    native_walk_rxs => serialization::FixedSequence<serialization::DefaultEncoding, native::NumWalkRx<C::Profile>>,
    native_program_rxs => serialization::FixedSequence<serialization::DefaultEncoding, native::NumProgramRx<C::Profile>>,
    native_points_binding_rx => serialization::DefaultEncoding,
    native_points_preamble_rx => serialization::DefaultEncoding,
    native_points_registry_wx_rx => serialization::DefaultEncoding,
    native_points_ab_rx => serialization::DefaultEncoding,
    native_points_f_rx => serialization::DefaultEncoding,
    native_points_walk_rx => serialization::DefaultEncoding,

    // The step's own online polynomials (CircuitField, HostCurve commitment)
    online_polynomials => serialization::Array<serialization::DefaultEncoding>,
    // What the step exposes of its online openings for the statement
    // claim's step binding, for a profile with a statement circuit: nothing
    // on the wire for one without
    step_binding => serialization::FixedSequence<serialization::Scalar, native::online::StepBindingLen<C::Profile>>,

    // Bridge rx polynomials (non-cached, set by caller)
    bridge_preamble_rx => serialization::DefaultEncoding,
    bridge_hash_rx => serialization::DefaultEncoding,
    bridge_s_prime_rx => serialization::DefaultEncoding,
    bridge_inner_error_rx => serialization::DefaultEncoding,
    bridge_outer_error_rx => serialization::DefaultEncoding,
    bridge_query_rx => serialization::DefaultEncoding,
    bridge_f_rx => serialization::DefaultEncoding,
    bridge_eval_rx => serialization::DefaultEncoding,

    // Bridge rx polynomial (cached, derived from bridge_alpha + native commitments)
    bridge_ab_rx => serialization::DefaultEncoding,

    // Nested endoscaling data (ScalarField, NestedCurve commitment)
    nested_endoscaling_step_rxs => serialization::FixedSequence<serialization::DefaultEncoding, nested::NumSteps<C::Profile>>,
    nested_extension_circuit_rxs => serialization::FixedSequence<serialization::DefaultEncoding, nested::NumExtensionCircuits<C::Profile>>,
    nested_extension_stage_rxs => serialization::FixedSequence<serialization::DefaultEncoding, nested::NumExtensionStages<C::Profile>>,
    nested_paged_stage_rxs => serialization::FixedSequence<serialization::DefaultEncoding, nested::NumPagedStages<C::Profile>>,
    nested_step_rxs => serialization::FixedSequence<serialization::DefaultEncoding, nested::NumProgramSteps<C::Profile>>,
    nested_endoscalar_rx => serialization::DefaultEncoding,
    nested_points_rx => serialization::DefaultEncoding,

    // Nested accumulator polynomials (ScalarField, NestedCurve commitment):
    // the children's nested claims, folded.
    nested_a_poly => serialization::DefaultEncoding,
    nested_b_poly => serialization::DefaultEncoding,

    // Nested batch polynomials (ScalarField, NestedCurve commitment): the
    // $m_n(W, x_n, y_n)$ restriction, and the batch accumulated into $p_n$.
    nested_registry_xy_poly => serialization::DefaultEncoding,
    nested_p_poly => serialization::DefaultEncoding,

    // Nested challenge stage (ScalarField, zero-alpha NestedCurve
    // commitment): the lifts of this step's native challenges, the
    // base-case sign and the lift of `pre_beta`.
    nested_challenges_rx => serialization::DefaultEncoding,
    // The challenge stage's commitment without its beta term: the sum the
    // `bind_challenges` circuits recompute from the transcript challenges,
    // carried by the native unified instance so that a parent can complete
    // it and hold it against the stage it walks.
    nested_challenges_partial => serialization::Point,

    // Nested instance circuits (ScalarField, NestedCurve commitments): the
    // collapse circuit pins the nested unified instance to the stages and
    // verifies the nested fold; compute-v checks the nested batch evaluation.
    nested_collapse_rx => serialization::DefaultEncoding,
    nested_compute_v_rx => serialization::DefaultEncoding,

    // Nested endoscaling commitment caches
    nested_endoscaling_step_commitments => serialization::FixedSequence<CachedPoint, nested::NumSteps<C::Profile>>,
    nested_extension_circuit_commitments => serialization::FixedSequence<CachedPoint, nested::NumExtensionCircuits<C::Profile>>,
    nested_extension_stage_commitments => serialization::FixedSequence<CachedPoint, nested::NumExtensionStages<C::Profile>>,
    nested_paged_stage_commitments => serialization::FixedSequence<CachedPoint, nested::NumPagedStages<C::Profile>>,
    nested_step_commitments => serialization::FixedSequence<CachedPoint, nested::NumProgramSteps<C::Profile>>,
    nested_endoscalar_commitment => CachedPoint,
    nested_points_commitment => CachedPoint,

    // Nested accumulator commitment caches
    nested_a_commitment => CachedPoint,
    nested_b_commitment => CachedPoint,

    // Nested batch commitment caches
    nested_registry_xy_commitment => CachedPoint,
    nested_p_commitment => CachedPoint,

    // Nested challenge stage commitment cache
    nested_challenges_commitment => CachedPoint,

    // Nested instance circuit commitment caches
    nested_collapse_commitment => CachedPoint,
    nested_compute_v_commitment => CachedPoint,

    // Challenges
    w => serialization::Scalar,
    y => serialization::Scalar,
    z => serialization::Scalar,
    mu => serialization::Scalar,
    mu_prime => serialization::Scalar,
    x => serialization::Scalar,
    alpha => serialization::Scalar,
    u => serialization::Scalar,
    pre_beta => serialization::Scalar,

    // Native commitment caches
    native_preamble_commitment => CachedPoint,
    native_inner_error_commitment => CachedPoint,
    native_outer_error_commitment => CachedPoint,
    native_a_commitment => CachedPoint,
    native_b_commitment => CachedPoint,
    native_query_commitment => CachedPoint,
    native_registry_xy_commitment => CachedPoint,
    native_eval_commitment => CachedPoint,
    native_p_commitment => CachedPoint,
    native_hashes_1_commitment => CachedPoint,
    native_hashes_2_commitment => CachedPoint,
    native_collapse_commitment => CachedPoint,
    native_compute_v_commitment => CachedPoint,
    native_bind_challenges_commitments => serialization::FixedSequence<CachedPoint, ConstLen<{ native::NUM_BINDERS }>>,
    native_bind_beta_commitment => CachedPoint,
    native_bind_endoscalar_commitment => CachedPoint,
    native_endoscaling_step_commitments => serialization::FixedSequence<CachedPoint, native::NumSteps<C::Profile>>,
    native_extension_circuit_commitments => serialization::FixedSequence<CachedPoint, native::NumExtensionCircuits<C::Profile>>,
    native_extension_stage_commitments => serialization::FixedSequence<CachedPoint, native::NumExtensionStages<C::Profile>>,
    native_walk_commitments => serialization::FixedSequence<CachedPoint, native::NumWalkRx<C::Profile>>,
    native_program_commitments => serialization::FixedSequence<CachedPoint, native::NumProgramRx<C::Profile>>,
    native_points_binding_commitment => CachedPoint,
    native_points_preamble_commitment => CachedPoint,
    native_points_registry_wx_commitment => CachedPoint,
    native_points_ab_commitment => CachedPoint,
    native_points_f_commitment => CachedPoint,
    native_points_walk_commitment => CachedPoint,
    online_commitments => serialization::Array<CachedPoint>,

    // Bridge commitments (non-cached)
    bridge_preamble_commitment => serialization::Point,
    bridge_hash_commitment => serialization::Point,
    bridge_s_prime_commitment => serialization::Point,
    bridge_inner_error_commitment => serialization::Point,
    bridge_outer_error_commitment => serialization::Point,
    bridge_query_commitment => serialization::Point,
    bridge_f_commitment => serialization::Point,
    bridge_eval_commitment => serialization::Point,

    // Bridge commitment (cached, derived from the cached bridge rx)
    bridge_ab_commitment => CachedPoint,
}

/// The wire codec of a [`Cached`] commitment: the point itself. A marker of
/// its own keeps the impl clear of the point codec's blanket over every
/// `Affine` type, which coherence cannot rule out for `Cached`.
struct CachedPoint;

impl<G: Encode<serialization::Point>> Encode<CachedPoint> for Cached<G> {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: serialization::Dimensions,
    ) -> core::result::Result<(), serialization::Error<'static>> {
        <G as Encode<serialization::Point>>::encode(&self.0, output, dims)
    }
}

impl<G: Decode<serialization::Point>> Decode<CachedPoint> for Cached<G> {
    fn encoded_len(dims: serialization::Dimensions) -> usize {
        <G as Decode<serialization::Point>>::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut serialization::Reader<'a>,
        dims: serialization::Dimensions,
    ) -> core::result::Result<Self, serialization::Error<'a>> {
        <G as Decode<serialization::Point>>::decode(reader, dims).map(Cached)
    }
}

// A cached polynomial encodes as the polynomial it caches.
impl<T: Encode> Encode for Cached<T> {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: serialization::Dimensions,
    ) -> core::result::Result<(), serialization::Error<'static>> {
        self.0.encode(output, dims)
    }
}

impl<T: Decode> Decode for Cached<T> {
    fn encoded_len(dims: serialization::Dimensions) -> usize {
        T::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut serialization::Reader<'a>,
        dims: serialization::Dimensions,
    ) -> core::result::Result<Self, serialization::Error<'a>> {
        T::decode(reader, dims).map(Cached)
    }
}
