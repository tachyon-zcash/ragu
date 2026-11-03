//! The wire codec of [`Proof`]: every field in declaration order, each with
//! the codec it encodes under. Decoding builds the struct from this list, so a
//! field missing from it is a build error.
//!
//! The commitment caches are private to `proof`, which is why this list
//! lives beneath it rather than in `wire`.

#[cfg(test)]
#[path = "../../tests/wire/malformed_proofs.rs"]
mod malformed_proof_tests;
#[cfg(test)]
#[path = "../../tests/wire/validation.rs"]
mod wire_validation_tests;

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_primitives::vec::{ConstLen, Len};
use udon::{curve::Affine, field::Field};

use super::{Cached, PolyQuery, Proof};
use crate::{
    framework_hooks::{PolyQueries, WitnessPolys},
    internal::{native, nested},
    poly_commitment::HANDLE_WIRES,
    profile::ProfiledCycle,
    wire::{self, Decode, Encode},
};

/// Generates the codec of [`Proof`] from its fields and their codecs. The
/// field types are inferred from the struct; `encoded_len` alone has no
/// value to infer them from and takes them from a projection. The fields
/// after `unencoded` are test-only and never on the wire; decoding
/// initializes them.
macro_rules! codec {
    (
        $($field:ident => $codec:ty),* $(,)?;
        unencoded { $($(#[$attr:meta])* $unencoded:ident: $init:expr),* $(,)? }
    ) => {
        /// The fields in wire order, for the fixtures that pin the format.
        #[cfg(test)]
        pub(super) const WIRE_FIELDS: &[&str] = &[$(stringify!($field)),*];

        impl<C: ProfiledCycle, R: Rank> Encode for Proof<C, R> {
            fn encode(
                &self,
                output: &mut Vec<u8>,
                dims: wire::Dimensions,
            ) -> core::result::Result<(), wire::Error<'static>> {
                $( <_ as Encode<$codec>>::encode(&self.$field, output, dims)?; )*
                Ok(())
            }
        }

        impl<C: ProfiledCycle, R: Rank> Decode for Proof<C, R> {
            fn encoded_len(dims: wire::Dimensions) -> usize {
                0usize $( + wire::field_len::<Self, _, $codec>(|proof| &proof.$field, dims) )*
            }
            fn decode<'a>(
                reader: &mut wire::Reader<'a>,
                dims: wire::Dimensions,
            ) -> core::result::Result<Self, wire::Error<'a>> {
                Ok(Self {
                    $( $field: <_ as Decode<$codec>>::decode(reader, dims)?, )*
                    $( $(#[$attr])* $unencoded: $init, )*
                })
            }
        }
    };
}

codec! {
    bridge_alpha => wire::Scalar,

    // Application metadata
    circuit_id => wire::DefaultEncoding,
    left_header => wire::SizedSequence<wire::Scalar, wire::HeaderSize>,
    right_header => wire::SizedSequence<wire::Scalar, wire::HeaderSize>,

    // Native rx polynomials (CircuitField, HostCurve commitment)
    native_application_rx => wire::DefaultEncoding,
    native_application_stage_rx => wire::DefaultEncoding,
    native_preamble_rx => wire::DefaultEncoding,
    native_inner_error_rx => wire::DefaultEncoding,
    native_outer_error_rx => wire::DefaultEncoding,
    native_a_poly => wire::DefaultEncoding,
    native_b_poly => wire::DefaultEncoding,
    native_query_rx => wire::DefaultEncoding,
    native_registry_xy_poly => wire::DefaultEncoding,
    native_eval_rx => wire::DefaultEncoding,
    native_p_poly => wire::DefaultEncoding,
    native_hashes_1_rx => wire::DefaultEncoding,
    native_hashes_2_rx => wire::DefaultEncoding,
    native_collapse_rx => wire::DefaultEncoding,
    native_compute_v_rx => wire::DefaultEncoding,
    native_bind_challenges_rxs => wire::FixedSequence<wire::DefaultEncoding, ConstLen<{ native::NUM_BINDERS }>>,
    native_bind_beta_rx => wire::DefaultEncoding,
    // The native endoscaling walk over the nested batch's commitments: the
    // endoscalar binding circuit, the steps, the five points stages holding
    // the walk's inputs (see `native::stages::points`) and the walk stage
    // holding the endoscalar's bits and the interstitials.
    native_bind_endoscalar_rx => wire::DefaultEncoding,
    native_endoscaling_step_rxs => wire::FixedSequence<wire::DefaultEncoding, native::NumSteps<C::Profile>>,
    native_extension_circuit_rxs => wire::FixedSequence<wire::DefaultEncoding, native::NumExtensionCircuits<C::Profile>>,
    native_extension_stage_rxs => wire::FixedSequence<wire::DefaultEncoding, native::NumExtensionStages<C::Profile>>,
    native_points_binding_rx => wire::DefaultEncoding,
    native_points_children_rx => wire::DefaultEncoding,
    native_points_registry_wx_rx => wire::DefaultEncoding,
    native_points_ab_rx => wire::DefaultEncoding,
    native_points_f_rx => wire::DefaultEncoding,
    native_points_walk_rx => wire::DefaultEncoding,

    // Bridge rx polynomials (non-cached, set by caller)
    bridge_preamble_rx => wire::DefaultEncoding,
    bridge_s_prime_rx => wire::DefaultEncoding,
    bridge_inner_error_rx => wire::DefaultEncoding,
    bridge_outer_error_rx => wire::DefaultEncoding,
    bridge_query_rx => wire::DefaultEncoding,
    bridge_f_rx => wire::DefaultEncoding,
    bridge_eval_rx => wire::DefaultEncoding,

    // Bridge rx polynomial (cached, derived from bridge_alpha + native commitments)
    bridge_ab_rx => wire::DefaultEncoding,

    // Nested endoscaling data (ScalarField, NestedCurve commitment)
    nested_endoscaling_step_rxs => wire::FixedSequence<wire::DefaultEncoding, nested::NumSteps<C::Profile>>,
    nested_extension_circuit_rxs => wire::FixedSequence<wire::DefaultEncoding, nested::NumExtensionCircuits<C::Profile>>,
    nested_extension_stage_rxs => wire::FixedSequence<wire::DefaultEncoding, nested::NumExtensionStages<C::Profile>>,
    nested_endoscalar_rx => wire::DefaultEncoding,
    nested_points_rx => wire::DefaultEncoding,

    // Nested accumulator polynomials (ScalarField, NestedCurve commitment):
    // the children's nested claims, folded.
    nested_a_poly => wire::DefaultEncoding,
    nested_b_poly => wire::DefaultEncoding,

    // Nested batch polynomials (ScalarField, NestedCurve commitment): the
    // $m_n(W, x_n, y_n)$ restriction, and the batch accumulated into $p_n$.
    nested_registry_xy_poly => wire::DefaultEncoding,
    nested_p_poly => wire::DefaultEncoding,

    // Nested challenge stage (ScalarField, unblinded NestedCurve
    // commitment): the lifts of this step's native challenges, the
    // base-case sign and the lift of `pre_beta`.
    nested_challenges_rx => wire::DefaultEncoding,
    // The challenge stage's commitment without its beta term: the sum the
    // `bind_challenges` circuits recompute from the transcript challenges,
    // carried by the native unified instance so that a parent can complete
    // it and hold it against the stage it walks.
    nested_challenges_partial => wire::Point,

    // Nested instance circuits (ScalarField, NestedCurve commitments): the
    // collapse circuit pins the nested unified instance to the stages and
    // verifies the nested fold; compute-v checks the nested batch evaluation.
    nested_collapse_rx => wire::DefaultEncoding,
    nested_compute_v_rx => wire::DefaultEncoding,

    // Nested endoscaling commitment caches
    nested_endoscaling_step_commitments => wire::FixedSequence<CachedPoint, nested::NumSteps<C::Profile>>,
    nested_extension_circuit_commitments => wire::FixedSequence<CachedPoint, nested::NumExtensionCircuits<C::Profile>>,
    nested_extension_stage_commitments => wire::FixedSequence<CachedPoint, nested::NumExtensionStages<C::Profile>>,
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
    w => wire::Scalar,
    y => wire::Scalar,
    z => wire::Scalar,
    mu => wire::Scalar,
    mu_prime => wire::Scalar,
    x => wire::Scalar,
    alpha => wire::Scalar,
    u => wire::Scalar,
    pre_beta => wire::Scalar,

    // Native commitment caches
    native_application_commitment => CachedPoint,
    native_application_stage_commitment => CachedPoint,
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
    native_bind_challenges_commitments => wire::FixedSequence<CachedPoint, ConstLen<{ native::NUM_BINDERS }>>,
    native_bind_beta_commitment => CachedPoint,
    native_bind_endoscalar_commitment => CachedPoint,
    native_endoscaling_step_commitments => wire::FixedSequence<CachedPoint, native::NumSteps<C::Profile>>,
    native_extension_circuit_commitments => wire::FixedSequence<CachedPoint, native::NumExtensionCircuits<C::Profile>>,
    native_extension_stage_commitments => wire::FixedSequence<CachedPoint, native::NumExtensionStages<C::Profile>>,
    native_points_binding_commitment => CachedPoint,
    native_points_children_commitment => CachedPoint,
    native_points_registry_wx_commitment => CachedPoint,
    native_points_ab_commitment => CachedPoint,
    native_points_f_commitment => CachedPoint,
    native_points_walk_commitment => CachedPoint,

    // Bridge commitments (non-cached)
    bridge_preamble_commitment => wire::Point,
    bridge_s_prime_commitment => wire::Point,
    bridge_inner_error_commitment => wire::Point,
    bridge_outer_error_commitment => wire::Point,
    bridge_query_commitment => wire::Point,
    bridge_f_commitment => wire::Point,
    bridge_eval_commitment => wire::Point,

    // Bridge commitment (cached, derived from the cached bridge rx)
    bridge_ab_commitment => CachedPoint,

    // Hooks, one slot per profile count: the step's poly-queries, its
    // witnessed polynomials, and the caches of their commitments and of
    // those commitments' names.
    application_poly_queries => wire::FixedSequence<wire::DefaultEncoding, PolyQueries<C::Profile>>,
    witness_polys => wire::FixedSequence<wire::DefaultEncoding, WitnessPolys<C::Profile>>,
    witness_poly_commitments => CachedSequence<wire::Point, WitnessPolys<C::Profile>>,
    witness_poly_names => CachedSequence<NameWires, WitnessPolys<C::Profile>>;

    unencoded {
        #[cfg(test)]
        skip_stage_check: false,
        #[cfg(test)]
        forged_names: None,
    }
}

/// The wire codec of a commitment's name: its wires, as scalars.
struct NameWires;

impl<F: Field> Encode<NameWires> for [F; HANDLE_WIRES] {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: wire::Dimensions,
    ) -> core::result::Result<(), wire::Error<'static>> {
        self.iter()
            .try_for_each(|wire| <F as Encode<wire::Scalar>>::encode(wire, output, dims))
    }
}

impl<F: Field> Decode<NameWires> for [F; HANDLE_WIRES] {
    fn encoded_len(dims: wire::Dimensions) -> usize {
        HANDLE_WIRES * <F as Decode<wire::Scalar>>::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut wire::Reader<'a>,
        dims: wire::Dimensions,
    ) -> core::result::Result<Self, wire::Error<'a>> {
        let mut name = [F::ZERO; HANDLE_WIRES];
        for wire in &mut name {
            *wire = <F as Decode<wire::Scalar>>::decode(reader, dims)?;
        }
        Ok(name)
    }
}

/// The wire codec of a poly-query: the commitment, then `x` and `y`.
impl<G: Affine> Encode for PolyQuery<G> {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: wire::Dimensions,
    ) -> core::result::Result<(), wire::Error<'static>> {
        <G as Encode<wire::Point>>::encode(&self.com, output, dims)?;
        <G::Scalar as Encode<wire::Scalar>>::encode(&self.x, output, dims)?;
        <G::Scalar as Encode<wire::Scalar>>::encode(&self.y, output, dims)
    }
}

impl<G: Affine> Decode for PolyQuery<G> {
    fn encoded_len(dims: wire::Dimensions) -> usize {
        <G as Decode<wire::Point>>::encoded_len(dims)
            + 2 * <G::Scalar as Decode<wire::Scalar>>::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut wire::Reader<'a>,
        dims: wire::Dimensions,
    ) -> core::result::Result<Self, wire::Error<'a>> {
        Ok(Self {
            com: <G as Decode<wire::Point>>::decode(reader, dims)?,
            x: <G::Scalar as Decode<wire::Scalar>>::decode(reader, dims)?,
            y: <G::Scalar as Decode<wire::Scalar>>::decode(reader, dims)?,
        })
    }
}

/// The wire codec of a [`Cached`] sequence: exactly `L` elements of codec
/// `C`, as [`wire::FixedSequence`] encodes them.
struct CachedSequence<C, L>(PhantomData<(C, L)>);

impl<T: Encode<C>, C, L: Len> Encode<CachedSequence<C, L>> for Cached<Vec<T>> {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: wire::Dimensions,
    ) -> core::result::Result<(), wire::Error<'static>> {
        <Vec<T> as Encode<wire::FixedSequence<C, L>>>::encode(&self.0, output, dims)
    }
}

impl<T: Decode<C>, C, L: Len> Decode<CachedSequence<C, L>> for Cached<Vec<T>> {
    fn encoded_len(dims: wire::Dimensions) -> usize {
        <Vec<T> as Decode<wire::FixedSequence<C, L>>>::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut wire::Reader<'a>,
        dims: wire::Dimensions,
    ) -> core::result::Result<Self, wire::Error<'a>> {
        <Vec<T> as Decode<wire::FixedSequence<C, L>>>::decode(reader, dims).map(Cached)
    }
}

/// The wire codec of a [`Cached`] commitment: the point itself. A marker of
/// its own keeps the impl clear of the point codec's blanket over every
/// `Affine` type, which coherence cannot rule out for `Cached`.
struct CachedPoint;

impl<G: Encode<wire::Point>> Encode<CachedPoint> for Cached<G> {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: wire::Dimensions,
    ) -> core::result::Result<(), wire::Error<'static>> {
        <G as Encode<wire::Point>>::encode(&self.0, output, dims)
    }
}

impl<G: Decode<wire::Point>> Decode<CachedPoint> for Cached<G> {
    fn encoded_len(dims: wire::Dimensions) -> usize {
        <G as Decode<wire::Point>>::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut wire::Reader<'a>,
        dims: wire::Dimensions,
    ) -> core::result::Result<Self, wire::Error<'a>> {
        <G as Decode<wire::Point>>::decode(reader, dims).map(Cached)
    }
}

// A cached polynomial encodes as the polynomial it caches.
impl<T: Encode> Encode for Cached<T> {
    fn encode(
        &self,
        output: &mut Vec<u8>,
        dims: wire::Dimensions,
    ) -> core::result::Result<(), wire::Error<'static>> {
        self.0.encode(output, dims)
    }
}

impl<T: Decode> Decode for Cached<T> {
    fn encoded_len(dims: wire::Dimensions) -> usize {
        T::encoded_len(dims)
    }

    fn decode<'a>(
        reader: &mut wire::Reader<'a>,
        dims: wire::Dimensions,
    ) -> core::result::Result<Self, wire::Error<'a>> {
        T::decode(reader, dims).map(Cached)
    }
}
