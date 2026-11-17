//! The compressed proof's instance: everything the verifier reads about a
//! proof besides polynomials, and the decider's remaining checks restated
//! over it.
//!
//! The decider holds the polynomials and reads three kinds of things off
//! them that a compressed verifier cannot: the accumulator values $c$ and
//! $v$ on each curve, which it derives; the challenges, which it rederives
//! from the transcript and compares; and stage wires, which it compares to
//! the registry, to the nested commitments and to its own evaluations. Here
//! the values are supplied and bound: $c$, $v$, $c_n$ and $v_n$ enter the
//! $k(y)$ targets the revdot claims must hit, the challenges are rederived
//! from the bridge commitments on the same transcript the compression
//! continues, and the wires become [`Masked`](crate::protocol::compress::revdot::claims::Masked) claims that pin them to the
//! stage commitments, with the evaluations among them also opened.

use alloc::vec::Vec;

use ragu_circuits::{
    polynomials::Rank,
    registry::CircuitIndex,
    staging::{stage_wire_indices, wire_degree},
};
use ragu_core::{Cycle, Error, Result};
use udon::{curve::Affine, field::Field};

use crate::{
    SelectableBackend,
    header::NUM_ONLINE_FP_POLYS,
    profile::ProfiledCycle,
    protocol::{
        compress::revdot::{native_position, nested_position},
        ipa::{CycleTranscript, IpaTranscript},
        native,
        native::{online, unified as native_unified},
        nested,
        nested::{challenge as nested_challenge, unified as nested_unified},
    },
    verifier::recursive::{native::stages as native_stages, nested::stages as nested_stages},
};

/// A child's values the current step's query and eval stages are checked
/// against: its $x$, $y$ and circuit id as the preamble stage holds them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Child<F> {
    pub x: F,
    pub y: F,
    pub id: F,
}

/// A child's nested $x$ and $y$ as the preamble bridge stage holds them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NestedChild<F> {
    pub x: F,
    pub y: F,
}

/// How many polynomials [`Instance::native_openings`] and
/// [`Instance::nested_openings`] open beyond the reduction's.
pub(crate) const OPENED: usize = 4;

/// The instance of a proof: its commitments, its headers and the scalars
/// the decider would derive or read off polynomials.
#[derive(Clone, Debug)]
pub(crate) struct Instance<C: Cycle> {
    pub circuit_id: CircuitIndex,
    pub left_header: Vec<C::CircuitField>,
    pub right_header: Vec<C::CircuitField>,
    /// The online openings the proof's `compute_v` exported, which its
    /// application circuit's instance is held to.
    pub online: online::Queries<C::CircuitField>,

    /// The native commitments in [`native_components`](crate::protocol::compress::revdot::native_components) order.
    pub native: Vec<C::HostCurve>,
    pub native_registry_xy: C::HostCurve,
    pub native_p: C::HostCurve,
    /// The commitments of the step's own online polynomials, which its
    /// nested instance exports.
    pub online_commitments: [C::HostCurve; NUM_ONLINE_FP_POLYS],

    /// The nested commitments in [`nested_components`](crate::protocol::compress::revdot::nested_components) order, the bridge
    /// stages and the challenge stage among them.
    pub nested: Vec<C::NestedCurve>,
    pub nested_registry_xy: C::NestedCurve,
    pub nested_p: C::NestedCurve,
    pub nested_challenges_partial: C::NestedCurve,
    /// The blinding source of the `ab` bridge stage.
    pub bridge_alpha: C::ScalarField,

    /// The accumulator values the decider derives.
    pub c: C::CircuitField,
    pub v: C::CircuitField,
    pub nested_c: C::ScalarField,
    pub nested_v: C::ScalarField,

    /// The wires the decider reads off the preamble and eval stages.
    pub left: Child<C::CircuitField>,
    pub right: Child<C::CircuitField>,
    pub a_at_u: C::CircuitField,
    pub b_at_u: C::CircuitField,
    pub nested_left: NestedChild<C::ScalarField>,
    pub nested_right: NestedChild<C::ScalarField>,
    pub nested_a_at_u: C::ScalarField,
    pub nested_b_at_u: C::ScalarField,
}

pub(crate) type NativePreamble<C, R, const H: usize> = native_stages::preamble::Stage<C, R, H>;
pub(crate) type NativeQuery<C, R, const H: usize> = native_stages::query::Stage<C, R, H>;
pub(crate) type NativeEval<C, R, const H: usize> = native_stages::eval::Stage<C, R, H>;
pub(crate) type NestedPreamble<C, R> =
    nested_stages::preamble::Stage<<C as Cycle>::HostCurve, R, <C as ProfiledCycle>::Profile>;
pub(crate) type NestedQuery<C, R> =
    nested_stages::query::Stage<<C as Cycle>::HostCurve, R, <C as ProfiledCycle>::Profile>;
pub(crate) type NestedEval<C, R> =
    nested_stages::eval::Stage<<C as Cycle>::HostCurve, R, <C as ProfiledCycle>::Profile>;

/// The coefficient degrees of the wires `select` picks from stage `S`.
pub(crate) fn degrees<F: Field, R: Rank, S: ragu_circuits::staging::Stage<F, R> + Default>(
    select: impl for<'dst> FnOnce(
        ragu_core::gadgets::Bound<'dst, ragu_circuits::staging::Indexed<F>, S::OutputKind>,
    ) -> Result<Vec<usize>>,
) -> Result<Vec<usize>> {
    Ok(stage_wire_indices::<F, R, S>(select)?
        .into_iter()
        .map(wire_degree::<R>)
        .collect())
}

/// The coordinates of a commitment, which is never the identity.
pub(crate) fn coordinates<P: Affine>(point: P) -> Result<[P::Base; 2]> {
    let (x, y) = point
        .coordinates()
        .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
    Ok([x, y])
}

impl<C: ProfiledCycle> Instance<C> {
    /// A native component's commitment.
    pub(crate) fn native_commitment(&self, component: native::RxComponent) -> C::HostCurve {
        self.native[native_position::<C::Profile>(component)]
    }

    /// A nested component's commitment.
    pub(crate) fn nested_commitment(&self, component: nested::RxComponent) -> C::NestedCurve {
        self.nested[nested_position::<C::Profile>(component)]
    }

    /// A bridge stage's commitment.
    pub(crate) fn bridge(&self, index: nested::RxIndex) -> C::NestedCurve {
        self.nested_commitment(nested::RxComponent::Rx(index))
    }

    /// Absorbs the instance into `transcript`: the circuit id, the headers
    /// and the online openings, then every commitment and scalar of each
    /// curve, so that every challenge squeezed afterwards depends on all of
    /// it.
    pub(crate) fn absorb<B: SelectableBackend>(
        &self,
        transcript: &mut CycleTranscript<'_, C, B>,
    ) -> Result<()> {
        let mut host = transcript.host();
        host.write_scalar(self.circuit_id.omega_j())?;
        for &element in self.left_header.iter().chain(&self.right_header) {
            host.write_scalar(element)?;
        }
        for query in &self.online {
            host.write_scalar(query.x)?;
            host.write_scalar(query.y)?;
        }
        for &point in self
            .native
            .iter()
            .chain([&self.native_registry_xy, &self.native_p])
            .chain(&self.online_commitments)
        {
            host.write_point(point)?;
        }
        let (l, r) = (self.left, self.right);
        for scalar in [
            self.c,
            self.v,
            l.x,
            l.y,
            l.id,
            r.x,
            r.y,
            r.id,
            self.a_at_u,
            self.b_at_u,
        ] {
            host.write_scalar(scalar)?;
        }

        let mut nested = transcript.nested();
        for &point in self.nested.iter().chain([
            &self.nested_registry_xy,
            &self.nested_p,
            &self.nested_challenges_partial,
        ]) {
            nested.write_point(point)?;
        }
        let (l, r) = (self.nested_left, self.nested_right);
        for scalar in [
            self.bridge_alpha,
            self.nested_c,
            self.nested_v,
            l.x,
            l.y,
            r.x,
            r.y,
            self.nested_a_at_u,
            self.nested_b_at_u,
        ] {
            nested.write_scalar(scalar)?;
        }
        Ok(())
    }

    /// The native unified instance under `challenges`.
    pub(crate) fn unified(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
    ) -> native_unified::Instance<C> {
        use nested::RxIndex::*;
        native_unified::Instance {
            bridge_preamble_commitment: self.bridge(BridgePreamble),
            bridge_hash_commitment: self.bridge(BridgeHash),
            w: challenges.w,
            bridge_s_prime_commitment: self.bridge(BridgeSPrime),
            y: challenges.y,
            z: challenges.z,
            bridge_inner_error_commitment: self.bridge(BridgeInnerError),
            mu: challenges.mu,
            bridge_outer_error_commitment: self.bridge(BridgeOuterError),
            mu_prime: challenges.mu_prime,
            c: self.c,
            bridge_ab_commitment: self.bridge(BridgeAB),
            x: challenges.x,
            bridge_query_commitment: self.bridge(BridgeQuery),
            alpha: challenges.alpha,
            bridge_f_commitment: self.bridge(BridgeF),
            u: challenges.u,
            bridge_eval_commitment: self.bridge(BridgeEval),
            pre_beta: challenges.pre_beta,
            v: self.v,
            nested_challenges_partial: self.nested_challenges_partial,
            nested_p_commitment: self.nested_p,
            nested_a_commitment: self.nested_commitment(nested::RxComponent::AbA),
            nested_b_commitment: self.nested_commitment(nested::RxComponent::AbB),
            nested_registry_xy_commitment: self.nested_registry_xy,
            coverage: Default::default(),
        }
    }

    /// The nested unified instance under `challenges`, as the collapse circuit
    /// serializes it.
    pub(crate) fn nested_unified(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
    ) -> Result<nested_unified::Instance<C::HostCurve>> {
        use native::{RxComponent::*, RxIndex::*};
        Ok(nested_unified::Instance {
            c: self.nested_c,
            v: self.nested_v,
            x: nested_challenge::<C>(challenges.x)?,
            y: nested_challenge::<C>(challenges.y)?,
            u: nested_challenge::<C>(challenges.u)?,
            exported: [
                self.native_commitment(Rx(Preamble)),
                self.native_commitment(Rx(InnerError)),
                self.native_commitment(Rx(OuterError)),
                self.native_commitment(Rx(Query)),
                self.native_commitment(Rx(Eval)),
                self.native_commitment(AbA),
                self.native_commitment(AbB),
                self.native_registry_xy,
                self.native_p,
                self.native_commitment(Rx(PointsBinding)),
                self.native_commitment(Rx(PointsPreamble)),
                self.native_commitment(Rx(PointsRegistryWx)),
                self.native_commitment(Rx(PointsAb)),
                self.native_commitment(Rx(PointsF)),
                self.online_commitments[0],
                self.online_commitments[1],
                self.native_commitment(Rx(ApplicationStage)),
            ],
            coverage: Default::default(),
        })
    }
}
