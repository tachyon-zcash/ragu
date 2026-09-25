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
//! continues, and the wires become [`Masked`] claims that pin them to the
//! stage commitments, with the evaluations among them also opened.

use alloc::{vec, vec::Vec};

use ragu_arithmetic::{Coordinates, CurveAffine, Cycle, bitreverse, ff::Field};
use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, Registry},
    staging::{StageExt, StageReader, stage_wire_indices, wire_degree, wires_of},
};
use ragu_core::{Error, Result};
use ragu_primitives::extract_endoscalar;

use super::{
    claims::Masked,
    revdot::{
        OpeningClaim, native_components, native_position, nested_components, nested_position,
    },
};
use crate::{
    Proof,
    internal::{
        ky::{self, NativeKy, NestedKy},
        native::{self, stages as native_stages, unified as native_unified},
        nested::{
            self, challenge as nested_challenge, stages as nested_stages, unified as nested_unified,
        },
    },
    ipa::{CycleTranscript, IpaTranscript},
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

/// The instance of a proof: its commitments, its headers and the scalars
/// the decider would derive or read off polynomials.
#[derive(Clone, Debug)]
pub(crate) struct Instance<C: Cycle> {
    pub circuit_id: CircuitIndex,
    pub left_header: Vec<C::CircuitField>,
    pub right_header: Vec<C::CircuitField>,

    /// The native commitments in [`native_components`] order.
    pub native: Vec<C::HostCurve>,
    pub native_registry_xy: C::HostCurve,
    pub native_p: C::HostCurve,

    /// The nested commitments in [`nested_components`] order, the bridge
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

type NativePreamble<C, R, const H: usize> = native_stages::preamble::Stage<C, R, H>;
type NativeQuery<C, R, const H: usize> = native_stages::query::Stage<C, R, H>;
type NativeEval<C, R, const H: usize> = native_stages::eval::Stage<C, R, H>;
type NestedPreamble<C, R> = nested_stages::preamble::Stage<<C as Cycle>::HostCurve, R>;
type NestedQuery<C, R> = nested_stages::query::Stage<<C as Cycle>::HostCurve, R>;
type NestedEval<C, R> = nested_stages::eval::Stage<<C as Cycle>::HostCurve, R>;

/// The coefficient degrees of the wires `select` picks from stage `S`.
fn degrees<F: Field, R: Rank, S: ragu_circuits::staging::Stage<F, R> + Default>(
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
fn coordinates<P: CurveAffine>(point: P) -> Result<[P::Base; 2]> {
    let coordinates = Option::<Coordinates<P>>::from(point.coordinates())
        .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
    let (x, y) = (coordinates.x(), coordinates.y());
    Ok([*x, *y])
}

impl<C: Cycle> Instance<C> {
    /// The instance of `proof`, with the values the decider derives computed
    /// from its polynomials and the wires read off its stages.
    pub(crate) fn of<R: Rank, const HEADER_SIZE: usize>(proof: &Proof<C, R>) -> Result<Self> {
        let preamble = StageReader::<C::CircuitField, R>::new(&proof[native::RxIndex::Preamble]);
        let child = stage_wire_indices::<_, R, NativePreamble<C, R, HEADER_SIZE>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.unified.x)?);
                wires.extend(wires_of(&child.unified.y)?);
                wires.extend(wires_of(&child.circuit_id)?);
            }
            Ok(wires)
        })?;
        let child: Vec<_> = child.iter().map(|&i| preamble.read(i)).collect();
        let [lx, ly, lid, rx, ry, rid] = child.try_into().expect("six child values");

        let eval = StageReader::<C::CircuitField, R>::new(&proof[native::RxIndex::Eval]);
        let ab = stage_wire_indices::<_, R, NativeEval<C, R, HEADER_SIZE>>(|out| {
            let mut wires = wires_of(&out.evaluations.a_poly)?;
            wires.extend(wires_of(&out.evaluations.b_poly)?);
            Ok(wires)
        })?;
        let [a_at_u, b_at_u] = [eval.read(ab[0]), eval.read(ab[1])];

        let bridge_preamble =
            StageReader::<C::ScalarField, R>::new(&proof[nested::RxIndex::BridgePreamble]);
        let nested_child = stage_wire_indices::<_, R, NestedPreamble<C, R>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.nested.x)?);
                wires.extend(wires_of(&child.nested.y)?);
            }
            Ok(wires)
        })?;
        let nested_child: Vec<_> = nested_child
            .iter()
            .map(|&i| bridge_preamble.read(i))
            .collect();
        let [left_x, left_y, right_x, right_y] =
            nested_child.try_into().expect("four child values");

        let bridge_eval =
            StageReader::<C::ScalarField, R>::new(&proof[nested::RxIndex::BridgeEval]);
        let nested_ab = stage_wire_indices::<_, R, NestedEval<C, R>>(|out| {
            let mut wires = wires_of(&out.nested.a_poly)?;
            wires.extend(wires_of(&out.nested.b_poly)?);
            Ok(wires)
        })?;
        let [nested_a_at_u, nested_b_at_u] = [
            bridge_eval.read(nested_ab[0]),
            bridge_eval.read(nested_ab[1]),
        ];

        Ok(Instance {
            circuit_id: proof.circuit_id(),
            left_header: proof.left_header().to_vec(),
            right_header: proof.right_header().to_vec(),
            native: native_components()
                .map(|component| proof.native_commitment(component))
                .collect(),
            native_registry_xy: proof.native_registry_xy_commitment(),
            native_p: proof.native_p_commitment(),
            nested: nested_components()
                .map(|component| match component {
                    nested::RxComponent::AbA => proof.nested_a_commitment(),
                    nested::RxComponent::AbB => proof.nested_b_commitment(),
                    nested::RxComponent::Rx(index) => proof.nested_rx_commitment(index),
                })
                .collect(),
            nested_registry_xy: proof.nested_registry_xy_commitment(),
            nested_p: proof.nested_p_commitment(),
            nested_challenges_partial: proof.nested_challenges_partial(),
            bridge_alpha: proof.bridge_alpha,
            c: proof.native_c(),
            v: proof.v(),
            nested_c: proof.nested_c(),
            nested_v: proof.nested_v()?,
            left: Child {
                x: lx,
                y: ly,
                id: lid,
            },
            right: Child {
                x: rx,
                y: ry,
                id: rid,
            },
            a_at_u,
            b_at_u,
            nested_left: NestedChild {
                x: left_x,
                y: left_y,
            },
            nested_right: NestedChild {
                x: right_x,
                y: right_y,
            },
            nested_a_at_u,
            nested_b_at_u,
        })
    }

    /// A native component's commitment.
    pub(crate) fn native_commitment(&self, component: native::RxComponent) -> C::HostCurve {
        self.native[native_position(component)]
    }

    /// A nested component's commitment.
    pub(crate) fn nested_commitment(&self, component: nested::RxComponent) -> C::NestedCurve {
        self.nested[nested_position(component)]
    }

    /// A bridge stage's commitment.
    fn bridge(&self, index: nested::RxIndex) -> C::NestedCurve {
        self.nested_commitment(nested::RxComponent::Rx(index))
    }

    /// Absorbs the instance into `transcript`: the circuit id and the
    /// headers, then every commitment and scalar of each curve, so that
    /// every challenge squeezed afterwards depends on all of it.
    pub(crate) fn absorb(&self, transcript: &mut CycleTranscript<'_, C>) -> Result<()> {
        let mut host = transcript.host();
        host.write_scalar(self.circuit_id.omega_j())?;
        for &element in self.left_header.iter().chain(&self.right_header) {
            host.write_scalar(element)?;
        }
        for &point in self
            .native
            .iter()
            .chain([&self.native_registry_xy, &self.native_p])
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

    /// Rederives the fuse's challenges from the bridge commitments on
    /// `transcript`, which must be fresh under the fuse's tag, in the fuse's
    /// schedule. Returns `None` if `pre_beta` lies outside the endoscalar
    /// range.
    pub(crate) fn challenges(
        &self,
        transcript: &mut CycleTranscript<'_, C>,
    ) -> Result<Option<nested::Challenges<C::CircuitField>>> {
        use nested::RxIndex::*;
        macro_rules! absorb {
            ($bridge:expr) => {
                transcript.nested().write_point(self.bridge($bridge))?
            };
        }
        macro_rules! squeeze {
            () => {
                transcript.host().squeeze_challenge()?
            };
        }
        absorb!(BridgePreamble);
        let w = squeeze!();
        absorb!(BridgeSPrime);
        let y = squeeze!();
        let z = squeeze!();
        absorb!(BridgeInnerError);
        let mu = squeeze!();
        let nu = squeeze!();
        absorb!(BridgeOuterError);
        let mu_prime = squeeze!();
        let nu_prime = squeeze!();
        absorb!(BridgeAB);
        let x = squeeze!();
        absorb!(BridgeQuery);
        let alpha = squeeze!();
        absorb!(BridgeF);
        let u = squeeze!();
        absorb!(BridgeEval);
        let pre_beta = squeeze!();

        if extract_endoscalar(pre_beta).is_err() {
            return Ok(None);
        }
        Ok(Some(nested::Challenges {
            w,
            y,
            z,
            mu,
            nu,
            mu_prime,
            nu_prime,
            x,
            alpha,
            u,
            pre_beta,
        }))
    }

    /// The native unified instance under `challenges`.
    pub(crate) fn unified(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
    ) -> native_unified::Instance<C> {
        use nested::RxIndex::*;
        native_unified::Instance {
            bridge_preamble_commitment: self.bridge(BridgePreamble),
            w: challenges.w,
            bridge_s_prime_commitment: self.bridge(BridgeSPrime),
            y: challenges.y,
            z: challenges.z,
            bridge_inner_error_commitment: self.bridge(BridgeInnerError),
            mu: challenges.mu,
            nu: challenges.nu,
            bridge_outer_error_commitment: self.bridge(BridgeOuterError),
            mu_prime: challenges.mu_prime,
            nu_prime: challenges.nu_prime,
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

    /// The nested unified instance under `challenges`, as the export circuit
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
                self.native_commitment(Rx(PointsChildren)),
                self.native_commitment(Rx(PointsRegistryWx)),
                self.native_commitment(Rx(PointsAb)),
                self.native_commitment(Rx(PointsF)),
            ],
            coverage: Default::default(),
        })
    }

    /// The claims' targets at `y` and the nested `nested_y`, for the step's
    /// encoded `output_header`.
    pub(crate) fn targets<const HEADER_SIZE: usize>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        output_header: &[C::CircuitField],
        y: C::CircuitField,
        nested_y: C::ScalarField,
    ) -> Result<(NativeKy<C::CircuitField>, NestedKy<C::ScalarField>)> {
        let unified = self.unified(challenges);
        let native = NativeKy {
            c: Some(self.c),
            ..ky::native_ky_of::<C, HEADER_SIZE>(
                ky::NativeParts {
                    left_header: &self.left_header,
                    right_header: &self.right_header,
                    output_header,
                    circuit_id: self.circuit_id,
                    unified: &unified,
                },
                y,
            )?
        };
        let nested = NestedKy {
            c: self.nested_c,
            unified: ky::nested_ky_of::<C>(&self.nested_unified(challenges)?, nested_y)?,
        };
        Ok((native, nested))
    }

    /// Whether the two nested stages the decider recomputes from public data
    /// commit as the instance claims: the challenge stage from the
    /// challenges' lifts and the headers, and the `ab` bridge stage from the
    /// native $a$, $b$ and points commitments under `bridge_alpha`.
    pub(crate) fn stages_match<R: Rank, B: Backend, const HEADER_SIZE: usize>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        generators: &C::NestedGenerators,
    ) -> Result<bool> {
        let Ok(lifts) = challenges.lifts::<C>() else {
            return Ok(false);
        };
        let (challenge_lifts, beta_lift) = lifts.split_at(nested_stages::challenges::NUM);
        let challenge_stage = nested_stages::challenges::Stage::<C::HostCurve, R>::rx(
            C::ScalarField::ZERO,
            &nested_stages::challenges::Witness::new::<_, HEADER_SIZE>(
                challenge_lifts.try_into().expect("NUM challenge lifts"),
                &self.left_header,
                &self.right_header,
                beta_lift[0],
            ),
        )?;
        let ab_bridge = nested_stages::ab::Stage::<C::HostCurve, R>::rx(
            crate::proof::bridge_alpha_power(self.bridge_alpha, nested::RxIndex::BridgeAB),
            &nested_stages::ab::Witness {
                a: self.native_commitment(native::RxComponent::AbA),
                b: self.native_commitment(native::RxComponent::AbB),
                native_points_ab: self
                    .native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb)),
            },
        )?;
        Ok(B::sparse_commit_to_affine(&challenge_stage, generators)
            == self.bridge(nested::RxIndex::ChallengeStage)
            && B::sparse_commit_to_affine(&ab_bridge, generators)
                == self.bridge(nested::RxIndex::BridgeAB))
    }

    /// The native wire claims under `sigma`: the preamble stage holds the
    /// children's values, the query stage the registry's, the eval stage
    /// the registry's and the accumulator's evaluations at $u$, and the
    /// points stages the nested commitments' coordinates.
    pub(crate) fn native_bindings<R: Rank, B: Backend, const HEADER_SIZE: usize>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        registry: &Registry<'_, C::CircuitField, R>,
        sigma: C::CircuitField,
    ) -> Result<Vec<Masked<native::RxComponent, C::CircuitField>>> {
        use native::{RxComponent::Rx, RxIndex::*};
        type F<C> = <C as Cycle>::CircuitField;
        let (w, x, y, u) = (challenges.w, challenges.x, challenges.y, challenges.u);
        let m = |w, x, y| B::registry_wxy(registry, w, x, y);
        let (l, r) = (self.left, self.right);
        let claim = |poly, degrees: Vec<usize>, values: Vec<F<C>>| Masked {
            poly,
            wires: degrees.into_iter().zip(values).collect(),
            sigma,
        };

        let preamble = degrees::<_, R, NativePreamble<C, R, HEADER_SIZE>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.unified.x)?);
                wires.extend(wires_of(&child.unified.y)?);
                wires.extend(wires_of(&child.circuit_id)?);
            }
            Ok(wires)
        })?;
        let preamble = claim(Rx(Preamble), preamble, vec![l.x, l.y, l.id, r.x, r.y, r.id]);

        let query = degrees::<_, R, NativeQuery<C, R, HEADER_SIZE>>(|out| {
            let mut wires = wires_of(&out.fixed_registry)?;
            wires.extend(wires_of(&out.registry_wxy)?);
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.child_registry_xy_at_current_w)?);
                wires.extend(wires_of(&child.current_registry_xy_at_child_circuit_id)?);
                wires.extend(wires_of(&child.current_registry_wy_at_child_x)?);
            }
            Ok(wires)
        })?;
        let evals = B::registry_wxy_over_domain(registry, x, y);
        let log2_n = registry.log2_domain();
        let mut values: Vec<_> = native::InternalCircuitIndex::ALL
            .iter()
            .map(|id| {
                let j = usize::from(id.circuit_index()) as u32;
                evals[bitreverse(j, log2_n) as usize]
            })
            .collect();
        values.extend([
            m(w, x, y),
            m(w, l.x, l.y),
            m(l.id, x, y),
            m(w, l.x, y),
            m(w, r.x, r.y),
            m(r.id, x, y),
            m(w, r.x, y),
        ]);
        let query = claim(Rx(Query), query, values);

        let eval = degrees::<_, R, NativeEval<C, R, HEADER_SIZE>>(|out| {
            let e = &out.evaluations;
            let mut wires = Vec::new();
            for element in [
                &e.registry_wx0,
                &e.registry_wx1,
                &e.registry_wy,
                &e.a_poly,
                &e.b_poly,
                &e.registry_xy,
            ] {
                wires.extend(wires_of(element)?);
            }
            Ok(wires)
        })?;
        let eval = claim(
            Rx(Eval),
            eval,
            vec![
                m(w, l.x, u),
                m(w, r.x, u),
                m(w, u, y),
                self.a_at_u,
                self.b_at_u,
                m(u, x, y),
            ],
        );

        let points_ab = degrees::<_, R, native_stages::points::AbStage<C::NestedCurve>>(|stage| {
            let mut wires = wires_of(&stage.a)?;
            wires.extend(wires_of(&stage.b)?);
            Ok(wires)
        })?;
        let [ax, ay] = coordinates(self.nested_commitment(nested::RxComponent::AbA))?;
        let [bx, by] = coordinates(self.nested_commitment(nested::RxComponent::AbB))?;
        let points_ab = claim(Rx(PointsAb), points_ab, vec![ax, ay, bx, by]);

        let points_f = degrees::<_, R, native_stages::points::FStage<C::NestedCurve>>(|stage| {
            wires_of(&stage.registry_xy)
        })?;
        let [gx, gy] = coordinates(self.nested_registry_xy)?;
        let points_f = claim(Rx(PointsF), points_f, vec![gx, gy]);

        Ok(vec![preamble, query, eval, points_ab, points_f])
    }

    /// The nested wire claims under `sigma`, over the preamble, query and
    /// eval bridge stages.
    pub(crate) fn nested_bindings<R: Rank, B: Backend>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        registry: &Registry<'_, C::ScalarField, R>,
        sigma: C::ScalarField,
    ) -> Result<Vec<Masked<nested::RxComponent, C::ScalarField>>> {
        use nested::{RxComponent::Rx, RxIndex::*};
        type F<C> = <C as Cycle>::ScalarField;
        let w = nested_challenge::<C>(challenges.w)?;
        let x = nested_challenge::<C>(challenges.x)?;
        let y = nested_challenge::<C>(challenges.y)?;
        let u = nested_challenge::<C>(challenges.u)?;
        let m = |w, x, y| B::registry_wxy(registry, w, x, y);
        let (l, r) = (self.nested_left, self.nested_right);
        let claim = |poly, degrees: Vec<usize>, values: Vec<F<C>>| Masked {
            poly,
            wires: degrees.into_iter().zip(values).collect(),
            sigma,
        };

        let preamble = degrees::<_, R, NestedPreamble<C, R>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.nested.x)?);
                wires.extend(wires_of(&child.nested.y)?);
            }
            Ok(wires)
        })?;
        let preamble = claim(Rx(BridgePreamble), preamble, vec![l.x, l.y, r.x, r.y]);

        let query = degrees::<_, R, NestedQuery<C, R>>(|out| {
            let q = &out.nested;
            let mut wires = wires_of(&q.fixed_registry)?;
            wires.extend(wires_of(&q.registry_wxy)?);
            for child in [&q.left, &q.right] {
                wires.extend(wires_of(&child.child_registry_xy_at_current_w)?);
                wires.extend(wires_of(&child.current_registry_wy_at_child_x)?);
            }
            Ok(wires)
        })?;
        let evals = B::registry_wxy_over_domain(registry, x, y);
        let log2_n = registry.log2_domain();
        let mut values: Vec<_> = nested::InternalCircuitIndex::ALL
            .iter()
            .map(|id| {
                let j = usize::from(id.circuit_index()) as u32;
                evals[bitreverse(j, log2_n) as usize]
            })
            .collect();
        values.extend([
            m(w, x, y),
            m(w, l.x, l.y),
            m(w, l.x, y),
            m(w, r.x, r.y),
            m(w, r.x, y),
        ]);
        let query = claim(Rx(BridgeQuery), query, values);

        let eval = degrees::<_, R, NestedEval<C, R>>(|out| {
            let e = &out.nested;
            let mut wires = Vec::new();
            for element in [
                &e.registry_wx0,
                &e.registry_wx1,
                &e.registry_wy,
                &e.a_poly,
                &e.b_poly,
                &e.registry_xy,
            ] {
                wires.extend(wires_of(element)?);
            }
            Ok(wires)
        })?;
        let eval = claim(
            Rx(BridgeEval),
            eval,
            vec![
                m(w, l.x, u),
                m(w, r.x, u),
                m(w, u, y),
                self.nested_a_at_u,
                self.nested_b_at_u,
                m(u, x, y),
            ],
        );

        Ok(vec![preamble, query, eval])
    }

    /// The native openings beyond the revdot reduction's, over two more
    /// polynomials appended at `base`: the registry restriction at a fresh
    /// `w`, where it must equal $m(w, x, y)$, and the accumulator's batch
    /// polynomial at $u$, where it must equal $v$; and the accumulator's $a$
    /// and $b$ at $u$, where they must equal the eval stage's wires.
    pub(crate) fn native_openings<R: Rank, B: Backend>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        registry: &Registry<'_, C::CircuitField, R>,
        w: C::CircuitField,
        base: usize,
    ) -> ([C::HostCurve; 2], Vec<OpeningClaim<C::CircuitField>>) {
        let (x, y, u) = (challenges.x, challenges.y, challenges.u);
        let claim = |poly, point, value| OpeningClaim { poly, point, value };
        (
            [self.native_registry_xy, self.native_p],
            vec![
                claim(base, w, B::registry_wxy(registry, w, x, y)),
                claim(base + 1, u, self.v),
                claim(native_position(native::RxComponent::AbA), u, self.a_at_u),
                claim(native_position(native::RxComponent::AbB), u, self.b_at_u),
            ],
        )
    }

    /// The nested counterpart of [`native_openings`](Self::native_openings),
    /// at the nested $u$ and a fresh nested `w`.
    pub(crate) fn nested_openings<R: Rank, B: Backend>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        registry: &Registry<'_, C::ScalarField, R>,
        w: C::ScalarField,
        base: usize,
    ) -> Result<([C::NestedCurve; 2], Vec<OpeningClaim<C::ScalarField>>)> {
        let x = nested_challenge::<C>(challenges.x)?;
        let y = nested_challenge::<C>(challenges.y)?;
        let u = nested_challenge::<C>(challenges.u)?;
        let claim = |poly, point, value| OpeningClaim { poly, point, value };
        Ok((
            [self.nested_registry_xy, self.nested_p],
            vec![
                claim(base, w, B::registry_wxy(registry, w, x, y)),
                claim(base + 1, u, self.nested_v),
                claim(
                    nested_position(nested::RxComponent::AbA),
                    u,
                    self.nested_a_at_u,
                ),
                claim(
                    nested_position(nested::RxComponent::AbB),
                    u,
                    self.nested_b_at_u,
                ),
            ],
        ))
    }
}

#[cfg(test)]
#[path = "../../tests/compress_instance.rs"]
mod tests;
