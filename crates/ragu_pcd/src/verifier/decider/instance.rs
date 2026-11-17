//! Verifier operations on a compressed instance.
use alloc::{vec, vec::Vec};

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::Rank,
    registry::Registry,
    staging::{StageExt, wires_of},
};
use ragu_core::{Cycle, Result};
use ragu_primitives::extract_endoscalar;
use udon::{fft::bit_reverse, field::Field};

use crate::{
    SelectableBackend,
    profile::ProfiledCycle,
    protocol::{
        compress::{
            instance::*,
            revdot::{OpeningClaim, claims::Masked},
        },
        ipa::{CycleTranscript, IpaTranscript},
        ky,
        ky::{NativeKy, NestedKy},
        native, nested,
        nested::challenge as nested_challenge,
    },
    verifier::recursive::{native::stages as native_stages, nested::stages as nested_stages},
};
impl<C: ProfiledCycle> Instance<C> {
    /// Rederives the fuse's challenges from the bridge commitments on
    /// `transcript`, which must be fresh under the fuse's tag, in the fuse's
    /// schedule. Returns `None` if `pre_beta` lies outside the endoscalar
    /// range.
    pub(crate) fn challenges<B: SelectableBackend>(
        &self,
        transcript: &mut CycleTranscript<'_, C, B>,
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
        absorb!(BridgeOuterError);
        let mu_prime = squeeze!();
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
            mu_prime,
            x,
            alpha,
            u,
            pre_beta,
        }))
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
        let nested_bound = ky::native_bound::<C::Profile, _>(|index| {
            self.nested_commitment(nested::RxComponent::Rx(index))
        });
        let native = NativeKy {
            c: Some(self.c),
            ..ky::native_ky_of::<C, HEADER_SIZE>(
                ky::NativeParts {
                    left_header: &self.left_header,
                    right_header: &self.right_header,
                    output_header,
                    online: &self.online,
                    circuit_id: self.circuit_id,
                    unified: &unified,
                    nested_bound: &nested_bound,
                },
                y,
            )?
        };
        let native_bound = ky::nested_bound::<C::Profile, _>(|index| {
            self.native_commitment(native::RxComponent::Rx(index))
        });
        let nested = NestedKy {
            c: self.nested_c,
            unified: ky::nested_ky_of::<C>(&self.nested_unified(challenges)?, nested_y)?,
            binding: ky::binding_ky_of(&native_bound, nested_y)?,
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
        let challenge_stage = nested_stages::challenges::Stage::<C::HostCurve, R, C::Profile>::rx(
            C::ScalarField::ZERO,
            &nested_stages::challenges::Witness::new::<_, HEADER_SIZE>(
                challenge_lifts.try_into().expect("NUM challenge lifts"),
                &self.left_header,
                &self.right_header,
                beta_lift[0],
            ),
        )?;
        let ab_bridge = nested_stages::ab::Stage::<C::HostCurve, R, C::Profile>::rx(
            crate::proof::bridge_alpha_power(self.bridge_alpha, nested::RxIndex::BridgeAB),
            &nested_stages::ab::Witness {
                a: self.native_commitment(native::RxComponent::AbA),
                b: self.native_commitment(native::RxComponent::AbB),
                native_points_ab: self
                    .native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb)),
            },
        )?;

        // Both stage polynomials are fixed before either commitment is
        // checked. Commit to them together, keeping the two equality checks
        // separate.
        let [challenge_commitment, ab_commitment] =
            B::sparse_commit_batch([&challenge_stage, &ab_bridge], generators)
                .map(C::NestedCurve::from);
        Ok(
            challenge_commitment == self.bridge(nested::RxIndex::ChallengeStage)
                && ab_commitment == self.bridge(nested::RxIndex::BridgeAB),
        )
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
        let claim = |poly, degrees: Vec<usize>, values: Vec<F<C>>| {
            Masked::new(poly, degrees, values, sigma)
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
        let mut values: Vec<_> = native::InternalCircuitIndex::all::<C::Profile>()
            .into_iter()
            .map(|id| {
                let j = usize::from(id.circuit_index::<C::Profile>()) as u32;
                evals[bit_reverse(j as usize, log2_n)]
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

        let points_ab =
            degrees::<_, R, native_stages::points::AbStage<C::NestedCurve, C::Profile>>(|stage| {
                let mut wires = wires_of(&stage.a)?;
                wires.extend(wires_of(&stage.b)?);
                Ok(wires)
            })?;
        let [ax, ay] = coordinates(self.nested_commitment(nested::RxComponent::AbA))?;
        let [bx, by] = coordinates(self.nested_commitment(nested::RxComponent::AbB))?;
        let points_ab = claim(Rx(PointsAb), points_ab, vec![ax, ay, bx, by]);

        let points_f =
            degrees::<_, R, native_stages::points::FStage<C::NestedCurve, C::Profile>>(|stage| {
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
        let claim = |poly, degrees: Vec<usize>, values: Vec<F<C>>| {
            Masked::new(poly, degrees, values, sigma)
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
        let mut values: Vec<_> = nested::InternalCircuitIndex::all::<C::Profile>()
            .into_iter()
            .map(|id| {
                let j = usize::from(id.circuit_index::<C::Profile>()) as u32;
                evals[bit_reverse(j as usize, log2_n)]
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

    /// The native openings beyond the revdot reduction's, over [`OPENED`]
    /// more polynomials appended at `base`: the registry restriction at a
    /// fresh `w`, where it must equal $m(w, x, y)$, the accumulator's batch
    /// polynomial at $u$, where it must equal $v$, and the accumulator's
    /// $a$ and $b$ at $u$, where they must equal the eval stage's wires.
    pub(crate) fn native_openings<R: Rank, B: Backend>(
        &self,
        challenges: &nested::Challenges<C::CircuitField>,
        registry: &Registry<'_, C::CircuitField, R>,
        w: C::CircuitField,
        base: usize,
    ) -> ([C::HostCurve; OPENED], Vec<OpeningClaim<C::CircuitField>>) {
        let (x, y, u) = (challenges.x, challenges.y, challenges.u);
        let claim = |poly, point, value| OpeningClaim { poly, point, value };
        (
            [
                self.native_registry_xy,
                self.native_p,
                self.native_commitment(native::RxComponent::AbA),
                self.native_commitment(native::RxComponent::AbB),
            ],
            vec![
                claim(base, w, B::registry_wxy(registry, w, x, y)),
                claim(base + 1, u, self.v),
                claim(base + 2, u, self.a_at_u),
                claim(base + 3, u, self.b_at_u),
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
    ) -> Result<([C::NestedCurve; OPENED], Vec<OpeningClaim<C::ScalarField>>)> {
        let x = nested_challenge::<C>(challenges.x)?;
        let y = nested_challenge::<C>(challenges.y)?;
        let u = nested_challenge::<C>(challenges.u)?;
        let claim = |poly, point, value| OpeningClaim { poly, point, value };
        Ok((
            [
                self.nested_registry_xy,
                self.nested_p,
                self.nested_commitment(nested::RxComponent::AbA),
                self.nested_commitment(nested::RxComponent::AbB),
            ],
            vec![
                claim(base, w, B::registry_wxy(registry, w, x, y)),
                claim(base + 1, u, self.nested_v),
                claim(base + 2, u, self.nested_a_at_u),
                claim(base + 3, u, self.nested_b_at_u),
            ],
        ))
    }
}

#[cfg(test)]
#[path = "../../../tests/compress_instance.rs"]
mod tests;
