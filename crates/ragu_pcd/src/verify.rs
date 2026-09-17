//! This module provides the [`Application::verify`] method implementation.
//!
//! The verifier is the decider: it holds every polynomial of the proof and
//! checks the accumulated claims on them directly, at challenges it samples
//! itself. What it reads from the proof beyond the polynomials it rederives
//! rather than trusts:
//!
//! - every cached commitment is checked against its polynomial, native and
//!   nested alike, batched per curve under a fresh scalar; this includes
//!   the batch commitments $P$ and $P_n$;
//! - the challenges are rederived from the transcript over the bridge
//!   commitments, in the fuse's schedule;
//! - the `ab` bridge stage and the nested challenge stage, whose contents
//!   are functions of other proof data, are rederived and compared;
//! - the registry values the query and eval stages claim, and the current
//!   step's own evaluations at $u$ and $u_n$, are read off the stage
//!   polynomials and held against the registry and the polynomials;
//! - the nested accumulator and registry commitments inside the native
//!   points stages are compared with the recomputed polynomial commitments;
//! - $c$, $v$, $c_n$ and $v_n$ are derived from the polynomials, never read.
//!
//! Checking a cached commitment against its polynomial does not tie it to a
//! walk's staged inputs or endpoint; the recursion circuits do, and the
//! decider checks their claims. For $P_n$, the native `bind_endoscalar`
//! circuit pins the endpoint through the unified instance, and `bind_beta`
//! holds the children's staged points against the children's unified
//! instances.
//!
//! A parent holds each child's nested challenge stage to the child's headers
//! (see [`challenges`]). The root has no parent, which is why the decider
//! rederives that stage itself.
//!
//! [`challenges`]: crate::internal::nested::stages::challenges

use alloc::vec::Vec;
use core::iter::once;

use ragu_arithmetic::{
    CurveAffine, Cycle, FixedGenerators, bitreverse,
    ff::{Field, PrimeField},
    group::Curve,
    rand::CryptoRng,
};
use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{Element, GadgetExt as _, Point, extract_endoscalar};

use crate::{
    Application, Pcd, Proof, RAGU_TAG, SelectableBackend,
    header::Header,
    internal::{
        claims,
        native::{
            self as native_internal, RxComponent, claims as native_claims,
            stages::preamble::ProofInputs,
        },
        nested::{
            self as nested_internal, RxComponent as NestedRxComponent,
            challenge as nested_challenge, claims as nested_claims,
            stages::{ab as nested_ab, challenges as nested_challenges},
            unified as nested_unified,
        },
        stage_wires::{StageReader, stage_wire_indices, wires_of},
        transcript::Transcript,
    },
};

/// The backend whose kernels [`Application::verify`] consults for the selected
/// backend `B`. Every computational call in this module goes through this
/// alias, never through `B` directly, so which code path decides acceptance is
/// fixed by the sealed [`SelectableBackend::Verifier`] mapping.
type Verifier<B> = <B as SelectableBackend>::Verifier;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Verifies some [`Pcd`] for the provided [`Header`].
    ///
    /// Returns `Ok(true)` if all verification checks pass, `Ok(false)` if
    /// any check fails (e.g., invalid circuit ID, header size mismatch,
    /// corrupted commitments or evaluations), or `Err` if an internal
    /// computation error occurs.
    ///
    /// The computational kernels used here are those of the sealed
    /// [`SelectableBackend::Verifier`] of the selected backend: the reference
    /// kernels for `ReferenceBackend` and `AcceleratedProver`, the accelerated
    /// ones for `AcceleratedBackend`. Applications choose between them but
    /// cannot supply the implementation that controls the acceptance decision.
    pub fn verify<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // Sample verification challenges w, y, and z.
        let w = C::CircuitField::random(&mut rng);
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);

        // The proof's circuit_id selects which wiring polynomial the verifier
        // checks against, and every domain point carries one, so an in-domain id
        // is always well defined. It need not name a circuit: the domain also
        // holds registered bonding polynomials and, at unassigned points, the
        // zero polynomial, which is itself a bonding polynomial. Letting the
        // prover choose freely among them is safe because this check expects a
        // circuit and so fixes k_0 = 1, which no bonding polynomial (s(X, 0) =
        // 0) can satisfy. Rejecting out-of-domain ids keeps the selection inside
        // that argument, rather than an evaluation of the registry interpolation
        // at an arbitrary point.
        // (Internal circuit IDs are constants and don't need this check.)
        if !self
            .native_registry
            .circuit_in_domain(pcd.proof().circuit_id())
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof().left_header().len() != HEADER_SIZE
            || pcd.proof().right_header().len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Every nested challenge is the lift of a native one, which exists
        // only for challenges in the endoscalar range. An honest transcript
        // output lies outside it with negligible probability; a proof
        // carrying one is malformed rather than an internal error.
        let Ok(lifts) = pcd.proof().challenges().lifts::<C>() else {
            return Ok(false);
        };

        // Compute unified k(y), unified_bridge k(y), and application k(y).
        let (unified_ky, unified_bridge_ky, application_ky) =
            Emulator::emulate_wireless((pcd.proof(), pcd.data().clone(), y), |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, &mut (), y)?;
                let proof_inputs =
                    ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

                let (unified_ky, unified_bridge_ky) = proof_inputs.unified_ky_values(dr, &y)?;
                let unified_ky = *unified_ky.value().take();
                let unified_bridge_ky = *unified_bridge_ky.value().take();
                let application_ky = *proof_inputs.application_ky(dr, &y)?.value().take();

                Ok((unified_ky, unified_bridge_ky, application_ky))
            })?;

        // Build a and b polynomials for each revdot claim.
        let source = native::SingleProofSource { proof: pcd.proof() };
        let mut builder =
            claims::Builder::<_, C::CircuitField, R, Verifier<B>>::new(&self.native_registry, y, z);
        native_claims::build(&source, &mut builder)?;

        // Check all native revdot claims.
        let native_revdot_claims = {
            let ky_source = native::SingleProofKySource {
                // NOTE: `raw_c` is now computed as `revdot(a, b)` rather
                // than stored in the proof, so this claim is tautological
                // in the verifier. It remains meaningful inside the circuit
                // where `c` is an independently allocated witness element.
                raw_c: Verifier::<B>::sparse_revdot(
                    &pcd.proof()[RxComponent::AbA],
                    &pcd.proof()[RxComponent::AbB],
                ),
                application_ky,
                unified_bridge_ky,
                unified_ky,
            };

            native::ky_values(&ky_source)
                .zip(builder.a.iter().zip(builder.b.iter()))
                .all(|(ky, (a, b))| Verifier::<B>::sparse_revdot(a, b) == ky)
        };

        // Check all nested revdot claims.
        let nested_revdot_claims = {
            let nested_source = nested::SingleProofSource { proof: pcd.proof() };
            let y_nested = C::ScalarField::random(&mut rng);
            let z_nested = C::ScalarField::random(&mut rng);
            let mut nested_builder = claims::Builder::<_, C::ScalarField, R, Verifier<B>>::new(
                &self.nested_registry,
                y_nested,
                z_nested,
            );
            nested_claims::build(&nested_source, &mut nested_builder)?;

            // The nested unified instance's k(y), at the sampled nested y,
            // for the instance circuits' claims: the instance is read off
            // the proof (c_n and v_n derived from its polynomials), and the
            // claims bind it to those circuits' traces.
            let unified_ky = Emulator::emulate_wireless(
                (pcd.proof().nested_instance()?, y_nested),
                |dr, witness| {
                    let (instance, y) = witness.cast();
                    let y = Element::alloc(dr, &mut (), y)?;
                    let output = nested_unified::Output::<_, C::HostCurve>::alloc(
                        dr,
                        &mut (),
                        instance.as_ref(),
                    )?;
                    Ok(*output.ky(dr, &y)?.value().take())
                },
            )?;
            let ky_source = nested::SingleProofKySource {
                // As with the native `raw_c` above, the nested accumulator's
                // claim is tautological here: its k(y) is derived from the
                // very polynomials the claim checks. It remains meaningful
                // inside the collapse circuit, where c_n is an instance
                // wire the fold is checked against.
                raw_c: Verifier::<B>::sparse_revdot(
                    &pcd.proof()[NestedRxComponent::AbA],
                    &pcd.proof()[NestedRxComponent::AbB],
                ),
                unified_ky,
            };
            nested::ky_values(&ky_source)
                .zip(nested_builder.a.iter().zip(nested_builder.b.iter()))
                .all(|(ky, (a, b))| Verifier::<B>::sparse_revdot(a, b) == ky)
        };

        // Check registry_xy polynomial evaluation at the sampled w.
        // registry_xy_poly is m(W, x, y) - the registry evaluated at current x, y, free in W.
        let registry_xy_claim = {
            let x = pcd.proof().x();
            let y = pcd.proof().y();
            let poly_eval = Verifier::<B>::sparse_eval(pcd.proof().native_registry_xy_poly(), w);
            let expected = Verifier::<B>::registry_wxy(&self.native_registry, w, x, y);
            poly_eval == expected
        };

        // The nested counterpart: the proof's nested registry_xy polynomial is
        // m_n(W, x_n, y_n) at the nested counterparts of its x and y, checked
        // at a sampled w.
        let nested_registry_xy_claim = {
            let w = C::ScalarField::random(&mut rng);
            let x = nested_challenge::<C>(pcd.proof().x())?;
            let y = nested_challenge::<C>(pcd.proof().y())?;
            let poly_eval = Verifier::<B>::sparse_eval(pcd.proof().nested_registry_xy_poly(), w);
            let expected = Verifier::<B>::registry_wxy(&self.nested_registry, w, x, y);
            poly_eval == expected
        };

        // Recompute this proof's unblinded nested challenge stage from its
        // native challenges, base-case sign and `pre_beta`, and compare its
        // coefficients. A parent holds a child's stage to the child's headers
        // through `bind_beta`, its walk and its nested batch; the root has no
        // parent, so the decider holds the root's stage to its headers here.
        let nested_challenges_claim = {
            let (challenge_lifts, beta_lift) = lifts.split_at(nested_challenges::NUM);
            let expected_challenges = nested_challenges::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                &nested_challenges::Witness::new::<_, HEADER_SIZE>(
                    challenge_lifts.try_into().expect("NUM challenge lifts"),
                    pcd.proof().left_header(),
                    pcd.proof().right_header(),
                    beta_lift[0],
                ),
            )?;
            pcd.proof()
                .nested_challenges_rx()
                .iter_coeffs()
                .eq(expected_challenges.iter_coeffs())
        };

        // Check cached commitments against their polynomials in one batch
        // per curve, including P = Com(p) and P_n = Com(p_n). The endoscaling
        // walks' staged inputs and endpoints are tied to these commitments by
        // `nested_points_claim` below and by the circuits that pin each walk
        // (`bind_endoscalar` and `bind_beta` for P_n, the nested `export` and
        // `loading` for P), whose claims the revdot checks above cover.
        let commitments_claim = {
            let proof = pcd.proof();
            let native = {
                let mut polys: Vec<&sparse::Polynomial<C::CircuitField, R>> = Vec::new();
                let mut points: Vec<C::HostCurve> = Vec::new();
                for &id in &native_internal::RxIndex::ALL {
                    polys.push(&proof[id]);
                    points.push(proof.native_rx_commitment(id));
                }
                for component in [RxComponent::AbA, RxComponent::AbB] {
                    polys.push(&proof[component]);
                    points.push(proof.native_commitment(component));
                }
                polys.push(proof.native_registry_xy_poly());
                points.push(proof.native_registry_xy_commitment());
                polys.push(proof.native_p_poly());
                points.push(proof.native_p_commitment());
                commitments_match::<Verifier<B>, _, _, R, _>(
                    &polys,
                    &points,
                    C::CircuitField::random(&mut rng),
                    C::host_generators(self.params),
                )
            };
            let nested = {
                let mut polys: Vec<&sparse::Polynomial<C::ScalarField, R>> = Vec::new();
                let mut points: Vec<C::NestedCurve> = Vec::new();
                for &id in &nested_internal::RxIndex::ALL {
                    polys.push(&proof[id]);
                    points.push(proof.nested_rx_commitment(id));
                }
                polys.push(&proof[NestedRxComponent::AbA]);
                points.push(proof.nested_a_commitment());
                polys.push(&proof[NestedRxComponent::AbB]);
                points.push(proof.nested_b_commitment());
                polys.push(proof.nested_registry_xy_poly());
                points.push(proof.nested_registry_xy_commitment());
                polys.push(proof.nested_p_poly());
                points.push(proof.nested_p_commitment());
                commitments_match::<Verifier<B>, _, _, R, _>(
                    &polys,
                    &points,
                    C::ScalarField::random(&mut rng),
                    C::nested_generators(self.params),
                )
            };
            native && nested
        };

        // The points the native walk consumes must commit to the nested
        // polynomials the decider retains, not just to evaluations at u_n.
        let nested_points_claim = nested_points_match(pcd.proof())?;

        // The challenges, rederived from the transcript over the bridge
        // commitments in the fuse's schedule, and pre_beta in the endoscalar
        // challenge range the prover grinds it into.
        let transcript_claim = {
            let proof = pcd.proof();
            let mut dr = Emulator::execute();
            let mut transcript =
                Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;
            macro_rules! absorb {
                ($point:expr) => {
                    Point::constant(&mut dr, $point)?.write(&mut dr, &mut transcript)?
                };
            }
            macro_rules! squeeze {
                () => {
                    *transcript.challenge(&mut dr)?.value().take()
                };
            }
            absorb!(proof.bridge_preamble_commitment());
            let w = squeeze!();
            absorb!(proof.bridge_s_prime_commitment());
            let y = squeeze!();
            let z = squeeze!();
            absorb!(proof.bridge_inner_error_commitment());
            let mu = squeeze!();
            let nu = squeeze!();
            absorb!(proof.bridge_outer_error_commitment());
            let mu_prime = squeeze!();
            let nu_prime = squeeze!();
            absorb!(proof.bridge_ab_commitment());
            let x = squeeze!();
            absorb!(proof.bridge_query_commitment());
            let alpha = squeeze!();
            absorb!(proof.bridge_f_commitment());
            let u = squeeze!();
            absorb!(proof.bridge_eval_commitment());
            let pre_beta = squeeze!();

            [w, y, z, mu, nu, mu_prime, nu_prime, x, alpha, u, pre_beta]
                == [
                    proof.w(),
                    proof.y(),
                    proof.z(),
                    proof.mu(),
                    proof.nu(),
                    proof.mu_prime(),
                    proof.nu_prime(),
                    proof.x(),
                    proof.alpha(),
                    proof.u(),
                    proof.pre_beta(),
                ]
                && extract_endoscalar(proof.pre_beta()).is_ok()
        };

        // The `ab` bridge stage is a function of the native a and b
        // commitments, the native points stage holding the nested ones, and
        // the proof's bridge blinding: rederive and compare.
        let ab_bridge_claim = {
            let proof = pcd.proof();
            let expected = nested_ab::Stage::<C::HostCurve, R>::rx(
                crate::proof::bridge_alpha_power(
                    proof.bridge_alpha,
                    nested_internal::RxIndex::BridgeAB,
                ),
                &nested_ab::Witness {
                    a: proof.native_commitment(RxComponent::AbA),
                    b: proof.native_commitment(RxComponent::AbB),
                    native_points_ab: proof
                        .native_rx_commitment(native_internal::RxIndex::PointsAb),
                },
            )?;
            proof[nested_internal::RxIndex::BridgeAB]
                .iter_coeffs()
                .eq(expected.iter_coeffs())
        };

        // What the query and eval stages claim of the registry, and of the
        // current step's own polynomials, held against the registry and the
        // polynomials themselves. The children's challenges and circuit ids
        // are read off the preamble stage, where the fold binds them. The
        // registry restrictions the step opened (m(w, x_i, Y), m(w, X, y))
        // are not carried by the proof, but their claimed evaluations are,
        // and the registry gives what they must be.
        let mesh_claim = {
            let proof = pcd.proof();
            let native = self.native_mesh_claim(proof)?;
            let nested = self.nested_mesh_claim(proof)?;
            native && nested
        };

        Ok(native_revdot_claims
            && nested_revdot_claims
            && registry_xy_claim
            && nested_registry_xy_claim
            && nested_challenges_claim
            && commitments_claim
            && nested_points_claim
            && transcript_claim
            && ab_bridge_claim
            && mesh_claim)
    }

    /// The native mesh claim: see [`verify`](Self::verify).
    fn native_mesh_claim(&self, proof: &Proof<C, R>) -> Result<bool> {
        use native_internal::{InternalCircuitIndex, RxIndex, stages};
        type Preamble<C, R, const H: usize> = stages::preamble::Stage<C, R, H>;
        type Query<C, R, const H: usize> = stages::query::Stage<C, R, H>;
        type Eval<C, R, const H: usize> = stages::eval::Stage<C, R, H>;

        let registry = &self.native_registry;
        let (w, x, y, u) = (proof.w(), proof.x(), proof.y(), proof.u());
        let m = |w, x, y| Verifier::<B>::registry_wxy(registry, w, x, y);

        // The children's challenges and circuit ids, off the preamble.
        let preamble = StageReader::<C::CircuitField, R>::new(&proof[RxIndex::Preamble]);
        let child = stage_wire_indices::<_, R, Preamble<C, R, HEADER_SIZE>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.unified.x)?);
                wires.extend(wires_of(&child.unified.y)?);
                wires.extend(wires_of(&child.circuit_id)?);
            }
            Ok(wires)
        })?;
        let child: Vec<C::CircuitField> = child.iter().map(|&i| preamble.read(i)).collect();
        let [left_x, left_y, left_id, right_x, right_y, right_id] =
            child.try_into().expect("six child values");

        // The query stage's registry values.
        let query = StageReader::<C::CircuitField, R>::new(&proof[RxIndex::Query]);
        let mut fixed = Vec::new();
        let claimed = stage_wire_indices::<_, R, Query<C, R, HEADER_SIZE>>(|out| {
            fixed = wires_of(&out.fixed_registry)?;
            let mut wires = wires_of(&out.registry_wxy)?;
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.child_registry_xy_at_current_w)?);
                wires.extend(wires_of(&child.current_registry_xy_at_child_circuit_id)?);
                wires.extend(wires_of(&child.current_registry_wy_at_child_x)?);
            }
            Ok(wires)
        })?;
        let evals = Verifier::<B>::registry_wxy_over_domain(registry, x, y);
        let log2_n = registry.log2_domain();
        let fixed_registry_claim = InternalCircuitIndex::ALL
            .iter()
            .zip(&fixed)
            .all(|(id, &i)| {
                let j = usize::from(id.circuit_index()) as u32;
                query.read(i) == evals[bitreverse(j, log2_n) as usize]
            });
        let claimed: Vec<C::CircuitField> = claimed.iter().map(|&i| query.read(i)).collect();
        let query_claim = claimed
            == [
                m(w, x, y),
                m(w, left_x, left_y),
                m(left_id, x, y),
                m(w, left_x, y),
                m(w, right_x, right_y),
                m(right_id, x, y),
                m(w, right_x, y),
            ];

        // The eval stage's current-step evaluations at u.
        let eval = StageReader::<C::CircuitField, R>::new(&proof[RxIndex::Eval]);
        let current = stage_wire_indices::<_, R, Eval<C, R, HEADER_SIZE>>(|out| {
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
        let current: Vec<C::CircuitField> = current.iter().map(|&i| eval.read(i)).collect();
        let eval_claim = current
            == [
                m(w, left_x, u),
                m(w, right_x, u),
                m(w, u, y),
                Verifier::<B>::sparse_eval(&proof[RxComponent::AbA], u),
                Verifier::<B>::sparse_eval(&proof[RxComponent::AbB], u),
                m(u, x, y),
            ];

        Ok(fixed_registry_claim && query_claim && eval_claim)
    }

    /// The nested mesh claim: see [`verify`](Self::verify).
    fn nested_mesh_claim(&self, proof: &Proof<C, R>) -> Result<bool> {
        use nested_internal::{InternalCircuitIndex, RxIndex, stages};
        type Preamble<C, R> = stages::preamble::Stage<C, R>;
        type Query<C, R> = stages::query::Stage<C, R>;
        type Eval<C, R> = stages::eval::Stage<C, R>;

        let registry = &self.nested_registry;
        let w = nested_challenge::<C>(proof.w())?;
        let x = nested_challenge::<C>(proof.x())?;
        let y = nested_challenge::<C>(proof.y())?;
        let u = nested_challenge::<C>(proof.u())?;
        let m = |w, x, y| Verifier::<B>::registry_wxy(registry, w, x, y);

        // The children's lifted challenges, off the preamble.
        let preamble = StageReader::<C::ScalarField, R>::new(&proof[RxIndex::BridgePreamble]);
        let child = stage_wire_indices::<_, R, Preamble<C::HostCurve, R>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.nested.x)?);
                wires.extend(wires_of(&child.nested.y)?);
            }
            Ok(wires)
        })?;
        let child: Vec<C::ScalarField> = child.iter().map(|&i| preamble.read(i)).collect();
        let [left_x, left_y, right_x, right_y] = child.try_into().expect("four child values");

        // The query stage's registry values.
        let query = StageReader::<C::ScalarField, R>::new(&proof[RxIndex::BridgeQuery]);
        let mut fixed = Vec::new();
        let claimed = stage_wire_indices::<_, R, Query<C::HostCurve, R>>(|out| {
            let q = &out.nested;
            fixed = wires_of(&q.fixed_registry)?;
            let mut wires = wires_of(&q.registry_wxy)?;
            for child in [&q.left, &q.right] {
                wires.extend(wires_of(&child.child_registry_xy_at_current_w)?);
                wires.extend(wires_of(&child.current_registry_wy_at_child_x)?);
            }
            Ok(wires)
        })?;
        let evals = Verifier::<B>::registry_wxy_over_domain(registry, x, y);
        let log2_n = registry.log2_domain();
        let fixed_registry_claim = InternalCircuitIndex::ALL
            .iter()
            .zip(&fixed)
            .all(|(id, &i)| {
                let j = usize::from(id.circuit_index()) as u32;
                query.read(i) == evals[bitreverse(j, log2_n) as usize]
            });
        let claimed: Vec<C::ScalarField> = claimed.iter().map(|&i| query.read(i)).collect();
        let query_claim = claimed
            == [
                m(w, x, y),
                m(w, left_x, left_y),
                m(w, left_x, y),
                m(w, right_x, right_y),
                m(w, right_x, y),
            ];

        // The eval stage's current-step evaluations at u_n.
        let eval = StageReader::<C::ScalarField, R>::new(&proof[RxIndex::BridgeEval]);
        let current = stage_wire_indices::<_, R, Eval<C::HostCurve, R>>(|out| {
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
        let current: Vec<C::ScalarField> = current.iter().map(|&i| eval.read(i)).collect();
        let eval_claim = current
            == [
                m(w, left_x, u),
                m(w, right_x, u),
                m(w, u, y),
                Verifier::<B>::sparse_eval(&proof[NestedRxComponent::AbA], u),
                Verifier::<B>::sparse_eval(&proof[NestedRxComponent::AbB], u),
                m(u, x, y),
            ];

        Ok(fixed_registry_claim && query_claim && eval_claim)
    }
}

/// Whether the persistent nested points consumed by the native walk are
/// the proof's polynomial commitments. `verify` separately recomputes the
/// caches; the recursive counterpart is `bind_endoscalar`'s exports and the
/// parent's `bind_beta` checks.
pub(crate) fn nested_points_match<C: Cycle, R: Rank>(proof: &Proof<C, R>) -> Result<bool> {
    use native_internal::{RxIndex, stages::points};

    let ab = StageReader::<C::CircuitField, R>::new(&proof[RxIndex::PointsAb]);
    let ab_wires = stage_wire_indices::<_, R, points::AbStage<C::NestedCurve>>(|stage| {
        let mut wires = wires_of(&stage.a)?;
        wires.extend(wires_of(&stage.b)?);
        Ok(wires)
    })?;
    let f = StageReader::<C::CircuitField, R>::new(&proof[RxIndex::PointsF]);
    let registry_wires = stage_wire_indices::<_, R, points::FStage<C::NestedCurve>>(|stage| {
        wires_of(&stage.registry_xy)
    })?;
    let held = ab_wires
        .iter()
        .map(|&i| ab.read(i))
        .chain(registry_wires.iter().map(|&i| f.read(i)));

    let mut expected = Vec::with_capacity(6);
    for point in [
        proof.nested_a_commitment(),
        proof.nested_b_commitment(),
        proof.nested_registry_xy_commitment(),
    ] {
        let Some(coordinates) = point.coordinates().into_option() else {
            return Ok(false);
        };
        expected.extend_from_slice(&[*coordinates.x(), *coordinates.y()]);
    }
    Ok(held.eq(expected))
}

/// Whether `commitments` are the commitments of `polys` under `generators`,
/// as one batch: the Horner combination of the polynomials under `r` must
/// commit to the same combination of the points, which a mismatch in any
/// pair breaks unless `r` is a root of the difference.
fn commitments_match<B, F, P, R, G>(
    polys: &[&sparse::Polynomial<F, R>],
    commitments: &[P],
    r: F,
    generators: &G,
) -> bool
where
    B: Backend,
    F: PrimeField,
    P: CurveAffine<ScalarExt = F>,
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

mod native {
    use super::*;
    pub use crate::internal::native::claims::ky_values;
    use crate::internal::{
        claims::Source,
        native::{RxComponent, claims::KySource},
    };

    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx sparse::Polynomial<C::CircuitField, R>;
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(&self.proof[component])
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::once(self.proof.circuit_id())
        }
    }

    /// Source for k(y) values for single-proof verification.
    pub struct SingleProofKySource<F> {
        pub raw_c: F,
        pub application_ky: F,
        pub unified_bridge_ky: F,
        pub unified_ky: F,
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn raw_c(&self) -> impl Iterator<Item = F> {
            once(self.raw_c)
        }

        fn application_ky(&self) -> impl Iterator<Item = F> {
            once(self.application_ky)
        }

        fn unified_bridge_ky(&self) -> impl Iterator<Item = F> {
            once(self.unified_bridge_ky)
        }

        fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
            once(self.unified_ky)
        }

        fn ones(&self) -> impl Iterator<Item = F> + Clone {
            once(F::ONE)
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

mod nested {
    use super::*;
    pub use crate::internal::nested::claims::ky_values;
    use crate::internal::{
        claims::Source,
        nested::{RxComponent, claims::KySource},
    };

    /// Source for nested field polynomials for single-proof verification.
    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx sparse::Polynomial<C::ScalarField, R>;
        type AppCircuitId = ();

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            core::iter::once(&self.proof[component])
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::empty()
        }
    }

    /// Source for k(y) values for nested single-proof verification.
    pub struct SingleProofKySource<F> {
        pub raw_c: F,
        pub unified_ky: F,
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn raw_c(&self) -> impl Iterator<Item = F> {
            once(self.raw_c)
        }

        fn ones(&self) -> impl Iterator<Item = F> + Clone {
            once(F::ONE)
        }

        fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
            once(self.unified_ky)
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

#[cfg(test)]
mod tests {
    use ragu_arithmetic::{
        ff::Field,
        rand::{SeedableRng, rngs::StdRng},
    };
    use ragu_circuits::{
        polynomials::{ProductionRank, sparse},
        registry::CircuitIndex,
    };
    use ragu_core::drivers::{Driver, DriverValue};
    use ragu_pasta::Pasta;
    use ragu_primitives::allocator::Standard;

    use super::*;
    use crate::{
        ApplicationBuilder,
        step::{Encoded, Index, Step},
    };

    type TestR = ProductionRank;
    const HEADER_SIZE: usize = 4;

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    /// A seed step with no predicate that outputs `()`.
    struct UnitSeed;

    impl Step<Pasta> for UnitSeed {
        const INDEX: Index = Index::new(0);

        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = ();

        fn witness<
            'dr,
            'source: 'dr,
            D: Driver<'dr, F = <Pasta as Cycle>::CircuitField>,
            const HS: usize,
        >(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
            _: DriverValue<D, ()>,
            _: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, ()>,
            DriverValue<D, ()>,
        )>
        where
            Self: 'dr,
        {
            Ok((
                (
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                ),
                D::unit(),
                D::unit(),
            ))
        }
    }

    /// A step with no predicate that fuses two `Pcd<()>` children into `()`.
    struct UnitStep;

    impl Step<Pasta> for UnitStep {
        const INDEX: Index = Index::new(1);

        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = ();

        fn witness<
            'dr,
            'source: 'dr,
            D: Driver<'dr, F = <Pasta as Cycle>::CircuitField>,
            const HS: usize,
        >(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, ()>,
            DriverValue<D, ()>,
        )>
        where
            Self: 'dr,
        {
            let allocator = &mut Standard::new();
            Ok((
                (
                    Encoded::new(dr, allocator, left)?,
                    Encoded::new(dr, allocator, right)?,
                    Encoded::from_gadget(()),
                ),
                D::unit(),
                D::unit(),
            ))
        }
    }

    #[test]
    fn verify_rejects_invalid_circuit_id() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a synthesized dummy proof
        let mut proof = app.dummy_proof();

        // Corrupt the circuit_id to be outside the registry domain
        proof.circuit_id = CircuitIndex::new(u32::MAX as usize);

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject invalid circuit_id");
    }

    #[test]
    fn verify_rejects_wrong_left_header_size() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a synthesized dummy proof
        let mut proof = app.dummy_proof();

        // Corrupt left_header to have wrong size
        proof.left_header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE + 1];

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject wrong left_header size");
    }

    #[test]
    fn verify_rejects_wrong_right_header_size() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a synthesized dummy proof
        let mut proof = app.dummy_proof();

        // Corrupt right_header to have wrong size
        proof.right_header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE - 1];

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject wrong right_header size");
    }

    /// Builds an application with a unit seed step to seed and a unit step
    /// fusing two `Pcd<()>` children.
    fn unit_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(UnitSeed)
            .expect("register seed step")
            .register(UnitStep)
            .expect("register fuse step")
            .finalize(Pasta::baked())
            .expect("failed to create test application")
    }

    /// Corrupts a proof so that it no longer verifies on its own. The edited
    /// polynomial's commitment cache is left stale, so a parent fused from the
    /// result opens a polynomial that its walked commitment does not match.
    fn corrupt(pcd: Pcd<Pasta, TestR, ()>) -> Pcd<Pasta, TestR, ()> {
        let (mut proof, ()) = pcd.into_parts();
        proof
            .native_a_poly
            .add_assign(&sparse::Polynomial::from_coeffs(alloc::vec![
                <Pasta as Cycle>::CircuitField::ONE,
            ]));
        proof.carry(())
    }

    /// Makes a proof's statement false without editing a polynomial: its stored
    /// $\mu$ no longer matches the transcript. A parent reads a child's $\mu$
    /// only into its copy of the child's instance, and every commitment cache
    /// stays consistent, so a parent fused from the result can be rejected only
    /// by enforcing its children's claims.
    fn invalidate(pcd: Pcd<Pasta, TestR, ()>) -> Pcd<Pasta, TestR, ()> {
        let (mut proof, ()) = pcd.into_parts();
        proof.mu += <Pasta as Cycle>::CircuitField::ONE;
        proof.carry(())
    }

    #[test]
    fn base_case_confined_to_bootstrap_rejects_invalid_unit_children() {
        // Regression test for the base-case over-broadness closed by confining
        // the base case to the internal `Bootstrap` step (see `is_base_case`).
        //
        // Previously any fuse whose step declared `()` inputs was treated as a
        // base case, so the child revdot claim was skipped and a corrupted
        // `Pcd<()>` slipped through. Now only a step declaring `Dummy`
        // inputs triggers it, so an application step's children always have
        // their claims enforced and the forgery is rejected.
        //
        // The children are invalidated without editing a polynomial. An edit
        // leaves that polynomial's commitment cache stale, and the verifier
        // rejects the parent on that mismatch alone, whether or not the child
        // claims are enforced: the test would pass with the base case open.
        let app = unit_app();
        let mut rng = StdRng::seed_from_u64(1);

        // Genuine seed still works: it fuses against the bootstrap proof, so an
        // honestly produced unit proof verifies.
        let (valid_unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        assert!(
            app.verify(&valid_unit, StdRng::seed_from_u64(2))
                .expect("valid child verify should not error"),
            "honestly produced unit proof should still verify"
        );

        // Positive control: the same fuse over honest children verifies, so a
        // rejection below is attributable to the children rather than to the
        // step itself.
        let (honest_parent, ()) = app
            .fuse(
                &mut rng,
                UnitStep,
                (),
                valid_unit.clone(),
                valid_unit.clone(),
            )
            .expect("honest fuse");
        assert!(
            app.verify(&honest_parent, StdRng::seed_from_u64(3))
                .expect("honest parent verify should not error"),
            "a parent fused from valid children must verify"
        );

        let invalid_child = invalidate(valid_unit);
        assert!(
            !app.verify(&invalid_child, StdRng::seed_from_u64(4))
                .expect("invalid child verify should not error"),
            "invalidated child proof should not verify on its own"
        );

        // Fusing the invalidated children through a unit step no longer
        // receives base-case treatment: `UnitStep` declares `()` inputs, not
        // `Dummy`, so the revdot claim is enforced. `fuse` does not check that
        // the trace it assembles is satisfiable, so it still succeeds; the
        // forgery is rejected by the verifier.
        let (parent, ()) = app
            .fuse(&mut rng, UnitStep, (), invalid_child.clone(), invalid_child)
            .expect("fuse assembles a proof regardless of satisfiability");
        assert!(
            !app.verify(&parent, StdRng::seed_from_u64(5))
                .expect("parent verify should not error"),
            "a parent fused from invalid children must not verify"
        );
    }

    #[test]
    fn forged_dummy_headers_cannot_trigger_the_base_case() {
        // Base-case detection reads the suffix slot of the headers the current
        // step declared for its children (see `is_dummy_input`). Those headers
        // live in three places that an honest prover keeps equal: the step's
        // application circuit bakes them in as constants, the proof stores
        // them, and the preamble stage witnesses them. A prover who forges any
        // one of the three to the reserved `Dummy` suffix — trying to make the
        // circuit skip the child revdot claim — breaks that agreement, and the
        // consumer's claims pin it:
        //
        // * `hashes_1` publishes the witnessed headers, which the verifier's
        //   `unified_bridge_ky` compares against the proof's stored headers; and
        // * the verifier's `application_ky` pins the stored headers to the
        //   constants the step's application circuit emitted.
        //
        // Forging the stored headers, as here, diverges from both, so the proof
        // must be rejected whether or not its children are valid.
        let app = unit_app();
        let forged = {
            let mut header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE];
            header[HEADER_SIZE - 1] =
                <Pasta as Cycle>::CircuitField::from(crate::header::Suffix::internal(2).get());
            header
        };

        let mut rng = StdRng::seed_from_u64(11);
        let (valid_unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        let invalid_unit = corrupt(valid_unit.clone());

        for (child, child_desc) in [(valid_unit, "valid"), (invalid_unit, "corrupted")] {
            let (parent, ()) = app
                .fuse(&mut rng, UnitStep, (), child.clone(), child)
                .expect("fuse assembles a proof regardless of satisfiability");

            let (mut proof, ()) = parent.into_parts();
            proof.left_header.clone_from(&forged);
            proof.right_header.clone_from(&forged);
            let parent = proof.carry::<()>(());

            assert!(
                !app.verify(&parent, StdRng::seed_from_u64(12))
                    .expect("parent verify should not error"),
                "forged dummy suffixes over {child_desc} children must not verify"
            );
        }
    }

    #[test]
    fn rerandomize_unit_proof_still_verifies() {
        // A `Pcd<()>` used to trip the over-broad base case during
        // rerandomization (both fuse inputs carried a `()` output), silently
        // dropping its revdot claim. With the base case confined to `Bootstrap`
        // and `Rerandomize`'s suffix wire constrained away from `Dummy`,
        // an honest rerandomize takes the normal claim-enforcing path — and
        // must still preserve verification.
        let pasta = Pasta::baked();
        let app = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(UnitSeed)
            .expect("register seed step")
            .finalize(pasta)
            .expect("failed to create test application");

        let mut rng = StdRng::seed_from_u64(7);
        let (unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        assert!(
            app.verify(&unit, StdRng::seed_from_u64(8))
                .expect("verify should not error"),
            "seeded unit proof should verify"
        );

        let rerandomized = app.rerandomize(unit, &mut rng).expect("rerandomize");
        assert!(
            app.verify(&rerandomized, StdRng::seed_from_u64(9))
                .expect("verify should not error"),
            "rerandomized unit proof should still verify through the enforced path"
        );
    }

    #[test]
    fn bootstrap_proof_verifies_as_unit() {
        let app = unit_app();
        let t = app.bootstrap_pcd();
        assert!(
            app.verify(&t, StdRng::seed_from_u64(51))
                .expect("verify should not error"),
            "the bootstrap proof must verify as ()"
        );
    }

    #[test]
    fn bootstrap_exempts_child_claims_with_consistent_commitments() {
        // Bootstrap may consume invalid child statements. Its PCS openings
        // must still match the children's committed polynomials.
        use crate::{header::Dummy, step::internal::bootstrap::Bootstrap};

        let app = unit_app();
        let mut rng = StdRng::seed_from_u64(71);
        let (unit, ()) = app.seed(&mut rng, UnitSeed, ()).expect("seed");
        let (consistent, ()) = unit.clone().into_parts();
        let (mismatched, ()) = corrupt(unit).into_parts();

        for (proof, expected, case) in [
            (consistent, true, "retyped child"),
            (mismatched, false, "mismatched child commitment"),
        ] {
            // A unit proof cannot attest a Dummy output. Retyping it makes
            // the child claim false without changing any polynomial or point.
            let child = proof.carry::<Dummy>(());
            assert!(
                !app.verify(&child, StdRng::seed_from_u64(74))
                    .expect("child verify should not error"),
                "{case}: the child claim must be invalid"
            );

            let (minted, ()) = app
                .fuse(&mut rng, Bootstrap::new(), (), child.clone(), child)
                .expect("fuse");
            assert_eq!(
                app.verify(&minted, StdRng::seed_from_u64(72))
                    .expect("verify should not error"),
                expected,
                "{case}: bootstrap exempts child claims while enforcing PCS consistency"
            );

            // A valid minted proof works like the cached bootstrap beneath a
            // seed step; a broken PCS check must still be rejected there.
            let (seeded, ()) = app
                .fuse(&mut rng, UnitSeed, (), minted.clone(), minted)
                .expect("fuse");
            assert_eq!(
                app.verify(&seeded, StdRng::seed_from_u64(73))
                    .expect("verify should not error"),
                expected,
                "{case}: the seed step must preserve the bootstrap verdict"
            );
        }
    }
}
