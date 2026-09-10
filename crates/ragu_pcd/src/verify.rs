//! This module provides the [`Application::verify`] method implementation.
//!
//! The verifier is the decider: it holds every polynomial of the proof and
//! checks the accumulated claims on them directly, at challenges it samples
//! itself. What it reads from the proof beyond the polynomials it rederives
//! rather than trusts:
//!
//! - every cached commitment is recomputed from its polynomial, native and
//!   nested alike, batched per curve under a fresh scalar; the walked $P$
//!   and $P_n$ are among them, which is what ties the endoscaling walks the
//!   circuits verified to the batch polynomials;
//! - the challenges are rederived from the transcript over the bridge
//!   commitments, in the fuse's schedule;
//! - the `ab` bridge stage and the nested challenge and beta stages, whose
//!   contents are functions of other proof data, are rederived and compared;
//! - the registry values the query and eval stages claim, and the current
//!   step's own evaluations at $u$ and $u_n$, are read off the stage
//!   polynomials and held against the registry and the polynomials;
//! - $c$, $v$, $c_n$ and $v_n$ are derived from the polynomials, never read.

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
            stages::{ab as nested_ab, beta as nested_beta, challenges as nested_challenges},
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

        // The nested challenge stage is the unblinded stage of the lifts of
        // this proof's challenges: recompute it and compare. In-circuit, the
        // binding circuits tie its commitment to the transcript challenges.
        let nested_challenges_claim = {
            let lifts = pcd.proof().challenges().lifts::<C>()?;
            let (challenge_lifts, beta_lift) = lifts.split_at(nested_challenges::NUM);
            let expected_challenges = nested_challenges::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                &nested_challenges::Witness::new(
                    challenge_lifts.try_into().expect("NUM challenge lifts"),
                    pcd.proof().is_base_case::<HEADER_SIZE>(),
                ),
            )?;
            let expected_beta = nested_beta::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::ZERO,
                nested_beta::Witness { lift: beta_lift[0] },
            )?;
            pcd.proof()
                .nested_challenges_rx()
                .iter_coeffs()
                .eq(expected_challenges.iter_coeffs())
                && pcd
                    .proof()
                    .nested_beta_rx()
                    .iter_coeffs()
                    .eq(expected_beta.iter_coeffs())
        };

        // Every cached commitment, recomputed from its polynomial and
        // compared as one batch per curve. The walked P and P_n are among
        // them: the endoscaling steps verified the walks over the copied
        // points, and this is what ties those walks to p and p_n.
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
        // commitments and the proof's bridge blinding: rederive and compare.
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
    use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
    use ragu_pasta::Pasta;

    use super::*;
    use crate::ApplicationBuilder;

    type TestR = ProductionRank;
    const HEADER_SIZE: usize = 4;

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    #[test]
    fn verify_rejects_invalid_circuit_id() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Create a valid trivial proof
        let mut proof = app.trivial_proof();

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

        // Create a valid trivial proof
        let mut proof = app.trivial_proof();

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

        // Create a valid trivial proof
        let mut proof = app.trivial_proof();

        // Corrupt right_header to have wrong size
        proof.right_header = alloc::vec![<Pasta as Cycle>::CircuitField::ZERO; HEADER_SIZE - 1];

        let pcd = proof.carry::<()>(());
        let result = app.verify(&pcd, &mut rng).expect("verify should not error");
        assert!(!result, "verify should reject wrong right_header size");
    }
}
