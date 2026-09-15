//! Repaired substitutions at the recursive bindings introduced by PR #873.
//!
//! Each mutation states which local relation it preserves before checking the
//! production verifier and two generations of production fusion. Rejection is
//! required to be `Ok(false)`; construction errors and panics fail the test.
//! These are current-implementation regressions, not historical exploit replays.

use alloc::{sync::Arc, vec::Vec};

use proptest::prelude::*;
use ragu_arithmetic::{
    CurveAffine, Cycle, FixedGenerators,
    ff::{Field, PrimeField},
    group::{Curve, CurveAffine as _, Group},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::{Stage, StageExt},
};
use ragu_core::Result;
use ragu_pasta::{Ep, EpAffine, EqAffine, Fp, Fq};
use ragu_primitives::extract_endoscalar;
use ragu_testing::strategies;
use rand::{SeedableRng, rngs::StdRng};

use super::recursive_propagation_tests::support::{self, C, HEADER_SIZE, R, Value};
use crate::{
    Proof,
    internal::{
        Side,
        endoscalar::PointsWitness,
        native::{self, stages::points},
        nested::{self, stages::challenges},
        stage_wires::{StageReader, stage_wire_indices, wires_of},
    },
};

fn native_commit(app: &support::App, poly: &sparse::Polynomial<Fp, R>) -> EqAffine {
    ReferenceBackend::sparse_commit_to_affine(poly, C::host_generators(app.params))
}

fn nested_commit(app: &support::App, poly: &sparse::Polynomial<Fq, R>) -> EpAffine {
    ReferenceBackend::sparse_commit_to_affine(poly, C::nested_generators(app.params))
}

/// Check both child slots and every grandparent slot. Rerandomization is checked
/// at the child and at each descendant, with unchanged application data. The
/// generated flag also puts the rerandomized child through the recursive path.
fn check_descendants(
    app: &support::App,
    inputs: &support::Inputs,
    child: &support::TestPcd,
    sibling: &support::TestPcd,
    expected: bool,
    reblind_first: bool,
    label: &str,
) -> Result<()> {
    let mut rng = StdRng::seed_from_u64(inputs.proof_seed.wrapping_add(0x873));
    let verify = |pcd: &support::TestPcd, seed, position: &str| -> Result<()> {
        assert_eq!(
            app.verify(pcd, StdRng::seed_from_u64(seed))?,
            expected,
            "{label}: {position}"
        );
        Ok(())
    };
    verify(child, inputs.verifier_seed, "child")?;
    let reblinded = app.rerandomize(child.clone(), &mut rng)?;
    assert_eq!(reblinded.data(), child.data());
    verify(
        &reblinded,
        inputs.verifier_seed.wrapping_add(1),
        "rerandomized child",
    )?;
    let child = if reblind_first { &reblinded } else { child };
    for (i, (position, descendant)) in support::descendants(app, child, sibling, &mut rng)?
        .into_iter()
        .enumerate()
    {
        let seed = inputs.verifier_seed.wrapping_add(2 + 2 * i as u64);
        verify(&descendant, seed, &position)?;
        let data = *descendant.data();
        let reblinded = app.rerandomize(descendant, &mut rng)?;
        assert_eq!(*reblinded.data(), data);
        verify(&reblinded, seed.wrapping_add(1), &position)?;
    }
    Ok(())
}

mod challenge_binding {
    use super::*;

    fn witness(proof: &Proof<C, R>) -> Result<challenges::Witness<Fq>> {
        let lifts = proof.challenges().lifts::<C>()?;
        Ok(challenges::Witness::new::<_, HEADER_SIZE>(
            lifts[..challenges::NUM].try_into().unwrap(),
            proof.left_header(),
            proof.right_header(),
            lifts[challenges::NUM],
        ))
    }

    /// Repair the stage, its cache, every running binder partial, the exported
    /// partial, and the eval bridge's copy of the changed native eval commitment.
    /// The native transcript challenges deliberately remain the original ones.
    fn install_lifts(
        app: &support::App,
        proof: &mut Proof<C, R>,
        changed: &challenges::Witness<Fq>,
    ) -> Result<()> {
        let partials = native::stages::eval::BindingPartials::compute::<C, R, ReferenceBackend>(
            app.params, changed,
        );
        proof.nested_challenges_rx = challenges::Stage::<EqAffine, R>::rx(Fq::ZERO, changed)?;
        proof.nested_challenges_commitment.0 = nested_commit(app, &proof.nested_challenges_rx);
        proof.nested_challenges_partial = partials.binding;
        let wires =
            stage_wire_indices::<_, R, native::stages::eval::Stage<C, R, HEADER_SIZE>>(|stage| {
                wires_of(&stage.partials)
            })?;
        let values: Vec<_> = partials
            .partials
            .iter()
            .flat_map(|&point| support::coordinates(point))
            .collect();
        support::set_wires(&mut proof.native_eval_rx, &wires, &values);
        proof.native_eval_commitment.0 = native_commit(app, &proof.native_eval_rx);
        let copy = stage_wire_indices::<_, R, nested::stages::eval::Stage<EqAffine, R>>(|stage| {
            wires_of(&stage.native_eval)
        })?;
        support::set_wires(
            Arc::make_mut(&mut proof.bridge_eval_rx),
            &copy,
            &support::coordinates(proof.native_eval_commitment.0),
        );
        proof.bridge_eval_commitment = nested_commit(app, &proof.bridge_eval_rx);
        assert_complete_binding(app, proof)?;
        Ok(())
    }

    /// This is precisely the equality the parent completes with pre_beta.
    fn assert_complete_binding(app: &support::App, proof: &Proof<C, R>) -> Result<()> {
        let beta_generator = C::nested_generators(app.params).g()
            [native::circuits::bind_beta::generator_index::<C, R>()];
        assert_eq!(
            (proof.nested_challenges_partial.to_curve()
                + beta_generator * nested::challenge::<C>(proof.pre_beta())?)
            .to_affine(),
            proof.nested_challenges_commitment(),
            "the repaired parent beta-binding relation must hold"
        );
        Ok(())
    }

    fn check_lifts(
        app: &support::App,
        inputs: &support::Inputs,
        slot: usize,
        delta: Fq,
        reblind_first: bool,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let mut rng = inputs.prover_rng();
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        let (mut control, data) = honest.clone().into_parts();
        install_lifts(app, &mut control, &witness(honest.proof())?)?;
        check_descendants(
            app,
            inputs,
            &control.carry::<Value>(data),
            &sibling,
            true,
            reblind_first,
            "unchanged lifts with repaired caches",
        )?;

        let (mut proof, data) = honest.clone().into_parts();
        let original = witness(&proof)?;
        let mut changed = original.clone();
        changed.lifts[slot] += delta;
        install_lifts(app, &mut proof, &changed)?;
        assert_eq!(
            proof.challenges().in_order(),
            honest.proof().challenges().in_order()
        );
        assert_ne!(changed.lifts[slot], original.lifts[slot]);
        assert_ne!(
            proof.nested_challenges_commitment(),
            honest.proof().nested_challenges_commitment()
        );
        assert!(crate::verify::nested_points_match(&proof)?);
        check_descendants(
            app,
            inputs,
            &proof.carry::<Value>(data),
            &sibling,
            false,
            reblind_first,
            &alloc::format!("lift {slot}"),
        )
    }

    fn check_partials(
        app: &support::App,
        inputs: &support::Inputs,
        bit: u32,
        delta: Fq,
        reblind_first: bool,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let mut rng = inputs.prover_rng();
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        check_descendants(
            app,
            inputs,
            &honest,
            &sibling,
            true,
            reblind_first,
            "honest",
        )?;
        let beta_generator = C::nested_generators(app.params).g()
            [native::circuits::bind_beta::generator_index::<C, R>()];
        for case in ["partial", "pre_beta", "pre_beta_with_compensating_partial"] {
            let (mut proof, data) = honest.clone().into_parts();
            if case == "partial" {
                proof.nested_challenges_partial = (proof.nested_challenges_partial.to_curve()
                    + Ep::generator() * delta)
                    .to_affine();
            } else {
                let old_beta = nested::challenge::<C>(proof.pre_beta())?;
                let old_bits = extract_endoscalar(proof.pre_beta())?;
                proof.pre_beta = Fp::from_u128(old_bits ^ (1u128 << bit));
                let new_beta = nested::challenge::<C>(proof.pre_beta())?;
                assert_ne!(new_beta, old_beta);
                if case == "pre_beta_with_compensating_partial" {
                    proof.nested_challenges_partial = (proof.nested_challenges_partial.to_curve()
                        + beta_generator * (old_beta - new_beta))
                        .to_affine();
                    // The entire parent binding still agrees, even though the
                    // partial and pre_beta each differ from the child's trace.
                    assert_complete_binding(app, &proof)?;
                }
            }
            // The challenge polynomial and every polynomial commitment remain
            // untouched. This is not a stale commitment-cache rejection.
            assert_eq!(
                proof.nested_challenges_commitment(),
                honest.proof().nested_challenges_commitment()
            );
            assert!(
                proof
                    .nested_challenges_rx
                    .iter_coeffs()
                    .eq(honest.proof().nested_challenges_rx.iter_coeffs())
            );
            check_descendants(
                app,
                inputs,
                &proof.carry::<Value>(data),
                &sibling,
                false,
                reblind_first,
                case,
            )?;
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn repaired_lifts_reject_through_parent_and_grandparent(
            inputs in support::inputs(),
            slot in 0usize..challenges::NUM,
            delta in strategies::nonzero_prime_field_element::<Fq>(),
            reblind_first in any::<bool>(),
        ) {
            support::with_app(|app| check_lifts(app, &inputs, slot, delta, reblind_first)).unwrap();
        }

        #[test]
        fn partial_and_pre_beta_substitutions_reject_through_two_generations(
            inputs in support::inputs(),
            bit in 0u32..128,
            delta in strategies::nonzero_prime_field_element::<Fq>(),
            reblind_first in any::<bool>(),
        ) {
            support::with_app(|app| check_partials(app, &inputs, bit, delta, reblind_first)).unwrap();
        }
    }
}

/// Read a points-only native stage, excluding its SYSTEM blinding coefficient.
fn stage_points<S: Stage<Fp, R> + Default>(
    poly: &sparse::Polynomial<Fp, R>,
) -> Result<Vec<EpAffine>> {
    let wires = stage_wire_indices::<_, R, S>(|stage| wires_of(&stage))?;
    assert!(wires.len().is_multiple_of(2));
    let reader = StageReader::new(poly);
    Ok(wires
        .chunks_exact(2)
        .map(|pair| {
            EpAffine::from_xy(reader.read(pair[0]), reader.read(pair[1]))
                .into_option()
                .expect("the fixture's staged point must be on curve")
        })
        .collect())
}

fn walk_inputs(
    proof: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<points::Inputs<EpAffine>> {
    let f = stage_points::<points::FStage<EpAffine>>(&proof.native_points_f_rx)?;
    let wx =
        stage_points::<points::RegistryWxStage<EpAffine>>(&proof.native_points_registry_wx_rx)?;
    let ab = stage_points::<points::AbStage<EpAffine>>(&proof.native_points_ab_rx)?;
    let mut points = alloc::vec![f[1]];
    points.extend(nested::pcs::child_commitments(left));
    points.extend(nested::pcs::child_commitments(right));
    points.extend([wx[0], wx[1], ab[0], ab[1], ab[2], f[0]]);
    let inputs = points::Inputs::from_walk(&points);
    assert_eq!(
        horner(&points, nested::challenge::<C>(proof.pre_beta())?),
        proof.nested_p_commitment()
    );
    Ok(inputs)
}

fn horner(points: &[EpAffine], beta: Fq) -> EpAffine {
    points
        .iter()
        .fold(Ep::identity(), |acc, point| acc * beta + point)
        .to_affine()
}

fn native_instance(proof: &Proof<C, R>) -> native::unified::Instance<C> {
    native::unified::Instance {
        bridge_preamble_commitment: proof.bridge_preamble_commitment(),
        w: proof.w(),
        bridge_s_prime_commitment: proof.bridge_s_prime_commitment(),
        y: proof.y(),
        z: proof.z(),
        bridge_inner_error_commitment: proof.bridge_inner_error_commitment(),
        mu: proof.mu(),
        nu: proof.nu(),
        bridge_outer_error_commitment: proof.bridge_outer_error_commitment(),
        mu_prime: proof.mu_prime(),
        nu_prime: proof.nu_prime(),
        c: proof.native_c(),
        bridge_ab_commitment: proof.bridge_ab_commitment(),
        x: proof.x(),
        bridge_query_commitment: proof.bridge_query_commitment(),
        alpha: proof.alpha(),
        bridge_f_commitment: proof.bridge_f_commitment(),
        u: proof.u(),
        bridge_eval_commitment: proof.bridge_eval_commitment(),
        pre_beta: proof.pre_beta(),
        v: proof.v(),
        nested_challenges_partial: proof.nested_challenges_partial(),
        nested_p_commitment: proof.nested_p_commitment(),
        nested_a_commitment: proof.nested_a_commitment(),
        nested_b_commitment: proof.nested_b_commitment(),
        nested_registry_xy_commitment: proof.nested_registry_xy_commitment(),
        coverage: native::unified::Coverage::default(),
    }
}

/// Preserve each stage's blinding while rebuilding the walk and its real circuit
/// traces. Merely changing input coordinates would leave stale arithmetic in the
/// endoscaling steps and would not exercise a Horner-preserving substitution.
fn install_walk(
    app: &support::App,
    proof: &mut Proof<C, R>,
    inputs: &points::Inputs<EpAffine>,
    rng: &mut StdRng,
) -> Result<()> {
    fn alpha(poly: &sparse::Polynomial<Fp, R>) -> Fp {
        poly.iter_coeffs().nth(2 * R::n() - 1).unwrap()
    }
    proof.native_points_binding_rx = <points::BindingStage<EpAffine> as StageExt<Fp, R>>::rx(
        alpha(&proof.native_points_binding_rx),
        &inputs.binding,
    )?;
    proof.native_points_binding_commitment.0 = native_commit(app, &proof.native_points_binding_rx);
    proof.native_points_f_rx = <points::FStage<EpAffine> as StageExt<Fp, R>>::rx(
        alpha(&proof.native_points_f_rx),
        &inputs.f,
    )?;
    proof.native_points_f_commitment.0 = native_commit(app, &proof.native_points_f_rx);

    let binding_copy =
        stage_wire_indices::<_, R, nested::stages::preamble::Stage<EqAffine, R>>(|stage| {
            wires_of(&stage.native_points_binding)
        })?;
    support::set_wires(
        Arc::make_mut(&mut proof.bridge_preamble_rx),
        &binding_copy,
        &support::coordinates(proof.native_points_binding_commitment.0),
    );
    proof.bridge_preamble_commitment = nested_commit(app, &proof.bridge_preamble_rx);
    let f_copy = stage_wire_indices::<_, R, nested::stages::f::Stage<EqAffine, R>>(|stage| {
        wires_of(&stage.native_points_f)
    })?;
    support::set_wires(
        Arc::make_mut(&mut proof.bridge_f_rx),
        &f_copy,
        &support::coordinates(proof.native_points_f_commitment.0),
    );
    proof.bridge_f_commitment = nested_commit(app, &proof.bridge_f_rx);

    let bits = extract_endoscalar(proof.pre_beta())?;
    let walked = inputs.walk();
    let walk = points::WalkWitness::new(
        bits,
        PointsWitness::<
            EpAffine,
            { native::NUM_ENDOSCALING_POINTS },
            { native::ENDOSCALINGS_PER_STEP },
        >::new(bits, &walked),
    );
    assert_eq!(walk.p(), proof.nested_p_commitment());
    assert_eq!(
        horner(&walked, nested::challenge::<C>(proof.pre_beta())?),
        walk.p()
    );
    proof.native_points_walk_rx = <points::WalkStage<EpAffine> as StageExt<Fp, R>>::rx(
        alpha(&proof.native_points_walk_rx),
        &walk,
    )?;
    proof.native_points_walk_commitment.0 = native_commit(app, &proof.native_points_walk_rx);
    for step in 0..native::NUM_ENDOSCALING_STEPS {
        let trace = native::circuits::endoscaling_step::Circuit::<C, R>::new(step)
            .trace(native::circuits::endoscaling_step::Witness {
                inputs,
                walk: &walk,
            })?
            .into_output();
        proof.native_endoscaling_step_rxs[step] = app.native_registry.assemble(
            &trace,
            native::InternalCircuitIndex::EndoscalingStep(step as u32).circuit_index(),
            &mut *rng,
        )?;
        proof.native_endoscaling_step_commitments[step].0 =
            native_commit(app, &proof.native_endoscaling_step_rxs[step]);
    }
    let trace = native::circuits::bind_endoscalar::Circuit::<C, R>::new()
        .trace(native::circuits::bind_endoscalar::Witness {
            unified: native_instance(proof),
            inputs,
            walk: &walk,
        })?
        .into_output();
    proof.native_bind_endoscalar_rx = app.native_registry.assemble(
        &trace,
        native::InternalCircuitIndex::BindEndoscalarCircuit.circuit_index(),
        rng,
    )?;
    proof.native_bind_endoscalar_commitment.0 =
        native_commit(app, &proof.native_bind_endoscalar_rx);
    assert!(crate::verify::nested_points_match(proof)?);
    Ok(())
}

mod walk_binding {
    use super::*;

    fn check_input_substitutions(
        app: &support::App,
        inputs: &support::Inputs,
        bridge: usize,
        right_side: bool,
        delta: Fq,
        reblind_first: bool,
    ) -> Result<()> {
        let (honest, left, right) = support::fused(app, inputs)?;
        let mut rng = inputs.prover_rng();
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        let original_inputs = walk_inputs(honest.proof(), left.proof(), right.proof())?;
        let (mut control, data) = honest.clone().into_parts();
        install_walk(app, &mut control, &original_inputs, &mut rng)?;
        check_descendants(
            app,
            inputs,
            &control.carry::<Value>(data),
            &sibling,
            true,
            reblind_first,
            "unchanged walk with rebuilt traces",
        )?;
        let original = original_inputs.walk();
        let beta = nested::challenge::<C>(honest.proof().pre_beta())?;
        let change = Ep::generator() * delta;
        let offset = 1 + usize::from(right_side) * points::NUM_CHILD_POINTS;
        let cases = [
            ("bridge", nested::RxIndex::BRIDGES[bridge].position()),
            ("challenge", nested::RxIndex::ChallengeStage.position()),
            ("A_n", nested::RxIndex::NUM),
            ("B_n", nested::RxIndex::NUM + 1),
            ("registry_xy", nested::RxIndex::NUM + 2),
            ("P_n", nested::RxIndex::NUM + 3),
        ];
        for (name, position) in cases {
            let index = offset + position;
            let mut points = original.clone();
            points[index] = (points[index].to_curve() + change).to_affine();
            // beta^(N-1-index) * change is canceled by the initial
            // point's beta^(N-1) weight. Every other input stays fixed.
            points[0] = (points[0].to_curve()
                - change * beta.invert().unwrap().pow_vartime([index as u64]))
            .to_affine();
            assert_ne!(points[index], original[index]);
            assert_ne!(points[0], original[0]);
            assert_eq!(horner(&points, beta), honest.proof().nested_p_commitment());
            let changed_inputs = points::Inputs::from_walk(&points);
            let (mut proof, data) = honest.clone().into_parts();
            install_walk(app, &mut proof, &changed_inputs, &mut rng)?;
            assert_eq!(proof.nested_v()?, honest.proof().nested_v()?);
            assert_eq!(
                proof.nested_p_commitment(),
                honest.proof().nested_p_commitment()
            );
            check_descendants(
                app,
                inputs,
                &proof.carry::<Value>(data),
                &sibling,
                false,
                reblind_first,
                name,
            )?;
        }
        Ok(())
    }

    fn check_registry(
        app: &support::App,
        inputs: &support::Inputs,
        offset: usize,
        delta: Fq,
        reblind_first: bool,
    ) -> Result<()> {
        let (honest, left, right) = support::fused(app, inputs)?;
        let mut rng = inputs.prover_rng();
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        let original_inputs = walk_inputs(honest.proof(), left.proof(), right.proof())?;
        let (mut control, data) = honest.clone().into_parts();
        install_walk(app, &mut control, &original_inputs, &mut rng)?;
        check_descendants(
            app,
            inputs,
            &control.carry::<Value>(data),
            &sibling,
            true,
            reblind_first,
            "unchanged registry with rebuilt traces",
        )?;
        let (mut proof, data) = honest.clone().into_parts();
        let mut points = original_inputs.walk();
        let w = nested::challenge::<C>(proof.w())?;
        let u = nested::challenge::<C>(proof.u())?;
        let beta = nested::challenge::<C>(proof.pre_beta())?;
        let domain_size = 1usize << app.nested_registry.log2_domain();
        let offset = offset % (R::num_coeffs() - domain_size - 2);
        let queries: Vec<_> = (0..domain_size)
            .map(|i| CircuitIndex::new(i).omega_j())
            .chain([w, u])
            .collect();
        // Vanish at every old opening, including the whole registry domain.
        // The independent expected polynomial remains the fixed registry's
        // restriction at the unchanged x/y, not this edited polynomial.
        let expected = ReferenceBackend::registry_xy(
            &app.nested_registry,
            nested::challenge::<C>(proof.x())?,
            nested::challenge::<C>(proof.y())?,
        );
        assert!(
            expected
                .iter_coeffs()
                .eq(proof.nested_registry_xy_poly.iter_coeffs())
        );
        support::edit(&mut proof.nested_registry_xy_poly, |coefficients| {
            for (degree, value) in [(0, u * w), (1, -u - w), (2, Fq::ONE)] {
                coefficients[offset + degree] -= delta * value;
                coefficients[offset + domain_size + degree] += delta * value;
            }
        });
        assert!(
            !expected
                .iter_coeffs()
                .eq(proof.nested_registry_xy_poly.iter_coeffs())
        );
        for query in queries {
            assert_eq!(
                proof.nested_registry_xy_poly.eval(query),
                expected.eval(query)
            );
        }
        proof.nested_registry_xy_commitment.0 = nested_commit(app, &proof.nested_registry_xy_poly);
        let last = points.len() - 1;
        let difference = proof.nested_registry_xy_commitment().to_curve() - points[last];
        assert!(!bool::from(difference.is_identity()));
        points[last] = proof.nested_registry_xy_commitment();
        points[0] = (points[0].to_curve()
            - difference * beta.invert().unwrap().pow_vartime([last as u64]))
        .to_affine();
        install_walk(
            app,
            &mut proof,
            &points::Inputs::from_walk(&points),
            &mut rng,
        )?;
        assert_eq!(proof.nested_v()?, honest.proof().nested_v()?);
        assert_eq!(
            proof.nested_p_commitment(),
            honest.proof().nested_p_commitment()
        );
        check_descendants(
            app,
            inputs,
            &proof.carry::<Value>(data),
            &sibling,
            false,
            reblind_first,
            "late registry with compensated F_n",
        )
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn substituted_walk_inputs_reject_with_the_same_horner_endpoint(
            inputs in support::inputs(),
            bridge in 0usize..nested::RxIndex::BRIDGES.len(),
            right_side in any::<bool>(),
            delta in strategies::nonzero_prime_field_element::<Fq>(),
            reblind_first in any::<bool>(),
        ) {
            support::with_app(|app| check_input_substitutions(app, &inputs, bridge, right_side, delta, reblind_first)).unwrap();
        }

        #[test]
        fn late_registry_substitution_rejects_with_openings_and_endpoint_preserved(
            inputs in support::inputs(),
            offset in any::<usize>(),
            delta in strategies::nonzero_prime_field_element::<Fq>(),
            reblind_first in any::<bool>(),
        ) {
            support::with_app(|app| check_registry(app, &inputs, offset, delta, reblind_first)).unwrap();
        }
    }
}

mod claim_values {
    use super::*;

    /// Move c by an independently chosen delta, rather than rescale A/B while
    /// preserving c. The untouched circuit traces still claim the original fold.
    fn change_c<F: ragu_arithmetic::DeferredField>(
        a: &mut sparse::Polynomial<F, R>,
        b: &sparse::Polynomial<F, R>,
        delta: F,
        selector: usize,
    ) {
        let expected = a.revdot(b) + delta;
        let coefficients: Vec<_> = b.iter_coeffs().collect();
        let nonzero: Vec<_> = coefficients
            .iter()
            .enumerate()
            .filter(|(_, value)| **value != F::ZERO)
            .collect();
        let (degree, &value) = nonzero[selector % nonzero.len()];
        support::edit(a, |coefficients| {
            coefficients[R::num_coeffs() - 1 - degree] += delta * value.invert().unwrap();
        });
        assert_eq!(a.revdot(b), expected);
    }

    fn changed(
        app: &support::App,
        original: &Proof<C, R>,
        native_delta: Option<Fp>,
        nested_delta: Option<Fq>,
        selector: usize,
    ) -> Result<Proof<C, R>> {
        let mut proof = original.clone();
        if let Some(delta) = native_delta {
            change_c(
                &mut proof.native_a_poly,
                &proof.native_b_poly,
                delta,
                selector,
            );
            proof.native_a_commitment.0 = native_commit(app, &proof.native_a_poly);
        }
        if let Some(delta) = nested_delta {
            change_c(
                &mut proof.nested_a_poly,
                &proof.nested_b_poly,
                delta,
                selector,
            );
            proof.nested_a_commitment.0 = nested_commit(app, &proof.nested_a_poly);
            let wires =
                stage_wire_indices::<_, R, points::AbStage<EpAffine>>(|stage| wires_of(&stage.a))?;
            support::set_wires(
                &mut proof.native_points_ab_rx,
                &wires,
                &support::coordinates(proof.nested_a_commitment.0),
            );
            proof.native_points_ab_commitment.0 = native_commit(app, &proof.native_points_ab_rx);
        }
        // Repair the deterministic AB bridge too, so this is not a mismatch
        // between a newly committed A and an old cached AB bridge.
        let bridge = nested::stages::ab::Stage::<EqAffine, R>::rx(
            crate::proof::bridge_alpha_power(proof.bridge_alpha, nested::RxIndex::BridgeAB),
            &nested::stages::ab::Witness {
                a: proof.native_a_commitment.0,
                b: proof.native_b_commitment.0,
                native_points_ab: proof.native_points_ab_commitment.0,
            },
        )?;
        proof.bridge_ab_commitment.0 = nested_commit(app, &bridge);
        proof.bridge_ab_rx.0 = Arc::new(bridge);
        assert_eq!(
            proof.native_c(),
            original.native_c() + native_delta.unwrap_or(Fp::ZERO)
        );
        assert_eq!(
            proof.nested_c(),
            original.nested_c() + nested_delta.unwrap_or(Fq::ZERO)
        );
        assert!(crate::verify::nested_points_match(&proof)?);
        Ok(proof)
    }

    /// Bootstrap's own sign is +1, but its unit output is an ordinary child of
    /// the next application step. Changing its accumulator must not evade that
    /// step's claim checks. The permitted local c exemption is tested separately
    /// by base_case_combinations::both_collapse_guards_confine_the_base_case_to_bootstrap.
    fn check_bootstrap(
        app: &support::App,
        inputs: &support::Inputs,
        child: support::UnitPcd,
        sibling: &support::TestPcd,
        expected: bool,
        reblind_first: bool,
        label: &str,
    ) -> Result<()> {
        let mut rng = inputs.prover_rng();
        assert_eq!(
            app.verify(&child, inputs.verifier_rng())?,
            expected,
            "{label}: bootstrap"
        );
        let reblinded = app.rerandomize(child.clone(), &mut rng)?;
        assert_eq!(
            app.verify(&reblinded, inputs.verifier_rng())?,
            expected,
            "{label}: rerandomized bootstrap"
        );
        let child = if reblind_first { reblinded } else { child };
        for side in [Side::Left, Side::Right] {
            let parent = match side {
                Side::Left => {
                    app.fuse(
                        &mut rng,
                        support::UnitLeft::new(),
                        inputs.salt,
                        child.clone(),
                        sibling.clone(),
                    )?
                    .0
                }
                Side::Right => {
                    app.fuse(
                        &mut rng,
                        support::UnitRight::new(),
                        inputs.salt,
                        sibling.clone(),
                        child.clone(),
                    )?
                    .0
                }
            };
            support::assert_copied_endpoints(parent.proof(), child.proof(), side)?;
            assert_eq!(
                app.verify(&parent, inputs.verifier_rng())?,
                expected,
                "{label}: bootstrap parent {side:?}"
            );
            let reblinded = app.rerandomize(parent.clone(), &mut rng)?;
            assert_eq!(
                app.verify(&reblinded, inputs.verifier_rng())?,
                expected,
                "{label}: rerandomized bootstrap parent {side:?}"
            );
            for grandparent_side in [Side::Left, Side::Right] {
                let (left, right) = match grandparent_side {
                    Side::Left => (parent.clone(), sibling.clone()),
                    Side::Right => (sibling.clone(), parent.clone()),
                };
                let grandparent = app
                    .fuse(&mut rng, support::Merge::new(), inputs.salt, left, right)?
                    .0;
                support::assert_copied_endpoints(
                    grandparent.proof(),
                    parent.proof(),
                    grandparent_side,
                )?;
                assert_eq!(
                    app.verify(&grandparent, inputs.verifier_rng())?,
                    expected,
                    "{label}: bootstrap grandparent {grandparent_side:?} / parent {side:?}"
                );
                let reblinded = app.rerandomize(grandparent, &mut rng)?;
                assert_eq!(
                    app.verify(&reblinded, inputs.verifier_rng())?,
                    expected,
                    "{label}: rerandomized bootstrap grandparent {grandparent_side:?} / parent {side:?}"
                );
            }
        }
        Ok(())
    }

    fn check_claims(
        app: &support::App,
        inputs: &support::Inputs,
        native_delta: Fp,
        nested_delta: Fq,
        selector: usize,
        reblind_first: bool,
    ) -> Result<()> {
        let (honest, _, _) = support::fused(app, inputs)?;
        let bootstrap = app.bootstrap_pcd();
        let mut rng = inputs.prover_rng();
        let sibling = support::sibling(app, &honest, &mut rng)?;
        assert!(app.verify(&sibling, inputs.verifier_rng())?);
        let sign = stage_wire_indices::<_, R, challenges::Stage<EqAffine, R>>(|stage| {
            wires_of(&stage.base_case.lift)
        })?[0];
        assert_eq!(
            StageReader::new(&honest.proof().nested_challenges_rx).read(sign),
            -Fq::ONE
        );
        assert_eq!(
            StageReader::new(&bootstrap.proof().nested_challenges_rx).read(sign),
            Fq::ONE
        );
        check_descendants(
            app,
            inputs,
            &honest,
            &sibling,
            true,
            reblind_first,
            "honest",
        )?;
        check_bootstrap(
            app,
            inputs,
            bootstrap.clone(),
            &sibling,
            true,
            reblind_first,
            "honest",
        )?;
        for (label, native, nested) in [
            ("c", Some(native_delta), None),
            ("c_n", None, Some(nested_delta)),
            ("c and c_n", Some(native_delta), Some(nested_delta)),
        ] {
            let proof = changed(app, honest.proof(), native, nested, selector)?;
            check_descendants(
                app,
                inputs,
                &proof.carry::<Value>(*honest.data()),
                &sibling,
                false,
                reblind_first,
                label,
            )?;
            let proof = changed(app, bootstrap.proof(), native, nested, selector)?;
            check_bootstrap(
                app,
                inputs,
                proof.carry::<()>(()),
                &sibling,
                false,
                reblind_first,
                label,
            )?;
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn independent_c_and_c_n_substitutions_reject_with_both_base_case_signs(
            inputs in support::inputs(),
            native_delta in strategies::nonzero_prime_field_element::<Fp>(),
            nested_delta in strategies::nonzero_prime_field_element::<Fq>(),
            selector in any::<usize>(),
            reblind_first in any::<bool>(),
        ) {
            support::with_app(|app| check_claims(app, &inputs, native_delta, nested_delta, selector, reblind_first)).unwrap();
        }
    }
}
