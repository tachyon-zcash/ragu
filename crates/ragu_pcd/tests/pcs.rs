//! Check the production nested PCS batch against independently constructed expectations.
//!
//! Proofs are built by `Application::fuse`. The tests compare the production batch
//! iterators and proof outputs with explicit expected query lists and batching
//! arithmetic, so a shared ordering bug cannot change both sides of an assertion.

use alloc::{format, string::String, vec, vec::Vec};

use proptest::prelude::*;
use ragu_arithmetic::{Cycle, ff::Field};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::Stage,
};
use ragu_core::Result;
use ragu_pasta::{Fp, Fq};
use ragu_primitives::vec::Len;

use crate::{
    Pcd,
    header::Header,
    internal::nested::{self, InternalCircuitIndex, RxIndex, pcs},
    proof::recursive_propagation_tests::support::{self, C, R},
};

type Poly = sparse::Polynomial<Fq, R>;
type Commitment = <C as Cycle>::NestedCurve;
type Query<'a> = (String, &'a Poly, Fq);
type Evaluation<'a> = (String, &'a Poly, Commitment);

fn expected_rx_order() -> Vec<RxIndex> {
    use RxIndex::*;

    (0..nested::NumStepsLen::len())
        .map(|step| EndoscalingStep(step.try_into().unwrap()))
        .chain([
            Export,
            Collapse,
            ComputeV,
            EndoscalarStage,
            PointsStage,
            BridgePreamble,
            BridgeSPrime,
            BridgeInnerError,
            BridgeOuterError,
            BridgeAB,
            BridgeQuery,
            BridgeF,
            BridgeEval,
            ChallengeStage,
        ])
        .collect()
}

fn expected_circuit_order() -> Vec<InternalCircuitIndex> {
    use InternalCircuitIndex::*;

    (0..nested::NumStepsLen::len())
        .map(|step| EndoscalingStep(step.try_into().unwrap()))
        .chain([
            Export,
            Collapse,
            ComputeV,
            EndoscalarStage,
            PointsStage,
            PointsFinalStaged,
            BridgePreamble,
            BridgeSPrime,
            BridgeInnerError,
            BridgeOuterError,
            BridgeAB,
            BridgeQuery,
            BridgeF,
            BridgeEval,
            ChallengeStage,
            ChallengeFinalStaged,
            Loading,
        ])
        .collect()
}

fn check_batch<H: Header<Fp>>(
    app: &support::App,
    parent_pcd: &Pcd<C, R, H>,
    left_pcd: &Pcd<C, R, H>,
    right_pcd: &Pcd<C, R, H>,
    inputs: &support::Inputs,
) -> Result<()> {
    let (parent, left, right) = (parent_pcd.proof(), left_pcd.proof(), right_pcd.proof());
    let ch = pcs::Challenges {
        w: nested::challenge::<C>(parent.w())?,
        x: nested::challenge::<C>(parent.x())?,
        y: nested::challenge::<C>(parent.y())?,
        z: nested::challenge::<C>(parent.z())?,
        left: pcs::ChildChallenges::of(left)?,
        right: pcs::ChildChallenges::of(right)?,
    };
    let alpha = nested::challenge::<C>(parent.alpha())?;
    let beta = nested::challenge::<C>(parent.pre_beta())?;
    let u = nested::challenge::<C>(parent.u())?;
    let xz = ch.x * ch.z;

    let registry = app.nested_registry.at(ch.w);
    let registry_wx0 = ReferenceBackend::registry_at_x(&registry, ch.left.x);
    let registry_wx1 = ReferenceBackend::registry_at_x(&registry, ch.right.x);
    let registry_wy = ReferenceBackend::registry_at_y(&registry, ch.y);
    let registry_xy = ReferenceBackend::registry_xy(&app.nested_registry, ch.x, ch.y);
    assert!(
        registry_xy
            .iter_coeffs()
            .eq(parent.nested_registry_xy_poly().iter_coeffs()),
        "nested registry_xy is not m_n(W, x_n, y_n)"
    );
    let batch = pcs::Batch {
        left,
        right,
        registry_wx0: &registry_wx0,
        registry_wx1: &registry_wx1,
        registry_wy: &registry_wy,
        registry_xy: parent.nested_registry_xy_poly(),
        a: &parent.nested_a_poly,
        b: &parent.nested_b_poly,
    };
    let commit = |poly: &Poly| {
        ReferenceBackend::sparse_commit_to_affine(poly, C::nested_generators(app.params))
    };
    let current = pcs::CurrentCommitments {
        registry_wx0: commit(batch.registry_wx0),
        registry_wx1: commit(batch.registry_wx1),
        registry_wy: commit(batch.registry_wy),
        a: commit(batch.a),
        b: commit(batch.b),
        registry_xy: commit(batch.registry_xy),
    };

    // Name occurrences, not just polynomials: wx0, wx1, wy and xy each
    // occur at several different points, with different alpha weights.
    let mut queries: Vec<Query<'_>> = [
        ("left.p@left.u", left.nested_p_poly(), ch.left.u),
        ("right.p@right.u", right.nested_p_poly(), ch.right.u),
        ("left.xy@w", left.nested_registry_xy_poly(), ch.w),
        ("right.xy@w", right.nested_registry_xy_poly(), ch.w),
        ("wx0@left.y", batch.registry_wx0, ch.left.y),
        ("wx1@right.y", batch.registry_wx1, ch.right.y),
        ("wx0@y", batch.registry_wx0, ch.y),
        ("wx1@y", batch.registry_wx1, ch.y),
        ("wy@left.x", batch.registry_wy, ch.left.x),
        ("wy@right.x", batch.registry_wy, ch.right.x),
        ("wy@x", batch.registry_wy, ch.x),
        ("xy@w", batch.registry_xy, ch.w),
        ("left.a@xz", &left.nested_a_poly, xz),
        ("left.b@x", &left.nested_b_poly, ch.x),
        ("right.a@xz", &right.nested_a_poly, xz),
        ("right.b@x", &right.nested_b_poly, ch.x),
        ("a@xz", batch.a, xz),
        ("b@x", batch.b, ch.x),
    ]
    .into_iter()
    .map(|(tag, poly, point)| (tag.into(), poly, point))
    .collect();

    let rx = expected_rx_order();
    let circuits = expected_circuit_order();
    assert_eq!(rx.len(), RxIndex::NUM);
    assert_eq!(circuits.len(), InternalCircuitIndex::NUM);
    let mut evaluated: Vec<Evaluation<'_>> = Vec::new();
    for (side, child) in [("left", left), ("right", right)] {
        for &id in &rx {
            queries.push((format!("{side}.{id:?}@xz"), &child[id], xz));
            evaluated.push((
                format!("{side}.{id:?}"),
                &child[id],
                child.nested_rx_commitment(id),
            ));
        }
        for (tag, poly, commitment) in [
            ("a", &child.nested_a_poly, child.nested_a_commitment()),
            ("b", &child.nested_b_poly, child.nested_b_commitment()),
            (
                "xy",
                child.nested_registry_xy_poly(),
                child.nested_registry_xy_commitment(),
            ),
            ("p", child.nested_p_poly(), child.nested_p_commitment()),
        ] {
            evaluated.push((format!("{side}.{tag}"), poly, commitment));
        }
    }
    for (index, id) in circuits.into_iter().enumerate() {
        // Derive each expected domain point from its position in the test's
        // circuit list, so a reordered production table cannot relabel it.
        assert_eq!(usize::from(id.circuit_index()), index, "{id:?}");
        queries.push((
            format!("xy@{id:?}"),
            batch.registry_xy,
            CircuitIndex::new(index).omega_j(),
        ));
    }
    for (tag, poly, commitment) in [
        ("wx0", batch.registry_wx0, current.registry_wx0),
        ("wx1", batch.registry_wx1, current.registry_wx1),
        ("wy", batch.registry_wy, current.registry_wy),
        ("a", batch.a, current.a),
        ("b", batch.b, current.b),
        ("xy", batch.registry_xy, current.registry_xy),
    ] {
        evaluated.push((format!("current.{tag}"), poly, commitment));
    }

    let actual_queries: Vec<_> = batch.queries(ch).collect();
    assert_eq!(actual_queries.len(), queries.len());
    for ((poly, point), (tag, expected_poly, expected_point)) in
        actual_queries.into_iter().zip(&queries)
    {
        assert!(
            core::ptr::eq(poly, *expected_poly),
            "query polynomial: {tag}"
        );
        assert_eq!(point, *expected_point, "query point: {tag}");
    }
    let actual_evaluated: Vec<_> = batch.evaluated().collect();
    let actual_commitments: Vec<_> = batch.commitments(current).collect();
    assert_eq!(actual_evaluated.len(), evaluated.len());
    assert_eq!(actual_commitments.len(), evaluated.len());
    assert_eq!(1 + evaluated.len(), pcs::NUM_BATCHED_POINTS);
    for ((poly, commitment), (tag, expected_poly, expected_commitment)) in actual_evaluated
        .into_iter()
        .zip(actual_commitments)
        .zip(&evaluated)
    {
        assert!(
            core::ptr::eq(poly, *expected_poly),
            "evaluated polynomial: {tag}"
        );
        assert_eq!(commitment, *expected_commitment, "commitment: {tag}");
    }

    // Check the production eval bridge's stored wires against direct
    // polynomial evaluations. The first two values hold native_eval.
    let values = stage_values::<nested::stages::eval::Stage<<C as Cycle>::HostCurve, R>>(
        &parent.bridge_eval_rx,
    );
    assert_eq!(values.len(), 2 + evaluated.len());
    for (value, (tag, poly, _)) in values[2..].iter().zip(&evaluated) {
        assert_eq!(*value, poly.eval(u), "eval bridge: {tag}");
    }

    // Compute the expected f by synthetic division of each p(X) - p(point)
    // by X - point, weighted by alpha^(queries.len() - 1 - i).
    // Application::fuse exercises the production quotient-batching helper;
    // reusing it for this expectation would reproduce its bugs here.
    let mut f = vec![Fq::ZERO; R::num_coeffs()];
    let mut weight = Fq::ONE;
    for (_, poly, point) in queries.iter().rev() {
        let coefficients: Vec<_> = poly.iter_coeffs().collect();
        let mut quotient = Fq::ZERO;
        for degree in (1..coefficients.len()).rev() {
            quotient = coefficients[degree] + *point * quotient;
            f[degree - 1] += weight * quotient;
        }
        weight *= alpha;
    }

    // Compute the expected p_n(X) = beta^m f_n(X) + sum_i beta^(m - 1 - i) p_i(X).
    // Compare it with the production proof's coefficients, evaluation, and
    // walked commitment.
    let mut p = vec![Fq::ZERO; R::num_coeffs()];
    let mut weight = Fq::ONE;
    for (_, poly, _) in evaluated.iter().rev() {
        for (coefficient, value) in p.iter_mut().zip(poly.iter_coeffs()) {
            *coefficient += weight * value;
        }
        weight *= beta;
    }
    for (coefficient, value) in p.iter_mut().zip(f) {
        *coefficient += weight * value;
    }
    let expected_p = Poly::from_coeffs(p);
    assert!(
        expected_p
            .iter_coeffs()
            .eq(parent.nested_p_poly().iter_coeffs()),
        "nested p differs from the expected PCS batch polynomial"
    );
    assert_eq!(expected_p.eval(u), parent.nested_v()?);
    assert_eq!(commit(&expected_p), parent.nested_p_commitment());
    assert!(app.verify(parent_pcd, inputs.verifier_rng())?);

    Ok(())
}

fn check_dummy(app: &support::App) {
    let proof = app.dummy_proof();

    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(
            proof.nested_p_poly(),
            C::nested_generators(app.params),
        ),
        proof.nested_p_commitment(),
        "a dummy child's nested batch polynomial must match its walked commitment"
    );
}

/// Read the production stage's stored values directly from its polynomial.
/// Stage values occupy successive a/d wires after the ancestor stages; the
/// random blinding is at the system gate.
fn stage_values<S: Stage<Fq, R>>(rx: &sparse::Polynomial<Fq, R>) -> Vec<Fq> {
    let coefficients: Vec<_> = rx.iter_coeffs().collect();
    (0..S::values())
        .map(|i| {
            let gate = S::skip_gates() + i / 2;
            let degree = if i % 2 == 0 {
                2 * R::n() - 1 - gate
            } else {
                4 * R::n() - 1 - gate
            };
            coefficients[degree]
        })
        .collect()
}

mod folding {
    //! Check the production nested accumulator and bridge payloads against child claims.
    //!
    //! Reuse the production claim and folding helpers, then compare their results
    //! with the accumulator and bridge polynomials stored by `Application::fuse`.
    //! The parent's fold uses copied child instances to bind the children's claims.

    use alloc::vec::Vec;

    use ragu_arithmetic::{Cycle, ff::Field};
    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::polynomials::sparse;
    use ragu_core::{Result, maybe::Maybe};
    use ragu_pasta::Fq;
    use ragu_primitives::{Element, vec::FixedVec};
    use support::{C, R};

    use super::{
        super::{NestedFuseEmulator, claims::NestedFuseProofSource},
        stage_values, support,
    };
    use crate::{
        Proof,
        internal::{
            claims,
            fold_revdot::{self, ClaimFolder},
            nested::{self, claims::KySource},
        },
    };

    type P = nested::RevdotParameters;

    /// The two children's `k(y)` values as plain scalars.
    struct ChildValues {
        left_c: Fq,
        right_c: Fq,
        left_unified: Fq,
        right_unified: Fq,
    }

    impl KySource for ChildValues {
        type Ky = Fq;

        fn raw_c(&self) -> impl Iterator<Item = Fq> {
            [self.left_c, self.right_c].into_iter()
        }

        fn ones(&self) -> impl Iterator<Item = Fq> + Clone {
            [Fq::ONE, Fq::ONE].into_iter()
        }

        fn unified_ky(&self) -> impl Iterator<Item = Fq> + Clone {
            [self.left_unified, self.right_unified].into_iter()
        }

        fn zero(&self) -> Fq {
            Fq::ZERO
        }
    }

    pub(super) fn check(
        app: &support::App,
        parent: &Proof<C, R>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<()> {
        let nested_source = NestedFuseProofSource { left, right };

        let y = nested::challenge::<C>(parent.y())?;
        let z = nested::challenge::<C>(parent.z())?;
        let mu = nested::challenge::<C>(parent.mu())?;
        let nu = nested::challenge::<C>(parent.nu())?;
        let mu_prime = nested::challenge::<C>(parent.mu_prime())?;
        let nu_prime = nested::challenge::<C>(parent.nu_prime())?;

        let mut nested_claims =
            claims::Builder::<_, Fq, R, ReferenceBackend>::new(&app.nested_registry, y, z);
        nested::claims::build(&nested_source, &mut nested_claims)?;
        let unified_ky = |proof: &Proof<C, R>| -> Result<Fq> {
            NestedFuseEmulator::<C>::emulate_wireless(
                (proof.nested_instance()?, y),
                |dr, witness| {
                    let (instance, y) = witness.cast();
                    let y = Element::alloc(dr, &mut (), y)?;
                    let output = nested::unified::Output::<_, ragu_pasta::EqAffine>::alloc(
                        dr,
                        &mut (),
                        instance.as_ref(),
                    )?;
                    Ok(*output.ky(dr, &y)?.value().take())
                },
            )
        };
        let children = ChildValues {
            left_c: left.nested_c(),
            right_c: right.nested_c(),
            left_unified: unified_ky(left)?,
            right_unified: unified_ky(right)?,
        };

        // Two raw claims, one circuit claim per endoscaling step and per
        // instance circuit per child, and one bonding claim per bonding kind
        // folded across both children.
        let steps = crate::internal::endoscalar::num_steps::<{ nested::ENDOSCALINGS_PER_STEP }>(
            nested::NUM_ENDOSCALING_POINTS,
        );
        let circuits = steps + nested::NUM_INSTANCE_CIRCUITS;
        let bonding_kinds = nested::InternalCircuitIndex::NUM - circuits;
        assert_eq!(nested_claims.a.len(), 2 + 2 * circuits + bonding_kinds);

        // 1. Every nested claim of the children holds at the derived challenges.
        for (i, (ky, (a, b))) in nested::claims::ky_values(&children)
            .zip(nested_claims.a.iter().zip(nested_claims.b.iter()))
            .enumerate()
        {
            assert_eq!(a.revdot(b), ky, "nested claim {i} does not hold");
        }

        // 2. The accumulator is the two-layer fold of those claims.
        let inner_errors =
            fold_revdot::inner_error_terms::<_, R, P>(&nested_claims.a, &nested_claims.b);
        let a_folded = fold_revdot::fold_inner::<sparse::Polynomial<Fq, R>, _, P>(
            &nested_claims.a,
            mu.invert().unwrap(),
        );
        let b_folded =
            fold_revdot::fold_inner::<sparse::Polynomial<Fq, R>, _, P>(&nested_claims.b, mu * nu);
        let outer_errors = fold_revdot::outer_error_terms::<_, R, P>(&a_folded, &b_folded);
        let collapsed: Vec<_> = a_folded
            .iter()
            .zip(b_folded.iter())
            .map(|(a, b)| a.revdot(b))
            .collect();

        // Check the bridge payloads as well as the fold arithmetic. Reading the
        // stored coefficients catches omitted, reordered or corrupted witness
        // fields even when the accumulator itself is computed correctly.
        assert!(
            inner_errors
                .iter()
                .flat_map(|group| group.iter())
                .any(|v| *v != Fq::ZERO),
            "the fixture must exercise nonzero inner errors"
        );
        assert!(
            outer_errors.iter().any(|v| *v != Fq::ZERO),
            "the fixture must exercise nonzero outer errors"
        );
        assert!(
            collapsed.iter().any(|v| *v != Fq::ZERO),
            "the fixture must exercise nonzero collapsed values"
        );

        // The inner stage starts with two curve points (four coordinates),
        // followed by the error terms in group-major order.
        let inner_values = stage_values::<
            nested::stages::inner_error::Stage<<C as Cycle>::HostCurve, R>,
        >(&parent.bridge_inner_error_rx);
        assert!(
            inner_values[4..]
                .iter()
                .eq(inner_errors.iter().flat_map(|group| group.iter())),
            "the inner bridge does not store the fold's error terms"
        );

        // The outer stage starts with one curve point, followed by the outer
        // error terms and then one collapsed value per group.
        let outer_values = stage_values::<
            nested::stages::outer_error::Stage<<C as Cycle>::HostCurve, R>,
        >(&parent.bridge_outer_error_rx);
        let (stored_outer_errors, stored_collapsed) =
            outer_values[2..].split_at(outer_errors.len());
        assert_eq!(
            stored_outer_errors,
            &outer_errors[..],
            "the outer bridge does not store the fold's error terms"
        );
        assert_eq!(
            stored_collapsed,
            collapsed.as_slice(),
            "the outer bridge does not store the first layer's revdot values"
        );

        for (name, rx, commitment) in [
            (
                "inner",
                parent.bridge_inner_error_rx.as_ref(),
                parent.bridge_inner_error_commitment,
            ),
            (
                "outer",
                parent.bridge_outer_error_rx.as_ref(),
                parent.bridge_outer_error_commitment,
            ),
        ] {
            assert_eq!(
                ReferenceBackend::sparse_commit_to_affine(rx, C::nested_generators(app.params)),
                commitment,
                "the {name} bridge commitment does not match its stored polynomial"
            );
        }

        let a_final = fold_revdot::fold_outer::<_, _, P>(a_folded, mu_prime.invert().unwrap());
        let b_final = fold_revdot::fold_outer::<_, _, P>(b_folded, mu_prime * nu_prime);
        assert!(
            a_final.iter_coeffs().eq(parent.nested_a_poly.iter_coeffs()),
            "nested a is not the fold of the children's claims"
        );
        assert!(
            b_final.iter_coeffs().eq(parent.nested_b_poly.iter_coeffs()),
            "nested b is not the fold of the children's claims"
        );

        // 3. Its revdot value is what a nested collapse circuit computes from the
        //    error terms and the children's values, layer by layer.
        let expected_c = NestedFuseEmulator::<C>::emulate_wireless(
            (
                (&inner_errors, &outer_errors),
                (mu, nu),
                (mu_prime, nu_prime),
                (
                    (children.left_c, children.right_c),
                    (children.left_unified, children.right_unified),
                ),
            ),
            |dr, witness| {
                let (errors, layer1, layer2, kys) = witness.cast();
                let (inner_errors, outer_errors) = errors.cast();
                let (mu, nu) = layer1.cast();
                let (mu_prime, nu_prime) = layer2.cast();
                let (cs, unifieds) = kys.cast();
                let (left_c, right_c) = cs.cast();
                let (left_unified, right_unified) = unifieds.cast();
                let allocator = &mut ();

                let mu = Element::alloc(dr, allocator, mu)?;
                let nu = Element::alloc(dr, allocator, nu)?;
                let mu_prime = Element::alloc(dr, allocator, mu_prime)?;
                let nu_prime = Element::alloc(dr, allocator, nu_prime)?;
                let left_c = Element::alloc(dr, allocator, left_c)?;
                let right_c = Element::alloc(dr, allocator, right_c)?;

                let left_unified = Element::alloc(dr, allocator, left_unified)?;
                let right_unified = Element::alloc(dr, allocator, right_unified)?;
                let ky_source = nested::claims::TwoProofKySource::new(
                    dr,
                    left_c,
                    right_c,
                    left_unified,
                    right_unified,
                );
                let mut ky = nested::claims::ky_values(&ky_source);

                let layer1 = ClaimFolder::new(dr, &mu, &nu)?;
                let collapsed = FixedVec::try_from_fn(|i| {
                    let errors = FixedVec::try_from_fn(|j| {
                        Element::alloc(dr, allocator, inner_errors.as_ref().map(|et| et[i][j]))
                    })?;
                    let ky = FixedVec::from_fn(|_| ky.next().unwrap());
                    layer1.fold_inner::<P>(dr, &errors, &ky)
                })?;

                let outer_errors = FixedVec::try_from_fn(|i| {
                    Element::alloc(dr, allocator, outer_errors.as_ref().map(|et| et[i]))
                })?;
                let layer2 = ClaimFolder::new(dr, &mu_prime, &nu_prime)?;
                let c = layer2.fold_outer::<P>(dr, &outer_errors, &collapsed)?;
                Ok(*c.value().take())
            },
        )?;
        assert_eq!(
            parent.nested_c(),
            expected_c,
            "nested c is not the collapse of the children's claims"
        );

        Ok(())
    }
}

proptest! {
    #![proptest_config(support::config())]

    #[test]
    fn nested_batch_opens_what_it_claims(inputs in support::inputs()) {
        support::with_app(|app| {
            let (parent, left, right) = support::fused(app, &inputs)?;
            check_batch(app, &parent, &left, &right, &inputs)?;
            folding::check(app, parent.proof(), left.proof(), right.proof())?;
            let (parent, left, right) = support::unit_fused(app, &inputs)?;
            check_batch(app, &parent, &left, &right, &inputs)?;
            folding::check(app, parent.proof(), left.proof(), right.proof())?;
            check_dummy(app);
            Ok::<_, ragu_core::Error>(())
        }).unwrap();
    }
}

mod denominators {
    //! Exercise the PCD quotient denominator constraints on both Pasta fields.
    //!
    //! These are checking-driver tests at the inversion gadget boundary. They do
    //! not force the production Fiat-Shamir transcript to emit chosen challenges.

    use alloc::vec::Vec;

    use proptest::prelude::*;
    use ragu_arithmetic::ff::PrimeField;
    use ragu_circuits::registry::CircuitIndex;
    use ragu_core::{Error, Result, drivers::Driver, maybe::Maybe};
    use ragu_pasta::{Fp, Fq};
    use ragu_primitives::{Element, Simulator, allocator::Standard};
    use ragu_testing::strategies;

    use crate::internal::inverter::Inverter;

    #[derive(Clone, Copy)]
    enum Zero {
        Variable(usize),
        Constant(usize),
    }

    fn batch<F: PrimeField>(
        base: F,
        differences: &[F],
        circuit: CircuitIndex,
        zero: Option<Zero>,
    ) -> Result<()> {
        Simulator::<F>::simulate(base, |dr, witness| {
            let allocator = &mut Standard::new();
            let base_element = Element::alloc(dr, allocator, witness)?;
            let mut inverter = Inverter::with_base(base_element);
            let mut expected = Vec::new();
            for (i, &difference) in differences.iter().enumerate() {
                let value = match zero {
                    Some(Zero::Variable(position) | Zero::Constant(position)) if position == i => {
                        base
                    }
                    _ => base - difference,
                };
                let constant = match zero {
                    Some(Zero::Variable(position)) if position == i => false,
                    Some(Zero::Constant(position)) if position == i => true,
                    _ => i.is_multiple_of(2),
                };
                let index = if constant {
                    inverter.add_constant(dr, value)?
                } else {
                    let value = Element::alloc(dr, allocator, Simulator::<F>::just(|| value))?;
                    inverter.add(dr, &value)?
                };
                assert_eq!(index, expected.len());
                expected.push(base - value);
            }
            let index = inverter.add_circuit(dr, circuit)?;
            assert_eq!(index, expected.len());
            expected.push(base - circuit.omega_j::<F>());
            let inverses = inverter.invert(dr)?;
            assert_eq!(inverses.len(), expected.len());
            for (inverse, difference) in inverses.iter().zip(expected) {
                assert_eq!(**inverse.value().snag() * difference, F::ONE);
            }
            Ok(())
        })?;
        Ok(())
    }

    fn check<F: PrimeField>(
        differences: &[F],
        circuit: CircuitIndex,
        position: usize,
    ) -> Result<()> {
        assert!(!differences.is_empty());
        assert!(differences.iter().all(|difference| *difference != F::ZERO));
        Simulator::<F>::simulate(F::ZERO, |dr, witness| {
            let base = Element::alloc(dr, &mut Standard::new(), witness)?;
            assert!(Inverter::with_base(base).invert(dr)?.is_empty());
            Ok(())
        })?;

        let position = position % differences.len();
        let omega = circuit.omega_j::<F>();
        // Zero is a valid base when no denominator vanishes. The second base
        // gives the registry denominator a generated nonzero difference.
        for base in [F::ZERO, omega + differences[0]] {
            batch(base, differences, circuit, None)?;
            for zero in [Zero::Variable(position), Zero::Constant(position)] {
                assert!(matches!(
                    batch(base, differences, circuit, Some(zero)),
                    Err(Error::InvalidWitness(_))
                ));
            }
        }
        // All variable/constant differences remain nonzero; only u - omega_j
        // vanishes. The batch inversion's zero advice must still be constrained.
        assert!(matches!(
            batch(omega, differences, circuit, None),
            Err(Error::InvalidWitness(_))
        ));
        Ok(())
    }

    proptest! {
        #[test]
        fn quotient_inversion_rejects_each_kind_of_zero_denominator(
            native in proptest::collection::vec(strategies::nonzero_prime_field_element::<Fp>(), 1..=32),
            nested in proptest::collection::vec(strategies::nonzero_prime_field_element::<Fq>(), 1..=32),
            circuit in 0u32..=u16::MAX.into(),
            position in any::<usize>(),
        ) {
            let circuit = CircuitIndex::from_u32(circuit);
            check(&native, circuit, position).unwrap();
            check(&nested, circuit, position).unwrap();
        }
    }
}

mod child_openings {
    //! The folded child PCS claims of a terminal proof are bound.
    //!
    //! A root's native `compute_v` reads each child's claimed opening
    //! $p_c(u_c) = v_c$ off the preamble stage and $p_c(u)$ off the eval
    //! stage, and the decider never reads those wires directly. They are
    //! bound all the same: the eval stage is committed before $\beta$ is
    //! squeezed and $P$ is the walk over the constituent commitments, so
    //! opening the root's $p$ pins every eval wire to the real evaluation of
    //! its committed polynomial, the children's included.
    //!
    //! Each edit here repairs every cache it invalidates, so a rejection
    //! comes from the binding rather than from a stale commitment: editing
    //! any of the four wires is rejected, and editing an eval wire is still
    //! rejected once the eval bridge slot is repaired too. A child that never
    //! ran, presented as an application child, is the forgery those wires
    //! would have to cover; the honest pipeline sets them for it and the root
    //! is still rejected.

    use proptest::prelude::*;
    use ragu_core::Result;
    use ragu_pasta::Fp;
    use ragu_testing::strategies;
    use rand::{SeedableRng, rngs::StdRng};

    use super::support::{self, C, ChildWire, R, Value, dummy_as_value, repair_bridge_eval_slot};
    use crate::Proof;

    fn check(app: &support::App, inputs: &support::Inputs, delta: Fp) -> Result<()> {
        let (parent, _, right) = support::fused(app, inputs)?;
        assert!(
            app.verify(&parent, inputs.verifier_rng())?,
            "the honest root verifies"
        );
        let data = *parent.data();
        let rejected = |proof: Proof<C, R>| -> Result<bool> {
            Ok(!app.verify(&proof.carry::<Value>(data), inputs.verifier_rng())?)
        };

        for wire in ChildWire::ALL {
            let mut proof = parent.proof().clone();
            wire.bump(app, &mut proof, delta, true)?;
            assert!(
                rejected(proof)?,
                "{wire:?}: an edited child opening wire must be rejected"
            );
        }

        let mut proof = parent.proof().clone();
        ChildWire::EvalLeftP.bump(app, &mut proof, delta, true)?;
        repair_bridge_eval_slot(app, &mut proof)?;
        assert!(
            rejected(proof)?,
            "the eval stage is transcript-bound before beta"
        );

        let mut rng = StdRng::seed_from_u64(inputs.proof_seed.wrapping_add(2));
        let root = app
            .fuse(
                &mut rng,
                support::Merge::new(),
                inputs.salt,
                dummy_as_value(app),
                right,
            )?
            .0;
        assert!(
            !app.verify(&root, inputs.verifier_rng())?,
            "a child that never ran must be rejected"
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(support::config())]

        #[test]
        fn edited_child_openings_reject(
            inputs in support::inputs(),
            delta in strategies::nonzero_prime_field_element::<Fp>(),
        ) {
            support::with_app(|app| check(app, &inputs, delta)).unwrap();
        }
    }
}
