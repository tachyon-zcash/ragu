//! The nested fold and batch, checked against the children they cover.
//!
//! Nothing in-circuit verifies the nested side yet, and the decider's raw
//! nested claim is tautological, so this is where the prover-side work is
//! held to its definition: the children's nested claims all hold at the
//! derived nested challenges, the accumulator is their two-layer fold, its
//! revdot value is what a nested collapse circuit would compute from the
//! committed error terms and the children's `c` values, and the nested batch
//! evaluation $v_n$ is what a nested `compute_v` circuit would compute from
//! the openings the batch claims.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    staging::Stage,
};
use ragu_core::{Result, maybe::Maybe};
use ragu_pasta::{Fq, Pasta};
use ragu_primitives::{Element, vec::FixedVec};
use rand::{SeedableRng, rngs::StdRng};

use super::{NestedFuseEmulator, claims::NestedFuseProofSource};
use crate::{
    Application, ApplicationBuilder, Proof,
    internal::{
        claims,
        fold_revdot::{self, ClaimFolder},
        nested::{self, claims::KySource, pcs},
    },
    step::internal::trivial::Trivial,
};

type C = Pasta;
type R = ProductionRank;
const HEADER_SIZE: usize = 4;
type P = nested::RevdotParameters;

/// An application with no steps of its own: the internal `Trivial` step is
/// enough to seed and fuse, and this test is not about application data.
fn app() -> Application<'static, C, R, HEADER_SIZE> {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("the application must build")
}

/// A fuse of two seeded leaves, returned as `(parent, left, right)`.
///
/// A seed is itself a fuse of two trivial proofs, so the leaves carry
/// nondegenerate nested accumulators of their own, and the parent folds
/// real error terms.
fn fused(app: &Application<'_, C, R, HEADER_SIZE>) -> (Proof<C, R>, Proof<C, R>, Proof<C, R>) {
    let mut rng = StdRng::seed_from_u64(0xf01d);

    let mut leaf = || {
        app.seed(&mut rng, Trivial::new(), ())
            .expect("seeding must succeed")
            .0
    };
    let (left, right) = (leaf(), leaf());
    let (left_proof, right_proof) = (left.proof().clone(), right.proof().clone());

    let parent = app
        .fuse(&mut rng, Trivial::new(), (), left, right)
        .expect("fusing two leaves must succeed")
        .0
        .into_parts()
        .0;

    (parent, left_proof, right_proof)
}

/// Reads the values actually stored in a stage's polynomial, independently
/// of the witness constructor. Stage values occupy successive a/d wires
/// after the ancestor stages; the random blinding is at the system gate.
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

/// The two children's `k(y)` values as plain scalars.
struct ChildValues {
    left_c: Fq,
    right_c: Fq,
}

impl KySource for ChildValues {
    type Ky = Fq;

    fn raw_c(&self) -> impl Iterator<Item = Fq> {
        [self.left_c, self.right_c].into_iter()
    }

    fn ones(&self) -> impl Iterator<Item = Fq> + Clone {
        [Fq::ONE, Fq::ONE].into_iter()
    }

    fn zero(&self) -> Fq {
        Fq::ZERO
    }
}

#[test]
fn nested_accumulator_is_the_fold_of_the_children() -> Result<()> {
    let app = app();
    let (parent, left, right) = fused(&app);
    let nested_source = NestedFuseProofSource {
        left: &left,
        right: &right,
    };

    let y = nested::challenge::<C>(parent.y())?;
    let z = nested::challenge::<C>(parent.z())?;
    let mu = nested::challenge::<C>(parent.mu())?;
    let nu = nested::challenge::<C>(parent.nu())?;
    let mu_prime = nested::challenge::<C>(parent.mu_prime())?;
    let nu_prime = nested::challenge::<C>(parent.nu_prime())?;

    let mut nested_claims =
        claims::Builder::<_, Fq, R, ReferenceBackend>::new(&app.nested_registry, y, z);
    nested::claims::build(&nested_source, &mut nested_claims)?;
    let children = ChildValues {
        left_c: left.nested_c(),
        right_c: right.nested_c(),
    };

    // Two raw claims, one circuit claim per endoscaling step per child, and
    // one bonding claim per bonding kind folded across both children.
    let steps = crate::internal::endoscalar::num_steps(nested::NUM_ENDOSCALING_POINTS);
    let bonding_kinds = nested::InternalCircuitIndex::NUM - steps;
    assert_eq!(nested_claims.a.len(), 2 + 2 * steps + bonding_kinds);

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
    let inner_values = stage_values::<nested::stages::inner_error::Stage<<C as Cycle>::HostCurve, R>>(
        &parent.bridge_inner_error_rx,
    );
    assert!(
        inner_values[4..]
            .iter()
            .eq(inner_errors.iter().flat_map(|group| group.iter())),
        "the inner bridge does not store the fold's error terms"
    );

    // The outer stage starts with one curve point, followed by the outer
    // error terms and then one collapsed value per group.
    let outer_values = stage_values::<nested::stages::outer_error::Stage<<C as Cycle>::HostCurve, R>>(
        &parent.bridge_outer_error_rx,
    );
    let (stored_outer_errors, stored_collapsed) = outer_values[2..].split_at(outer_errors.len());
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
            (children.left_c, children.right_c),
        ),
        |dr, witness| {
            let (errors, layer1, layer2, cs) = witness.cast();
            let (inner_errors, outer_errors) = errors.cast();
            let (mu, nu) = layer1.cast();
            let (mu_prime, nu_prime) = layer2.cast();
            let (left_c, right_c) = cs.cast();
            let allocator = &mut ();

            let mu = Element::alloc(dr, allocator, mu)?;
            let nu = Element::alloc(dr, allocator, nu)?;
            let mu_prime = Element::alloc(dr, allocator, mu_prime)?;
            let nu_prime = Element::alloc(dr, allocator, nu_prime)?;
            let left_c = Element::alloc(dr, allocator, left_c)?;
            let right_c = Element::alloc(dr, allocator, right_c)?;

            let ky_source = nested::claims::TwoProofKySource::new(dr, left_c, right_c);
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

#[test]
fn nested_batch_opens_what_it_claims() -> Result<()> {
    let app = app();
    let (parent, left, right) = fused(&app);

    let challenges = pcs::Challenges {
        w: nested::challenge::<C>(parent.w())?,
        x: nested::challenge::<C>(parent.x())?,
        y: nested::challenge::<C>(parent.y())?,
        z: nested::challenge::<C>(parent.z())?,
        left: pcs::ChildChallenges::of(&left)?,
        right: pcs::ChildChallenges::of(&right)?,
    };
    let alpha = nested::challenge::<C>(parent.alpha())?;
    let u = nested::challenge::<C>(parent.u())?;
    let beta = nested::challenge::<C>(parent.pre_beta())?;

    // The registry restrictions the step committed, recomputed from the
    // registry at the derived challenges.
    let registry = app.nested_registry.at(challenges.w);
    let registry_wx0 = ReferenceBackend::registry_at_x(&registry, challenges.left.x);
    let registry_wx1 = ReferenceBackend::registry_at_x(&registry, challenges.right.x);
    let registry_wy = ReferenceBackend::registry_at_y(&registry, challenges.y);
    let registry_xy =
        ReferenceBackend::registry_xy(&app.nested_registry, challenges.x, challenges.y);

    // 1. The stored restriction is the registry's.
    assert!(
        registry_xy
            .iter_coeffs()
            .eq(parent.nested_registry_xy_poly().iter_coeffs()),
        "nested registry_xy is not m_n(W, x_n, y_n)"
    );

    let batch = pcs::Batch {
        left: &left,
        right: &right,
        registry_wx0: &registry_wx0,
        registry_wx1: &registry_wx1,
        registry_wy: &registry_wy,
        registry_xy: parent.nested_registry_xy_poly(),
        a: &parent.nested_a_poly,
        b: &parent.nested_b_poly,
    };

    // 2. f_n(u_n) from the quotients' definition: each opening contributes
    //    (p(u) - p(point)) / (u - point), batched by alpha with the first
    //    query weighted highest.
    let mut f_at_u = Fq::ZERO;
    for (poly, point) in batch.queries(challenges) {
        let quotient = (poly.eval(u) - poly.eval(point)) * (u - point).invert().unwrap();
        f_at_u = f_at_u * alpha + quotient;
    }

    // 3. v_n is the beta-weighted sum of f_n(u_n) and the batch's evaluations
    //    at u_n, in the order the batch fixes, over exactly the points P_n
    //    folds.
    let mut v = f_at_u;
    let mut folded = 1;
    for poly in batch.evaluated() {
        v = v * beta + poly.eval(u);
        folded += 1;
    }
    assert_eq!(folded, pcs::NUM_BATCHED_POINTS);
    assert_eq!(
        parent.nested_v()?,
        v,
        "nested v is not the batch's evaluation"
    );

    Ok(())
}

#[test]
fn nested_challenge_stages_are_bound_by_their_commitments() -> Result<()> {
    use ragu_arithmetic::{
        Cycle, FixedGenerators,
        group::{Curve, Group},
    };
    use ragu_circuits::staging::StageExt;

    use crate::internal::native::{
        circuits::{
            bind_beta,
            bind_challenges::{NUM_BINDERS, NUM_BOUND},
        },
        stages::eval::{BindingPartials, generator_index},
    };

    let app = app();
    let (parent, _, _) = fused(&app);
    let pasta = Pasta::baked();

    // 1. The stored stages are the unblinded stages of the lifts.
    let lifts = parent.challenges().lifts::<C>()?;
    let (challenge_lifts, beta_lift) = lifts.split_at(NUM_BOUND);
    let expected = nested::stages::challenges::Stage::<ragu_pasta::EqAffine, R>::rx(
        Fq::ZERO,
        &nested::stages::challenges::Witness::new(challenge_lifts.try_into().unwrap()),
    )?;
    assert!(
        parent
            .nested_challenges_rx()
            .iter_coeffs()
            .eq(expected.iter_coeffs()),
        "nested challenge stage is not the stage of the lifts"
    );
    let expected = nested::stages::beta::Stage::<ragu_pasta::EqAffine, R>::rx(
        Fq::ZERO,
        nested::stages::beta::Witness { lift: beta_lift[0] },
    )?;
    assert!(
        parent
            .nested_beta_rx()
            .iter_coeffs()
            .eq(expected.iter_coeffs()),
        "nested beta stage is not the stage of the lift"
    );

    // 2. Their commitments are the fixed generator combinations the binding
    //    circuits recompute, term by term.
    let generators = Pasta::nested_generators(pasta);
    let mut acc = ragu_pasta::Ep::identity();
    for (i, lift) in challenge_lifts.iter().enumerate() {
        acc += generators.g()[generator_index::<C, R>(i)] * *lift;
    }
    assert_eq!(
        parent.nested_challenges_commitment(),
        acc.to_affine(),
        "challenge commitment is not the generator combination of the lifts"
    );
    assert_eq!(
        parent.nested_beta_commitment(),
        (generators.g()[bind_beta::generator_index::<C, R>()] * beta_lift[0]).to_affine(),
        "beta commitment is not the generator times the lift"
    );

    // 3. The eval stage's partials are the running sums the binders check;
    //    the last is the challenge commitment.
    let partials = BindingPartials::compute::<C, R, ReferenceBackend>(pasta, challenge_lifts);
    let mut acc = ragu_pasta::Ep::identity();
    for k in 0..NUM_BINDERS {
        for (i, lift) in challenge_lifts
            .iter()
            .enumerate()
            .take(2 * (k + 1))
            .skip(2 * k)
        {
            acc += generators.g()[generator_index::<C, R>(i)] * *lift;
        }
        assert_eq!(partials.partials[k], acc.to_affine(), "partial {k}");
    }
    assert_eq!(
        parent.nested_challenges_commitment(),
        partials.partials[NUM_BINDERS - 1]
    );

    Ok(())
}
