//! The nested fold and batch, checked against the children they cover.
//!
//! The prover-side work is held to its definition independently of the
//! circuits that mirror it: the children's nested claims all hold at the
//! derived nested challenges, the accumulator is their two-layer fold, its
//! revdot value is what the nested collapse circuit computes from the
//! committed error terms and the children's `c` values, and the nested batch
//! evaluation $v_n$ is what the nested `compute_v` circuit computes from
//! the openings the batch claims.
//!
//! The export circuit relates a proof's own instance to its stages. Recursive
//! binding is enforced by the parent's nested fold, whose expected export
//! claim values are computed from its copies of the children's instances.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    staging::Stage,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Fq, Pasta};
use ragu_primitives::{Element, allocator::Standard, vec::FixedVec};
use rand::{SeedableRng, rngs::StdRng};

use super::{NestedFuseEmulator, claims::NestedFuseProofSource};
use crate::{
    Application, ApplicationBuilder, Proof,
    internal::{
        claims,
        fold_revdot::{self, ClaimFolder},
        nested::{self, claims::KySource, pcs},
    },
    step::{Encoded, Index, Step},
};

type C = Pasta;
type R = ProductionRank;
const HEADER_SIZE: usize = 4;
type P = nested::RevdotParameters;

pub(super) use super::test_steps;

#[path = "batch_fingerprint_tests.rs"]
mod batch_fingerprint_tests;

#[path = "native_batch_fingerprint_tests.rs"]
mod native_batch_fingerprint_tests;

#[path = "quotient_transfer_tests.rs"]
mod quotient_transfer_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "expanded_witness_tests.rs"]
mod expanded_witness_tests;

#[path = "adaptive_transcript_tests.rs"]
mod adaptive_transcript_tests;

#[path = "sign_binding_tests.rs"]
mod sign_binding_tests;

#[path = "transcript_tests.rs"]
pub(super) mod transcript_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "substitution_tests.rs"]
mod substitution_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "recursive_binding_tests.rs"]
mod recursive_binding_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "routing_asymmetry_tests.rs"]
mod routing_asymmetry_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "oracle_scope_tests.rs"]
mod oracle_scope_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "support_transfer_tests.rs"]
mod support_transfer_tests;

#[cfg(feature = "unstable-fuzzing")]
#[path = "context_splicing_tests.rs"]
mod context_splicing_tests;

/// A seed step with no predicate that outputs `()`, replacing the internal
/// `Trivial` step these tests used before the base case was confined to
/// `Dummy`-headed children.
struct UnitSeed;

impl Step<C> for UnitSeed {
    const INDEX: Index = Index::new(0);

    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
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
struct UnitFuse;

impl Step<C> for UnitFuse {
    const INDEX: Index = Index::new(1);

    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
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

/// An application whose only steps are unit seed/fuse: enough to seed and
/// fuse, and this test is not about application data.
fn app() -> Application<'static, C, R, HEADER_SIZE> {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(UnitSeed)
        .expect("UnitSeed must register")
        .register(UnitFuse)
        .expect("UnitFuse must register")
        .finalize(Pasta::baked())
        .expect("the application must build")
}

/// A fuse of two seeded leaves, returned as `(parent, left, right)`.
///
/// A seed is itself a fuse of two bootstrap proofs, so the leaves carry
/// nondegenerate nested accumulators of their own, and the parent folds
/// real error terms.
fn fused(app: &Application<'_, C, R, HEADER_SIZE>) -> (Proof<C, R>, Proof<C, R>, Proof<C, R>) {
    let mut rng = StdRng::seed_from_u64(0xf01d);

    let mut leaf = || {
        app.seed(&mut rng, UnitSeed, ())
            .expect("seeding must succeed")
            .0
    };
    let (left, right) = (leaf(), leaf());
    let (left_proof, right_proof) = (left.proof().clone(), right.proof().clone());

    let parent = app
        .fuse(&mut rng, UnitFuse, (), left, right)
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

#[test]
fn nested_accumulator_is_the_fold_of_the_children() -> Result<()> {
    let app = app();
    let (parent, left, right) = fused(&app);
    check_nested_accumulator(&app, &parent, &left, &right)
}

fn check_nested_accumulator(
    app: &Application<'_, C, R, HEADER_SIZE>,
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
        NestedFuseEmulator::<C>::emulate_wireless((proof.nested_instance()?, y), |dr, witness| {
            let (instance, y) = witness.cast();
            let y = Element::alloc(dr, &mut (), y)?;
            let output = nested::unified::Output::<_, ragu_pasta::EqAffine>::alloc(
                dr,
                &mut (),
                instance.as_ref(),
            )?;
            Ok(*output.ky(dr, &y)?.value().take())
        })
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

#[test]
fn trivial_nested_batch_commitment_matches_polynomial() {
    let app = app();
    let proof = app.dummy_proof();

    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(
            proof.nested_p_poly(),
            C::nested_generators(app.params),
        ),
        proof.nested_p_commitment(),
        "a trivial child's nested batch polynomial must match its walked commitment"
    );
}

#[test]
fn nested_batch_opens_what_it_claims() -> Result<()> {
    let app = app();
    let (parent, left, right) = fused(&app);
    check_nested_batch(&app, &parent, &left, &right)
}

fn check_nested_batch(
    app: &Application<'_, C, R, HEADER_SIZE>,
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<()> {
    let challenges = pcs::Challenges {
        w: nested::challenge::<C>(parent.w())?,
        x: nested::challenge::<C>(parent.x())?,
        y: nested::challenge::<C>(parent.y())?,
        z: nested::challenge::<C>(parent.z())?,
        left: pcs::ChildChallenges::of(left)?,
        right: pcs::ChildChallenges::of(right)?,
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
        left,
        right,
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

/// Review's nondegenerate-fixture gap: seeded Trivial proofs have real
/// accumulators but still take the base-case branch. Distinct application
/// headers exercise normal recursion, including an asymmetric grandparent.
#[test]
fn nontrivial_parent_and_grandparent_fold_and_batch_match_their_children() -> Result<()> {
    use test_steps::{Add, Leaf};

    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x0f01_d873);
    let mut left = app.seed(&mut rng, Leaf, Fp::from(42))?.0;
    assert!(app.verify(&left, &mut rng)?);

    for value in [99, 171] {
        let right = app.seed(&mut rng, Leaf, Fp::from(value))?.0;
        assert!(app.verify(&right, &mut rng)?);
        assert_ne!(
            left.data(),
            right.data(),
            "child headers must be asymmetric"
        );
        let left_proof = left.proof().clone();
        let right_proof = right.proof().clone();
        let expected_data = *left.data() + right.data();
        let parent = app.fuse(&mut rng, Add, (), left, right)?.0;
        assert_eq!(*parent.data(), expected_data);

        let challenge_values = stage_values::<
            nested::stages::challenges::Stage<<C as Cycle>::HostCurve, R>,
        >(parent.proof().nested_challenges_rx());
        assert_eq!(
            &challenge_values[20..22],
            &[-Fq::ONE, Fq::ZERO],
            "normal recursive base-case sign"
        );
        check_nested_accumulator(&app, parent.proof(), &left_proof, &right_proof)?;
        check_nested_batch(&app, parent.proof(), &left_proof, &right_proof)?;
        let (accepted, checks) = app.verify_with_checks(&parent, &mut rng)?;
        let checks = checks.expect("verification reaches semantic checks");
        assert!(accepted && checks.all(), "diagnostics: {checks:?}");
        left = parent;
    }
    Ok(())
}

/// Review V05: identify the twelve a/d pairs independently of the witness
/// constructor, including beta, and the separate system blinding coefficient.
fn challenge_stage_coefficients() -> Vec<(&'static str, &'static str, usize)> {
    type ChallengeStage = nested::stages::challenges::Stage<<C as Cycle>::HostCurve, R>;
    let names = [
        "w", "y", "z", "mu", "nu", "mu_prime", "nu_prime", "x", "alpha", "u", "sign", "beta",
    ];
    assert_eq!(ChallengeStage::values(), 2 * names.len());
    names
        .into_iter()
        .enumerate()
        .flat_map(|(slot, name)| {
            let gate = ChallengeStage::skip_gates() + slot;
            [
                (name, "a", 2 * R::n() - 1 - gate),
                (name, "d", 4 * R::n() - 1 - gate),
            ]
        })
        .chain(core::iter::once(("system", "blinding", 2 * R::n() - 1)))
        .collect()
}

fn check_changed_challenge_coefficients(
    repair_cache: impl Fn(&mut Proof<C, R>),
    cache_repaired: bool,
) -> Result<()> {
    let app = app();
    let (parent, _, _) = fused(&app);
    let verify = |proof: Proof<C, R>| {
        let pcd = proof.carry::<()>(());
        let (accepted, checks) = app.verify_with_checks(&pcd, StdRng::seed_from_u64(0x87303))?;
        let checks = checks.expect("valid metadata reaches all decider checks");
        assert_eq!(accepted, checks.all(), "diagnostics: {checks:?}");
        assert_eq!(
            accepted,
            app.verify(&pcd, StdRng::seed_from_u64(0x87303))?,
            "diagnostics must preserve the ordinary verifier decision"
        );
        Ok::<_, ragu_core::Error>((accepted, checks))
    };
    let (accepted, checks) = verify(parent.clone())?;
    assert!(accepted, "the honest parent must verify: {checks:?}");

    let original: Vec<_> = parent.nested_challenges_rx.iter_coeffs().collect();
    let coefficients = challenge_stage_coefficients();
    assert_eq!(
        coefficients.len(),
        25,
        "all lifts, sign, zeros and blinding"
    );
    for (name, wire, coefficient) in coefficients {
        let mut changed = parent.clone();
        let mut mutated = original.clone();
        if wire == "d" || wire == "blinding" {
            assert_eq!(mutated[coefficient], Fq::ZERO, "{name} {wire}");
        }
        // Flip the sign to the other legal branch; all other edits add one.
        mutated[coefficient] = if name == "sign" && wire == "a" {
            assert_eq!(
                mutated[coefficient],
                -Fq::ONE,
                "ordinary unit children still enforce their claims"
            );
            Fq::ONE
        } else {
            mutated[coefficient] + Fq::ONE
        };
        changed.nested_challenges_rx = sparse::Polynomial::from_coeffs(mutated.clone());
        repair_cache(&mut changed);
        assert!(changed.nested_challenges_rx.iter_coeffs().eq(mutated));
        assert_ne!(
            changed
                .nested_challenges_rx
                .iter_coeffs()
                .collect::<Vec<_>>(),
            original
        );
        assert_eq!(
            changed.challenges().in_order(),
            parent.challenges().in_order()
        );
        assert_eq!(changed.left_header(), parent.left_header());
        assert_eq!(changed.right_header(), parent.right_header());
        assert_eq!(
            changed.nested_challenges_partial(),
            parent.nested_challenges_partial()
        );

        let (accepted, checks) = verify(changed)?;
        assert!(
            !checks.nested_challenges,
            "{name} {wire} coefficient {coefficient}: {checks:?}"
        );
        assert_eq!(
            checks.commitments, cache_repaired,
            "{name} {wire}: {checks:?}"
        );
        assert!(
            checks.transcript,
            "native challenges stay frozen: {checks:?}"
        );
        assert!(
            !accepted,
            "accepted changed {name} {wire} coefficient {coefficient}: {checks:?}"
        );
    }

    Ok(())
}

#[test]
fn nested_challenge_stage_rejects_changed_coefficients() -> Result<()> {
    check_changed_challenge_coefficients(|_| {}, false)
}

/// Only the changed polynomial's direct cache may follow the mutation. The
/// transcript, binding partial, other stages and all other caches stay frozen.
/// This tests root reconstruction, not propagation of a child's bad stage.
/// Deleting only the exact reconstruction must fail the predicate assertion
/// even if another verifier check still rejects the proof (review O02).
/// Calibration on w's a-wire confirms that nested revdot still rejects when
/// exact reconstruction is disabled; overall rejection alone misses that fault.
#[cfg(feature = "unstable-fuzzing")]
#[test]
fn nested_challenge_stage_rejects_changed_coefficients_with_repaired_cache() -> Result<()> {
    use crate::fuzzing::corrupt::{NestedCommitment, NestedRx};

    check_changed_challenge_coefficients(
        |proof| {
            let commitment = ReferenceBackend::sparse_commit_to_affine(
                proof.nested_challenges_rx(),
                C::nested_generators(Pasta::baked()),
            );
            assert_ne!(commitment, proof.nested_challenges_commitment());
            *proof.nested_commitment_cache_mut(NestedCommitment::Rx(NestedRx::ChallengeStage)) =
                commitment;
        },
        true,
    )
}

#[test]
fn nested_challenge_stage_is_bound_by_its_commitment() -> Result<()> {
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

    // 1. The stored stage is the unblinded stage of the lifts, the sign and
    //    beta's lift.
    let lifts = parent.challenges().lifts::<C>()?;
    let (challenge_lifts, beta_lift) = lifts.split_at(NUM_BOUND);
    // Unit headers take the recursive branch; only Dummy children are a base case.
    let sign = -Fq::ONE;
    let challenges = nested::stages::challenges::Witness::new::<_, HEADER_SIZE>(
        challenge_lifts.try_into().unwrap(),
        parent.left_header(),
        parent.right_header(),
        beta_lift[0],
    );
    assert_eq!(challenges.base_case_sign, sign);
    let expected =
        nested::stages::challenges::Stage::<ragu_pasta::EqAffine, R>::rx(Fq::ZERO, &challenges)?;
    assert!(
        parent
            .nested_challenges_rx()
            .iter_coeffs()
            .eq(expected.iter_coeffs()),
        "nested challenge stage is not the stage of the lifts"
    );

    // 2. Its commitment is the fixed generator combination the binding
    //    circuits recompute, term by term: the binders' terms, then beta's.
    let generators = Pasta::nested_generators(pasta);
    let mut binding = ragu_pasta::Ep::identity();
    for (i, lift) in challenge_lifts.iter().enumerate() {
        binding += generators.g()[generator_index::<C, R>(i)] * *lift;
    }
    binding +=
        generators.g()[generator_index::<C, R>(nested::stages::challenges::SIGN_INDEX)] * sign;
    let beta_term = generators.g()[bind_beta::generator_index::<C, R>()] * beta_lift[0];
    assert_eq!(
        parent.nested_challenges_commitment(),
        (binding + beta_term).to_affine(),
        "challenge commitment is not the generator combination of the lifts"
    );
    assert_eq!(
        parent.nested_challenges_partial(),
        binding.to_affine(),
        "the exported binding is not the commitment without beta's term"
    );

    // 3. The eval stage's partials are the running sums the binders check;
    //    the last binder's sum is the exported binding.
    let partials = BindingPartials::compute::<C, R, ReferenceBackend>(pasta, &challenges);
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
        if k + 1 == NUM_BINDERS {
            acc += generators.g()[generator_index::<C, R>(nested::stages::challenges::SIGN_INDEX)]
                * sign;
            assert_eq!(partials.binding, acc.to_affine(), "binding");
        } else {
            assert_eq!(partials.partials[k], acc.to_affine(), "partial {k}");
        }
    }
    assert_eq!(parent.nested_challenges_partial(), partials.binding);

    Ok(())
}

/// The parent's root stage holds each child's bridge, challenge-stage and
/// persistent polynomial commitments. Its own persistent points match the
/// decider's caches, including $P_n$ at the walk's last interstitial.
#[test]
fn nested_commitments_are_pinned_at_both_ends_of_the_walk() -> Result<()> {
    use ragu_arithmetic::CurveAffine;

    use crate::internal::{
        native::{
            RxIndex,
            stages::points::{BindingStage, WalkStage},
        },
        stage_wires::{StageReader, stage_wire_indices, wires_of},
    };

    type Nested = <C as ragu_arithmetic::Cycle>::NestedCurve;
    let coordinates = |point: Nested| -> [ragu_pasta::Fp; 2] {
        let c = point
            .coordinates()
            .into_option()
            .expect("a walked point is not the identity");
        [*c.x(), *c.y()]
    };

    let app = app();
    let (parent, left, right) = fused(&app);

    // The root stage, wire by wire, against the children's caches.
    let binding = StageReader::<ragu_pasta::Fp, R>::new(&parent[RxIndex::PointsBinding]);
    let wires = stage_wire_indices::<_, R, BindingStage<Nested>>(|stage| wires_of(&stage))?;
    let held: alloc::vec::Vec<ragu_pasta::Fp> = wires.iter().map(|&i| binding.read(i)).collect();
    let expected: alloc::vec::Vec<ragu_pasta::Fp> = [&left, &right]
        .into_iter()
        .flat_map(|child| {
            [
                child.bridge_preamble_commitment(),
                child.bridge_s_prime_commitment(),
                child.bridge_inner_error_commitment(),
                child.bridge_outer_error_commitment(),
                child.bridge_ab_commitment(),
                child.bridge_query_commitment(),
                child.bridge_f_commitment(),
                child.bridge_eval_commitment(),
                child.nested_challenges_commitment(),
                child.nested_a_commitment(),
                child.nested_b_commitment(),
                child.nested_registry_xy_commitment(),
                child.nested_p_commitment(),
            ]
        })
        .flat_map(coordinates)
        .collect();
    assert_eq!(
        held, expected,
        "the root stage does not hold the children's points"
    );

    // The walk's last interstitial, against this step's cache.
    let walk = StageReader::<ragu_pasta::Fp, R>::new(&parent[RxIndex::PointsWalk]);
    let wires = stage_wire_indices::<_, R, WalkStage<Nested>>(|stage| wires_of(stage.p()))?;
    let last: alloc::vec::Vec<ragu_pasta::Fp> = wires.iter().map(|&i| walk.read(i)).collect();
    assert_eq!(
        last,
        coordinates(parent.nested_p_commitment()).to_vec(),
        "P_n is not the walk's last interstitial"
    );

    for (i, proof) in [&parent, &left, &right].into_iter().enumerate() {
        assert!(crate::verify::nested_points_match(proof)?);
        assert!(app.verify(
            &proof.clone().carry::<()>(()),
            StdRng::seed_from_u64(0xb1d0 + i as u64),
        )?);
    }

    // Exercise the decider's point comparison in isolation: a valid point
    // in the cache must still be the one carried by the walk's stage.
    #[cfg(feature = "unstable-fuzzing")]
    for which in [
        crate::fuzzing::corrupt::NestedCommitment::AbA,
        crate::fuzzing::corrupt::NestedCommitment::AbB,
        crate::fuzzing::corrupt::NestedCommitment::RegistryXy,
    ] {
        let mut changed = parent.clone();
        let point = changed.nested_commitment_cache_mut(which);
        *point = -*point;
        assert!(
            !crate::verify::nested_points_match(&changed)?,
            "mismatched {which:?}"
        );
        *changed.nested_commitment_cache_mut(which) =
            <Nested as ragu_arithmetic::group::CurveAffine>::identity();
        assert!(
            !crate::verify::nested_points_match(&changed)?,
            "identity {which:?}"
        );
    }

    Ok(())
}
