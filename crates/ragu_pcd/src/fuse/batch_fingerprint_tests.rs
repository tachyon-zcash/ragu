//! Review A11: an independent specification of the nested batch's occurrences.
//!
//! Expected identities and exponents never come from the production query,
//! evaluation, commitment, or rx enumerators. An occurrence includes its child,
//! polynomial/stage, and query point: repeated registry polynomials remain
//! distinct openings. Polynomial and scalar arithmetic is in the nested field,
//! Fq; the commitments are also checked in their native-field point stages.
//! These are honest recursive fixtures and exact algebra checks, not adaptive
//! transcript attacks or a claim of complete native-batch coverage.
//!
//! Mutation controls: shared rx/registry permutations, a shared left/right query
//! swap, dropping the leading f, duplicating the persistent P commitment, and
//! shifting the six-term tail must each fail these independent expectations.

use alloc::vec;

use ragu_arithmetic::{CurveAffine, group::Curve};
use ragu_circuits::registry::CircuitIndex;

use super::*;
use crate::internal::{native, nested::RxIndex};

type Poly = sparse::Polynomial<Fq, R>;
type Point = <C as Cycle>::NestedCurve;

// Deliberately independent of NUM/ALL/INSTANCE/BRIDGES. A protocol layout
// change must update this specification explicitly, rather than silently
// moving both the implementation and its expected result together.
pub(super) fn rx_order() -> Vec<RxIndex> {
    use RxIndex::*;
    (0..28)
        .map(EndoscalingStep)
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

fn registry_order() -> Vec<nested::InternalCircuitIndex> {
    use nested::InternalCircuitIndex::*;
    (0..28)
        .map(EndoscalingStep)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Child {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Rx(RxIndex),
    A,
    B,
    Xy,
    P,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Polynomial {
    Child(Child, Part),
    Wx0,
    Wx1,
    Wy,
    A,
    B,
    Xy,
}

impl Polynomial {
    fn get<'a>(self, batch: &pcs::Batch<'a, C, R>) -> &'a Poly {
        match self {
            Self::Child(child, part) => {
                let proof = match child {
                    Child::Left => batch.left,
                    Child::Right => batch.right,
                };
                match part {
                    Part::Rx(id) => &proof[id],
                    Part::A => &proof.nested_a_poly,
                    Part::B => &proof.nested_b_poly,
                    Part::Xy => proof.nested_registry_xy_poly(),
                    Part::P => proof.nested_p_poly(),
                }
            }
            Self::Wx0 => batch.registry_wx0,
            Self::Wx1 => batch.registry_wx1,
            Self::Wy => batch.registry_wy,
            Self::A => batch.a,
            Self::B => batch.b,
            Self::Xy => batch.registry_xy,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum At {
    LeftU,
    RightU,
    W,
    LeftY,
    RightY,
    Y,
    LeftX,
    RightX,
    X,
    Xz,
    Registry(usize),
}

impl At {
    fn value(self, ch: pcs::Challenges<Fq>) -> Fq {
        match self {
            Self::LeftU => ch.left.u,
            Self::RightU => ch.right.u,
            Self::W => ch.w,
            Self::LeftY => ch.left.y,
            Self::RightY => ch.right.y,
            Self::Y => ch.y,
            Self::LeftX => ch.left.x,
            Self::RightX => ch.right.x,
            Self::X => ch.x,
            Self::Xz => ch.x * ch.z,
            Self::Registry(j) => CircuitIndex::new(j).omega_j(),
        }
    }
}

fn openings() -> Vec<(Polynomial, At)> {
    use Polynomial::{Child, *};

    use self::Child::{Left, Right};
    let mut result = vec![
        (Child(Left, Part::P), At::LeftU),
        (Child(Right, Part::P), At::RightU),
        (Child(Left, Part::Xy), At::W),
        (Child(Right, Part::Xy), At::W),
        (Wx0, At::LeftY),
        (Wx1, At::RightY),
        (Wx0, At::Y),
        (Wx1, At::Y),
        (Wy, At::LeftX),
        (Wy, At::RightX),
        (Wy, At::X),
        (Xy, At::W),
        (Child(Left, Part::A), At::Xz),
        (Child(Left, Part::B), At::X),
        (Child(Right, Part::A), At::Xz),
        (Child(Right, Part::B), At::X),
        (A, At::Xz),
        (B, At::X),
    ];
    for child in [Left, Right] {
        result.extend(
            rx_order()
                .into_iter()
                .map(|id| (Child(child, Part::Rx(id)), At::Xz)),
        );
    }
    result.extend((0..45).map(|j| (Xy, At::Registry(j))));
    result
}

fn evaluated() -> Vec<Polynomial> {
    let mut result = Vec::new();
    for child in [Child::Left, Child::Right] {
        result.extend(
            rx_order()
                .into_iter()
                .map(|id| Polynomial::Child(child, Part::Rx(id))),
        );
        result.extend(
            [Part::A, Part::B, Part::Xy, Part::P].map(|part| Polynomial::Child(child, part)),
        );
    }
    result.extend([
        Polynomial::Wx0,
        Polynomial::Wx1,
        Polynomial::Wy,
        Polynomial::A,
        Polynomial::B,
        Polynomial::Xy,
    ]);
    result
}

/// The query bridge serializes a different projection of the openings from
/// the quotient's order: registry domain, registry at w, then each child.
fn query_stage_order() -> Vec<(Polynomial, At)> {
    let mut result: Vec<_> = (0..45).map(|j| (Polynomial::Xy, At::Registry(j))).collect();
    result.push((Polynomial::Xy, At::W));
    for (child, child_x) in [(Child::Left, At::LeftX), (Child::Right, At::RightX)] {
        result.extend(
            rx_order()
                .into_iter()
                .map(|id| (Polynomial::Child(child, Part::Rx(id)), At::Xz)),
        );
        result.extend([
            (Polynomial::Child(child, Part::A), At::Xz),
            (Polynomial::Child(child, Part::B), At::X),
            (Polynomial::Child(child, Part::Xy), At::W),
            (Polynomial::Wy, child_x),
        ]);
    }
    result
}

fn power(base: Fq, exponent: usize) -> Fq {
    base.pow_vartime([exponent as u64])
}

/// Direct coefficient dot product with the powers, independent of sparse eval.
fn evaluate(coefficients: impl IntoIterator<Item = Fq>, at: Fq) -> Fq {
    let mut degree_power = Fq::ONE;
    coefficients
        .into_iter()
        .map(|coefficient| {
            let term = coefficient * degree_power;
            degree_power *= at;
            term
        })
        .sum()
}

fn raw_stage<F: ragu_arithmetic::ff::PrimeField, S: Stage<F, R>>(
    rx: &sparse::Polynomial<F, R>,
) -> Vec<F> {
    let coefficients: Vec<_> = rx.iter_coeffs().collect();
    (0..S::values())
        .map(|i| {
            let gate = S::skip_gates() + i / 2;
            coefficients[if i % 2 == 0 {
                2 * R::n() - 1 - gate
            } else {
                4 * R::n() - 1 - gate
            }]
        })
        .collect()
}

fn coordinates(point: Point) -> [Fp; 2] {
    let coordinates = point.coordinates().unwrap();
    [*coordinates.x(), *coordinates.y()]
}

/// Hold all five pre-challenge point stages to direct polynomial commitments.
/// Their storage order is specified separately from the batch's walk order.
fn check_point_stages(parent: &Proof<C, R>, points: &[Point], f: Point, p: Point) {
    use native::stages::points::*;
    let flatten =
        |points: Vec<Point>| -> Vec<Fp> { points.into_iter().flat_map(coordinates).collect() };
    // Each child has 33 circuit/stage points, eight bridges, the challenge
    // stage, then A, B, registry_xy, P. The final 13 live in BindingStage.
    let bindings = points[33..46]
        .iter()
        .chain(&points[79..92])
        .copied()
        .collect();
    assert_eq!(
        raw_stage::<Fp, BindingStage<Point>>(&parent.native_points_binding_rx),
        flatten(bindings)
    );
    let children = points[..33]
        .iter()
        .chain(&points[46..79])
        .copied()
        .collect();
    assert_eq!(
        raw_stage::<Fp, ChildrenStage<Point>>(&parent.native_points_children_rx),
        flatten(children)
    );
    assert_eq!(
        raw_stage::<Fp, RegistryWxStage<Point>>(&parent.native_points_registry_wx_rx),
        flatten(points[92..94].to_vec())
    );
    assert_eq!(
        raw_stage::<Fp, AbStage<Point>>(&parent.native_points_ab_rx),
        flatten(points[94..97].to_vec())
    );
    assert_eq!(
        raw_stage::<Fp, FStage<Point>>(&parent.native_points_f_rx),
        flatten(vec![points[97], f])
    );
    let walk = raw_stage::<Fp, WalkStage<Point>>(&parent.native_points_walk_rx);
    assert_eq!(&walk[walk.len() - 2..], &coordinates(p), "walk endpoint");
}

fn check_fingerprint(
    app: &Application<'_, C, R, HEADER_SIZE>,
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<()> {
    let child_challenges = |proof: &Proof<C, R>| -> Result<pcs::ChildChallenges<Fq>> {
        Ok(pcs::ChildChallenges {
            x: nested::challenge::<C>(proof.x())?,
            y: nested::challenge::<C>(proof.y())?,
            u: nested::challenge::<C>(proof.u())?,
        })
    };
    let ch = pcs::Challenges {
        w: nested::challenge::<C>(parent.w())?,
        x: nested::challenge::<C>(parent.x())?,
        y: nested::challenge::<C>(parent.y())?,
        z: nested::challenge::<C>(parent.z())?,
        left: child_challenges(left)?,
        right: child_challenges(right)?,
    };
    let alpha = nested::challenge::<C>(parent.alpha())?;
    let beta = nested::challenge::<C>(parent.pre_beta())?;
    let u = nested::challenge::<C>(parent.u())?;
    assert_ne!(ch.x, ch.x * ch.z, "fixture must distinguish dilation");
    assert_ne!(ch.left.y, ch.y);
    assert_ne!(ch.right.y, ch.y);
    assert_ne!(ch.left.x, ch.x);
    assert_ne!(ch.right.x, ch.x);
    for challenge in [alpha, beta] {
        assert_ne!(challenge, Fq::ZERO);
        assert_ne!(challenge, Fq::ONE);
    }

    let registry = app.nested_registry.at(ch.w);
    let wx0 = ReferenceBackend::registry_at_x(&registry, ch.left.x);
    let wx1 = ReferenceBackend::registry_at_x(&registry, ch.right.x);
    let wy = ReferenceBackend::registry_at_y(&registry, ch.y);
    let batch = pcs::Batch {
        left,
        right,
        registry_wx0: &wx0,
        registry_wx1: &wx1,
        registry_wy: &wy,
        registry_xy: parent.nested_registry_xy_poly(),
        a: &parent.nested_a_poly,
        b: &parent.nested_b_poly,
    };

    let expected_queries = openings();
    let actual_queries: Vec<_> = batch.queries(ch).collect();
    assert_eq!(expected_queries.len(), 147);
    assert_eq!(actual_queries.len(), expected_queries.len());
    let mut f = vec![Fq::ZERO; R::num_coeffs()];
    let mut f_at_u = Fq::ZERO;
    for (slot, &(role, at)) in expected_queries.iter().enumerate() {
        // Pointer identity distinguishes occurrences even if their coefficients
        // happen to agree (e.g. stages in two proofs with the same header).
        let poly = role.get(&batch);
        let point = at.value(ch);
        assert!(
            core::ptr::eq(actual_queries[slot].0, poly),
            "query {slot}: {role:?} at {at:?}"
        );
        assert_eq!(
            actual_queries[slot].1, point,
            "query {slot}: {role:?} at {at:?}"
        );
        let weight = power(alpha, 146 - slot);
        let coefficients: Vec<_> = poly.iter_coeffs().collect();
        // (p(X)-p(q))/(X-q), from its coefficient recurrence. No factor_iter,
        // polynomial fold, production query order, or shared Horner reduction.
        let mut carry = Fq::ZERO;
        for degree in (1..coefficients.len()).rev() {
            carry = coefficients[degree] + point * carry;
            f[degree - 1] += weight * carry;
        }
        // Separate rational-evaluation specification of the same quotient.
        assert_ne!(u, point, "fixture has a coincident opening point");
        f_at_u += weight
            * (evaluate(coefficients.iter().copied(), u) - evaluate(coefficients, point))
            * (u - point).invert().unwrap();
    }
    assert_eq!(evaluate(f.iter().copied(), u), f_at_u);
    assert!(f.iter().any(|&v| v != Fq::ZERO));

    let roles = evaluated();
    let actual_evaluated: Vec<_> = batch.evaluated().collect();
    assert_eq!(roles.len(), 98);
    assert_eq!(actual_evaluated.len(), roles.len());
    let generators = C::nested_generators(app.params);
    let commit = |poly: &Poly| ReferenceBackend::sparse_commit_to_affine(poly, generators);
    let f_commitment = commit(&Poly::from_coeffs(f.clone()));
    let f_weight = power(beta, 98);
    let mut p: Vec<_> = f.into_iter().map(|c| c * f_weight).collect();
    let mut v = f_at_u * f_weight;
    let mut group_sum = f_commitment * f_weight;
    let mut evaluations = Vec::new();
    let mut points = Vec::new();
    for (slot, &role) in roles.iter().enumerate() {
        let poly = role.get(&batch);
        assert!(
            core::ptr::eq(actual_evaluated[slot], poly),
            "evaluation {slot}: {role:?}"
        );
        let weight = power(beta, 97 - slot);
        for (degree, coefficient) in poly.iter_coeffs().enumerate() {
            p[degree] += coefficient * weight;
        }
        let value = evaluate(poly.iter_coeffs(), u);
        v += value * weight;
        evaluations.push(value);
        let point = commit(poly);
        group_sum += point * weight;
        points.push(point);
    }
    assert!(
        parent.nested_p_poly().iter_coeffs().eq(p.iter().copied()),
        "every coefficient of nested p"
    );
    assert_eq!(evaluate(p.iter().copied(), u), v);
    assert_eq!(
        parent.nested_v()?,
        v,
        "compute_v's beta powers and leading f"
    );
    assert_eq!(group_sum.to_affine(), commit(&Poly::from_coeffs(p)));
    assert_eq!(
        group_sum.to_affine(),
        parent.nested_p_commitment(),
        "walk's beta powers and leading f"
    );

    let current = pcs::CurrentCommitments {
        registry_wx0: points[92],
        registry_wx1: points[93],
        registry_wy: points[94],
        a: points[95],
        b: points[96],
        registry_xy: points[97],
    };
    let actual_points: Vec<_> = batch.commitments(current).collect();
    assert_eq!(actual_points.len(), 98);
    for (slot, role) in roles.iter().enumerate() {
        assert_eq!(
            actual_points[slot], points[slot],
            "commitment {slot}: {role:?}"
        );
    }
    let stored = raw_stage::<Fq, nested::stages::eval::Stage<<C as Cycle>::HostCurve, R>>(
        &parent.bridge_eval_rx,
    );
    assert_eq!(
        &stored[2..],
        evaluations,
        "eval bridge's serialized occurrence order"
    );
    let stored = raw_stage::<Fq, nested::stages::query::Stage<<C as Cycle>::HostCurve, R>>(
        &parent.bridge_query_rx,
    );
    let expected: Vec<_> = query_stage_order()
        .into_iter()
        .map(|(role, at)| evaluate(role.get(&batch).iter_coeffs(), at.value(ch)))
        .collect();
    assert_eq!(
        &stored[4..],
        expected,
        "query bridge's serialized occurrence order and points"
    );
    check_point_stages(parent, &points, f_commitment, group_sum.to_affine());
    Ok(())
}

#[test]
fn nested_batch_inventory_preserves_occurrence_identity() {
    assert_eq!(nested::RxIndex::ALL.as_slice(), rx_order());
    assert_eq!(
        nested::InternalCircuitIndex::ALL.as_slice(),
        registry_order()
    );
    for (j, id) in registry_order().into_iter().enumerate() {
        assert_eq!(
            id.circuit_index(),
            CircuitIndex::new(j),
            "registry slot {id:?}"
        );
    }
    let queries = openings();
    for (slot, occurrence) in queries.iter().enumerate() {
        assert!(
            !queries[..slot].contains(occurrence),
            "duplicate occurrence: {occurrence:?}"
        );
    }
    for (role, multiplicity) in [
        (Polynomial::Wx0, 2),
        (Polynomial::Wx1, 2),
        (Polynomial::Wy, 3),
        (Polynomial::Xy, 46),
    ] {
        assert_eq!(
            queries.iter().filter(|(poly, _)| *poly == role).count(),
            multiplicity
        );
    }
}

#[test]
fn nested_batch_fingerprint_matches_polynomials_scalars_and_walk() -> Result<()> {
    use test_steps::{Add, Leaf};
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0xa11_0873);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let parent = app.fuse(&mut rng, Add, (), left.clone(), right.clone())?.0;
    check_fingerprint(&app, parent.proof(), left.proof(), right.proof())?;
    assert!(app.verify(&parent, &mut rng)?);
    let leaf = app.seed(&mut rng, Leaf, Fp::from(101))?.0;
    // Exercise both child positions at unequal depths, plus repeated-child
    // multiplicity even when corresponding polynomials are numerically equal.
    for (left, right) in [
        (parent.clone(), leaf.clone()),
        (leaf, parent.clone()),
        (parent.clone(), parent),
    ] {
        let next = app.fuse(&mut rng, Add, (), left.clone(), right.clone())?.0;
        assert_eq!(*next.data(), *left.data() + right.data());
        check_fingerprint(&app, next.proof(), left.proof(), right.proof())?;
        assert!(app.verify(&next, &mut rng)?);
    }
    Ok(())
}
