//! Review A04: an independent, distinct-symbol specification of the native batch.
//!
//! The expected opening, evaluation, commitment, and registry orders below do
//! not use the production query tables or `ALL` iterators. Each occurrence is
//! named by its child, polynomial role, and point, so equal-valued polynomials
//! cannot hide a permutation. The quotient coefficients and evaluation are
//! reconstructed directly, then the full 113-point commitment walk is checked
//! against the serialized point stage and persistent native P commitment.

use alloc::vec;

use ragu_arithmetic::{
    CurveAffine,
    group::{Curve, CurveAffine as GroupCurveAffine},
};
use ragu_circuits::registry::CircuitIndex;
use ragu_primitives::{extract_endoscalar, lift_endoscalar};

use super::*;
use crate::internal::{endoscalar, native};

type Poly = sparse::Polynomial<Fp, R>;
type Point = <C as Cycle>::HostCurve;

// Deliberately independent of RxIndex::ALL and NUM. A protocol-layout change
// must update this specification explicitly.
fn rx_order() -> Vec<native::RxIndex> {
    use native::RxIndex::*;
    let mut order = Vec::new();
    order.extend([
        Application,
        Hashes1,
        Hashes2,
        InnerCollapse,
        OuterCollapse,
        ComputeV,
    ]);
    order.extend((0..5).map(BindChallenges));
    order.extend([BindBeta, BindEndoscalar]);
    order.extend((0..25).map(EndoscalingStep));
    order.extend([
        Preamble,
        InnerError,
        OuterError,
        Query,
        Eval,
        PointsBinding,
        PointsChildren,
        PointsRegistryWx,
        PointsAb,
        PointsF,
        PointsWalk,
    ]);
    order
}

fn registry_order() -> Vec<native::InternalCircuitIndex> {
    use native::InternalCircuitIndex::*;
    let mut order = Vec::new();
    order.extend([
        Hashes1Circuit,
        Hashes2Circuit,
        InnerCollapseCircuit,
        OuterCollapseCircuit,
        ComputeVCircuit,
    ]);
    order.extend((0..5).map(BindChallengesCircuit));
    order.extend([BindBetaCircuit, BindEndoscalarCircuit]);
    order.extend((0..25).map(EndoscalingStep));
    order.extend([
        PreambleStage,
        InnerErrorStage,
        OuterErrorStage,
        QueryStage,
        EvalStage,
        PointsBindingStage,
        PointsChildrenStage,
        PointsRegistryWxStage,
        PointsAbStage,
        PointsFStage,
        PointsWalkStage,
        InnerErrorFinalStaged,
        OuterErrorFinalStaged,
        EvalFinalStaged,
        PointsWalkFinalStaged,
    ]);
    order
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Child {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Rx(native::RxIndex),
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

struct Batch<'a> {
    left: &'a Proof<C, R>,
    right: &'a Proof<C, R>,
    wx0: &'a Poly,
    wx1: &'a Poly,
    wy: &'a Poly,
    a: &'a Poly,
    b: &'a Poly,
    xy: &'a Poly,
}

impl Polynomial {
    fn get<'a>(self, batch: &Batch<'a>) -> &'a Poly {
        match self {
            Self::Child(child, part) => {
                let proof = match child {
                    Child::Left => batch.left,
                    Child::Right => batch.right,
                };
                match part {
                    Part::Rx(id) => &proof[id],
                    Part::A => &proof[native::RxComponent::AbA],
                    Part::B => &proof[native::RxComponent::AbB],
                    Part::Xy => proof.native_registry_xy_poly(),
                    Part::P => proof.native_p_poly(),
                }
            }
            Self::Wx0 => batch.wx0,
            Self::Wx1 => batch.wx1,
            Self::Wy => batch.wy,
            Self::A => batch.a,
            Self::B => batch.b,
            Self::Xy => batch.xy,
        }
    }
}

#[derive(Clone, Copy)]
struct ChildChallenges {
    x: Fp,
    y: Fp,
    u: Fp,
    circuit_id: Fp,
}

#[derive(Clone, Copy)]
struct Challenges {
    w: Fp,
    x: Fp,
    y: Fp,
    z: Fp,
    u: Fp,
    left: ChildChallenges,
    right: ChildChallenges,
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
    LeftCircuitId,
    RightCircuitId,
    Registry(usize),
}

impl At {
    fn value(self, ch: Challenges) -> Fp {
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
            Self::LeftCircuitId => ch.left.circuit_id,
            Self::RightCircuitId => ch.right.circuit_id,
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
        (Xy, At::LeftCircuitId),
        (Xy, At::RightCircuitId),
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
    result.extend((0..52).map(|j| (Xy, At::Registry(j))));
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

/// The query stage serializes the registry projection first, followed by the
/// two children's xz-backed evaluations. Other static quotient openings live
/// in earlier stages or in the child proof itself.
fn query_stage_order() -> Vec<(Polynomial, At)> {
    let mut result: Vec<_> = (0..52).map(|j| (Polynomial::Xy, At::Registry(j))).collect();
    result.push((Polynomial::Xy, At::W));
    for (child, child_x, circuit_id) in [
        (Child::Left, At::LeftX, At::LeftCircuitId),
        (Child::Right, At::RightX, At::RightCircuitId),
    ] {
        result.extend(
            rx_order()
                .into_iter()
                .map(|id| (Polynomial::Child(child, Part::Rx(id)), At::Xz)),
        );
        result.extend([
            (Polynomial::Child(child, Part::A), At::Xz),
            (Polynomial::Child(child, Part::B), At::X),
            (Polynomial::Child(child, Part::Xy), At::W),
            (Polynomial::Xy, circuit_id),
            (Polynomial::Wy, child_x),
        ]);
    }
    result
}

fn evaluate(coefficients: impl IntoIterator<Item = Fp>, at: Fp) -> Fp {
    let mut degree_power = Fp::ONE;
    coefficients
        .into_iter()
        .map(|coefficient| {
            let term = coefficient * degree_power;
            degree_power *= at;
            term
        })
        .sum()
}

fn power(base: Fp, exponent: usize) -> Fp {
    base.pow_vartime([exponent as u64])
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

fn coordinates(point: Point) -> [Fq; 2] {
    let coordinates = point.coordinates().unwrap();
    [*coordinates.x(), *coordinates.y()]
}

fn flatten_points(points: &[Point]) -> Vec<Fq> {
    points.iter().copied().flat_map(coordinates).collect()
}

fn endoscalar_bits(endoscalar: u128) -> Vec<Fq> {
    (0..u128::BITS)
        .map(|bit| {
            if endoscalar & (1 << bit) == 0 {
                Fq::ZERO
            } else {
                Fq::ONE
            }
        })
        .collect()
}

fn check_fingerprint(
    app: &Application<'_, C, R, HEADER_SIZE>,
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<()> {
    let child_challenges = |proof: &Proof<C, R>| ChildChallenges {
        x: proof.x(),
        y: proof.y(),
        u: proof.u(),
        circuit_id: proof.circuit_id().omega_j(),
    };
    let ch = Challenges {
        w: parent.w(),
        x: parent.x(),
        y: parent.y(),
        z: parent.z(),
        u: parent.u(),
        left: child_challenges(left),
        right: child_challenges(right),
    };
    let alpha = parent.alpha();
    let beta_endo = extract_endoscalar(parent.pre_beta())?;
    let beta = lift_endoscalar::<Fp>(beta_endo);
    assert_ne!(ch.x, ch.x * ch.z, "fixture must distinguish x from xz");
    assert_ne!(ch.left.x, ch.x);
    assert_ne!(ch.right.x, ch.x);
    assert_ne!(ch.left.y, ch.y);
    assert_ne!(ch.right.y, ch.y);
    for challenge in [alpha, beta] {
        assert_ne!(challenge, Fp::ZERO);
        assert_ne!(challenge, Fp::ONE);
    }

    let registry = app.native_registry().at(ch.w);
    let wx0 = ReferenceBackend::registry_at_x(&registry, ch.left.x);
    let wx1 = ReferenceBackend::registry_at_x(&registry, ch.right.x);
    let wy = ReferenceBackend::registry_at_y(&registry, ch.y);
    let batch = Batch {
        left,
        right,
        wx0: &wx0,
        wx1: &wx1,
        wy: &wy,
        a: &parent[native::RxComponent::AbA],
        b: &parent[native::RxComponent::AbB],
        xy: parent.native_registry_xy_poly(),
    };

    // Reconstruct f coefficient by coefficient from the distinct opening
    // occurrences. This uses neither factor_iter nor alpha_batched_quotients.
    let queries = openings();
    assert_eq!(queries.len(), 170);
    let mut f = vec![Fp::ZERO; R::num_coeffs()];
    let mut f_at_u = Fp::ZERO;
    for (slot, &(role, at)) in queries.iter().enumerate() {
        let poly = role.get(&batch);
        let point = at.value(ch);
        let weight = power(alpha, 169 - slot);
        let coefficients: Vec<_> = poly.iter_coeffs().collect();
        let mut carry = Fp::ZERO;
        for degree in (1..coefficients.len()).rev() {
            carry = coefficients[degree] + point * carry;
            f[degree - 1] += weight * carry;
        }
        assert_ne!(ch.u, point, "fixture has a coincident opening point");
        f_at_u += weight
            * (evaluate(coefficients.iter().copied(), ch.u) - evaluate(coefficients, point))
            * (ch.u - point).invert().unwrap();
    }
    assert_eq!(evaluate(f.iter().copied(), ch.u), f_at_u);
    assert!(f.iter().any(|&coefficient| coefficient != Fp::ZERO));

    let roles = evaluated();
    assert_eq!(roles.len(), 112);
    let generators = C::host_generators(app.params);
    let commit = |poly: &Poly| ReferenceBackend::sparse_commit_to_affine(poly, generators);
    let f_commitment = commit(&Poly::from_coeffs(f.clone()));
    let mut p = f;
    let mut v = f_at_u;
    let mut p_commitment = f_commitment.to_curve();
    let mut evaluations = Vec::new();
    let mut points = vec![f_commitment];
    for &role in &roles {
        let poly = role.get(&batch);
        for coefficient in &mut p {
            *coefficient *= beta;
        }
        for (degree, coefficient) in poly.iter_coeffs().enumerate() {
            p[degree] += coefficient;
        }
        let value = evaluate(poly.iter_coeffs(), ch.u);
        v = v * beta + value;
        evaluations.push(value);
        let point = commit(poly);
        p_commitment = p_commitment * beta + point.to_curve();
        points.push(point);
    }
    assert_eq!(points.len(), 113);
    assert!(
        parent.native_p_poly().iter_coeffs().eq(p.iter().copied()),
        "every coefficient of native p"
    );
    assert_eq!(evaluate(p.iter().copied(), ch.u), v);
    assert_eq!(parent.v(), v, "compute_v's beta order and leading f");
    assert_eq!(commit(&Poly::from_coeffs(p)), p_commitment.to_affine());
    assert_eq!(parent.native_p_commitment(), p_commitment.to_affine());

    let query_values = raw_stage::<Fp, native::stages::query::Stage<C, R, HEADER_SIZE>>(
        &parent[native::RxIndex::Query],
    );
    let expected_queries: Vec<_> = query_stage_order()
        .into_iter()
        .map(|(role, at)| evaluate(role.get(&batch).iter_coeffs(), at.value(ch)))
        .collect();
    assert_eq!(
        query_values, expected_queries,
        "query-stage occurrence order"
    );

    let eval_values = raw_stage::<Fp, native::stages::eval::Stage<C, R, HEADER_SIZE>>(
        &parent[native::RxIndex::Eval],
    );
    assert_eq!(
        &eval_values[..evaluations.len()],
        evaluations,
        "eval-stage occurrence order"
    );

    // The native batch walk is serialized as all 113 inputs followed by 28
    // four-at-a-time Horner checkpoints. Recompute every checkpoint directly.
    let mut interstitials = Vec::new();
    let mut accumulator = points[0].to_curve();
    for chunk in points[1..].chunks(4) {
        for point in chunk {
            accumulator = accumulator * beta + point.to_curve();
        }
        interstitials.push(accumulator.to_affine());
    }
    assert_eq!(interstitials.len(), 28);
    assert_eq!(
        interstitials.last().copied(),
        Some(parent.native_p_commitment())
    );
    let point_stage = raw_stage::<Fq, nested::PointsStage<Point>>(&parent.nested_points_rx);
    let expected_point_stage: Vec<_> = flatten_points(&points)
        .into_iter()
        .chain(flatten_points(&interstitials))
        .collect();
    assert_eq!(
        point_stage, expected_point_stage,
        "all walk inputs and checkpoints"
    );
    assert_eq!(
        raw_stage::<Fq, endoscalar::EndoscalarStage>(&parent.nested_endoscalar_rx),
        endoscalar_bits(beta_endo),
        "walk endoscalar bits"
    );
    Ok(())
}

#[test]
fn native_batch_inventory_preserves_distinct_occurrences() {
    assert_eq!(native::RxIndex::ALL.as_slice(), rx_order());
    assert_eq!(
        native::InternalCircuitIndex::ALL.as_slice(),
        registry_order()
    );
    assert_eq!(rx_order().len(), 49);
    assert_eq!(registry_order().len(), 52);
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
        (Polynomial::Xy, 55),
    ] {
        assert_eq!(
            queries.iter().filter(|(poly, _)| *poly == role).count(),
            multiplicity
        );
    }
}

#[test]
fn native_batch_fingerprint_matches_polynomials_scalars_and_full_walk() -> Result<()> {
    use test_steps::{Add, Leaf};

    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0xa04_0873);
    let left_leaf = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right_leaf = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let left = app.fuse(&mut rng, Add, (), left_leaf, right_leaf)?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(101))?.0;
    let parent = app.fuse(&mut rng, Add, (), left.clone(), right.clone())?.0;
    assert_eq!(*parent.data(), *left.data() + right.data());
    check_fingerprint(&app, parent.proof(), left.proof(), right.proof())?;
    assert!(app.verify(&parent, &mut rng)?);
    Ok(())
}
