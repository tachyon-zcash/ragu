//! Reviews A12 and T09: a false transient quotient at its real commitment
//! deadline, followed as an independently tagged semantic residual.
//!
//! The pre-alpha prefix is frozen. Only f/f_n is edited, before committing it
//! and squeezing u; the ordinary pipeline builds the entire remaining suffix.
//! The expanded batch below specifies both fields without production query,
//! evaluation, quotient, or Horner helpers. It retains the discarded quotient,
//! checks every coefficient of p and its point-stage commitment, and measures
//! the difference between p(u) and the honest batch evaluation. Parents and
//! descendants build fresh traces; expanded circuit equations identify the
//! evaluation/collapse obligation that carries the error at each generation.
//! Three-generation liveness checks use the actual challenge provenance and
//! reject models with a deleted edge, dropped circuit term, or a challenge
//! merged in from the preceding generation.
//! This is a fixed pre-u attack, not a post-u adaptive schedule experiment.

use alloc::{format, vec, vec::Vec};

use ragu_arithmetic::{CurveAffine, ff::PrimeField};
use ragu_circuits::registry::{CircuitIndex, Registry};
use ragu_primitives::{extract_endoscalar, lift_endoscalar};

use super::{
    test_steps::{Add, Leaf, Number},
    *,
};
use crate::{Pcd, internal::native, verify::VerificationChecks};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
type Poly<F> = sparse::Polynomial<F, R>;

#[derive(Clone, Copy, Debug)]
enum FieldSide {
    Native,
    Nested,
}

/// Independently specified native trace/stage order. The nested specification
/// is shared with A11, never with a production enumerator.
fn native_rxs() -> Vec<native::RxIndex> {
    use native::RxIndex::*;
    [
        Application,
        Hashes1,
        Hashes2,
        InnerCollapse,
        OuterCollapse,
        ComputeV,
    ]
    .into_iter()
    .chain((0..5).map(BindChallenges))
    .chain([BindBeta, BindEndoscalar])
    .chain((0..25).map(EndoscalingStep))
    .chain([
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
    ])
    .collect()
}

pub(super) fn power<F: Field>(base: F, exponent: usize) -> F {
    base.pow_vartime([exponent as u64])
}

pub(super) fn evaluate<F: Field>(coefficients: &[F], at: F) -> F {
    coefficients
        .iter()
        .rev()
        .fold(F::ZERO, |sum, c| sum * at + c)
}

/// Each polynomial occurs once in the beta batch. Repeated openings of that
/// polynomial remain separate (index, point) entries in the alpha batch.
pub(super) struct ExpandedBatch<F: PrimeField> {
    pub(super) polynomials: Vec<Poly<F>>,
    pub(super) queries: Vec<(usize, F)>,
    pub(super) alpha: F,
    pub(super) beta: F,
    pub(super) u: F,
}

impl<F: PrimeField> ExpandedBatch<F> {
    fn new(
        polynomials: Vec<Poly<F>>,
        [w, x, y, z, alpha, beta, u]: [F; 7],
        children: [[F; 3]; 2], // x, y, u
        application_ids: Option<[F; 2]>,
    ) -> Self {
        let native = application_ids.is_some();
        let rxs = if native { 49 } else { 42 };
        let width = rxs + 4;
        let tail = 2 * width;
        assert_eq!(polynomials.len(), if native { 112 } else { 98 });
        let [[lx, ly, lu], [rx, ry, ru]] = children;
        let mut queries = vec![
            (rxs + 3, lu),
            (width + rxs + 3, ru),
            (rxs + 2, w),
            (width + rxs + 2, w),
            (tail, ly),
            (tail + 1, ry),
            (tail, y),
            (tail + 1, y),
            (tail + 2, lx),
            (tail + 2, rx),
            (tail + 2, x),
            (tail + 5, w),
        ];
        if let Some([left, right]) = application_ids {
            queries.extend([(tail + 5, left), (tail + 5, right)]);
        }
        queries.extend([
            (rxs, x * z),
            (rxs + 1, x),
            (width + rxs, x * z),
            (width + rxs + 1, x),
            (tail + 3, x * z),
            (tail + 4, x),
        ]);
        for start in [0, width] {
            queries.extend((start..start + rxs).map(|i| (i, x * z)));
        }
        queries.extend(
            (0..if native { 52 } else { 45 }).map(|j| (tail + 5, CircuitIndex::new(j).omega_j())),
        );
        assert_eq!(queries.len(), if native { 170 } else { 147 });
        Self {
            polynomials,
            queries,
            alpha,
            beta,
            u,
        }
    }

    /// Dense long division and a separate rational evaluation, with explicit
    /// powers rather than the production factor_iter or batching routines.
    pub(super) fn quotient(&self) -> Vec<F> {
        let mut f = vec![F::ZERO; R::num_coeffs()];
        let mut rational = F::ZERO;
        for (slot, &(index, q)) in self.queries.iter().enumerate() {
            let coefficients: Vec<_> = self.polynomials[index].iter_coeffs().collect();
            let weight = power(self.alpha, self.queries.len() - 1 - slot);
            let mut carry = F::ZERO;
            for degree in (1..coefficients.len()).rev() {
                carry = coefficients[degree] + q * carry;
                f[degree - 1] += weight * carry;
            }
            assert_ne!(self.u, q, "fixture must avoid coincident openings");
            rational += weight
                * (evaluate(&coefficients, self.u) - evaluate(&coefficients, q))
                * (self.u - q).invert().unwrap();
        }
        assert_eq!(evaluate(&f, self.u), rational);
        f
    }

    pub(super) fn accumulate(&self, f: &[F]) -> Vec<F> {
        let mut p: Vec<_> = f
            .iter()
            .map(|c| *c * power(self.beta, self.polynomials.len()))
            .collect();
        for (slot, poly) in self.polynomials.iter().enumerate() {
            let weight = power(self.beta, self.polynomials.len() - 1 - slot);
            for (sum, coefficient) in p.iter_mut().zip(poly.iter_coeffs()) {
                *sum += weight * coefficient;
            }
        }
        p
    }
}

pub(super) fn native_batch(
    app: &App,
    proof: &Proof<C, R>,
    children: [&Proof<C, R>; 2],
) -> ExpandedBatch<Fp> {
    let mut polynomials = Vec::new();
    for child in children {
        polynomials.extend(native_rxs().into_iter().map(|id| child[id].clone()));
        polynomials.extend([
            child.native_a_poly.clone(),
            child.native_b_poly.clone(),
            child.native_registry_xy_poly().clone(),
            child.native_p_poly().clone(),
        ]);
    }
    let registry = app.native_registry.at(proof.w());
    polynomials.extend([
        ReferenceBackend::registry_at_x(&registry, children[0].x()),
        ReferenceBackend::registry_at_x(&registry, children[1].x()),
        ReferenceBackend::registry_at_y(&registry, proof.y()),
        proof.native_a_poly.clone(),
        proof.native_b_poly.clone(),
        proof.native_registry_xy_poly().clone(),
    ]);
    ExpandedBatch::new(
        polynomials,
        [
            proof.w(),
            proof.x(),
            proof.y(),
            proof.z(),
            proof.alpha(),
            lift_endoscalar(extract_endoscalar(proof.pre_beta()).expect("canonical pre_beta")),
            proof.u(),
        ],
        children.map(|child| [child.x(), child.y(), child.u()]),
        Some(children.map(|child| child.circuit_id().omega_j())),
    )
}

pub(super) fn nested_batch(
    app: &App,
    proof: &Proof<C, R>,
    children: [&Proof<C, R>; 2],
) -> Result<ExpandedBatch<Fq>> {
    let lift = nested::challenge::<C>;
    let mut polynomials = Vec::new();
    for child in children {
        polynomials.extend(
            batch_fingerprint_tests::rx_order()
                .into_iter()
                .map(|id| child[id].clone()),
        );
        polynomials.extend([
            child.nested_a_poly.clone(),
            child.nested_b_poly.clone(),
            child.nested_registry_xy_poly().clone(),
            child.nested_p_poly().clone(),
        ]);
    }
    let registry = app.nested_registry.at(lift(proof.w())?);
    polynomials.extend([
        ReferenceBackend::registry_at_x(&registry, lift(children[0].x())?),
        ReferenceBackend::registry_at_x(&registry, lift(children[1].x())?),
        ReferenceBackend::registry_at_y(&registry, lift(proof.y())?),
        proof.nested_a_poly.clone(),
        proof.nested_b_poly.clone(),
        proof.nested_registry_xy_poly().clone(),
    ]);
    let ch = |p: &Proof<C, R>| -> Result<_> { Ok([lift(p.x())?, lift(p.y())?, lift(p.u())?]) };
    Ok(ExpandedBatch::new(
        polynomials,
        [
            lift(proof.w())?,
            lift(proof.x())?,
            lift(proof.y())?,
            lift(proof.z())?,
            lift(proof.alpha())?,
            lift(proof.pre_beta())?,
            lift(proof.u())?,
        ],
        [ch(children[0])?, ch(children[1])?],
        None,
    ))
}

#[derive(Default)]
struct Quotients {
    native: Vec<Fp>,
    nested: Vec<Fq>,
}

fn perturb<F: PrimeField>(poly: &mut Poly<F>, degree: usize) {
    let mut coefficients: Vec<_> = poly.iter_coeffs().collect();
    coefficients[degree] += F::from(7);
    *poly = Poly::from_coeffs(coefficients);
}

/// Refuse an erased or moved attack. Tests also
/// deliberately supply the honest quotient to calibrate this harness guard.
fn preserved<F: PrimeField>(honest: &[F], changed: &[F], degree: usize) -> bool {
    honest.len() == changed.len()
        && honest
            .iter()
            .zip(changed)
            .enumerate()
            .all(|(i, (a, b))| *b - a == if i == degree { F::from(7) } else { F::ZERO })
}

fn check_batch<F: PrimeField>(
    batch: &ExpandedBatch<F>,
    captured: Option<(&[F], &[F])>,
    attacked_degree: Option<usize>,
    actual_p: &Poly<F>,
    actual_v: F,
) -> (Vec<F>, F) {
    let honest_f = batch.quotient();
    let f = if let Some((before, after)) = captured {
        assert_eq!(
            before, honest_f,
            "independently expanded transient quotient"
        );
        if let Some(degree) = attacked_degree {
            assert!(
                preserved(before, after, degree),
                "repair erased or moved the attack"
            );
            assert!(
                !preserved(before, before, degree),
                "honest repair must fail the guard"
            );
        } else {
            assert_eq!(before, after);
        }
        after
    } else {
        assert!(attacked_degree.is_none());
        &honest_f
    };
    let p = batch.accumulate(f);
    assert!(
        actual_p.iter_coeffs().eq(p.iter().copied()),
        "discarded f must remain in every coefficient of p"
    );
    assert_eq!(actual_v, evaluate(&p, batch.u));
    let expected_v = evaluate(&batch.accumulate(&honest_f), batch.u);
    let residual = actual_v - expected_v;
    let expected_residual = attacked_degree.map_or(F::ZERO, |degree| {
        F::from(7) * power(batch.u, degree) * power(batch.beta, batch.polynomials.len())
    });
    assert_eq!(
        residual, expected_residual,
        "quotient error survives beta batching"
    );
    if attacked_degree.is_some() {
        assert_ne!(residual, F::ZERO, "fixture cannot erase the false relation");
    }
    // A representation that drops the leading quotient cannot satisfy this
    // coefficient oracle, even if another representation shares the omission.
    assert_ne!(p, batch.accumulate(&vec![F::ZERO; R::num_coeffs()]));
    (f.to_vec(), residual)
}

pub(super) fn raw_stage<F: PrimeField, S: Stage<F, R>>(rx: &Poly<F>) -> Vec<F> {
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

fn coordinates<G: CurveAffine>(point: G) -> [G::Base; 2] {
    let coordinates = point.coordinates().unwrap();
    [*coordinates.x(), *coordinates.y()]
}

pub(super) fn revdot<F: Field>(a: &Poly<F>, b: &Poly<F>) -> F {
    let b: Vec<_> = b.iter_coeffs().collect();
    a.iter_coeffs()
        .zip(b.into_iter().rev())
        .map(|(a, b)| a * b)
        .sum()
}

/// Expand a named circuit's equation directly from its trace constituents and
/// registry wiring. No claim builder, claim enumerator, sparse revdot, or
/// production dilation/t(z) helper participates in this terminal oracle.
pub(super) fn circuit_value<F: PrimeField>(
    registry: &Registry<'_, F, R>,
    circuit: CircuitIndex,
    rxs: &[&Poly<F>],
    y: F,
    z: F,
) -> F {
    let mut a = vec![F::ZERO; R::num_coeffs()];
    for rx in rxs {
        for (sum, c) in a.iter_mut().zip(rx.iter_coeffs()) {
            *sum += c;
        }
    }
    let mut zp = vec![F::ONE; R::num_coeffs()];
    for i in 1..zp.len() {
        zp[i] = zp[i - 1] * z;
    }
    let sy = ReferenceBackend::registry_circuit_y(registry, circuit, y);
    let mut b: Vec<_> = a
        .iter()
        .zip(&zp)
        .zip(sy.iter_coeffs())
        .map(|((a, z), s)| *a * z + s)
        .collect();
    for i in 0..R::n() {
        b[4 * R::n() - 1 - i] -= zp[2 * R::n() - 1 - i] + zp[2 * R::n() + i];
    }
    a.into_iter()
        .zip(b.into_iter().rev())
        .map(|(a, b)| a * b)
        .sum()
}

fn ky<F: Field>(wires: &[F], y: F) -> F {
    F::ONE
        + wires
            .iter()
            .enumerate()
            .map(|(i, value)| *value * power(y, wires.len() - i))
            .sum::<F>()
}

/// The instance wire orders are written out independently of Output::write,
/// Output::ky, and the claim builders used by both prover and verifier.
pub(super) fn native_instance_wires(proof: &Proof<C, R>) -> Vec<Fp> {
    let mut wires = Vec::new();
    wires.extend(coordinates(proof.bridge_preamble_commitment()));
    wires.push(proof.w());
    wires.extend(coordinates(proof.bridge_s_prime_commitment()));
    wires.extend([proof.y(), proof.z()]);
    wires.extend(coordinates(proof.bridge_inner_error_commitment()));
    wires.extend([proof.mu(), proof.nu()]);
    wires.extend(coordinates(proof.bridge_outer_error_commitment()));
    wires.extend([
        proof.mu_prime(),
        proof.nu_prime(),
        revdot(&proof.native_a_poly, &proof.native_b_poly),
    ]);
    wires.extend(coordinates(proof.bridge_ab_commitment()));
    wires.push(proof.x());
    wires.extend(coordinates(proof.bridge_query_commitment()));
    wires.push(proof.alpha());
    wires.extend(coordinates(proof.bridge_f_commitment()));
    wires.push(proof.u());
    wires.extend(coordinates(proof.bridge_eval_commitment()));
    wires.extend([proof.pre_beta(), proof.v()]);
    for point in [
        proof.nested_challenges_partial(),
        proof.nested_p_commitment(),
        proof.nested_a_commitment(),
        proof.nested_b_commitment(),
        proof.nested_registry_xy_commitment(),
    ] {
        wires.extend(coordinates(point));
    }
    assert_eq!(wires.len(), 39);
    wires
}

pub(super) fn native_ky(proof: &Proof<C, R>, y: Fp) -> Fp {
    let mut wires = native_instance_wires(proof);
    wires.push(Fp::ZERO); // Internal-circuit suffix, before k's constant 1.
    ky(&wires, y)
}

pub(super) fn nested_ky(proof: &Proof<C, R>, y: Fq) -> Result<Fq> {
    let mut wires = vec![
        revdot(&proof.nested_a_poly, &proof.nested_b_poly),
        proof.nested_v()?,
        nested::challenge::<C>(proof.x())?,
        nested::challenge::<C>(proof.y())?,
        nested::challenge::<C>(proof.u())?,
    ];
    for point in [
        proof.native_rx_commitment(native::RxIndex::Preamble),
        proof.native_rx_commitment(native::RxIndex::InnerError),
        proof.native_rx_commitment(native::RxIndex::OuterError),
        proof.native_rx_commitment(native::RxIndex::Query),
        proof.native_rx_commitment(native::RxIndex::Eval),
        proof.native_commitment(native::RxComponent::AbA),
        proof.native_commitment(native::RxComponent::AbB),
        proof.native_registry_xy_commitment(),
        proof.native_p_commitment(),
        proof.native_rx_commitment(native::RxIndex::PointsBinding),
        proof.native_rx_commitment(native::RxIndex::PointsChildren),
        proof.native_rx_commitment(native::RxIndex::PointsRegistryWx),
        proof.native_rx_commitment(native::RxIndex::PointsAb),
        proof.native_rx_commitment(native::RxIndex::PointsF),
    ] {
        wires.extend(coordinates(point));
    }
    assert_eq!(wires.len(), 33);
    Ok(ky(&wires, y))
}

fn check_terminal_equations(
    app: &App,
    proof: &Proof<C, R>,
    attack: Option<FieldSide>,
    descendant: bool,
) -> Result<(Fp, Fq)> {
    let native_y = Fp::from(29);
    let native_z = Fp::from(31);
    let nested_y = Fq::from(37);
    let nested_z = Fq::from(41);
    let native_ky = native_ky(proof, native_y);
    let mut native_v_error = Fp::ZERO;
    for (circuit, ids, evaluation) in [
        (
            native::InternalCircuitIndex::ComputeVCircuit,
            vec![
                native::RxIndex::ComputeV,
                native::RxIndex::Preamble,
                native::RxIndex::Query,
                native::RxIndex::Eval,
            ],
            true,
        ),
        (
            native::InternalCircuitIndex::OuterCollapseCircuit,
            vec![
                native::RxIndex::OuterCollapse,
                native::RxIndex::Preamble,
                native::RxIndex::OuterError,
            ],
            false,
        ),
    ] {
        let residual = circuit_value(
            &app.native_registry,
            circuit.circuit_index(),
            &ids.into_iter().map(|id| &proof[id]).collect::<Vec<_>>(),
            native_y,
            native_z,
        ) - native_ky;
        if evaluation {
            native_v_error = residual;
        }
        assert_eq!(
            residual != Fp::ZERO,
            matches!(attack, Some(FieldSide::Native)) && evaluation != descendant,
            "expanded native {circuit:?}, descendant={descendant}"
        );
    }
    let nested_ky = nested_ky(proof, nested_y)?;
    let mut nested_v_error = Fq::ZERO;
    for (circuit, own, evaluation) in [
        (
            nested::InternalCircuitIndex::ComputeV,
            nested::RxIndex::ComputeV,
            true,
        ),
        (
            nested::InternalCircuitIndex::Collapse,
            nested::RxIndex::Collapse,
            false,
        ),
    ] {
        use nested::RxIndex::*;
        let ids = [
            own,
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
        ];
        let residual = circuit_value(
            &app.nested_registry,
            circuit.circuit_index(),
            &ids.map(|id| &proof[id]),
            nested_y,
            nested_z,
        ) - nested_ky;
        if evaluation {
            nested_v_error = residual;
        }
        assert_eq!(
            residual != Fq::ZERO,
            matches!(attack, Some(FieldSide::Nested)) && evaluation != descendant,
            "expanded nested {circuit:?}, descendant={descendant}"
        );
    }
    Ok((native_v_error, nested_v_error))
}

/// O07 entry point for an honest proof. It keeps the attack-specific types in
/// this module while exposing the independent terminal equations to the
/// expanded-witness tree checker.
#[cfg(feature = "unstable-fuzzing")]
pub(super) fn check_honest_terminal(app: &App, proof: &Proof<C, R>) -> Result<()> {
    check_terminal_equations(app, proof, None, false).map(|_| ())
}

/// Review T09: identify the semantic relation carrying a tagged error at a
/// generation boundary. A fresh quotient error first appears in ComputeV;
/// after one fusion, the resulting child is false at Collapse. The names and
/// positions below are an independent, finite specification of the claim
/// inventory rather than indices obtained from the production builders.
#[derive(Clone, Copy, Debug)]
enum LiveRelation {
    ComputeV,
    Collapse,
}

fn native_relation_residual(
    app: &App,
    proof: &Proof<C, R>,
    relation: LiveRelation,
    y: Fp,
    z: Fp,
    drop_own_trace: bool,
) -> Fp {
    use native::RxIndex::*;
    let (circuit, mut ids) = match relation {
        LiveRelation::ComputeV => (
            native::InternalCircuitIndex::ComputeVCircuit,
            vec![ComputeV, Preamble, Query, Eval],
        ),
        LiveRelation::Collapse => (
            native::InternalCircuitIndex::OuterCollapseCircuit,
            vec![OuterCollapse, Preamble, OuterError],
        ),
    };
    if drop_own_trace {
        ids.remove(0);
    }
    circuit_value(
        &app.native_registry,
        circuit.circuit_index(),
        &ids.into_iter().map(|id| &proof[id]).collect::<Vec<_>>(),
        y,
        z,
    ) - native_ky(proof, y)
}

fn nested_relation_residual(
    app: &App,
    proof: &Proof<C, R>,
    relation: LiveRelation,
    y: Fq,
    z: Fq,
    drop_own_trace: bool,
) -> Result<Fq> {
    use nested::RxIndex::*;
    let (circuit, own) = match relation {
        LiveRelation::ComputeV => (nested::InternalCircuitIndex::ComputeV, ComputeV),
        LiveRelation::Collapse => (nested::InternalCircuitIndex::Collapse, Collapse),
    };
    let mut ids = vec![
        own,
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
    ];
    if drop_own_trace {
        ids.remove(0);
    }
    Ok(circuit_value(
        &app.nested_registry,
        circuit.circuit_index(),
        &ids.into_iter().map(|id| &proof[id]).collect::<Vec<_>>(),
        y,
        z,
    ) - nested_ky(proof, y)?)
}

/// Explicit row-major expansion of the committed second fold. This is kept
/// local to the liveness oracle so neither its stored-value interpretation nor
/// its challenge provenance comes from the production fold implementation.
fn expanded_outer_value<F: Field>(values: &[F], groups: usize, mu: F, nu: F) -> F {
    let inverse = mu.invert().unwrap();
    let mut sum = F::ZERO;
    let mut index = 0;
    for i in 0..groups {
        for j in 0..groups {
            if i != j {
                sum +=
                    values[index] * power(inverse, groups - 1 - i) * power(mu * nu, groups - 1 - j);
                index += 1;
            }
        }
    }
    for i in 0..groups {
        sum += values[index + i] * power(nu, groups - 1 - i);
    }
    sum
}

/// The coefficient of a diagonal claim at `index` in the padded 7-by-groups
/// fold. It deliberately does not use ClaimFolder or either claims iterator.
fn live_claim_weight<F: Field>(nu: F, nu_prime: F, groups: usize, index: usize) -> F {
    power(nu, 6 - index % 7) * power(nu_prime, groups - 1 - index / 7)
}

/// Follow one semantic residual tag across one generation of a real proof
/// tree. The controls are deliberately wrong models: deleting the transfer,
/// omitting the relation's own trace, or reusing the child's folding
/// challenges must all disagree with the committed accumulator residual.
fn check_live_tag(
    app: &App,
    child: &Proof<C, R>,
    parent: &Proof<C, R>,
    side: FieldSide,
    child_on_left: bool,
    generation: usize,
) -> Result<()> {
    let relation = if generation == 0 {
        LiveRelation::ComputeV
    } else {
        LiveRelation::Collapse
    };
    let child_slot = usize::from(!child_on_left);
    match side {
        FieldSide::Native => {
            // Native two-proof claim positions: ComputeV is 12/13 and
            // OuterCollapse is 10/11. The fold has 19 padded groups.
            let index = match relation {
                LiveRelation::ComputeV => 12 + child_slot,
                LiveRelation::Collapse => 10 + child_slot,
            };
            let residual =
                native_relation_residual(app, child, relation, parent.y(), parent.z(), false);
            let dropped =
                native_relation_residual(app, child, relation, parent.y(), parent.z(), true);
            let values = raw_stage::<
                Fp,
                native::stages::outer_error::Stage<C, R, HEADER_SIZE, native::RevdotParameters>,
            >(&parent[native::RxIndex::OuterError]);
            let actual = revdot(&parent.native_a_poly, &parent.native_b_poly)
                - expanded_outer_value(&values, 19, parent.mu_prime(), parent.nu_prime());
            let weight = live_claim_weight(parent.nu(), parent.nu_prime(), 19, index);
            let expected = residual * weight;
            assert_ne!(residual, Fp::ZERO, "live native semantic tag");
            assert_eq!(actual, expected, "native tag at generation {generation}");
            assert_ne!(actual, Fp::ZERO, "deleted native transfer edge");
            assert_ne!(actual, dropped * weight, "dropped native circuit term");
            let merged = residual * live_claim_weight(child.nu(), child.nu_prime(), 19, index);
            assert_ne!(actual, merged, "merged native generation challenges");
        }
        FieldSide::Nested => {
            // Nested two-proof claim positions: ComputeV is 62/63 and
            // Collapse is 60/61. The fold has 12 padded groups.
            let index = match relation {
                LiveRelation::ComputeV => 62 + child_slot,
                LiveRelation::Collapse => 60 + child_slot,
            };
            let y = nested::challenge::<C>(parent.y())?;
            let z = nested::challenge::<C>(parent.z())?;
            let residual = nested_relation_residual(app, child, relation, y, z, false)?;
            let dropped = nested_relation_residual(app, child, relation, y, z, true)?;
            let values = raw_stage::<
                Fq,
                nested::stages::outer_error::Stage<<C as Cycle>::HostCurve, R>,
            >(&parent[nested::RxIndex::BridgeOuterError]);
            let mu_prime = nested::challenge::<C>(parent.mu_prime())?;
            let nu = nested::challenge::<C>(parent.nu())?;
            let nu_prime = nested::challenge::<C>(parent.nu_prime())?;
            let actual = revdot(&parent.nested_a_poly, &parent.nested_b_poly)
                - expanded_outer_value(&values[2..], 12, mu_prime, nu_prime);
            let weight = live_claim_weight(nu, nu_prime, 12, index);
            let expected = residual * weight;
            assert_ne!(residual, Fq::ZERO, "live nested semantic tag");
            assert_eq!(actual, expected, "nested tag at generation {generation}");
            assert_ne!(actual, Fq::ZERO, "deleted nested transfer edge");
            assert_ne!(actual, dropped * weight, "dropped nested circuit term");
            let child_nu = nested::challenge::<C>(child.nu())?;
            let child_nu_prime = nested::challenge::<C>(child.nu_prime())?;
            let merged = residual * live_claim_weight(child_nu, child_nu_prime, 12, index);
            assert_ne!(actual, merged, "merged nested generation challenges");
        }
    }
    Ok(())
}

fn check_expanded(
    app: &App,
    node: &Node,
    children: [&Proof<C, R>; 2],
    captured: Option<(&Quotients, &Quotients)>,
    attack: Option<(FieldSide, usize)>,
) -> Result<(Fp, Fq)> {
    let proof = node.proof();
    let native = native_batch(app, proof, children);
    let nested = nested_batch(app, proof, children)?;
    let (native_f, native_residual) = check_batch(
        &native,
        captured.map(|(a, b)| (a.native.as_slice(), b.native.as_slice())),
        attack.and_then(|(side, degree)| matches!(side, FieldSide::Native).then_some(degree)),
        proof.native_p_poly(),
        proof.v(),
    );
    let (nested_f, nested_residual) = check_batch(
        &nested,
        captured.map(|(a, b)| (a.nested.as_slice(), b.nested.as_slice())),
        attack.and_then(|(side, degree)| matches!(side, FieldSide::Nested).then_some(degree)),
        proof.nested_p_poly(),
        proof.nested_v()?,
    );
    let native_f = ReferenceBackend::sparse_commit_to_affine(
        &Poly::from_coeffs(native_f),
        C::host_generators(app.params),
    );
    let nested_f = ReferenceBackend::sparse_commit_to_affine(
        &Poly::from_coeffs(nested_f),
        C::nested_generators(app.params),
    );
    let native_p = ReferenceBackend::sparse_commit_to_affine(
        proof.native_p_poly(),
        C::host_generators(app.params),
    );
    let nested_p = ReferenceBackend::sparse_commit_to_affine(
        proof.nested_p_poly(),
        C::nested_generators(app.params),
    );
    assert_eq!(native_p, proof.native_p_commitment());
    assert_eq!(nested_p, proof.nested_p_commitment());
    let bridge =
        raw_stage::<Fq, nested::stages::f::Stage<<C as Cycle>::HostCurve, R>>(&proof.bridge_f_rx);
    assert_eq!(
        bridge[..2],
        coordinates(native_f),
        "native f was committed before u"
    );
    let points = raw_stage::<Fp, native::stages::points::FStage<<C as Cycle>::NestedCurve>>(
        &proof.native_points_f_rx,
    );
    assert_eq!(
        points[2..4],
        coordinates(nested_f),
        "nested f was committed before u"
    );
    let walk =
        raw_stage::<Fq, nested::PointsStage<<C as Cycle>::HostCurve>>(&proof.nested_points_rx);
    assert_eq!(walk[walk.len() - 2..], coordinates(native_p));
    let walk = raw_stage::<Fp, native::stages::points::WalkStage<<C as Cycle>::NestedCurve>>(
        &proof.native_points_walk_rx,
    );
    assert_eq!(walk[walk.len() - 2..], coordinates(nested_p));
    Ok((native_residual, nested_residual))
}

/// O07 entry point for an honest proof and its actual children. This expands
/// both complete quotient batches, their P polynomials, evaluations, direct
/// commitments, and the two commitment-walk endpoints.
#[cfg(feature = "unstable-fuzzing")]
pub(super) fn check_honest_expanded(
    app: &App,
    node: &Node,
    children: [&Proof<C, R>; 2],
) -> Result<()> {
    check_expanded(app, node, children, None, None).map(|_| ())
}

fn check_decider(app: &App, node: &Node, attack: Option<FieldSide>, context: &str) -> Result<()> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(0xa12_dec1de))?;
    let checks = checks.expect("well-formed metadata must reach the decider");
    assert_eq!(accepted, checks.all());
    assert_eq!(
        checks,
        VerificationChecks {
            native_revdot: !matches!(attack, Some(FieldSide::Native)),
            nested_revdot: !matches!(attack, Some(FieldSide::Nested)),
            native_registry: true,
            nested_registry: true,
            nested_challenges: true,
            commitments: true,
            nested_points: true,
            transcript: true,
            ab_bridge: true,
            mesh: true,
        },
        "{context}"
    );
    Ok(())
}

pub(super) fn check_prefix(honest: &Proof<C, R>, changed: &Proof<C, R>) {
    const FROZEN_CHALLENGES_THROUGH_ALPHA: usize = 9;
    assert_eq!(
        &honest.challenges().in_order()[..FROZEN_CHALLENGES_THROUGH_ALPHA],
        &changed.challenges().in_order()[..FROZEN_CHALLENGES_THROUGH_ALPHA]
    );
    assert_eq!(honest.left_header(), changed.left_header());
    assert_eq!(honest.right_header(), changed.right_header());
    for id in [
        native::RxIndex::Application,
        native::RxIndex::Preamble,
        native::RxIndex::InnerError,
        native::RxIndex::OuterError,
        native::RxIndex::Query,
        native::RxIndex::PointsBinding,
        native::RxIndex::PointsChildren,
        native::RxIndex::PointsRegistryWx,
        native::RxIndex::PointsAb,
    ] {
        assert!(
            honest[id].iter_coeffs().eq(changed[id].iter_coeffs()),
            "frozen native {id:?}"
        );
        assert_eq!(
            honest.native_rx_commitment(id),
            changed.native_rx_commitment(id)
        );
    }
    for id in [
        nested::RxIndex::BridgePreamble,
        nested::RxIndex::BridgeSPrime,
        nested::RxIndex::BridgeInnerError,
        nested::RxIndex::BridgeOuterError,
        nested::RxIndex::BridgeAB,
        nested::RxIndex::BridgeQuery,
    ] {
        assert!(
            honest[id].iter_coeffs().eq(changed[id].iter_coeffs()),
            "frozen bridge {id:?}"
        );
        assert_eq!(
            honest.nested_rx_commitment(id),
            changed.nested_rx_commitment(id)
        );
    }
    for (a, b) in [
        (&honest.native_a_poly, &changed.native_a_poly),
        (&honest.native_b_poly, &changed.native_b_poly),
        (
            honest.native_registry_xy_poly(),
            changed.native_registry_xy_poly(),
        ),
    ] {
        assert!(a.iter_coeffs().eq(b.iter_coeffs()));
    }
    for (a, b) in [
        (&honest.nested_a_poly, &changed.nested_a_poly),
        (&honest.nested_b_poly, &changed.nested_b_poly),
        (
            honest.nested_registry_xy_poly(),
            changed.nested_registry_xy_poly(),
        ),
    ] {
        assert!(a.iter_coeffs().eq(b.iter_coeffs()));
    }
}

/// Calibrate the guard with an actual suffix replay that restores the honest
/// quotient. The resulting proof is valid, but is refused as an attack fixture.
fn check_erased_attack(
    app: &App,
    left: &Node,
    right: &Node,
    honest: &Node,
    side: FieldSide,
) -> Result<()> {
    fn edit_then_erase<F: PrimeField>(poly: &mut Poly<F>) -> bool {
        let before: Vec<_> = poly.iter_coeffs().collect();
        perturb(poly, 0);
        assert!(preserved(
            &before,
            &poly.iter_coeffs().collect::<Vec<_>>(),
            0
        ));
        *poly = Poly::from_coeffs(before.clone());
        preserved(&before, &poly.iter_coeffs().collect::<Vec<_>>(), 0)
    }
    let mut attack_preserved = true;
    let mut rng = StdRng::seed_from_u64(0xa12_f053);
    let repaired = app
        .fuse_inner(
            &mut rng,
            Add,
            (),
            left.clone(),
            right.clone(),
            |native, nested| {
                attack_preserved = match side {
                    FieldSide::Native => edit_then_erase(native),
                    FieldSide::Nested => edit_then_erase(nested),
                };
            },
            |_| Ok(None),
            &mut (),
        )?
        .0;
    assert!(!attack_preserved, "harness must refuse the erased attack");
    check_prefix(honest.proof(), repaired.proof());
    assert_eq!(
        honest.proof().challenges().in_order(),
        repaired.proof().challenges().in_order()
    );
    check_expanded(app, &repaired, [left.proof(), right.proof()], None, None)?;
    check_terminal_equations(app, repaired.proof(), None, false)?;
    check_decider(app, &repaired, None, "erased attack is an honest proof")
}

fn exercise(side: FieldSide) -> Result<()> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0xa12_873);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let sibling = app.seed(&mut rng, Leaf, Fp::from(101))?.0;
    let mut rng = StdRng::seed_from_u64(0xa12_f053);
    let honest = app.fuse(&mut rng, Add, (), left.clone(), right.clone())?.0;
    check_expanded(&app, &honest, [left.proof(), right.proof()], None, None)?;
    check_terminal_equations(&app, honest.proof(), None, false)?;
    check_decider(&app, &honest, None, "honest root")?;
    check_erased_attack(&app, &left, &right, &honest, side)?;

    // Constant and high-degree errors exercise both ends of the quotient's
    // coefficient range, on asymmetric, non-base-case child headers.
    for degree in [0, R::num_coeffs() - 2] {
        let mut rng = StdRng::seed_from_u64(0xa12_f053);
        let mut before = Quotients::default();
        let mut after = Quotients::default();
        let changed = app
            .fuse_inner(
                &mut rng,
                Add,
                (),
                left.clone(),
                right.clone(),
                |native, nested| {
                    before = Quotients {
                        native: native.iter_coeffs().collect(),
                        nested: nested.iter_coeffs().collect(),
                    };
                    match side {
                        FieldSide::Native => perturb(native, degree),
                        FieldSide::Nested => perturb(nested, degree),
                    }
                    after = Quotients {
                        native: native.iter_coeffs().collect(),
                        nested: nested.iter_coeffs().collect(),
                    };
                },
                |_| Ok(None),
                &mut (),
            )?
            .0;
        let context = format!("{side:?}, degree {degree}");
        assert_eq!(*changed.data(), Fp::from(62));
        check_prefix(honest.proof(), changed.proof());
        assert_ne!(
            honest.proof().u(),
            changed.proof().u(),
            "edited commitments precede u"
        );
        let residual = check_expanded(
            &app,
            &changed,
            [left.proof(), right.proof()],
            Some((&before, &after)),
            Some((side, degree)),
        )?;
        let equation_error = check_terminal_equations(&app, changed.proof(), Some(side), false)?;
        // v has twelve trailing k(Y) powers in the native instance and
        // thirty-two in the nested instance. The false batch value reaches
        // the independently expanded ComputeV equation with exactly this weight.
        assert_eq!(equation_error.0, -residual.0 * power(Fp::from(29), 12));
        assert_eq!(equation_error.1, -residual.1 * power(Fq::from(37), 32));
        check_decider(&app, &changed, Some(side), &context)?;

        // Follow every independent (field, coefficient, initial route) tag
        // through three ordinary fusions. The route alternates so both child
        // slots occur after the origin as well as at it.
        for on_left in [true, false] {
            let mut child = changed.clone();
            for generation in 0usize..3 {
                let child_on_left = on_left ^ !generation.is_multiple_of(2);
                let child_proof = child.proof().clone();
                let (l, r) = if child_on_left {
                    (child, sibling.clone())
                } else {
                    (sibling.clone(), child)
                };
                let parent = app.fuse(&mut rng, Add, (), l.clone(), r.clone())?.0;
                assert_eq!(*parent.data(), Fp::from(163 + 101 * generation as u64));
                check_expanded(&app, &parent, [l.proof(), r.proof()], None, None)?;
                check_live_tag(
                    &app,
                    &child_proof,
                    parent.proof(),
                    side,
                    child_on_left,
                    generation,
                )?;
                check_terminal_equations(&app, parent.proof(), Some(side), true)?;
                check_decider(
                    &app,
                    &parent,
                    Some(side),
                    &format!(
                        "{context}, descendant {}, child_on_left={child_on_left}",
                        generation + 1
                    ),
                )?;
                child = parent;
            }
        }
    }
    Ok(())
}

#[test]
fn native_transient_quotient_error_survives_discard_and_recursion() -> Result<()> {
    exercise(FieldSide::Native)
}

#[test]
fn nested_transient_quotient_error_survives_discard_and_recursion() -> Result<()> {
    exercise(FieldSide::Nested)
}
