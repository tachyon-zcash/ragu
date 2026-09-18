//! Review O07: retain and independently check an expanded fusion witness.
//!
//! The production proof intentionally discards six registry restrictions and
//! the two quotient polynomials. A test-only observer keeps those objects,
//! their commitments, and their child associations after the proof is built.
//! This file reconstructs the restrictions and both complete quotient batches
//! without the production PCS helpers, checks the P accumulations, all 99
//! polynomial-to-cache commitments, and the bridge ancestry (including every
//! one of the preamble's 228 wires), independently walks every commitment
//! through both P Horner accumulations, directly evaluates every scalar in the
//! error, Query and Eval bridge suffixes, and combines that with the independent
//! terminal and nested parent-fold checks used elsewhere in this module. It
//! also independently expands all 97 registered native and nested local
//! internal-circuit equations, with isolated omission or misroute controls for
//! every equation family. The native parent fold is reconstructed here
//! claim-by-claim, through both error stages and into A, B and c, across a
//! retained three-generation non-base tree.

use alloc::{borrow::Cow, vec, vec::Vec};

use ragu_arithmetic::{
    CurveAffine, Cycle,
    ff::{Field, PrimeField},
    group::{Curve, CurveAffine as _},
};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry},
};
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};
use ragu_primitives::{extract_endoscalar, lift_endoscalar, vec::Len};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R, check_nested_accumulator, quotient_transfer_tests,
    test_steps::{AddSquare, Leaf, Number},
    transcript_tests,
};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    fuse::{
        ExpandedWitness, SuffixAttack,
        claims::{
            FoldKey, NativeFuseBuilder, NativeFuseProofSource, NestedFuseBuilder,
            NestedFuseProofSource, TrackedPoly,
        },
    },
    internal::{endoscalar, fold_revdot, native, nested},
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
type Poly<F> = sparse::Polynomial<F, R>;
type NativeTracked<'a> = TrackedPoly<'a, FoldKey, Fp, R>;
type NativePoint = <C as Cycle>::HostCurve;
type NestedPoint = <C as Cycle>::NestedCurve;

#[derive(Clone)]
struct Retained {
    proof: Proof<C, R>,
    left: Proof<C, R>,
    right: Proof<C, R>,
    native_wx: [Poly<Fp>; 2],
    native_wx_commitments: [NativePoint; 2],
    nested_wx: [Poly<Fq>; 2],
    nested_wx_commitments: [NestedPoint; 2],
    native_wy: Poly<Fp>,
    native_wy_commitment: NativePoint,
    nested_wy: Poly<Fq>,
    nested_wy_commitment: NestedPoint,
    native_f: Poly<Fp>,
    native_f_commitment: NativePoint,
    nested_f: Poly<Fq>,
    nested_f_commitment: NestedPoint,
}

#[derive(Default)]
struct Recorder(Option<Retained>);

impl SuffixAttack<C, R> for Recorder {
    fn inspect(&mut self, witness: ExpandedWitness<'_, C, R>) {
        assert!(self.0.is_none(), "one recorder covers exactly one fusion");
        self.0 = Some(Retained {
            proof: witness.proof.clone(),
            left: witness.left.clone(),
            right: witness.right.clone(),
            native_wx: [
                witness.native_s_prime.registry_wx0_poly.clone(),
                witness.native_s_prime.registry_wx1_poly.clone(),
            ],
            native_wx_commitments: [
                witness.native_s_prime.registry_wx0_commitment,
                witness.native_s_prime.registry_wx1_commitment,
            ],
            nested_wx: [
                witness.nested_s_prime.registry_wx0_poly.clone(),
                witness.nested_s_prime.registry_wx1_poly.clone(),
            ],
            nested_wx_commitments: [
                witness.nested_s_prime.registry_wx0_commitment,
                witness.nested_s_prime.registry_wx1_commitment,
            ],
            native_wy: witness.registry_wy.poly.clone(),
            native_wy_commitment: witness.registry_wy.commitment,
            nested_wy: witness.nested_registry_wy.poly.clone(),
            nested_wy_commitment: witness.nested_registry_wy.commitment,
            native_f: witness.native_f.poly.clone(),
            native_f_commitment: witness.native_f.commitment,
            nested_f: witness.nested_f.poly.clone(),
            nested_f_commitment: witness.nested_f.commitment,
        });
    }
}

impl Recorder {
    fn take(self) -> Retained {
        self.0.expect("fusion must publish its expanded witness")
    }
}

#[derive(Debug)]
struct ExpandedChecks {
    registry_restrictions: bool,
    quotients: bool,
    accumulations: bool,
    direct_commitments: bool,
    commitment_caches: CommitmentCacheChecks,
    stage_associations: StageAssociationChecks,
    scalar_payloads: ScalarPayloadChecks,
    commitment_walks: CommitmentWalkChecks,
    local_equations: LocalEquationChecks,
}

impl ExpandedChecks {
    fn all(&self) -> bool {
        self.registry_restrictions
            && self.quotients
            && self.accumulations
            && self.direct_commitments
            && self.commitment_caches.all()
            && self.stage_associations.all()
            && self.scalar_payloads.all()
            && self.commitment_walks.all()
            && self.local_equations.all()
    }
}

#[derive(Debug)]
struct CommitmentCacheChecks {
    native_rx: bool,
    native_ab: bool,
    native_registry_xy: bool,
    native_p: bool,
    nested_rx: bool,
    nested_ab: bool,
    nested_registry_xy: bool,
    nested_p: bool,
}

impl CommitmentCacheChecks {
    fn all(&self) -> bool {
        self.native_rx
            && self.native_ab
            && self.native_registry_xy
            && self.native_p
            && self.nested_rx
            && self.nested_ab
            && self.nested_registry_xy
            && self.nested_p
    }
}

#[derive(Clone, Copy)]
enum CacheMutation {
    NativeRxMisroute,
    NestedRxMisroute,
}

#[derive(Debug)]
struct StageAssociationChecks {
    bridge_preamble: bool,
    bridge_s_prime: bool,
    bridge_inner_error: bool,
    bridge_outer_error: bool,
    bridge_ab: bool,
    bridge_query: bool,
    bridge_f: bool,
    bridge_eval: bool,
    points_registry_wx: bool,
    points_ab: bool,
    points_f: bool,
}

impl StageAssociationChecks {
    fn all(&self) -> bool {
        self.bridge_preamble
            && self.bridge_s_prime
            && self.bridge_inner_error
            && self.bridge_outer_error
            && self.bridge_ab
            && self.bridge_query
            && self.bridge_f
            && self.bridge_eval
            && self.points_registry_wx
            && self.points_ab
            && self.points_f
    }
}

#[derive(Clone, Copy)]
enum StageMutation {
    PreambleChildQueryMisroute,
    BridgeQuerySourceMisroute,
}

#[derive(Debug)]
struct ScalarPayloadChecks {
    bridge_inner_error: bool,
    bridge_outer_error: bool,
    bridge_query: bool,
    bridge_eval: bool,
}

impl ScalarPayloadChecks {
    fn all(&self) -> bool {
        self.bridge_inner_error && self.bridge_outer_error && self.bridge_query && self.bridge_eval
    }
}

#[derive(Clone, Copy)]
enum ScalarPayloadMutation {
    InnerError,
    OuterCollapsed,
    QueryChildRx,
    EvalCurrent,
}

#[derive(Debug)]
struct CommitmentWalkChecks {
    native_inputs: bool,
    native_endoscalar: bool,
    native_interstitials: bool,
    native_endpoint: bool,
    nested_inputs: bool,
    nested_endoscalar: bool,
    nested_interstitials: bool,
    nested_endpoint: bool,
}

impl CommitmentWalkChecks {
    fn all(&self) -> bool {
        self.native_inputs
            && self.native_endoscalar
            && self.native_interstitials
            && self.native_endpoint
            && self.nested_inputs
            && self.nested_endoscalar
            && self.nested_interstitials
            && self.nested_endpoint
    }
}

#[derive(Clone, Copy)]
enum WalkMutation {
    NestedInputMisroute,
    NativeInputOmission,
    NestedInputOmission,
}

#[derive(Debug)]
struct LocalEquationChecks {
    native_logic: bool,
    native_stage_masks: bool,
    native_final_masks: bool,
    nested_logic: bool,
    nested_stage_masks: bool,
    nested_final_masks: bool,
    nested_loading: bool,
}

impl LocalEquationChecks {
    fn all(&self) -> bool {
        self.native_logic
            && self.native_stage_masks
            && self.native_final_masks
            && self.nested_logic
            && self.nested_stage_masks
            && self.nested_final_masks
            && self.nested_loading
    }
}

#[derive(Clone, Copy)]
enum LocalEquationMutation {
    NativeLogicOmission,
    NativeStageMaskMisroute,
    NativeFinalMaskOmission,
    NestedLogicOmission,
    NestedStageMaskMisroute,
    NestedFinalMaskOmission,
    NestedLoadingOmission,
}

fn same_poly<F: Field>(left: &Poly<F>, right: &Poly<F>) -> bool {
    left.iter_coeffs().eq(right.iter_coeffs())
}

fn same_coefficients<F: Field>(poly: &Poly<F>, coefficients: &[F]) -> bool {
    poly.iter_coeffs().eq(coefficients.iter().copied())
}

fn coordinates<G: CurveAffine>(point: G) -> [G::Base; 2] {
    transcript_tests::coordinates(point)
}

fn flatten_points<G: CurveAffine>(points: &[G]) -> Vec<G::Base> {
    points.iter().copied().flat_map(coordinates).collect()
}

fn endoscalar_bits<F: Field>(endoscalar: u128) -> Vec<F> {
    (0..u128::BITS)
        .map(|bit| {
            if endoscalar & (1 << bit) == 0 {
                F::ZERO
            } else {
                F::ONE
            }
        })
        .collect()
}

// Deliberately explicit and independent of RxIndex::ALL. A protocol layout
// change must update the walk specification instead of silently changing both
// the production order and this expected order.
fn native_rx_order() -> Vec<native::RxIndex> {
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
    assert_eq!(order.len(), 49);
    assert_eq!(order.len(), native::RxIndex::NUM);
    order
}

fn nested_rx_order() -> Vec<nested::RxIndex> {
    use nested::RxIndex::*;
    let mut order: Vec<_> = (0..28).map(EndoscalingStep).collect();
    order.extend([
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
    ]);
    assert_eq!(order.len(), 42);
    assert_eq!(order.len(), nested::RxIndex::NUM);
    order
}

// Keep the internal-circuit order independent of `InternalCircuitIndex::ALL`.
// Query's fixed-registry suffix is indexed by this complete list.
fn nested_internal_order() -> Vec<nested::InternalCircuitIndex> {
    use nested::InternalCircuitIndex::*;
    let mut order: Vec<_> = (0..28).map(EndoscalingStep).collect();
    order.extend([
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
    ]);
    assert_eq!(order.len(), 45);
    assert_eq!(order.len(), nested::InternalCircuitIndex::NUM);
    order
}

/// Evaluate from the coefficient iterator directly, without the production
/// backend's sparse evaluator or the stage-witness constructors.
fn direct_eval<F: Field>(poly: &Poly<F>, point: F) -> F {
    poly.iter_coeffs()
        .rev()
        .fold(F::ZERO, |acc, coefficient| acc * point + coefficient)
}

/// Evaluate only a registered constraint polynomial against the sum of its
/// trace constituents. Stage masks, final-stage masks, and Loading use this
/// relation directly, without the circuit trace's dilation and boundary term.
fn constraint_value<F: PrimeField>(
    registry: &Registry<'_, F, R>,
    circuit: CircuitIndex,
    rxs: &[&Poly<F>],
    y: F,
) -> F {
    let (trace, constraint) = constraint_terms(registry, circuit, rxs, y);
    trace
        .into_iter()
        .zip(constraint)
        .map(|(trace, constraint)| trace * constraint)
        .sum()
}

/// Inject one coefficient prohibited by the registered mask. The complete
/// constraint must reject it, while deleting exactly the attacked mask term
/// must accept the resulting local counterexample.
fn constraint_value_with_omission_counterexample<F: PrimeField>(
    registry: &Registry<'_, F, R>,
    circuit: CircuitIndex,
    rxs: &[&Poly<F>],
    y: F,
) -> F {
    let (mut trace, mut constraint) = constraint_terms(registry, circuit, rxs, y);
    let honest: F = trace
        .iter()
        .zip(&constraint)
        .map(|(trace, constraint)| *trace * constraint)
        .sum();
    assert_eq!(honest, F::ZERO);

    let attacked = trace
        .iter()
        .zip(&constraint)
        .position(|(trace, constraint)| *trace == F::ZERO && *constraint != F::ZERO)
        .expect("final-mask omission control requires a prohibited coefficient");
    trace[attacked] += F::ONE;
    let complete: F = trace
        .iter()
        .zip(&constraint)
        .map(|(trace, constraint)| *trace * constraint)
        .sum();
    assert_ne!(complete, F::ZERO);

    constraint[attacked] = F::ZERO;
    let omitted: F = trace
        .iter()
        .zip(&constraint)
        .map(|(trace, constraint)| *trace * constraint)
        .sum();
    assert_eq!(omitted, F::ZERO);
    complete
}

fn constraint_terms<F: PrimeField>(
    registry: &Registry<'_, F, R>,
    circuit: CircuitIndex,
    rxs: &[&Poly<F>],
    y: F,
) -> (Vec<F>, Vec<F>) {
    let mut trace = vec![F::ZERO; R::num_coeffs()];
    for rx in rxs {
        for (sum, coefficient) in trace.iter_mut().zip(rx.iter_coeffs()) {
            *sum += coefficient;
        }
    }
    let constraint: Vec<_> = ReferenceBackend::registry_circuit_y(registry, circuit, y)
        .iter_coeffs()
        .rev()
        .collect();
    (trace, constraint)
}

fn omit_first_live(values: &mut [Fq], mut range: core::ops::Range<usize>, name: &str) {
    let slot = range
        .find(|&i| values[i] != Fq::ZERO)
        .unwrap_or_else(|| panic!("{name} omission control must have a live scalar"));
    values[slot] = Fq::ZERO;
}

// The preamble bridge deliberately uses the accumulation order rather than
// `RxIndex::ALL`. Keep this list independent of both so a routing edit cannot
// silently update the test oracle along with the witness builder.
fn preamble_child_points(proof: &Proof<C, R>, misroute_query: bool) -> Vec<NativePoint> {
    use native::{RxComponent, RxIndex::*};
    let mut points = Vec::new();
    points.extend([
        proof.native_rx_commitment(Application),
        proof.native_rx_commitment(Hashes1),
        proof.native_rx_commitment(Hashes2),
        proof.native_rx_commitment(InnerCollapse),
        proof.native_rx_commitment(OuterCollapse),
        proof.native_rx_commitment(ComputeV),
    ]);
    points.extend((0..5).map(|k| proof.native_rx_commitment(BindChallenges(k))));
    points.extend([
        proof.native_rx_commitment(BindBeta),
        proof.native_rx_commitment(BindEndoscalar),
    ]);
    points.extend((0..25).map(|step| proof.native_rx_commitment(EndoscalingStep(step))));
    points.push(proof.native_rx_commitment(PointsWalk));
    points.extend([
        proof.native_rx_commitment(Preamble),
        proof.native_rx_commitment(InnerError),
        proof.native_rx_commitment(OuterError),
        proof.native_rx_commitment(if misroute_query { Eval } else { Query }),
        proof.native_rx_commitment(Eval),
        proof.native_commitment(RxComponent::AbA),
        proof.native_commitment(RxComponent::AbB),
        proof.native_registry_xy_commitment(),
        proof.native_p_commitment(),
        proof.native_rx_commitment(PointsBinding),
        proof.native_rx_commitment(PointsChildren),
        proof.native_rx_commitment(PointsRegistryWx),
        proof.native_rx_commitment(PointsAb),
        proof.native_rx_commitment(PointsF),
    ]);
    assert_eq!(points.len(), native::RxIndex::NUM + 4);
    points
}

fn preamble_child_wires(proof: &Proof<C, R>, misroute_query: bool) -> Result<Vec<Fq>> {
    let mut wires = flatten_points(&preamble_child_points(proof, misroute_query));
    wires.extend([
        proof.nested_c(),
        proof.nested_v()?,
        nested::challenge::<C>(proof.x())?,
        nested::challenge::<C>(proof.y())?,
        nested::challenge::<C>(proof.u())?,
    ]);
    Ok(wires)
}

fn native_interstitials(
    points: &[NativePoint],
    beta: Fp,
    omitted: Option<usize>,
) -> Vec<NativePoint> {
    let mut result = Vec::new();
    let mut acc = points[0].to_curve();
    for (offset, input) in points[1..].iter().enumerate() {
        let point = offset + 1;
        acc *= beta;
        if omitted != Some(point) {
            acc += input.to_curve();
        }
        if point % 4 == 0 || point + 1 == points.len() {
            result.push(acc.to_affine());
        }
    }
    result
}

fn nested_interstitials(
    points: &[NestedPoint],
    beta: Fq,
    omitted: Option<usize>,
) -> Vec<NestedPoint> {
    let mut result = Vec::new();
    let mut acc = points[0].to_curve();
    for (offset, input) in points[1..].iter().enumerate() {
        let point = offset + 1;
        acc *= beta;
        if omitted != Some(point) {
            acc += input.to_curve();
        }
        if point % 4 == 0 || point + 1 == points.len() {
            result.push(acc.to_affine());
        }
    }
    result
}

/// The two child instances' native k(y) values, written out without the
/// production preamble gadget or its `Output::ky` helpers.
#[derive(Clone, Copy)]
struct NativeChildValues {
    raw_c: [Fp; 2],
    application: [Fp; 2],
    unified_bridge: [Fp; 2],
    unified: [Fp; 2],
}

impl native::claims::KySource for NativeChildValues {
    type Ky = Fp;

    fn raw_c(&self) -> impl Iterator<Item = Fp> {
        self.raw_c.into_iter()
    }

    fn application_ky(&self) -> impl Iterator<Item = Fp> {
        self.application.into_iter()
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = Fp> {
        self.unified_bridge.into_iter()
    }

    fn unified_ky(&self) -> impl Iterator<Item = Fp> + Clone {
        self.unified.into_iter()
    }

    fn ones(&self) -> impl Iterator<Item = Fp> + Clone {
        [Fp::ONE, Fp::ONE].into_iter()
    }

    fn zero(&self) -> Fp {
        Fp::ZERO
    }
}

#[derive(Clone, Copy)]
struct NestedChildValues {
    raw_c: [Fq; 2],
    unified: [Fq; 2],
}

impl nested::claims::KySource for NestedChildValues {
    type Ky = Fq;

    fn raw_c(&self) -> impl Iterator<Item = Fq> {
        self.raw_c.into_iter()
    }

    fn ones(&self) -> impl Iterator<Item = Fq> + Clone {
        [Fq::ONE, Fq::ONE].into_iter()
    }

    fn unified_ky(&self) -> impl Iterator<Item = Fq> + Clone {
        self.unified.into_iter()
    }

    fn zero(&self) -> Fq {
        Fq::ZERO
    }
}

fn instance_ky(wires: &[Fp], y: Fp) -> Fp {
    wires.iter().fold(Fp::ZERO, |acc, value| acc * y + value) * y + Fp::ONE
}

fn native_child_values(
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> NativeChildValues {
    let children = [left, right];
    let output_headers = [parent.left_header(), parent.right_header()];
    let mut application = [Fp::ZERO; 2];
    let mut unified_bridge = [Fp::ZERO; 2];
    let mut unified = [Fp::ZERO; 2];
    for i in 0..2 {
        let child = children[i];
        let mut application_wires = Vec::new();
        application_wires.extend(child.left_header());
        application_wires.extend(child.right_header());
        application_wires.extend(output_headers[i]);
        assert_eq!(application_wires.len(), 3 * HEADER_SIZE);
        application[i] = instance_ky(&application_wires, parent.y());

        let instance = quotient_transfer_tests::native_instance_wires(child);
        let mut bridge_wires = instance.clone();
        bridge_wires.extend(child.left_header());
        bridge_wires.extend(child.right_header());
        bridge_wires.push(Fp::ZERO);
        unified_bridge[i] = instance_ky(&bridge_wires, parent.y());

        let mut unified_wires = instance;
        unified_wires.push(Fp::ZERO);
        unified[i] = instance_ky(&unified_wires, parent.y());
    }
    NativeChildValues {
        raw_c: [left.native_c(), right.native_c()],
        application,
        unified_bridge,
        unified,
    }
}

/// Scalar form of one revdot collapse layer. Its row-major Horner loops are
/// intentionally separate from `ClaimFolder`, which is the circuit path.
fn fold_claim_values<F: Field>(errors: &[F], diagonal: &[F], mu: F, nu: F) -> F {
    let n = diagonal.len();
    assert_eq!(errors.len(), n * (n - 1));
    let mut errors = errors.iter().copied();
    let mut result = F::ZERO;
    for (i, diagonal) in diagonal.iter().enumerate() {
        let mut row = F::ZERO;
        for j in 0..n {
            let value = if i == j {
                *diagonal
            } else {
                errors.next().expect("one error per off-diagonal pair")
            };
            row = row * (mu * nu) + value;
        }
        result = result * mu.invert().unwrap() + row;
    }
    assert!(errors.next().is_none());
    result
}

fn check_native_accumulator(
    app: &App,
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<()> {
    type P = native::RevdotParameters;
    let source = NativeFuseProofSource { left, right };
    let mut claims = NativeFuseBuilder::<Fp, R, ReferenceBackend>::new(
        &app.native_registry,
        parent.y(),
        parent.z(),
    );
    native::claims::build(&source, &mut claims)?;
    let values = native_child_values(parent, left, right);
    let ky: Vec<_> = native::claims::ky_values(&values)
        .take(claims.a.len())
        .collect();
    assert_eq!(claims.a.len(), claims.b.len());
    assert_eq!(claims.a.len(), ky.len());
    for (i, ((a, b), expected)) in claims.a.iter().zip(&claims.b).zip(&ky).enumerate() {
        assert_eq!(
            ReferenceBackend::sparse_revdot(a.poly.as_ref(), b.as_ref()),
            *expected,
            "native claim {i} does not hold"
        );
    }

    let inner_errors = fold_revdot::inner_error_terms::<_, R, P>(&claims.a, &claims.b);
    let a_inner = fold_revdot::fold_inner::<NativeTracked<'_>, _, P>(
        &claims.a,
        parent.mu().invert().unwrap(),
    );
    let b_inner = fold_revdot::fold_inner::<Poly<Fp>, _, P>(&claims.b, parent.mu() * parent.nu());
    let outer_errors = fold_revdot::outer_error_terms::<_, R, P>(&a_inner, &b_inner);
    let collapsed: Vec<_> = a_inner
        .iter()
        .zip(b_inner.iter())
        .map(|(a, b)| ReferenceBackend::sparse_revdot(a.poly.as_ref(), b))
        .collect();

    let inner_stage = transcript_tests::raw_stage::<
        Fp,
        native::stages::inner_error::Stage<C, R, HEADER_SIZE, P>,
    >(&parent.native_inner_error_rx);
    assert!(
        inner_stage
            .iter()
            .eq(inner_errors.iter().flat_map(|group| group.iter())),
        "the native inner stage does not store the fold's error terms"
    );
    let outer_stage = transcript_tests::raw_stage::<
        Fp,
        native::stages::outer_error::Stage<C, R, HEADER_SIZE, P>,
    >(&parent.native_outer_error_rx);
    let (stored_outer_errors, rest) = outer_stage.split_at(outer_errors.len());
    let (stored_collapsed, rest) = rest.split_at(collapsed.len());
    let expected_ky = [
        values.application[0],
        values.unified[0],
        values.unified_bridge[0],
        values.application[1],
        values.unified[1],
        values.unified_bridge[1],
    ];
    assert_eq!(stored_outer_errors, &outer_errors[..]);
    assert_eq!(stored_collapsed, collapsed);
    assert_eq!(&rest[..expected_ky.len()], &expected_ky);

    for (name, rx, commitment) in [
        (
            "inner",
            &parent.native_inner_error_rx,
            parent.native_rx_commitment(native::RxIndex::InnerError),
        ),
        (
            "outer",
            &parent.native_outer_error_rx,
            parent.native_rx_commitment(native::RxIndex::OuterError),
        ),
    ] {
        assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(rx, C::host_generators(app.params)),
            commitment,
            "the native {name} stage commitment does not match its polynomial"
        );
    }

    let a_final = fold_revdot::fold_outer::<_, _, P>(a_inner, parent.mu_prime().invert().unwrap());
    let b_final =
        fold_revdot::fold_outer::<_, _, P>(b_inner, parent.mu_prime() * parent.nu_prime());
    assert!(same_poly(a_final.poly.as_ref(), &parent.native_a_poly));
    assert!(same_poly(&b_final, &parent.native_b_poly));
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(
            a_final.poly.as_ref(),
            C::host_generators(app.params),
        ),
        parent.native_commitment(native::RxComponent::AbA)
    );
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&b_final, C::host_generators(app.params)),
        parent.native_commitment(native::RxComponent::AbB)
    );

    let group_size = <P as fold_revdot::Parameters>::GroupSize::len();
    let groups = <P as fold_revdot::Parameters>::NumGroups::len();
    let mut padded_ky = ky;
    padded_ky.resize(group_size * groups, Fp::ZERO);
    let expected_collapsed: Vec<_> = inner_errors
        .iter()
        .zip(padded_ky.chunks_exact(group_size))
        .map(|(errors, diagonal)| {
            fold_claim_values(&errors[..], diagonal, parent.mu(), parent.nu())
        })
        .collect();
    assert_eq!(expected_collapsed, collapsed);
    let expected_c = fold_claim_values(
        &outer_errors[..],
        &expected_collapsed,
        parent.mu_prime(),
        parent.nu_prime(),
    );
    assert_eq!(parent.native_c(), expected_c);
    Ok(())
}

/// Delete the left application claim in-place, preserving every later slot.
/// All three independently checked layers must notice that omission.
fn check_native_claim_omission(
    app: &App,
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<()> {
    type P = native::RevdotParameters;
    const OMITTED: usize = 2; // [left raw, right raw, left application, ...]
    let source = NativeFuseProofSource { left, right };
    let mut claims = NativeFuseBuilder::<Fp, R, ReferenceBackend>::new(
        &app.native_registry,
        parent.y(),
        parent.z(),
    );
    native::claims::build(&source, &mut claims)?;
    let values = native_child_values(parent, left, right);
    let expected_ky = native::claims::ky_values(&values).nth(OMITTED).unwrap();
    assert_ne!(expected_ky, Fp::ZERO, "omission control must be live");
    claims.a[OMITTED].poly = Cow::Owned(Poly::default());
    claims.a[OMITTED].decomp = Default::default();
    claims.b[OMITTED] = Cow::Owned(Poly::default());
    assert_ne!(
        ReferenceBackend::sparse_revdot(
            claims.a[OMITTED].poly.as_ref(),
            claims.b[OMITTED].as_ref(),
        ),
        expected_ky,
        "the per-claim equation must detect the omitted application claim"
    );

    let mutant_inner = fold_revdot::inner_error_terms::<_, R, P>(&claims.a, &claims.b);
    let stored_inner = transcript_tests::raw_stage::<
        Fp,
        native::stages::inner_error::Stage<C, R, HEADER_SIZE, P>,
    >(&parent.native_inner_error_rx);
    assert!(
        !stored_inner
            .iter()
            .eq(mutant_inner.iter().flat_map(|group| group.iter())),
        "the stored inner errors must detect the omitted claim"
    );
    let mutant_a_inner = fold_revdot::fold_inner::<NativeTracked<'_>, _, P>(
        &claims.a,
        parent.mu().invert().unwrap(),
    );
    let mutant_b_inner =
        fold_revdot::fold_inner::<Poly<Fp>, _, P>(&claims.b, parent.mu() * parent.nu());
    let mutant_a =
        fold_revdot::fold_outer::<_, _, P>(mutant_a_inner, parent.mu_prime().invert().unwrap());
    let mutant_b =
        fold_revdot::fold_outer::<_, _, P>(mutant_b_inner, parent.mu_prime() * parent.nu_prime());
    assert!(
        !same_poly(mutant_a.poly.as_ref(), &parent.native_a_poly)
            || !same_poly(&mutant_b, &parent.native_b_poly),
        "the final native accumulator must detect the omitted claim"
    );
    Ok(())
}

/// Reconstruct the nested fold payloads from the two retained children. This
/// intentionally starts from the claim polynomials rather than either bridge
/// stage, so the two stage suffixes are only the observed side of the check.
fn nested_error_payloads(
    app: &App,
    parent: &Proof<C, R>,
    left: &Proof<C, R>,
    right: &Proof<C, R>,
) -> Result<(Vec<Fq>, Vec<Fq>)> {
    type P = nested::RevdotParameters;
    let source = NestedFuseProofSource { left, right };
    let y = nested::challenge::<C>(parent.y())?;
    let mut claims = NestedFuseBuilder::<Fq, R, ReferenceBackend>::new(
        &app.nested_registry,
        y,
        nested::challenge::<C>(parent.z())?,
    );
    nested::claims::build(&source, &mut claims)?;

    let mu = nested::challenge::<C>(parent.mu())?;
    let nu = nested::challenge::<C>(parent.nu())?;
    let inner = fold_revdot::inner_error_terms::<_, R, P>(&claims.a, &claims.b);
    let a_inner = fold_revdot::fold_inner::<Poly<Fq>, _, P>(
        &claims.a,
        mu.invert().expect("nested mu is nonzero"),
    );
    let b_inner = fold_revdot::fold_inner::<Poly<Fq>, _, P>(&claims.b, mu * nu);
    let outer = fold_revdot::outer_error_terms::<_, R, P>(&a_inner, &b_inner);
    let values = NestedChildValues {
        raw_c: [left.nested_c(), right.nested_c()],
        unified: [
            quotient_transfer_tests::nested_ky(left, y)?,
            quotient_transfer_tests::nested_ky(right, y)?,
        ],
    };
    let group_size = <P as fold_revdot::Parameters>::GroupSize::len();
    let groups = <P as fold_revdot::Parameters>::NumGroups::len();
    let mut ky: Vec<_> = nested::claims::ky_values(&values)
        .take(claims.a.len())
        .collect();
    ky.resize(group_size * groups, Fq::ZERO);
    let collapsed: Vec<_> = inner
        .iter()
        .zip(ky.chunks_exact(group_size))
        .map(|(errors, diagonal)| fold_claim_values(&errors[..], diagonal, mu, nu))
        .collect();

    let inner = inner
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    let outer = outer.iter().copied().chain(collapsed).collect();
    Ok((inner, outer))
}

impl Retained {
    /// Commit every polynomial separately instead of using the verifier's
    /// batched MSM check. This covers 49 native rx caches, 42 nested rx
    /// caches, both A/B pairs, both registry restrictions, and both P values.
    fn commitment_cache_checks(
        &self,
        app: &App,
        mutation: Option<CacheMutation>,
    ) -> CommitmentCacheChecks {
        let native_rx = native_rx_order().into_iter().all(|id| {
            let cached = if matches!(mutation, Some(CacheMutation::NativeRxMisroute))
                && id == native::RxIndex::Query
            {
                self.proof.native_rx_commitment(native::RxIndex::Eval)
            } else {
                self.proof.native_rx_commitment(id)
            };
            ReferenceBackend::sparse_commit_to_affine(
                &self.proof[id],
                C::host_generators(app.params),
            ) == cached
        });
        let native_ab = [native::RxComponent::AbA, native::RxComponent::AbB]
            .into_iter()
            .all(|component| {
                ReferenceBackend::sparse_commit_to_affine(
                    &self.proof[component],
                    C::host_generators(app.params),
                ) == self.proof.native_commitment(component)
            });
        let native_registry_xy = ReferenceBackend::sparse_commit_to_affine(
            self.proof.native_registry_xy_poly(),
            C::host_generators(app.params),
        ) == self.proof.native_registry_xy_commitment();
        let native_p = ReferenceBackend::sparse_commit_to_affine(
            self.proof.native_p_poly(),
            C::host_generators(app.params),
        ) == self.proof.native_p_commitment();

        let nested_rx = nested_rx_order().into_iter().all(|id| {
            let cached = if matches!(mutation, Some(CacheMutation::NestedRxMisroute))
                && id == nested::RxIndex::BridgeQuery
            {
                self.proof.nested_rx_commitment(nested::RxIndex::BridgeEval)
            } else {
                self.proof.nested_rx_commitment(id)
            };
            ReferenceBackend::sparse_commit_to_affine(
                &self.proof[id],
                C::nested_generators(app.params),
            ) == cached
        });
        let nested_ab = [
            (nested::RxComponent::AbA, self.proof.nested_a_commitment()),
            (nested::RxComponent::AbB, self.proof.nested_b_commitment()),
        ]
        .into_iter()
        .all(|(component, cached)| {
            ReferenceBackend::sparse_commit_to_affine(
                &self.proof[component],
                C::nested_generators(app.params),
            ) == cached
        });
        let nested_registry_xy = ReferenceBackend::sparse_commit_to_affine(
            self.proof.nested_registry_xy_poly(),
            C::nested_generators(app.params),
        ) == self.proof.nested_registry_xy_commitment();
        let nested_p = ReferenceBackend::sparse_commit_to_affine(
            self.proof.nested_p_poly(),
            C::nested_generators(app.params),
        ) == self.proof.nested_p_commitment();

        CommitmentCacheChecks {
            native_rx,
            native_ab,
            native_registry_xy,
            native_p,
            nested_rx,
            nested_ab,
            nested_registry_xy,
            nested_p,
        }
    }

    /// Check every point source copied into a bridge stage, plus the complete
    /// preamble ancestry for both children. The scalar suffixes of the error,
    /// Query and Eval bridges are checked by the independent fold and batch
    /// expansions; this checker owns their point-valued ancestry.
    fn stage_association_checks(
        &self,
        mutation: Option<StageMutation>,
    ) -> Result<StageAssociationChecks> {
        let mut expected_preamble = flatten_points(&[
            self.proof.native_rx_commitment(native::RxIndex::Preamble),
            self.proof
                .native_rx_commitment(native::RxIndex::PointsBinding),
            self.proof
                .native_rx_commitment(native::RxIndex::PointsChildren),
        ]);
        expected_preamble.extend(preamble_child_wires(
            &self.left,
            matches!(mutation, Some(StageMutation::PreambleChildQueryMisroute)),
        )?);
        expected_preamble.extend(preamble_child_wires(&self.right, false)?);
        assert_eq!(expected_preamble.len(), 228);
        let bridge_preamble =
            transcript_tests::raw_stage::<Fq, nested::stages::preamble::Stage<NativePoint, R>>(
                &self.proof.bridge_preamble_rx,
            ) == expected_preamble;

        let expected_s_prime = flatten_points(&[
            self.native_wx_commitments[0],
            self.native_wx_commitments[1],
            self.proof
                .native_rx_commitment(native::RxIndex::PointsRegistryWx),
        ]);
        let bridge_s_prime =
            transcript_tests::raw_stage::<Fq, nested::stages::s_prime::Stage<NativePoint, R>>(
                &self.proof.bridge_s_prime_rx,
            ) == expected_s_prime;

        let inner_error = transcript_tests::raw_stage::<
            Fq,
            nested::stages::inner_error::Stage<NativePoint, R>,
        >(&self.proof.bridge_inner_error_rx);
        let bridge_inner_error = inner_error[..4]
            == flatten_points(&[
                self.proof.native_rx_commitment(native::RxIndex::InnerError),
                self.native_wy_commitment,
            ]);

        let outer_error = transcript_tests::raw_stage::<
            Fq,
            nested::stages::outer_error::Stage<NativePoint, R>,
        >(&self.proof.bridge_outer_error_rx);
        let bridge_outer_error = outer_error[..2]
            == coordinates(self.proof.native_rx_commitment(native::RxIndex::OuterError));

        let bridge_ab = transcript_tests::raw_stage::<Fq, nested::stages::ab::Stage<NativePoint, R>>(
            &self.proof[nested::RxIndex::BridgeAB],
        ) == flatten_points(&[
            self.proof.native_commitment(native::RxComponent::AbA),
            self.proof.native_commitment(native::RxComponent::AbB),
            self.proof.native_rx_commitment(native::RxIndex::PointsAb),
        ]);

        let query_source = if matches!(mutation, Some(StageMutation::BridgeQuerySourceMisroute)) {
            native::RxIndex::Eval
        } else {
            native::RxIndex::Query
        };
        let query = transcript_tests::raw_stage::<Fq, nested::stages::query::Stage<NativePoint, R>>(
            &self.proof.bridge_query_rx,
        );
        let bridge_query = query[..4]
            == flatten_points(&[
                self.proof.native_rx_commitment(query_source),
                self.proof.native_registry_xy_commitment(),
            ]);

        let bridge_f = transcript_tests::raw_stage::<Fq, nested::stages::f::Stage<NativePoint, R>>(
            &self.proof.bridge_f_rx,
        ) == flatten_points(&[
            self.native_f_commitment,
            self.proof.native_rx_commitment(native::RxIndex::PointsF),
        ]);

        let eval = transcript_tests::raw_stage::<Fq, nested::stages::eval::Stage<NativePoint, R>>(
            &self.proof.bridge_eval_rx,
        );
        let bridge_eval =
            eval[..2] == coordinates(self.proof.native_rx_commitment(native::RxIndex::Eval));

        let points_registry_wx = transcript_tests::raw_stage::<
            Fp,
            native::stages::points::RegistryWxStage<NestedPoint>,
        >(&self.proof.native_points_registry_wx_rx)
            == flatten_points(&self.nested_wx_commitments);
        let points_ab =
            transcript_tests::raw_stage::<Fp, native::stages::points::AbStage<NestedPoint>>(
                &self.proof.native_points_ab_rx,
            ) == flatten_points(&[
                self.nested_wy_commitment,
                self.proof.nested_a_commitment(),
                self.proof.nested_b_commitment(),
            ]);
        let points_f = transcript_tests::raw_stage::<Fp, native::stages::points::FStage<NestedPoint>>(
            &self.proof.native_points_f_rx,
        ) == flatten_points(&[
            self.proof.nested_registry_xy_commitment(),
            self.nested_f_commitment,
        ]);

        Ok(StageAssociationChecks {
            bridge_preamble,
            bridge_s_prime,
            bridge_inner_error,
            bridge_outer_error,
            bridge_ab,
            bridge_query,
            bridge_f,
            bridge_eval,
            points_registry_wx,
            points_ab,
            points_f,
        })
    }

    /// Directly check every non-point value in the four scalar-bearing bridge
    /// stages. The expected Query and Eval inventories are constructed here in
    /// protocol order and evaluated with [`direct_eval`], independently of the
    /// production witness constructors and backend evaluation routines.
    fn scalar_payload_checks(
        &self,
        app: &App,
        mutation: Option<ScalarPayloadMutation>,
    ) -> Result<ScalarPayloadChecks> {
        let (mut expected_inner, mut expected_outer) =
            nested_error_payloads(app, &self.proof, &self.left, &self.right)?;
        if matches!(mutation, Some(ScalarPayloadMutation::InnerError)) {
            let len = expected_inner.len();
            omit_first_live(&mut expected_inner, 0..len, "inner-error");
        }
        if matches!(mutation, Some(ScalarPayloadMutation::OuterCollapsed)) {
            let collapsed = <nested::RevdotParameters as fold_revdot::Parameters>::NumGroups::len();
            let len = expected_outer.len();
            omit_first_live(&mut expected_outer, len - collapsed..len, "outer collapsed");
        }

        let inner = transcript_tests::raw_stage::<
            Fq,
            nested::stages::inner_error::Stage<NativePoint, R>,
        >(&self.proof.bridge_inner_error_rx);
        let outer = transcript_tests::raw_stage::<
            Fq,
            nested::stages::outer_error::Stage<NativePoint, R>,
        >(&self.proof.bridge_outer_error_rx);
        let bridge_inner_error = inner[4..] == expected_inner;
        let bridge_outer_error = outer[2..] == expected_outer;

        let w = nested::challenge::<C>(self.proof.w())?;
        let x = nested::challenge::<C>(self.proof.x())?;
        let z = nested::challenge::<C>(self.proof.z())?;
        let xz = x * z;
        let mut expected_query = Vec::new();
        expected_query.extend(nested_internal_order().into_iter().map(|id| {
            let point: Fq = id.circuit_index().omega_j();
            direct_eval(self.proof.nested_registry_xy_poly(), point)
        }));
        expected_query.push(direct_eval(self.proof.nested_registry_xy_poly(), w));
        for child in [&self.left, &self.right] {
            expected_query.extend(
                nested_rx_order()
                    .into_iter()
                    .map(|id| direct_eval(&child[id], xz)),
            );
            expected_query.extend([
                direct_eval(&child[nested::RxComponent::AbA], xz),
                direct_eval(&child[nested::RxComponent::AbB], x),
                direct_eval(child.nested_registry_xy_poly(), w),
                direct_eval(&self.nested_wy, nested::challenge::<C>(child.x())?),
            ]);
        }
        assert_eq!(expected_query.len(), 138);
        if matches!(mutation, Some(ScalarPayloadMutation::QueryChildRx)) {
            let first_child_rx = nested::InternalCircuitIndex::NUM + 1;
            omit_first_live(
                &mut expected_query,
                first_child_rx..first_child_rx + nested::RxIndex::NUM,
                "Query child rx",
            );
        }
        let query = transcript_tests::raw_stage::<Fq, nested::stages::query::Stage<NativePoint, R>>(
            &self.proof.bridge_query_rx,
        );
        let bridge_query = query[4..] == expected_query;

        let u = nested::challenge::<C>(self.proof.u())?;
        let mut expected_eval = Vec::new();
        for child in [&self.left, &self.right] {
            expected_eval.extend(
                nested_rx_order()
                    .into_iter()
                    .map(|id| direct_eval(&child[id], u)),
            );
            expected_eval.extend([
                direct_eval(&child[nested::RxComponent::AbA], u),
                direct_eval(&child[nested::RxComponent::AbB], u),
                direct_eval(child.nested_registry_xy_poly(), u),
                direct_eval(child.nested_p_poly(), u),
            ]);
        }
        let first_current = expected_eval.len();
        expected_eval.extend([
            direct_eval(&self.nested_wx[0], u),
            direct_eval(&self.nested_wx[1], u),
            direct_eval(&self.nested_wy, u),
            direct_eval(&self.proof[nested::RxComponent::AbA], u),
            direct_eval(&self.proof[nested::RxComponent::AbB], u),
            direct_eval(self.proof.nested_registry_xy_poly(), u),
        ]);
        assert_eq!(first_current, 92);
        assert_eq!(expected_eval.len(), 98);
        if matches!(mutation, Some(ScalarPayloadMutation::EvalCurrent)) {
            let len = expected_eval.len();
            omit_first_live(&mut expected_eval, first_current..len, "Eval current-step");
        }
        let eval = transcript_tests::raw_stage::<Fq, nested::stages::eval::Stage<NativePoint, R>>(
            &self.proof.bridge_eval_rx,
        );
        let bridge_eval = eval[2..] == expected_eval;

        Ok(ScalarPayloadChecks {
            bridge_inner_error,
            bridge_outer_error,
            bridge_query,
            bridge_eval,
        })
    }

    fn native_batch_points(&self) -> Vec<NativePoint> {
        let mut points = Vec::new();
        points.push(self.native_f_commitment);
        for proof in [&self.left, &self.right] {
            points.extend(
                native_rx_order()
                    .into_iter()
                    .map(|id| proof.native_rx_commitment(id)),
            );
            points.extend([
                proof.native_commitment(native::RxComponent::AbA),
                proof.native_commitment(native::RxComponent::AbB),
                proof.native_registry_xy_commitment(),
                proof.native_p_commitment(),
            ]);
        }
        points.extend([
            self.native_wx_commitments[0],
            self.native_wx_commitments[1],
            self.native_wy_commitment,
            self.proof.native_commitment(native::RxComponent::AbA),
            self.proof.native_commitment(native::RxComponent::AbB),
            self.proof.native_registry_xy_commitment(),
        ]);
        assert_eq!(points.len(), 113);
        assert_eq!(points.len(), nested::NUM_ENDOSCALING_POINTS);
        points
    }

    fn nested_batch_points(&self) -> Vec<NestedPoint> {
        let mut points = Vec::new();
        points.push(self.nested_f_commitment);
        for proof in [&self.left, &self.right] {
            points.extend(
                nested_rx_order()
                    .into_iter()
                    .map(|id| proof.nested_rx_commitment(id)),
            );
            points.extend([
                proof.nested_a_commitment(),
                proof.nested_b_commitment(),
                proof.nested_registry_xy_commitment(),
                proof.nested_p_commitment(),
            ]);
        }
        points.extend([
            self.nested_wx_commitments[0],
            self.nested_wx_commitments[1],
            self.nested_wy_commitment,
            self.proof.nested_a_commitment(),
            self.proof.nested_b_commitment(),
            self.proof.nested_registry_xy_commitment(),
        ]);
        assert_eq!(points.len(), 99);
        assert_eq!(points.len(), native::NUM_ENDOSCALING_POINTS);
        points
    }

    /// Independently specify both commitment walks from their retained source
    /// commitments. The mutation modes perturb only this specification, so a
    /// control can show exactly which association or recurrence checks fail
    /// against an otherwise honest recorded proof.
    fn commitment_walk_checks(
        &self,
        mutation: Option<WalkMutation>,
    ) -> Result<CommitmentWalkChecks> {
        let endoscalar = extract_endoscalar(self.proof.pre_beta())?;

        // The native batch is a host-curve walk stored in the nested
        // EndoscalarStage and PointsStage. PointsStage lays out its initial,
        // 112 inputs and then all 28 four-at-a-time Horner checkpoints.
        let native_points = self.native_batch_points();
        let native_stage = transcript_tests::raw_stage::<Fq, nested::PointsStage<NativePoint>>(
            &self.proof.nested_points_rx,
        );
        let native_inputs_len = 2 * native_points.len();
        let (actual_native_inputs, actual_native_interstitials) =
            native_stage.split_at(native_inputs_len);
        let native_inputs = actual_native_inputs == flatten_points(&native_points);
        let native_endoscalar = transcript_tests::raw_stage::<Fq, endoscalar::EndoscalarStage>(
            &self.proof.nested_endoscalar_rx,
        ) == endoscalar_bits(endoscalar);
        let native_omission =
            matches!(mutation, Some(WalkMutation::NativeInputOmission)).then_some(1);
        let expected_native_interstitials =
            native_interstitials(&native_points, lift_endoscalar(endoscalar), native_omission);
        assert_eq!(expected_native_interstitials.len(), 28);
        let native_interstitials =
            actual_native_interstitials == flatten_points(&expected_native_interstitials);
        let native_endpoint =
            expected_native_interstitials.last().copied() == Some(self.proof.native_p_commitment());

        // The nested batch's 98 post-f inputs are split over five native
        // stages. Spell out that split independently of Inputs::from_walk:
        // each child has 33 ordinary points then 13 binding points, followed
        // by the current step's six-point tail.
        let nested_points = self.nested_batch_points();
        let ordered = &nested_points[1..];
        assert_eq!(ordered.len(), 98);
        let mut binding: Vec<_> = ordered[33..46]
            .iter()
            .chain(&ordered[79..92])
            .copied()
            .collect();
        if matches!(mutation, Some(WalkMutation::NestedInputMisroute)) {
            assert_ne!(coordinates(binding[0]), coordinates(binding[1]));
            binding.swap(0, 1);
        }
        let children: Vec<_> = ordered[..33]
            .iter()
            .chain(&ordered[46..79])
            .copied()
            .collect();
        let registry_wx = &ordered[92..94];
        let ab = &ordered[94..97];
        let f = [ordered[97], nested_points[0]];
        use native::stages::points::*;
        let nested_inputs = transcript_tests::raw_stage::<Fp, BindingStage<NestedPoint>>(
            &self.proof.native_points_binding_rx,
        ) == flatten_points(&binding)
            && transcript_tests::raw_stage::<Fp, ChildrenStage<NestedPoint>>(
                &self.proof.native_points_children_rx,
            ) == flatten_points(&children)
            && transcript_tests::raw_stage::<Fp, RegistryWxStage<NestedPoint>>(
                &self.proof.native_points_registry_wx_rx,
            ) == flatten_points(registry_wx)
            && transcript_tests::raw_stage::<Fp, AbStage<NestedPoint>>(
                &self.proof.native_points_ab_rx,
            ) == flatten_points(ab)
            && transcript_tests::raw_stage::<Fp, FStage<NestedPoint>>(
                &self.proof.native_points_f_rx,
            ) == flatten_points(&f);

        let nested_walk = transcript_tests::raw_stage::<Fp, WalkStage<NestedPoint>>(
            &self.proof.native_points_walk_rx,
        );
        let (actual_nested_endoscalar, actual_nested_interstitials) =
            nested_walk.split_at(u128::BITS as usize);
        let nested_endoscalar = actual_nested_endoscalar == endoscalar_bits(endoscalar);
        let nested_omission =
            matches!(mutation, Some(WalkMutation::NestedInputOmission)).then_some(1);
        let expected_nested_interstitials =
            nested_interstitials(&nested_points, lift_endoscalar(endoscalar), nested_omission);
        assert_eq!(expected_nested_interstitials.len(), 25);
        let nested_interstitials =
            actual_nested_interstitials == flatten_points(&expected_nested_interstitials);
        let nested_endpoint =
            expected_nested_interstitials.last().copied() == Some(self.proof.nested_p_commitment());

        Ok(CommitmentWalkChecks {
            native_inputs,
            native_endoscalar,
            native_interstitials,
            native_endpoint,
            nested_inputs,
            nested_endoscalar,
            nested_interstitials,
            nested_endpoint,
        })
    }

    /// Independently expand every registered logic-circuit equation and every
    /// stage, final-stage, and Loading constraint family at fresh y/z points.
    /// The inventories below are deliberately explicit: they do not use either
    /// claims builder or `InternalCircuitIndex::ALL`, so a changed production
    /// route cannot silently update this local-equation specification.
    fn local_equation_checks(
        &self,
        app: &App,
        mutation: Option<LocalEquationMutation>,
    ) -> Result<LocalEquationChecks> {
        let native_y = Fp::from(109);
        let native_z = Fp::from(113);
        let native_unified = quotient_transfer_tests::native_ky(&self.proof, native_y);
        let mut native_bridge_wires = quotient_transfer_tests::native_instance_wires(&self.proof);
        native_bridge_wires.extend(self.proof.left_header());
        native_bridge_wires.extend(self.proof.right_header());
        native_bridge_wires.push(Fp::ZERO);
        let native_bridge = instance_ky(&native_bridge_wires, native_y);

        use native::{InternalCircuitIndex as NI, RxIndex as NR};
        let mut native_logic_relations = vec![
            (
                NI::Hashes1Circuit,
                if matches!(mutation, Some(LocalEquationMutation::NativeLogicOmission)) {
                    vec![NR::Hashes1, NR::Preamble]
                } else {
                    vec![NR::Hashes1, NR::Preamble, NR::OuterError]
                },
                native_bridge,
            ),
            (
                NI::Hashes2Circuit,
                vec![NR::Hashes2, NR::OuterError],
                native_unified,
            ),
            (
                NI::InnerCollapseCircuit,
                vec![
                    NR::InnerCollapse,
                    NR::Preamble,
                    NR::InnerError,
                    NR::OuterError,
                ],
                native_unified,
            ),
            (
                NI::OuterCollapseCircuit,
                vec![NR::OuterCollapse, NR::Preamble, NR::OuterError],
                native_unified,
            ),
            (
                NI::ComputeVCircuit,
                vec![NR::ComputeV, NR::Preamble, NR::Query, NR::Eval],
                native_unified,
            ),
        ];
        native_logic_relations.extend((0..5).map(|k| {
            (
                NI::BindChallengesCircuit(k),
                vec![NR::BindChallenges(k), NR::Preamble, NR::Query, NR::Eval],
                native_unified,
            )
        }));
        native_logic_relations.push((
            NI::BindBetaCircuit,
            vec![
                NR::BindBeta,
                NR::PointsBinding,
                NR::Preamble,
                NR::OuterError,
            ],
            native_unified,
        ));
        let native_walk_stages = [
            NR::PointsBinding,
            NR::PointsChildren,
            NR::PointsRegistryWx,
            NR::PointsAb,
            NR::PointsF,
            NR::PointsWalk,
        ];
        native_logic_relations.push((
            NI::BindEndoscalarCircuit,
            core::iter::once(NR::BindEndoscalar)
                .chain(native_walk_stages)
                .collect(),
            native_unified,
        ));
        native_logic_relations.extend((0..25).map(|step| {
            (
                NI::EndoscalingStep(step),
                core::iter::once(NR::EndoscalingStep(step))
                    .chain(native_walk_stages)
                    .collect(),
                Fp::ONE,
            )
        }));
        assert_eq!(native_logic_relations.len(), 37);
        assert_eq!(
            NI::NUM,
            37 + 11 + 4,
            "explicit native local-equation inventory is stale"
        );
        let native_logic = native_logic_relations
            .into_iter()
            .all(|(circuit, ids, expected)| {
                let rxs: Vec<_> = ids.iter().map(|&id| &self.proof[id]).collect();
                quotient_transfer_tests::circuit_value(
                    &app.native_registry,
                    circuit.circuit_index(),
                    &rxs,
                    native_y,
                    native_z,
                ) == expected
            });

        let native_stage_relations = [
            (NI::PreambleStage, NR::Preamble),
            (NI::InnerErrorStage, NR::InnerError),
            (NI::OuterErrorStage, NR::OuterError),
            (NI::QueryStage, NR::Query),
            (NI::EvalStage, NR::Eval),
            (NI::PointsBindingStage, NR::PointsBinding),
            (NI::PointsChildrenStage, NR::PointsChildren),
            (NI::PointsRegistryWxStage, NR::PointsRegistryWx),
            (NI::PointsAbStage, NR::PointsAb),
            (NI::PointsFStage, NR::PointsF),
            (NI::PointsWalkStage, NR::PointsWalk),
        ];
        let native_stage_masks = native_stage_relations.into_iter().all(|(circuit, rx)| {
            let circuit = if matches!(
                mutation,
                Some(LocalEquationMutation::NativeStageMaskMisroute)
            ) && circuit == NI::QueryStage
            {
                NI::EvalStage
            } else {
                circuit
            };
            constraint_value(
                &app.native_registry,
                circuit.circuit_index(),
                &[&self.proof[rx]],
                native_y,
            ) == Fp::ZERO
        });

        let mut native_eval_final = vec![NR::ComputeV];
        native_eval_final.extend((0..5).map(NR::BindChallenges));
        let mut native_walk_final = vec![NR::BindEndoscalar];
        native_walk_final.extend((0..25).map(NR::EndoscalingStep));
        let native_final_relations = [
            (NI::InnerErrorFinalStaged, vec![NR::InnerCollapse]),
            (
                NI::OuterErrorFinalStaged,
                vec![NR::Hashes1, NR::Hashes2, NR::OuterCollapse, NR::BindBeta],
            ),
            (NI::EvalFinalStaged, native_eval_final),
            (NI::PointsWalkFinalStaged, native_walk_final),
        ];
        let native_final_masks = native_final_relations.into_iter().all(|(circuit, ids)| {
            let omit = matches!(
                mutation,
                Some(LocalEquationMutation::NativeFinalMaskOmission)
            ) && circuit == NI::InnerErrorFinalStaged;
            let rxs: Vec<_> = ids.iter().map(|&id| &self.proof[id]).collect();
            let value = if omit {
                constraint_value_with_omission_counterexample(
                    &app.native_registry,
                    circuit.circuit_index(),
                    &rxs,
                    native_y,
                )
            } else {
                constraint_value(
                    &app.native_registry,
                    circuit.circuit_index(),
                    &rxs,
                    native_y,
                )
            };
            value == Fp::ZERO
        });

        let nested_y = Fq::from(127);
        let nested_z = Fq::from(131);
        let nested_unified = quotient_transfer_tests::nested_ky(&self.proof, nested_y)?;
        use nested::{InternalCircuitIndex as SI, RxIndex as SR};
        let mut nested_logic_relations: Vec<(SI, Vec<SR>, Fq)> = (0..28)
            .map(|step| {
                (
                    SI::EndoscalingStep(step),
                    vec![
                        SR::EndoscalingStep(step),
                        SR::EndoscalarStage,
                        SR::PointsStage,
                    ],
                    Fq::ONE,
                )
            })
            .collect();
        for (circuit, own) in [
            (SI::Export, SR::Export),
            (SI::Collapse, SR::Collapse),
            (SI::ComputeV, SR::ComputeV),
        ] {
            let mut ids = vec![
                own,
                SR::EndoscalarStage,
                SR::PointsStage,
                SR::BridgePreamble,
                SR::BridgeSPrime,
                SR::BridgeInnerError,
                SR::BridgeOuterError,
                SR::BridgeAB,
                SR::BridgeQuery,
                SR::BridgeF,
                SR::BridgeEval,
                SR::ChallengeStage,
            ];
            if matches!(mutation, Some(LocalEquationMutation::NestedLogicOmission))
                && circuit == SI::Export
            {
                ids.retain(|&id| id != SR::PointsStage);
            }
            nested_logic_relations.push((circuit, ids, nested_unified));
        }
        assert_eq!(nested_logic_relations.len(), 31);
        assert_eq!(
            SI::NUM,
            31 + 11 + 2 + 1,
            "explicit nested local-equation inventory is stale"
        );
        let nested_logic = nested_logic_relations
            .into_iter()
            .all(|(circuit, ids, expected)| {
                let rxs: Vec<_> = ids.iter().map(|&id| &self.proof[id]).collect();
                quotient_transfer_tests::circuit_value(
                    &app.nested_registry,
                    circuit.circuit_index(),
                    &rxs,
                    nested_y,
                    nested_z,
                ) == expected
            });

        let nested_stage_relations = [
            (SI::EndoscalarStage, SR::EndoscalarStage),
            (SI::PointsStage, SR::PointsStage),
            (SI::BridgePreamble, SR::BridgePreamble),
            (SI::BridgeSPrime, SR::BridgeSPrime),
            (SI::BridgeInnerError, SR::BridgeInnerError),
            (SI::BridgeOuterError, SR::BridgeOuterError),
            (SI::BridgeAB, SR::BridgeAB),
            (SI::BridgeQuery, SR::BridgeQuery),
            (SI::BridgeF, SR::BridgeF),
            (SI::BridgeEval, SR::BridgeEval),
            (SI::ChallengeStage, SR::ChallengeStage),
        ];
        let nested_stage_masks = nested_stage_relations.into_iter().all(|(circuit, rx)| {
            let circuit = if matches!(
                mutation,
                Some(LocalEquationMutation::NestedStageMaskMisroute)
            ) && circuit == SI::BridgeQuery
            {
                SI::BridgeEval
            } else {
                circuit
            };
            constraint_value(
                &app.nested_registry,
                circuit.circuit_index(),
                &[&self.proof[rx]],
                nested_y,
            ) == Fq::ZERO
        });

        let nested_points_final: Vec<_> = (0..28).map(SR::EndoscalingStep).collect();
        let nested_final_relations = [
            (SI::PointsFinalStaged, nested_points_final),
            (
                SI::ChallengeFinalStaged,
                vec![SR::Export, SR::Collapse, SR::ComputeV],
            ),
        ];
        let nested_final_masks = nested_final_relations.into_iter().all(|(circuit, ids)| {
            let omit = matches!(
                mutation,
                Some(LocalEquationMutation::NestedFinalMaskOmission)
            ) && circuit == SI::PointsFinalStaged;
            let rxs: Vec<_> = ids.iter().map(|&id| &self.proof[id]).collect();
            let value = if omit {
                constraint_value_with_omission_counterexample(
                    &app.nested_registry,
                    circuit.circuit_index(),
                    &rxs,
                    nested_y,
                )
            } else {
                constraint_value(
                    &app.nested_registry,
                    circuit.circuit_index(),
                    &rxs,
                    nested_y,
                )
            };
            value == Fq::ZERO
        });

        let mut loading = vec![
            SR::PointsStage,
            SR::BridgePreamble,
            SR::BridgeSPrime,
            SR::BridgeInnerError,
            SR::BridgeAB,
            SR::BridgeQuery,
            SR::BridgeF,
        ];
        if matches!(mutation, Some(LocalEquationMutation::NestedLoadingOmission)) {
            loading.retain(|&id| id != SR::BridgeQuery);
        }
        let loading_rxs: Vec<_> = loading.iter().map(|&id| &self.proof[id]).collect();
        let nested_loading = constraint_value(
            &app.nested_registry,
            SI::Loading.circuit_index(),
            &loading_rxs,
            nested_y,
        ) == Fq::ZERO;

        Ok(LocalEquationChecks {
            native_logic,
            native_stage_masks,
            native_final_masks,
            nested_logic,
            nested_stage_masks,
            nested_final_masks,
            nested_loading,
        })
    }

    fn checks(&self, app: &App) -> Result<ExpandedChecks> {
        let native_registry = app.native_registry.at(self.proof.w());
        let expected_native_wx = [
            ReferenceBackend::registry_at_x(&native_registry, self.left.x()),
            ReferenceBackend::registry_at_x(&native_registry, self.right.x()),
        ];
        let expected_native_wy = ReferenceBackend::registry_at_y(&native_registry, self.proof.y());
        let expected_native_xy =
            ReferenceBackend::registry_xy(&app.native_registry, self.proof.x(), self.proof.y());

        let lift = nested::challenge::<C>;
        let nested_registry = app.nested_registry.at(lift(self.proof.w())?);
        let expected_nested_wx = [
            ReferenceBackend::registry_at_x(&nested_registry, lift(self.left.x())?),
            ReferenceBackend::registry_at_x(&nested_registry, lift(self.right.x())?),
        ];
        let expected_nested_wy =
            ReferenceBackend::registry_at_y(&nested_registry, lift(self.proof.y())?);
        let expected_nested_xy = ReferenceBackend::registry_xy(
            &app.nested_registry,
            lift(self.proof.x())?,
            lift(self.proof.y())?,
        );
        let registry_restrictions = self
            .native_wx
            .iter()
            .zip(&expected_native_wx)
            .all(|(actual, expected)| same_poly(actual, expected))
            && same_poly(&self.native_wy, &expected_native_wy)
            && same_poly(self.proof.native_registry_xy_poly(), &expected_native_xy)
            && self
                .nested_wx
                .iter()
                .zip(&expected_nested_wx)
                .all(|(actual, expected)| same_poly(actual, expected))
            && same_poly(&self.nested_wy, &expected_nested_wy)
            && same_poly(self.proof.nested_registry_xy_poly(), &expected_nested_xy);

        let children = [&self.left, &self.right];
        let native_batch = quotient_transfer_tests::native_batch(app, &self.proof, children);
        let nested_batch = quotient_transfer_tests::nested_batch(app, &self.proof, children)?;
        let expected_native_f = native_batch.quotient();
        let expected_nested_f = nested_batch.quotient();
        let quotients = same_coefficients(&self.native_f, &expected_native_f)
            && same_coefficients(&self.nested_f, &expected_nested_f);
        let native_f: Vec<_> = self.native_f.iter_coeffs().collect();
        let nested_f: Vec<_> = self.nested_f.iter_coeffs().collect();
        let expected_native_p = native_batch.accumulate(&native_f);
        let expected_nested_p = nested_batch.accumulate(&nested_f);
        let accumulations = same_coefficients(self.proof.native_p_poly(), &expected_native_p)
            && quotient_transfer_tests::evaluate(&expected_native_p, self.proof.u())
                == self.proof.v()
            && same_coefficients(self.proof.nested_p_poly(), &expected_nested_p)
            && quotient_transfer_tests::evaluate(&expected_nested_p, lift(self.proof.u())?)
                == self.proof.nested_v()?;

        let direct_commitments =
            self.native_wx
                .iter()
                .zip(self.native_wx_commitments)
                .all(|(poly, commitment)| {
                    ReferenceBackend::sparse_commit_to_affine(poly, C::host_generators(app.params))
                        == commitment
                })
                && self.nested_wx.iter().zip(self.nested_wx_commitments).all(
                    |(poly, commitment)| {
                        ReferenceBackend::sparse_commit_to_affine(
                            poly,
                            C::nested_generators(app.params),
                        ) == commitment
                    },
                )
                && ReferenceBackend::sparse_commit_to_affine(
                    &self.native_wy,
                    C::host_generators(app.params),
                ) == self.native_wy_commitment
                && ReferenceBackend::sparse_commit_to_affine(
                    &self.nested_wy,
                    C::nested_generators(app.params),
                ) == self.nested_wy_commitment
                && ReferenceBackend::sparse_commit_to_affine(
                    &self.native_f,
                    C::host_generators(app.params),
                ) == self.native_f_commitment
                && ReferenceBackend::sparse_commit_to_affine(
                    &self.nested_f,
                    C::nested_generators(app.params),
                ) == self.nested_f_commitment;
        let commitment_caches = self.commitment_cache_checks(app, None);
        let stage_associations = self.stage_association_checks(None)?;
        let scalar_payloads = self.scalar_payload_checks(app, None)?;
        let commitment_walks = self.commitment_walk_checks(None)?;
        let local_equations = self.local_equation_checks(app, None)?;

        Ok(ExpandedChecks {
            registry_restrictions,
            quotients,
            accumulations,
            direct_commitments,
            commitment_caches,
            stage_associations,
            scalar_payloads,
            commitment_walks,
            local_equations,
        })
    }
}

fn recorded_leaf(app: &App, rng: &mut StdRng, value: Fp) -> Result<(Node, Retained)> {
    let mut recorder = Recorder::default();
    let node = app
        .fuse_inner(
            rng,
            Leaf,
            value,
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            |_, _| {},
            |_| Ok(None),
            &mut recorder,
        )?
        .0;
    Ok((node, recorder.take()))
}

fn recorded_add_square(
    app: &App,
    rng: &mut StdRng,
    root: Fp,
    left: Node,
    right: Node,
) -> Result<(Node, Retained)> {
    let mut recorder = Recorder::default();
    let node = app
        .fuse_inner(
            rng,
            AddSquare,
            root,
            left,
            right,
            |_, _| {},
            |_| Ok(None),
            &mut recorder,
        )?
        .0;
    Ok((node, recorder.take()))
}

fn check_node(app: &App, node: &Node, retained: &Retained, base_case: bool) -> Result<()> {
    assert_eq!(retained.proof.test_mismatch(node.proof()), None);
    let expanded = retained.checks(app)?;
    assert!(expanded.all(), "expanded witness: {expanded:?}");
    quotient_transfer_tests::check_honest_expanded(app, node, [&retained.left, &retained.right])?;
    quotient_transfer_tests::check_honest_terminal(app, node.proof())?;
    if !base_case {
        check_native_accumulator(app, node.proof(), &retained.left, &retained.right)?;
        check_nested_accumulator(app, node.proof(), &retained.left, &retained.right)?;
    }
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(0x8730_0707))?;
    assert!(accepted);
    assert!(checks.expect("well-formed proof reaches every check").all());
    Ok(())
}

fn add_square_relation(left: Fp, right: Fp, root: Fp, output: Fp) -> bool {
    output == left + right + root.square()
}

#[test]
fn expanded_small_tree_tracks_transients_semantics_and_valid_replacements() -> Result<()> {
    const LEFT: Fp = Fp::from_raw([19, 0, 0, 0]);
    const RIGHT: Fp = Fp::from_raw([43, 0, 0, 0]);
    const ROOT: Fp = Fp::from_raw([17, 0, 0, 0]);
    const TAIL: Fp = Fp::from_raw([71, 0, 0, 0]);
    const DEEP_ROOT: Fp = Fp::from_raw([23, 0, 0, 0]);
    const FINAL_ROOT: Fp = Fp::from_raw([29, 0, 0, 0]);

    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(super::test_steps::Add)?
        .register(AddSquare)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x8730_0701);
    let (left, left_retained) = recorded_leaf(&app, &mut rng, LEFT)?;
    let (right, right_retained) = recorded_leaf(&app, &mut rng, RIGHT)?;
    assert_eq!(*left.data(), LEFT, "independent leaf relation");
    assert_eq!(*right.data(), RIGHT, "independent leaf relation");
    check_node(&app, &left, &left_retained, true)?;
    check_node(&app, &right, &right_retained, true)?;

    let (positive, positive_retained) =
        recorded_add_square(&app, &mut rng, ROOT, left.clone(), right.clone())?;
    let (negative, negative_retained) = recorded_add_square(&app, &mut rng, -ROOT, left, right)?;
    assert!(add_square_relation(LEFT, RIGHT, ROOT, *positive.data()));
    assert!(add_square_relation(LEFT, RIGHT, -ROOT, *negative.data()));
    assert_eq!(positive.data(), negative.data());
    assert!(
        positive.proof().test_mismatch(negative.proof()).is_some(),
        "valid private replacements need not reproduce historical traces"
    );
    check_node(&app, &positive, &positive_retained, false)?;
    check_node(&app, &negative, &negative_retained, false)?;

    // Retain two more fusion generations. The deep node folds one ordinary
    // leaf with a non-base proof, and the final node folds two non-base
    // children of unequal depth.
    let (tail, tail_retained) = recorded_leaf(&app, &mut rng, TAIL)?;
    check_node(&app, &tail, &tail_retained, true)?;
    let (deep, deep_retained) =
        recorded_add_square(&app, &mut rng, DEEP_ROOT, positive.clone(), tail)?;
    assert!(add_square_relation(
        *positive.data(),
        TAIL,
        DEEP_ROOT,
        *deep.data()
    ));
    check_node(&app, &deep, &deep_retained, false)?;
    check_native_claim_omission(
        &app,
        deep.proof(),
        &deep_retained.left,
        &deep_retained.right,
    )?;

    let (final_node, final_retained) =
        recorded_add_square(&app, &mut rng, FINAL_ROOT, deep.clone(), negative.clone())?;
    assert!(add_square_relation(
        *deep.data(),
        *negative.data(),
        FINAL_ROOT,
        *final_node.data()
    ));
    check_node(&app, &final_node, &final_retained, false)?;

    // A single wrong cache route on either curve is localized to that rx
    // family while all other independently committed cache families remain
    // valid. These are specification mutants, so the recorded proof itself
    // remains honest and immutable.
    let native_cache =
        final_retained.commitment_cache_checks(&app, Some(CacheMutation::NativeRxMisroute));
    assert!(!native_cache.native_rx);
    assert!(
        native_cache.native_ab
            && native_cache.native_registry_xy
            && native_cache.native_p
            && native_cache.nested_rx
            && native_cache.nested_ab
            && native_cache.nested_registry_xy
            && native_cache.nested_p
    );
    let nested_cache =
        final_retained.commitment_cache_checks(&app, Some(CacheMutation::NestedRxMisroute));
    assert!(!nested_cache.nested_rx);
    assert!(
        nested_cache.native_rx
            && nested_cache.native_ab
            && nested_cache.native_registry_xy
            && nested_cache.native_p
            && nested_cache.nested_ab
            && nested_cache.nested_registry_xy
            && nested_cache.nested_p
    );

    // Calibrate the ancestry checker at both ends of a parent-child copy: a
    // child Query commitment misrouted inside the 228-wire preamble, and the
    // current Query stage replaced by the current Eval source. Each changes
    // only its named bridge predicate.
    let preamble_misroute =
        final_retained.stage_association_checks(Some(StageMutation::PreambleChildQueryMisroute))?;
    assert!(!preamble_misroute.bridge_preamble);
    assert!(
        preamble_misroute.bridge_s_prime
            && preamble_misroute.bridge_inner_error
            && preamble_misroute.bridge_outer_error
            && preamble_misroute.bridge_ab
            && preamble_misroute.bridge_query
            && preamble_misroute.bridge_f
            && preamble_misroute.bridge_eval
            && preamble_misroute.points_registry_wx
            && preamble_misroute.points_ab
            && preamble_misroute.points_f
    );
    let query_misroute =
        final_retained.stage_association_checks(Some(StageMutation::BridgeQuerySourceMisroute))?;
    assert!(!query_misroute.bridge_query);
    assert!(
        query_misroute.bridge_preamble
            && query_misroute.bridge_s_prime
            && query_misroute.bridge_inner_error
            && query_misroute.bridge_outer_error
            && query_misroute.bridge_ab
            && query_misroute.bridge_f
            && query_misroute.bridge_eval
            && query_misroute.points_registry_wx
            && query_misroute.points_ab
            && query_misroute.points_f
    );

    // Deleting one live value from each independently specified scalar
    // family is detected by that family alone. The proof remains immutable;
    // these controls perturb only the expected serialization/evaluation.
    let inner_omission =
        final_retained.scalar_payload_checks(&app, Some(ScalarPayloadMutation::InnerError))?;
    assert!(!inner_omission.bridge_inner_error);
    assert!(
        inner_omission.bridge_outer_error
            && inner_omission.bridge_query
            && inner_omission.bridge_eval
    );
    let outer_omission =
        final_retained.scalar_payload_checks(&app, Some(ScalarPayloadMutation::OuterCollapsed))?;
    assert!(!outer_omission.bridge_outer_error);
    assert!(
        outer_omission.bridge_inner_error
            && outer_omission.bridge_query
            && outer_omission.bridge_eval
    );
    let query_omission =
        final_retained.scalar_payload_checks(&app, Some(ScalarPayloadMutation::QueryChildRx))?;
    assert!(!query_omission.bridge_query);
    assert!(
        query_omission.bridge_inner_error
            && query_omission.bridge_outer_error
            && query_omission.bridge_eval
    );
    let eval_omission =
        final_retained.scalar_payload_checks(&app, Some(ScalarPayloadMutation::EvalCurrent))?;
    assert!(!eval_omission.bridge_eval);
    assert!(
        eval_omission.bridge_inner_error
            && eval_omission.bridge_outer_error
            && eval_omission.bridge_query
    );

    // Every registered local equation family has an isolated specification
    // mutant. Logic and Loading controls delete a live trace constituent;
    // stage controls deliberately apply the wrong registered mask. Final-mask
    // controls inject one prohibited coefficient and prove that deleting its
    // exact mask term admits the counterexample. In each case the other six
    // independently expanded families remain satisfied.
    for (mutation, expected) in [
        (
            LocalEquationMutation::NativeLogicOmission,
            [false, true, true, true, true, true, true],
        ),
        (
            LocalEquationMutation::NativeStageMaskMisroute,
            [true, false, true, true, true, true, true],
        ),
        (
            LocalEquationMutation::NativeFinalMaskOmission,
            [true, true, false, true, true, true, true],
        ),
        (
            LocalEquationMutation::NestedLogicOmission,
            [true, true, true, false, true, true, true],
        ),
        (
            LocalEquationMutation::NestedStageMaskMisroute,
            [true, true, true, true, false, true, true],
        ),
        (
            LocalEquationMutation::NestedFinalMaskOmission,
            [true, true, true, true, true, false, true],
        ),
        (
            LocalEquationMutation::NestedLoadingOmission,
            [true, true, true, true, true, true, false],
        ),
    ] {
        let checks = final_retained.local_equation_checks(&app, Some(mutation))?;
        assert_eq!(
            [
                checks.native_logic,
                checks.native_stage_masks,
                checks.native_final_masks,
                checks.nested_logic,
                checks.nested_stage_masks,
                checks.nested_final_masks,
                checks.nested_loading,
            ],
            expected,
            "local equation omission/misroute calibration: {checks:?}"
        );
    }

    // Calibrate the complete walk checker with isolated specification
    // mutants. A staged-point misroute changes only the input association;
    // deleting one Horner input on either curve changes that walk's stored
    // checkpoints and final P association, but nothing on the other curve.
    let misrouted =
        final_retained.commitment_walk_checks(Some(WalkMutation::NestedInputMisroute))?;
    assert!(!misrouted.nested_inputs);
    assert!(
        misrouted.native_inputs
            && misrouted.native_endoscalar
            && misrouted.native_interstitials
            && misrouted.native_endpoint
            && misrouted.nested_endoscalar
            && misrouted.nested_interstitials
            && misrouted.nested_endpoint
    );
    let omitted_native =
        final_retained.commitment_walk_checks(Some(WalkMutation::NativeInputOmission))?;
    assert!(!omitted_native.native_interstitials);
    assert!(!omitted_native.native_endpoint);
    assert!(
        omitted_native.native_inputs
            && omitted_native.native_endoscalar
            && omitted_native.nested_inputs
            && omitted_native.nested_endoscalar
            && omitted_native.nested_interstitials
            && omitted_native.nested_endpoint
    );
    let omitted_nested =
        final_retained.commitment_walk_checks(Some(WalkMutation::NestedInputOmission))?;
    assert!(!omitted_nested.nested_interstitials);
    assert!(!omitted_nested.nested_endpoint);
    assert!(
        omitted_nested.native_inputs
            && omitted_nested.native_endoscalar
            && omitted_nested.native_interstitials
            && omitted_nested.native_endpoint
            && omitted_nested.nested_inputs
            && omitted_nested.nested_endoscalar
    );

    // Mutation controls show that the retained-object checks are live even
    // when the edited polynomial's direct commitment is repaired.
    let mut wrong_registry = positive_retained.clone();
    let mut coefficients: Vec<_> = wrong_registry.native_wx[0].iter_coeffs().collect();
    coefficients[0] += Fp::ONE;
    wrong_registry.native_wx[0] = Poly::from_coeffs(coefficients);
    wrong_registry.native_wx_commitments[0] = ReferenceBackend::sparse_commit_to_affine(
        &wrong_registry.native_wx[0],
        C::host_generators(app.params),
    );
    let registry_checks = wrong_registry.checks(&app)?;
    assert!(!registry_checks.registry_restrictions);
    assert!(registry_checks.direct_commitments);
    assert!(!registry_checks.stage_associations.all());

    let mut wrong_quotient = positive_retained.clone();
    let mut coefficients: Vec<_> = wrong_quotient.nested_f.iter_coeffs().collect();
    coefficients[0] += Fq::ONE;
    wrong_quotient.nested_f = Poly::from_coeffs(coefficients);
    wrong_quotient.nested_f_commitment = ReferenceBackend::sparse_commit_to_affine(
        &wrong_quotient.nested_f,
        C::nested_generators(app.params),
    );
    let quotient_checks = wrong_quotient.checks(&app)?;
    assert!(!quotient_checks.quotients);
    assert!(!quotient_checks.accumulations);
    assert!(quotient_checks.direct_commitments);
    assert!(!quotient_checks.stage_associations.all());

    // The public relation, rather than historical witness identity, decides
    // whether changing the carried statement is a soundness-relevant event.
    let false_output = *positive.data() + Fp::ONE;
    assert!(!add_square_relation(LEFT, RIGHT, ROOT, false_output));
    let false_statement = positive.proof().clone().carry::<Number>(false_output);
    assert!(!app.verify(&false_statement, StdRng::seed_from_u64(0x8730_0708))?);

    let original_output = *positive.data();
    let rerandomized = app.rerandomize(positive, &mut rng)?;
    assert_eq!(*rerandomized.data(), original_output);
    assert!(add_square_relation(LEFT, RIGHT, ROOT, *rerandomized.data()));
    assert!(app.verify(&rerandomized, StdRng::seed_from_u64(0x8730_0709))?);
    Ok(())
}
