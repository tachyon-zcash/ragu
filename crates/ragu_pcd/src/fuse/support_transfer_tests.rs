//! Review A07 / R06: a stage/trace transfer must survive the circuit sums.
//!
//! Every consumer is compensated, not just the first one. Thus every circuit
//! claim in the attacked field stays coefficient-identical, including its
//! public instance. Only the support/loading claims can see the transfer.
//! An independently specified residual checks the actual production inventory
//! for one proof and both positions in a two-proof fold. Deleting the precise
//! failing masks restores the honest local equations; deleting any proper
//! subset does not. This is a polynomial-layer cut, not a forged full proof:
//! opposite-field bindings and the already-fixed transcript are not repaired.
//!
//! Source calibration: skip just QueryStage or EvalFinalStaged in native
//! claims::build, or BridgeEval, ChallengeFinalStaged or Loading in nested
//! claims::build. Keep the registry/constraint implementation intact. The
//! corresponding local test must lose the independently predicted numerical
//! error, even though its honest fixture still verifies. Restore each skip
//! before testing the next; no calibration mutant belongs in production.

use alloc::{borrow::Cow, vec, vec::Vec};

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::registry::{CircuitIndex, Registry};

use super::{
    quotient_transfer_tests::{circuit_value, native_ky, nested_ky, raw_stage, revdot},
    test_steps::{Add, Leaf, Number},
    *,
};
use crate::{
    Pcd,
    fuzzing::corrupt::{NativeCommitment, NativeRx, NestedCommitment, NestedRx, RxComponent},
    internal::native,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
type Poly<F> = sparse::Polynomial<F, R>;
type Builder<'m, 'rx, F> = claims::Builder<'m, 'rx, Cow<'rx, Poly<F>>, F, R, ReferenceBackend>;

struct NativeSource<'a>(&'a [&'a Proof<C, R>]);

impl<'a> claims::Source for NativeSource<'a> {
    type RxComponent = native::RxComponent;
    type Rx = &'a Poly<Fp>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, id: Self::RxComponent) -> impl Iterator<Item = Self::Rx> {
        self.0.iter().map(move |proof| &proof[id])
    }

    fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
        self.0.iter().map(|proof| proof.circuit_id())
    }
}

struct NestedSource<'a>(&'a [&'a Proof<C, R>]);

impl<'a> claims::Source for NestedSource<'a> {
    type RxComponent = nested::RxComponent;
    type Rx = &'a Poly<Fq>;
    type AppCircuitId = ();

    fn rx(&self, id: Self::RxComponent) -> impl Iterator<Item = Self::Rx> {
        self.0.iter().map(move |proof| &proof[id])
    }

    fn app_circuits(&self) -> impl Iterator<Item = ()> {
        core::iter::empty()
    }
}

/// Record labels while delegating every polynomial operation to production.
/// The expected mask identities, consumers, degrees and weights below do not
/// come from these labels or from the production claim enumerator.
struct Inventory<'m, 'rx, F: PrimeField> {
    builder: Builder<'m, 'rx, F>,
    labels: Vec<(Option<CircuitIndex>, bool)>, // circuit, is_bonding
}

impl<'m, 'rx, F: PrimeField> Inventory<'m, 'rx, F> {
    fn new(registry: &'m Registry<'m, F, R>, y: F, z: F) -> Self {
        Self {
            builder: Builder::new(registry, y, z),
            labels: Vec::new(),
        }
    }
}

impl<'rx> native::claims::Processor<&'rx Poly<Fp>, CircuitIndex> for Inventory<'_, 'rx, Fp> {
    fn raw_claim(&mut self, a: &'rx Poly<Fp>, b: &'rx Poly<Fp>) {
        self.labels.push((None, false));
        native::claims::Processor::raw_claim(&mut self.builder, a, b);
    }

    fn circuit_claim(&mut self, id: CircuitIndex, rx: &'rx Poly<Fp>) {
        self.labels.push((Some(id), false));
        native::claims::Processor::circuit_claim(&mut self.builder, id, rx);
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx Poly<Fp>>,
    ) {
        self.labels.push((Some(id.circuit_index()), false));
        native::claims::Processor::internal_circuit_claim(&mut self.builder, id, rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx Poly<Fp>>>,
    ) -> Result<()> {
        self.labels.push((Some(id.circuit_index()), true));
        native::claims::Processor::grouped_bonding_claim(&mut self.builder, id, groups)
    }
}

impl<'rx> nested::claims::Processor<&'rx Poly<Fq>> for Inventory<'_, 'rx, Fq> {
    fn raw_claim(&mut self, a: &'rx Poly<Fq>, b: &'rx Poly<Fq>) {
        self.labels.push((None, false));
        nested::claims::Processor::raw_claim(&mut self.builder, a, b);
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx Poly<Fq>>,
    ) {
        self.labels.push((Some(id.circuit_index()), false));
        nested::claims::Processor::internal_circuit_claim(&mut self.builder, id, rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx Poly<Fq>>>,
    ) -> Result<()> {
        self.labels.push((Some(id.circuit_index()), true));
        nested::claims::Processor::grouped_bonding_claim(&mut self.builder, id, groups)
    }
}

fn fixture() -> Result<(App, Node, Node)> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0xa07_006);
    let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
    let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
    let node = app.fuse(&mut rng, Add, (), left, right)?.0;
    let sibling = app.seed(&mut rng, Leaf, Fp::from(101))?.0;
    assert!(app.verify(&node, StdRng::seed_from_u64(0xa07))?);
    assert!(app.verify(&sibling, StdRng::seed_from_u64(0xa08))?);
    Ok((app, node, sibling))
}

fn power<F: Field>(base: F, exponent: usize) -> F {
    base.pow_vartime([exponent as u64])
}

/// a/d degree layout, independently of sparse wire-index helpers.
fn degree(gate: usize, d_wire: bool) -> usize {
    (if d_wire { 4 } else { 2 }) * R::n() - 1 - gate
}

fn monomial<F: Field>(degree: usize, delta: F) -> Poly<F> {
    let mut coefficients = vec![F::ZERO; R::num_coeffs()];
    coefficients[degree] = delta;
    Poly::from_coeffs(coefficients)
}

/// Query has six consumers. Each gets the opposite edit in its own trace.
fn native_transfer(app: &App, original: &Proof<C, R>, degree: usize, delta: Fp) -> Proof<C, R> {
    let mut changed = original.clone();
    for (id, sign) in core::iter::once((NativeRx::Query, Fp::ONE))
        .chain(core::iter::once((NativeRx::ComputeV, -Fp::ONE)))
        .chain((0..5).map(|i| (NativeRx::BindChallenges(i), -Fp::ONE)))
    {
        let rx = changed.native_component_mut(RxComponent::Rx(id));
        rx.add_assign(&monomial(degree, delta * sign));
        let commitment =
            ReferenceBackend::sparse_commit_to_affine(rx, C::host_generators(app.params));
        *changed.native_commitment_cache_mut(NativeCommitment::Rx(id)) = commitment;
    }
    assert_eq!(
        original.challenges().in_order(),
        changed.challenges().in_order()
    );
    assert_eq!(
        native_ky(original, Fp::from(17)),
        native_ky(&changed, Fp::from(17))
    );
    changed
}

/// All three instance circuits consume both BridgeEval and BridgeF.
fn nested_transfer(
    app: &App,
    original: &Proof<C, R>,
    stage: NestedRx,
    degree: usize,
    delta: Fq,
) -> Result<Proof<C, R>> {
    let mut changed = original.clone();
    for (id, sign) in [
        (stage, Fq::ONE),
        (NestedRx::Export, -Fq::ONE),
        (NestedRx::Collapse, -Fq::ONE),
        (NestedRx::ComputeV, -Fq::ONE),
    ] {
        let rx = changed.nested_rx_mut(id);
        rx.add_assign(&monomial(degree, delta * sign));
        let commitment =
            ReferenceBackend::sparse_commit_to_affine(rx, C::nested_generators(app.params));
        *changed.nested_commitment_cache_mut(NestedCommitment::Rx(id)) = commitment;
    }
    assert_eq!(
        original.challenges().in_order(),
        changed.challenges().in_order()
    );
    assert_eq!(
        nested_ky(original, Fq::from(23))?,
        nested_ky(&changed, Fq::from(23))?
    );
    Ok(changed)
}

/// Expected response of one mask to delta X^degree in each named consumer.
/// Group weights are expanded explicitly, including the interleaved child
/// position. This does not call production Horner/revdot/claim helpers.
fn mask_response<F: PrimeField>(
    registry: &Registry<'_, F, R>,
    id: CircuitIndex,
    degree: usize,
    delta: F,
    [y, z]: [F; 2],
    consumers: usize,
    [children, position]: [usize; 2],
) -> F {
    let sy = ReferenceBackend::registry_circuit_y(registry, id, y);
    let dual = sy.iter_coeffs().nth(R::num_coeffs() - 1 - degree).unwrap();
    let weight: F = (0..consumers)
        .map(|i| power(z, consumers * children - 1 - (i * children + position)))
        .sum();
    delta * dual * weight
}

/// All raw/circuit polynomials remain EXACTLY the honest ones. Every other
/// claim's numerical residual is independently predicted, not just nonzero.
/// Enumerating all subsets proves a minimum local cut while retaining every
/// circuit claim and the attack itself. Omission cannot pass unnoticed: every
/// expected mask must actually occur once in the recorded inventory.
fn check_inventory<F: PrimeField>(
    honest: &Inventory<'_, '_, F>,
    changed: &Inventory<'_, '_, F>,
    expected: &[(CircuitIndex, F)],
) {
    assert_eq!(honest.labels, changed.labels);
    assert_eq!(honest.labels.len(), honest.builder.a.len());
    assert_eq!(changed.labels.len(), changed.builder.a.len());
    assert_eq!(changed.labels.len(), changed.builder.b.len());
    let mut failures = Vec::new();
    let mut total = F::ZERO;
    for (i, &(id, bonding)) in changed.labels.iter().enumerate() {
        let (a, b) = (&changed.builder.a[i], &changed.builder.b[i]);
        if !bonding {
            assert!(
                honest.builder.a[i].iter_coeffs().eq(a.iter_coeffs()),
                "circuit a: {id:?}"
            );
            assert!(
                honest.builder.b[i].iter_coeffs().eq(b.iter_coeffs()),
                "circuit b: {id:?}"
            );
            continue;
        }
        assert_eq!(revdot(&honest.builder.a[i], &honest.builder.b[i]), F::ZERO);
        let id = id.unwrap();
        let residual = revdot(a, b);
        total += residual;
        let predicted = expected
            .iter()
            .find(|(mask, _)| *mask == id)
            .map_or(F::ZERO, |(_, v)| *v);
        assert_eq!(residual, predicted, "mask {id:?}: exact transfer residual");
        if residual != F::ZERO {
            failures.push(id);
        }
    }
    assert!(!expected.is_empty());
    assert_eq!(
        total,
        expected.iter().map(|(_, residual)| *residual).sum(),
        "accumulated masks must retain the independently predicted error"
    );
    for &(id, residual) in expected {
        assert_ne!(residual, F::ZERO, "nondegenerate independent mask response");
        assert_eq!(
            changed
                .labels
                .iter()
                .filter(|&&label| label == (Some(id), true))
                .count(),
            1
        );
    }
    assert_eq!(failures.len(), expected.len());
    for disabled in 0..1 << expected.len() {
        let accepts = failures.iter().all(|id| {
            expected
                .iter()
                .enumerate()
                .any(|(i, (mask, _))| mask == id && disabled & (1 << i) != 0)
        });
        assert_eq!(
            accepts,
            disabled == (1 << expected.len()) - 1,
            "minimum mask cut"
        );
    }
}

fn check_native(
    app: &App,
    original: &Proof<C, R>,
    changed: &Proof<C, R>,
    sibling: &Proof<C, R>,
    degree: usize,
    delta: Fp,
    reserved: bool,
) -> Result<()> {
    use native::InternalCircuitIndex::{EvalFinalStaged, QueryStage};
    let [y, z] = [Fp::from(17), Fp::from(19)];
    for (before, after, position) in [
        (vec![original], vec![changed], 0),
        (vec![original, sibling], vec![changed, sibling], 0),
        (vec![sibling, original], vec![sibling, changed], 1),
    ] {
        let mut honest = Inventory::new(&app.native_registry, y, z);
        let mut attacked = Inventory::new(&app.native_registry, y, z);
        native::claims::build(&NativeSource(&before), &mut honest)?;
        native::claims::build(&NativeSource(&after), &mut attacked)?;
        let (mask, sign, consumers) = if reserved {
            (EvalFinalStaged, -Fp::ONE, 6)
        } else {
            (QueryStage, Fp::ONE, 1)
        };
        let residual = mask_response(
            &app.native_registry,
            mask.circuit_index(),
            degree,
            delta * sign,
            [y, z],
            consumers,
            [before.len(), position],
        );
        check_inventory(&honest, &attacked, &[(mask.circuit_index(), residual)]);
    }
    Ok(())
}

fn check_nested(
    app: &App,
    original: &Proof<C, R>,
    changed: &Proof<C, R>,
    sibling: &Proof<C, R>,
    degree: usize,
    delta: Fq,
    masks: &[(nested::InternalCircuitIndex, usize, Fq)],
) -> Result<()> {
    let [y, z] = [Fq::from(23), Fq::from(29)];
    for (before, after, position) in [
        (vec![original], vec![changed], 0),
        (vec![original, sibling], vec![changed, sibling], 0),
        (vec![sibling, original], vec![sibling, changed], 1),
    ] {
        let mut honest = Inventory::new(&app.nested_registry, y, z);
        let mut attacked = Inventory::new(&app.nested_registry, y, z);
        nested::claims::build(&NestedSource(&before), &mut honest)?;
        nested::claims::build(&NestedSource(&after), &mut attacked)?;
        let expected: Vec<_> = masks
            .iter()
            .map(|&(mask, consumers, sign)| {
                (
                    mask.circuit_index(),
                    mask_response(
                        &app.nested_registry,
                        mask.circuit_index(),
                        degree,
                        delta * sign,
                        [y, z],
                        consumers,
                        [before.len(), position],
                    ),
                )
            })
            .collect();
        check_inventory(&honest, &attacked, &expected);
    }
    Ok(())
}

#[test]
fn native_compensated_transfers_isolate_both_support_masks() -> Result<()> {
    let (app, node, sibling) = fixture()?;
    for d_wire in [false, true] {
        for reserved in [true, false] {
            let gate = if reserved {
                native::stages::query::Stage::<C, R, HEADER_SIZE>::skip_gates()
            } else {
                R::n() - 1
            };
            let degree = degree(gate, d_wire);
            let delta = Fp::from(7);
            let changed = native_transfer(&app, node.proof(), degree, delta);
            check_native(
                &app,
                node.proof(),
                &changed,
                sibling.proof(),
                degree,
                delta,
                reserved,
            )?;
            let restored =
                native_transfer(&app, &changed, degree, -delta).carry::<Number>(*node.data());
            assert!(app.verify(&restored, StdRng::seed_from_u64(0xa07_00d0))?);
        }
    }
    Ok(())
}

#[test]
fn nested_compensated_transfers_isolate_both_support_masks() -> Result<()> {
    use nested::InternalCircuitIndex::{BridgeEval, ChallengeFinalStaged};
    let (app, node, sibling) = fixture()?;
    for d_wire in [false, true] {
        for reserved in [true, false] {
            let gate = if reserved {
                nested::stages::eval::Stage::<<C as Cycle>::HostCurve, R>::skip_gates()
            } else {
                R::n() - 1
            };
            let degree = degree(gate, d_wire);
            let delta = Fq::from(11);
            let changed = nested_transfer(&app, node.proof(), NestedRx::BridgeEval, degree, delta)?;
            let mask = if reserved {
                (ChallengeFinalStaged, 3, -Fq::ONE)
            } else {
                (BridgeEval, 1, Fq::ONE)
            };
            check_nested(
                &app,
                node.proof(),
                &changed,
                sibling.proof(),
                degree,
                delta,
                &[mask],
            )?;
            let restored = nested_transfer(&app, &changed, NestedRx::BridgeEval, degree, -delta)?
                .carry::<Number>(*node.data());
            assert!(app.verify(&restored, StdRng::seed_from_u64(0xa07_00d0))?);
        }
    }
    Ok(())
}

#[test]
fn loading_routed_mismatch_has_a_two_mask_local_cut() -> Result<()> {
    use nested::InternalCircuitIndex::{ChallengeFinalStaged, Loading};
    let (app, node, sibling) = fixture()?;
    let degree = degree(
        nested::stages::f::Stage::<<C as Cycle>::HostCurve, R>::skip_gates(),
        true,
    );
    let old_y = node.proof()[nested::RxIndex::BridgeF]
        .iter_coeffs()
        .nth(degree)
        .unwrap();
    let points = raw_stage::<Fq, nested::PointsStage<<C as Cycle>::HostCurve>>(
        &node.proof()[nested::RxIndex::PointsStage],
    );
    assert_eq!(
        old_y, points[1],
        "BridgeF.native_f.y routes to PointsStage.initial.y"
    );
    // Negating y keeps the point on-curve, but PointsStage.initial stays put.
    let delta = -old_y.double();
    assert_ne!(delta, Fq::ZERO);
    let changed = nested_transfer(&app, node.proof(), NestedRx::BridgeF, degree, delta)?;
    assert!(
        node.proof()[nested::RxIndex::PointsStage]
            .iter_coeffs()
            .eq(changed[nested::RxIndex::PointsStage].iter_coeffs())
    );
    assert_eq!(
        changed[nested::RxIndex::BridgeF]
            .iter_coeffs()
            .nth(degree)
            .unwrap(),
        -old_y
    );
    check_nested(
        &app,
        node.proof(),
        &changed,
        sibling.proof(),
        degree,
        delta,
        &[(Loading, 1, Fq::ONE), (ChallengeFinalStaged, 3, -Fq::ONE)],
    )?;
    let restored = nested_transfer(&app, &changed, NestedRx::BridgeF, degree, -delta)?
        .carry::<Number>(*node.data());
    assert!(app.verify(&restored, StdRng::seed_from_u64(0xa07_00d0))?);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Transfer {
    Native { reserved: bool },
    Nested { reserved: bool },
    Loading,
}

impl Transfer {
    fn native(self) -> bool {
        matches!(self, Self::Native { .. })
    }

    fn degree(self) -> usize {
        let gate = match self {
            Self::Native { reserved: true } => {
                native::stages::query::Stage::<C, R, HEADER_SIZE>::skip_gates()
            }
            Self::Nested { reserved: true } => {
                nested::stages::eval::Stage::<<C as Cycle>::HostCurve, R>::skip_gates()
            }
            Self::Loading => nested::stages::f::Stage::<<C as Cycle>::HostCurve, R>::skip_gates(),
            _ => R::n() - 1,
        };
        // Recursion covers both a and d wires; the local tests cross both
        // wire kinds with both support directions.
        degree(
            gate,
            !matches!(
                self,
                Self::Native { reserved: true } | Self::Nested { reserved: true }
            ),
        )
    }

    fn nested_delta(self, original: &Proof<C, R>) -> Fq {
        if matches!(self, Self::Loading) {
            -original[nested::RxIndex::BridgeF]
                .iter_coeffs()
                .nth(self.degree())
                .unwrap()
                .double()
        } else {
            Fq::from(11)
        }
    }

    fn apply(self, app: &App, original: &Proof<C, R>) -> Result<Proof<C, R>> {
        if self.native() {
            Ok(native_transfer(app, original, self.degree(), Fp::from(7)))
        } else {
            nested_transfer(
                app,
                original,
                if matches!(self, Self::Loading) {
                    NestedRx::BridgeF
                } else {
                    NestedRx::BridgeEval
                },
                self.degree(),
                self.nested_delta(original),
            )
        }
    }
}

/// Explicit row-major off-diagonal expansion of the *stored* second layer,
/// followed by its diagonal. No production folding/claim gadget is used.
fn outer_value<F: Field>(values: &[F], groups: usize, mu: F, nu: F) -> F {
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

/// Both production folds pad groups to seven, including the final group.
/// The diagonal weight is independent of mu at each layer.
fn diagonal_weight<F: Field>(nu: F, nu_prime: F, groups: usize, index: usize) -> F {
    power(nu, 6 - index % 7) * power(nu_prime, groups - 1 - index / 7)
}

/// The first parent's accumulator error must equal the independently
/// predicted child mask residuals at the parent's actual challenges, with
/// independently specified inventory positions. This catches missing,
/// misindexed and wrongly weighted claims in the real fuse path, even if a
/// transcript or opposite-field check would also reject the child.
fn check_first_parent(
    app: &App,
    original: &Proof<C, R>,
    parent: &Proof<C, R>,
    attack: Transfer,
    position: usize,
) -> Result<()> {
    match attack {
        Transfer::Native { reserved } => {
            use native::InternalCircuitIndex::{EvalFinalStaged, QueryStage};
            let (mask, sign, consumers, index) = if reserved {
                (EvalFinalStaged, -Fp::ONE, 6, 91)
            } else {
                (QueryStage, Fp::ONE, 1, 81)
            };
            // 2 raw + 2 app + 74 internal circuit claims precede the masks.
            let expected = mask_response(
                &app.native_registry,
                mask.circuit_index(),
                attack.degree(),
                Fp::from(7) * sign,
                [parent.y(), parent.z()],
                consumers,
                [2, position],
            ) * diagonal_weight(parent.nu(), parent.nu_prime(), 19, index);
            let values = raw_stage::<
                Fp,
                native::stages::outer_error::Stage<C, R, HEADER_SIZE, native::RevdotParameters>,
            >(&parent[native::RxIndex::OuterError]);
            let actual = revdot(&parent.native_a_poly, &parent.native_b_poly)
                - outer_value(&values, 19, parent.mu_prime(), parent.nu_prime());
            assert_ne!(expected, Fp::ZERO);
            assert_eq!(
                actual, expected,
                "native mask error reaches parent's accumulator"
            );
        }
        Transfer::Nested { .. } | Transfer::Loading => {
            use nested::InternalCircuitIndex::{BridgeEval, ChallengeFinalStaged, Loading};
            // 2 raw + 56 endoscaling + 6 instance claims precede the masks.
            let masks = match attack {
                Transfer::Nested { reserved: true } => {
                    vec![(ChallengeFinalStaged, -Fq::ONE, 3, 76)]
                }
                Transfer::Nested { reserved: false } => vec![(BridgeEval, Fq::ONE, 1, 74)],
                Transfer::Loading => vec![
                    (Loading, Fq::ONE, 1, 77),
                    (ChallengeFinalStaged, -Fq::ONE, 3, 76),
                ],
                _ => unreachable!(),
            };
            let nu = nested::challenge::<C>(parent.nu())?;
            let mu_prime = nested::challenge::<C>(parent.mu_prime())?;
            let nu_prime = nested::challenge::<C>(parent.nu_prime())?;
            let yz = [
                nested::challenge::<C>(parent.y())?,
                nested::challenge::<C>(parent.z())?,
            ];
            let expected: Fq = masks
                .into_iter()
                .map(|(mask, sign, consumers, index)| {
                    mask_response(
                        &app.nested_registry,
                        mask.circuit_index(),
                        attack.degree(),
                        attack.nested_delta(original) * sign,
                        yz,
                        consumers,
                        [2, position],
                    ) * diagonal_weight(nu, nu_prime, 12, index)
                })
                .sum();
            let values = raw_stage::<
                Fq,
                nested::stages::outer_error::Stage<<C as Cycle>::HostCurve, R>,
            >(&parent[nested::RxIndex::BridgeOuterError]);
            // The bridge starts with the native outer-error commitment's x/y.
            let actual = revdot(&parent.nested_a_poly, &parent.nested_b_poly)
                - outer_value(&values[2..], 12, mu_prime, nu_prime);
            assert_ne!(expected, Fq::ZERO);
            assert_eq!(
                actual, expected,
                "nested mask error reaches parent's accumulator"
            );
        }
    }
    Ok(())
}

/// Name the recursive circuit carrying the error, independently expanding
/// its trace/stage equation and its public instance (shared with A12).
fn check_collapse(app: &App, proof: &Proof<C, R>, native: bool, invalid: bool) -> Result<()> {
    if native {
        use native::RxIndex::{OuterCollapse, OuterError, Preamble};
        let [y, z] = [Fp::from(37), Fp::from(41)];
        let residual = circuit_value(
            &app.native_registry,
            native::InternalCircuitIndex::OuterCollapseCircuit.circuit_index(),
            &[&proof[OuterCollapse], &proof[Preamble], &proof[OuterError]],
            y,
            z,
        ) - native_ky(proof, y);
        assert_eq!(
            residual != Fp::ZERO,
            invalid,
            "native outer-collapse equation"
        );
    } else {
        use nested::RxIndex::*;
        let [y, z] = [Fq::from(43), Fq::from(47)];
        let rxs = [
            Collapse,
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
            nested::InternalCircuitIndex::Collapse.circuit_index(),
            &rxs.map(|id| &proof[id]),
            y,
            z,
        ) - nested_ky(proof, y)?;
        assert_eq!(residual != Fq::ZERO, invalid, "nested collapse equation");
    }
    Ok(())
}

fn check_decider(app: &App, node: &Node, native: bool, invalid: bool) -> Result<()> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(0xa07_dec1de))?;
    let checks = checks.expect("well-formed metadata must reach the decider");
    assert_eq!(accepted, !invalid);
    assert_eq!(accepted, checks.all());
    assert!(
        checks.commitments,
        "every edited polynomial's cache was repaired"
    );
    assert_eq!(
        if native {
            checks.native_revdot
        } else {
            checks.nested_revdot
        },
        !invalid
    );
    Ok(())
}

#[test]
fn compensated_support_and_loading_errors_propagate_through_two_generations() -> Result<()> {
    let (app, node, sibling) = fixture()?;
    for attack in [
        Transfer::Native { reserved: true },
        Transfer::Native { reserved: false },
        Transfer::Nested { reserved: true },
        Transfer::Nested { reserved: false },
        Transfer::Loading,
    ] {
        let changed = attack
            .apply(&app, node.proof())?
            .carry::<Number>(*node.data());
        check_decider(&app, &changed, attack.native(), true)?;
        for position in 0..2 {
            let mut valid = node.clone();
            let mut invalid = changed.clone();
            for generation in 0..2 {
                let left = (position + generation) % 2 == 0;
                let (good_left, good_right, bad_left, bad_right) = if left {
                    (valid, sibling.clone(), invalid, sibling.clone())
                } else {
                    (sibling.clone(), valid, sibling.clone(), invalid)
                };
                // Paired RNG streams and asymmetric children are deliberate.
                // A construction error is not counted as rejection.
                let seed = 0xa07_f053 + (position * 2 + generation) as u64;
                let mut honest_rng = StdRng::seed_from_u64(seed);
                let mut rng = StdRng::seed_from_u64(seed);
                valid = app.fuse(&mut honest_rng, Add, (), good_left, good_right)?.0;
                invalid = app.fuse(&mut rng, Add, (), bad_left, bad_right)?.0;
                assert_eq!(valid.data(), invalid.data());
                check_decider(&app, &valid, attack.native(), false)?;
                check_decider(&app, &invalid, attack.native(), true)?;
                check_collapse(&app, valid.proof(), attack.native(), false)?;
                check_collapse(&app, invalid.proof(), attack.native(), true)?;
                if generation == 0 {
                    check_first_parent(&app, node.proof(), invalid.proof(), attack, position)?;
                }
            }
        }
    }
    Ok(())
}
