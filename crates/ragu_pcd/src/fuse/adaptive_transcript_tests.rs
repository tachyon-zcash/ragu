//! T01-T06, T09, A09, R07/R08 and V09: adaptive attacks against actual transcript deadlines.
//!
//! The hooks run after production squeezes the challenge and cannot modify
//! earlier builder cells. Fusion regenerates every later trace and walk. An
//! independent expanded batch checks the false relation and exact aggregate
//! cancellation; actual stage coefficients authenticate the earlier object.
//!
//! Delayed-commitment controls below are LOCAL SHADOW GAMES: they replace the
//! frozen stage only in the expanded circuit equation. Their accepting result
//! is not a production Fiat-Shamir forgery or an accepting whole-proof mutant.

use alloc::{sync::Arc, vec, vec::Vec};

use ragu_arithmetic::{
    CurveAffine as _, FixedGenerators,
    ff::PrimeField,
    group::{Curve, CurveAffine, Group},
};
use ragu_pasta::{EpAffine, EqAffine};
use ragu_primitives::{extract_endoscalar, lift_endoscalar};

use super::{
    batch_fingerprint_tests,
    quotient_transfer_tests::{
        ExpandedBatch, check_prefix, circuit_value, evaluate, native_batch, native_ky,
        nested_batch, nested_ky, power, revdot,
    },
    test_steps::{Add, Leaf, Number},
    transcript_tests::{bridge_points, coordinates, raw_stage, replay},
    *,
};
use crate::{
    Pcd,
    fuse::{NativeSPrime, NestedSPrime, SuffixAttack},
    internal::native,
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
type Poly<F> = sparse::Polynomial<F, R>;
type NativeEval = native::stages::eval::Stage<C, R, HEADER_SIZE>;
type NestedEval = nested::stages::eval::Stage<EqAffine, R>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Native,
    Nested,
}

fn same<F: Field>(a: &Poly<F>, b: &Poly<F>) -> bool {
    a.iter_coeffs().eq(b.iter_coeffs())
}

fn set_stage<F: Field, S: Stage<F, R>>(poly: &mut Poly<F>, values: &[(usize, F)]) {
    let mut coefficients: Vec<_> = poly.iter_coeffs().collect();
    for &(slot, value) in values {
        assert!(slot < S::values());
        let gate = S::skip_gates() + slot / 2;
        coefficients[(if slot % 2 == 0 { 2 } else { 4 }) * R::n() - 1 - gate] = value;
    }
    *poly = Poly::from_coeffs(coefficients);
}

fn check_frozen(honest: &Proof<C, R>, changed: &Proof<C, R>) -> Result<()> {
    check_prefix(honest, changed);
    // All eight commitments and all eleven actual hash outputs are fixed,
    // including Eval, which is after u but before the second attack deadline.
    assert_eq!(bridge_points(honest), bridge_points(changed));
    assert_eq!(
        honest.challenges().in_order(),
        changed.challenges().in_order()
    );
    assert_eq!(
        replay(&bridge_points(changed), None, &[])?.challenges,
        changed.challenges().in_order()
    );
    for id in [native::RxIndex::PointsF, native::RxIndex::Eval] {
        assert!(same(&honest[id], &changed[id]), "frozen {id:?}");
        assert_eq!(
            honest.native_rx_commitment(id),
            changed.native_rx_commitment(id)
        );
    }
    for id in [
        nested::RxIndex::BridgeF,
        nested::RxIndex::BridgeEval,
        nested::RxIndex::ChallengeStage,
    ] {
        assert!(same(&honest[id], &changed[id]), "frozen {id:?}");
    }
    assert_eq!(
        honest.nested_challenges_partial(),
        changed.nested_challenges_partial()
    );
    assert_eq!(honest.v(), changed.v());
    assert_eq!(honest.nested_v()?, changed.nested_v()?);
    Ok(())
}

/// Rehashing the shadow game's changed commitment loses the original attack
/// challenge. This is a counterfactual replay, never a repair of the real proof.
fn rehash_late_bridge(
    app: &App,
    original: &Proof<C, R>,
    late: &Proof<C, R>,
    quotient: bool,
) -> Result<()> {
    let (index, deadline, polynomial) = if quotient {
        (6, 9, &late.bridge_f_rx)
    } else {
        (7, 10, &late.bridge_eval_rx)
    };
    let mut points = bridge_points(original);
    let commitment =
        ReferenceBackend::sparse_commit_to_affine(polynomial, C::nested_generators(app.params));
    assert_ne!(commitment, points[index]);
    points[index] = commitment;
    let new = replay(&points, None, &[])?.challenges;
    let old = original.challenges().in_order();
    assert_eq!(&new[..deadline], &old[..deadline]);
    assert_ne!(new[deadline], old[deadline]);
    Ok(())
}

fn decider(app: &App, node: &Node, bad_field: Option<Side>) -> Result<()> {
    // The proof is fixed before any of these verifier seeds are sampled.
    for seed in [0x873_0301, 0x873_0401] {
        let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
        let expected = VerificationChecks {
            native_revdot: bad_field != Some(Side::Native),
            nested_revdot: bad_field != Some(Side::Nested),
            native_registry: true,
            nested_registry: true,
            nested_challenges: true,
            commitments: true,
            nested_points: true,
            transcript: true,
            ab_bridge: true,
            mesh: true,
        };
        assert_eq!(
            accepted,
            bad_field.is_none(),
            "root verdict with {checks:?}"
        );
        assert_eq!(checks.unwrap(), expected);
    }
    Ok(())
}

fn native_equation(app: &App, proof: &Proof<C, R>, binding: bool) -> Fp {
    use native::{InternalCircuitIndex as Circuit, RxIndex::*};
    let (circuit, ids) = if binding {
        (
            Circuit::BindEndoscalarCircuit,
            vec![
                BindEndoscalar,
                PointsBinding,
                PointsChildren,
                PointsRegistryWx,
                PointsAb,
                PointsF,
                PointsWalk,
            ],
        )
    } else {
        (
            Circuit::ComputeVCircuit,
            vec![ComputeV, Preamble, Query, Eval],
        )
    };
    let y = Fp::from(29);
    circuit_value(
        &app.native_registry,
        circuit.circuit_index(),
        &ids.iter().map(|&id| &proof[id]).collect::<Vec<_>>(),
        y,
        Fp::from(31),
    ) - native_ky(proof, y)
}

fn nested_equation(app: &App, proof: &Proof<C, R>, binding: bool) -> Result<Fq> {
    use nested::{InternalCircuitIndex as Circuit, RxIndex::*};
    if binding {
        // Loading is a linear bonding claim with k(y)=0. In one proof its
        // single fold group is exactly these seven stages; it has no own rx.
        let sy = ReferenceBackend::registry_circuit_y(
            &app.nested_registry,
            Circuit::Loading.circuit_index(),
            Fq::from(37),
        );
        return Ok([
            PointsStage,
            BridgePreamble,
            BridgeSPrime,
            BridgeInnerError,
            BridgeAB,
            BridgeQuery,
            BridgeF,
        ]
        .iter()
        .map(|&id| revdot(&proof[id], &sy))
        .sum());
    }
    let ids = [
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
    ];
    let y = Fq::from(37);
    Ok(circuit_value(
        &app.nested_registry,
        Circuit::ComputeV.circuit_index(),
        &ids.map(|id| &proof[id]),
        y,
        Fq::from(41),
    ) - nested_ky(proof, y)?)
}

fn collapse(app: &App, proof: &Proof<C, R>, side: Side) -> Result<()> {
    use native::{InternalCircuitIndex as Circuit, RxIndex::*};
    let y = Fp::from(29);
    let residual = circuit_value(
        &app.native_registry,
        Circuit::OuterCollapseCircuit.circuit_index(),
        &[&proof[OuterCollapse], &proof[Preamble], &proof[OuterError]],
        y,
        Fp::from(31),
    ) - native_ky(proof, y);
    assert_eq!(residual != Fp::ZERO, side == Side::Native);
    use nested::RxIndex as N;
    let ids = [
        N::Collapse,
        N::EndoscalarStage,
        N::PointsStage,
        N::BridgePreamble,
        N::BridgeSPrime,
        N::BridgeInnerError,
        N::BridgeOuterError,
        N::BridgeAB,
        N::BridgeQuery,
        N::BridgeF,
        N::BridgeEval,
        N::ChallengeStage,
    ];
    let y = Fq::from(37);
    let residual = circuit_value(
        &app.nested_registry,
        nested::InternalCircuitIndex::Collapse.circuit_index(),
        &ids.map(|id| &proof[id]),
        y,
        Fq::from(41),
    ) - nested_ky(proof, y)?;
    assert_eq!(residual != Fq::ZERO, side == Side::Nested);
    Ok(())
}

fn descendants(app: &App, changed: &Node, honest: &Node, sibling: &Node, side: Side) -> Result<()> {
    for on_left in [true, false] {
        let mut bad = changed.clone();
        let mut good = honest.clone();
        for generation in 0..2 {
            let mut rng = StdRng::seed_from_u64(0x873_0340 + generation);
            let mut fuse = |node: Node| {
                let (l, r) = if on_left ^ (generation == 1) {
                    (node, sibling.clone())
                } else {
                    (sibling.clone(), node)
                };
                app.fuse(&mut rng, Add, (), l, r).map(|p| p.0)
            };
            bad = fuse(bad)?;
            good = fuse(good)?;
            assert_eq!(*bad.data(), *good.data());
            decider(app, &good, None)?;
            decider(app, &bad, Some(side))?;
            collapse(app, bad.proof(), side)?;
        }
    }
    Ok(())
}

struct Fixture {
    app: App,
    left: Node,
    right: Node,
    honest: Node,
}

impl Fixture {
    fn new() -> Result<Self> {
        let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(Leaf)?
            .register(Add)?
            .finalize(Pasta::baked())?;
        let mut rng = StdRng::seed_from_u64(0x873_0300);
        let left = app.seed(&mut rng, Leaf, Fp::from(19))?.0;
        let right = app.seed(&mut rng, Leaf, Fp::from(43))?.0;
        let honest = app
            .fuse(
                &mut StdRng::seed_from_u64(0x873_f053),
                Add,
                (),
                left.clone(),
                right.clone(),
            )?
            .0;
        decider(&app, &honest, None)?;
        assert_eq!(*honest.data(), Fp::from(62));
        Ok(Self {
            app,
            left,
            right,
            honest,
        })
    }

    fn run(&self, attack: &mut impl SuffixAttack<C, R>) -> Result<Node> {
        Ok(self
            .app
            .fuse_inner(
                &mut StdRng::seed_from_u64(0x873_f053),
                Add,
                (),
                self.left.clone(),
                self.right.clone(),
                |_, _| {},
                |_| Ok(None),
                attack,
            )?
            .0)
    }
}

struct QuotientAttack {
    side: Side,
    degree: usize,
    erase: bool,
    calls: usize,
    native: Vec<Fp>,
    nested: Vec<Fq>,
}

/// q'(X) = q(X) + 7 X^d (X-u). u is supplied by the actual squeeze;
/// neither the strategy nor the late-commitment model chooses a hash output.
fn adaptive_quotient<F: PrimeField>(poly: &mut Poly<F>, u: F, degree: usize, erase: bool) {
    let before: Vec<_> = poly.iter_coeffs().collect();
    let mut after = before.clone();
    after[degree] -= F::from(7) * u;
    after[degree + 1] += F::from(7);
    assert_ne!(after, before);
    assert_eq!(evaluate(&after, u), evaluate(&before, u));
    let t = u + F::ONE;
    assert_ne!(t, F::ZERO);
    assert_eq!(
        evaluate(&after, t) - evaluate(&before, t),
        F::from(7) * power(t, degree)
    );
    assert_ne!(evaluate(&after, t), evaluate(&before, t));
    *poly = Poly::from_coeffs(if erase { before } else { after });
}

impl SuffixAttack<C, R> for QuotientAttack {
    fn after_u(&mut self, u: Fp, native: &mut Poly<Fp>, nested: &mut Poly<Fq>) -> bool {
        self.calls += 1;
        match self.side {
            Side::Native => adaptive_quotient(native, u, self.degree, self.erase),
            Side::Nested => adaptive_quotient(
                nested,
                nested::challenge::<C>(u).unwrap(),
                self.degree,
                self.erase,
            ),
        }
        self.native = native.iter_coeffs().collect();
        self.nested = nested.iter_coeffs().collect();
        true
    }
}

fn quotient_batch<F: PrimeField>(
    batch: &ExpandedBatch<F>,
    retained: &[F],
    actual_p: &Poly<F>,
    actual_v: F,
    degree: usize,
    attacked: bool,
) {
    let honest = batch.quotient();
    let mut delta = vec![F::ZERO; honest.len()];
    if attacked {
        delta[degree] = -F::from(7) * batch.u;
        delta[degree + 1] = F::from(7);
    }
    assert_eq!(
        retained
            .iter()
            .zip(&honest)
            .map(|(a, b)| *a - b)
            .collect::<Vec<_>>(),
        delta,
        "attack-preservation guard: exact post-u difference"
    );
    assert_eq!(retained != honest, attacked);
    assert!(actual_p.iter_coeffs().eq(batch.accumulate(retained)));
    assert_eq!(evaluate(retained, batch.u), evaluate(&honest, batch.u));
    assert_eq!(actual_v, evaluate(&batch.accumulate(&honest), batch.u));
}

fn quotient_experiment(side: Side) -> Result<()> {
    let f = Fixture::new()?;
    for degree in [0, R::num_coeffs() - 3] {
        let mut attack = QuotientAttack {
            side,
            degree,
            erase: false,
            calls: 0,
            native: Vec::new(),
            nested: Vec::new(),
        };
        let changed = f.run(&mut attack)?;
        assert_eq!(attack.calls, 1);
        check_frozen(f.honest.proof(), changed.proof())?;
        let children = [f.left.proof(), f.right.proof()];
        let n = native_batch(&f.app, changed.proof(), children);
        let q = nested_batch(&f.app, changed.proof(), children)?;
        quotient_batch(
            &n,
            &attack.native,
            changed.proof().native_p_poly(),
            changed.proof().v(),
            degree,
            side == Side::Native,
        );
        quotient_batch(
            &q,
            &attack.nested,
            changed.proof().nested_p_poly(),
            changed.proof().nested_v()?,
            degree,
            side == Side::Nested,
        );
        // The false polynomial still has a truthful cache and exactly the same
        // evaluation. Authentication fails in the opposite field's point stage.
        let bad_field = if side == Side::Native {
            Side::Nested
        } else {
            Side::Native
        };
        decider(&f.app, &changed, Some(bad_field))?;
        let mut late = changed.proof().clone();
        match side {
            Side::Native => {
                let commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(attack.native),
                    C::host_generators(f.app.params),
                );
                type S = nested::stages::f::Stage<EqAffine, R>;
                let old = raw_stage::<Fq, S>(&late.bridge_f_rx);
                assert_ne!(&old[..2], &coordinates(commitment));
                assert_ne!(nested_equation(&f.app, changed.proof(), true)?, Fq::ZERO);
                let [x, y] = coordinates(commitment);
                set_stage::<Fq, S>(Arc::make_mut(&mut late.bridge_f_rx), &[(0, x), (1, y)]);
                // Delaying the commitment admits the false quotient in this
                // local binding equation. The actual early stage stays fixed.
                assert_eq!(nested_equation(&f.app, &late, true)?, Fq::ZERO);
            }
            Side::Nested => {
                let commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(attack.nested),
                    C::nested_generators(f.app.params),
                );
                type S = native::stages::points::FStage<EpAffine>;
                let old = raw_stage::<Fp, S>(&late.native_points_f_rx);
                assert_ne!(&old[2..4], &coordinates(commitment));
                assert_ne!(native_equation(&f.app, changed.proof(), true), Fp::ZERO);
                let [x, y] = coordinates(commitment);
                set_stage::<Fp, S>(&mut late.native_points_f_rx, &[(2, x), (3, y)]);
                assert_eq!(native_equation(&f.app, &late, true), Fp::ZERO);
                let stage_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &late.native_points_f_rx,
                    C::host_generators(f.app.params),
                );
                let [x, y] = coordinates(stage_commitment);
                set_stage::<Fq, nested::stages::f::Stage<EqAffine, R>>(
                    Arc::make_mut(&mut late.bridge_f_rx),
                    &[(2, x), (3, y)],
                );
            }
        }
        rehash_late_bridge(&f.app, changed.proof(), &late, true)?;
        descendants(&f.app, &changed, &f.honest, &f.right, bad_field)?;
    }
    // Actual suffix replay deliberately erases the edit. It accepts but fails
    // the semantic attack guard (every retained coefficient is honest).
    let mut erased = QuotientAttack {
        side,
        degree: 0,
        erase: true,
        calls: 0,
        native: Vec::new(),
        nested: Vec::new(),
    };
    let node = f.run(&mut erased)?;
    assert_eq!(erased.calls, 1);
    let children = [f.left.proof(), f.right.proof()];
    quotient_batch(
        &native_batch(&f.app, node.proof(), children),
        &erased.native,
        node.proof().native_p_poly(),
        node.proof().v(),
        0,
        false,
    );
    quotient_batch(
        &nested_batch(&f.app, node.proof(), children)?,
        &erased.nested,
        node.proof().nested_p_poly(),
        node.proof().nested_v()?,
        0,
        false,
    );
    check_frozen(f.honest.proof(), node.proof())?;
    decider(&f.app, &node, None)
}

/// The coefficient of Eval[i] in f(u), independently expanded from every
/// opening occurrence. Its total weight in v also includes the direct beta
/// term. Using just adjacent beta powers would miss the quotient contribution.
struct EvalWeights<F> {
    count: usize,
    slots: [usize; 2],
    quotient: [F; 2],
}

impl<F: PrimeField> EvalWeights<F> {
    fn new(batch: &ExpandedBatch<F>, pair: usize) -> Self {
        let count = batch.polynomials.len();
        let slots = if pair == 0 {
            [count - 3, count - 2]
        } else {
            [count - 6, count - 5]
        };
        let quotient = slots.map(|index| {
            batch
                .queries
                .iter()
                .enumerate()
                .filter(|(_, (i, _))| *i == index)
                .map(|(j, (_, point))| {
                    power(batch.alpha, batch.queries.len() - 1 - j)
                        * (batch.u - point).invert().unwrap()
                })
                .sum()
        });
        Self {
            count,
            slots,
            quotient,
        }
    }

    fn weights(&self, beta: F) -> [F; 2] {
        core::array::from_fn(|i| {
            power(beta, self.count - 1 - self.slots[i]) + power(beta, self.count) * self.quotient[i]
        })
    }

    fn errors(&self, beta: F) -> [F; 2] {
        let [a, b] = self.weights(beta);
        let delta = [F::from(7) * b, -F::from(7) * a];
        assert!(delta.iter().all(|d| *d != F::ZERO));
        assert_eq!(a * delta[0] + b * delta[1], F::ZERO);
        assert_ne!(
            self.quotient[0] * delta[0] + self.quotient[1] * delta[1],
            F::ZERO
        );
        // A fixed candidate does not cancel at independent model challenges.
        let mut rng = StdRng::seed_from_u64(0x873_0404);
        for _ in 0..4 {
            let [a, b] = self.weights(F::random(&mut rng));
            assert_ne!(a * delta[0] + b * delta[1], F::ZERO);
        }
        delta
    }
}

struct EvalAttack {
    side: Side,
    pair: usize,
    erase: bool,
    calls: usize,
    native: EvalWeights<Fp>,
    nested: EvalWeights<Fq>,
    native_delta: [Fp; 2],
    nested_delta: [Fq; 2],
}

fn perturb_pair<F: Field>(a: &mut F, b: &mut F, delta: [F; 2], erase: bool) {
    let before = [*a, *b];
    *a += delta[0];
    *b += delta[1];
    assert_ne!(*a, before[0]);
    assert_ne!(*b, before[1]);
    if erase {
        // Exercise a repair that overwrites the adversary's real edit.
        [*a, *b] = before;
    }
}

impl SuffixAttack<C, R> for EvalAttack {
    fn after_pre_beta(
        &mut self,
        pre_beta: Fp,
        native: &mut native::stages::eval::Witness<C>,
        nested: &mut nested::stages::eval::Evaluations<Fq>,
        _nested_challenges: &mut nested::stages::challenges::Witness<Fq>,
    ) {
        self.calls += 1;
        let bits = extract_endoscalar(pre_beta).unwrap();
        match self.side {
            Side::Native => {
                self.native_delta = self.native.errors(lift_endoscalar(bits));
                let (a, b) = if self.pair == 0 {
                    (&mut native.current.a_poly, &mut native.current.b_poly)
                } else {
                    (
                        &mut native.current.registry_wx0,
                        &mut native.current.registry_wx1,
                    )
                };
                perturb_pair(a, b, self.native_delta, self.erase);
            }
            Side::Nested => {
                self.nested_delta = self.nested.errors(lift_endoscalar(bits));
                let (a, b) = if self.pair == 0 {
                    (&mut nested.current.a_poly, &mut nested.current.b_poly)
                } else {
                    (
                        &mut nested.current.registry_wx0,
                        &mut nested.current.registry_wx1,
                    )
                };
                perturb_pair(a, b, self.nested_delta, self.erase);
            }
        }
    }
}

fn eval_model<F: PrimeField>(
    batch: &ExpandedBatch<F>,
    staged: &[F],
    weights: &EvalWeights<F>,
    delta: [F; 2],
    actual_v: F,
) -> Vec<(usize, F)> {
    let honest: Vec<_> = batch
        .polynomials
        .iter()
        .map(|p| evaluate(&p.iter_coeffs().collect::<Vec<_>>(), batch.u))
        .collect();
    assert_eq!(
        staged, honest,
        "authenticate each actual pre-beta evaluation entry"
    );
    let mut forged = honest.clone();
    for i in 0..2 {
        forged[weights.slots[i]] += delta[i];
    }
    assert_eq!(
        forged.iter().zip(&honest).filter(|(a, b)| a != b).count(),
        2
    );
    let quotient_value = |entries: &[F]| {
        batch
            .queries
            .iter()
            .enumerate()
            .map(|(j, &(i, point))| {
                power(batch.alpha, batch.queries.len() - 1 - j)
                    * (entries[i]
                        - evaluate(
                            &batch.polynomials[i].iter_coeffs().collect::<Vec<_>>(),
                            point,
                        ))
                    * (batch.u - point).invert().unwrap()
            })
            .sum::<F>()
    };
    let v = |entries: &[F]| {
        power(batch.beta, entries.len()) * quotient_value(entries)
            + entries
                .iter()
                .enumerate()
                .map(|(i, e)| power(batch.beta, entries.len() - 1 - i) * e)
                .sum::<F>()
    };
    assert_eq!(v(&honest), actual_v);
    assert_eq!(
        v(&forged),
        actual_v,
        "late-Eval shadow model admits cancellation"
    );
    assert_ne!(quotient_value(&honest), quotient_value(&forged));
    // Each unpaired edit is detectable, despite the paired aggregate matching.
    for i in 0..2 {
        let mut single = honest.clone();
        single[weights.slots[i]] += delta[i];
        assert_ne!(v(&single), actual_v);
    }
    weights.slots.map(|i| (i, forged[i])).to_vec()
}

fn eval_experiment(side: Side) -> Result<()> {
    let f = Fixture::new()?;
    let children = [f.left.proof(), f.right.proof()];
    let n = native_batch(&f.app, f.honest.proof(), children);
    let q = nested_batch(&f.app, f.honest.proof(), children)?;
    for pair in 0..2 {
        let mut attack = EvalAttack {
            side,
            pair,
            erase: false,
            calls: 0,
            native: EvalWeights::new(&n, pair),
            nested: EvalWeights::new(&q, pair),
            native_delta: [Fp::ZERO; 2],
            nested_delta: [Fq::ZERO; 2],
        };
        let changed = f.run(&mut attack)?;
        assert_eq!(attack.calls, 1);
        check_frozen(f.honest.proof(), changed.proof())?;
        assert!(same(
            changed.proof().native_p_poly(),
            f.honest.proof().native_p_poly()
        ));
        assert!(same(
            changed.proof().nested_p_poly(),
            f.honest.proof().nested_p_poly()
        ));
        decider(&f.app, &changed, Some(side))?;
        let mut late = changed.proof().clone();
        match side {
            Side::Native => {
                let staged = raw_stage::<Fp, NativeEval>(&late.native_eval_rx);
                let edits = eval_model(
                    &n,
                    &staged[..112],
                    &attack.native,
                    attack.native_delta,
                    late.v(),
                );
                assert_ne!(native_equation(&f.app, &late, false), Fp::ZERO);
                set_stage::<Fp, NativeEval>(&mut late.native_eval_rx, &edits);
                assert_eq!(
                    native_equation(&f.app, &late, false),
                    Fp::ZERO,
                    "delayed Eval admits the repaired local ComputeV witness"
                );
                let commitment = ReferenceBackend::sparse_commit_to_affine(
                    &late.native_eval_rx,
                    C::host_generators(f.app.params),
                );
                let [x, y] = coordinates(commitment);
                set_stage::<Fq, NestedEval>(
                    Arc::make_mut(&mut late.bridge_eval_rx),
                    &[(0, x), (1, y)],
                );
            }
            Side::Nested => {
                let staged = raw_stage::<Fq, NestedEval>(&late.bridge_eval_rx);
                let edits = eval_model(
                    &q,
                    &staged[2..],
                    &attack.nested,
                    attack.nested_delta,
                    late.nested_v()?,
                )
                .into_iter()
                .map(|(i, v)| (i + 2, v))
                .collect::<Vec<_>>();
                assert_ne!(nested_equation(&f.app, &late, false)?, Fq::ZERO);
                set_stage::<Fq, NestedEval>(Arc::make_mut(&mut late.bridge_eval_rx), &edits);
                assert_eq!(
                    nested_equation(&f.app, &late, false)?,
                    Fq::ZERO,
                    "delayed Eval admits the repaired local ComputeV witness"
                );
            }
        }
        rehash_late_bridge(&f.app, changed.proof(), &late, false)?;
        descendants(&f.app, &changed, &f.honest, &f.right, side)?;
        // Restoring the real witness erases the attack. The semantic guard
        // refuses it: the expected nonzero local residual is now zero.
        attack.erase = true;
        attack.calls = 0;
        let erased = f.run(&mut attack)?;
        assert_eq!(attack.calls, 1);
        check_frozen(f.honest.proof(), erased.proof())?;
        assert_eq!(native_equation(&f.app, erased.proof(), false), Fp::ZERO);
        assert_eq!(nested_equation(&f.app, erased.proof(), false)?, Fq::ZERO);
        decider(&f.app, &erased, None)?;
    }
    Ok(())
}

/// V09 changes only the challenge stage's beta coefficient after the actual
/// `pre_beta` squeeze. The Eval stages and their exported binding partial have
/// already been committed, so the ordinary suffix cannot make the changed
/// coefficient agree with both the transcript and the frozen partial.
struct ChallengeCompletionAttack {
    delta: Fq,
    erase: bool,
    calls: usize,
    expected_beta: Fq,
    retained_beta: Fq,
}

impl SuffixAttack<C, R> for ChallengeCompletionAttack {
    fn after_pre_beta(
        &mut self,
        pre_beta: Fp,
        _native: &mut native::stages::eval::Witness<C>,
        _nested: &mut nested::stages::eval::Evaluations<Fq>,
        nested_challenges: &mut nested::stages::challenges::Witness<Fq>,
    ) {
        self.calls += 1;
        self.expected_beta = nested::challenge::<C>(pre_beta).unwrap();
        assert_eq!(nested_challenges.beta, self.expected_beta);
        if !self.erase {
            nested_challenges.beta += self.delta;
        }
        self.retained_beta = nested_challenges.beta;
    }
}

fn bind_beta_residual(app: &App, proof: &Proof<C, R>) -> Fp {
    use native::{InternalCircuitIndex as Circuit, RxIndex::*};
    let y = Fp::from(29);
    circuit_value(
        &app.native_registry,
        Circuit::BindBetaCircuit.circuit_index(),
        &[
            &proof[BindBeta],
            &proof[PointsBinding],
            &proof[Preamble],
            &proof[OuterError],
        ],
        y,
        Fp::from(31),
    ) - native_ky(proof, y)
}

fn challenge_completion_frontier(honest: &Proof<C, R>, changed: &Proof<C, R>) -> Result<()> {
    check_prefix(honest, changed);
    assert_eq!(bridge_points(honest), bridge_points(changed));
    assert_eq!(
        honest.challenges().in_order(),
        changed.challenges().in_order()
    );
    assert_eq!(
        replay(&bridge_points(changed), None, &[])?.challenges,
        changed.challenges().in_order()
    );
    assert!(same(&honest.native_eval_rx, &changed.native_eval_rx));
    assert_eq!(
        honest.native_rx_commitment(native::RxIndex::Eval),
        changed.native_rx_commitment(native::RxIndex::Eval)
    );
    assert!(same(&honest.bridge_eval_rx, &changed.bridge_eval_rx));
    assert_eq!(
        honest.bridge_eval_commitment(),
        changed.bridge_eval_commitment()
    );
    assert_eq!(
        honest.nested_challenges_partial(),
        changed.nested_challenges_partial(),
        "the pre-beta partial must stay fixed"
    );
    Ok(())
}

fn challenge_completion_model(
    f: &Fixture,
    changed: &Node,
    attack: &ChallengeCompletionAttack,
    attacked: bool,
) -> Result<()> {
    type Challenges = nested::stages::challenges::Stage<EqAffine, R>;

    challenge_completion_frontier(f.honest.proof(), changed.proof())?;
    let honest_stage = raw_stage::<Fq, Challenges>(&f.honest.proof().nested_challenges_rx);
    let changed_stage = raw_stage::<Fq, Challenges>(&changed.proof().nested_challenges_rx);
    let beta_slot = 2 * nested::stages::challenges::BETA_INDEX;
    assert_eq!(honest_stage[beta_slot], attack.expected_beta);
    assert_eq!(changed_stage[beta_slot], attack.retained_beta);
    assert_eq!(changed_stage[beta_slot + 1], Fq::ZERO);
    assert_eq!(
        honest_stage
            .iter()
            .zip(&changed_stage)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect::<Vec<_>>(),
        if attacked { vec![beta_slot] } else { vec![] },
        "attack-preservation guard: only beta's a-wire may change"
    );

    let params = f.app.params;
    let generator =
        C::nested_generators(params).g()[native::circuits::bind_beta::generator_index::<C, R>()];
    let partial = changed.proof().nested_challenges_partial();
    let honest_completed = (partial.to_curve() + generator * attack.expected_beta).to_affine();
    assert_eq!(
        honest_completed,
        f.honest.proof().nested_challenges_commitment()
    );
    let retained_completed = (partial.to_curve() + generator * attack.retained_beta).to_affine();
    assert_eq!(
        retained_completed,
        changed.proof().nested_challenges_commitment(),
        "independently expand the retained challenge-stage commitment"
    );
    assert_eq!(retained_completed != honest_completed, attacked);

    // LOCAL DELAYED-PARTIAL MODEL. If the exported partial could be selected
    // after beta, this compensating point would make the parent's completion
    // equation accept the changed stage. Production keeps `partial` above.
    let late_partial =
        (retained_completed.to_curve() - generator * attack.expected_beta).to_affine();
    assert_eq!(late_partial != partial, attacked);
    assert_eq!(
        (late_partial.to_curve() + generator * attack.expected_beta).to_affine(),
        retained_completed,
        "late-partial shadow model must admit exact compensation"
    );
    Ok(())
}

fn child_bind_beta_expectations(app: &App, child: &Proof<C, R>) -> Result<Vec<EpAffine>> {
    let generator = C::nested_generators(app.params).g()
        [native::circuits::bind_beta::generator_index::<C, R>()];
    let beta = nested::challenge::<C>(child.pre_beta())?;
    let completed = (child.nested_challenges_partial().to_curve() + generator * beta).to_affine();
    Ok(vec![
        child.bridge_preamble_commitment(),
        child.bridge_s_prime_commitment(),
        child.bridge_inner_error_commitment(),
        child.bridge_outer_error_commitment(),
        child.bridge_ab_commitment(),
        child.bridge_query_commitment(),
        child.bridge_f_commitment(),
        child.bridge_eval_commitment(),
        completed,
        child.nested_a_commitment(),
        child.nested_b_commitment(),
        child.nested_registry_xy_commitment(),
        child.nested_p_commitment(),
    ])
}

/// Expand BindBeta's 26 semantic point equalities independently of the
/// circuit. `actual` is the parent's walked BindingStage; `expected` is
/// rebuilt from each child's exported instance and transcript challenge.
fn bind_beta_edge_residuals(
    app: &App,
    parent: &Proof<C, R>,
    children: [&Proof<C, R>; 2],
) -> Result<Vec<ragu_pasta::Ep>> {
    type Binding = native::stages::points::BindingStage<EpAffine>;

    let values = raw_stage::<Fp, Binding>(&parent.native_points_binding_rx);
    let actual: Vec<_> = values
        .chunks_exact(2)
        .map(|xy| EpAffine::from_xy(xy[0], xy[1]).unwrap())
        .collect();
    let mut expected = child_bind_beta_expectations(app, children[0])?;
    expected.extend(child_bind_beta_expectations(app, children[1])?);
    assert_eq!(actual.len(), 26, "all walked BindBeta points");
    assert_eq!(actual.len(), expected.len());
    Ok(actual
        .into_iter()
        .zip(expected)
        .map(|(actual, expected)| actual.to_curve() - expected.to_curve())
        .collect())
}

fn completion_cut_accepts(residuals: &[ragu_pasta::Ep], omitted: &[usize]) -> bool {
    residuals
        .iter()
        .enumerate()
        .all(|(i, residual)| omitted.contains(&i) || *residual == ragu_pasta::Ep::identity())
}

fn assert_completion_terminal(app: &App, node: &Node, seed: u64) -> Result<()> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
    let checks = checks.expect("well-formed completion mutant reaches every predicate");
    assert!(
        !accepted,
        "missing child completion edge accepted: {checks:?}"
    );
    assert_eq!(
        checks,
        VerificationChecks {
            native_revdot: false,
            nested_revdot: false,
            native_registry: true,
            nested_registry: true,
            nested_challenges: true,
            commitments: true,
            nested_points: true,
            transcript: true,
            ab_bridge: true,
            mesh: true,
        },
        "the two revdots must be the completion mismatch's exact terminal anchors"
    );
    Ok(())
}

fn challenge_completion_descendants(f: &Fixture, changed: &Node) -> Result<()> {
    const CHILD_BINDINGS: usize = 13;
    const CHALLENGES: usize = 8;

    for on_left in [true, false] {
        let mut bad = changed.clone();
        let mut good = f.honest.clone();
        for generation in 0..3 {
            let child_on_left = on_left ^ (generation == 1);
            let (bad_left, bad_right) = if child_on_left {
                (bad, f.right.clone())
            } else {
                (f.right.clone(), bad)
            };
            let (good_left, good_right) = if child_on_left {
                (good, f.right.clone())
            } else {
                (f.right.clone(), good)
            };
            let seed = 0x873_0960 + generation;
            bad = f
                .app
                .fuse(
                    &mut StdRng::seed_from_u64(seed),
                    Add,
                    (),
                    bad_left.clone(),
                    bad_right.clone(),
                )?
                .0;
            good = f
                .app
                .fuse(
                    &mut StdRng::seed_from_u64(seed),
                    Add,
                    (),
                    good_left,
                    good_right,
                )?
                .0;
            assert_eq!(bad.data(), good.data());
            decider(&f.app, &good, None)?;
            let (accepted, checks) = f
                .app
                .verify_with_checks(&bad, StdRng::seed_from_u64(0x873_0968 + generation))?;
            let checks = checks.expect("well-formed descendant reaches every predicate");
            assert!(!accepted, "changed descendant accepted: {checks:?}");
            assert!(
                checks.native_registry
                    && checks.nested_registry
                    && checks.nested_challenges
                    && checks.commitments
                    && checks.nested_points
                    && checks.transcript
                    && checks.ab_bridge
                    && checks.mesh,
                "fresh descendant bookkeeping must pass: {checks:?}"
            );
            assert!(
                !checks.native_revdot || !checks.nested_revdot,
                "the child completion residual expired: {checks:?}"
            );
            if generation == 0 {
                let residuals = bind_beta_edge_residuals(
                    &f.app,
                    bad.proof(),
                    [bad_left.proof(), bad_right.proof()],
                )?;
                let completion = if child_on_left {
                    CHALLENGES
                } else {
                    CHILD_BINDINGS + CHALLENGES
                };
                assert_eq!(
                    residuals
                        .iter()
                        .filter(|residual| **residual != ragu_pasta::Ep::identity())
                        .count(),
                    1,
                    "only the attacked child's completion equality may fail"
                );
                for edge in 0..2 * CHILD_BINDINGS {
                    assert_eq!(
                        completion_cut_accepts(&residuals, &[edge]),
                        edge == completion,
                        "only BindBeta edge {completion} may be a one-edge accepting cut; tried {edge}"
                    );
                }
                assert_ne!(
                    bind_beta_residual(&f.app, bad.proof()),
                    Fp::ZERO,
                    "the first parent must retain the exact completion mismatch"
                );
                assert_completion_terminal(&f.app, &bad, 0x873_0970 + u64::from(on_left))?;
            }
        }
    }
    Ok(())
}

fn challenge_completion_experiment() -> Result<()> {
    let f = Fixture::new()?;
    let mut attack = ChallengeCompletionAttack {
        delta: Fq::from(7),
        erase: false,
        calls: 0,
        expected_beta: Fq::ZERO,
        retained_beta: Fq::ZERO,
    };
    let changed = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    challenge_completion_model(&f, &changed, &attack, true)?;
    for seed in [0x873_0901, 0x873_0902] {
        let (accepted, checks) = f
            .app
            .verify_with_checks(&changed, StdRng::seed_from_u64(seed))?;
        let checks = checks.expect("well-formed attack reaches every predicate");
        assert!(
            !accepted,
            "post-pre_beta challenge edit accepted: {checks:?}"
        );
        assert!(
            !checks.nested_challenges,
            "exact reconstruction missed the edit"
        );
        assert!(checks.commitments && checks.transcript, "{checks:?}");
    }
    challenge_completion_descendants(&f, &changed)?;

    // An ordinary suffix replay that restores the transcript-derived beta is
    // valid, but the coefficient-level preservation guard refuses it as an
    // attack fixture.
    attack.erase = true;
    attack.calls = 0;
    let erased = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    challenge_completion_model(&f, &erased, &attack, false)?;
    decider(&f.app, &erased, None)
}

/// The challenge stage is deliberately unblinded. Giving only its otherwise
/// semantically inert SYSTEM coefficient a nonzero value leaves every staged
/// lift unchanged. Keeping the old cache then leaves BindBeta's completion
/// equation honest and isolates the distinct child-polynomial-to-PCS edge.
fn stale_challenge_blinding(node: &Node, delta: Fq) -> Node {
    type Challenges = nested::stages::challenges::Stage<EqAffine, R>;

    assert_ne!(delta, Fq::ZERO);
    let mut proof = node.proof().clone();
    let before_stage = raw_stage::<Fq, Challenges>(proof.nested_challenges_rx());
    let before_cache = proof.nested_challenges_commitment();
    let mut coefficients: Vec<_> = proof.nested_challenges_rx().iter_coeffs().collect();
    let system_blinding = 2 * R::n() - 1;
    assert_eq!(coefficients[system_blinding], Fq::ZERO);
    coefficients[system_blinding] = delta;
    proof.nested_challenges_rx = Poly::from_coeffs(coefficients);

    assert_eq!(
        raw_stage::<Fq, Challenges>(proof.nested_challenges_rx()),
        before_stage,
        "the SYSTEM blinding must not change any semantic stage wire"
    );
    assert_eq!(proof.nested_challenges_commitment(), before_cache);
    assert_ne!(
        ReferenceBackend::sparse_commit_to_affine(
            proof.nested_challenges_rx(),
            C::nested_generators(Pasta::baked()),
        ),
        before_cache,
        "the deliberately stale cache must differ from the changed polynomial"
    );
    proof.carry::<Number>(*node.data())
}

fn child_nested_commitments(proof: &Proof<C, R>) -> Vec<EpAffine> {
    let rxs = batch_fingerprint_tests::rx_order();
    assert_eq!(rxs.len(), 42, "independent nested rx inventory");
    rxs.into_iter()
        .map(|id| proof.nested_rx_commitment(id))
        .chain([
            proof.nested_a_commitment(),
            proof.nested_b_commitment(),
            proof.nested_registry_xy_commitment(),
            proof.nested_p_commitment(),
        ])
        .collect()
}

fn nested_p_residual(app: &App, proof: &Proof<C, R>) -> ragu_pasta::Ep {
    ReferenceBackend::sparse_commit_to_affine(
        proof.nested_p_poly(),
        C::nested_generators(app.params),
    )
    .to_curve()
        - proof.nested_p_commitment().to_curve()
}

fn beta_weight(batch: &ExpandedBatch<Fq>, slot: usize) -> Fq {
    assert!(slot < batch.polynomials.len());
    power(batch.beta, batch.polynomials.len() - 1 - slot)
}

fn omit_evaluated_edges(
    app: &App,
    proof: &Proof<C, R>,
    batch: &ExpandedBatch<Fq>,
    child_commitments: &[EpAffine],
    slots: &[usize],
) -> (Poly<Fq>, ragu_pasta::Ep) {
    let mut polynomial = proof.nested_p_poly().clone();
    let mut commitment = proof.nested_p_commitment().to_curve();
    for &slot in slots {
        let mut term = batch.polynomials[slot].clone();
        let weight = beta_weight(batch, slot);
        term.scale(weight);
        polynomial.sub_assign(&term);
        commitment -= child_commitments[slot] * weight;
    }
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&polynomial, C::nested_generators(app.params),)
            .to_curve()
            - commitment,
        nested_p_residual(app, proof)
            - slots.iter().fold(ragu_pasta::Ep::identity(), |sum, &slot| {
                let actual = ReferenceBackend::sparse_commit_to_affine(
                    &batch.polynomials[slot],
                    C::nested_generators(app.params),
                );
                sum + (actual.to_curve() - child_commitments[slot].to_curve())
                    * beta_weight(batch, slot)
            }),
        "edge deletion must remove exactly the selected weighted mismatch"
    );
    (polynomial, commitment)
}

fn assert_pcs_terminal(app: &App, node: &Node, seed: u64) -> Result<()> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
    let checks = checks.expect("well-formed PCS mutant reaches every predicate");
    assert!(!accepted, "stale nested PCS edge accepted: {checks:?}");
    assert_eq!(
        checks,
        VerificationChecks {
            native_revdot: true,
            nested_revdot: true,
            native_registry: true,
            nested_registry: true,
            nested_challenges: true,
            commitments: false,
            nested_points: true,
            transcript: true,
            ab_bridge: true,
            mesh: true,
        },
        "the direct P commitment check must be the isolated terminal anchor"
    );
    Ok(())
}

/// T06/T09: keep the full challenge commitment honest while changing only
/// the stage polynomial's unused blinding. Ordinary release-mode fusion then
/// consumes the changed polynomial in both nested PCS passes but walks the
/// frozen child commitment. This supplies a clean complementary frontier to
/// the post-pre_beta test above: BindBeta is exactly zero and the P commitment
/// discrepancy is the sole terminal failure.
fn challenge_pcs_transfer_experiment() -> Result<()> {
    const RX_COUNT: usize = 42;
    const CHILD_WIDTH: usize = RX_COUNT + 4;
    const CHALLENGE_RX: usize = RX_COUNT - 1;
    const CHILD_P: usize = RX_COUNT + 3;

    let f = Fixture::new()?;
    assert_eq!(
        batch_fingerprint_tests::rx_order()[CHALLENGE_RX],
        nested::RxIndex::ChallengeStage,
        "independent challenge-stage position"
    );

    // First establish a unique one-edge cut among all 92 child inputs.
    let changed = stale_challenge_blinding(&f.honest, Fq::from(7));
    let single = f
        .app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_09c0),
            Add,
            (),
            changed.clone(),
            f.honest.clone(),
        )?
        .0;
    let single_children = [changed.proof(), f.honest.proof()];
    let single_batch = nested_batch(&f.app, single.proof(), single_children)?;
    assert_eq!(single_batch.polynomials.len(), 98);
    assert!(
        single
            .proof()
            .nested_p_poly()
            .iter_coeffs()
            .eq(single_batch.accumulate(&single_batch.quotient())),
        "ordinary suffix must retain the changed child polynomial"
    );
    assert_eq!(bind_beta_residual(&f.app, single.proof()), Fp::ZERO);
    assert_pcs_terminal(&f.app, &single, 0x873_09c1)?;

    let mut single_points = child_nested_commitments(changed.proof());
    single_points.extend(child_nested_commitments(f.honest.proof()));
    assert_eq!(single_points.len(), 2 * CHILD_WIDTH);
    let single_slot = CHALLENGE_RX;
    let single_residual = nested_p_residual(&f.app, single.proof());
    assert_ne!(single_residual, ragu_pasta::Ep::identity());
    let actual = ReferenceBackend::sparse_commit_to_affine(
        &single_batch.polynomials[single_slot],
        C::nested_generators(f.app.params),
    );
    assert_eq!(
        single_residual,
        (actual.to_curve() - single_points[single_slot].to_curve())
            * beta_weight(&single_batch, single_slot),
        "the single residual must be exactly the weighted challenge-stage edge"
    );
    for slot in 0..2 * CHILD_WIDTH {
        let (poly, point) = omit_evaluated_edges(
            &f.app,
            single.proof(),
            &single_batch,
            &single_points,
            &[slot],
        );
        let accepts =
            ReferenceBackend::sparse_commit_to_affine(&poly, C::nested_generators(f.app.params))
                .to_curve()
                == point;
        assert_eq!(
            accepts,
            slot == single_slot,
            "only child slot {single_slot} may be a one-edge accepting cut; tried {slot}"
        );
    }

    // Now put two independently tagged discrepancies in the same field and
    // show that neither one-edge deletion clears their combined residual.
    let left = stale_challenge_blinding(&f.honest, Fq::from(7));
    let right = stale_challenge_blinding(&f.honest, Fq::from(11));
    let mut bad = f
        .app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_09d0),
            Add,
            (),
            left.clone(),
            right.clone(),
        )?
        .0;
    let mut good = f
        .app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_09d0),
            Add,
            (),
            f.honest.clone(),
            f.honest.clone(),
        )?
        .0;
    let first_children = [left.proof(), right.proof()];
    let first_batch = nested_batch(&f.app, bad.proof(), first_children)?;
    let slots = [CHALLENGE_RX, CHILD_WIDTH + CHALLENGE_RX];
    let points = {
        let mut points = child_nested_commitments(left.proof());
        points.extend(child_nested_commitments(right.proof()));
        points
    };
    let mut tags = slots.map(|slot| {
        let actual = ReferenceBackend::sparse_commit_to_affine(
            &first_batch.polynomials[slot],
            C::nested_generators(f.app.params),
        );
        (actual.to_curve() - points[slot].to_curve()) * beta_weight(&first_batch, slot)
    });
    assert!(tags.iter().all(|tag| *tag != ragu_pasta::Ep::identity()));
    assert_eq!(nested_p_residual(&f.app, bad.proof()), tags[0] + tags[1]);
    for &slot in &slots {
        let (poly, point) =
            omit_evaluated_edges(&f.app, bad.proof(), &first_batch, &points, &[slot]);
        assert_ne!(
            ReferenceBackend::sparse_commit_to_affine(&poly, C::nested_generators(f.app.params),)
                .to_curve(),
            point,
            "one of two live tags was incorrectly sufficient to cut"
        );
    }
    let (poly, point) = omit_evaluated_edges(&f.app, bad.proof(), &first_batch, &points, &slots);
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&poly, C::nested_generators(f.app.params))
            .to_curve(),
        point,
        "the exact two-edge cut must remove both live tags"
    );

    let mut previous_beta = first_batch.beta;
    for generation in 0..3 {
        assert_eq!(bad.data(), good.data());
        decider(&f.app, &good, None)?;
        assert_eq!(bind_beta_residual(&f.app, bad.proof()), Fp::ZERO);
        assert_pcs_terminal(&f.app, &bad, 0x873_09e0 + generation)?;
        assert_eq!(nested_p_residual(&f.app, bad.proof()), tags[0] + tags[1]);
        assert_ne!(tags[0], tags[1], "semantic tags must remain distinct");
        assert_ne!(tags[0] + tags[1], ragu_pasta::Ep::identity());

        if generation == 2 {
            break;
        }
        let on_left = generation % 2 == 0;
        let bad_child = bad;
        let good_child = good;
        let sibling = f.right.clone();
        let bad_children = if on_left {
            [bad_child.proof(), sibling.proof()]
        } else {
            [sibling.proof(), bad_child.proof()]
        };
        let fuse = |node: Node, seed| {
            let (left, right) = if on_left {
                (node, sibling.clone())
            } else {
                (sibling.clone(), node)
            };
            f.app
                .fuse(&mut StdRng::seed_from_u64(seed), Add, (), left, right)
                .map(|p| p.0)
        };
        bad = fuse(bad_child.clone(), 0x873_09f0 + generation)?;
        good = fuse(good_child, 0x873_09f0 + generation)?;
        let batch = nested_batch(&f.app, bad.proof(), bad_children)?;
        let slot = if on_left {
            CHILD_P
        } else {
            CHILD_WIDTH + CHILD_P
        };
        let weight = beta_weight(&batch, slot);
        let wrong_weight = power(previous_beta, batch.polynomials.len() - 1 - slot);
        let before = tags;
        tags = tags.map(|tag| tag * weight);
        assert_eq!(nested_p_residual(&f.app, bad.proof()), tags[0] + tags[1]);
        assert_ne!(
            nested_p_residual(&f.app, bad.proof()),
            (before[0] + before[1]) * wrong_weight,
            "reusing the child generation's beta must not predict this hop"
        );
        previous_beta = batch.beta;
    }
    Ok(())
}

struct SPrimeAttack {
    side: Side,
    index: usize,
    erase: bool,
    calls: usize,
    native_child_y: Fp,
    nested_child_y: Fq,
    native: Vec<Fp>,
    nested: Vec<Fq>,
}

/// Add 7(X-a)(X-b), chosen only after b is squeezed. Both openings which
/// enter Query stay fixed, while the retained polynomial really changes.
fn perturb_two_roots<F: PrimeField>(poly: &mut Poly<F>, a: F, b: F, erase: bool) {
    let before: Vec<_> = poly.iter_coeffs().collect();
    let mut after = before.clone();
    after[0] += F::from(7) * a * b;
    after[1] -= F::from(7) * (a + b);
    after[2] += F::from(7);
    assert_ne!(after, before);
    assert_eq!(evaluate(&after, a), evaluate(&before, a));
    assert_eq!(evaluate(&after, b), evaluate(&before, b));
    *poly = Poly::from_coeffs(if erase { before } else { after });
}

impl SuffixAttack<C, R> for SPrimeAttack {
    fn after_y(&mut self, y: Fp, native: &mut NativeSPrime<C, R>, nested: &mut NestedSPrime<C, R>) {
        self.calls += 1;
        match self.side {
            Side::Native => {
                let poly = if self.index == 0 {
                    &mut native.registry_wx0_poly
                } else {
                    &mut native.registry_wx1_poly
                };
                perturb_two_roots(poly, self.native_child_y, y, self.erase);
            }
            Side::Nested => {
                let poly = if self.index == 0 {
                    &mut nested.registry_wx0_poly
                } else {
                    &mut nested.registry_wx1_poly
                };
                perturb_two_roots(
                    poly,
                    self.nested_child_y,
                    nested::challenge::<C>(y).unwrap(),
                    self.erase,
                );
            }
        }
        self.native = if self.index == 0 {
            native.registry_wx0_poly.iter_coeffs().collect()
        } else {
            native.registry_wx1_poly.iter_coeffs().collect()
        };
        self.nested = if self.index == 0 {
            nested.registry_wx0_poly.iter_coeffs().collect()
        } else {
            nested.registry_wx1_poly.iter_coeffs().collect()
        };
    }
}

fn deadline_prefix(honest: &Proof<C, R>, changed: &Proof<C, R>) {
    assert_eq!(
        &honest.challenges().in_order()[..9],
        &changed.challenges().in_order()[..9],
        "all transcript challenges through alpha are frozen"
    );
    assert_eq!(&bridge_points(honest)[..6], &bridge_points(changed)[..6]);
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
        assert!(same(&honest[id], &changed[id]), "frozen native {id:?}");
    }
    for id in [
        nested::RxIndex::BridgePreamble,
        nested::RxIndex::BridgeSPrime,
        nested::RxIndex::BridgeInnerError,
        nested::RxIndex::BridgeOuterError,
        nested::RxIndex::BridgeAB,
        nested::RxIndex::BridgeQuery,
    ] {
        assert!(same(&honest[id], &changed[id]), "frozen nested {id:?}");
    }
}

fn commitment_rejected(app: &App, node: &Node, mesh: bool) -> Result<()> {
    for seed in [0x873_0101, 0x873_0201] {
        let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
        let checks = checks.expect("well-formed attack reaches every decider predicate");
        assert_eq!(accepted, checks.all());
        assert!(!accepted, "post-deadline attack accepted: {checks:?}");
        assert_eq!(
            checks,
            VerificationChecks {
                native_revdot: true,
                nested_revdot: true,
                native_registry: true,
                nested_registry: true,
                nested_challenges: true,
                commitments: false,
                nested_points: true,
                transcript: true,
                ab_bridge: true,
                mesh,
            },
            "unexpected root rejection boundary"
        );
    }
    Ok(())
}

fn rejected_descendants(f: &Fixture, changed: &Node) -> Result<()> {
    for on_left in [true, false] {
        let mut bad = changed.clone();
        let mut good = f.honest.clone();
        for generation in 0..2 {
            let fuse = |node: Node, seed| {
                let (left, right) = if on_left ^ (generation == 1) {
                    (node, f.right.clone())
                } else {
                    (f.right.clone(), node)
                };
                f.app
                    .fuse(&mut StdRng::seed_from_u64(seed), Add, (), left, right)
                    .map(|p| p.0)
            };
            bad = fuse(bad, 0x873_0120 + generation)?;
            good = fuse(good, 0x873_0120 + generation)?;
            assert_eq!(*bad.data(), *good.data());
            decider(&f.app, &good, None)?;
            let (accepted, checks) = f
                .app
                .verify_with_checks(&bad, StdRng::seed_from_u64(0x873_0128 + generation))?;
            assert!(!accepted, "invalid descendant accepted: {checks:?}");
        }
    }
    Ok(())
}

fn s_prime_model(f: &Fixture, changed: &Node, attack: &SPrimeAttack, attacked: bool) -> Result<()> {
    let children = [f.left.proof(), f.right.proof()];
    match attack.side {
        Side::Native => {
            let frozen = native_batch(&f.app, changed.proof(), children);
            let slot = 106 + attack.index;
            let honest: Vec<_> = frozen.polynomials[slot].iter_coeffs().collect();
            assert_eq!(
                honest != attack.native,
                attacked,
                "attack-preservation guard"
            );
            if attacked {
                let attacked_wx = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(attack.native.clone()),
                    C::host_generators(f.app.params),
                );
                let staged = raw_stage::<Fq, nested::stages::s_prime::Stage<EqAffine, R>>(
                    &changed.proof().bridge_s_prime_rx,
                );
                assert_ne!(
                    &staged[2 * attack.index..2 * attack.index + 2],
                    &coordinates(attacked_wx),
                    "the post-y polynomial must not rewrite its frozen commitment"
                );
                let mut actual = native_batch(&f.app, changed.proof(), children);
                actual.polynomials[slot] = Poly::from_coeffs(attack.native.clone());
                let quotient = actual.quotient();
                let actual_p = actual.accumulate(&quotient);
                assert!(
                    changed
                        .proof()
                        .native_p_poly()
                        .iter_coeffs()
                        .eq(actual_p.clone())
                );
                let frozen_p = frozen.accumulate(&quotient);
                let actual_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(actual_p),
                    C::host_generators(f.app.params),
                );
                let frozen_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(frozen_p),
                    C::host_generators(f.app.params),
                );
                assert_ne!(actual_commitment, changed.proof().native_p_commitment());
                assert_eq!(frozen_commitment, changed.proof().native_p_commitment());
            }
        }
        Side::Nested => {
            let frozen = nested_batch(&f.app, changed.proof(), children)?;
            let slot = 92 + attack.index;
            let honest: Vec<_> = frozen.polynomials[slot].iter_coeffs().collect();
            assert_eq!(
                honest != attack.nested,
                attacked,
                "attack-preservation guard"
            );
            if attacked {
                let attacked_wx = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(attack.nested.clone()),
                    C::nested_generators(f.app.params),
                );
                let staged = raw_stage::<Fp, native::stages::points::RegistryWxStage<EpAffine>>(
                    &changed.proof().native_points_registry_wx_rx,
                );
                assert_ne!(
                    &staged[2 * attack.index..2 * attack.index + 2],
                    &coordinates(attacked_wx),
                    "the post-y polynomial must not rewrite its frozen commitment"
                );
                let mut actual = nested_batch(&f.app, changed.proof(), children)?;
                actual.polynomials[slot] = Poly::from_coeffs(attack.nested.clone());
                let quotient = actual.quotient();
                let actual_p = actual.accumulate(&quotient);
                assert!(
                    changed
                        .proof()
                        .nested_p_poly()
                        .iter_coeffs()
                        .eq(actual_p.clone())
                );
                let frozen_p = frozen.accumulate(&quotient);
                let actual_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(actual_p),
                    C::nested_generators(f.app.params),
                );
                let frozen_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(frozen_p),
                    C::nested_generators(f.app.params),
                );
                assert_ne!(actual_commitment, changed.proof().nested_p_commitment());
                assert_eq!(frozen_commitment, changed.proof().nested_p_commitment());
            }
        }
    }
    Ok(())
}

fn s_prime_experiment(side: Side) -> Result<()> {
    let f = Fixture::new()?;
    for index in 0..2 {
        let child = if index == 0 { &f.left } else { &f.right };
        let mut attack = SPrimeAttack {
            side,
            index,
            erase: false,
            calls: 0,
            native_child_y: child.proof().y(),
            nested_child_y: nested::challenge::<C>(child.proof().y())?,
            native: Vec::new(),
            nested: Vec::new(),
        };
        let changed = f.run(&mut attack)?;
        assert_eq!(attack.calls, 1);
        deadline_prefix(f.honest.proof(), changed.proof());
        s_prime_model(&f, &changed, &attack, true)?;
        commitment_rejected(&f.app, &changed, false)?;
        rejected_descendants(&f, &changed)?;

        attack.erase = true;
        attack.calls = 0;
        let erased = f.run(&mut attack)?;
        assert_eq!(attack.calls, 1);
        s_prime_model(&f, &erased, &attack, false)?;
        decider(&f.app, &erased, None)?;
    }
    Ok(())
}

/// T05 selects a noncanonical nested registry restriction after the actual
/// alpha squeeze, while its commitment is still causally available. The
/// perturbation vanishes at every registry opening already committed by the
/// query stage. The ordinary suffix then rebuilds f_n, P_n, Eval and all
/// commitment walks from that retained polynomial.
struct LateRegistryAttack {
    erase: bool,
    calls: usize,
    alpha: Fq,
    roots: Vec<Fq>,
    delta: Vec<Fq>,
    before: Vec<Fq>,
    candidate: Vec<Fq>,
    retained: Vec<Fq>,
}

fn polynomial_with_roots<F: PrimeField>(roots: &[F], scale: F) -> Vec<F> {
    assert!(roots.len() < R::num_coeffs());
    let mut coefficients = vec![scale];
    for &root in roots {
        let mut next = vec![F::ZERO; coefficients.len() + 1];
        for (degree, &coefficient) in coefficients.iter().enumerate() {
            next[degree] -= root * coefficient;
            next[degree + 1] += coefficient;
        }
        coefficients = next;
    }
    coefficients.resize(R::num_coeffs(), F::ZERO);
    coefficients
}

impl SuffixAttack<C, R> for LateRegistryAttack {
    fn after_alpha(&mut self, w: Fp, alpha: Fp, registry_xy: &mut Poly<Fq>) {
        self.calls += 1;
        self.alpha = nested::challenge::<C>(alpha).unwrap();
        let scale = if self.alpha == Fq::ZERO {
            Fq::ONE
        } else {
            self.alpha
        };
        self.roots = core::iter::once(nested::challenge::<C>(w).unwrap())
            .chain(
                nested::InternalCircuitIndex::ALL
                    .iter()
                    .map(|id| id.circuit_index().omega_j()),
            )
            .collect();
        self.delta = polynomial_with_roots(&self.roots, scale);
        assert!(
            self.roots
                .iter()
                .all(|&root| evaluate(&self.delta, root) == Fq::ZERO)
        );
        self.before = registry_xy.iter_coeffs().collect();
        self.candidate = self
            .before
            .iter()
            .zip(&self.delta)
            .map(|(value, delta)| *value + delta)
            .collect();
        assert_ne!(self.candidate, self.before);
        self.retained = if self.erase {
            self.before.clone()
        } else {
            self.candidate.clone()
        };
        *registry_xy = Poly::from_coeffs(self.retained.clone());
    }
}

fn late_registry_frontier(
    honest: &Proof<C, R>,
    changed: &Proof<C, R>,
    attack: &LateRegistryAttack,
    attacked: bool,
) {
    deadline_prefix(honest, changed);
    assert_eq!(
        changed
            .nested_registry_xy_poly()
            .iter_coeffs()
            .collect::<Vec<_>>(),
        attack.retained,
        "attack-preservation guard: retain the selected post-alpha object"
    );
    assert_eq!(attack.retained != attack.before, attacked);
    assert_eq!(
        honest
            .nested_registry_xy_poly()
            .iter_coeffs()
            .collect::<Vec<_>>(),
        attack.before
    );
    assert_eq!(
        honest.nested_registry_xy_commitment() != changed.nested_registry_xy_commitment(),
        attacked,
        "the registry commitment is first selected after alpha"
    );
    assert_eq!(
        honest.bridge_f_commitment() != changed.bridge_f_commitment(),
        attacked,
        "the next transcript commitment must carry the late selection"
    );
}

fn late_registry_batch_model(
    f: &Fixture,
    changed: &Node,
    attack: &LateRegistryAttack,
    attacked: bool,
) -> Result<()> {
    let children = [f.left.proof(), f.right.proof()];
    let attacked_batch = nested_batch(&f.app, changed.proof(), children)?;
    let registry_slot = attacked_batch.polynomials.len() - 1;
    assert_eq!(registry_slot, 97);
    assert_eq!(
        attacked_batch.polynomials[registry_slot]
            .iter_coeffs()
            .collect::<Vec<_>>(),
        attack.retained
    );

    // These are exactly the pre-alpha PCS openings of registry_xy: current w
    // followed by every registered circuit/bonding domain point. The selected
    // polynomial keeps all of them byte-for-byte compatible with Query.
    let earlier_points: Vec<_> = attacked_batch
        .queries
        .iter()
        .filter_map(|&(slot, point)| (slot == registry_slot).then_some(point))
        .collect();
    assert_eq!(earlier_points, attack.roots);
    for &point in &earlier_points {
        assert_eq!(
            evaluate(&attack.candidate, point),
            evaluate(&attack.before, point)
        );
    }

    let quotient = attacked_batch.quotient();
    let accumulated = attacked_batch.accumulate(&quotient);
    assert!(
        changed
            .proof()
            .nested_p_poly()
            .iter_coeffs()
            .eq(accumulated.iter().copied()),
        "the production-shaped joint PCS suffix must be exact"
    );
    assert_eq!(
        changed.proof().nested_v()?,
        evaluate(&accumulated, attacked_batch.u)
    );

    let mut canonical_polynomials = attacked_batch.polynomials.clone();
    canonical_polynomials[registry_slot] = Poly::from_coeffs(attack.before.clone());
    let canonical = ExpandedBatch {
        polynomials: canonical_polynomials,
        queries: attacked_batch.queries.clone(),
        alpha: attacked_batch.alpha,
        beta: attacked_batch.beta,
        u: attacked_batch.u,
    };
    assert_eq!(
        quotient != canonical.quotient(),
        attacked,
        "the post-alpha quotient must be regenerated from the selected object"
    );

    // u is sampled only after the changed registry commitment enters the real
    // transcript. No solver or test hook selects it. It is therefore an
    // independent production mesh point for this fixed candidate.
    assert_eq!(
        evaluate(&attack.retained, attacked_batch.u) != evaluate(&attack.before, attacked_batch.u),
        attacked,
        "the later mesh anchor must distinguish the noncanonical restriction"
    );
    Ok(())
}

fn late_registry_root_controls(f: &Fixture, changed: &Node, attacked: bool) -> Result<()> {
    for seed in [0x873_0501, 0x873_0502] {
        let (accepted, checks) = f
            .app
            .verify_with_checks(changed, StdRng::seed_from_u64(seed))?;
        let checks = checks.expect("well-formed joint game reaches every predicate");
        assert_eq!(accepted, !attacked, "root verdict: {checks:?}");
        assert!(
            checks.native_revdot
                && checks.nested_revdot
                && checks.native_registry
                && checks.nested_challenges
                && checks.commitments
                && checks.nested_points
                && checks.transcript
                && checks.ab_bridge,
            "the quotient, PCS, commitments and transcript must remain valid: {checks:?}"
        );
        assert_eq!(checks.nested_registry, !attacked);
        assert_eq!(checks.mesh, !attacked);
        // DELIBERATELY UNANCHORED SHADOW VERIFIER. Removing just the canonical
        // registry comparison and semantic mesh leaves the entire joint PCS
        // game accepting; this is not a production verifier mutation.
        assert!(
            checks.native_revdot
                && checks.nested_revdot
                && checks.native_registry
                && checks.nested_challenges
                && checks.commitments
                && checks.nested_points
                && checks.transcript
                && checks.ab_bridge,
            "unanchored control must accept the production-shaped algebra"
        );
    }
    Ok(())
}

fn late_registry_descendants(f: &Fixture, changed: &Node) -> Result<()> {
    for on_left in [true, false] {
        let mut bad = changed.clone();
        let mut good = f.honest.clone();
        for generation in 0..3 {
            let fuse = |node: Node, seed| {
                let (left, right) = if on_left ^ (generation == 1) {
                    (node, f.right.clone())
                } else {
                    (f.right.clone(), node)
                };
                f.app
                    .fuse(&mut StdRng::seed_from_u64(seed), Add, (), left, right)
                    .map(|p| p.0)
            };
            bad = fuse(bad, 0x873_0520 + generation)?;
            good = fuse(good, 0x873_0520 + generation)?;
            assert_eq!(bad.data(), good.data());
            decider(&f.app, &good, None)?;
            let (accepted, checks) = f
                .app
                .verify_with_checks(&bad, StdRng::seed_from_u64(0x873_0528 + generation))?;
            let checks = checks.expect("descendant reaches every predicate");
            assert!(!accepted, "late-registry residual expired: {checks:?}");
            assert!(
                checks.commitments && checks.transcript && checks.nested_points,
                "fresh descendant bookkeeping must remain valid: {checks:?}"
            );
        }
    }
    Ok(())
}

fn late_registry_experiment() -> Result<()> {
    let f = Fixture::new()?;
    let mut attack = LateRegistryAttack {
        erase: false,
        calls: 0,
        alpha: Fq::ZERO,
        roots: Vec::new(),
        delta: Vec::new(),
        before: Vec::new(),
        candidate: Vec::new(),
        retained: Vec::new(),
    };
    let changed = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    late_registry_frontier(f.honest.proof(), changed.proof(), &attack, true);
    late_registry_batch_model(&f, &changed, &attack, true)?;
    late_registry_root_controls(&f, &changed, true)?;
    late_registry_descendants(&f, &changed)?;

    // A complete ordinary suffix replay that restores the canonical object is
    // valid, but the coefficient-level preservation guard labels it erased.
    attack.erase = true;
    attack.calls = 0;
    let erased = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    late_registry_frontier(f.honest.proof(), erased.proof(), &attack, false);
    late_registry_batch_model(&f, &erased, &attack, false)?;
    late_registry_root_controls(&f, &erased, false)
}

struct AccumulatorRescaleAttack {
    side: Side,
    erase: bool,
    calls: usize,
    before: Option<(Poly<Fp>, Poly<Fp>, Poly<Fq>, Poly<Fq>)>,
    after: Option<(Poly<Fp>, Poly<Fp>, Poly<Fq>, Poly<Fq>)>,
}

impl SuffixAttack<C, R> for AccumulatorRescaleAttack {
    fn before_ab_commitment(
        &mut self,
        native_a: &mut Poly<Fp>,
        native_b: &mut Poly<Fp>,
        nested_a: &mut Poly<Fq>,
        nested_b: &mut Poly<Fq>,
    ) -> bool {
        self.calls += 1;
        let before = (
            native_a.clone(),
            native_b.clone(),
            nested_a.clone(),
            nested_b.clone(),
        );
        let native_c = revdot(native_a, native_b);
        let nested_c = revdot(nested_a, nested_b);
        match self.side {
            Side::Native => {
                let scale = Fp::from(5);
                native_a.scale(scale);
                native_b.scale(scale.invert().unwrap());
            }
            Side::Nested => {
                let scale = Fq::from(5);
                nested_a.scale(scale);
                nested_b.scale(scale.invert().unwrap());
            }
        }
        assert_eq!(revdot(native_a, native_b), native_c);
        assert_eq!(revdot(nested_a, nested_b), nested_c);
        if self.erase {
            *native_a = before.0.clone();
            *native_b = before.1.clone();
            *nested_a = before.2.clone();
            *nested_b = before.3.clone();
        }
        self.after = Some((
            native_a.clone(),
            native_b.clone(),
            nested_a.clone(),
            nested_b.clone(),
        ));
        self.before = Some(before);
        !self.erase
    }
}

fn assert_rescaled<F: PrimeField>(before: &Poly<F>, after: &Poly<F>, scale: F) {
    assert!(!same(before, after));
    assert!(
        before
            .iter_coeffs()
            .map(|coefficient| coefficient * scale)
            .eq(after.iter_coeffs())
    );
}

fn accumulator_rescale_root(f: &Fixture, changed: &Node, side: Side, attacked: bool) -> Result<()> {
    for seed in [0x873_0901, 0x873_0902] {
        let (accepted, checks) = f
            .app
            .verify_with_checks(changed, StdRng::seed_from_u64(seed))?;
        let expected = VerificationChecks {
            native_revdot: !attacked || side != Side::Native,
            nested_revdot: !attacked || side != Side::Nested,
            native_registry: true,
            nested_registry: true,
            nested_challenges: true,
            commitments: true,
            nested_points: true,
            transcript: true,
            ab_bridge: true,
            mesh: true,
        };
        assert_eq!(accepted, !attacked, "causal A/B verdict with {checks:?}");
        assert_eq!(checks.unwrap(), expected);
    }
    Ok(())
}

fn accumulator_rescale_experiment(side: Side) -> Result<()> {
    let f = Fixture::new()?;
    let mut attack = AccumulatorRescaleAttack {
        side,
        erase: false,
        calls: 0,
        before: None,
        after: None,
    };
    let changed = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    let before = attack.before.as_ref().unwrap();
    let after = attack.after.as_ref().unwrap();
    match side {
        Side::Native => {
            assert_rescaled(&before.0, &after.0, Fp::from(5));
            assert_rescaled(&before.1, &after.1, Fp::from(5).invert().unwrap());
            assert!(same(&before.2, &after.2));
            assert!(same(&before.3, &after.3));
        }
        Side::Nested => {
            assert!(same(&before.0, &after.0));
            assert!(same(&before.1, &after.1));
            assert_rescaled(&before.2, &after.2, Fq::from(5));
            assert_rescaled(&before.3, &after.3, Fq::from(5).invert().unwrap());
        }
    }

    let honest = f.honest.proof();
    let proof = changed.proof();
    assert!(same(&after.0, &proof.native_a_poly));
    assert!(same(&after.1, &proof.native_b_poly));
    assert!(same(&after.2, &proof.nested_a_poly));
    assert!(same(&after.3, &proof.nested_b_poly));
    assert_eq!(proof.native_c(), honest.native_c());
    assert_eq!(proof.nested_c(), honest.nested_c());

    // The child-derived fold prefix is fixed through nu'. The edited A/B
    // commitments first enter bridge AB, so x and the entire ordinary suffix
    // are causally rebuilt from that point.
    assert_eq!(
        &proof.challenges().in_order()[..7],
        &honest.challenges().in_order()[..7]
    );
    let honest_bridges = bridge_points(honest);
    let changed_bridges = bridge_points(proof);
    assert_eq!(&changed_bridges[..4], &honest_bridges[..4]);
    assert_ne!(changed_bridges[4], honest_bridges[4]);
    assert_ne!(proof.x(), honest.x());
    assert_eq!(
        replay(&changed_bridges, None, &[])?.challenges,
        proof.challenges().in_order()
    );

    let host_gen = C::host_generators(f.app.params);
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&proof.native_a_poly, host_gen),
        proof.native_commitment(native::RxComponent::AbA)
    );
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&proof.native_b_poly, host_gen),
        proof.native_commitment(native::RxComponent::AbB)
    );
    let nested_gen = C::nested_generators(f.app.params);
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&proof.nested_a_poly, nested_gen),
        proof.nested_a_commitment()
    );
    assert_eq!(
        ReferenceBackend::sparse_commit_to_affine(&proof.nested_b_poly, nested_gen),
        proof.nested_b_commitment()
    );
    accumulator_rescale_root(&f, &changed, side, true)?;
    descendants(&f.app, &changed, &f.honest, &f.right, side)?;

    // The same hook can restore the prescribed fold before anything commits;
    // that control must produce the original transcript and accept.
    attack.erase = true;
    attack.calls = 0;
    let erased = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    let erased_after = attack.after.as_ref().unwrap();
    assert!(same(&erased_after.0, &honest.native_a_poly));
    assert!(same(&erased_after.1, &honest.native_b_poly));
    assert!(same(&erased_after.2, &honest.nested_a_poly));
    assert!(same(&erased_after.3, &honest.nested_b_poly));
    assert_eq!(bridge_points(erased.proof()), honest_bridges);
    assert_eq!(
        erased.proof().challenges().in_order(),
        honest.challenges().in_order()
    );
    accumulator_rescale_root(&f, &erased, side, false)
}

struct AbAttack {
    side: Side,
    erase: bool,
    calls: usize,
    native_a: Vec<Fp>,
    native_b: Vec<Fp>,
    nested_a: Vec<Fq>,
    nested_b: Vec<Fq>,
}

fn root_poly<F: PrimeField>(at: F, shift: usize) -> Poly<F> {
    let mut coefficients = vec![F::ZERO; R::num_coeffs()];
    coefficients[shift] = -at;
    coefficients[shift + 1] = F::ONE;
    Poly::from_coeffs(coefficients)
}

/// Find P=X^d(X-xz), Q=X^e(X-x), then choose nonzero t,s so
/// <A+tP,B+sQ>_rev = <A,B>_rev. The two queried evaluations also survive.
fn perturb_ab<F: PrimeField>(a: &mut Poly<F>, b: &mut Poly<F>, x: F, z: F, erase: bool) {
    let before_a = a.clone();
    let before_b = b.clone();
    let old_c = revdot(a, b);
    let xz = x * z;
    let mut choice = None;
    'outer: for d in 0..8 {
        for e in 0..8 {
            let p = root_poly::<F>(xz, d);
            let q = root_poly::<F>(x, e);
            let pa = revdot(&p, b);
            let aq = revdot(a, &q);
            let pq = revdot(&p, &q);
            for candidate in 2..10 {
                let t = F::from(candidate);
                let denominator = aq + t * pq;
                if pa != F::ZERO && denominator != F::ZERO {
                    choice = Some((p, q, t, -t * pa * denominator.invert().unwrap()));
                    break 'outer;
                }
            }
        }
    }
    let (p, q, t, s) = choice.expect("fixture must admit a c-preserving substitution");
    assert_ne!(s, F::ZERO);
    let mut ac: Vec<_> = a.iter_coeffs().collect();
    let mut bc: Vec<_> = b.iter_coeffs().collect();
    for (value, delta) in ac.iter_mut().zip(p.iter_coeffs()) {
        *value += t * delta;
    }
    for (value, delta) in bc.iter_mut().zip(q.iter_coeffs()) {
        *value += s * delta;
    }
    *a = Poly::from_coeffs(ac);
    *b = Poly::from_coeffs(bc);
    assert!(!same(a, &before_a));
    assert!(!same(b, &before_b));
    assert_eq!(a.eval(xz), before_a.eval(xz));
    assert_eq!(b.eval(x), before_b.eval(x));
    assert_eq!(revdot(a, b), old_c);
    if erase {
        *a = before_a;
        *b = before_b;
    }
}

impl SuffixAttack<C, R> for AbAttack {
    fn after_x(
        &mut self,
        x: Fp,
        z: Fp,
        native_a: &mut Poly<Fp>,
        native_b: &mut Poly<Fp>,
        nested_a: &mut Poly<Fq>,
        nested_b: &mut Poly<Fq>,
    ) {
        self.calls += 1;
        match self.side {
            Side::Native => perturb_ab(native_a, native_b, x, z, self.erase),
            Side::Nested => perturb_ab(
                nested_a,
                nested_b,
                nested::challenge::<C>(x).unwrap(),
                nested::challenge::<C>(z).unwrap(),
                self.erase,
            ),
        }
        self.native_a = native_a.iter_coeffs().collect();
        self.native_b = native_b.iter_coeffs().collect();
        self.nested_a = nested_a.iter_coeffs().collect();
        self.nested_b = nested_b.iter_coeffs().collect();
    }
}

fn ab_model(f: &Fixture, changed: &Node, attack: &AbAttack, attacked: bool) -> Result<()> {
    let children = [f.left.proof(), f.right.proof()];
    match attack.side {
        Side::Native => {
            let actual = native_batch(&f.app, changed.proof(), children);
            assert_eq!(
                !same(&actual.polynomials[109], &f.honest.proof().native_a_poly),
                attacked,
                "A attack-preservation guard"
            );
            assert_eq!(
                actual.polynomials[109].iter_coeffs().collect::<Vec<_>>(),
                attack.native_a
            );
            assert_eq!(
                actual.polynomials[110].iter_coeffs().collect::<Vec<_>>(),
                attack.native_b
            );
            if attacked {
                let q = actual.quotient();
                let actual_p = actual.accumulate(&q);
                assert!(
                    changed
                        .proof()
                        .native_p_poly()
                        .iter_coeffs()
                        .eq(actual_p.clone())
                );
                let mut frozen = native_batch(&f.app, changed.proof(), children);
                frozen.polynomials[109] = f.honest.proof().native_a_poly.clone();
                frozen.polynomials[110] = f.honest.proof().native_b_poly.clone();
                let frozen_p = frozen.accumulate(&q);
                let actual_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(actual_p),
                    C::host_generators(f.app.params),
                );
                let frozen_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(frozen_p),
                    C::host_generators(f.app.params),
                );
                assert_ne!(actual_commitment, changed.proof().native_p_commitment());
                assert_eq!(frozen_commitment, changed.proof().native_p_commitment());
                assert_ne!(
                    ReferenceBackend::sparse_commit_to_affine(
                        &changed.proof().native_a_poly,
                        C::host_generators(f.app.params),
                    ),
                    changed.proof().native_commitment(native::RxComponent::AbA)
                );
                assert_ne!(
                    ReferenceBackend::sparse_commit_to_affine(
                        &changed.proof().native_b_poly,
                        C::host_generators(f.app.params),
                    ),
                    changed.proof().native_commitment(native::RxComponent::AbB)
                );
                let mut repaired = changed.proof().clone();
                let a = ReferenceBackend::sparse_commit_to_affine(
                    &repaired.native_a_poly,
                    C::host_generators(f.app.params),
                );
                let b = ReferenceBackend::sparse_commit_to_affine(
                    &repaired.native_b_poly,
                    C::host_generators(f.app.params),
                );
                repaired.replace_native_ab_commitments(a, b);
                let (_, checks) = f.app.verify_with_checks(
                    &repaired.carry::<Number>(*changed.data()),
                    StdRng::seed_from_u64(0x873_02ca),
                )?;
                assert!(
                    !checks.unwrap().ab_bridge,
                    "repairing the direct caches must expose the frozen AB bridge"
                );
            }
        }
        Side::Nested => {
            let actual = nested_batch(&f.app, changed.proof(), children)?;
            assert_eq!(
                !same(&actual.polynomials[95], &f.honest.proof().nested_a_poly),
                attacked,
                "A attack-preservation guard"
            );
            assert_eq!(
                actual.polynomials[95].iter_coeffs().collect::<Vec<_>>(),
                attack.nested_a
            );
            assert_eq!(
                actual.polynomials[96].iter_coeffs().collect::<Vec<_>>(),
                attack.nested_b
            );
            if attacked {
                let q = actual.quotient();
                let actual_p = actual.accumulate(&q);
                assert!(
                    changed
                        .proof()
                        .nested_p_poly()
                        .iter_coeffs()
                        .eq(actual_p.clone())
                );
                let mut frozen = nested_batch(&f.app, changed.proof(), children)?;
                frozen.polynomials[95] = f.honest.proof().nested_a_poly.clone();
                frozen.polynomials[96] = f.honest.proof().nested_b_poly.clone();
                let frozen_p = frozen.accumulate(&q);
                let actual_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(actual_p),
                    C::nested_generators(f.app.params),
                );
                let frozen_commitment = ReferenceBackend::sparse_commit_to_affine(
                    &Poly::from_coeffs(frozen_p),
                    C::nested_generators(f.app.params),
                );
                assert_ne!(actual_commitment, changed.proof().nested_p_commitment());
                assert_eq!(frozen_commitment, changed.proof().nested_p_commitment());
                assert_ne!(
                    ReferenceBackend::sparse_commit_to_affine(
                        &changed.proof().nested_a_poly,
                        C::nested_generators(f.app.params),
                    ),
                    changed.proof().nested_a_commitment()
                );
                assert_ne!(
                    ReferenceBackend::sparse_commit_to_affine(
                        &changed.proof().nested_b_poly,
                        C::nested_generators(f.app.params),
                    ),
                    changed.proof().nested_b_commitment()
                );
                let mut repaired = changed.proof().clone();
                let a = ReferenceBackend::sparse_commit_to_affine(
                    &repaired.nested_a_poly,
                    C::nested_generators(f.app.params),
                );
                let b = ReferenceBackend::sparse_commit_to_affine(
                    &repaired.nested_b_poly,
                    C::nested_generators(f.app.params),
                );
                repaired.replace_nested_ab_commitments(a, b);
                let (_, checks) = f.app.verify_with_checks(
                    &repaired.carry::<Number>(*changed.data()),
                    StdRng::seed_from_u64(0x873_02cb),
                )?;
                assert!(
                    !checks.unwrap().nested_points,
                    "repairing the direct caches must expose the frozen point stage"
                );
            }
        }
    }
    Ok(())
}

fn ab_experiment(side: Side) -> Result<()> {
    let f = Fixture::new()?;
    let mut attack = AbAttack {
        side,
        erase: false,
        calls: 0,
        native_a: Vec::new(),
        native_b: Vec::new(),
        nested_a: Vec::new(),
        nested_b: Vec::new(),
    };
    let changed = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    deadline_prefix(f.honest.proof(), changed.proof());
    assert_eq!(changed.proof().native_c(), f.honest.proof().native_c());
    assert_eq!(changed.proof().nested_c(), f.honest.proof().nested_c());
    ab_model(&f, &changed, &attack, true)?;
    commitment_rejected(&f.app, &changed, true)?;
    rejected_descendants(&f, &changed)?;

    attack.erase = true;
    attack.calls = 0;
    let erased = f.run(&mut attack)?;
    assert_eq!(attack.calls, 1);
    ab_model(&f, &erased, &attack, false)?;
    decider(&f.app, &erased, None)
}

/// The five native point stages whose commitments are copied into nested
/// bridges and checked by Export. Each bridge replacement happens after the
/// authentic point stage exists but before the bridge is committed.
#[derive(Clone, Copy, Debug)]
enum PointBridge {
    Binding,
    Children,
    RegistryWx,
    Ab,
    F,
}

impl PointBridge {
    const ALL: [Self; 5] = [
        Self::Binding,
        Self::Children,
        Self::RegistryWx,
        Self::Ab,
        Self::F,
    ];

    fn native_rx(self) -> native::RxIndex {
        match self {
            Self::Binding => native::RxIndex::PointsBinding,
            Self::Children => native::RxIndex::PointsChildren,
            Self::RegistryWx => native::RxIndex::PointsRegistryWx,
            Self::Ab => native::RxIndex::PointsAb,
            Self::F => native::RxIndex::PointsF,
        }
    }

    fn bridge_rx(self) -> nested::RxIndex {
        match self {
            Self::Binding | Self::Children => nested::RxIndex::BridgePreamble,
            Self::RegistryWx => nested::RxIndex::BridgeSPrime,
            Self::Ab => nested::RxIndex::BridgeAB,
            Self::F => nested::RxIndex::BridgeF,
        }
    }

    fn bridge_index(self) -> usize {
        match self {
            Self::Binding | Self::Children => 0,
            Self::RegistryWx => 1,
            Self::Ab => 4,
            Self::F => 6,
        }
    }

    /// Number of native Fiat-Shamir outputs fixed before this bridge.
    fn challenge_prefix(self) -> usize {
        match self {
            Self::Binding | Self::Children => 0,
            Self::RegistryWx => 1,
            Self::Ab => 7,
            Self::F => 9,
        }
    }

    fn bridge_slots(self) -> core::ops::Range<usize> {
        match self {
            Self::Binding => 2..4,
            Self::Children => 4..6,
            Self::RegistryWx | Self::Ab => 4..6,
            Self::F => 2..4,
        }
    }
}

struct PointBridgeAttack {
    target: PointBridge,
    replacement: EqAffine,
    calls: usize,
}

impl PointBridgeAttack {
    fn replace(&mut self, actual: &mut EqAffine) {
        assert_ne!(*actual, self.replacement);
        *actual = self.replacement;
        self.calls += 1;
    }
}

impl SuffixAttack<C, R> for PointBridgeAttack {
    fn before_preamble_bridge(
        &mut self,
        witness: &mut nested::stages::preamble::Witness<EqAffine>,
    ) {
        match self.target {
            PointBridge::Binding => self.replace(&mut witness.native_points_binding),
            PointBridge::Children => self.replace(&mut witness.native_points_children),
            _ => {}
        }
    }

    fn before_s_prime_bridge(&mut self, witness: &mut nested::stages::s_prime::Witness<EqAffine>) {
        if matches!(self.target, PointBridge::RegistryWx) {
            self.replace(&mut witness.native_points_registry_wx);
        }
    }

    fn before_ab_bridge(&mut self, witness: &mut nested::stages::ab::Witness<EqAffine>) -> bool {
        if matches!(self.target, PointBridge::Ab) {
            self.replace(&mut witness.native_points_ab);
            true
        } else {
            false
        }
    }

    fn before_f_bridge(&mut self, witness: &mut nested::stages::f::Witness<EqAffine>) {
        if matches!(self.target, PointBridge::F) {
            self.replace(&mut witness.native_points_f);
        }
    }
}

fn point_bridge_values(proof: &Proof<C, R>, target: PointBridge) -> Vec<Fq> {
    match target {
        PointBridge::Binding | PointBridge::Children => {
            raw_stage::<Fq, nested::stages::preamble::Stage<EqAffine, R>>(
                &proof[nested::RxIndex::BridgePreamble],
            )
        }
        PointBridge::RegistryWx => raw_stage::<Fq, nested::stages::s_prime::Stage<EqAffine, R>>(
            &proof[nested::RxIndex::BridgeSPrime],
        ),
        PointBridge::Ab => raw_stage::<Fq, nested::stages::ab::Stage<EqAffine, R>>(
            &proof[nested::RxIndex::BridgeAB],
        ),
        PointBridge::F => {
            raw_stage::<Fq, nested::stages::f::Stage<EqAffine, R>>(&proof[nested::RxIndex::BridgeF])
        }
    }
}

fn export_equation(app: &App, proof: &Proof<C, R>) -> Result<Fq> {
    use nested::{InternalCircuitIndex as Circuit, RxIndex::*};
    let ids = [
        Export,
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
    let y = Fq::from(37);
    Ok(circuit_value(
        &app.nested_registry,
        Circuit::Export.circuit_index(),
        &ids.map(|id| &proof[id]),
        y,
        Fq::from(41),
    ) - nested_ky(proof, y)?)
}

fn point_bridge_decider(app: &App, node: &Node, target: PointBridge) -> Result<()> {
    for seed in [0x873_0301, 0x873_0401] {
        let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
        assert!(!accepted);
        assert_eq!(
            checks.unwrap(),
            VerificationChecks {
                native_revdot: true,
                nested_revdot: false,
                native_registry: true,
                nested_registry: true,
                nested_challenges: true,
                commitments: true,
                nested_points: true,
                transcript: true,
                ab_bridge: !matches!(target, PointBridge::Ab),
                mesh: true,
            },
            "exact root rejection boundary for {target:?}"
        );
    }
    Ok(())
}

fn point_bridge_replacement_experiment() -> Result<()> {
    let f = Fixture::new()?;
    let donor = f
        .app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_b123),
            Add,
            (),
            f.left.clone(),
            f.right.clone(),
        )?
        .0;
    assert_eq!(donor.data(), f.honest.data());
    decider(&f.app, &donor, None)?;
    assert_eq!(export_equation(&f.app, f.honest.proof())?, Fq::ZERO);
    assert_eq!(export_equation(&f.app, donor.proof())?, Fq::ZERO);

    for target in PointBridge::ALL {
        let native_rx = target.native_rx();
        let replacement = donor.proof().native_rx_commitment(native_rx);
        assert_ne!(
            replacement,
            f.honest.proof().native_rx_commitment(native_rx),
            "same-header donor must supply a distinct {target:?} stage"
        );
        let mut attack = PointBridgeAttack {
            target,
            replacement,
            calls: 0,
        };
        let changed = f.run(&mut attack)?;
        assert_eq!(attack.calls, 1, "one real bridge deadline for {target:?}");

        // The source point stage and its direct cache remain the authentic
        // ones from the honest fusion. Only the bridge-facing copy changes.
        assert!(same(
            &changed.proof()[native_rx],
            &f.honest.proof()[native_rx]
        ));
        assert_eq!(
            changed.proof().native_rx_commitment(native_rx),
            f.honest.proof().native_rx_commitment(native_rx)
        );
        assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(
                &changed.proof()[native_rx],
                C::host_generators(f.app.params),
            ),
            changed.proof().native_rx_commitment(native_rx)
        );

        let slots = target.bridge_slots();
        let bridge_values = point_bridge_values(changed.proof(), target);
        assert_eq!(&bridge_values[slots], coordinates(replacement));
        let bridge_rx = target.bridge_rx();
        assert_eq!(
            ReferenceBackend::sparse_commit_to_affine(
                &changed.proof()[bridge_rx],
                C::nested_generators(f.app.params),
            ),
            bridge_points(changed.proof())[target.bridge_index()]
        );

        // Everything before the selected deadline is frozen; replay confirms
        // that the changed bridge causally determines the regenerated suffix.
        let honest_bridges = bridge_points(f.honest.proof());
        let changed_bridges = bridge_points(changed.proof());
        let bridge_index = target.bridge_index();
        assert_eq!(
            &changed_bridges[..bridge_index],
            &honest_bridges[..bridge_index]
        );
        assert_ne!(changed_bridges[bridge_index], honest_bridges[bridge_index]);
        let honest_challenges = f.honest.proof().challenges().in_order();
        let changed_challenges = changed.proof().challenges().in_order();
        let challenge_prefix = target.challenge_prefix();
        assert_eq!(
            &changed_challenges[..challenge_prefix],
            &honest_challenges[..challenge_prefix]
        );
        assert_ne!(
            changed_challenges[challenge_prefix], honest_challenges[challenge_prefix],
            "first post-{target:?} challenge must be rehashed"
        );
        assert_eq!(
            replay(&changed_bridges, None, &[])?.challenges,
            changed_challenges
        );

        // Export is traced again with the replacement bridge witness, rather
        // than copied from either proof, and retains exactly the source edge
        // that the authentic point stage contradicts.
        assert!(!same(
            &changed.proof()[nested::RxIndex::Export],
            &f.honest.proof()[nested::RxIndex::Export]
        ));
        assert_ne!(export_equation(&f.app, changed.proof())?, Fq::ZERO);
        point_bridge_decider(&f.app, &changed, target)?;
        descendants(&f.app, &changed, &f.honest, &f.right, Side::Nested)?;
    }
    Ok(())
}

#[test]
fn post_y_native_registry_restrictions_require_the_frozen_commitments() -> Result<()> {
    s_prime_experiment(Side::Native)
}

#[test]
fn post_y_nested_registry_restrictions_require_the_frozen_commitments() -> Result<()> {
    s_prime_experiment(Side::Nested)
}

#[test]
fn post_x_native_accumulator_requires_the_frozen_commitments() -> Result<()> {
    ab_experiment(Side::Native)
}

#[test]
fn post_x_nested_accumulator_requires_the_frozen_commitments() -> Result<()> {
    ab_experiment(Side::Nested)
}

#[test]
fn precommit_native_accumulator_rescale_rebuilds_the_complete_suffix() -> Result<()> {
    accumulator_rescale_experiment(Side::Native)
}

#[test]
fn precommit_nested_accumulator_rescale_rebuilds_the_complete_suffix() -> Result<()> {
    accumulator_rescale_experiment(Side::Nested)
}

#[test]
fn point_stage_bridge_replacements_rebuild_suffix_and_reject_through_three_fusions() -> Result<()> {
    point_bridge_replacement_experiment()
}

#[test]
fn post_u_native_quotient_requires_rewriting_the_frozen_commitment() -> Result<()> {
    quotient_experiment(Side::Native)
}

#[test]
fn post_u_nested_quotient_requires_rewriting_the_frozen_commitment() -> Result<()> {
    quotient_experiment(Side::Nested)
}

#[test]
fn post_pre_beta_native_evaluations_cancel_only_in_the_late_eval_model() -> Result<()> {
    eval_experiment(Side::Native)
}

#[test]
fn post_pre_beta_nested_evaluations_cancel_only_in_the_late_eval_model() -> Result<()> {
    eval_experiment(Side::Nested)
}

#[test]
fn post_pre_beta_challenge_completion_requires_the_frozen_partial() -> Result<()> {
    challenge_completion_experiment()
}

#[test]
fn child_challenge_polynomial_requires_its_pcs_edge_through_three_generations() -> Result<()> {
    if cfg!(debug_assertions) {
        // The production mismatch this regression exercises is intentionally
        // guarded by compute_nested_p's internal debug assertion.
        return Ok(());
    }
    challenge_pcs_transfer_experiment()
}

#[test]
fn post_alpha_nested_registry_requires_canonical_anchors() -> Result<()> {
    late_registry_experiment()
}
