//! V10: the base-case sign is independently owned at every binding layer.
//!
//! Two attack tiers flip the nested challenge stage's sign while retaining
//! the actual encoded child headers. The frozen-partial tier acts only after
//! `pre_beta`, when Eval and the exported partial are already committed. The
//! rebuilt-advice tier acts before Eval commitment and coherently recomputes
//! the exported partial and Eval advice. It therefore removes the completion
//! mismatch without repairing either independent derivation from the child
//! headers or the already frozen transcript suffix.

use alloc::format;
use core::marker::PhantomData;

use ragu_arithmetic::{
    Cycle, FixedGenerators,
    ff::Field,
    group::{Curve, Group},
};
use ragu_backend::ReferenceBackend;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_pasta::{Ep, EpAffine, EqAffine, Fp, Fq, Pasta};
use ragu_primitives::allocator::Standard;
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R,
    test_steps::{Add, Leaf, Number},
    transcript_tests::{bridge_points, raw_stage, replay},
};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    header::Header,
    internal::{native, nested},
    step::{Encoded, Index, Step, internal::bootstrap::Bootstrap},
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;
type Node = Pcd<C, R, Number>;
type ChallengeStage = nested::stages::challenges::Stage<EqAffine, R>;

/// A small application relation whose input header types are the only fact
/// relevant to this test. Its output is supplied directly as the witness.
struct HeaderCase<L, Rt, const ID: usize>(PhantomData<(L, Rt)>);

impl<L, Rt, const ID: usize> HeaderCase<L, Rt, ID> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<L, Rt, const ID: usize> Step<Pasta> for HeaderCase<L, Rt, ID>
where
    L: Header<Fp>,
    Rt: Header<Fp>,
{
    const INDEX: Index = Index::new(ID);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = L;
    type Right = Rt;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, L::Data>,
        right: DriverValue<D, Rt::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, L, H>,
            Encoded<'dr, D, Rt, H>,
            Encoded<'dr, D, Number, H>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::new(dr, allocator, witness.as_ref().map(|value| *value))?;
        Ok(((left, right, output), witness, D::unit()))
    }
}

type TrivialTrivial = HeaderCase<(), (), 2>;
type NumberTrivial = HeaderCase<Number, (), 3>;
type TrivialNumber = HeaderCase<(), Number, 4>;
type NumberNumber = HeaderCase<Number, Number, 5>;

/// Produce a unit header with application history distinct from bootstrap.
struct ToTrivial;

impl Step<Pasta> for ToTrivial {
    const INDEX: Index = Index::new(6);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, H>,
            Encoded<'dr, D, Number, H>,
            Encoded<'dr, D, (), H>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        Ok((
            (left, right, Encoded::from_gadget(())),
            D::unit(),
            D::unit(),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    FrozenPartial,
    RebuiltAdvice,
}

struct SignAttack {
    tier: Tier,
    calls: usize,
}

impl SignAttack {
    fn flip(witness: &mut nested::stages::challenges::Witness<Fq>) {
        assert!(witness.base_case_sign == Fq::ONE || witness.base_case_sign == -Fq::ONE);
        witness.base_case_sign = -witness.base_case_sign;
    }
}

impl super::super::SuffixAttack<C, R> for SignAttack {
    fn before_eval_commitment(
        &mut self,
        native: &mut native::stages::eval::Witness<C>,
        challenges: &mut nested::stages::challenges::Witness<Fq>,
    ) {
        if self.tier == Tier::RebuiltAdvice {
            self.calls += 1;
            Self::flip(challenges);
            native.partials = native::stages::eval::BindingPartials::compute::<
                C,
                R,
                ReferenceBackend,
            >(Pasta::baked(), challenges);
        }
    }

    fn after_pre_beta(
        &mut self,
        _pre_beta: Fp,
        _native: &mut native::stages::eval::Witness<C>,
        _nested: &mut nested::stages::eval::Evaluations<Fq>,
        challenges: &mut nested::stages::challenges::Witness<Fq>,
    ) {
        if self.tier == Tier::FrozenPartial {
            self.calls += 1;
            Self::flip(challenges);
        }
    }
}

fn checks<H: Header<Fp>>(
    app: &App,
    node: &Pcd<C, R, H>,
    seed: u64,
    context: &str,
) -> Result<VerificationChecks> {
    let (accepted, checks) = app.verify_with_checks(node, StdRng::seed_from_u64(seed))?;
    let checks = checks.expect("well-formed proof reaches every root predicate");
    assert_eq!(accepted, checks.all(), "{context}: {checks:?}");
    Ok(checks)
}

fn is_dummy_header(header: &[Fp]) -> bool {
    header.len() == HEADER_SIZE && header[HEADER_SIZE - 1] == Fp::from(2)
}

fn expected_sign(proof: &Proof<C, R>) -> Fq {
    if is_dummy_header(proof.left_header()) && is_dummy_header(proof.right_header()) {
        Fq::ONE
    } else {
        -Fq::ONE
    }
}

fn stage_scalars(proof: &Proof<C, R>) -> [Fq; nested::stages::challenges::NUM + 2] {
    let stage = raw_stage::<Fq, ChallengeStage>(proof.nested_challenges_rx());
    core::array::from_fn(|i| stage[2 * i])
}

fn binding(scalars: &[Fq]) -> EpAffine {
    let generators = Pasta::nested_generators(Pasta::baked());
    let mut sum = Ep::identity();
    for (i, scalar) in scalars.iter().enumerate() {
        sum += generators.g()[native::stages::eval::generator_index::<C, R>(i)] * scalar;
    }
    sum.to_affine()
}

fn assert_stage_and_frontier(
    honest: &Proof<C, R>,
    changed: &Proof<C, R>,
    tier: Tier,
    base_case: bool,
    context: &str,
) -> Result<()> {
    assert_eq!(honest.left_header(), changed.left_header(), "{context}");
    assert_eq!(honest.right_header(), changed.right_header(), "{context}");
    let expected = if base_case { Fq::ONE } else { -Fq::ONE };
    assert_eq!(expected_sign(honest), expected, "{context}");
    assert_eq!(expected_sign(changed), expected, "{context}");

    let honest_scalars = stage_scalars(honest);
    let changed_scalars = stage_scalars(changed);
    let sign = nested::stages::challenges::SIGN_INDEX;
    let beta = nested::stages::challenges::BETA_INDEX;
    assert_eq!(honest_scalars[sign], expected, "{context}");
    assert_eq!(changed_scalars[sign], -expected, "{context}");
    for i in 0..sign {
        assert_eq!(changed_scalars[i], honest_scalars[i], "{context}: lift {i}");
    }

    let honest_binding = binding(&honest_scalars[..=sign]);
    let changed_binding = binding(&changed_scalars[..=sign]);
    assert_eq!(
        honest.nested_challenges_partial(),
        honest_binding,
        "{context}"
    );
    assert_ne!(changed_binding, honest_binding, "{context}");
    assert_eq!(
        changed.nested_challenges_partial() == changed_binding,
        tier == Tier::RebuiltAdvice,
        "{context}: the two tiers must differ exactly at the exported partial"
    );
    assert_eq!(
        changed.nested_challenges_partial() == honest.nested_challenges_partial(),
        tier == Tier::FrozenPartial,
        "{context}"
    );

    assert_eq!(
        binding(&honest_scalars),
        honest.nested_challenges_commitment(),
        "{context}"
    );
    assert_eq!(
        binding(&changed_scalars),
        changed.nested_challenges_commitment(),
        "{context}"
    );
    assert_eq!(
        changed_scalars[beta], honest_scalars[beta],
        "{context}: the terminal transcript challenge stays frozen"
    );

    let honest_points = bridge_points(honest);
    let changed_points = bridge_points(changed);
    assert_eq!(
        changed_points, honest_points,
        "{context}: every transcript commitment stays frozen"
    );
    assert_eq!(
        replay(&changed_points, None, &[])?.challenges,
        changed.challenges().in_order(),
        "{context}: changed transcript suffix must replay exactly"
    );
    Ok(())
}

fn assert_root_isolation<H: Header<Fp>>(
    app: &App,
    changed: &Pcd<C, R, H>,
    tier: Tier,
    base_case: bool,
    context: &str,
) -> Result<()> {
    let root = checks(app, changed, 0x873_10d0, context)?;
    assert!(!root.all(), "{context}: flipped sign accepted");
    assert!(
        root.native_registry
            && root.nested_registry
            && root.commitments
            && root.nested_points
            && root.transcript
            && root.ab_bridge
            && root.mesh,
        "{context}: unrelated root bookkeeping failed: {root:?}"
    );
    assert!(
        !root.nested_challenges,
        "{context}: terminal coefficient reconstruction must derive the sign from headers: {root:?}"
    );
    assert_eq!(
        root.native_revdot,
        tier == Tier::FrozenPartial,
        "{context}: native header derivation must reject the rebuilt bad sign: {root:?}"
    );
    assert_eq!(
        root.nested_revdot, !base_case,
        "{context}: flipping the sign must activate the false seed equality and disable only the non-base equality: {root:?}"
    );
    Ok(())
}

fn assert_descendants_reject(
    app: &App,
    changed: &Node,
    honest: &Node,
    sibling: &Node,
    context: &str,
) -> Result<()> {
    for initial_left in [false, true] {
        let mut bad = changed.clone();
        let mut good = honest.clone();
        for generation in 0..2u64 {
            let on_left = initial_left ^ (generation == 1);
            let fuse = |node: Node, seed| {
                let (left, right) = if on_left {
                    (node, sibling.clone())
                } else {
                    (sibling.clone(), node)
                };
                app.fuse(&mut StdRng::seed_from_u64(seed), Add, (), left, right)
                    .map(|result| result.0)
            };
            bad = fuse(bad, 0x873_10e0 + generation)?;
            good = fuse(good, 0x873_10e0 + generation)?;
            assert_eq!(bad.data(), good.data(), "{context}");
            assert!(
                checks(app, &good, 0x873_10f0 + generation, "honest descendant")?.all(),
                "{context}"
            );
            let descendant = checks(app, &bad, 0x873_1100 + generation, context)?;
            assert!(!descendant.all(), "{context}: bad descendant accepted");
            assert!(
                descendant.native_registry
                    && descendant.nested_registry
                    && descendant.nested_challenges
                    && descendant.commitments
                    && descendant.nested_points
                    && descendant.transcript
                    && descendant.ab_bridge
                    && descendant.mesh,
                "{context}: fresh descendant bookkeeping failed: {descendant:?}"
            );
            assert!(
                !descendant.native_revdot || !descendant.nested_revdot,
                "{context}: sign obligation expired at generation {generation}: {descendant:?}"
            );
        }
    }
    Ok(())
}

fn exercise_case<L, Rt, const ID: usize>(
    app: &App,
    left: Pcd<C, R, L>,
    right: Pcd<C, R, Rt>,
    sibling: &Node,
    base_case: bool,
    label: &str,
) -> Result<()>
where
    L: Header<Fp>,
    Rt: Header<Fp>,
{
    let output = Fp::from(100 + ID as u64);
    let honest = app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_1000 + ID as u64),
            HeaderCase::<L, Rt, ID>::new(),
            output,
            left.clone(),
            right.clone(),
        )?
        .0;
    assert_eq!(*honest.data(), output);
    let honest_checks = checks(app, &honest, 0x873_1010 + ID as u64, label)?;
    assert!(honest_checks.all(), "{label}: {honest_checks:?}");
    assert_eq!(
        expected_sign(honest.proof()) == Fq::ONE,
        base_case,
        "{label}"
    );

    for tier in [Tier::FrozenPartial, Tier::RebuiltAdvice] {
        let mut attack = SignAttack { tier, calls: 0 };
        let changed = app
            .fuse_inner(
                &mut StdRng::seed_from_u64(0x873_1000 + ID as u64),
                HeaderCase::<L, Rt, ID>::new(),
                output,
                left.clone(),
                right.clone(),
                |_, _| {},
                |_| Ok(None),
                &mut attack,
            )?
            .0;
        assert_eq!(attack.calls, 1, "{label}: {tier:?}");
        assert_eq!(changed.data(), honest.data(), "{label}: {tier:?}");
        let context = format!("V10 {label}, {tier:?}");
        assert_stage_and_frontier(honest.proof(), changed.proof(), tier, base_case, &context)?;
        assert_root_isolation(app, &changed, tier, base_case, &context)?;
        assert_descendants_reject(app, &changed, &honest, sibling, &context)?;
    }
    Ok(())
}

fn exercise_bootstrap(app: &App, sibling: &Node) -> Result<()> {
    let honest = app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_1030),
            Bootstrap::new(),
            (),
            app.dummy_pcd(),
            app.dummy_pcd(),
        )?
        .0;
    assert!(checks(app, &honest, 0x873_1031, "bootstrap")?.all());

    for tier in [Tier::FrozenPartial, Tier::RebuiltAdvice] {
        let mut attack = SignAttack { tier, calls: 0 };
        let changed = app
            .fuse_inner(
                &mut StdRng::seed_from_u64(0x873_1030),
                Bootstrap::new(),
                (),
                app.dummy_pcd(),
                app.dummy_pcd(),
                |_, _| {},
                |_| Ok(None),
                &mut attack,
            )?
            .0;
        let context = format!("V10 dummy/dummy, {tier:?}");
        assert_eq!(attack.calls, 1, "{context}");
        assert_stage_and_frontier(honest.proof(), changed.proof(), tier, true, &context)?;
        assert_root_isolation(app, &changed, tier, true, &context)?;

        // A seed must inherit the malformed bootstrap's obligation in either
        // child position, and ordinary descendants must continue to enforce it.
        for initial_left in [false, true] {
            let seed = |child: Pcd<C, R, ()>| {
                let (left, right) = if initial_left {
                    (child, app.bootstrap_pcd())
                } else {
                    (app.bootstrap_pcd(), child)
                };
                app.fuse(
                    &mut StdRng::seed_from_u64(0x873_1032),
                    TrivialTrivial::new(),
                    Fp::from(211),
                    left,
                    right,
                )
                .map(|(node, _)| node)
            };
            let good = seed(honest.clone())?;
            let bad = seed(changed.clone())?;
            assert!(checks(app, &good, 0x873_1033, &context)?.all());
            assert!(!checks(app, &bad, 0x873_1033, &context)?.all());
            assert_descendants_reject(app, &bad, &good, sibling, &context)?;
        }
    }
    Ok(())
}

#[test]
fn base_case_sign_repairs_cover_every_child_header_combination() -> Result<()> {
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(Add)?
        .register(TrivialTrivial::new())?
        .register(NumberTrivial::new())?
        .register(TrivialNumber::new())?
        .register(NumberNumber::new())?
        .register(ToTrivial)?
        .finalize(Pasta::baked())?;
    let left = app
        .seed(&mut StdRng::seed_from_u64(0x873_1020), Leaf, Fp::from(19))?
        .0;
    let right = app
        .seed(&mut StdRng::seed_from_u64(0x873_1021), Leaf, Fp::from(43))?
        .0;
    let sibling = app
        .seed(&mut StdRng::seed_from_u64(0x873_1022), Leaf, Fp::from(101))?
        .0;
    let trivial_left = app
        .fuse(
            &mut StdRng::seed_from_u64(0x873_1023),
            ToTrivial,
            (),
            left.clone(),
            right.clone(),
        )?
        .0;
    let trivial_seed = app.bootstrap_pcd();

    exercise_bootstrap(&app, &sibling)?;

    exercise_case::<Number, (), 3>(
        &app,
        left.clone(),
        trivial_left.clone(),
        &sibling,
        false,
        "number/trivial",
    )?;
    exercise_case::<(), Number, 4>(
        &app,
        trivial_left.clone(),
        right.clone(),
        &sibling,
        false,
        "trivial/number",
    )?;
    exercise_case::<Number, Number, 5>(&app, left, right, &sibling, false, "number/number")?;
    exercise_case::<(), (), 2>(
        &app,
        trivial_seed.clone(),
        trivial_seed,
        &sibling,
        false,
        "trivial/trivial",
    )
}
