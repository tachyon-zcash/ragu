//! Mirrors the real poly-query integration tests
//! (`ragu_pcd/tests/{poly_query,multi_poly,collections}.rs`) in the mock's
//! driverless idiom.

use alloc::vec::Vec;

use ragu_arithmetic::{
    ff::{Field as _, PrimeField as _},
    rand::{SeedableRng as _, rngs::StdRng},
};
use ragu_core::{Error, Result};
use ragu_pasta::Fp;

use crate::{
    application::ApplicationBuilder,
    ctx::StepCtx,
    framework_hooks::AppHooks,
    header::{Header, Suffix},
    poly_commitment::{HANDLE_WIRES, PolyHandle},
    polynomial::Polynomial,
    step::{Index, Step},
};

/// Header carrying a witnessed polynomial's handle wires and the challenge
/// derived from them.
struct PolyHeader;

#[derive(Clone, Debug)]
struct PolyHeaderData {
    wires: [Fp; HANDLE_WIRES],
    challenge: Fp,
}

impl Header for PolyHeader {
    type Data = PolyHeaderData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut bytes = Vec::new();
        for wire in data.wires {
            bytes.extend_from_slice(wire.to_repr().as_ref());
        }
        bytes.extend_from_slice(data.challenge.to_repr().as_ref());
        bytes
    }
}

fn test_coeffs() -> Vec<Fp> {
    [3u64, 1, 4, 1, 5].map(Fp::from).to_vec()
}

/// Layout of the honest fixture: one polynomial, opened at the derived
/// challenge and again at zero (a repeat opening costs a query slot, not a
/// polynomial slot), one challenge derived from the handle's wires.
type OracleHooks = AppHooks<1, 2, 1, HANDLE_WIRES>;

/// Witnesses a polynomial, derives a challenge from its handle, and opens at
/// the challenge and at zero. Mirrors `ragu_testing`'s `CommitAndOpen`.
struct CommitAndOpen;

impl Step for CommitAndOpen {
    type Aux<'source> = ();
    type Left = ();
    type Output = PolyHeader;
    type Right = ();
    type Witness<'source> = Vec<Fp>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let handle = ctx.witness_polynomial(Polynomial::from_coeffs(&witness))?;
        let challenge = ctx.derive_challenge(&handle.wires())?;
        let y = ctx.evaluate(&handle, challenge)?;
        ctx.enforce_poly_query(&handle, challenge, y)?;
        let at_zero = ctx.evaluate(&handle, Fp::ZERO)?;
        ctx.enforce_poly_query(&handle, Fp::ZERO, at_zero)?;
        Ok((
            PolyHeaderData {
                wires: handle.wires(),
                challenge,
            },
            (),
        ))
    }
}

/// Re-witnesses the carried polynomial and opens it again: the cross-step
/// opening resolves because the commitment — and so the handle — is a
/// function of the polynomial alone.
struct ReopenStep;

impl Step for ReopenStep {
    type Aux<'source> = ();
    type Left = PolyHeader;
    type Output = PolyHeader;
    type Right = PolyHeader;
    type Witness<'source> = Vec<Fp>;

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let handle = ctx.witness_polynomial(Polynomial::from_coeffs(&witness))?;
        if handle.wires() != left.wires || handle.wires() != right.wires {
            return Err(Error::InvalidWitness(
                "carried handle does not name the witnessed polynomial".into(),
            ));
        }
        let challenge = ctx.derive_challenge(&handle.wires())?;
        let y = ctx.evaluate(&handle, challenge)?;
        ctx.enforce_poly_query(&handle, challenge, y)?;
        let at_zero = ctx.evaluate(&handle, Fp::ZERO)?;
        ctx.enforce_poly_query(&handle, Fp::ZERO, at_zero)?;
        Ok((
            PolyHeaderData {
                wires: handle.wires(),
                challenge,
            },
            (),
        ))
    }
}

#[test]
fn oracle_end_to_end() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<OracleHooks>::with_hooks()
        .register(CommitAndOpen)
        .expect("register")
        .register(ReopenStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (left, ()) = app
        .seed(&mut rng, CommitAndOpen, test_coeffs())
        .expect("seed left");
    let (right, ()) = app
        .seed(&mut rng, CommitAndOpen, test_coeffs())
        .expect("seed right");
    assert!(app.verify(&left, &mut rng).expect("verify"));

    let (fused, ()) = app
        .fuse(&mut rng, ReopenStep, test_coeffs(), left, right)
        .expect("fuse");
    assert!(app.verify(&fused, &mut rng).expect("verify"));
}

#[test]
fn commit_polynomial_matches_carried_handle() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<OracleHooks>::with_hooks()
        .register(CommitAndOpen)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd, ()) = app
        .seed(&mut rng, CommitAndOpen, test_coeffs())
        .expect("seed");
    let expected = app
        .commit_polynomial(&Polynomial::from_coeffs(&test_coeffs()))
        .expect("commit");
    assert_eq!(pcd.data().wires, expected);
}

#[test]
fn challenge_is_deterministic() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<OracleHooks>::with_hooks()
        .register(CommitAndOpen)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (first, ()) = app
        .seed(&mut rng, CommitAndOpen, test_coeffs())
        .expect("seed");
    let (second, ()) = app
        .seed(&mut rng, CommitAndOpen, test_coeffs())
        .expect("seed");
    assert_eq!(first.data().challenge, second.data().challenge);

    let different = [2u64, 7, 1, 8].map(Fp::from).to_vec();
    let (third, ()) = app.seed(&mut rng, CommitAndOpen, different).expect("seed");
    assert_ne!(first.data().challenge, third.data().challenge);
}

/// Claims a wrong evaluation; mirrors `dishonest_evaluation_is_rejected`.
struct DishonestStep;

impl Step for DishonestStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = PolyHeader;
    type Right = ();
    type Witness<'source> = Vec<Fp>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let handle = ctx.witness_polynomial(Polynomial::from_coeffs(&witness))?;
        let challenge = ctx.derive_challenge(&handle.wires())?;
        ctx.enforce_poly_query(&handle, challenge, Fp::from(42u64))?;
        Ok((
            PolyHeaderData {
                wires: handle.wires(),
                challenge,
            },
            (),
        ))
    }
}

#[test]
fn dishonest_evaluation_is_rejected() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<OracleHooks>::with_hooks()
        .register(DishonestStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let result = app.seed(&mut rng, DishonestStep, test_coeffs());
    assert!(
        matches!(result.map(|_| ()), Err(Error::InvalidWitness(_))),
        "a dishonest evaluation must be rejected during seed"
    );
}

/// Header carrying only handle wires.
struct WiresHeader;

impl Header for WiresHeader {
    type Data = [Fp; HANDLE_WIRES];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut bytes = Vec::new();
        for wire in data {
            bytes.extend_from_slice(wire.to_repr().as_ref());
        }
        bytes
    }
}

/// Witnesses a polynomial and smuggles the handle out through `Aux`.
struct LeakHandleStep;

impl Step for LeakHandleStep {
    type Aux<'source> = PolyHandle;
    type Left = ();
    type Output = WiresHeader;
    type Right = ();
    type Witness<'source> = Vec<Fp>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let handle = ctx.witness_polynomial(Polynomial::from_coeffs(&witness))?;
        Ok((handle.wires(), handle))
    }
}

/// Feeds a foreign handle to `evaluate` or `enforce_poly_query` without
/// re-witnessing the polynomial.
struct ForeignHandleStep {
    enforce: bool,
}

impl Step for ForeignHandleStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = WiresHeader;
    type Right = ();
    type Witness<'source> = PolyHandle;

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if self.enforce {
            ctx.enforce_poly_query(&witness, Fp::ZERO, Fp::ZERO)?;
        } else {
            ctx.evaluate(&witness, Fp::ZERO)?;
        }
        Ok((witness.wires(), ()))
    }
}

#[test]
fn foreign_handle_is_rejected() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<AppHooks<1, 0, 0, 0>>::with_hooks()
        .register(LeakHandleStep)
        .expect("register")
        .register(ForeignHandleStep { enforce: false })
        .expect("register")
        .finalize()
        .expect("finalize");

    let (_pcd, foreign) = app
        .seed(&mut rng, LeakHandleStep, test_coeffs())
        .expect("seed");

    for enforce in [false, true] {
        let result = app.seed(&mut rng, ForeignHandleStep { enforce }, foreign.clone());
        assert!(
            matches!(result.map(|_| ()), Err(Error::InvalidWitness(_))),
            "a handle from another step must not resolve without re-witnessing"
        );
    }
}

/// Which hook the step over-uses relative to [`BudgetHooks`].
#[derive(Clone, Copy)]
enum BudgetCase {
    ExactFit,
    ExtraPolynomial,
    ExtraQuery,
    ExtraChallenge,
    OversizeChallengeInputs,
}

type BudgetHooks = AppHooks<1, 1, 1, 2>;

struct BudgetStep;

impl Step for BudgetStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = WiresHeader;
    type Right = ();
    type Witness<'source> = BudgetCase;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let handle = ctx.witness_polynomial(Polynomial::from_coeffs(&test_coeffs()))?;
        let at_zero = ctx.evaluate(&handle, Fp::ZERO)?;
        ctx.enforce_poly_query(&handle, Fp::ZERO, at_zero)?;
        match witness {
            BudgetCase::ExactFit => {
                ctx.derive_challenge(&handle.wires())?;
            }
            BudgetCase::ExtraPolynomial => {
                ctx.derive_challenge(&handle.wires())?;
                ctx.witness_polynomial(Polynomial::from_coeffs(&[Fp::from(9u64)]))?;
            }
            BudgetCase::ExtraQuery => {
                ctx.derive_challenge(&handle.wires())?;
                let at_one = ctx.evaluate(&handle, Fp::ONE)?;
                ctx.enforce_poly_query(&handle, Fp::ONE, at_one)?;
            }
            BudgetCase::ExtraChallenge => {
                ctx.derive_challenge(&handle.wires())?;
                ctx.derive_challenge(&handle.wires())?;
            }
            BudgetCase::OversizeChallengeInputs => {
                ctx.derive_challenge(&[Fp::ONE, Fp::ONE, Fp::ONE])?;
            }
        }
        Ok((handle.wires(), ()))
    }
}

#[test]
fn over_budget_is_rejected_at_seed() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<BudgetHooks>::with_hooks()
        .register(BudgetStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd, ()) = app
        .seed(&mut rng, BudgetStep, BudgetCase::ExactFit)
        .expect("an exact-fit step must succeed");
    assert!(app.verify(&pcd, &mut rng).expect("verify"));

    for case in [
        BudgetCase::ExtraPolynomial,
        BudgetCase::ExtraQuery,
        BudgetCase::ExtraChallenge,
        BudgetCase::OversizeChallengeInputs,
    ] {
        let err = app
            .seed(&mut rng, BudgetStep, case)
            .map(|_| ())
            .expect_err("an over-budget step must be rejected during seed");
        assert!(
            matches!(err, Error::VectorLengthMismatch { .. }),
            "unexpected error: {err:?}"
        );
    }
}

#[test]
fn zero_width_challenge_layout_is_refused() {
    let err = ApplicationBuilder::<AppHooks<0, 0, 1, 0>>::with_hooks()
        .finalize()
        .map(|_| ())
        .expect_err("a zero-width challenge layout must be refused at finalize");
    assert!(
        alloc::format!("{err:?}").contains("nonzero width"),
        "unexpected error: {err:?}"
    );
}

/// Uses less than the layout affords; the framework pads the rest.
struct UnderBudgetStep;

impl Step for UnderBudgetStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = WiresHeader;
    type Right = ();
    type Witness<'source> = Vec<Fp>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let handle = ctx.witness_polynomial(Polynomial::from_coeffs(&witness))?;
        let at_zero = ctx.evaluate(&handle, Fp::ZERO)?;
        ctx.enforce_poly_query(&handle, Fp::ZERO, at_zero)?;
        let at_one = ctx.evaluate(&handle, Fp::ONE)?;
        ctx.enforce_poly_query(&handle, Fp::ONE, at_one)?;
        Ok((handle.wires(), ()))
    }
}

#[test]
fn under_budget_is_padded() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<AppHooks<2, 3, 1, HANDLE_WIRES>>::with_hooks()
        .register(UnderBudgetStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd, ()) = app
        .seed(&mut rng, UnderBudgetStep, test_coeffs())
        .expect("an under-budget step is padded to the layout");
    assert!(app.verify(&pcd, &mut rng).expect("verify"));
}

/// Constant output header; only the witnessed polynomial varies, so any proof
/// difference comes from the hook transcript.
struct ConstOutputStep;

impl Step for ConstOutputStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = WiresHeader;
    type Right = ();
    type Witness<'source> = Vec<Fp>;

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        ctx.witness_polynomial(Polynomial::from_coeffs(&witness))?;
        Ok(([Fp::ZERO; HANDLE_WIRES], ()))
    }
}

#[test]
fn transcript_binds_the_proof() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::<AppHooks<1, 0, 0, 0>>::with_hooks()
        .register(ConstOutputStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (first, ()) = app
        .seed(&mut rng, ConstOutputStep, test_coeffs())
        .expect("seed");
    let (second, ()) = app
        .seed(
            &mut rng,
            ConstOutputStep,
            [9u64, 9, 9].map(Fp::from).to_vec(),
        )
        .expect("seed");

    assert_ne!(
        first.proof().serialize(),
        second.proof().serialize(),
        "the hook transcript must be bound into the proof"
    );
}
