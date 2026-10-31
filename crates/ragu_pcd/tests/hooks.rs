//! Hooked profiles end to end: steps that witness polynomials and record
//! poly-queries, driven through seed, fuse, rerandomize and the uncompressed
//! verifier on the real pipeline.
//!
//! In-crate, beside steps of its own, because some cases are fabrications no
//! [`Step`] can express through [`StepCtx`]: [`PolyHandle`](crate::PolyHandle)'s
//! constructors are crate-private, so a step cannot name a commitment the
//! proof does not carry. A malicious prover can still commit to one, which is
//! what the verifier's checks are for, so those cases edit a proof's fields
//! directly.

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{Element, GadgetExt, allocator::Standard, poseidon::Sponge};
use rand::{SeedableRng, rngs::StdRng};

use crate::{
    AppHooks, Application, ApplicationBuilder, HookLayout, Pcd, Proof,
    poly_commitment::HANDLE_WIRES,
    profile::Profiled,
    step::{Encoded, Index, Step, StepCtx},
};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// One polynomial and two queries, so a repeat opening must spend a query
/// slot rather than a polynomial.
type Hooks = AppHooks<1, 2>;
type Hooked = Profiled<Pasta, Hooks>;
type App = Application<'static, Hooked, R, HEADER_SIZE>;

/// What [`CommitAndOpen`] witnesses: a polynomial, and an opening `(x, y)` of
/// it to record. A `y` that is not the polynomial's value at `x` makes the
/// step dishonest.
struct Opening {
    coeffs: Vec<u64>,
    x: u64,
    y_offset: u64,
}

impl Opening {
    fn honest(coeffs: &[u64], x: u64) -> Self {
        Opening {
            coeffs: coeffs.to_vec(),
            x,
            y_offset: 0,
        }
    }

    fn polynomial(&self) -> sparse::Polynomial<Fp, R> {
        sparse::Polynomial::from_coeffs(self.coeffs.iter().map(|&c| Fp::from(c)).collect())
    }
}

/// Witnesses a polynomial, opens it at the witnessed point, and opens it
/// again at the next point, which spends a second query and no second
/// polynomial. Usable as a seed and, with `()` children, as a fuse.
struct CommitAndOpen;

impl Step<Hooked> for CommitAndOpen {
    const INDEX: Index = Index::new(0);
    type Shared = ();
    type Witness<'source> = Opening;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, Hooked>,
        witness: DriverValue<D, Opening>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        (),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let polynomial = witness.as_ref().map(|w| w.polynomial());
        let at = witness.as_ref().map(|w| Fp::from(w.x));
        let claimed = witness
            .as_ref()
            .map(|w| w.polynomial().eval(Fp::from(w.x)) + Fp::from(w.y_offset));

        let handle = ctx.witness_polynomial(polynomial)?;
        let x = Element::alloc(ctx.dr, allocator, at)?;
        let y = Element::alloc(ctx.dr, allocator, claimed)?;
        ctx.enforce_poly_query(&handle, x.clone(), y)?;

        let next = x.add(ctx.dr, &Element::one());
        let at_next = ctx.evaluate(&handle, next.value().map(|x| *x))?;
        let at_next = Element::alloc(ctx.dr, allocator, at_next)?;
        ctx.enforce_poly_query(&handle, next, at_next)?;

        Ok((
            (
                Encoded::new(ctx.dr, allocator, left)?,
                Encoded::new(ctx.dr, allocator, right)?,
                Encoded::new(ctx.dr, allocator, D::unit())?,
            ),
            (),
            D::unit(),
            D::unit(),
        ))
    }
}

fn app() -> Result<App> {
    ApplicationBuilder::<Hooked, R, HEADER_SIZE>::new()
        .register(CommitAndOpen)?
        .finalize(crate::pasta::baked())
}

fn seeded(app: &App, rng: &mut StdRng, coeffs: &[u64]) -> Result<Pcd<Hooked, R, ()>> {
    Ok(app.seed(rng, CommitAndOpen, Opening::honest(coeffs, 11))?.0)
}

/// The control the refusals below rest on, and the full loop: two seeds
/// whose queries the fuse discharges, and a fuse whose own queries the root
/// discharges.
#[test]
fn a_hooked_application_seeds_fuses_and_verifies() -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(1234);

    let left = seeded(&app, &mut rng, &[3, 1, 4, 1, 5])?;
    assert!(app.verify_uncompressed(&left, &mut rng)?);
    let right = seeded(&app, &mut rng, &[2, 7, 1, 8, 2, 8])?;

    let (node, ()) = app.fuse(
        &mut rng,
        CommitAndOpen,
        Opening::honest(&[3, 1, 4, 1, 5], 9),
        left,
        right,
    )?;
    assert!(app.verify_uncompressed(&node, &mut rng)?);
    Ok(())
}

/// `Application::poly_handle` is the handle a step is handed for the same
/// polynomial, so an off-circuit party can name what a step witnessed.
#[test]
fn poly_handle_is_the_handle_a_step_is_handed() -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(808);
    let coeffs = [3, 1, 4, 1, 5];
    let proof = seeded(&app, &mut rng, &coeffs)?.into_parts().0;
    let polynomial = Opening::honest(&coeffs, 11).polynomial();
    assert_eq!(app.poly_handle(&polynomial)?, proof.witness_poly_names()[0]);
    Ok(())
}

/// The internal steps call no hooks, so the adapter pads every slot: the case
/// the layout's polynomials-first ordering exists for, since a padding query
/// has to name a polynomial.
#[test]
fn rerandomize_pads_every_hook_slot() -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(8080);

    let leaf = seeded(&app, &mut rng, &[3, 1, 4, 1, 5])?;
    let rerandomized = app.rerandomize(leaf, &mut rng)?;
    assert!(app.verify_uncompressed(&rerandomized, &mut rng)?);

    // Again, so an all-padding proof is also folded as a child.
    let again = app.rerandomize(rerandomized, &mut rng)?;
    assert!(app.verify_uncompressed(&again, &mut rng)?);
    Ok(())
}

/// `enforce_poly_query` evaluates the polynomial it holds and compares it to
/// the claimed `y`, so the step body fails while witnessing. Prover-side
/// validation, not soundness: a forging prover would not come this way.
#[test]
fn a_false_opening_cannot_be_proven() -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(1234);
    let opening = Opening {
        y_offset: 1,
        ..Opening::honest(&[3, 1, 4, 1, 5], 11)
    };
    assert!(matches!(
        app.seed(&mut rng, CommitAndOpen, opening),
        Err(Error::InvalidWitness(_))
    ));
    Ok(())
}

/// Edits a copy of a seeded proof and asserts the root refuses it.
fn refuse(seed: u64, apply: impl FnOnce(&mut Proof<Hooked, R>)) -> Result<()> {
    let app = app()?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut proof = seeded(&app, &mut rng, &[3, 1, 4, 1, 5])?.into_parts().0;
    apply(&mut proof);
    assert!(!app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)?);
    Ok(())
}

/// A poly-query whose commitment is no carried polynomial's. Negating it
/// leaves a valid curve point that nothing in the stage commits to.
#[test]
fn a_poly_query_against_an_uncarried_commitment_is_refused() -> Result<()> {
    for slot in 0..HookLayout::of::<Hooks>().poly_queries {
        refuse(4242 + slot as u64, |proof| {
            proof.application_poly_queries[slot].com = -proof.application_poly_queries[slot].com;
        })?;
    }
    Ok(())
}

/// A poly-query whose claimed value is not the polynomial's.
#[test]
fn a_poly_query_with_a_false_value_is_refused() -> Result<()> {
    for slot in 0..HookLayout::of::<Hooks>().poly_queries {
        refuse(5151 + slot as u64, |proof| {
            proof.application_poly_queries[slot].y += Fp::from(1u64);
        })?;
    }
    Ok(())
}

/// A seed that witnesses $p(X) = 3 + X$ and records the false opening
/// $p(2) = 6$, skipping the prover's courtesy check as a malicious prover
/// would. Its application stage holds that opening.
struct Liar;

impl Step<Hooked> for Liar {
    const INDEX: Index = Index::new(1);
    type Shared = ();
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, Hooked>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        (),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let handle = ctx.witness_polynomial(D::just(|| {
            sparse::Polynomial::<Fp, R>::from_coeffs(vec![Fp::from(3u64), Fp::from(1u64)])
        }))?;
        let allocator = &mut Standard::new();
        let x = Element::alloc(ctx.dr, allocator, D::just(|| Fp::from(2u64)))?;
        let y = Element::alloc(ctx.dr, allocator, D::just(|| Fp::from(6u64)))?;
        ctx.enforce_poly_query_unchecked(&handle, x, y)?;
        Ok((
            (
                Encoded::new(ctx.dr, allocator, left)?,
                Encoded::new(ctx.dr, allocator, right)?,
                Encoded::new(ctx.dr, allocator, D::unit())?,
            ),
            (),
            D::unit(),
            D::unit(),
        ))
    }
}

/// A fusing prover that discharges a true opening in place of the false one
/// its child's step recorded must not produce a proof that verifies.
///
/// The forgery edits only what the parent reads: the child's carried
/// poly-query takes the true value $p(2) = 5$, while the child's application
/// stage, and with it the step the child proved, keeps the false $6$. The
/// child is marked to skip the stage comparison in
/// [`has_shape`](Proof::has_shape), which a malicious prover runs on itself
/// or not at all. Below the root, only a circuit can tie the parent's copy to
/// the child's stage: the `read_hooks` claim.
#[test]
fn a_parent_cannot_discharge_a_swapped_poly_query() -> Result<()> {
    let app = ApplicationBuilder::<Hooked, R, HEADER_SIZE>::new()
        .register(CommitAndOpen)?
        .register(Liar)?
        .finalize(crate::pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(930);
    let liar = app.seed(&mut rng, Liar, ())?.0;
    let sibling = app
        .seed(&mut rng, CommitAndOpen, Opening::honest(&[3, 1, 4], 11))?
        .0;
    let opening = || Opening::honest(&[2, 7, 1], 9);

    // Controls: the root refuses the false opening, and so does an honest
    // parent, which discharges it.
    assert!(!app.verify_uncompressed(&liar, &mut rng)?);
    let honest = app.fuse(
        &mut rng,
        CommitAndOpen,
        opening(),
        liar.clone(),
        sibling.clone(),
    );
    let honest_verifies = match honest {
        Ok((pcd, ())) => app.verify_uncompressed(&pcd, &mut rng)?,
        Err(_) => false,
    };
    assert!(!honest_verifies);

    let (mut forged, ()) = liar.into_parts();
    forged.application_poly_queries[0].y = Fp::from(5u64);
    forged.skip_stage_check = true;
    // The prover completes the fuse; the proof it produces is what fails.
    let (fused, ()) = app.fuse(
        &mut rng,
        CommitAndOpen,
        opening(),
        forged.carry::<()>(()),
        sibling,
    )?;
    assert!(
        !app.verify_uncompressed(&fused, &mut rng)?,
        "the parent discharged an opening the child's stage does not hold"
    );
    Ok(())
}

/// Gap 1b probe: a seed that opens `q(X) = X - 7` at `x = Poseidon(h_q)`,
/// where `h_q` is `q`'s honest handle, claiming `q(x) + 1`. It stages `h_q`
/// but commits `p'`, the constant `q(x) + 1`, so the opening holds for the
/// polynomial actually committed.
struct Renamer;

impl Step<Hooked> for Renamer {
    const INDEX: Index = Index::new(1);
    type Shared = ();
    type Witness<'source> = [Fp; HANDLE_WIRES];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, Hooked>,
        name: DriverValue<D, [Fp; HANDLE_WIRES]>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        (),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        // x is derived from the staged name, before any polynomial exists.
        let limbs = [
            Element::alloc(ctx.dr, allocator, name.as_ref().map(|n| n[0]))?,
            Element::alloc(ctx.dr, allocator, name.as_ref().map(|n| n[1]))?,
        ];
        let mut sponge = Sponge::new(ctx.dr, Pasta::circuit_poseidon(crate::pasta::baked()));
        limbs.write(ctx.dr, &mut sponge)?;
        let x = sponge.squeeze(ctx.dr)?;
        let claim = x.value().map(|x| *x - Fp::from(7u64) + Fp::from(1u64));
        let forged = claim
            .as_ref()
            .map(|c| sparse::Polynomial::<Fp, R>::from_coeffs(vec![*c]));
        let handle = ctx.witness_polynomial_named(forged, name)?;
        let y = Element::alloc(ctx.dr, allocator, claim)?;
        ctx.enforce_poly_query(&handle, x, y)?;
        Ok((
            (
                Encoded::new(ctx.dr, allocator, left)?,
                Encoded::new(ctx.dr, allocator, right)?,
                Encoded::new(ctx.dr, allocator, D::unit())?,
            ),
            (),
            D::unit(),
            D::unit(),
        ))
    }
}

fn renamer_app() -> Result<App> {
    ApplicationBuilder::<Hooked, R, HEADER_SIZE>::new()
        .register(CommitAndOpen)?
        .register(Renamer)?
        .finalize(crate::pasta::baked())
}

/// The renamer's proof and the hook region its stage holds: its one handle,
/// then each query's handle, `x` and `y`, all naming `h_q`.
fn renamed(app: &App, rng: &mut StdRng) -> Result<(Proof<Hooked, R>, Vec<Fp>)> {
    let q = sparse::Polynomial::<Fp, R>::from_coeffs(vec![-Fp::from(7u64), Fp::from(1u64)]);
    let h_q = app.poly_handle(&q)?;
    let (proof, ()) = app.seed(rng, Renamer, h_q)?.0.into_parts();
    let mut region = Vec::new();
    region.extend(h_q);
    for query in proof.application_poly_queries() {
        region.extend(h_q);
        region.push(query.x);
        region.push(query.y);
    }
    Ok((proof, region))
}

/// Fuses `child` beside an honest seed under an honest step.
fn fuse_beside(app: &App, rng: &mut StdRng, child: Proof<Hooked, R>) -> Result<Pcd<Hooked, R, ()>> {
    let sibling = seeded(app, rng, &[3, 1, 4, 1, 5])?;
    Ok(app
        .fuse(
            rng,
            CommitAndOpen,
            Opening::honest(&[2, 7, 1], 9),
            child.carry::<()>(()),
            sibling,
        )?
        .0)
}

/// Control for [`a_fusing_prover_cannot_rename_a_child_polynomial`]: the
/// renamed child under an honest parent, whose copy of the handles comes from
/// the carried commitments. `read_hooks` refuses the copy against the child's
/// stage, so a child-side rename alone never reaches the handle-to-commitment
/// seam.
#[test]
fn a_child_side_rename_is_refused_by_read_hooks() -> Result<()> {
    let app = renamer_app()?;
    let mut rng = StdRng::seed_from_u64(1931);
    let (mut child, _) = renamed(&app, &mut rng)?;
    // The root refuses the renamer itself.
    assert!(!app.verify_uncompressed(&child.clone().carry::<()>(()), &mut rng)?);
    child.skip_stage_check = true;
    let fused = fuse_beside(&app, &mut rng, child)?;
    assert!(!app.verify_uncompressed(&fused, &mut rng)?);
    Ok(())
}

/// Gap 1b: the fusing prover copies the child's staged hook region into its
/// preamble, so `read_hooks` and the one-hot hold, while its nested stash
/// keeps the commitment the child carries, which the walk folds. The step
/// opened `q` at `x = Poseidon(h_q)` to a value `q` does not take; the root
/// must refuse.
///
/// Nothing in-circuit ties a handle to the commitment it names, so on the
/// current code the root accepts this proof: run with `--ignored` to see it
/// fail.
#[test]
#[ignore = "gap 1b: no circuit binds a child's handle to its committed polynomial"]
fn a_fusing_prover_cannot_rename_a_child_polynomial() -> Result<()> {
    let app = renamer_app()?;
    let mut rng = StdRng::seed_from_u64(1930);
    let (mut child, region) = renamed(&app, &mut rng)?;
    let query = child.application_poly_queries()[0];
    assert_ne!(
        query.y,
        query.x - Fp::from(7u64),
        "the claim is false for q"
    );
    child.skip_stage_check = true;
    child.forged_hook_region = Some(region);
    // The prover completes the fuse; the proof it produces is what must fail.
    let fused = fuse_beside(&app, &mut rng, child)?;
    assert!(
        !app.verify_uncompressed(&fused, &mut rng)?,
        "the root accepted a polynomial its step named by another polynomial's handle"
    );
    Ok(())
}
