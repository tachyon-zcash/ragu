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
    poly_commitment::{self, HANDLE_WIRES},
    profile::Profiled,
    proof::ForgedNames,
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

/// A seed that witnesses `polynomial` honestly, and opens it honestly at
/// 11, but stages `name` as its handle: a child-side rename the parent's
/// copy can follow past `read_hooks`.
struct Misnamer;

impl Step<Hooked> for Misnamer {
    const INDEX: Index = Index::new(2);
    type Shared = ();
    type Witness<'source> = (Vec<u64>, [Fp; HANDLE_WIRES]);
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, Hooked>,
        witness: DriverValue<D, (Vec<u64>, [Fp; HANDLE_WIRES])>,
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
        let (coeffs, name) = witness.cast();
        let polynomial = coeffs.map(|c| Opening::honest(&c, 11).polynomial());
        let handle = ctx.witness_polynomial_named(polynomial, name)?;
        let x = Element::constant(ctx.dr, Fp::from(11u64));
        let y = ctx.evaluate(&handle, D::just(|| Fp::from(11u64)))?;
        let y = Element::alloc(ctx.dr, allocator, y)?;
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
        .register(Misnamer)?
        .finalize(crate::pasta::baked())
}

/// A commitment beside its name, at the application's rank and backend.
fn named(
    commitment: <Hooked as Cycle>::HostCurve,
) -> Result<ForgedNames<<Hooked as Cycle>::HostCurve>> {
    Ok(ForgedNames {
        commitments: vec![commitment],
        names: vec![poly_commitment::name::<
            Hooked,
            R,
            ragu_backend::ReferenceBackend,
        >(commitment, crate::pasta::baked())?],
        in_batch: false,
    })
}

/// The renamer's proof, and the copy of its names a fusing prover takes
/// from its stage: `h_q`, the name of `q`'s commitment.
fn renamed(
    app: &App,
    rng: &mut StdRng,
) -> Result<(Proof<Hooked, R>, ForgedNames<<Hooked as Cycle>::HostCurve>)> {
    let q = [-Fp::from(7u64), Fp::from(1u64)];
    let c_q = poly_commitment::commit::<Hooked, R, ragu_backend::ReferenceBackend>(
        &q,
        crate::pasta::baked(),
    );
    let copy = named(c_q)?;
    let (proof, ()) = app.seed(rng, Renamer, copy.names[0])?.0.into_parts();
    Ok((proof, copy))
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

/// The [`verify_uncompressed`](Application::verify_uncompressed) checks that
/// refuse `pcd`, by name. Panics for a proof refused before any check runs,
/// since the forgeries here must reach the checks.
fn refusing(app: &App, pcd: &Pcd<Hooked, R, ()>, rng: &mut StdRng) -> Result<Vec<&'static str>> {
    let conjuncts = app
        .verify_uncompressed_conjuncts(pcd, rng)?
        .expect("the proof reaches the verifier's checks");
    Ok(conjuncts
        .into_iter()
        .filter(|&(_, holds)| !holds)
        .map(|(name, _)| name)
        .collect())
}

/// Control for [`a_fusing_prover_cannot_rename_a_child_polynomial`]: the
/// renamed child under an honest parent, whose copy of the handles comes from
/// the carried commitments. `read_hooks` refuses the copy against the child's
/// stage, so a child-side rename alone never reaches the handle-to-commitment
/// seam: the native revdot claims refuse it, and nothing else does.
#[test]
fn a_child_side_rename_is_refused_by_read_hooks() -> Result<()> {
    let app = renamer_app()?;
    let mut rng = StdRng::seed_from_u64(1931);
    let (mut child, _) = renamed(&app, &mut rng)?;
    // The root refuses the renamer itself, up front: its stage's hook region
    // is not the one its carried commitments encode.
    assert!(
        app.verify_uncompressed_conjuncts(&child.clone().carry::<()>(()), &mut rng)?
            .is_none()
    );
    child.skip_stage_check = true;
    let fused = fuse_beside(&app, &mut rng, child)?;
    assert_eq!(refusing(&app, &fused, &mut rng)?, ["native_revdot_claims"]);
    Ok(())
}

/// Gap 1b: the fusing prover copies the child's staged names into its
/// binding stage, so `read_hooks` and the one-hot hold, while its nested
/// stash keeps the commitment the child carries. The step opened `q` at
/// `x = Poseidon(h_q)` to a value `q` does not take; the root must refuse.
///
/// The walk folds the copy, `h_q`, into $P_n$, and nested `compute_v`
/// evaluates the name polynomial of the stashed commitment, $C_{p'}$, at
/// $u_n$. `in_batch` chooses which name polynomial the prover's nested batch
/// folds: the stash's, so that $P_n$ is not the commitment of $p_n$ (T1a), or
/// the copy's, so that $P_n$ matches and only $v_n$ disagrees (T1b).
///
/// Returns the forged proof and the checks that refuse it. The native revdot
/// claims hold, `read_hooks`'s among them: the copy is what the child's stage
/// holds, so the forgery is the strongest one the parent can make.
fn fusing_rename(
    app: &App,
    rng: &mut StdRng,
    in_batch: bool,
) -> Result<(Pcd<Hooked, R, ()>, Vec<&'static str>)> {
    let (mut child, copy) = renamed(app, rng)?;
    let query = child.application_poly_queries()[0];
    assert_ne!(
        query.y,
        query.x - Fp::from(7u64),
        "the claim is false for q"
    );
    child.skip_stage_check = true;
    child.forged_names = Some(ForgedNames { in_batch, ..copy });
    // The prover completes the fuse; the proof it produces is what must fail.
    let fused = fuse_beside(app, rng, child)?;
    let refused = refusing(app, &fused, rng)?;
    assert!(
        !refused.is_empty(),
        "the root accepted a polynomial its step named by another polynomial's handle"
    );
    assert!(
        !refused.contains(&"native_revdot_claims"),
        "the native revdot claims refused it: {refused:?}"
    );
    Ok((fused, refused))
}

/// The check that refuses [`fusing_rename`]'s proof: with the stash's name
/// polynomial in the batch, the walk's $P_n$ is not the commitment of $p_n$;
/// with the copy's, $P_n$ is, and the nested `compute_v` claim refuses the
/// $v_n$ it computes from the stash.
fn refuses_rename(in_batch: bool) -> &'static str {
    if in_batch {
        "nested_revdot_claims"
    } else {
        "commitments_claim"
    }
}

/// T1a: [`fusing_rename`], the nested batch folding the stash's name.
#[test]
fn a_fusing_prover_cannot_rename_a_child_polynomial() -> Result<()> {
    let app = renamer_app()?;
    let (_, refused) = fusing_rename(&app, &mut StdRng::seed_from_u64(1930), false)?;
    assert_eq!(refused, [refuses_rename(false)]);
    Ok(())
}

/// T1b: [`fusing_rename`], the nested batch folding the copy's name.
#[test]
fn a_fusing_prover_cannot_rename_a_child_polynomial_in_its_batch() -> Result<()> {
    let app = renamer_app()?;
    let (_, refused) = fusing_rename(&app, &mut StdRng::seed_from_u64(1932), true)?;
    assert_eq!(refused, [refuses_rename(true)]);
    Ok(())
}

/// T2: the rename's obligation outlives the fuse that made it. An honest
/// grandparent folds the forged parent, and its root is refused, by the same
/// check as the parent's, though the grandparent's own names and queries are
/// honest; an honest grandparent of an honest parent verifies.
#[test]
fn a_renamed_polynomial_is_refused_a_level_up() -> Result<()> {
    let app = renamer_app()?;
    let mut rng = StdRng::seed_from_u64(1933);

    let leaf = seeded(&app, &mut rng, &[2, 7, 1])?.into_parts().0;
    let parent = fuse_beside(&app, &mut rng, leaf)?;
    let grandparent = fuse_beside(&app, &mut rng, parent.into_parts().0)?;
    assert!(app.verify_uncompressed(&grandparent, &mut rng)?);

    for in_batch in [false, true] {
        let (forged, _) = fusing_rename(&app, &mut rng, in_batch)?;
        // The grandparent's prover completes; the proof it produces is what
        // must fail.
        let grandparent = fuse_beside(&app, &mut rng, forged.into_parts().0)?;
        assert_eq!(
            refusing(&app, &grandparent, &mut rng)?,
            [refuses_rename(in_batch)],
            "the grandparent root, in_batch = {in_batch}"
        );
    }
    Ok(())
}

/// T4: a child stages the name of $-C$ for a polynomial committed in $C$,
/// a valid point, and a fusing prover copies it, folding $n_{-C}$ in its
/// nested batch. $-C$'s name is not $C$'s (its $C_y$ differs), so $v_n$,
/// computed from the stashed $C$, disagrees with $p_n(u_n)$.
#[test]
fn the_negated_commitments_name_is_refused() -> Result<()> {
    let app = renamer_app()?;
    let mut rng = StdRng::seed_from_u64(1934);
    let coeffs = vec![3, 1, 4, 1, 5];
    let c = poly_commitment::commit::<Hooked, R, ragu_backend::ReferenceBackend>(
        &coeffs.iter().map(|&c| Fp::from(c)).collect::<Vec<_>>(),
        crate::pasta::baked(),
    );
    let copy = named(-c)?;
    let (mut child, ()) = app
        .seed(&mut rng, Misnamer, (coeffs, copy.names[0]))?
        .0
        .into_parts();
    child.skip_stage_check = true;
    child.forged_names = Some(ForgedNames {
        in_batch: true,
        ..copy
    });
    let fused = fuse_beside(&app, &mut rng, child)?;
    assert_eq!(
        refusing(&app, &fused, &mut rng)?,
        [refuses_rename(true)],
        "the root accepted the name of a negated commitment"
    );
    Ok(())
}
