//! End-to-end tests for the polynomial-query oracle, through seed/fuse/verify
//! on the real pipeline.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{Error, Result};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{AppHooks, Application, ApplicationBuilder, HookConfig, Pcd};
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, HEADER_SIZE, HashedOpening, OpenAndHash,
    OpenAndHashWitness, PolyQueryApp, poly, poly_query_app,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

/// The fixtures registered at an arbitrary layout, so a proof can be presented
/// to an application that declares hooks the one that built it did not.
fn app_at<J: HookConfig>(
    pasta: &<Pasta as Cycle>::Params,
) -> Result<Application<'_, Pasta, R, HEADER_SIZE, J>> {
    ApplicationBuilder::<Pasta, R, HEADER_SIZE, J>::new(pasta)
        .register(CommitAndOpen::<Pasta, R>::new(pasta))?
        .register(OpenAndHash::<Pasta, R>::new(Pasta::circuit_poseidon(pasta)))?
        .finalize()
}

/// Fuses two `PolyQueryHooks` children under an application declaring `J`.
fn fuse_under<J: HookConfig>(
    pasta: &<Pasta as Cycle>::Params,
    rng: &mut StdRng,
    leaf: &Pcd<Pasta, R, HashedOpening<R>>,
    sibling: &Pcd<Pasta, R, HashedOpening<R>>,
) -> Result<()> {
    let polynomial = poly::<Fp, R>(&[5, 5, 5]);
    let x = Fp::from(9u64);
    let y = polynomial.eval(x);
    app_at::<J>(pasta)?.fuse(
        rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness { polynomial, x, y },
        leaf.clone(),
        sibling.clone(),
    )?;
    Ok(())
}

fn seed_leaf(
    app: &PolyQueryApp<'_, Pasta, R>,
    pasta: &<Pasta as Cycle>::Params,
    rng: &mut StdRng,
    coeffs: &[u64],
) -> Result<Pcd<Pasta, R, HashedOpening<R>>> {
    let polynomial = poly::<Fp, R>(coeffs);
    let x = Fp::from(11u64);
    let y = polynomial.eval(x);
    let (leaf, ()) = app.seed(
        rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness { polynomial, x, y },
    )?;
    Ok(leaf)
}

/// The full oracle loop with honest witnesses: seed, cross-step opening via
/// fuse, verify. Declared at `POLYS = 1, CLAIMS = 2` so the repeat opening
/// must spend a poly-query, not a polynomial, or `seed` would fail.
#[test]
fn oracle_end_to_end() -> Result<()> {
    let pasta = Pasta::baked();
    let app = poly_query_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let p1 = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let x1 = Fp::from(11u64);
    let y1 = p1.eval(x1);
    let (leaf1, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial: p1.clone(),
            x: x1,
            y: y1,
        },
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);

    let p2 = poly::<Fp, R>(&[2, 7, 1, 8, 2, 8]);
    let x2 = Fp::from(11u64);
    let y2 = p2.eval(x2);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial: p2,
            x: x2,
            y: y2,
        },
    )?;

    // The same polynomial the leaf witnessed: a cross-step opening, which
    // resolves because the commitment is a function of the polynomial.
    let x = Fp::from(9u64);
    let y = p1.eval(x);
    let (node, ()) = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            polynomial: p1.clone(),
            x,
            y,
        },
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&node, &mut rng)?);

    Ok(())
}

/// `rerandomize` at a layout that declares hooks.
///
/// The internal `Rerandomize` and `Trivial` steps call no hooks, so
/// `pad_to_layout` supplies every slot — the case the layout's
/// polynomials-first ordering exists for, since a padding query has to name a
/// polynomial. `tests/rerandomization.rs` runs at `NoHooks`, where there is
/// nothing to pad.
#[test]
fn rerandomize_pads_every_hook_slot() -> Result<()> {
    let pasta = Pasta::baked();
    let app = poly_query_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(8080);

    let polynomial = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let x = Fp::from(11u64);
    let y = polynomial.eval(x);
    let (leaf, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness { polynomial, x, y },
    )?;
    assert!(app.verify(&leaf, &mut rng)?, "the leaf verifies");

    let hash = leaf.data().hash;
    let rerandomized = app.rerandomize(leaf, &mut rng)?;
    assert!(
        app.verify(&rerandomized, &mut rng)?,
        "a rerandomized proof at a hooked layout must verify"
    );
    assert_eq!(
        rerandomized.data().hash,
        hash,
        "rerandomization preserves the carried header"
    );

    // Again, so an all-padding proof is also folded as a child.
    let again = app.rerandomize(rerandomized, &mut rng)?;
    assert!(
        app.verify(&again, &mut rng)?,
        "rerandomizing a rerandomized proof must verify"
    );
    Ok(())
}

/// `enforce_poly_query` evaluates the polynomial it holds and compares it to the
/// claimed `y`, so the step body fails while witnessing. Prover-side validation,
/// not soundness — a forging prover would not come this way.
#[test]
fn a_false_opening_claim_cannot_be_proven() -> Result<()> {
    let pasta = Pasta::baked();
    let app = poly_query_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let polynomial = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let x = Fp::from(11u64);
    let y = polynomial.eval(x) + Fp::from(1u64);
    let result = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness { polynomial, x, y },
    );
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness",
    );
    Ok(())
}

/// A proof is refused by an application whose layout is not the one it was built
/// under. `Pcd` carries no `HookConfig`, so the type system permits the call.
#[test]
fn a_proof_of_another_layout_does_not_verify() -> Result<()> {
    let pasta = Pasta::baked();
    let mut rng = StdRng::seed_from_u64(70707);

    let app = poly_query_app::<Pasta, R>(pasta)?;
    let leaf = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
    assert!(
        app.verify(&leaf, &mut rng)?,
        "the leaf verifies under its own application"
    );

    let wider = app_at::<AppHooks<1, 3, 1, 2>>(pasta)?;
    assert!(
        !wider.verify(&leaf, &mut rng)?,
        "a proof carrying two queries must not verify where three are declared"
    );
    Ok(())
}

/// Fusing a child whose hook lists are not the parent layout's lengths is a
/// malformed encoding, not a failed proof: `ProofInputs::alloc` reads the child
/// against the layout it is being fused under, and `Proof::has_shape` is what
/// stops it short of indexing past a list.
///
/// One layout per comparison `has_shape` makes, each a single slot wider than
/// `PolyQueryHooks`. A narrower layout is not a case to test: the adapter refuses to
/// witness a step whose hooks outrun its layout, so no such proof exists.
#[test]
fn fusing_a_child_of_another_layout_is_a_malformed_encoding() -> Result<()> {
    let pasta = Pasta::baked();
    let mut rng = StdRng::seed_from_u64(60606);

    let app = poly_query_app::<Pasta, R>(pasta)?;
    let leaf = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
    let sibling = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8])?;

    for (label, result) in [
        (
            "query",
            fuse_under::<AppHooks<1, 3, 1, 2>>(pasta, &mut rng, &leaf, &sibling),
        ),
        (
            "polynomial",
            fuse_under::<AppHooks<2, 2, 1, 2>>(pasta, &mut rng, &leaf, &sibling),
        ),
        (
            "challenge",
            fuse_under::<AppHooks<1, 2, 2, 2>>(pasta, &mut rng, &leaf, &sibling),
        ),
        (
            "absorbed input",
            fuse_under::<AppHooks<1, 2, 1, 3>>(pasta, &mut rng, &leaf, &sibling),
        ),
    ] {
        match result {
            Err(Error::MalformedEncoding(_)) => {}
            Err(e) => panic!("one {label} too many: expected MalformedEncoding, got {e:?}"),
            Ok(()) => panic!("one {label} too many: the fuse succeeded"),
        }
    }
    Ok(())
}
