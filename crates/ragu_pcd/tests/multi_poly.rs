//! A layout affording more witnessed polynomials than a step uses proves *and*
//! verifies.
//!
//! Padded slots all commit to `g[0]`, so the prover-side one-hot has several
//! equal candidates to pick exactly one of. Its constraints — booleanity,
//! sum-to-one, per-limb equality — are pinned in
//! `internal::native::circuits::poly_query`; this covers the prover. Layouts
//! whose slots are all real are covered by every other hooked test.

use ragu_arithmetic::rand::{SeedableRng, rngs::StdRng};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{AppHooks, ApplicationBuilder, HANDLE_WIRES};
use ragu_testing::pcd::poly_query::{CommitAndOpen, CommitAndOpenWitness, poly};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// Four polynomial slots against a step that witnesses one, so the three
/// padding slots sharing `g[0]` outnumber it and the one-hot picks one of three
/// equals.
#[test]
fn padding_outnumbering_the_real_polynomial_proves_and_verifies() -> Result<()> {
    let pasta = Pasta::baked();
    let app =
        ApplicationBuilder::<Pasta, R, HEADER_SIZE, AppHooks<4, 3, 1, HANDLE_WIRES>>::new(pasta)
            .register(CommitAndOpen::<Pasta, R>::new(pasta))?
            .finalize()?;
    let mut rng = StdRng::seed_from_u64(999);

    let polynomial = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let x = Fp::from(11u64);
    let y = polynomial.eval(x);
    let (leaf, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness { polynomial, x, y },
    )?;
    assert!(app.verify(&leaf, &mut rng)?, "an honest proof must verify");
    Ok(())
}
