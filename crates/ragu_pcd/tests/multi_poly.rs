//! A layout affording more witnessed polynomials than a step uses proves *and*
//! verifies.
//!
//! Padded slots all commit to `g[0]`, so the prover-side one-hot has several
//! equal candidates to pick exactly one of. Its constraints — booleanity,
//! sum-to-one, per-limb equality — are pinned in
//! `internal::native::circuits::poly_query`; this covers the prover. Layouts
//! whose slots are all real are covered by every other hooked test.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{AppHooks, ApplicationBuilder};
use ragu_testing::pcd::poly_query::{CommitAndOpen, CommitAndOpenWitness, poly};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// Four polynomial slots against a step that witnesses one, so the three
/// padding slots sharing `g[0]` outnumber it and the one-hot picks one of three
/// equals.
#[test]
#[ignore = "a layout of four polynomials exceeds the nested endoscaling step's gate budget at ProductionRank; one polynomial is the most that fits"]
fn padding_outnumbering_the_real_polynomial_proves_and_verifies() -> Result<()> {
    let pasta = ragu_pcd::pasta::baked();
    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, AppHooks<4, 3>>::new()
        .register(CommitAndOpen::<Pasta, R>::new(pasta))?
        .finalize(pasta)?;
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
