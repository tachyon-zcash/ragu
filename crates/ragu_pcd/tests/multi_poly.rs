//! Multi-polynomial proving regression: shapes affording more than one
//! witnessed polynomial must prove *and verify*. The prover-side one-hot
//! matcher once set a bit for **every** polynomial sharing the query's
//! commitment, and padded polynomials all share one, so at `POLYS ≥ 2`
//! sum-to-one was violated in the trace and the proof survived until root
//! verification.

use ragu_arithmetic::rand::{SeedableRng, rngs::StdRng};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{AppHooks, ApplicationBuilder, HANDLE_WIRES};
use ragu_testing::pcd::poly_query::{CommitAndOpen, CommitAndOpenWitness, poly};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// One honest polynomial in a two-polynomial layout, padding filling the
/// second: duplicate padding commitments must resolve to exactly one one-hot
/// bit.
#[test]
fn a_layout_with_two_polynomials_proves_and_verifies() -> Result<()> {
    let pasta = Pasta::baked();
    let app =
        ApplicationBuilder::<Pasta, R, HEADER_SIZE, AppHooks<2, 3, 1, HANDLE_WIRES>>::new(pasta)
            .register(CommitAndOpen::<Pasta, R>::new(pasta))?
            .finalize()?;
    let mut rng = StdRng::seed_from_u64(999);

    let polynomial = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let (leaf, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(
        app.verify(&leaf, &mut rng)?,
        "an honest proof in a multi-polynomial layout must verify"
    );
    Ok(())
}
