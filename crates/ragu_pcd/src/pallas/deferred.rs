//! New non-native R values (Pallas / EpAffine curve points) produced in this Fq round
//! are deferred through nested staging polynomials.
//!
//! The deferral occurs in three steps:
//!   1. **Inner (Fp) stage:** allocate Ep points natively for other curve and form the staging polynomial `r(X)`.
//!   2. **Off-circuit commitment:** commit `r(X)` using Vesta (Eq) generators.
//!   3. **Outer (Fq) stage:** stage the resulting Eq commitment inside the Fq circuit.

use ragu_core::Result;
use ragu_pasta::{EpAffine, EqAffine};

use crate::nested_encoding::b_stage::{InnerStage, OuterStage, StagingCircuit};

pub type FqInnerStage<const NUM: usize> = InnerStage<EpAffine, NUM>;
pub type FqOuterStage = OuterStage<EqAffine>;
pub type FqStageingCircuit = StagingCircuit<EqAffine>;

#[test]
fn test_nested_staging_polynomial() -> Result<()> {
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{
        CircuitExt,
        polynomials::Rank,
        staging::{StageExt, Staged},
    };
    use ragu_pasta::EpAffine;
    use ragu_pasta::Fq;
    use ragu_pasta::{Fp, Pasta};
    use rand::thread_rng;

    const NUM: usize = 8;
    type R = ragu_circuits::polynomials::R<10>;

    let params = Pasta::default();

    // Allocate Eq points that are non-native in Fp round.
    let eq_points = [(EpAffine::generator() * Fq::random(thread_rng())).to_affine(); NUM];

    // Generate the partial witness polynomial by executing the Fq staging polynomial, and compute a Ep commitment to
    // it outside the circuit.
    let inner_rx_fq = <FqInnerStage<NUM> as StageExt<Fp, R>>::rx(&eq_points)?;
    let ep_commit = inner_rx_fq.commit(&params.vesta, Fp::random(thread_rng()));

    // The staged circuit allocates the commitment in the circuit.
    let staged_circuit = Staged::<Fq, R, _>::new(FqStageingCircuit::new());
    let (outer_rx, ep_point_value) = staged_circuit.rx::<R>(ep_commit)?;

    assert_eq!(ep_point_value, ep_commit);

    let outer_s = <FqOuterStage as StageExt<Fq, R>>::final_into_object()?;
    let y = Fq::random(thread_rng());
    let z = Fq::random(thread_rng());

    let mut rhs = outer_rx.clone();
    rhs.dilate(z);
    rhs.add_assign(&outer_s.sy(y));
    rhs.add_assign(&R::tz(z));

    assert_eq!(outer_rx.revdot(&rhs), Fq::ZERO);

    Ok(())
}
