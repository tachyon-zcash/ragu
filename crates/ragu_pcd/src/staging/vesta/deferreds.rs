//! New non-native R values (Vesta / EqAffine curve points) produced in this Fp round
//! are deferred through nested staging polynomials.
//!
//! The deferral occurs in three steps:
//!   1. **Inner (Fq) stage:** allocate Eq points natively for other curve and form the staging polynomial `r(X)`.
//!   2. **Off-circuit commitment:** commit `r(X)` using Pallas (Ep) generators.
//!   3. **Outer (Fp) stage:** stage the resulting Ep commitment inside the Fp circuit.

use ragu_pasta::{EpAffine, EqAffine};

use crate::staging::common::deferreds::{InnerStage, OuterStage, StagingCircuit};

pub type FpInnerStage<const NUM: usize> = InnerStage<EqAffine, NUM>;
pub type FpOuterStage = OuterStage<EpAffine>;
pub type FpStageingCircuit = StagingCircuit<EpAffine>;

#[cfg(test)]
mod tests {
    use crate::staging::vesta::deferreds::OuterStage;
    use crate::staging::vesta::deferreds::StagingCircuit;
    use crate::staging::vesta::deferreds::{
        FpInnerStage, FpOuterStage, FpStageingCircuit, InnerStage,
    };
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{
        CircuitExt,
        polynomials::Rank,
        staging::{StageExt, Staged},
    };
    use ragu_core::Result;
    use ragu_pasta::EpAffine;
    use ragu_pasta::Fq;
    use ragu_pasta::{EqAffine, Fp, Pasta};
    use rand::thread_rng;

    const NUM: usize = 8;
    type R = ragu_circuits::polynomials::R<10>;

    #[test]
    fn test_nested_staging_polynomial() -> Result<()> {
        let params = Pasta::default();

        // Allocate Eq points that are non-native in Fp round.
        let eq_points = [(EqAffine::generator() * Fp::random(thread_rng())).to_affine(); NUM];

        // Generate the partial witness polynomial by executing the Fq staging polynomial, and compute a Ep commitment to
        // it outside the circuit.
        let inner_rx_fq = <FpInnerStage<NUM> as StageExt<Fq, R>>::rx(&eq_points)?;
        let ep_commit = inner_rx_fq.commit(&params.pallas, Fq::random(thread_rng()));

        // The staged circuit allocates the commitment in the circuit.
        let staged_circuit = Staged::<Fp, R, _>::new(FpStageingCircuit::new());
        let (outer_rx, ep_point_value) = staged_circuit.rx::<R>(ep_commit)?;

        assert_eq!(ep_point_value, ep_commit);

        let outer_s = <FpOuterStage as StageExt<Fp, R>>::final_into_object()?;
        let y = Fp::random(thread_rng());
        let z = Fp::random(thread_rng());

        let mut rhs = outer_rx.clone();
        rhs.dilate(z);
        rhs.add_assign(&outer_s.sy(y));
        rhs.add_assign(&R::tz(z));

        assert_eq!(outer_rx.revdot(&rhs), Fp::ZERO);

        Ok(())
    }
}
