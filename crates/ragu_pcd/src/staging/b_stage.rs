//! B-stage with a generic, two-layer nested encoding structure. Nested encoding
//! solves the issue of witnessing data from one curve inside a circuit
//! over a different curve, for instance Fq elements inside an Fp circuit.
//!
//! If you have for instance N polynomials over Fp, where the host curve is Vesta,
//! and you want to a succinct, in-circuit representation of those polynomials that
//! you can use to say derive a challenge, then nested encoding can be used to
//! implement a two-layer flow for doing that:
//!
//! * Inner-stage: commit to the N polynomials using Vesta and construct a staging
//! polynomial (over Fq) that witnesses those Vesta commitments,
//!         
//! * Off-circuit: commit to the staging polynomial using Pallas generators.
//!
//! * Outer-stage: allocate the commitment which can be used across staged circuits.
//!
//! Imprtantly, we can't form a connection between the inner and outer stages due to
//! the field boundary constraint in the `Stage` trait that disallowes stages from
//! building stages that aren't in the same curve. That's why the inner stage acts as
//! an interstitial, temporary stage that we use to construct the commitment, and
//! then we can form an outer stage from which subsequent stages can be built on.

use crate::{indirection_stage, inner_stage, outer_stage};
use arithmetic::CurveAffine;
use core::marker::PhantomData;
use ragu_circuits::{
    polynomials::Rank,
    staging::{Stage, StageBuilder, StagedCircuit},
};
use ragu_core::Result;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

inner_stage!(BInnerStage);
outer_stage!(BOuterStage, ());
indirection_stage!(BIndirectionStage);

/// Staged circuit that witnesses the B-stage nested encoding commitment.
#[derive(Clone)]
pub struct BNestedEncodingCircuit<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve> BNestedEncodingCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve: CurveAffine, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for BNestedEncodingCircuit<NestedCurve>
{
    type Final = BOuterStage<NestedCurve, 1>;
    type Instance<'src> = ();
    type Witness<'w> = NestedCurve;
    type Output = Kind![NestedCurve::Base; Point<'_, _, NestedCurve>];
    type Aux<'source> = NestedCurve;

    fn instance<'dr, 'src: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'src>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        unimplemented!()
    }

    fn witness<'a, 'dr, 'w: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'w>>,
    ) -> Result<(
        <Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'w>>,
    )> {
        // Add `BOuterStage` to allocate the commitment point.
        let (b_commitment_vec, dr) =
            dr.add_stage::<BOuterStage<NestedCurve, 1>>(witness.view().map(|&w| [w]))?;
        let b_commitment = b_commitment_vec[0].clone();
        let b_commitment_value = b_commitment.value();
        let _ = dr.finish();

        Ok((b_commitment, b_commitment_value))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ragu_circuits::staging::StageExt;
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq, Pasta};
    type TestRank = ragu_circuits::polynomials::R<10>;

    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{CircuitExt, polynomials::Rank, staging::Staged};
    use ragu_core::Result;
    use rand::thread_rng;

    const NUM: usize = 8;
    type R = ragu_circuits::polynomials::R<10>;

    #[test]
    fn test_b_staging() {
        assert_eq!(
            <BInnerStage<EqAffine, 4> as StageExt<Fq, TestRank>>::num_multiplications(),
            4
        );
        assert_eq!(
            <BOuterStage<EpAffine, 1> as StageExt<Fp, TestRank>>::num_multiplications(),
            1
        );
    }

    #[test]
    fn test_vesta_nested_staging_polynomial() -> Result<()> {
        pub type FpBInnerStage<const NUM: usize> = BInnerStage<EqAffine, NUM>;
        pub type FpBOuterStage = BOuterStage<EpAffine, 1>;
        pub type FpStageingCircuit = BNestedEncodingCircuit<EpAffine>;

        let params = Pasta::default();

        // Allocate Eq points that are non-native in Fp round.
        let eq_points = [(EqAffine::generator() * Fp::random(thread_rng())).to_affine(); NUM];

        // Generate the partial witness polynomial by executing the Fq staging polynomial, and compute a Ep commitment to
        // it outside the circuit.
        let inner_rx_fq = <FpBInnerStage<NUM> as StageExt<Fq, R>>::rx(&eq_points)?;
        let ep_commit = inner_rx_fq.commit(&params.pallas, Fq::random(thread_rng()));

        // The staged circuit allocates the commitment in the circuit.
        let staged_circuit = Staged::<Fp, R, _>::new(FpStageingCircuit::new());
        let (outer_rx, ep_point_value) = staged_circuit.rx::<R>(ep_commit)?;

        assert_eq!(ep_point_value, ep_commit);

        let outer_s = <FpBOuterStage as StageExt<Fp, R>>::final_into_object()?;
        let y = Fp::random(thread_rng());
        let z = Fp::random(thread_rng());

        let mut rhs = outer_rx.clone();
        rhs.dilate(z);
        rhs.add_assign(&outer_s.sy(y));
        rhs.add_assign(&R::tz(z));

        assert_eq!(outer_rx.revdot(&rhs), Fp::ZERO);

        Ok(())
    }

    #[test]
    fn test_pallas_nested_staging_polynomial() -> Result<()> {
        pub type FqBInnerStage<const NUM: usize> = BInnerStage<EpAffine, NUM>;
        pub type FqBOuterStage = BOuterStage<EqAffine, 1>;
        pub type FqStageingCircuit = BNestedEncodingCircuit<EqAffine>;

        const NUM: usize = 8;
        type R = ragu_circuits::polynomials::R<10>;

        let params = Pasta::default();

        // Allocate Eq points that are non-native in Fp round.
        let eq_points = [(EpAffine::generator() * Fq::random(thread_rng())).to_affine(); NUM];

        // Generate the partial witness polynomial by executing the Fq staging polynomial, and compute a Ep commitment to
        // it outside the circuit.
        let inner_rx_fq = <FqBInnerStage<NUM> as StageExt<Fp, R>>::rx(&eq_points)?;
        let ep_commit = inner_rx_fq.commit(&params.vesta, Fp::random(thread_rng()));

        // The staged circuit allocates the commitment in the circuit.
        let staged_circuit = Staged::<Fq, R, _>::new(FqStageingCircuit::new());
        let (outer_rx, ep_point_value) = staged_circuit.rx::<R>(ep_commit)?;

        assert_eq!(ep_point_value, ep_commit);

        let outer_s = <FqBOuterStage as StageExt<Fq, R>>::final_into_object()?;
        let y = Fq::random(thread_rng());
        let z = Fq::random(thread_rng());

        let mut rhs = outer_rx.clone();
        rhs.dilate(z);
        rhs.add_assign(&outer_s.sy(y));
        rhs.add_assign(&R::tz(z));

        assert_eq!(outer_rx.revdot(&rhs), Fq::ZERO);

        Ok(())
    }
}
