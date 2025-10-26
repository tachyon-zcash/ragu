//! New non-native R values (Vesta / EqAffine curve points) produced in this Fp round
//! are deferred through nested staging polynomials.
//!
//! We defer them via a two-stage process:
//!     1. Inner (Fq) stage: allocate Eq points natively and form the staging polynomial `r(X)`,
//!     2. Off-circuit commitment: commit `r(X)` using Pallas generators,
//!     3. Outer (Fp) stage: stage the Ep commitment inside the Fp circuit in this round.

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
use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

/// Inner (Fq) stage that allocates Vesta (Eq) points natively within the Fq circuit.
pub struct NewRInnerStage<const NUM_NEW: usize>;

impl<R: Rank, const NUM_NEW: usize> Stage<Fq, R> for NewRInnerStage<NUM_NEW> {
    type Parent = ();

    type Witness<'source> = &'source [EqAffine; NUM_NEW];

    type OutputKind = Kind![Fq; FixedVec<Point<'_, _, EqAffine>, ConstLen<NUM_NEW>>];

    fn values() -> usize {
        NUM_NEW * 2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fq>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<Fq>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let mut v = Vec::with_capacity(NUM_NEW);
        for i in 0..NUM_NEW {
            v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
        }

        Ok(FixedVec::new(v).expect("output"))
    }
}

/// Outer (Fp) stage that stages the native Ep commitment, corresponding to an off-circuit
/// commitment of the inner Fq stage’s deferred values. This achieves the nesting between
/// them.
pub struct NewROuterStage;

impl<R: Rank> Stage<Fp, R> for NewROuterStage {
    type Parent = ();

    type Witness<'source> = EpAffine;

    type OutputKind = Kind![Fp; Point<'_, _, EpAffine>];

    fn values() -> usize {
        2
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<Fp>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Point::alloc(dr, witness)
    }
}

#[derive(Clone)]
struct OuterCarrierCircuit;

impl<R: Rank> StagedCircuit<Fp, R> for OuterCarrierCircuit {
    type Final = NewROuterStage;
    type Instance<'src> = ();
    type Witness<'w> = EpAffine;
    type Output = Kind![Fp; Point<'_, _, EpAffine>];
    type Aux<'source> = EpAffine;

    fn instance<'dr, 'src: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'src>>,
    ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
        todo!()
    }

    fn witness<'a, 'dr, 'w: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'w>>,
    ) -> Result<(
        <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'w>>,
    )> {
        let (ep_point_gadget, dr) = dr.add_stage::<NewROuterStage>(witness)?;
        let dr = dr.finish();
        let ep_value = ep_point_gadget.value();

        Ok((ep_point_gadget, ep_value))
    }
}

#[cfg(test)]
mod tests {
    use crate::staging::fp::deferreds::{NewRInnerStage, NewROuterStage, OuterCarrierCircuit};
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{
        CircuitExt,
        polynomials::Rank,
        staging::{StageExt, Staged},
    };
    use ragu_core::Result;
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

        // Inner Fq staging polynomial and Ep commitment outside the circuit

        // Generate the partial witness polynomial by executing the Fq staging polynomial, and compute a Ep commitment to
        // it outside the circuit.
        let inner_rx_fq = <NewRInnerStage<NUM> as StageExt<Fq, R>>::rx(&eq_points)?;
        let ep_commit = inner_rx_fq.commit(&params.pallas, Fq::random(thread_rng()));

        // The staged circuit allocates the commitment in the circuit.
        let staged_circuit = Staged::<Fp, R, _>::new(OuterCarrierCircuit);
        let (outer_rx, ep_point_value) = staged_circuit.rx::<R>(ep_commit)?;

        assert_eq!(ep_point_value, ep_commit);

        let outer_s = <NewROuterStage as StageExt<Fp, R>>::final_into_object()?;
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
