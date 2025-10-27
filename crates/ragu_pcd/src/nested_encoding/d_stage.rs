//! D staging polynomial.
//!
//! Generic deferred staging that works for both Fp and Fq sides.
//!
//! Hashes a commitment from the host curve to generate a challenge.

use std::marker::PhantomData;

use crate::nested_encoding::b_stage::OuterStage as OuterStageB;
use arithmetic::CurveAffine;
use ff::PrimeField;
use ragu_circuits::{
    polynomials::Rank,
    staging::{Stage, StageBuilder, StagedCircuit},
};
use ragu_core::Result;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// D stage: Hashes a commitment to generate a challenge.
/// Generic over the host curve.
pub struct DStage<HostCurve>(PhantomData<HostCurve>);

impl<HostCurve, R> Stage<HostCurve::Base, R> for DStage<HostCurve>
where
    HostCurve: CurveAffine,
    <HostCurve>::Base: PrimeField,
    R: Rank,
{
    type Parent = OuterStageB<HostCurve>;

    type Witness<'source> = HostCurve;

    type OutputKind = Kind![HostCurve::Base; Element<'_, _>];

    fn values() -> usize {
        1
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<HostCurve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = HostCurve::Base>,
        Self: 'dr,
    {
        // Allocate the commitment point
        let c_b = Point::alloc(dr, witness)?;

        // Hash the commitment using Poseidon sponge to generate challenge w
        // TODO: Need to pass Poseidon params generically
        todo!("Need Poseidon params for generic hashing")
    }
}

#[derive(Clone)]
pub struct DStagingCircuit<HostCurve>(core::marker::PhantomData<HostCurve>);

impl<HostCurve> DStagingCircuit<HostCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<HostCurve, R> StagedCircuit<HostCurve::Base, R> for DStagingCircuit<HostCurve>
where
    HostCurve: arithmetic::CurveAffine,
    <HostCurve>::Base: PrimeField,
    R: Rank,
{
    type Final = DStage<HostCurve>;
    type Instance<'src> = ();
    type Witness<'w> = HostCurve;
    type Output = Kind![HostCurve::Base; Element<'_, _>];
    type Aux<'source> = (HostCurve, HostCurve::Base);

    fn instance<'dr, 'src: 'dr, D: Driver<'dr, F = HostCurve::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'src>>,
    ) -> Result<<Self::Output as GadgetKind<HostCurve::Base>>::Rebind<'dr, D>> {
        todo!()
    }

    fn witness<'a, 'dr, 'w: 'dr, D: Driver<'dr, F = HostCurve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'w>>,
    ) -> Result<(
        <Self::Output as GadgetKind<HostCurve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'w>>,
    )> {
        let (c_b_point, dr) = dr.add_stage::<OuterStageB<HostCurve>>(witness)?;

        let c_b_value = c_b_point.value();
        let (w_output, dr) = dr.add_stage::<DStage<HostCurve>>(c_b_value)?;
        let dr = dr.finish();

        todo!()
    }
}
