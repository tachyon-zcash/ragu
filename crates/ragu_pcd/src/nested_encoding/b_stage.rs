//! B staging polynomial.
//!
//! Generic deferred staging that works for both Fp and Fq sides.
//!
//! It's constructed to be generic over the staged curve and circuit field,
//! allowing you to reuse `InnerStage`, `OuterStage`, and `StagingCircuit`
//! for both sides of the cycle.

use std::marker::PhantomData;

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
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

/// Generic inner stage: allocates points from the nested curve using its native field.
///
/// - In the Fp round: uses Vesta (EqAffine) points, which are defined over Fq.
/// - In the Fq round: uses Pallas (EpAffine) points, which are defined over Fp.
pub struct InnerStage<NestedCurve, const NUM: usize> {
    _marker: core::marker::PhantomData<NestedCurve>,
}

impl<NestedCurve, R, const NUM: usize> Stage<<NestedCurve>::Base, R>
    for InnerStage<NestedCurve, NUM>
where
    NestedCurve: CurveAffine,
    <NestedCurve>::Base: PrimeField,
    R: Rank,
{
    type Parent = ();
    type Witness<'source> = &'source [NestedCurve; NUM];

    type OutputKind = Kind![<NestedCurve>::Base;
              FixedVec<Point<'_, _, NestedCurve>, ConstLen<NUM>>];

    fn values() -> usize {
        NUM * 2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<NestedCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <NestedCurve>::Base>,
        Self: 'dr,
    {
        let mut v = Vec::with_capacity(NUM);
        for i in 0..NUM {
            v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        Ok(FixedVec::new(v).expect("output"))
    }
}

/// Outer stage: allocates the host curve commitment using its native base field.
pub struct OuterStage<HostCurve>(PhantomData<HostCurve>);

impl<HostCurve, R> Stage<HostCurve::Base, R> for OuterStage<HostCurve>
where
    HostCurve: CurveAffine,
    <HostCurve>::Base: PrimeField,
    R: Rank,
{
    type Parent = ();

    type Witness<'source> = HostCurve;

    type OutputKind = Kind![HostCurve::Base; Point<'_, _, HostCurve>];

    fn values() -> usize {
        2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<HostCurve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = HostCurve::Base>,
        Self: 'dr,
    {
        Point::alloc(dr, witness)
    }
}

#[derive(Clone)]
pub struct StagingCircuit<HostCurve>(core::marker::PhantomData<HostCurve>);

impl<HostCurve> StagingCircuit<HostCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<HostCurve, R> StagedCircuit<HostCurve::Base, R> for StagingCircuit<HostCurve>
where
    HostCurve: arithmetic::CurveAffine,
    R: Rank,
{
    type Final = OuterStage<HostCurve>;
    type Instance<'src> = ();
    type Witness<'w> = HostCurve;
    type Output = Kind![HostCurve::Base; Point<'_, _, HostCurve>];
    type Aux<'source> = HostCurve;

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
        let (ep_point_gadget, dr) = dr.add_stage::<OuterStage<HostCurve>>(witness)?;
        let dr = dr.finish();
        let ep_value = ep_point_gadget.value();

        Ok((ep_point_gadget, ep_value))
    }
}
