//! E-stage with a composite challenge derivation circuit, which derives the
//! challenges (mu and nu), and computes C in a continuous parent chain.

use arithmetic::CurveAffine;
use ragu_circuits::{
    polynomials::Rank,
    staging::Stage,
};
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_primitives::{
    Element, GadgetExt, Point, Sponge,
    vec::{ConstLen, FixedVec},
};

/// E1 Inner Stage: staging polynomial (over `HostCurve::Base`) that witnesses the S mesh polynomial commitments.
pub struct E1InnerStage<HostCurve, const NUM: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM: usize> Stage<<HostCurve>::Base, R>
    for E1InnerStage<HostCurve, NUM>
{
    type Parent = ();
    type Witness<'source> = &'source [HostCurve; NUM];
    type OutputKind = Kind![<HostCurve>::Base;
              FixedVec<Point<'_, _, HostCurve>, ConstLen<NUM>>];

    fn values() -> usize {
        NUM * 2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate each commitment point.
        let mut v = Vec::with_capacity(NUM);
        for i in 0..NUM {
            v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        Ok(FixedVec::new(v).expect("length"))
    }
}

/// E2 Inner Stage: staging polynomial (over `HostCurve::Base`) that witnesses the S mesh polynomial commitments.
pub struct E2InnerStage<HostCurve, const NUM: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM: usize> Stage<<HostCurve>::Base, R>
    for E2InnerStage<HostCurve, NUM>
{
    type Parent = ();
    type Witness<'source> = &'source [HostCurve; NUM];
    type OutputKind = Kind![<HostCurve>::Base;
              FixedVec<Point<'_, _, HostCurve>, ConstLen<NUM>>];

    fn values() -> usize {
        NUM * 2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate each commitment point.
        let mut v = Vec::with_capacity(NUM);
        for i in 0..NUM {
            v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        Ok(FixedVec::new(v).expect("length"))
    }
}
