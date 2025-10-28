//! D staging polynomial.
//!
//! Hashes a commitment from the host curve to generate a challenge.
//! This doesn't need to be generic because it will always perform
//! a hash over an Fp transcript.
use std::marker::PhantomData;

use arithmetic::CurveAffine;
use ragu_circuits::{
    polynomials::Rank,
    staging::{Stage, StageBuilder, StagedCircuit},
};
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_pasta::{Fp, PoseidonFp};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

use crate::nested_encoding::b_stage::OuterStageB;

pub struct DStage<Curve>(PhantomData<Curve>);

impl<Curve: CurveAffine<Base = Fp>, R: Rank> Stage<Curve::Base, R> for DStage<Curve> {
    type Parent = OuterStageB<Curve>;
    type Witness<'src> = Curve;
    type OutputKind = Kind![Curve::Base; Element<'_, _>];

    fn values() -> usize {
        1
    }

    fn witness<'dr, 'src: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'src>>,
    ) -> Result<<Self::OutputKind as GadgetKind<Curve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = Curve::Base>,
        Self: 'dr,
    {
        let c_b = Point::alloc(dr, witness)?;
        let mut sponge = Sponge::new(dr, &PoseidonFp);
        c_b.write(dr, &mut sponge)?;
        let w = sponge.squeeze(dr)?;

        Ok(w)
    }
}

#[derive(Clone)]
pub struct StagingCircuitD<Curve>(core::marker::PhantomData<Curve>);

impl<Curve> StagingCircuitD<Curve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<Curve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<Curve::Base, R>
    for StagingCircuitD<Curve>
{
    type Final = DStage<Curve>;
    type Instance<'src> = ();
    type Witness<'w> = Curve;
    type Output = Kind![Curve::Base; Element<'_, _>];
    type Aux<'source> = Curve::Base;

    fn instance<'dr, 'src: 'dr, D: Driver<'dr, F = Curve::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'src>>,
    ) -> Result<<Self::Output as GadgetKind<Curve::Base>>::Rebind<'dr, D>> {
        todo!()
    }

    fn witness<'a, 'dr, 'w: 'dr, D: Driver<'dr, F = Curve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'w>>,
    ) -> Result<(
        <Self::Output as GadgetKind<Curve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'w>>,
    )> {
        let (c_b_point, dr) = dr.add_stage::<OuterStageB<Curve>>(witness)?;

        let c_b_value = c_b_point.value();
        let (w_challenge, dr) = dr.add_stage::<DStage<Curve>>(c_b_value)?;
        let _dr = dr.finish();

        let w_aux = w_challenge.value().map(|v| *v);
        Ok((w_challenge, w_aux))
    }
}
