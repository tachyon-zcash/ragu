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

/// Inner stage: Allocates commitment points on an arbitrary `Curve`, using `Curve::Base`
/// as the circuit’s native field.
///
/// * Fp round: caller parameterizes using `Curve = C::HostCurve` (Vesta)
/// * Fq round: caller parameterizes using `Curve = C::NestedCurve` (Pallas)
pub struct InnerStageB<Curve, const NUM: usize> {
    _marker: core::marker::PhantomData<Curve>,
}

impl<Curve, R, const NUM: usize> Stage<<Curve>::Base, R> for InnerStageB<Curve, NUM>
where
    Curve: CurveAffine,
    <Curve>::Base: PrimeField,
    R: Rank,
{
    type Parent = ();
    type Witness<'source> = &'source [Curve; NUM];

    type OutputKind = Kind![<Curve>::Base;
              FixedVec<Point<'_, _, Curve>, ConstLen<NUM>>];

    fn values() -> usize {
        NUM * 2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<Curve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <Curve>::Base>,
        Self: 'dr,
    {
        let mut v = Vec::with_capacity(NUM);
        for i in 0..NUM {
            v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        Ok(FixedVec::new(v).expect("output"))
    }
}

/// Outer stage: Allocates commitment points on an arbitrary `Curve`, using `Curve::Base`
/// as the circuit’s native field. This has the opposite parameterization to the inner stage
/// by design.
///
/// * Fp round: caller parameterizes using `Curve = C::NestedCurve` (Pallas)
/// * Fq round: caller parameterizes using `Curve = C::HostCurve` (Vesta)
///
/// /// Allocates a commitment point on an arbitrary `Curve`, with the circuit
/// field = `Curve::Base`.
///
/// In the Fp round, set `Curve = C::NestedCurve` (Pallas), so the gadget is a
/// Pallas point allocated over Fp. In the Fq round, set `Curve = C::NestedCurve`
/// (Vesta), allocated over Fq.

pub struct OuterStageB<Curve>(PhantomData<Curve>);

impl<Curve, R> Stage<Curve::Base, R> for OuterStageB<Curve>
where
    Curve: CurveAffine,
    <Curve>::Base: PrimeField,
    R: Rank,
{
    type Parent = ();

    type Witness<'source> = Curve;

    type OutputKind = Kind![Curve::Base; Point<'_, _, Curve>];

    fn values() -> usize {
        2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<Curve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = Curve::Base>,
        Self: 'dr,
    {
        Point::alloc(dr, witness)
    }
}

/// /// Staging circuit that witnesses a commitment point on `Curve` inside a circuit
/// over `Curve::Base`. Typically `Curve = C::NestedCurve` in the current round.
#[derive(Clone)]
pub struct StagingCircuitB<Curve>(core::marker::PhantomData<Curve>);

impl<Curve> StagingCircuitB<Curve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<Curve, R> StagedCircuit<Curve::Base, R> for StagingCircuitB<Curve>
where
    Curve: arithmetic::CurveAffine,
    R: Rank,
{
    type Final = OuterStageB<Curve>;
    type Instance<'src> = ();
    type Witness<'w> = Curve;
    type Output = Kind![Curve::Base; Point<'_, _, Curve>];
    type Aux<'source> = Curve;

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
        let (curve_point_gadget, dr) = dr.add_stage::<OuterStageB<Curve>>(witness)?;
        let curve_point_value = curve_point_gadget.value();
        let _ = dr.finish();

        Ok((curve_point_gadget, curve_point_value))
    }
}
