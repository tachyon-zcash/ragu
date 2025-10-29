//! B-stage with a generic, two-layer nested encoding structure. Nested encoding
//! solves the issue of witnessing data from one curve inside a circuit
//! over a different curve, for instance Fq elements inside an Fp circuit.
//!
//! If you have for instance N polynomials over Fp, where the host curve is Vesta,
//! and you want to a succinct, in-circuit representation of those polynomials that
//! you can use to say derive a challenge, then nested encoding can be used to
//! implement a two-layer flow for doing that:
//!
//!     * Inner-stage: commit to the N polynomials using Vesta and construct a staging
//!     polynomial (over Fq) that witnesses those Vesta commitments,
//!         
//!     * Off-circuit: commit to the staging polynomial using Pallas generators.
//!
//!     * Outer-stage: allocate the commitment which can be used across staged circuits.
//!
//! Imprtantly, we can't form a connection between the inner and outer stages due to
//! the field boundary constraint in the `Stage` trait that disallowes stages from
//! building stages that aren't in the same curve. That's why the inner stage acts as
//! an interstitial, temporary stage that we use to construct the commitment, and
//! then we can form an outer stage from which subsequent stages can be built on.

use arithmetic::CurveAffine;
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
use std::marker::PhantomData;

/// Inner stage: allocates `HostCurve` commitment points, using `HostCurve::Base`
/// as the circuit’s native base field.
///
/// * Fp round: caller parameterizes using `Curve = C::HostCurve` (Vesta)
/// * Fq round: caller parameterizes using `Curve = C::NestedCurve` (Pallas)
pub struct BInnerStage<HostCurve, const NUM: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM: usize> Stage<<HostCurve>::Base, R>
    for BInnerStage<HostCurve, NUM>
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

/// Outer stage: Allocates `NestedCurve` commitment points, using `NestedCurve::Base`
/// as the circuit’s base native field. This has the opposite parameterization to the
/// inner stage.
///
/// * Fp round: caller parameterizes using `Curve = C::NestedCurve` (Pallas)
/// * Fq round: caller parameterizes using `Curve = C::HostCurve` (Vesta)
pub struct BOuterStage<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve: CurveAffine, R: Rank> Stage<NestedCurve::Base, R> for BOuterStage<NestedCurve> {
    type Parent = ();

    type Witness<'source> = NestedCurve;

    type OutputKind = Kind![NestedCurve::Base; Point<'_, _, NestedCurve>];

    fn values() -> usize {
        2
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = NestedCurve::Base>,
        Self: 'dr,
    {
        // Allocate the commitment point.
        Point::alloc(dr, witness)
    }
}

/// Staged circuit that witnesses the B-stage nested encoding commitment.
#[derive(Clone)]
pub struct BNestedEncodingCircuit<NestedCurve>(core::marker::PhantomData<NestedCurve>);

impl<NestedCurve> BNestedEncodingCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<NestedCurve: CurveAffine, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for BNestedEncodingCircuit<NestedCurve>
{
    type Final = BOuterStage<NestedCurve>;
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
        let (b_commitment, dr) = dr.add_stage::<BOuterStage<NestedCurve>>(witness)?;
        let b_commitment_value = b_commitment.value();
        let _ = dr.finish();

        Ok((b_commitment, b_commitment_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_circuits::staging::StageExt;
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};
    type TestRank = ragu_circuits::polynomials::R<10>;

    #[test]
    fn test_b_staging() {
        assert_eq!(
            <BInnerStage<EqAffine, 4> as StageExt<Fq, TestRank>>::num_multiplications(),
            4
        );
        assert_eq!(
            <BOuterStage<EpAffine> as StageExt<Fp, TestRank>>::num_multiplications(),
            1
        );
    }
}
