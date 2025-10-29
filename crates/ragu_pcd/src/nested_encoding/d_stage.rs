//! D-stage with a composite challenge derivation circuit, which derives the
//! challenges (w, y, z) in a continuous parent chain, using two-layer nested
//! encoding (similiar to stage-b) for commitments.

use arithmetic::CurveAffine;
use ff::PrimeField;
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
use ragu_primitives::{
    Element, GadgetExt, Point, Sponge,
    vec::{ConstLen, FixedVec},
};
use std::marker::PhantomData;

use crate::nested_encoding::b_stage::BOuterStage;

/// D1 Inner Stage: staging polynomial (over `HostCurve::Base`) that witnesses the S' mesh polynomial commitments.
pub struct D1InnerStage<HostCurve, const NUM: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM: usize> Stage<<HostCurve>::Base, R>
    for D1InnerStage<HostCurve, NUM>
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

/// D1 Outer Stage: Witnesses the D1 nested commitment (Pallas point).
pub struct D1OuterStage<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for D1OuterStage<NestedCurve>
{
    type Parent = WChallengeStage<NestedCurve>;

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

/// D2 Inner Stage: staging polynomial (over `HostCurve::Base`) that witnesses the S' mesh polynomial commitments.
pub struct D2InnerStage<HostCurve, const NUM: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM: usize> Stage<<HostCurve>::Base, R>
    for D2InnerStage<HostCurve, NUM>
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

/// D2 Outer Stage: Witnesses the D2 nested commitment (Pallas point).
pub struct D2OuterStage<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for D2OuterStage<NestedCurve>
{
    type Parent = YChallengeStage<NestedCurve>;

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

/// W challenge stage: witnesses the w challenge derived from B nested commitment.
pub struct WChallengeStage<NestedCurve> {
    _marker: core::marker::PhantomData<NestedCurve>,
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for WChallengeStage<NestedCurve>
{
    type Parent = BOuterStage<NestedCurve>;
    type Witness<'source> = NestedCurve::Base;
    type OutputKind = Kind![NestedCurve::Base; Element<'_, _>];

    fn values() -> usize {
        1
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = NestedCurve::Base>,
        Self: 'dr,
    {
        Element::alloc(dr, witness)
    }
}

/// Y challenge stage: witnesses the y challenge derived from D1 nested commitment.
pub struct YChallengeStage<NestedCurve> {
    _marker: core::marker::PhantomData<NestedCurve>,
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for YChallengeStage<NestedCurve>
{
    type Parent = D1OuterStage<NestedCurve>;
    type Witness<'source> = NestedCurve::Base;
    type OutputKind = Kind![NestedCurve::Base; Element<'_, _>];

    fn values() -> usize {
        1
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = NestedCurve::Base>,
        Self: 'dr,
    {
        Element::alloc(dr, witness)
    }
}

/// Z challenge stage: witnesses the z challenge derived from D2 nested commitment.
pub struct ZChallengeStage<NestedCurve> {
    _marker: core::marker::PhantomData<NestedCurve>,
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for ZChallengeStage<NestedCurve>
{
    type Parent = D2OuterStage<NestedCurve>;
    type Witness<'source> = NestedCurve::Base;
    type OutputKind = Kind![NestedCurve::Base; Element<'_, _>];

    fn values() -> usize {
        1
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = NestedCurve::Base>,
        Self: 'dr,
    {
        Element::alloc(dr, witness)
    }
}

/// Composite circuit: witness data for the composite challenge derivation circuit.
/// The commitments here are nested commitments (Pallas points), representing
/// outputs of the two-layer nested encoding process.
pub struct CompositeChallengeWitness<C: CurveAffine> {
    pub b_nested_commitment: C,
    pub d1_nested_commitment: C,
    pub d2_nested_commitment: C,
}

/// Output struct containing all intermediate commitments and challenges.
#[derive(ragu_macros::Gadget, ragu_primitives::io::Write)]
pub struct CompositeOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub b_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub w_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub d1_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub y_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub d2_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub z_challenge: Element<'dr, D>,
}

/// Auxiliary output containing the derived challenges.
pub struct CompositeChallengeAux<F: PrimeField> {
    pub w_challenge: F,
    pub y_challenge: F,
    pub z_challenge: F,
}

#[derive(Clone)]
pub struct ChallengeCompositeCircuit<NestedCurve>(core::marker::PhantomData<NestedCurve>);

impl<NestedCurve> ChallengeCompositeCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for ChallengeCompositeCircuit<NestedCurve>
{
    type Final = ZChallengeStage<NestedCurve>;
    type Instance<'src> = ();
    type Witness<'w> = CompositeChallengeWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; CompositeOutput<'_, _, NestedCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        unimplemented!()
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        // STAGE 1: StageBuilder for `BOuterStage` to allocate B nested commitment.
        let (b_commitment, dr) = dr
            .add_stage::<BOuterStage<NestedCurve>>(witness.view().map(|w| w.b_nested_commitment))?;

        // Extract value for off-circuit w computation.
        let b_value = b_commitment.value();
        let w_value = b_value.map(|b| {
            let coords = b.coordinates().unwrap();
            *coords.x()
        });

        // STAGE 2: StageBuilder for `WChallengeStage` for computed w value.
        let (w_challenge, dr) = dr.add_stage::<WChallengeStage<NestedCurve>>(w_value)?;

        // STAGE 3: StageBuilder for `D1OuterStage` to allocate D1 nested commitment.
        let (d1_commitment, dr) = dr.add_stage::<D1OuterStage<NestedCurve>>(
            witness.view().map(|w| w.d1_nested_commitment),
        )?;

        // Extract value for off-circuit y computation.
        let d1_value = d1_commitment.value();
        let y_value = d1_value.map(|d1| {
            let coords = d1.coordinates().unwrap();
            *coords.x()
        });

        // STAGE 4: StageBuilder for `YChallengeStage` for computed y value.
        let (y_challenge, dr) = dr.add_stage::<YChallengeStage<NestedCurve>>(y_value)?;

        // STAGE 5: StageBuilder for `D2OuterStage` to allocate D2 nested commitment.
        let (d2_commitment, dr) = dr.add_stage::<D2OuterStage<NestedCurve>>(
            witness.view().map(|w| w.d2_nested_commitment),
        )?;

        // Extract value for off-circuit z computation.
        let d2_value = d2_commitment.value();
        let z_value = d2_value.map(|d2| {
            let coords = d2.coordinates().unwrap();
            *coords.x()
        });

        // STAGE 5: StageBuilder for `ZChallengeStage` for computed z value.
        let (z_challenge, dr) = dr.add_stage::<ZChallengeStage<NestedCurve>>(z_value)?;

        let dr = dr.finish();

        // Verify w = Poseidon(B).
        let mut sponge_w = Sponge::new(dr, &PoseidonFp);
        b_commitment.write(dr, &mut sponge_w)?;
        let w_computed = sponge_w.squeeze(dr)?;
        dr.enforce_equal(w_computed.wire(), w_challenge.wire())?;

        // Verify y = Poseidon(D1_nested).
        let mut sponge_y = Sponge::new(dr, &PoseidonFp);
        d1_commitment.write(dr, &mut sponge_y)?;
        let y_computed = sponge_y.squeeze(dr)?;
        dr.enforce_equal(y_computed.wire(), y_challenge.wire())?;

        // Verify z = Poseidon(D2_nested).
        let mut sponge_z = Sponge::new(dr, &PoseidonFp);
        d2_commitment.write(dr, &mut sponge_z)?;
        let z_computed = sponge_z.squeeze(dr)?;
        dr.enforce_equal(z_computed.wire(), z_challenge.wire())?;

        // Return output gadgets and empty auxilary.
        let output = CompositeOutput {
            b_commitment,
            w_challenge: w_challenge.clone(),
            d1_commitment,
            y_challenge: y_challenge.clone(),
            d2_commitment,
            z_challenge: z_challenge.clone(),
        };

        Ok((output, D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::CircuitExt;
    use ragu_circuits::staging::StageExt;
    use ragu_circuits::staging::{Stage, Staged};
    use ragu_pasta::{EpAffine, Fp, Fq};
    use rand::thread_rng;
    type Rank = ragu_circuits::polynomials::R<12>;

    #[test]
    fn test_parent_chain_multiplications_skipped() -> Result<()> {
        let b_nested_commitment = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();

        let witness = CompositeChallengeWitness {
            b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
        };

        let circuit = ChallengeCompositeCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);

        let (rx, _aux) = staged.rx::<Rank>(witness)?;
        assert!(
            rx.iter_coeffs().count() > 0,
            "Staging should produce a non-empty polynomial"
        );

        let z_skip = <ZChallengeStage<EpAffine> as Stage<Fp, Rank>>::skip_multiplications();

        let b_muls = <BOuterStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let w_muls = <WChallengeStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let d1_muls = <D1OuterStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let y_muls = <YChallengeStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let d2_muls = <D2OuterStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let expected_skip = b_muls + w_muls + d1_muls + y_muls + d2_muls;

        assert_eq!(
            z_skip, expected_skip,
            "skip_multiplications() should equal the sum of all parent stages' multiplications"
        );

        Ok(())
    }
}
