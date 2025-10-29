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
    type Parent = ();
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
pub struct DNestedEncodingWitness<C: CurveAffine> {
    pub b_nested_commitment: C,
    pub w_challenge: C::Base,
    pub d1_nested_commitment: C,
    pub y_challenge: C::Base,
    pub d2_nested_commitment: C,
    pub z_challenge: C::Base,
}

/// Output struct containing all intermediate commitments and challenges.
#[derive(ragu_macros::Gadget, ragu_primitives::io::Write)]
pub struct DNestedEncodingOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub b_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub w_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub d1_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub y_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub d2_nested_commitment: Point<'dr, D, C>,
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
pub struct DNestedEncodingCircuit<NestedCurve>(core::marker::PhantomData<NestedCurve>);

impl<NestedCurve> DNestedEncodingCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for DNestedEncodingCircuit<NestedCurve>
{
    type Final = ZChallengeStage<NestedCurve>;
    type Instance<'src> = ();
    type Witness<'w> = DNestedEncodingWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; DNestedEncodingOutput<'_, _, NestedCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        unimplemented!()

        // TODO: THIS SHOULD TAKE B-COMMITMENT AS A PUBLIC INPUT INTO THE CIRCUIT
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        // STAGE 1: StageBuilder for `WChallengeStage` for computed w value.
        let (w_challenge, dr) =
            dr.add_stage::<WChallengeStage<NestedCurve>>(witness.view().map(|w| w.w_challenge))?;

        // STAGE 3: StageBuilder for `D1OuterStage` to allocate D1 nested commitment.
        let (d1_nested_commitment, dr) = dr.add_stage::<D1OuterStage<NestedCurve>>(
            witness.view().map(|w| w.d1_nested_commitment),
        )?;

        // STAGE 4: StageBuilder for `YChallengeStage` for computed y value.
        let (y_challenge, dr) =
            dr.add_stage::<YChallengeStage<NestedCurve>>(witness.view().map(|w| w.y_challenge))?;

        // STAGE 5: StageBuilder for `D2OuterStage` to allocate D2 nested commitment.
        let (d2_nested_commitment, dr) = dr.add_stage::<D2OuterStage<NestedCurve>>(
            witness.view().map(|w| w.d2_nested_commitment),
        )?;

        // STAGE 5: StageBuilder for `ZChallengeStage` for computed z value.
        let (z_challenge, dr) =
            dr.add_stage::<ZChallengeStage<NestedCurve>>(witness.view().map(|w| w.z_challenge))?;

        let dr = dr.finish();

        // Now allocate `b_commitment` (NOT in the staging polynomial) and verify
        // that w was correctly derived from B. This keeps B and D as separate staging
        // polynomials while still verifying the FS challenge derivation.
        let b_nested_commitment = Point::alloc(dr, witness.view().map(|w| w.b_nested_commitment))?;

        // Initialize a single sponge for FS challenge derivation.
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive w = H(state_0 || B).
        b_nested_commitment.write(dr, &mut sponge)?;
        let w_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(w_computed.wire(), w_challenge.wire())?;

        // Derive y = H(state_1 || D1)  where state_1 contains (B, w).
        d1_nested_commitment.write(dr, &mut sponge)?;
        let y_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(y_computed.wire(), y_challenge.wire())?;

        // Derive z = H(state_2 || D2)  where state_2 contains (B, w, D1, y).
        d2_nested_commitment.write(dr, &mut sponge)?;
        let z_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(z_computed.wire(), z_challenge.wire())?;

        // Return output gadgets and empty auxilary.
        let output = DNestedEncodingOutput {
            b_nested_commitment,
            w_challenge: w_challenge.clone(),
            d1_nested_commitment,
            y_challenge: y_challenge.clone(),
            d2_nested_commitment,
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
        let w_challenge = Fp::random(thread_rng());
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let y_challenge = Fp::random(thread_rng());
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let z_challenge = Fp::random(thread_rng());

        let witness = DNestedEncodingWitness {
            b_nested_commitment,
            w_challenge,
            d1_nested_commitment,
            y_challenge,
            d2_nested_commitment,
            z_challenge,
        };

        let circuit = DNestedEncodingCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness)?;

        assert!(
            rx.iter_coeffs().count() > 0,
            "Staging should produce a non-empty polynomial"
        );

        let w_muls = <WChallengeStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let d1_muls = <D1OuterStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let y_muls = <YChallengeStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let d2_muls = <D2OuterStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let expected_skip = w_muls + d1_muls + y_muls + d2_muls;

        let z_skip = <ZChallengeStage<EpAffine> as Stage<Fp, Rank>>::skip_multiplications();

        assert_eq!(
            z_skip, expected_skip,
            "skip_multiplications() should equal the sum of all parent stages' multiplications"
        );

        Ok(())
    }
}
