//! G staging polynomial.

use crate::{
    ephemeral_stage, indirection_stage,
    staging::instance::{UnifiedRecursionInstance, UnifiedRecursionOutput},
};
use arithmetic::CurveAffine;
use core::marker::PhantomData;
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

///////////////////////////////////////////////////////////////////////////////////////
// G STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

pub const NUM_FINAL_EVALS: usize = 16;
pub const NUM_V_QUERIES: usize = 18;

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageG);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageG);

// G Stage.
#[derive(ragu_macros::Gadget)]
pub struct GStageOutput<
    'dr,
    D: Driver<'dr>,
    HostCurve: CurveAffine<Base = D::F>,
    const NUM_FINAL_EVALS: usize,
> {
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<2>>,
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<1>>,
    #[ragu(gadget)]
    pub evaluations: FixedVec<Element<'dr, D>, ConstLen<NUM_FINAL_EVALS>>,
}

/// G Stage: challenges (mu, nu, x), nested commitments (A and B, S), and evaluations.
pub struct GStage<HostCurve, const NUM_FINAL_EVALS: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM_FINAL_EVALS: usize> Stage<<HostCurve>::Base, R>
    for GStage<HostCurve, NUM_FINAL_EVALS>
{
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 2],
        [HostCurve; 1],
        [<HostCurve>::Base; NUM_FINAL_EVALS],
    );

    type OutputKind = Kind![<HostCurve>::Base; GStageOutput<'_, _, HostCurve, NUM_FINAL_EVALS>];

    fn values() -> usize {
        2 + 2 + NUM_FINAL_EVALS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the challenges (alpha, u, beta).
        let mut challenges = Vec::with_capacity(3);
        for i in 0..2 {
            challenges.push(Element::alloc(dr, witness.view().map(|w| w.0[i]))?);
        }
        let challenges = FixedVec::new(challenges).expect("challenges length");

        // Allocate the nested commitments (e3 nested commitment).
        let mut nested_commitments = Vec::with_capacity(2);
        for i in 0..1 {
            nested_commitments.push(Point::alloc(dr, witness.view().map(|w| w.1[i]))?);
        }
        let nested_commitments =
            FixedVec::new(nested_commitments).expect("nested commitments length");

        // Allocate the final (evals') evaluations.
        let mut evaluations = Vec::with_capacity(NUM_FINAL_EVALS);
        for i in 0..NUM_FINAL_EVALS {
            evaluations.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let evaluations = FixedVec::new(evaluations).expect("error terms length");

        Ok(GStageOutput {
            challenges,
            nested_commitments,
            evaluations,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////////////
// KY STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// K Stage.
#[derive(ragu_macros::Gadget)]
pub struct KYStageOutput<'dr, D: Driver<'dr>, const TOTAL_KY_COEFFS: usize> {
    #[ragu(gadget)]
    pub ky_coefficients: FixedVec<Element<'dr, D>, ConstLen<TOTAL_KY_COEFFS>>,
}

/// KY Stage: staging polynomial containing all ky coefficient data.
pub struct KYStage<HostCurve, const TOTAL_KY_COEFFS: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const TOTAL_KY_COEFFS: usize> Stage<<HostCurve>::Base, R>
    for KYStage<HostCurve, TOTAL_KY_COEFFS>
{
    type Parent = ();

    type Witness<'source> = [<HostCurve>::Base; TOTAL_KY_COEFFS];

    type OutputKind = Kind![<HostCurve>::Base; KYStageOutput<'_, _, TOTAL_KY_COEFFS>];

    fn values() -> usize {
        TOTAL_KY_COEFFS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the ky coefficients.
        let mut ky_coefficients = Vec::with_capacity(TOTAL_KY_COEFFS);
        for i in 0..TOTAL_KY_COEFFS {
            ky_coefficients.push(Element::alloc(dr, witness.view().map(|w| w[i]))?);
        }
        let ky_coefficients = FixedVec::new(ky_coefficients).expect("ky coefficients length");

        Ok(KYStageOutput { ky_coefficients })
    }
}

///////////////////////////////////////////////////////////////////////////////////////
// STAGED CIRCUIT: `GVComputationStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

pub struct GVComputationStagedWitness<C: CurveAffine> {
    // Other input.
    pub evals: [C::Base; NUM_FINAL_EVALS],
    pub eval_points: [C::Base; NUM_V_QUERIES],
    pub intermediate_evals: [C::Base; NUM_V_QUERIES],
    pub final_evals_for_queries: [C::Base; NUM_V_QUERIES],
    pub inverses: [C::Base; NUM_V_QUERIES],

    pub w_challenge: C::Base,
    pub y_challenge: C::Base,
    pub z_challenge: C::Base,
    pub mu_challenge: C::Base,
    pub nu_challenge: C::Base,
    pub x_challenge: C::Base,
    pub alpha_challenge: C::Base,
    pub u_challenge: C::Base,
    pub b_challenge: C::Base,

    pub b_staging_nested_commitment: C,
    pub d1_nested_commitment: C,
    pub d2_nested_commitment: C,
    pub d_staging_nested_commitment: C,
    pub e1_nested_commitment: C,
    pub e2_nested_commitment: C,
    pub e_staging_nested_commitment: C,
    pub g1_nested_commitment: C,
    pub g_staging_nested_commitment: C,
    pub p_nested_commitment: C,

    pub c: C::Base,
    pub v: C::Base,
}

#[derive(Clone)]
pub struct GVComputationStagedCircuit<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve> GVComputationStagedCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for GVComputationStagedCircuit<NestedCurve>
{
    type Final = GStage<NestedCurve, NUM_FINAL_EVALS>;
    type Instance<'src> = UnifiedRecursionInstance<NestedCurve>;
    type Witness<'w> = GVComputationStagedWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; UnifiedRecursionOutput<'_, _, NestedCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        // Allocate all challenges from unified instance.
        let w_challenge = Element::alloc(dr, instance.view().map(|i| i.w_challenge))?;
        let y_challenge = Element::alloc(dr, instance.view().map(|i| i.y_challenge))?;
        let z_challenge = Element::alloc(dr, instance.view().map(|i| i.z_challenge))?;
        let mu_challenge = Element::alloc(dr, instance.view().map(|i| i.mu_challenge))?;
        let nu_challenge = Element::alloc(dr, instance.view().map(|i| i.nu_challenge))?;
        let x_challenge = Element::alloc(dr, instance.view().map(|i| i.x_challenge))?;
        let alpha_challenge = Element::alloc(dr, instance.view().map(|i| i.alpha_challenge))?;
        let u_challenge = Element::alloc(dr, instance.view().map(|i| i.u_challenge))?;
        let b_challenge = Element::alloc(dr, instance.view().map(|i| i.b_challenge))?;

        // Allocate all nested commitments from unified instance.
        let b_staging_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.b_staging_nested_commitment))?;
        let d1_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.d1_nested_commitment))?;
        let d2_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.d2_nested_commitment))?;
        let d_staging_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.d_staging_nested_commitment))?;
        let e1_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.e1_nested_commitment))?;
        let e2_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.e2_nested_commitment))?;
        let e_staging_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.e_staging_nested_commitment))?;
        let g1_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.g1_nested_commitment))?;
        let g_staging_nested_commitment =
            Point::alloc(dr, instance.view().map(|i| i.g_staging_nested_commitment))?;
        let p_nested_commitment = Point::alloc(dr, instance.view().map(|i| i.p_nested_commitment))?;

        // Allocate computed values from unified instance.
        let c = Element::alloc(dr, instance.view().map(|i| i.c))?;
        let v = Element::alloc(dr, instance.view().map(|i| i.v))?;

        Ok(UnifiedRecursionOutput {
            w_challenge,
            y_challenge,
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
            d_staging_nested_commitment,
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment,
            g1_nested_commitment,
            g_staging_nested_commitment,
            p_nested_commitment,
            c,
            v,
        })
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        // STAGE: StageBuilder for `DStage`: challenges (w, y, z), nested commitments (D1, D2), and error terms.
        let (stage_output, dr) =
            dr.add_stage::<GStage<NestedCurve, NUM_FINAL_EVALS>>(witness.view().map(|w| {
                (
                    [w.alpha_challenge, w.u_challenge],
                    [w.e_staging_nested_commitment],
                    w.evals,
                )
            }))?;

        let dr = dr.finish();

        let alpha_challenge = stage_output.challenges[0].clone();
        let u_challenge = stage_output.challenges[1].clone();
        let e_nested_commitment = stage_output.nested_commitments[0].clone();

        // Initialize a sponge for FS challenge derivation.
        // Sponge has state size 5 and rate 4 (can output 4 challenges per absorption).
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive alpha from e_nested_commitment.
        e_nested_commitment.write(dr, &mut sponge)?;

        let alpha_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(alpha_computed.wire(), alpha_challenge.wire())?;

        let u_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(u_computed.wire(), u_challenge.wire())?;

        // Compute V in-circuit using witnessed inverses.
        let mut v = Element::zero(dr);

        for i in 0..NUM_V_QUERIES {
            // Allocate evaluation data.
            let point = Element::alloc(dr, witness.view().map(|w| w.eval_points[i]))?;
            let eval = Element::alloc(dr, witness.view().map(|w| w.intermediate_evals[i]))?;
            let eval_prime =
                Element::alloc(dr, witness.view().map(|w| w.final_evals_for_queries[i]))?;

            // Witness the inverse (u - point)^-1.
            let inv = Element::alloc(dr, witness.view().map(|w| w.inverses[i]))?;

            // Verify it's the inverse: (u - point) * inv == 1.
            let diff = u_challenge.sub(dr, &point);
            let product = diff.mul(dr, &inv)?;
            let one = Element::constant(dr, Fp::one());
            dr.enforce_equal(product.wire(), one.wire())?;

            // Compute v = v * alpha + inv * (eval' - eval).
            v = v.mul(dr, &alpha_challenge)?;
            let eval_diff = eval_prime.sub(dr, &eval);
            let term = inv.mul(dr, &eval_diff)?;
            v = v.add(dr, &term);
        }

        // Allocate remaining unified output fields from witness.
        let w_challenge = Element::alloc(dr, witness.view().map(|w| w.w_challenge))?;
        let y_challenge = Element::alloc(dr, witness.view().map(|w| w.y_challenge))?;
        let z_challenge = Element::alloc(dr, witness.view().map(|w| w.z_challenge))?;
        let b_challenge = Element::alloc(dr, witness.view().map(|w| w.b_challenge))?;
        let mu_challenge = Element::alloc(dr, witness.view().map(|w| w.mu_challenge))?;
        let nu_challenge = Element::alloc(dr, witness.view().map(|w| w.nu_challenge))?;
        let x_challenge = Element::alloc(dr, witness.view().map(|w| w.x_challenge))?;

        let b_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.b_staging_nested_commitment))?;
        let d1_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d1_nested_commitment))?;
        let d2_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d2_nested_commitment))?;
        let d_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d_staging_nested_commitment))?;
        let e1_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.e1_nested_commitment))?;
        let e2_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.e2_nested_commitment))?;
        let e_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.e_staging_nested_commitment))?;
        let g1_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.g1_nested_commitment))?;
        let g_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.g_staging_nested_commitment))?;
        let p_nested_commitment = Point::alloc(dr, witness.view().map(|w| w.p_nested_commitment))?;

        let c = Element::alloc(dr, witness.view().map(|w| w.c))?;
        let v = Element::alloc(dr, witness.view().map(|w| w.v))?;

        Ok((
            UnifiedRecursionOutput {
                w_challenge,
                y_challenge,
                z_challenge,
                mu_challenge,
                nu_challenge,
                x_challenge,
                alpha_challenge,
                u_challenge,
                b_challenge,
                b_staging_nested_commitment,
                d1_nested_commitment,
                d2_nested_commitment,
                d_staging_nested_commitment,
                e1_nested_commitment,
                e2_nested_commitment,
                e_staging_nested_commitment,
                g1_nested_commitment,
                g_staging_nested_commitment,
                p_nested_commitment,
                c,
                v,
            },
            D::just(|| ()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{CircuitExt, staging::Staged};
    use ragu_pasta::{EpAffine, Fp, Fq};
    use rand::rngs::OsRng;
    type Rank = ragu_circuits::polynomials::R<12>;

    #[test]
    fn test_g_stage_v_computation_valid() {
        const NUM_QUERIES: usize = 3;

        let alpha_challenge = Fp::random(OsRng);
        let u_challenge = Fp::random(OsRng);
        let b_challenge = Fp::random(OsRng);

        let mut eval_points = [Fp::ZERO; NUM_QUERIES];
        let mut intermediate_evals = [Fp::ZERO; NUM_QUERIES];
        let mut final_evals_for_queries = [Fp::ZERO; NUM_QUERIES];
        let mut inverses = [Fp::ZERO; NUM_QUERIES];

        for i in 0..NUM_QUERIES {
            eval_points[i] = Fp::random(OsRng);
            intermediate_evals[i] = Fp::random(OsRng);
            final_evals_for_queries[i] = Fp::random(OsRng);
            inverses[i] = (u_challenge - eval_points[i]).invert().unwrap();
        }

        let mut v_computed = Fp::ZERO;
        for i in 0..NUM_QUERIES {
            v_computed *= alpha_challenge;
            let eval_diff = final_evals_for_queries[i] - intermediate_evals[i];
            v_computed += inverses[i] * eval_diff;
        }

        let mut final_evals = [Fp::ZERO; NUM_FINAL_EVALS];
        for i in 0..NUM_FINAL_EVALS {
            final_evals[i] = Fp::random(OsRng);
        }

        let mut eval_points_padded = [Fp::ZERO; NUM_V_QUERIES];
        let mut intermediate_evals_padded = [Fp::ZERO; NUM_V_QUERIES];
        let mut final_evals_padded = [Fp::ZERO; NUM_V_QUERIES];
        let mut inverses_padded = [Fp::ONE; NUM_V_QUERIES];

        eval_points_padded[..NUM_QUERIES].copy_from_slice(&eval_points);
        intermediate_evals_padded[..NUM_QUERIES].copy_from_slice(&intermediate_evals);
        final_evals_padded[..NUM_QUERIES].copy_from_slice(&final_evals_for_queries);
        inverses_padded[..NUM_QUERIES].copy_from_slice(&inverses);

        for i in NUM_QUERIES..NUM_V_QUERIES {
            eval_points_padded[i] = u_challenge;
            intermediate_evals_padded[i] = Fp::ZERO;
            final_evals_padded[i] = Fp::ZERO;
        }

        let witness = GVComputationStagedWitness {
            evals: final_evals,
            eval_points: eval_points_padded,
            intermediate_evals: intermediate_evals_padded,
            final_evals_for_queries: final_evals_padded,
            inverses: inverses_padded,
            w_challenge: Fp::random(&mut OsRng),
            y_challenge: Fp::random(&mut OsRng),
            z_challenge: Fp::random(&mut OsRng),
            mu_challenge: Fp::random(&mut OsRng),
            nu_challenge: Fp::random(&mut OsRng),
            x_challenge: Fp::random(&mut OsRng),
            alpha_challenge,
            u_challenge,
            b_challenge,
            b_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            d1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d2_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            e1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            e2_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            e_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            g1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            g_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            p_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            c: Fp::random(&mut OsRng),
            v: Fp::random(&mut OsRng),
        };

        let circuit = Staged::<Fp, Rank, _>::new(GVComputationStagedCircuit::<EpAffine>::new());

        let result = circuit.rx::<Rank>(witness);
        assert!(result.is_ok(), "Valid V computation should pass");
    }
}
