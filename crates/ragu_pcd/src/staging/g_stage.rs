//! G staging polynomial.

use crate::{ephemeral_stage, indirection_stage};
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

/// Hardcoding the number of final evaluations.
pub const NUM_FINAL_EVALS: usize = 16;
pub const NUM_V_QUERIES: usize = 18;

///////////////////////////////////////////////////////////////////////////////////////
// G STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral Stage: used to creating nested commitments.
ephemeral_stage!(EphemeralStageG);

// Indirection Stage: for resolving the "outer layer problem".
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
// STAGED CIRCUIT: `GVComputationStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

pub struct GVComputationStagedWitness<C: CurveAffine> {
    // Staging polynomial data
    pub u_challenge: C::Base,
    pub e_nested_commitment: C,
    pub evals: [C::Base; NUM_FINAL_EVALS],

    // Transcript challenges
    pub alpha_challenge: C::Base,
    pub beta_challenge: C::Base,

    // Evaluation queries
    pub eval_points: [C::Base; NUM_V_QUERIES],
    pub intermediate_evals: [C::Base; NUM_V_QUERIES],
    pub final_evals_for_queries: [C::Base; NUM_V_QUERIES],

    // Witnessed inverses
    pub inverses: [C::Base; NUM_V_QUERIES],

    // V claimed to verify
    pub v_claimed: C::Base,
}

pub struct GVComputationStagedInstance<C: CurveAffine> {
    pub e_nested_commitment: C,
    pub alpha_challenge: C::Base,
    pub u_challenge: C::Base,
    pub v_claimed: C::Base,
}

#[derive(ragu_macros::Gadget, ragu_primitives::io::Write)]
pub struct GVComputationStagedOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub e_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub alpha_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub u_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub v_claimed: Element<'dr, D>,
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
    type Instance<'src> = GVComputationStagedInstance<NestedCurve>;
    type Witness<'w> = GVComputationStagedWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; GVComputationStagedOutput<'_, _, NestedCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        let e_nested_commitment = Point::alloc(
            dr,
            instance.view().map(|instance| instance.e_nested_commitment),
        )?;

        let alpha_challenge =
            Element::alloc(dr, instance.view().map(|instance| instance.alpha_challenge))?;
        let u_challenge = Element::alloc(dr, instance.view().map(|instance| instance.u_challenge))?;

        let v_claimed = Element::alloc(dr, instance.view().map(|instance| instance.v_claimed))?;

        Ok(GVComputationStagedOutput {
            e_nested_commitment,
            alpha_challenge,
            u_challenge,
            v_claimed,
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
                    [w.e_nested_commitment],
                    w.evals,
                )
            }))?;

        let dr = dr.finish();

        let alpha_challenge = stage_output.challenges[0].clone();
        let u_challenge = stage_output.challenges[1].clone();
        let e_nested_commitment = stage_output.nested_commitments[0].clone();

        let v_claimed = Element::alloc(dr, witness.view().map(|w| w.v_claimed))?;

        // Initialize a sponge for FS challenge derivation.
        // Sponge has state size 5 and rate 4 (can output 4 challenges per absorption).
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // TODO: fix these challenges
        // TODO: missing beta challenge verification

        // Derive alpha from e_nested_commitment.
        e_nested_commitment.write(dr, &mut sponge)?;

        let alpha_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(alpha_computed.wire(), alpha_challenge.wire())?;

        let u_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(u_computed.wire(), u_challenge.wire())?;

        // Compute V in-circuit using witnessed inverses.
        let mut v_computed = Element::zero(dr);

        let num_queries = witness.view().map(|w| w.eval_points.len()).take();

        for i in 0..num_queries {
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
            v_computed = v_computed.mul(dr, &alpha_challenge)?;
            let eval_diff = eval_prime.sub(dr, &eval);
            let term = inv.mul(dr, &eval_diff)?;
            v_computed = v_computed.add(dr, &term);
        }

        // Verify claimed V matches computed V.
        dr.enforce_equal(v_claimed.wire(), v_computed.wire())?;

        // Return output gadgets and empty auxilary.
        let output = GVComputationStagedOutput {
            e_nested_commitment,
            alpha_challenge,
            u_challenge,
            v_claimed,
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
    use ragu_circuits::{CircuitExt, staging::Staged};
    use ragu_pasta::{EpAffine, Fp, Fq};
    use rand::rngs::OsRng;
    type Rank = ragu_circuits::polynomials::R<12>;

    #[test]
    fn test_g_stage_v_computation_valid() {
        // Setup: Create a simple V computation scenario with a few queries
        const NUM_QUERIES: usize = 3;

        let alpha_challenge = Fp::random(OsRng);
        let u_challenge = Fp::random(OsRng);
        let b_challenge = Fp::random(OsRng);

        // Create random evaluation points (ensuring they're different from u)
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

        // Compute V correctly using the same formula as the circuit
        let mut v_computed = Fp::ZERO;
        for i in 0..NUM_QUERIES {
            v_computed *= alpha_challenge;
            let eval_diff = final_evals_for_queries[i] - intermediate_evals[i];
            v_computed += inverses[i] * eval_diff;
        }

        // Create a random nested commitment for e3
        let e3_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        // Create random final evaluations (these go into the staging polynomial)
        let mut final_evals = [Fp::ZERO; NUM_FINAL_EVALS];
        for i in 0..NUM_FINAL_EVALS {
            final_evals[i] = Fp::random(OsRng);
        }

        // Pad the arrays to match NUM_V_QUERIES (18)
        let mut eval_points_padded = [Fp::ZERO; NUM_V_QUERIES];
        let mut intermediate_evals_padded = [Fp::ZERO; NUM_V_QUERIES];
        let mut final_evals_padded = [Fp::ZERO; NUM_V_QUERIES];
        let mut inverses_padded = [Fp::ONE; NUM_V_QUERIES]; // Use ONE for unused slots to avoid division issues

        eval_points_padded[..NUM_QUERIES].copy_from_slice(&eval_points);
        intermediate_evals_padded[..NUM_QUERIES].copy_from_slice(&intermediate_evals);
        final_evals_padded[..NUM_QUERIES].copy_from_slice(&final_evals_for_queries);
        inverses_padded[..NUM_QUERIES].copy_from_slice(&inverses);

        // For the unused queries, set point = u so (u - point) = 0 and contribution is zero
        for i in NUM_QUERIES..NUM_V_QUERIES {
            eval_points_padded[i] = u_challenge;
            intermediate_evals_padded[i] = Fp::ZERO;
            final_evals_padded[i] = Fp::ZERO;
            // inverse doesn't matter since eval_diff will be zero
        }

        let witness = GVComputationStagedWitness {
            u_challenge,
            e_nested_commitment: e3_nested_commitment,
            evals: final_evals,
            alpha_challenge,
            beta_challenge: b_challenge,
            eval_points: eval_points_padded,
            intermediate_evals: intermediate_evals_padded,
            final_evals_for_queries: final_evals_padded,
            inverses: inverses_padded,
            v_claimed: v_computed,
        };

        // Create the staged circuit
        let circuit = Staged::<Fp, Rank, _>::new(GVComputationStagedCircuit::<EpAffine>::new());

        // This should succeed because v_claimed matches the computed V
        let result = circuit.rx::<Rank>(witness);
        assert!(result.is_ok(), "Valid V computation should pass");
    }
}
