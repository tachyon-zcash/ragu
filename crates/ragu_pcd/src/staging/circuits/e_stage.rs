//! E staging polynomial.

use crate::{
    ephemeral_stage, indirection_stage,
    staging::instance::{UnifiedRecursionInstance, UnifiedRecursionOutput},
};
use arithmetic::CurveAffine;
use core::marker::PhantomData;
use ragu_circuits::{
    polynomials::{Rank, txz::Evaluate},
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

/// Hardcoding the number of intermediary evaluations.
pub const NUM_EVALS: usize = 23;

///////////////////////////////////////////////////////////////////////////////////////
// E STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral stage used to create nested commitments.
ephemeral_stage!(EphemeralStageE);

// Indirection stage used for an extra layer of nesting.
indirection_stage!(IndirectionStageE);

// E Stage.
#[derive(ragu_macros::Gadget)]
pub struct EStageOutput<
    'dr,
    D: Driver<'dr>,
    HostCurve: CurveAffine<Base = D::F>,
    const NUM_EVALS: usize,
> {
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<3>>,
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<2>>,
    #[ragu(gadget)]
    pub evaluations: FixedVec<Element<'dr, D>, ConstLen<NUM_EVALS>>,
}

/// E Stage: challenges (mu, nu, x), nested commitments (A and B, S), and evaluations.
pub struct EStage<HostCurve, const NUM_EVALS: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const NUM_EVALS: usize> Stage<<HostCurve>::Base, R>
    for EStage<HostCurve, NUM_EVALS>
{
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 3],
        [HostCurve; 2],
        [<HostCurve>::Base; NUM_EVALS],
    );

    type OutputKind = Kind![<HostCurve>::Base; EStageOutput<'_, _, HostCurve, NUM_EVALS>];

    fn values() -> usize {
        3 + (2 * 2) + NUM_EVALS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the challenges (mu, nu, x).
        let mut challenges = Vec::with_capacity(3);
        for i in 0..3 {
            challenges.push(Element::alloc(dr, witness.view().map(|w| w.0[i]))?);
        }
        let challenges = FixedVec::new(challenges).expect("challenges length");

        // Allocate the nested commitments (A and B, S).
        let mut nested_commitments = Vec::with_capacity(2);
        for i in 0..2 {
            nested_commitments.push(Point::alloc(dr, witness.view().map(|w| w.1[i]))?);
        }
        let nested_commitments =
            FixedVec::new(nested_commitments).expect("nested commitments length");

        // Allocate the intermediate evaluations.
        let mut evaluations = Vec::with_capacity(NUM_EVALS);
        for i in 0..NUM_EVALS {
            evaluations.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let evaluations = FixedVec::new(evaluations).expect("error terms length");

        Ok(EStageOutput {
            challenges,
            nested_commitments,
            evaluations,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////////////
// STAGED CIRCUIT: `EChallengeDerivationStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

pub struct EChallengeDerivationWitness<C: CurveAffine> {
    // Other input.
    pub evals: [C::Base; NUM_EVALS],

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
pub struct EChallengeDerivationStagedCircuit<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve> EChallengeDerivationStagedCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for EChallengeDerivationStagedCircuit<NestedCurve>
{
    type Final = EStage<NestedCurve, NUM_EVALS>;
    type Instance<'src> = UnifiedRecursionInstance<NestedCurve>;
    type Witness<'w> = EChallengeDerivationWitness<NestedCurve>;
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
            dr.add_stage::<EStage<NestedCurve, NUM_EVALS>>(witness.view().map(|w| {
                (
                    [w.mu_challenge, w.nu_challenge, w.x_challenge],
                    [w.e1_nested_commitment, w.e2_nested_commitment],
                    w.evals,
                )
            }))?;

        let dr = dr.finish();

        let mu_challenge = stage_output.challenges[0].clone();
        let nu_challenge = stage_output.challenges[1].clone();
        let x_challenge = stage_output.challenges[2].clone();
        let a_b_nested_commitment = stage_output.nested_commitments[0].clone();
        let s_nested_commitment = stage_output.nested_commitments[1].clone();

        let d_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d_staging_nested_commitment))?;
        let z_challenge = Element::alloc(dr, witness.view().map(|w| w.z_challenge))?;

        // Initialize a sponge for FS challenge derivation.
        // Sponge has state size 5 and rate 4 (can output 4 challenges per absorption).
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive (mu, nu) = H(d_nested_commitment).
        d_nested_commitment.write(dr, &mut sponge)?;

        let mu_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(mu_computed.wire(), mu_challenge.wire())?;

        let nu_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(nu_computed.wire(), nu_challenge.wire())?;

        // Derive (x) = H(a_b_nested_commitment).
        a_b_nested_commitment.write(dr, &mut sponge)?;
        let x_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(x_computed.wire(), x_challenge.wire())?;

        // TODO: what to do with txz? launder out as aux data?
        let evaluate_txz = Evaluate::new(R::RANK);
        let txz = dr.routine(evaluate_txz, (x_challenge.clone(), z_challenge))?;

        // Allocate remaining unified output fields from witness.
        let w_challenge = Element::alloc(dr, witness.view().map(|w| w.w_challenge))?;
        let y_challenge = Element::alloc(dr, witness.view().map(|w| w.y_challenge))?;
        let z_challenge = Element::alloc(dr, witness.view().map(|w| w.z_challenge))?;
        let alpha_challenge = Element::alloc(dr, witness.view().map(|w| w.alpha_challenge))?;
        let u_challenge = Element::alloc(dr, witness.view().map(|w| w.u_challenge))?;
        let b_challenge = Element::alloc(dr, witness.view().map(|w| w.b_challenge))?;

        let b_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.b_staging_nested_commitment))?;
        let d1_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d1_nested_commitment))?;
        let d2_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d2_nested_commitment))?;
        let d_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d_staging_nested_commitment))?;
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
                e1_nested_commitment: a_b_nested_commitment,
                e2_nested_commitment: s_nested_commitment,
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
    use ragu_circuits::{
        CircuitExt,
        staging::{StageExt, Staged},
    };
    use ragu_core::Result;
    use ragu_core::drivers::{Emulator, Simulator};
    use ragu_core::maybe::{Always, Maybe};
    use ragu_pasta::{EpAffine, Fp, Fq};
    use rand::rngs::OsRng;
    type Rank = ragu_circuits::polynomials::R<12>;

    /// Helper to compute Fiat-Shamir challenges for E stage
    fn compute_e_fiat_shamir_challenges(
        d_nested_commitment: EpAffine,
        e1_nested_commitment: EpAffine,
    ) -> Result<(Fp, Fp, Fp)> {
        let mut em = Emulator::<Always<()>, Fp>::default();
        let mut sponge = Sponge::new(&mut em, &PoseidonFp);

        // Derive mu from D
        let d_point = Point::constant(&mut em, d_nested_commitment)?;
        d_point.write(&mut em, &mut sponge)?;
        let mu = sponge.squeeze(&mut em)?;
        let mu_challenge = *mu.value().take();

        // Re-absorb mu and derive nu
        mu.write(&mut em, &mut sponge)?;
        let nu = sponge.squeeze(&mut em)?;
        let nu_challenge = *nu.value().take();

        // Derive x from e1 (nested commitment to A, B)
        let e1_point = Point::constant(&mut em, e1_nested_commitment)?;
        e1_point.write(&mut em, &mut sponge)?;
        let x = sponge.squeeze(&mut em)?;
        let x_challenge = *x.value().take();

        Ok((mu_challenge, nu_challenge, x_challenge))
    }

    #[test]
    fn test_valid_e_fiat_shamir_challenges() -> Result<()> {
        let d_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (mu_challenge, nu_challenge, x_challenge) =
            compute_e_fiat_shamir_challenges(d_nested_commitment, e1_nested_commitment)?;

        let z_challenge = Fp::random(&mut OsRng);

        let witness = EChallengeDerivationWitness {
            evals: [Fp::ZERO; NUM_EVALS],
            w_challenge: Fp::random(&mut OsRng),
            y_challenge: Fp::random(&mut OsRng),
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge,
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            d1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d2_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            g1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            g_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            p_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            c: Fp::random(&mut OsRng),
            v: Fp::random(&mut OsRng),
        };

        let circuit = EChallengeDerivationStagedCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness)?;

        assert!(
            rx.iter_coeffs().count() > 0,
            "Valid E stage should produce non-empty staging polynomial"
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_invalid_mu_challenge_fails() {
        let d_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (_mu_correct, nu_challenge, x_challenge) =
            compute_e_fiat_shamir_challenges(d_nested_commitment, e1_nested_commitment).unwrap();

        let mu_invalid = Fp::random(&mut OsRng);
        let z_challenge = Fp::random(&mut OsRng);

        let witness = EChallengeDerivationWitness {
            evals: [Fp::ZERO; NUM_EVALS],
            w_challenge: Fp::random(&mut OsRng),
            y_challenge: Fp::random(&mut OsRng),
            z_challenge,
            mu_challenge: mu_invalid,
            nu_challenge,
            x_challenge,
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            d1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d2_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            g1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            g_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            p_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            c: Fp::random(&mut OsRng),
            v: Fp::random(&mut OsRng),
        };

        Simulator::simulate(witness, |dr, witness| {
            let circuit = EChallengeDerivationStagedCircuit::<EpAffine>::new();
            let stage_builder = ragu_circuits::staging::StageBuilder::<
                '_,
                '_,
                _,
                Rank,
                (),
                EStage<EpAffine, NUM_EVALS>,
            >::new(dr);
            circuit.witness(stage_builder, witness)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_invalid_nu_challenge_fails() {
        let d_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (mu_challenge, _nu_correct, x_challenge) =
            compute_e_fiat_shamir_challenges(d_nested_commitment, e1_nested_commitment).unwrap();

        let nu_invalid = Fp::random(&mut OsRng);
        let z_challenge = Fp::random(&mut OsRng);

        let witness = EChallengeDerivationWitness {
            evals: [Fp::ZERO; NUM_EVALS],
            w_challenge: Fp::random(&mut OsRng),
            y_challenge: Fp::random(&mut OsRng),
            z_challenge,
            mu_challenge,
            nu_challenge: nu_invalid,
            x_challenge,
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            d1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d2_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            g1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            g_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            p_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            c: Fp::random(&mut OsRng),
            v: Fp::random(&mut OsRng),
        };

        Simulator::simulate(witness, |dr, witness| {
            let circuit = EChallengeDerivationStagedCircuit::<EpAffine>::new();
            let stage_builder = ragu_circuits::staging::StageBuilder::<
                '_,
                '_,
                _,
                Rank,
                (),
                EStage<EpAffine, NUM_EVALS>,
            >::new(dr);
            circuit.witness(stage_builder, witness)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_invalid_x_challenge_fails() {
        let d_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (mu_challenge, nu_challenge, _x_correct) =
            compute_e_fiat_shamir_challenges(d_nested_commitment, e1_nested_commitment).unwrap();

        let x_invalid = Fp::random(&mut OsRng);
        let z_challenge = Fp::random(&mut OsRng);

        let witness = EChallengeDerivationWitness {
            evals: [Fp::ZERO; NUM_EVALS],
            w_challenge: Fp::random(&mut OsRng),
            y_challenge: Fp::random(&mut OsRng),
            z_challenge,
            mu_challenge,
            nu_challenge,
            x_challenge: x_invalid,
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            d1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d2_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            d_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            e1_nested_commitment,
            e2_nested_commitment,
            e_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            g1_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            g_staging_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng))
                .to_affine(),
            p_nested_commitment: (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            c: Fp::random(&mut OsRng),
            v: Fp::random(&mut OsRng),
        };

        Simulator::simulate(witness, |dr, witness| {
            let circuit = EChallengeDerivationStagedCircuit::<EpAffine>::new();
            let stage_builder = ragu_circuits::staging::StageBuilder::<
                '_,
                '_,
                _,
                Rank,
                (),
                EStage<EpAffine, NUM_EVALS>,
            >::new(dr);
            circuit.witness(stage_builder, witness)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_challenge_dependency() -> Result<()> {
        let d_nested_1 = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let e1_nested = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (mu1, nu1, x1) = compute_e_fiat_shamir_challenges(d_nested_1, e1_nested)?;

        let d_nested_2 = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let (mu2, nu2, x2) = compute_e_fiat_shamir_challenges(d_nested_2, e1_nested)?;

        assert_ne!(mu1, mu2, "Different D should produce different mu");
        assert_ne!(nu1, nu2, "Different D should produce different nu");
        assert_ne!(x1, x2, "Different D should produce different x");

        let e1_nested_2 = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let (mu3, nu3, x3) = compute_e_fiat_shamir_challenges(d_nested_1, e1_nested_2)?;

        assert_eq!(mu1, mu3, "Same D should produce same mu");
        assert_eq!(nu1, nu3, "Same D should produce same nu");
        assert_ne!(x1, x3, "Different e1 should produce different x");

        Ok(())
    }

    #[test]
    fn test_e_stage_polynomial_creation() -> Result<()> {
        let challenges = [
            Fp::random(&mut OsRng),
            Fp::random(&mut OsRng),
            Fp::random(&mut OsRng),
        ];

        let nested_commitments = [
            (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
            (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine(),
        ];

        let evals: [Fp; NUM_EVALS] = core::array::from_fn(|_| Fp::random(&mut OsRng));

        let e_rx = <EStage<EpAffine, NUM_EVALS> as StageExt<Fp, Rank>>::rx((
            challenges,
            nested_commitments,
            evals,
        ))?;

        assert!(
            e_rx.iter_coeffs().count() > 0,
            "E staging polynomial should have coefficients"
        );

        Ok(())
    }
}
