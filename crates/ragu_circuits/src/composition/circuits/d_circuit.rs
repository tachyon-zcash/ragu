//! D staged circuit.

use alloc::vec::Vec;
use arithmetic::CurveAffine;
use core::marker::PhantomData;
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_pasta::{Fp, PoseidonFp};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

use crate::{
    composition::staging::{
        d_stage::DStage,
        instance::{UnifiedRecursionInstance, UnifiedRecursionOutput},
    },
    polynomials::Rank,
    staging::{StageBuilder, StagedCircuit},
};

///////////////////////////////////////////////////////////////////////////////////////
// STAGED CIRCUIT: `DChallengeDerivationStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

pub struct DChallengeDerivationWitness<C: CurveAffine, const NUM_CIRCUITS: usize> {
    // Supplemental inputs.
    pub cross_products: Vec<C::Base>,

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
pub struct DChallengeDerivationStagedCircuit<NestedCurve, const NUM_CIRCUITS: usize>(
    PhantomData<NestedCurve>,
);

impl<NestedCurve, const NUM_CIRCUITS: usize> Default
    for DChallengeDerivationStagedCircuit<NestedCurve, NUM_CIRCUITS>
{
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve, const NUM_CIRCUITS: usize>
    DChallengeDerivationStagedCircuit<NestedCurve, NUM_CIRCUITS>
{
    pub fn new() -> Self {
        Self::default()
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank, const NUM_CIRCUITS: usize>
    StagedCircuit<NestedCurve::Base, R>
    for DChallengeDerivationStagedCircuit<NestedCurve, NUM_CIRCUITS>
{
    type Final = DStage<NestedCurve, NUM_CIRCUITS>;
    type Instance<'src> = UnifiedRecursionInstance<NestedCurve>;
    type Witness<'w> = DChallengeDerivationWitness<NestedCurve, NUM_CIRCUITS>;
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
            dr.add_stage::<DStage<NestedCurve, NUM_CIRCUITS>>(witness.view().map(|w| {
                (
                    [w.w_challenge, w.y_challenge, w.z_challenge],
                    [w.d1_nested_commitment, w.d2_nested_commitment],
                    w.cross_products.clone(),
                )
            }))?;

        let dr = dr.finish();

        let w_challenge = stage_output.challenges[0].clone();
        let y_challenge = stage_output.challenges[1].clone();
        let z_challenge = stage_output.challenges[2].clone();
        let d1_nested_commitment = stage_output.nested_commitments[0].clone();
        let d2_nested_commitment = stage_output.nested_commitments[1].clone();

        let b_staging_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.b_staging_nested_commitment))?;

        // Initialize a sponge for FS challenge derivation.
        // Sponge has state size 5 and rate 4 (can output 4 challenges per absorption).
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive w = H(B).
        b_staging_nested_commitment.write(dr, &mut sponge)?;
        let w_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(w_computed.wire(), w_challenge.wire())?;

        // Derive (y, z) = H(w || D1 || D2).
        d1_nested_commitment.write(dr, &mut sponge)?;
        d2_nested_commitment.write(dr, &mut sponge)?;

        let y_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(y_computed.wire(), y_challenge.wire())?;

        let z_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(z_computed.wire(), z_challenge.wire())?;

        // Allocate remaining unified output fields from witness.
        let mu_challenge = Element::alloc(dr, witness.view().map(|w| w.mu_challenge))?;
        let nu_challenge = Element::alloc(dr, witness.view().map(|w| w.nu_challenge))?;
        let x_challenge = Element::alloc(dr, witness.view().map(|w| w.x_challenge))?;
        let alpha_challenge = Element::alloc(dr, witness.view().map(|w| w.alpha_challenge))?;
        let u_challenge = Element::alloc(dr, witness.view().map(|w| w.u_challenge))?;
        let b_challenge = Element::alloc(dr, witness.view().map(|w| w.b_challenge))?;

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
    use crate::CircuitExt;
    use crate::polynomials::CrossProductsLen;
    use crate::staging::{StageBuilder, Staged};
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_core::drivers::emulator::Emulator;
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{EpAffine, Fp, Fq};
    use ragu_primitives::Simulator;
    use ragu_primitives::vec::Len;
    use ragu_primitives::{GadgetExt, Point, Sponge};
    use rand::rngs::OsRng;

    type Rank = crate::polynomials::R<12>;

    // Test constants using HEADER_SIZE and NUM_CIRCUITS
    const TEST_NUM_CIRCUITS: usize = 3;

    /// Staged Circuit: `DChallengeDerivationStagedCircuit`.
    fn validate_circuit_constraints(
        witness: DChallengeDerivationWitness<EpAffine, TEST_NUM_CIRCUITS>,
    ) -> Result<()> {
        Simulator::simulate(witness, |dr, witness| {
            let circuit = DChallengeDerivationStagedCircuit::<EpAffine, TEST_NUM_CIRCUITS>::new();
            let stage_builder =
                StageBuilder::<'_, '_, _, Rank, (), DStage<EpAffine, TEST_NUM_CIRCUITS>>::new(dr);
            circuit.witness(stage_builder, witness)?;
            Ok(())
        })?;
        Ok(())
    }

    fn compute_fiat_shamir_challenges(
        b_commitment: EpAffine,
        d1_commitment: EpAffine,
        d2_commitment: EpAffine,
    ) -> Result<(Fp, Fp, Fp)> {
        let mut em = Emulator::execute();

        let mut sponge = Sponge::new(&mut em, &PoseidonFp);

        let b_point = Point::constant(&mut em, b_commitment)?;
        b_point.write(&mut em, &mut sponge)?;
        let w = sponge.squeeze(&mut em)?;
        let w_challenge = *w.value().take();

        let d1_point = Point::constant(&mut em, d1_commitment)?;
        d1_point.write(&mut em, &mut sponge)?;
        let y = sponge.squeeze(&mut em)?;
        let y_challenge = y.value().take();

        let d2_point = Point::constant(&mut em, d2_commitment)?;
        d2_point.write(&mut em, &mut sponge)?;
        let z = sponge.squeeze(&mut em)?;
        let z_challenge = z.value().take();

        Ok((w_challenge, *y_challenge, *z_challenge))
    }

    #[test]
    fn test_valid_fiat_shamir_challenges_pass() -> Result<()> {
        let b_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (w_challenge, y_challenge, z_challenge) = compute_fiat_shamir_challenges(
            b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
        )?;

        let witness: DChallengeDerivationWitness<EpAffine, TEST_NUM_CIRCUITS> =
            DChallengeDerivationWitness {
                cross_products: vec![Fp::ZERO; CrossProductsLen::<TEST_NUM_CIRCUITS>::len()],
                w_challenge,
                y_challenge,
                z_challenge,
                mu_challenge: Fp::random(&mut OsRng),
                nu_challenge: Fp::random(&mut OsRng),
                x_challenge: Fp::random(&mut OsRng),
                alpha_challenge: Fp::random(&mut OsRng),
                u_challenge: Fp::random(&mut OsRng),
                b_challenge: Fp::random(&mut OsRng),
                b_staging_nested_commitment: b_nested_commitment,
                d1_nested_commitment,
                d2_nested_commitment,
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

        let circuit = DChallengeDerivationStagedCircuit::<EpAffine, TEST_NUM_CIRCUITS>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness, Fp::ONE)?;

        assert!(
            rx.iter_coeffs().count() > 0,
            "Valid transcript should produce non-empty staging polynomial"
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_invalid_w_challenge_fails() {
        let b_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (_w_challenge_correct, y_challenge, z_challenge) = compute_fiat_shamir_challenges(
            b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
        )
        .unwrap();

        let w_challenge_invalid = Fp::random(&mut OsRng);

        let witness: DChallengeDerivationWitness<EpAffine, TEST_NUM_CIRCUITS> =
            DChallengeDerivationWitness {
                cross_products: vec![Fp::ZERO; CrossProductsLen::<TEST_NUM_CIRCUITS>::len()],
                w_challenge: w_challenge_invalid,
                y_challenge,
                z_challenge,
                mu_challenge: Fp::random(&mut OsRng),
                nu_challenge: Fp::random(&mut OsRng),
                x_challenge: Fp::random(&mut OsRng),
                alpha_challenge: Fp::random(&mut OsRng),
                u_challenge: Fp::random(&mut OsRng),
                b_challenge: Fp::random(&mut OsRng),
                b_staging_nested_commitment: b_nested_commitment,
                d1_nested_commitment,
                d2_nested_commitment,
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

        validate_circuit_constraints(witness).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_invalid_y_challenge_fails() {
        let b_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (w_challenge, _y_challenge_correct, z_challenge) = compute_fiat_shamir_challenges(
            b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
        )
        .unwrap();

        let y_challenge_invalid = Fp::random(&mut OsRng);

        let witness = DChallengeDerivationWitness {
            cross_products: vec![Fp::ZERO; CrossProductsLen::<TEST_NUM_CIRCUITS>::len()],
            w_challenge,
            y_challenge: y_challenge_invalid,
            z_challenge,
            mu_challenge: Fp::random(&mut OsRng),
            nu_challenge: Fp::random(&mut OsRng),
            x_challenge: Fp::random(&mut OsRng),
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
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

        validate_circuit_constraints(witness).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_invalid_z_challenge_fails() {
        let b_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (w_challenge, y_challenge, _z_challenge_correct) = compute_fiat_shamir_challenges(
            b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
        )
        .unwrap();

        let z_challenge_invalid = Fp::random(&mut OsRng);

        let witness = DChallengeDerivationWitness {
            cross_products: vec![Fp::ZERO; CrossProductsLen::<TEST_NUM_CIRCUITS>::len()],
            w_challenge,
            y_challenge,
            z_challenge: z_challenge_invalid,
            mu_challenge: Fp::random(&mut OsRng),
            nu_challenge: Fp::random(&mut OsRng),
            x_challenge: Fp::random(&mut OsRng),
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
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

        validate_circuit_constraints(witness).unwrap();
    }

    #[test]
    fn test_sequential_dependency_of_challenges() -> Result<()> {
        let b_nested_commitment_1 = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d1_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let d2_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();

        let (w_challenge_1, y_challenge_1, z_challenge_1) = compute_fiat_shamir_challenges(
            b_nested_commitment_1,
            d1_nested_commitment,
            d2_nested_commitment,
        )?;

        let b_nested_commitment_2 = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        assert_ne!(
            b_nested_commitment_1, b_nested_commitment_2,
            "B commitments should differ"
        );

        let (w_challenge_2, y_challenge_2, z_challenge_2) = compute_fiat_shamir_challenges(
            b_nested_commitment_2,
            d1_nested_commitment,
            d2_nested_commitment,
        )?;

        assert_ne!(
            w_challenge_1, w_challenge_2,
            "w should change when B changes"
        );
        assert_ne!(
            y_challenge_1, y_challenge_2,
            "y should change when B changes"
        );
        assert_ne!(
            z_challenge_1, z_challenge_2,
            "z should change when B changes"
        );

        let witness_invalid = DChallengeDerivationWitness {
            cross_products: vec![Fp::ZERO; CrossProductsLen::<TEST_NUM_CIRCUITS>::len()],
            w_challenge: w_challenge_1,
            y_challenge: y_challenge_1,
            z_challenge: z_challenge_1,
            mu_challenge: Fp::random(&mut OsRng),
            nu_challenge: Fp::random(&mut OsRng),
            x_challenge: Fp::random(&mut OsRng),
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: b_nested_commitment_2,
            d1_nested_commitment,
            d2_nested_commitment,
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

        let result = validate_circuit_constraints(witness_invalid);
        assert!(
            result.is_err(),
            "Circuit should reject when B changes but challenges remain from old B"
        );

        let witness_valid = DChallengeDerivationWitness {
            cross_products: vec![Fp::ZERO; CrossProductsLen::<TEST_NUM_CIRCUITS>::len()],
            w_challenge: w_challenge_2,
            y_challenge: y_challenge_2,
            z_challenge: z_challenge_2,
            mu_challenge: Fp::random(&mut OsRng),
            nu_challenge: Fp::random(&mut OsRng),
            x_challenge: Fp::random(&mut OsRng),
            alpha_challenge: Fp::random(&mut OsRng),
            u_challenge: Fp::random(&mut OsRng),
            b_challenge: Fp::random(&mut OsRng),
            b_staging_nested_commitment: b_nested_commitment_2,
            d1_nested_commitment,
            d2_nested_commitment,
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

        let circuit = DChallengeDerivationStagedCircuit::<EpAffine, TEST_NUM_CIRCUITS>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness_valid, Fp::ONE)?;
        assert!(rx.iter_coeffs().count() > 0, "Valid new transcript");

        Ok(())
    }
}
