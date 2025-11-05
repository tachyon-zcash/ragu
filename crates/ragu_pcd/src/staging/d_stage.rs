//! D staging polynomial.

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

use crate::{ephemeral_stage, indirection_stage};

// Hardcoding a random constant for now, but this was variably change based on the
// circuit count, which could mean nearly a thousand error terms.
pub const MAX_CROSS_PRODUCTS: usize = 30;

///////////////////////////////////////////////////////////////////////////////////////
// D STAGING POLYNOMIAL
///////////////////////////////////////////////////////////////////////////////////////

// Ephemeral Stage: used to creating nested commitments.
ephemeral_stage!(EphemeralStageD);

// Indirection Stage: for resolving the "outer layer problem".
indirection_stage!(IndirectionStageD);

// D Stage.
#[derive(ragu_macros::Gadget)]
pub struct DStageOutput<
    'dr,
    D: Driver<'dr>,
    HostCurve: CurveAffine<Base = D::F>,
    const MAX_CROSS_PRODUCTS: usize,
> {
    #[ragu(gadget)]
    pub challenges: FixedVec<Element<'dr, D>, ConstLen<3>>,
    #[ragu(gadget)]
    pub nested_commitments: FixedVec<Point<'dr, D, HostCurve>, ConstLen<2>>,
    #[ragu(gadget)]
    pub error_terms: FixedVec<Element<'dr, D>, ConstLen<MAX_CROSS_PRODUCTS>>,
}

/// D Stage: challenges (w, y, z), nested commitments (D1, D2), and error terms.
pub struct DStage<HostCurve, const MAX_CROSS_PRODUCTS: usize> {
    _marker: core::marker::PhantomData<HostCurve>,
}

impl<HostCurve: CurveAffine, R: Rank, const MAX_CROSS_PRODUCTS: usize> Stage<<HostCurve>::Base, R>
    for DStage<HostCurve, MAX_CROSS_PRODUCTS>
{
    type Parent = ();

    type Witness<'source> = (
        [<HostCurve>::Base; 3],
        [HostCurve; 2],
        [<HostCurve>::Base; MAX_CROSS_PRODUCTS],
    );

    type OutputKind = Kind![<HostCurve>::Base; DStageOutput<'_, _, HostCurve, MAX_CROSS_PRODUCTS>];

    fn values() -> usize {
        3 + (2 * 2) + MAX_CROSS_PRODUCTS
    }

    fn witness<'dr, 'source: 'dr, D>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
    where
        D: Driver<'dr, F = <HostCurve>::Base>,
        Self: 'dr,
    {
        // Allocate the challenges (w, y, z).
        let mut challenges = Vec::with_capacity(3);
        for i in 0..3 {
            challenges.push(Element::alloc(dr, witness.view().map(|w| w.0[i]))?);
        }
        let challenges = FixedVec::new(challenges).expect("challenges length");

        // Allocate the nested commitments (s' and s'').
        let mut nested_commitments = Vec::with_capacity(2);
        for i in 0..2 {
            nested_commitments.push(Point::alloc(dr, witness.view().map(|w| w.1[i]))?);
        }
        let nested_commitments =
            FixedVec::new(nested_commitments).expect("nested commitments length");

        // Allocate the error terms.
        let mut error_terms = Vec::with_capacity(MAX_CROSS_PRODUCTS);
        for i in 0..MAX_CROSS_PRODUCTS {
            error_terms.push(Element::alloc(dr, witness.view().map(|w| w.2[i]))?);
        }
        let error_terms = FixedVec::new(error_terms).expect("error terms length");

        Ok(DStageOutput {
            challenges,
            nested_commitments,
            error_terms,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////////////
// STAGED CIRCUIT: `DChallengeDerivationStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

pub struct DChallengeDerivationWitness<C: CurveAffine> {
    pub b_nested_commitment: C,
    pub w_challenge: C::Base,
    pub d1_nested_commitment: C,
    pub y_challenge: C::Base,
    pub d2_nested_commitment: C,
    pub z_challenge: C::Base,
    pub cross_products: [C::Base; MAX_CROSS_PRODUCTS],
}

pub struct DChallengeDerivationInstance<C: CurveAffine> {
    pub b_nested_commitment: C,
    pub w_challenge: C::Base,
    pub y_challenge: C::Base,
    pub z_challenge: C::Base,
}

#[derive(ragu_macros::Gadget, ragu_primitives::io::Write)]
pub struct DChallengeDerivationOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub b_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub w_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub y_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub z_challenge: Element<'dr, D>,
}

#[derive(Clone)]
pub struct DChallengeDerivationStagedCircuit<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve> DChallengeDerivationStagedCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for DChallengeDerivationStagedCircuit<NestedCurve>
{
    type Final = DStage<NestedCurve, MAX_CROSS_PRODUCTS>;
    type Instance<'src> = DChallengeDerivationInstance<NestedCurve>;
    type Witness<'w> = DChallengeDerivationWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; DChallengeDerivationOutput<'_, _, NestedCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        let b_nested_commitment = Point::alloc(
            dr,
            instance.view().map(|instance| instance.b_nested_commitment),
        )?;

        let w_challenge = Element::alloc(dr, instance.view().map(|instance| instance.w_challenge))?;
        let y_challenge = Element::alloc(dr, instance.view().map(|instance| instance.y_challenge))?;
        let z_challenge = Element::alloc(dr, instance.view().map(|instance| instance.z_challenge))?;

        Ok(DChallengeDerivationOutput {
            b_nested_commitment,
            w_challenge,
            y_challenge,
            z_challenge,
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
            dr.add_stage::<DStage<NestedCurve, MAX_CROSS_PRODUCTS>>(witness.view().map(|w| {
                (
                    [w.w_challenge, w.y_challenge, w.z_challenge],
                    [w.d1_nested_commitment, w.d2_nested_commitment],
                    w.cross_products,
                )
            }))?;

        let dr = dr.finish();

        let w_challenge = stage_output.challenges[0].clone();
        let y_challenge = stage_output.challenges[1].clone();
        let z_challenge = stage_output.challenges[2].clone();
        let d1_nested_commitment = stage_output.nested_commitments[0].clone();
        let d2_nested_commitment = stage_output.nested_commitments[1].clone();

        // Now allocate `b_nested_commitment` (NOT as a seperate stage in this staging polynomial) and verify
        // that w was correctly derived from B. This keeps B and D as separate staging
        // polynomials while still verifying the FS challenge derivation.
        let b_nested_commitment = Point::alloc(dr, witness.view().map(|w| w.b_nested_commitment))?;

        // Initialize a sponge for FS challenge derivation.
        // Sponge has state size 5 and rate 4 (can output 4 challenges per absorption).
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive w = H(B).
        b_nested_commitment.write(dr, &mut sponge)?;
        let w_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(w_computed.wire(), w_challenge.wire())?;

        // Derive (y, z) = H(w || D1 || D2).
        d1_nested_commitment.write(dr, &mut sponge)?;
        d2_nested_commitment.write(dr, &mut sponge)?;

        let y_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(y_computed.wire(), y_challenge.wire())?;

        let z_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(z_computed.wire(), z_challenge.wire())?;

        // Return output gadgets and empty auxilary.
        let output = DChallengeDerivationOutput {
            b_nested_commitment,
            w_challenge,
            y_challenge,
            z_challenge,
        };

        Ok((output, D::just(|| ())))
    }
}

///////////////////////////////////////////////////////////////////////////////////////
// STAGED CIRCUIT: `DCValueComputationStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

/// Witness values.
pub struct DCValueComputationWitness<C: CurveAffine> {
    // Mu and nu challenges.
    pub mu_challenge: C::Base,
    pub nu_challenge: C::Base,

    /// Inverse of mu challenge (computed out-of-circuit).
    pub mu_inv: C::Base,

    /// Cross product scalar values.
    pub cross_products: Vec<C::Base>,

    /// Diagonal terms (ky values).
    pub ky_values: Vec<C::Base>,

    /// Number of total polynomials.
    pub len: usize,
}

/// Output containing mu, nu challenges and computed c value.
#[derive(ragu_macros::Gadget, ragu_primitives::io::Write)]
pub struct DCValueComputationOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub mu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub c_value: Element<'dr, D>,
}

// Instances values.
pub struct DCValueComputationInstance<C: CurveAffine> {
    pub d_commitment: C,
    pub mu: C::Base,
    pub nu: C::Base,
    pub c_value: C::Base,
}

/// Auxiliary output containing the computed c value.
pub struct DCValueComputationAux<C: CurveAffine> {
    pub c_value: C::Base,
}

#[derive(Clone)]
pub struct DCValueComputationStagedCircuit<NestedCurve>(PhantomData<NestedCurve>);

impl<NestedCurve> DCValueComputationStagedCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for DCValueComputationStagedCircuit<NestedCurve>
{
    type Final = ();
    type Instance<'src> = ();
    type Witness<'w> = DCValueComputationWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; DCValueComputationOutput<'_, _>];
    type Aux<'source> = DCValueComputationAux<NestedCurve>;

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
        // No stages to add, finish immediately.
        let dr = dr.finish();

        // Allocate the mu and nu challenges, and d_nested_commitment from the d staging polynomial.
        let mu_challenge = Element::alloc(dr, witness.view().map(|w| w.mu_challenge))?;
        let nu_challenge = Element::alloc(dr, witness.view().map(|w| w.nu_challenge))?;

        // let d_nested_commitment = Point::alloc(dr, witness.view().map(|w| w.d_nested_commitment))?;

        // // Initialize a sponge for FS challenge derivation.
        // // Sponge has state size 5 and rate 4 (can output 4 challenges per absorption).
        // let mut sponge = Sponge::new(dr, &PoseidonFp);

        // // Derive (mu, nu) = H(d_nested_commitment).
        // d_nested_commitment.write(dr, &mut sponge)?;

        // let mu_computed = sponge.squeeze(dr)?;
        // dr.enforce_equal(mu_computed.wire(), mu_challenge.wire())?;

        // let nu_computed = sponge.squeeze(dr)?;
        // dr.enforce_equal(nu_computed.wire(), nu_challenge.wire())?;

        // Witness mu_inv and verify it's the inverse of mu (the non-determinstic witness trick from the Halo paper).
        let mu_inv = Element::alloc(dr, witness.view().map(|w| w.mu_inv))?;
        let mu_times_mu_inv = mu_challenge.mul(dr, &mu_inv)?;
        let one = Element::constant(dr, Fp::one());
        dr.enforce_equal(mu_times_mu_inv.wire(), one.wire())?;

        // Compute mu * nu in circuit.
        let munu = mu_challenge.mul(dr, &nu_challenge)?;

        // Allocate cross products as witness elements.
        let mut cross_elements = Vec::new();
        let cross_count = witness.view().map(|w| w.cross_products.len()).take();

        for i in 0..cross_count {
            let elem = Element::alloc(dr, witness.view().map(|w| w.cross_products[i]))?;
            cross_elements.push(elem);
        }

        // Allocate ky values as witness elements.
        let mut ky_elements = Vec::new();
        let ky_count = witness.view().map(|w| w.ky_values.len()).take();

        for i in 0..ky_count {
            let elem = Element::alloc(dr, witness.view().map(|w| w.ky_values[i]))?;
            ky_elements.push(elem);
        }

        // Compute C value in circuit with constrained operations:
        //  * Computes coefficients (mu^-i * (mu*nu)^j) in circuit,
        //  * Multiplies by witnessed terms (cross products and ky values),
        //  * Accumulates via constrained additions,
        let len = witness.view().map(|w| w.len).take();
        let mut c_acc = Element::zero(dr);
        let mut row_power = Element::one();
        let mut cross_iter = 0;

        for i in 0..len {
            let mut col_power = row_power.clone();
            for j in 0..len {
                let term = if i == j {
                    ky_elements[i].clone()
                } else {
                    let cross_elem = cross_elements[cross_iter].clone();
                    cross_iter += 1;
                    cross_elem
                };

                let contribution = col_power.mul(dr, &term)?;
                c_acc = c_acc.add(dr, &contribution);
                col_power = col_power.mul(dr, &munu)?;
            }
            row_power = row_power.mul(dr, &mu_inv)?;
        }

        let output = DCValueComputationOutput {
            mu_challenge,
            nu_challenge,
            c_value: c_acc.clone(),
        };

        let aux = c_acc.value().map(|c| DCValueComputationAux { c_value: *c });

        Ok((output, aux))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::CircuitExt;
    use ragu_circuits::staging::{StageBuilder, Staged};
    use ragu_core::drivers::{Emulator, Simulator};
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{EpAffine, Fp, Fq};
    use ragu_primitives::{GadgetExt, Point, Sponge};
    use rand::rngs::OsRng;
    type Rank = ragu_circuits::polynomials::R<12>;

    /// Staged Circuit: `DChallengeDerivationStagedCircuit`.

    fn validate_circuit_constraints(witness: DChallengeDerivationWitness<EpAffine>) -> Result<()> {
        Simulator::simulate(witness, |dr, witness| {
            let circuit = DChallengeDerivationStagedCircuit::<EpAffine>::new();
            let stage_builder =
                StageBuilder::<'_, '_, _, Rank, (), DStage<EpAffine, MAX_CROSS_PRODUCTS>>::new(dr);
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
        use ragu_core::maybe::Always;
        let mut em = Emulator::<Always<()>, Fp>::default();

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

        let witness: DChallengeDerivationWitness<EpAffine> = DChallengeDerivationWitness {
            b_nested_commitment,
            w_challenge,
            d1_nested_commitment,
            y_challenge,
            d2_nested_commitment,
            z_challenge,
            cross_products: [Fp::ZERO; MAX_CROSS_PRODUCTS],
        };

        let circuit = DChallengeDerivationStagedCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness)?;

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

        let witness = DChallengeDerivationWitness {
            b_nested_commitment,
            w_challenge: w_challenge_invalid,
            d1_nested_commitment,
            y_challenge,
            d2_nested_commitment,
            z_challenge,
            cross_products: [Fp::ZERO; MAX_CROSS_PRODUCTS],
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
            b_nested_commitment,
            w_challenge,
            d1_nested_commitment,
            y_challenge: y_challenge_invalid,
            d2_nested_commitment,
            z_challenge,
            cross_products: [Fp::ZERO; MAX_CROSS_PRODUCTS],
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
            b_nested_commitment,
            w_challenge,
            d1_nested_commitment,
            y_challenge,
            d2_nested_commitment,
            z_challenge: z_challenge_invalid,
            cross_products: [Fp::ZERO; MAX_CROSS_PRODUCTS],
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
            b_nested_commitment: b_nested_commitment_2,
            w_challenge: w_challenge_1,
            d1_nested_commitment,
            y_challenge: y_challenge_1,
            d2_nested_commitment,
            z_challenge: z_challenge_1,
            cross_products: [Fp::ZERO; MAX_CROSS_PRODUCTS],
        };

        let result = validate_circuit_constraints(witness_invalid);
        assert!(
            result.is_err(),
            "Circuit should reject when B changes but challenges remain from old B"
        );

        let witness_valid = DChallengeDerivationWitness {
            b_nested_commitment: b_nested_commitment_2,
            w_challenge: w_challenge_2,
            d1_nested_commitment,
            y_challenge: y_challenge_2,
            d2_nested_commitment,
            z_challenge: z_challenge_2,
            cross_products: [Fp::ZERO; MAX_CROSS_PRODUCTS],
        };

        let circuit = DChallengeDerivationStagedCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness_valid)?;
        assert!(rx.iter_coeffs().count() > 0, "Valid new transcript");

        Ok(())
    }

    /// Staged Circuit: `DCValueComputationStagedCircuit`.

    fn derive_fiat_shamir_challenges(d3_commitment: EpAffine) -> Result<(Fp, Fp)> {
        use ragu_core::maybe::Always;
        let mut em = Emulator::<Always<()>, Fp>::default();

        let mut sponge = Sponge::new(&mut em, &PoseidonFp);

        let d3_point = Point::constant(&mut em, d3_commitment)?;
        d3_point.write(&mut em, &mut sponge)?;
        let mu = sponge.squeeze(&mut em)?;
        let mu_challenge = *mu.value().take();

        mu.write(&mut em, &mut sponge)?;
        let nu = sponge.squeeze(&mut em)?;
        let nu_challenge = *nu.value().take();

        Ok((mu_challenge, nu_challenge))
    }

    fn compute_c_value_reference(
        mu: Fp,
        nu: Fp,
        cross_products: &[Fp],
        ky_values: &[Fp],
        len: usize,
    ) -> Fp {
        let mu_inv = mu.invert().unwrap();
        let munu = mu * nu;

        let mut c = Fp::ZERO;
        let mut cross_iter = cross_products.iter();
        let mut row_power = Fp::ONE;

        for i in 0..len {
            let mut col_power = row_power;
            for j in 0..len {
                if i == j {
                    c += col_power * ky_values[i];
                } else {
                    c += col_power * cross_iter.next().unwrap();
                }
                col_power *= munu;
            }
            row_power *= mu_inv;
        }

        c
    }

    #[test]
    fn test_c_value_computation_matches_reference() -> Result<()> {
        let d_nested_commitment = (EpAffine::generator() * Fq::random(&mut OsRng)).to_affine();
        let (mu_challenge, nu_challenge) = derive_fiat_shamir_challenges(d_nested_commitment)?;

        let len = 4;
        let cross_products: Vec<Fp> = (0..(len * (len - 1)))
            .map(|_| Fp::random(&mut OsRng))
            .collect();
        let ky_values: Vec<Fp> = (0..len).map(|_| Fp::random(&mut OsRng)).collect();

        let c_expected =
            compute_c_value_reference(mu_challenge, nu_challenge, &cross_products, &ky_values, len);

        let mu_inv = mu_challenge.invert().unwrap();

        let witness = DCValueComputationWitness {
            mu_challenge,
            nu_challenge,
            mu_inv,
            cross_products,
            ky_values,
            len,
        };

        let circuit = DCValueComputationStagedCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (_rx, aux) = staged.rx::<Rank>(witness)?;

        let c_computed = aux.c_value;

        assert_eq!(
            c_computed, c_expected,
            "Circuit c value should match reference computation"
        );

        Ok(())
    }
}
