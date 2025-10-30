//! E-stage with a composite challenge derivation circuit, which derives the
//! challenges (mu and nu), and computes C in a continuous parent chain.

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
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// Mu challenge stage: witnesses the mu challenge derived from D staging polynomial.
pub struct MuChallengeStage<NestedCurve> {
    _marker: core::marker::PhantomData<NestedCurve>,
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for MuChallengeStage<NestedCurve>
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

/// Nu challenge stage: witnesses the Nu challenge derived from Mu challenge.
pub struct NuChallengeStage<NestedCurve> {
    _marker: core::marker::PhantomData<NestedCurve>,
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> Stage<NestedCurve::Base, R>
    for NuChallengeStage<NestedCurve>
{
    type Parent = MuChallengeStage<NestedCurve>;
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

/// C Circuit Witness: mu/nu derivation and c value computation
pub struct CNestedEncodingWitness<C: CurveAffine> {
    /// Cross product commitments.
    pub d3_nested_commitment: C,

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
pub struct CNestedEncodingOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub d3_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub mu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub c_value: Element<'dr, D>,
}

/// Auxiliary output containing the computed c value as a field element.
pub struct CCircuitAux<F: PrimeField> {
    pub c_value: F,
}

#[derive(Clone)]
pub struct CNestedEncodingCircuit<NestedCurve>(core::marker::PhantomData<NestedCurve>);

impl<NestedCurve> CNestedEncodingCircuit<NestedCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for CNestedEncodingCircuit<NestedCurve>
{
    type Final = NuChallengeStage<NestedCurve>;
    type Instance<'src> = ();
    type Witness<'w> = CNestedEncodingWitness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; CNestedEncodingOutput<'_, _, NestedCurve>];
    type Aux<'source> = CCircuitAux<NestedCurve::Base>;

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
        // STAGE 1: StageBuilder for `MuChallengeStage` for computed mu value.
        let (mu_challenge, dr) =
            dr.add_stage::<MuChallengeStage<NestedCurve>>(witness.view().map(|w| w.mu_challenge))?;

        let (nu_challenge, dr) =
            dr.add_stage::<NuChallengeStage<NestedCurve>>(witness.view().map(|w| w.nu_challenge))?;

        let dr = dr.finish();

        // Now allocate `d3_nested_commitment` (NOT in the staging polynomial) and verify
        // that mu and nu were correctly derived. This keeps D and E as separate staging
        // polynomials while still verifying the FS challenge derivation.
        let d3_nested_commitment =
            Point::alloc(dr, witness.view().map(|w| w.d3_nested_commitment))?;

        // Initialize a single sponge for FS challenge derivation.
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive mu = H(state_0 || D3)
        d3_nested_commitment.write(dr, &mut sponge)?;
        let mu_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(mu_computed.wire(), mu_challenge.wire())?;

        // Absorb Mu challenge.
        mu_computed.write(dr, &mut sponge)?;

        // Derive nu = H(state_1 || mu) where state_1 contains (D3, mu).
        let nu_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(nu_computed.wire(), nu_challenge.wire())?;

        // Witness mu_inv and verify it's the inverse of mu (non-determinstic witness trick from the Halo paper).
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

        let output = CNestedEncodingOutput {
            d3_nested_commitment,
            mu_challenge,
            nu_challenge,
            c_value: c_acc.clone(),
        };

        // Extract witness value from gadget and wrap in Aux type
        let aux = c_acc.value().map(|c| CCircuitAux { c_value: *c });

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
    use ragu_circuits::staging::{StageExt, Staged};
    use ragu_core::drivers::{Emulator, Simulator};
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{EpAffine, Fp, Fq};
    use ragu_primitives::{GadgetExt, Point, Sponge};
    use rand::thread_rng;
    type Rank = ragu_circuits::polynomials::R<12>;

    fn compute_fiat_shamir_challenges(d3_commitment: EpAffine) -> Result<(Fp, Fp)> {
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
    fn test_c_circuit_parent_chain_multiplications() -> Result<()> {
        let d3_commitment = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let (mu_challenge, nu_challenge) = compute_fiat_shamir_challenges(d3_commitment)?;

        let len = 3;
        let cross_products = vec![
            Fp::from(1),
            Fp::from(2),
            Fp::from(3),
            Fp::from(4),
            Fp::from(5),
            Fp::from(6),
        ];
        let ky_values = vec![Fp::from(10), Fp::from(20), Fp::from(30)];

        let mu_inv = mu_challenge.invert().unwrap();

        let witness = CNestedEncodingWitness {
            d3_nested_commitment: d3_commitment,
            mu_challenge,
            nu_challenge,
            mu_inv,
            cross_products,
            ky_values,
            len,
        };

        let circuit = CNestedEncodingCircuit::<EpAffine>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (rx, _aux) = staged.rx::<Rank>(witness)?;

        assert!(
            rx.iter_coeffs().count() > 0,
            "Staging polynomial shouldn't be empty"
        );

        let mu_muls = <MuChallengeStage<EpAffine> as StageExt<Fp, Rank>>::num_multiplications();
        let nu_skip = <NuChallengeStage<EpAffine> as Stage<Fp, Rank>>::skip_multiplications();

        assert_eq!(
            nu_skip, mu_muls,
            "skip_multiplications() should equal parent's num_multiplications"
        );

        Ok(())
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_c_circuit_invalid_mu_fails() {
        let mut rng = thread_rng();
        let d3_commitment = (EpAffine::generator() * Fq::random(&mut rng)).to_affine();
        let (_mu_correct, nu_challenge) = compute_fiat_shamir_challenges(d3_commitment).unwrap();

        let mu_invalid = Fp::random(&mut rng);

        let len = 3;
        let cross_products = vec![Fp::ONE; 6];
        let ky_values = vec![Fp::ONE; 3];

        let mu_inv = mu_invalid.invert().unwrap();

        let witness = CNestedEncodingWitness {
            d3_nested_commitment: d3_commitment,
            mu_challenge: mu_invalid,
            nu_challenge,
            mu_inv,
            cross_products,
            ky_values,
            len,
        };

        Simulator::simulate(witness, |dr, witness| {
            let circuit = CNestedEncodingCircuit::<EpAffine>::new();
            let stage_builder =
                StageBuilder::<'_, '_, _, Rank, (), NuChallengeStage<EpAffine>>::new(dr);
            circuit.witness(stage_builder, witness)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidWitness")]
    fn test_c_circuit_invalid_nu_fails() {
        let mut rng = thread_rng();
        let d3_commitment = (EpAffine::generator() * Fq::random(&mut rng)).to_affine();
        let (mu_challenge, _nu_correct) = compute_fiat_shamir_challenges(d3_commitment).unwrap();

        let nu_invalid = Fp::random(&mut rng);

        let len = 3;
        let cross_products = vec![Fp::ONE; 6];
        let ky_values = vec![Fp::ONE; 3];

        let mu_inv = mu_challenge.invert().unwrap();

        let witness = CNestedEncodingWitness {
            d3_nested_commitment: d3_commitment,
            mu_challenge,
            nu_challenge: nu_invalid,
            mu_inv,
            cross_products,
            ky_values,
            len,
        };

        Simulator::simulate(witness, |dr, witness| {
            let circuit = CNestedEncodingCircuit::<EpAffine>::new();
            let stage_builder =
                StageBuilder::<'_, '_, _, Rank, (), NuChallengeStage<EpAffine>>::new(dr);
            circuit.witness(stage_builder, witness)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_c_value_computation_matches_reference() -> Result<()> {
        let mut rng = thread_rng();
        let d3_commitment = (EpAffine::generator() * Fq::random(&mut rng)).to_affine();
        let (mu_challenge, nu_challenge) = compute_fiat_shamir_challenges(d3_commitment)?;

        let len = 4;
        let cross_products: Vec<Fp> = (0..(len * (len - 1)))
            .map(|_| Fp::random(&mut rng))
            .collect();
        let ky_values: Vec<Fp> = (0..len).map(|_| Fp::random(&mut rng)).collect();

        let c_expected =
            compute_c_value_reference(mu_challenge, nu_challenge, &cross_products, &ky_values, len);

        let mu_inv = mu_challenge.invert().unwrap();

        let witness = CNestedEncodingWitness {
            d3_nested_commitment: d3_commitment,
            mu_challenge,
            nu_challenge,
            mu_inv,
            cross_products,
            ky_values,
            len,
        };

        let circuit = CNestedEncodingCircuit::<EpAffine>::new();
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
