//! C staged circuit.

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
use ragu_primitives::vec::Len;
use ragu_primitives::{Element, Point, vec::FixedVec};
use ragu_primitives::{GadgetExt, Sponge};

use crate::composition::error_stage::ErrorStage;
use crate::polynomials::compute_c::{ComputeRevdotClaim, RevdotClaimInput};
use crate::polynomials::horners::EvaluateKyPolynomials;
use crate::polynomials::{CrossProductsLen, KyPolyLen, TotalKyCoeffsLen};
use crate::{
    composition::instance::{UnifiedRecursionInstance, UnifiedRecursionOutput},
    polynomials::Rank,
    staging::{StageBuilder, StagedCircuit},
};

///////////////////////////////////////////////////////////////////////////////////////
// STAGED CIRCUIT: `ErrorStagedCircuit`
///////////////////////////////////////////////////////////////////////////////////////

/// Witness values.
pub struct ErrorStagedCircuitWitness<
    C: CurveAffine,
    const HEADER_SIZE: usize,
    const NUM_CIRCUITS: usize,
> {
    // Supplemental inputs.
    pub mu_inv: C::Base,
    pub cross_products: Vec<C::Base>,
    pub ky_coeffs: Vec<C::Base>,

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

/// Auxiliary output containing the computed c value.
pub struct ErrorStagedCircuitAux<C: CurveAffine> {
    pub c_value: C::Base,
}

#[derive(Clone)]
pub struct ErrorStagedCircuit<NestedCurve, const HEADER_SIZE: usize, const NUM_CIRCUITS: usize>(
    PhantomData<NestedCurve>,
);

impl<NestedCurve, const HEADER_SIZE: usize, const NUM_CIRCUITS: usize> Default
    for ErrorStagedCircuit<NestedCurve, HEADER_SIZE, NUM_CIRCUITS>
{
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<NestedCurve, const HEADER_SIZE: usize, const NUM_CIRCUITS: usize>
    ErrorStagedCircuit<NestedCurve, HEADER_SIZE, NUM_CIRCUITS>
{
    pub fn new() -> Self {
        Self::default()
    }
}

impl<
    NestedCurve: CurveAffine<Base = Fp>,
    R: Rank,
    const HEADER_SIZE: usize,
    const NUM_CIRCUITS: usize,
> StagedCircuit<NestedCurve::Base, R>
    for ErrorStagedCircuit<NestedCurve, HEADER_SIZE, NUM_CIRCUITS>
{
    type Final = ErrorStage<NestedCurve, NUM_CIRCUITS>;
    type Instance<'src> = UnifiedRecursionInstance<NestedCurve>;
    type Witness<'w> = ErrorStagedCircuitWitness<NestedCurve, HEADER_SIZE, NUM_CIRCUITS>;
    type Output = Kind![NestedCurve::Base; UnifiedRecursionOutput<'_, _, NestedCurve>];
    type Aux<'source> = ErrorStagedCircuitAux<NestedCurve>;

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
        // STAGE: StageBuilder for `ErrorStage`: challenges (w, y, z), nested commitments (E1, E2), and error terms.
        let (stage_guard, dr) = dr.add_stage::<ErrorStage<NestedCurve, NUM_CIRCUITS>>()?;
        let dr = dr.finish();

        let stage_witness = witness.view().map(|w| {
            (
                [w.w_challenge, w.y_challenge, w.z_challenge],
                [w.e1_nested_commitment, w.e2_nested_commitment],
                w.cross_products.clone(),
            )
        });
        let stage_output = stage_guard.enforced(dr, stage_witness)?;

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
        // Allocate the mu and nu challenges, and d_nested_commitment from the d staging polynomial.
        let mu_challenge = Element::alloc(dr, witness.view().map(|w| w.mu_challenge))?;
        let nu_challenge = Element::alloc(dr, witness.view().map(|w| w.nu_challenge))?;
        let y_challenge = Element::alloc(dr, witness.view().map(|w| w.y_challenge))?;

        // Witness mu_inv and verify it's the inverse of mu (the non-determinstic witness trick from the Halo paper).
        let mu_inv = Element::alloc(dr, witness.view().map(|w| w.mu_inv))?;
        let mu_times_mu_inv = mu_challenge.mul(dr, &mu_inv)?;
        let one = Element::constant(dr, Fp::one());
        dr.enforce_equal(mu_times_mu_inv.wire(), one.wire())?;

        // Allocate cross products from the witness
        let num_cross_products = CrossProductsLen::<NUM_CIRCUITS>::len();
        let mut cross_elments = Vec::with_capacity(num_cross_products);

        for i in 0..num_cross_products {
            let elem = Element::alloc(dr, witness.view().map(|w| w.cross_products[i]))?;
            cross_elments.push(elem);
        }

        let cross_elements_fixed =
            FixedVec::<_, CrossProductsLen<NUM_CIRCUITS>>::new(cross_elments).unwrap();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Call Horner's rule to evaluate ky polynomials at y
        ///////////////////////////////////////////////////////////////////////////////////////

        // Allocate ky coefficients from the witness.
        let total_ky_coeffs = TotalKyCoeffsLen::<HEADER_SIZE, NUM_CIRCUITS>::len();
        let mut ky_coeff_elems = Vec::with_capacity(total_ky_coeffs);
        for i in 0..total_ky_coeffs {
            let elem = Element::alloc(dr, witness.view().map(|w| w.ky_coeffs[i]))?;
            ky_coeff_elems.push(elem);
        }
        let ky_coeffs =
            FixedVec::<_, TotalKyCoeffsLen<HEADER_SIZE, NUM_CIRCUITS>>::new(ky_coeff_elems)
                .unwrap();

        let ky_degree = KyPolyLen::<HEADER_SIZE>::len();
        let ky_routine = EvaluateKyPolynomials::<HEADER_SIZE, NUM_CIRCUITS>::new(ky_degree);
        let ky_evaluated = dr.routine(ky_routine, (ky_coeffs, y_challenge.clone()))?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Invoke `ComputeRevdotClaim` to compute c = sum over
        // i,j of (mu^-i * (mu*nu)^j * term where term is ky[i] when i==j (diagonal),
        // cross products otherwise.
        ///////////////////////////////////////////////////////////////////////////////////////

        let c_routine = ComputeRevdotClaim::<NUM_CIRCUITS>;
        let input = RevdotClaimInput {
            mu: mu_challenge.clone(),
            nu: nu_challenge.clone(),
            mu_inv,
            cross_products: cross_elements_fixed,
            ky_values: ky_evaluated,
        };
        let c = dr.routine(c_routine, input)?;

        let aux = c.value().map(|c| ErrorStagedCircuitAux { c_value: *c });

        // Allocate remaining unified output fields from witness.
        let w_challenge = Element::alloc(dr, witness.view().map(|w| w.w_challenge))?;
        let z_challenge = Element::alloc(dr, witness.view().map(|w| w.z_challenge))?;
        let x_challenge = Element::alloc(dr, witness.view().map(|w| w.x_challenge))?;
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
            aux,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CircuitExt;
    use crate::polynomials::{CrossProductsLen, KyPolyLen, TotalKyCoeffsLen};
    use crate::staging::Staged;
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_core::drivers::emulator::Emulator;
    use ragu_core::maybe::Maybe;
    use ragu_pasta::{EpAffine, Fp, Fq, PoseidonFp};
    use ragu_primitives::vec::Len;
    use ragu_primitives::{GadgetExt, Point, Sponge};
    use rand::rngs::OsRng;

    type Rank = crate::polynomials::R<12>;

    // Test constants using HEADER_SIZE and NUM_CIRCUITS
    const TEST_HEADER_SIZE: usize = 4;
    const TEST_NUM_CIRCUITS: usize = 3;

    /// Staged Circuit: `DCValueComputationStagedCircuit`.
    fn derive_fiat_shamir_challenges(d3_commitment: EpAffine) -> Result<(Fp, Fp)> {
        let mut em = Emulator::execute();

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

        // Use the Len traits to compute sizes
        let ky_degree = KyPolyLen::<TEST_HEADER_SIZE>::len();
        let total_ky_coeffs = TotalKyCoeffsLen::<TEST_HEADER_SIZE, TEST_NUM_CIRCUITS>::len();
        let num_cross_products = CrossProductsLen::<TEST_NUM_CIRCUITS>::len();

        let y_challenge = Fp::random(&mut OsRng);

        // Generate random cross products
        let cross_products_vec: Vec<Fp> = (0..num_cross_products)
            .map(|_| Fp::random(&mut OsRng))
            .collect();

        // Generate random polynomial coefficients for each ky polynomial
        let mut ky_coeffs_vec = Vec::with_capacity(total_ky_coeffs);
        for _ in 0..total_ky_coeffs {
            ky_coeffs_vec.push(Fp::random(&mut OsRng));
        }

        // Evaluate each ky polynomial at y using Horner's rule
        let mut ky_values_vec = Vec::with_capacity(TEST_NUM_CIRCUITS);
        for circuit_idx in 0..TEST_NUM_CIRCUITS {
            let ky_start = circuit_idx * ky_degree;
            let mut ky_at_y = Fp::ZERO;

            // Horner's method: evaluate polynomial at y
            for coeff_idx in (0..ky_degree).rev() {
                let global_idx = ky_start + coeff_idx;
                ky_at_y *= y_challenge;
                ky_at_y += ky_coeffs_vec[global_idx];
            }

            ky_values_vec.push(ky_at_y);
        }

        // Compute expected c value using evaluated ky values
        let c_expected = compute_c_value_reference(
            mu_challenge,
            nu_challenge,
            &cross_products_vec,
            &ky_values_vec,
            TEST_NUM_CIRCUITS,
        );

        let mu_inv = mu_challenge.invert().unwrap();

        // Create witness with Vec fields
        let witness: ErrorStagedCircuitWitness<EpAffine, TEST_HEADER_SIZE, TEST_NUM_CIRCUITS> =
            ErrorStagedCircuitWitness {
                mu_inv,
                cross_products: cross_products_vec,
                ky_coeffs: ky_coeffs_vec,
                w_challenge: Fp::random(&mut OsRng),
                y_challenge,
                z_challenge: Fp::random(&mut OsRng),
                mu_challenge,
                nu_challenge,
                x_challenge: Fp::random(&mut OsRng),
                alpha_challenge: Fp::random(&mut OsRng),
                u_challenge: Fp::random(&mut OsRng),
                b_challenge: Fp::random(&mut OsRng),
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

        let circuit = ErrorStagedCircuit::<EpAffine, TEST_HEADER_SIZE, TEST_NUM_CIRCUITS>::new();
        let staged = Staged::<Fp, Rank, _>::new(circuit);
        let (_rx, aux) = staged.rx::<Rank>(witness, Fp::ONE)?;

        let c_computed = aux.c_value;

        assert_eq!(
            c_computed, c_expected,
            "Circuit c value should match reference computation"
        );

        Ok(())
    }
}
