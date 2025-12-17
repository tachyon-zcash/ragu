use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{CollectFixed, FixedVec, Len},
};

use alloc::vec;
use core::marker::PhantomData;

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::{
    fold_revdot::{self, Parameters},
    root_of_unity, transcript,
};

pub use crate::internal_circuits::InternalCircuitIndex::ClaimCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::ClaimStaged as STAGED_ID;

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, P: Parameters> {
    params: &'params C,
    log2_circuits: u32,
    _marker: PhantomData<(R, P)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters>
    Circuit<'params, C, R, HEADER_SIZE, P>
{
    pub fn new(params: &'params C, log2_circuits: u32) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            params,
            log2_circuits,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub error_m_witness: &'a native_error_m::Witness<C, P>,
    pub error_n_witness: &'a native_error_n::Witness<C, P>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> StagedCircuit<C::CircuitField, R>
    for Circuit<'_, C, R, HEADER_SIZE, P>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, P>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, P>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        OutputBuilder::new().finish(dr, &instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_m, builder) =
            builder.add_stage::<native_error_m::Stage<C, R, HEADER_SIZE, P>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, P>>()?;
        let dr = builder.finish();

        let preamble = preamble.enforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let error_m = error_m.enforced(dr, witness.view().map(|w| w.error_m_witness))?;
        let error_n = error_n.enforced(dr, witness.view().map(|w| w.error_n_witness))?;

        // Check that circuit IDs are valid domain elements.
        root_of_unity::enforce(dr, preamble.left.circuit_id.clone(), self.log2_circuits)?;
        root_of_unity::enforce(dr, preamble.right.circuit_id.clone(), self.log2_circuits)?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Computation of w
        let w = {
            // Grab nested_preamble_commitment from the unified instance
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;

            transcript::derive_w::<_, C>(dr, &nested_preamble_commitment, self.params)?
        };

        // Derive (y, z) = H(w, nested_s_prime_commitment).
        let (y, z) = {
            let nested_s_prime_commitment = unified_output
                .nested_s_prime_commitment
                .get(dr, unified_instance)?;
            transcript::derive_y_z::<_, C>(dr, &w, &nested_s_prime_commitment, self.params)?
        };

        // Enforce derived z matches error_m stage's z.
        z.enforce_equal(dr, &error_m.z)?;

        unified_output.w.set(w);
        unified_output.y.set(y);
        unified_output.z.set(z);

        // Compute c, the folded revdot product claim using two-layer reduction.
        {
            // Derive (mu, nu) from nested_error_m_commitment
            let nested_error_m_commitment = unified_output
                .nested_error_m_commitment
                .get(dr, unified_instance)?;
            let (mu, nu) =
                transcript::derive_mu_nu::<_, C>(dr, &nested_error_m_commitment, self.params)?;

            // Enforce derived nu matches error_n stage's nu
            nu.enforce_equal(dr, &error_n.nu)?;

            unified_output.mu.set(mu.clone());
            unified_output.nu.set(nu.clone());

            // Layer 1: N instances of M-sized reductions
            // ky_values stay as zeros for now
            let ky_values_m: FixedVec<_, P::M> = (0..P::M::len())
                .map(|_| Element::zero(dr))
                .collect_fixed()?;

            let mut collapsed = vec![];
            for error_terms_i in error_m.error_terms.iter() {
                let v =
                    fold_revdot::compute_c_m::<_, P>(dr, &mu, &nu, error_terms_i, &ky_values_m)?;
                collapsed.push(v);
            }
            let collapsed: FixedVec<_, P::N> = FixedVec::new(collapsed)?;

            // Derive (mu', nu') from nested_error_n_commitment
            let nested_error_n_commitment = unified_output
                .nested_error_n_commitment
                .get(dr, unified_instance)?;
            let (mu_prime, nu_prime) =
                transcript::derive_mu_nu::<_, C>(dr, &nested_error_n_commitment, self.params)?;

            unified_output.mu_prime.set(mu_prime.clone());
            unified_output.nu_prime.set(nu_prime.clone());

            // Layer 2: Single N-sized reduction using collapsed as ky_values
            let c = fold_revdot::compute_c_n::<_, P>(
                dr,
                &mu_prime,
                &nu_prime,
                &error_n.error_terms,
                &collapsed,
            )?;
            unified_output.c.set(c);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
