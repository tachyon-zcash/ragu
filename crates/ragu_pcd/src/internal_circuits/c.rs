use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};
use ragu_primitives::{
    Element, InDomain,
    vec::{CollectFixed, FixedVec, Len},
};

use core::marker::PhantomData;

use super::{
    stages::native::preamble,
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot::{self, ErrorTermsLen};

pub use crate::internal_circuits::InternalCircuitIndex::ClaimCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::ClaimStaged as STAGED_ID;

pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize> {
    params: &'params C,
    log2_domain_size: u32,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize>
    Circuit<'params, C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>
{
    pub fn new(params: &'params C, log2_domain_size: u32) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            params,
            log2_domain_size,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize>
{
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub error_terms: FixedVec<C::CircuitField, ErrorTermsLen<NUM_REVDOT_CLAIMS>>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, const NUM_REVDOT_CLAIMS: usize>
    StagedCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>
{
    type Final = preamble::Stage<C, R, HEADER_SIZE>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, NUM_REVDOT_CLAIMS>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>> {
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
        let (preamble_guard, builder) =
            builder.add_stage::<preamble::Stage<C, R, HEADER_SIZE>>()?;
        let preamble_output =
            preamble_guard.unenforced(witness.view().map(|w| w.preamble_witness))?;
        let dr = builder.finish();

        // Check that circuit IDs are valid domain elements.
        InDomain::new(
            dr,
            preamble_output.left.circuit_id.clone(),
            self.log2_domain_size,
        )?;
        InDomain::new(
            dr,
            preamble_output.right.circuit_id.clone(),
            self.log2_domain_size,
        )?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Computation of w
        {
            // Grab nested_preamble_commitment from the unified instance
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance)?;

            let w = crate::components::transcript::derive_w::<_, C>(
                dr,
                &nested_preamble_commitment,
                self.params,
            )?;

            // Use our local w value to impose upon the unified instance
            unified_output.w.set(w);
        }

        // TODO: Call Horner's method routine to evaluate k(Y) polynomials at y.

        // Compute c, the folded revdot product claim.
        {
            // Grab mu and nu from the unified instance
            let mu = unified_output.mu.get(dr, unified_instance)?;
            let nu = unified_output.nu.get(dr, unified_instance)?;

            // Allocate error terms.
            let error_terms = ErrorTermsLen::<NUM_REVDOT_CLAIMS>::range()
                .map(|i| Element::alloc(dr, witness.view().map(|w| w.error_terms[i])))
                .try_collect_fixed()?;

            // TODO: Use zeros for ky_values for now.
            let ky_values = (0..NUM_REVDOT_CLAIMS)
                .map(|_| Element::zero(dr))
                .collect_fixed()?;

            let c = fold_revdot::compute_c::<_, NUM_REVDOT_CLAIMS>(
                dr,
                &mu,
                &nu,
                &error_terms,
                &ky_values,
            )?;
            unified_output.c.set(c);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
