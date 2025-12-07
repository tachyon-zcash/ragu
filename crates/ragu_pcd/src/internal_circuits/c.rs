use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageBuilder, Staged, StagedCircuit},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt, Sponge,
    vec::{CollectFixed, Len},
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{
    stages::native::preamble,
    unified::{self, OutputBuilder},
};
use crate::components::{
    ErrorTermsLen,
    compute_c::{ComputeRevdotClaim, ErrorMatrix, RevdotClaimInput},
};

pub const CIRCUIT_ID: usize = super::C_CIRCUIT_ID;
pub const STAGED_ID: usize = super::C_STAGED_ID;

pub struct Circuit<'a, C: Cycle, R, const NUM_REVDOT_CLAIMS: usize> {
    circuit_poseidon: &'a C::CircuitPoseidon,
    _marker: PhantomData<(C, R)>,
}

impl<'a, C: Cycle, R: Rank, const NUM_REVDOT_CLAIMS: usize> Circuit<'a, C, R, NUM_REVDOT_CLAIMS> {
    pub fn new(circuit_poseidon: &'a C::CircuitPoseidon) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            circuit_poseidon,
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle> {
    pub unified_instance: &'a unified::Instance<C>,
    pub mu: C::CircuitField,
    pub nu: C::CircuitField,
    pub error_terms: Vec<C::CircuitField>,
}

impl<C: Cycle, R: Rank, const NUM_REVDOT_CLAIMS: usize> StagedCircuit<C::CircuitField, R>
    for Circuit<'_, C, R, NUM_REVDOT_CLAIMS>
{
    type Final = preamble::Stage<C, R>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = unified::OutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<unified::Output<'dr, D, C>> {
        OutputBuilder::new().finish(dr, &instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        unified::Output<'dr, D, C>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let (_, builder) = builder.add_stage::<preamble::Stage<C, R>>()?;
        let dr = builder.finish();

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Computation of w
        {
            // Grab nested_preamble_commitment from the unified instance
            let nested_preamble_commitment = unified_output
                .nested_preamble_commitment
                .get(dr, unified_instance);

            let mut sponge = Sponge::new(dr, self.circuit_poseidon);
            nested_preamble_commitment.write(dr, &mut sponge)?;
            let w = sponge.squeeze(dr)?;

            // Use our local w value to impose upon the unified instance
            unified_output.w.set(w);
        }

        // TODO: Call Horner's method routine to evaluate k(Y) polynomials at y.

        // Compute c, the folded revdot product claim.
        {
            // TODO: witnessing these values for now; derive them later
            let mu = Element::alloc(dr, witness.view().map(|w| w.mu))?;
            let nu = Element::alloc(dr, witness.view().map(|w| w.nu))?;

            // Allocate error terms from witness as an error matrix.
            let error_elements = (0..ErrorTermsLen::<NUM_REVDOT_CLAIMS>::len())
                .map(|i| Element::alloc(dr, witness.view().map(|w| w.error_terms[i])))
                .try_collect_fixed()?;
            let error_matrix = ErrorMatrix::new(error_elements);

            // TODO: Use zeros for ky_values for now.
            let ky_values = (0..NUM_REVDOT_CLAIMS)
                .map(|_| Element::zero(dr))
                .collect_fixed()?;

            let input = RevdotClaimInput {
                mu,
                nu,
                error_matrix,
                ky_values,
            };

            let c = dr.routine(ComputeRevdotClaim::<NUM_REVDOT_CLAIMS>, input)?;
            unified_output.c.set(c);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
