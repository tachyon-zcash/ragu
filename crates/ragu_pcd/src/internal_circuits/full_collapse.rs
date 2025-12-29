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
use ragu_primitives::Element;

use core::marker::PhantomData;

use super::{
    stages::native::{error_m as native_error_m, error_n as native_error_n, preamble},
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot;

pub use crate::internal_circuits::InternalCircuitIndex::ErrorNFinalStaged as STAGED_ID;
pub use crate::internal_circuits::InternalCircuitIndex::FullCollapseCircuit as CIRCUIT_ID;

pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    pub unified_instance: &'a unified::Instance<C>,
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,
    pub error_m_witness: &'a native_error_m::Witness<C, FP>,
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    StagedCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Final = native_error_n::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
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
        let (preamble, builder) = builder.add_stage::<preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_m, builder) =
            builder.add_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.enforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let _error_m = error_m.enforced(dr, witness.view().map(|w| w.error_m_witness))?;
        let error_n = error_n.enforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        let left_is_trivial = preamble.left.is_trivial(dr)?;
        let right_is_trivial = preamble.right.is_trivial(dr)?;
        let is_base = left_is_trivial.and(dr, &right_is_trivial)?;

        // Get mu_prime, nu_prime from unified instance
        let mu_prime = unified_output.mu_prime.get(dr, unified_instance)?;
        let nu_prime = unified_output.nu_prime.get(dr, unified_instance)?;

        // Compute c, the folded revdot product claim.
        // Layer 1 folding is verified by circuit_ky; we use error_n.collapsed directly.
        {
            // Layer 2: Single N-sized reduction using collapsed from error_n as ky_values
            let fold_c = fold_revdot::FoldC::new(dr, &mu_prime, &nu_prime)?;
            let computed_c =
                fold_c.compute_n::<FP>(dr, &error_n.error_terms, &error_n.collapsed)?;

            // Get the witnessed C from the instance.
            let witnessed_c = Element::alloc(dr, unified_instance.view().map(|i| i.c))?;

            // Base case bypass: when both children are trivial, allow prover to substitute a C value.
            let c = is_base.conditional_select(dr, &witnessed_c, &computed_c)?;
            c.enforce_equal(dr, &witnessed_c)?;

            unified_output.c.set(witnessed_c);
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
