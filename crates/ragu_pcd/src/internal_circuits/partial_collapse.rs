//! Circuit for verifying the first layer of the revdot reductions.
//!
//! This circuit verifies that the collapsed values in error_n match the result
//! of folding the error_m terms with the k(y) values (which are computed and
//! verified in hashes_1).
//!
//! This circuit is built using the preamble, error_m (for layer 1 error terms),
//! and error_n (for layer 2 error terms, collapsed values, and k(y) values)
//! native stages.

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
use ragu_primitives::{Element, vec::FixedVec};

use core::{
    iter::{once, repeat_n},
    marker::PhantomData,
};

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot;

pub use crate::internal_circuits::InternalCircuitIndex::PartialCollapseCircuit as CIRCUIT_ID;

/// Number of circuits that use the unified k(y) value per proof.
// TODO: this constant seems brittle because it may vary between the two fields.
pub const NUM_UNIFIED_CIRCUITS: usize = 4;

/// Circuit that verifies layer 1 revdot folding.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    /// Create a new partial collapse circuit.
    pub fn new() -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the partial collapse circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// Witness for the preamble stage (contains child unified instances with c values).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The unified instance containing challenges.
    pub unified_instance: &'a unified::Instance<C>,
    /// Witness for the error_m stage (layer 1 error terms).
    pub error_m_witness: &'a native_error_m::Witness<C, FP>,
    /// Witness for the error_n stage (layer 2 error terms + collapsed values).
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
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (error_m, builder) =
            builder.add_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();
        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let error_m = error_m.unenforced(dr, witness.view().map(|w| w.error_m_witness))?;
        let error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Get mu, nu from unified instance
        let mu = unified_output.mu.get(dr, unified_instance)?;
        let nu = unified_output.nu.get(dr, unified_instance)?;
        let fold_products = fold_revdot::FoldProducts::new(dr, &mu, &nu)?;

        // Read k(y) values from error_n stage, plus child c values from preamble.
        let mut ky_elements = once(preamble.left.unified.c.clone())
            .chain(once(error_n.left.application))
            .chain(once(error_n.left.unified_bridge))
            .chain(repeat_n(error_n.left.unified, NUM_UNIFIED_CIRCUITS))
            .chain(once(preamble.right.unified.c.clone()))
            .chain(once(error_n.right.application))
            .chain(once(error_n.right.unified_bridge))
            .chain(repeat_n(error_n.right.unified, NUM_UNIFIED_CIRCUITS));

        for (i, error_terms) in error_m.error_terms.iter().enumerate() {
            let ky_elements =
                FixedVec::from_fn(|_| ky_elements.next().unwrap_or_else(|| Element::zero(dr)));

            fold_products
                .fold_products_m::<FP>(dr, error_terms, &ky_elements)?
                .enforce_equal(dr, &error_n.collapsed[i])?;
        }

        assert!(ky_elements.next().is_none());

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
