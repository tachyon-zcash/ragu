//! Circuit for computing the first layer of the revdot reductions, primarily to
//! compute the $k(Y)$ evaluations and also to invoke the $n$ parallel size-$m$
//! revdot folding operations.
//!
//! This circuit is built using the preamble (for access to unified instances
//! and so forth), error_m (for layer 1 error terms), and error_n (for layer 2
//! error terms and collapsed values) native stages.

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

use core::marker::PhantomData;

use super::{
    stages::native::{
        error_m as native_error_m, error_n as native_error_n, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::components::{
    fold_revdot::{self, Parameters},
    root_of_unity,
};

pub use crate::internal_circuits::InternalCircuitIndex::KyCircuit as CIRCUIT_ID;
pub use crate::internal_circuits::InternalCircuitIndex::KyStaged as STAGED_ID;

/// Circuit that verifies layer 1 revdot folding.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, P: Parameters> {
    log2_circuits: u32,
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> Circuit<C, R, HEADER_SIZE, P> {
    /// Create a new ky circuit.
    pub fn new(log2_circuits: u32) -> Staged<C::CircuitField, R, Self> {
        Staged::new(Circuit {
            log2_circuits,
            _marker: PhantomData,
        })
    }
}

/// Witness for the ky circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> {
    /// The unified instance containing challenges.
    pub unified_instance: &'a unified::Instance<C>,
    /// Witness for the preamble stage.
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// Witness for the error_m stage (layer 1 error terms).
    pub error_m_witness: &'a native_error_m::Witness<C, P>,
    /// Witness for the error_n stage (layer 2 error terms + collapsed values).
    pub error_n_witness: &'a native_error_n::Witness<C, P>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, P: Parameters> StagedCircuit<C::CircuitField, R>
    for Circuit<C, R, HEADER_SIZE, P>
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

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Check that circuit IDs are valid domain elements.
        root_of_unity::enforce(dr, preamble.left.circuit_id.clone(), self.log2_circuits)?;
        root_of_unity::enforce(dr, preamble.right.circuit_id.clone(), self.log2_circuits)?;

        // Get mu, nu from unified instance
        let mu = unified_output.mu.get(dr, unified_instance)?;
        let nu = unified_output.nu.get(dr, unified_instance)?;

        // TODO: Compute ky values properly based on the preamble
        let ky_values = FixedVec::from_fn(|_| Element::todo(dr));

        for (i, error_terms) in error_m.error_terms.iter().enumerate() {
            fold_revdot::compute_c_m::<_, P>(dr, &mu, &nu, error_terms, &ky_values)?
                .enforce_equal(dr, &error_n.collapsed[i])?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
