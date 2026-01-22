//! Circuit for verifying layer 2 of the two-layer revdot reduction.
//!
//! ## Operations
//!
//! ### Layer 2 verification
//!
//! This circuit verifies layer 2 of the two-layer reduction, completing the
//! folding process started by [`partial_collapse`]:
//! - Retrieves [$\mu'$] and [$\nu'$] challenges from the unified instance.
//!   These are distinct from the layer 1 challenges ([$\mu$], [$\nu$]) used in
//!   [`partial_collapse`].
//! - Uses the collapsed values from layer 1 (verified by [`partial_collapse`])
//!   as the $k(y)$ inputs.
//! - Computes the final folded revdot claim [$c$] using
//!   [`FoldProducts::fold_products_n`].
//! - Enforces that the computed [$c$] matches the witnessed value from the
//!   unified instance (with base case exception below).
//!
//! ### Base case handling
//!
//! When both child proofs are trivial (the "base case"), the prover may witness
//! any [$c$] value without constraint. This allows seeding the recursion with
//! initial proofs that don't yet carry meaningful revdot claims. The constraint
//! is enforced only when [`is_base_case`] returns false.
//!
//! ## Staging
//!
//! This circuit uses [`error_n`] as its final stage, which inherits in the
//! following chain:
//! - [`preamble`] (unenforced)
//! - [`error_n`] (unenforced)
//!
//! ## Public Inputs
//!
//! This circuit uses the standard [`unified::InternalOutputKind`] as its public
//! inputs, providing the unified instance fields needed for verification.
//!
//! [`partial_collapse`]: super::partial_collapse
//! [$\mu'$]: unified::Output::mu_prime
//! [$\nu'$]: unified::Output::nu_prime
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [$c$]: unified::Output::c
//! [`error_n`]: super::stages::error_n
//! [`preamble`]: super::stages::preamble
//! [`FoldProducts::fold_products_n`]: fold_revdot::FoldProducts::fold_products_n
//! [`is_base_case`]: super::stages::preamble::Output::is_base_case

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::{
    stages::{error_n, preamble},
    unified::{self, OutputBuilder},
};
use crate::components::fold_revdot;

pub(crate) use super::InternalCircuitIndex::FullCollapseCircuit as CIRCUIT_ID;

/// Circuit that verifies layer 2 of the two-layer revdot reduction.
///
/// See the [module-level documentation] for details on the operations
/// performed by this circuit.
///
/// [module-level documentation]: self
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    /// Creates a new multi-stage circuit for layer 2 revdot verification.
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness data for the full collapse circuit.
///
/// Combines the unified instance with stage witnesses needed to perform the
/// layer 2 revdot verification and base case check.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// The unified instance containing expected challenge values and the
    /// witnessed [$c$](unified::Output::c) claim.
    pub unified_instance: &'a unified::Instance<C>,

    /// Witness for the [`preamble`] stage
    /// (unenforced).
    ///
    /// Provides access to [`is_base_case`](super::stages::preamble::Output::is_base_case)
    /// for conditional constraint enforcement.
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,

    /// Witness for the [`error_n`] stage
    /// (unenforced).
    ///
    /// Provides layer 2 error terms and collapsed values from layer 1.
    pub error_n_witness: &'a error_n::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Final = error_n::Stage<C, R, HEADER_SIZE, FP>;

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
        let (error_n, builder) = builder.add_stage::<error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let error_n = error_n.unenforced(dr, witness.view().map(|w| w.error_n_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Get layer 2 folding challenges. These are distinct from the layer 1
        // challenges (mu, nu) used in partial_collapse.
        let mu_prime = unified_output.mu_prime.get(dr, unified_instance)?;
        let nu_prime = unified_output.nu_prime.get(dr, unified_instance)?;

        // Compute the final folded revdot claim c via layer 2 reduction.
        // The collapsed values from layer 1 (verified by partial_collapse) serve
        // as the k(y) inputs for this final fold.
        {
            let fold_products = fold_revdot::FoldProducts::new(dr, &mu_prime, &nu_prime)?;
            let computed_c = fold_products.fold_products_n::<FP>(
                dr,
                &error_n.error_terms,
                &error_n.collapsed,
            )?;

            // Retrieve the witnessed c from the unified instance.
            let witnessed_c = unified_output.c.get(dr, unified_instance)?;

            // Enforce witnessed_c == computed_c, but only when NOT in base case.
            // In base case (both children are trivial proofs), the prover may
            // witness any c value to seed the recursion.
            preamble
                .is_base_case(dr)?
                .not(dr)
                .conditional_enforce_equal(dr, &witnessed_c, &computed_c)?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
