//! Circuit for verifying layer 2 of the two-layer revdot reduction.
//!
//! ## Operations
//!
//! ### Layer 2 verification
//!
//! This circuit verifies layer 2 of the two-layer reduction, completing the
//! folding process started by [`inner_collapse`]:
//! - Retrieves [$\mu'$] and [$\nu'$] challenges from the unified instance.
//!   These are distinct from the layer 1 challenges ([$\mu$], [$\nu$]) used in
//!   [`inner_collapse`].
//! - Uses the collapsed values from layer 1 (verified by [`inner_collapse`])
//!   as the $k(y)$ inputs.
//! - Computes the final folded revdot claim [$c$] using
//!   [`ClaimFolder::fold_outer`].
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
//! This circuit uses [`outer_error`] as its final stage, which inherits in the
//! following chain:
//! - [`preamble`] (unenforced)
//! - [`outer_error`] (unenforced)
//!
//! ## Public Inputs
//!
//! This circuit uses the standard [`unified::InternalOutputKind`] as its public
//! inputs, providing the unified instance fields needed for verification.
//!
//! [`inner_collapse`]: super::inner_collapse
//! [$\mu'$]: unified::Output::mu_prime
//! [$\nu'$]: unified::Output::nu_prime
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [$c$]: unified::Output::c
//! [`outer_error`]: super::super::stages::outer_error
//! [`preamble`]: super::super::stages::preamble
//! [`ClaimFolder::fold_outer`]: fold_revdot::ClaimFolder::fold_outer
//! [`is_base_case`]: super::super::stages::preamble::Output::is_base_case

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};

use core::marker::PhantomData;

use super::super::{
    stages::{outer_error, preamble},
    unified::{self, OutputBuilder},
};
use crate::internal::fold_revdot;

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

/// Witness data for the outer collapse circuit.
///
/// Combines the unified instance with stage witnesses needed to perform the
/// layer 2 revdot verification and base case check.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// The unified instance containing expected challenge values, the
    /// witnessed [$c$](unified::Output::c) claim, and accumulated coverage.
    pub unified: unified::Instance<C>,

    /// Witness for the [`preamble`] stage
    /// (unenforced).
    ///
    /// Provides access to [`is_base_case`](super::super::stages::preamble::Output::is_base_case)
    /// for conditional constraint enforcement.
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,

    /// Witness for the [`outer_error`] stage
    /// (unenforced).
    ///
    /// Provides layer 2 error terms and collapsed values from layer 1.
    pub outer_error_witness: &'a outer_error::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Last = outer_error::Stage<C, R, HEADER_SIZE, FP>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE, FP>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (preamble, builder) = builder.add_stage::<preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let outer_error =
            outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;

        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // Get layer 2 folding challenges. These are distinct from the layer 1
        // challenges (mu, nu) used in inner_collapse.
        let mu_prime = unified_output.mu_prime.read(dr)?;
        let nu_prime = unified_output.nu_prime.read(dr)?;

        // Compute the final folded revdot claim c via layer 2 reduction.
        // The collapsed values from layer 1 (verified by inner_collapse) serve
        // as the k(y) inputs for this final fold.
        {
            let fold_products = fold_revdot::ClaimFolder::new(dr, &mu_prime, &nu_prime)?;
            let computed_c = fold_products.fold_outer::<FP>(
                dr,
                &outer_error.error_terms,
                &outer_error.collapsed,
            )?;

            // Retrieve the witnessed c from the unified instance and mark it
            // as covered by this circuit.
            let witnessed_c = unified_output.c.receive(dr)?;

            // Enforce witnessed_c == computed_c, but only when NOT in base case.
            // In base case (both children are trivial proofs), the prover may
            // witness any c value to seed the recursion.
            preamble
                .is_base_case(dr)?
                .not(dr)
                .conditional_enforce_equal(dr, &witnessed_c, &computed_c)?;
        }

        let (output, aux) = unified_output.finish(dr)?;
        Ok(WithAux::new(output, aux))
    }
}
