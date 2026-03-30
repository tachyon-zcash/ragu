//! Circuit for verifying layer 1 of the two-layer revdot reduction.
//!
//! ## Operations
//!
//! ### Two-layer revdot folding
//!
//! The PCD system uses a two-layer reduction to fold many revdot claims into a
//! single claim (see [`Parameters`] for the folding structure). Layer 1 groups
//! claims and folds each group into an intermediate "collapsed" value. Layer 2
//! (handled by [`outer_collapse`]) then reduces those collapsed values into the
//! final claim [$c$].
//!
//! ### Layer 1 verification
//!
//! This circuit verifies layer 1 of the two-layer reduction:
//! - Retrieves [$\mu$] and [$\nu$] challenges from the unified instance.
//! - For each group of claims, folds the [`inner_error`] terms with the $k(y)$
//!   values using [`ClaimFolder::fold_inner`].
//! - Enforces that each computed result equals the corresponding collapsed
//!   value witnessed in [`outer_error`].
//!
//! ### $k(y)$ values
//!
//! The $k(y)$ values used as inputs to the folding operation come from multiple
//! sources, assembled via [`TwoProofKySource`]:
//! - Child [$c$] values from the [`preamble`] (representing the children's
//!   final revdot claims).
//! - Application and unified $k(y)$ evaluations from [`outer_error`] (computed and
//!   verified in [`hashes_1`]).
//!
//! ## Staging
//!
//! This circuit uses [`inner_error`] as its final stage, which inherits in the
//! following chain:
//! - [`preamble`] (unenforced)
//! - [`outer_error`] (enforced)
//! - [`inner_error`] (enforced)
//!
//! ## Public Inputs
//!
//! This circuit uses the standard [`unified::InternalOutputKind`] as its public
//! inputs, providing the unified instance fields needed for verification.
//!
//! [`Parameters`]: fold_revdot::Parameters
//! [`outer_collapse`]: super::outer_collapse
//! [$c$]: unified::Output::c
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [`inner_error`]: super::super::stages::inner_error
//! [`outer_error`]: super::super::stages::outer_error
//! [`preamble`]: super::super::stages::preamble
//! [`hashes_1`]: super::hashes_1
//! [`ClaimFolder::fold_inner`]: fold_revdot::ClaimFolder::fold_inner
//! [`TwoProofKySource`]: crate::internal::native::claims::TwoProofKySource

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget},
    maybe::Maybe,
};
use ragu_primitives::vec::FixedVec;

use core::marker::PhantomData;

use super::super::claims::{TwoProofKySource, ky_values};
use super::super::{
    stages::{
        inner_error as native_inner_error, outer_error as native_outer_error,
        preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::internal::fold_revdot;

/// Circuit that verifies layer 1 of the two-layer revdot reduction.
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
    /// Creates a new multi-stage circuit for layer 1 revdot verification.
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the inner collapse circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// Witness for the preamble stage (contains child unified instances with c values).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The unified instance containing challenges and accumulated coverage.
    pub unified: unified::Instance<C>,
    /// Witness for the inner error stage (layer 1 error terms).
    pub inner_error_witness: &'a native_inner_error::Witness<C, FP>,
    /// Witness for the outer error stage (layer 2 error terms + collapsed values).
    pub outer_error_witness: &'a native_outer_error::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Last = native_inner_error::Stage<C, R, HEADER_SIZE, FP>;

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
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (inner_error, builder) =
            builder.add_stage::<native_inner_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();
        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let outer_error =
            outer_error.enforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;
        let inner_error =
            inner_error.enforced(dr, witness.as_ref().map(|w| w.inner_error_witness))?;

        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // Get layer 1 folding challenges from the unified instance.
        let mu = unified_output.mu.read(dr)?;
        let nu = unified_output.nu.read(dr)?;
        let fold_products = fold_revdot::ClaimFolder::new(dr, &mu, &nu)?;

        // Assemble k(y) values from multiple sources. The ordering must match
        // claims's iteration order for correct folding correspondence.
        // Sources include:
        // - Child c values from preamble (the children's final revdot claims)
        // - Application and unified k(y) evaluations from outer_error
        let ky = TwoProofKySource::new(
            dr,
            preamble.left.unified.c.clone(),
            preamble.right.unified.c.clone(),
            &outer_error.left,
            &outer_error.right,
        );
        let mut ky = ky_values(&ky);

        // Verify each group's layer 1 reduction. For each group, fold the
        // inner error terms with the corresponding k(y) values and enforce the
        // result matches the collapsed value witnessed in outer error.
        for (i, error_terms) in inner_error.error_terms.iter().enumerate() {
            let ky = FixedVec::from_fn(|_| ky.next().unwrap());

            fold_products
                .fold_inner::<FP>(dr, error_terms, &ky)?
                .enforce_equal(dr, &outer_error.collapsed[i])?;
        }

        let (output, aux) = unified_output.finish(dr)?;
        Ok(WithAux::new(output, aux))
    }
}
