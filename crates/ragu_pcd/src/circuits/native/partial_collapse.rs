//! Circuit for verifying layer 1 of the two-layer revdot reduction.
//!
//! ## Operations
//!
//! ### Two-layer revdot folding
//!
//! The PCD system uses a two-layer reduction to fold many revdot claims into a
//! single claim (see [`Parameters`] for the folding structure). Layer 1 groups
//! claims and folds each group into an intermediate "collapsed" value. Layer 2
//! (handled by [`full_collapse`]) then reduces those collapsed values into the
//! final claim [$c$].
//!
//! ### Layer 1 verification
//!
//! This circuit verifies layer 1 of the two-layer reduction:
//! - Retrieves [$\mu$] and [$\nu$] challenges from the unified instance.
//! - For each group of claims, folds the [`error_m`] terms with the $k(y)$
//!   values using [`FoldProducts::fold_products_m`].
//! - Enforces that each computed result equals the corresponding collapsed
//!   value witnessed in [`error_n`].
//!
//! ### $k(y)$ values
//!
//! The $k(y)$ values used as inputs to the folding operation come from multiple
//! sources, assembled via [`TwoProofKySource`]:
//! - Child [$c$] values from the [`preamble`] (representing the children's
//!   final revdot claims).
//! - Application and unified $k(y)$ evaluations from [`error_n`] (computed and
//!   verified in [`hashes_1`]).
//!
//! ## Staging
//!
//! This circuit uses [`error_m`] as its final stage, which inherits in the
//! following chain:
//! - [`preamble`] (unenforced)
//! - [`error_n`] (enforced)
//! - [`error_m`] (enforced)
//!
//! ## Public Inputs
//!
//! This circuit uses the standard [`unified::InternalOutputKind`] as its public
//! inputs, providing the unified instance fields needed for verification.
//!
//! [`Parameters`]: fold_revdot::Parameters
//! [`full_collapse`]: super::full_collapse
//! [$c$]: unified::Output::c
//! [$\mu$]: unified::Output::mu
//! [$\nu$]: unified::Output::nu
//! [`error_m`]: super::stages::error_m
//! [`error_n`]: super::stages::error_n
//! [`preamble`]: super::stages::preamble
//! [`hashes_1`]: super::hashes_1
//! [`FoldProducts::fold_products_m`]: fold_revdot::FoldProducts::fold_products_m
//! [`TwoProofKySource`]: crate::components::claims::native::TwoProofKySource

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
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
    stages::{error_m as native_error_m, error_n as native_error_n, preamble as native_preamble},
    unified::{self, OutputBuilder},
};
use crate::components::{
    claims::native::{TwoProofKySource, ky_values},
    fold_revdot,
};

pub(crate) use super::InternalCircuitIndex::PartialCollapseCircuit as CIRCUIT_ID;

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

/// Witness for the partial collapse circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// Witness for the preamble stage (contains child unified instances with c values).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The unified instance containing challenges.
    pub unified_instance: &'a unified::Instance<C>,
    /// Witness for the error_n stage (layer 2 error terms + collapsed values).
    pub error_n_witness: &'a native_error_n::Witness<C, FP>,
    /// Witness for the error_m stage (layer 1 error terms).
    pub error_m_witness: &'a native_error_m::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
{
    type Last = native_error_m::Stage<C, R, HEADER_SIZE, FP>;

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
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
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
        let (error_n, builder) =
            builder.add_stage::<native_error_n::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (error_m, builder) =
            builder.add_stage::<native_error_m::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();
        let preamble = preamble.unenforced(dr, witness.view().map(|w| w.preamble_witness))?;
        let error_n = error_n.enforced(dr, witness.view().map(|w| w.error_n_witness))?;
        let error_m = error_m.enforced(dr, witness.view().map(|w| w.error_m_witness))?;

        let unified_instance = &witness.view().map(|w| w.unified_instance);
        let mut unified_output = OutputBuilder::new();

        // Get layer 1 folding challenges from the unified instance.
        let mu = unified_output.mu.get(dr, unified_instance)?;
        let nu = unified_output.nu.get(dr, unified_instance)?;
        let fold_products = fold_revdot::FoldProducts::new(dr, &mu, &nu)?;

        // Assemble k(y) values from multiple sources. The ordering must match
        // claims's iteration order for correct folding correspondence.
        // Sources include:
        // - Child c values from preamble (the children's final revdot claims)
        // - Application and unified k(y) evaluations from error_n
        let ky = TwoProofKySource {
            left_raw_c: preamble.left.unified.c.clone(),
            right_raw_c: preamble.right.unified.c.clone(),
            left_app: error_n.left.application.clone(),
            right_app: error_n.right.application.clone(),
            left_bridge: error_n.left.unified_bridge.clone(),
            right_bridge: error_n.right.unified_bridge.clone(),
            left_unified: error_n.left.unified.clone(),
            right_unified: error_n.right.unified.clone(),
            zero: Element::zero(dr),
        };
        let mut ky = ky_values(&ky);

        // Verify each group's layer 1 reduction. For each group, fold the
        // error_m terms with the corresponding k(y) values and enforce the
        // result matches the collapsed value witnessed in error_n.
        for (i, error_terms) in error_m.error_terms.iter().enumerate() {
            let ky = FixedVec::from_fn(|_| ky.next().unwrap());

            fold_products
                .fold_products_m::<FP>(dr, error_terms, &ky)?
                .enforce_equal(dr, &error_n.collapsed[i])?;
        }

        Ok((unified_output.finish(dr, unified_instance)?, D::just(|| ())))
    }
}
