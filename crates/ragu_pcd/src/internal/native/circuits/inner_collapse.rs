//! Circuit for verifying layer 1 of the two-layer revdot reduction.
//!
//! Quotient folding uses only $\mu$ and $\mu'$; `nu` and `nu_prime`
//! below apply to the original Horner fold.
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
//! - Retrieves [$\mu$] and `nu` challenges from the unified instance.
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
//!   verified in [`outer_collapse`]).
//! - The statement circuit's $k(y)$, from the preamble's headers, and the
//!   binding circuit's, from the children's nested extension stage
//!   commitments the [`points::BindingStage`] walks, for a profile whose
//!   native extension has them.
//!
//! ## Staging
//!
//! This circuit uses [`inner_error`] as its final stage, which inherits in the
//! following chain:
//! - [`points::BindingStage`] (unenforced, for a profile whose native
//!   extension binds, which puts the stage in the circuit's claim; its
//!   curve membership is `bind_endoscalar`'s. Skipped otherwise, as the
//!   standard profile's circuit always has.)
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
//! [`inner_error`]: super::super::stages::inner_error
//! [`outer_error`]: super::super::stages::outer_error
//! [`preamble`]: super::super::stages::preamble
//! [`points::BindingStage`]: super::super::stages::points::BindingStage
//! [`ClaimFolder::fold_inner`]: fold_revdot::ClaimFolder::fold_inner
//! [`TwoProofKySource`]: crate::internal::native::claims::TwoProofKySource

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt as _, allocator::Standard, vec::FixedVec};

use super::super::{
    claims::{TwoProofKySource, ky_values},
    stages::{
        inner_error as native_inner_error, outer_error as native_outer_error,
        preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::{
    internal::{fold_revdot, ky},
    profile::{Profile, ProfiledCycle},
};

/// Circuit that verifies layer 1 of the two-layer revdot reduction.
///
/// See the [module-level documentation] for details on the operations
/// performed by this circuit.
///
/// [module-level documentation]: self
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
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
pub struct Witness<
    'a,
    C: ProfiledCycle,
    R: Rank,
    const HEADER_SIZE: usize,
    FP: fold_revdot::Parameters,
> {
    /// The binding stage: the children's walked commitments, for the
    /// nested extension stages the binding circuit's k(y) is over.
    pub binding: &'a super::super::stages::points::BindingWitness<C::NestedCurve, C::Profile>,
    /// Witness for the preamble stage (contains child unified instances with c values).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// The unified instance containing challenges and accumulated coverage.
    pub unified: unified::Instance<C>,
    /// Witness for the inner error stage (layer 1 error terms).
    pub inner_error_witness: &'a native_inner_error::Witness<C, FP>,
    /// Witness for the outer error stage (layer 2 error terms + collapsed values).
    pub outer_error_witness: &'a native_outer_error::Witness<C, FP>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
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
        type Binding<C, P> = super::super::stages::points::BindingStage<C, P>;
        // The binding stage is loaded, and so in the circuit's claim, only
        // for a profile whose native extension binds: the circuit reads
        // its extension points for the binding k(y) and nothing else.
        let extension = C::Profile::native_extension();
        let (binding, builder) = if extension.binding.is_some() {
            let (binding, builder) = builder.add_stage::<Binding<C::NestedCurve, C::Profile>>()?;
            (Some(binding), builder)
        } else {
            (
                None,
                builder.skip_stage::<Binding<C::NestedCurve, C::Profile>>()?,
            )
        };
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (inner_error, builder) =
            builder.add_stage::<native_inner_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();
        let binding = match binding {
            Some(binding) => Some(binding.unenforced(dr, witness.as_ref().map(|w| w.binding))?),
            None => None,
        };
        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let outer_error =
            outer_error.enforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;
        let inner_error =
            inner_error.enforced(dr, witness.as_ref().map(|w| w.inner_error_witness))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // Get layer 1 folding challenges from the unified instance.
        let mu = unified_output.mu.read(dr, allocator)?;
        #[cfg(not(feature = "experimental-quotient-fold"))]
        let nu = unified_output.nu.read(dr, allocator)?;
        let fold_products = fold_revdot::ClaimFolder::new(
            dr,
            &mu,
            #[cfg(not(feature = "experimental-quotient-fold"))]
            &nu,
        )?;

        // Assemble k(y) values from multiple sources. The ordering must match
        // claims's iteration order for correct folding correspondence.
        // Sources include:
        // - Child c values from preamble (the children's final revdot claims)
        // - Application and unified k(y) evaluations from outer_error
        // The statement circuit's k(y) values come straight from the
        // preamble, as the application ones do in `outer_collapse`, and the
        // binding circuit's from the children's nested extension stage
        // commitments the binding stage walks. A profile without either
        // computes nothing here, and reads nothing: its circuit is the one
        // it had.
        let y = if extension.statement.is_some() || extension.binding.is_some() {
            Some(unified_output.y.read(dr, allocator)?)
        } else {
            None
        };
        let (left_statement, right_statement) = match (&y, extension.statement) {
            (Some(y), Some(_)) => (
                preamble.left.statement_ky::<C::Profile>(dr, y)?,
                preamble.right.statement_ky::<C::Profile>(dr, y)?,
            ),
            _ => (None, None),
        };
        let (left_binding, right_binding) = match (&y, &extension.binding, &binding) {
            (Some(y), Some(declared), Some(binding)) => {
                let bound = |child: &super::super::stages::points::ChildBinding<'dr, D, _, _>| {
                    ky::bound(Some(declared), |j| child.extension[j as usize].clone())
                };
                (
                    ky::binding_ky(dr, y, &bound(&binding.left))?,
                    ky::binding_ky(dr, y, &bound(&binding.right))?,
                )
            }
            _ => (None, None),
        };
        let ky = TwoProofKySource::new(
            dr,
            preamble.left.unified.c.clone(),
            preamble.right.unified.c.clone(),
            &outer_error.left,
            &outer_error.right,
            left_statement,
            right_statement,
            left_binding,
            right_binding,
        );
        let mut ky = ky_values::<C::Profile, _>(&ky);

        // Verify each group's layer 1 reduction. For each group, fold the
        // inner error terms with the corresponding k(y) values and enforce the
        // result matches the collapsed value witnessed in outer error.
        for (i, error_terms) in inner_error.error_terms.iter().enumerate() {
            let ky = FixedVec::from_fn(|_| ky.next().unwrap());

            fold_products
                .fold_inner::<FP>(dr, error_terms, &ky)?
                .enforce_equal(dr, &outer_error.collapsed[i])?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
