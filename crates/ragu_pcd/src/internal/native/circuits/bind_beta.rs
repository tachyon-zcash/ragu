//! Circuit binding the children's nested challenge stages, as walked, to
//! the bindings the children exported and to their `pre_beta`.
//!
//! ## Operations
//!
//! A proof's nested [`challenges`] stage holds the lifts of its challenges,
//! the base-case sign and the lift of its `pre_beta`, committed unblinded,
//! so its commitment is a fixed combination of nested-curve generators. The
//! proof's own `bind_challenges` circuits recompute every term but
//! $\beta$'s from the transcript challenges and export that partial sum as
//! the [`nested_challenges_partial`] slot of the unified instance;
//! `pre_beta` is squeezed after the native `eval` stage is committed, so
//! its term cannot be bound by the same step. The parent completes the
//! binding: for each child it takes the exported partial and `pre_beta`
//! from the child's unified instance in the [`preamble`], decomposes
//! `pre_beta` into bits ([`EndoscalarChallenge`]), endoscales the beta
//! lift's generator by them ([`Endoscalar::group_scale`]), adds the term
//! to the partial, and enforces the result equal to the child's
//! challenge-stage commitment as the parent walks it, which the
//! [`points::BindingStage`] holds at the root of the native stage tree.
//! That is what ties the stage the child's nested circuits read their
//! challenges from to the child's transcript.
//!
//! ## Staging
//!
//! Chained through [`outer_error`] to share the final mask of the hash and
//! outer collapse circuits; the binding stage is loaded unenforced, its
//! curve membership being `bind_endoscalar`'s, and the preamble's contracts
//! `compute_v`'s.
//!
//! ## Instance
//!
//! Uses [`unified::Output`] via [`unified::InternalOutputKind`]; reads no
//! slot and covers none.
//!
//! [`challenges`]: crate::internal::nested::stages::challenges
//! [`nested_challenges_partial`]: unified::Output::nested_challenges_partial
//! [`points::BindingStage`]: super::super::stages::points::BindingStage
//! [`preamble`]: super::super::stages::preamble
//! [`outer_error`]: super::super::stages::outer_error

use core::marker::PhantomData;

use ragu_arithmetic::{Cycle, FixedGenerators};
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder, StageExt},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{
    Endoscalar, EndoscalarChallenge, GadgetExt, NonzeroBank, Point, allocator::Standard,
};

use super::super::{
    stages::{
        outer_error as native_outer_error, points::BindingStage, preamble as native_preamble,
    },
    unified::{self, OutputBuilder},
};
use crate::internal::{fold_revdot, nested};

/// The nested-curve generator index the challenge stage commits the lift of
/// `pre_beta` with.
pub fn generator_index<C: Cycle, R: Rank>() -> usize {
    <nested::stages::challenges::Stage<C::HostCurve, R> as StageExt<C::ScalarField, R>>::generator_index_for_a(
        nested::stages::challenges::BETA_INDEX,
    )
}

/// Circuit binding both children's challenge stages.
///
/// See the [module-level documentation] for details.
///
/// [module-level documentation]: self
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, FP> {
    params: &'params C::Params,
    _marker: PhantomData<(R, FP)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    Circuit<'params, C, R, HEADER_SIZE, FP>
{
    /// Creates a new multi-stage circuit.
    ///
    /// `params` provides the nested-curve generators the challenge stage is
    /// committed with.
    pub fn new(params: &'params C::Params) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

/// Witness for the beta binding circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters> {
    /// The unified instance, for the instance and accumulated coverage.
    pub unified: unified::Instance<C>,
    /// The binding stage: the children's challenge-stage commitments as
    /// walked.
    pub binding: &'a super::super::stages::points::BindingWitness<C::NestedCurve>,
    /// Witness for the preamble stage (provides the children's `pre_beta`
    /// and exported bindings).
    pub preamble_witness: &'a native_preamble::Witness<'a, C, R, HEADER_SIZE>,
    /// Witness for the outer error stage (reserved, unused).
    pub outer_error_witness: &'a native_outer_error::Witness<C, FP>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, FP: fold_revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, FP>
{
    type Last = native_outer_error::Stage<C, R, HEADER_SIZE, FP>;

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
        let (binding, builder) = builder.add_stage::<BindingStage<C::NestedCurve>>()?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let binding = binding.unenforced(dr, witness.as_ref().map(|w| w.binding))?;
        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let _ = outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;

        let allocator = &mut Standard::new();
        let unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        let generator = C::nested_generators(self.params).g()[generator_index::<C, R>()];
        for (child, walked) in [
            (&preamble.left, &binding.left),
            (&preamble.right, &binding.right),
        ] {
            let pre_beta =
                EndoscalarChallenge::from_element(dr, allocator, child.unified.pre_beta.clone())?;
            let bits = Endoscalar::extract(pre_beta);
            let generator = Point::constant(dr, generator)?;
            let beta_term = bits.group_scale(dr, &generator)?;
            let expected = NonzeroBank::scope(dr, |dr, bank| {
                child
                    .unified
                    .nested_challenges_partial
                    .add_incomplete(dr, &beta_term, bank)
            })?;
            walked.enforce_equal(dr, &expected)?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
