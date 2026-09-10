//! Circuit binding the children's nested beta stages to their `pre_beta`.
//!
//! ## Operations
//!
//! A proof's nested [`beta`] stage holds the lift of its `pre_beta`,
//! committed unblinded, so its commitment is $\mathrm{lift}(\beta) \cdot
//! G_{\mathrm{idx}}$ for a fixed nested-curve generator. `pre_beta` is
//! squeezed after the native `eval` stage is committed, so unlike the other
//! challenges (see [`bind_challenges`]) it cannot be bound by the same step.
//! The parent binds it instead: this circuit takes each child's `pre_beta`
//! from the child's unified instance in the [`preamble`] and its beta stage
//! commitment from the same stage, decomposes the challenge into bits
//! ([`EndoscalarChallenge`]), endoscales the generator by them
//! ([`Endoscalar::group_scale`]) and enforces equality.
//!
//! ## Staging
//!
//! Chained through [`outer_error`] to share the final mask of the hash and
//! outer collapse circuits; both stages are unenforced here, the preamble's
//! contracts being [`compute_v`]'s responsibility.
//!
//! ## Instance
//!
//! Uses [`unified::Output`] via [`unified::InternalOutputKind`]; reads no
//! slot and covers none.
//!
//! [`beta`]: crate::internal::nested::stages::beta
//! [`bind_challenges`]: super::bind_challenges
//! [`compute_v`]: super::compute_v
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
use ragu_primitives::{Endoscalar, EndoscalarChallenge, GadgetExt, Point, allocator::Standard};

use super::super::{
    stages::{outer_error as native_outer_error, preamble as native_preamble},
    unified::{self, OutputBuilder},
};
use crate::internal::{fold_revdot, nested};

/// The nested-curve generator index the beta stage commits its lift with.
pub fn generator_index<C: Cycle, R: Rank>() -> usize {
    <nested::stages::beta::Stage<C::HostCurve, R> as StageExt<C::ScalarField, R>>::generator_index_for_a(0)
}

/// Circuit binding both children's beta stages.
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
    /// `params` provides the nested-curve generators the beta stage is
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
    /// Witness for the preamble stage (provides the children's `pre_beta`
    /// and beta stage commitments).
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
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let _ = outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;

        let allocator = &mut Standard::new();
        let unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        let generator = C::nested_generators(self.params).g()[generator_index::<C, R>()];
        for child in [&preamble.left, &preamble.right] {
            let pre_beta =
                EndoscalarChallenge::from_element(dr, allocator, child.unified.pre_beta.clone())?;
            let bits = Endoscalar::extract(pre_beta);
            let generator = Point::constant(dr, generator)?;
            bits.group_scale(dr, &generator)?
                .enforce_equal(dr, &child.nested_beta_commitment)?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
