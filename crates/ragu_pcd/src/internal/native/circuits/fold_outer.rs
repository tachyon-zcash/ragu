//! The second layer of a native fold verified in chunks.
//!
//! In a profile whose fold is verified in chunks
//! ([`Chunking`](crate::profile::Chunking)), the
//! [`fold_inner`](super::fold_inner) circuits hold every group's collapsed
//! value in the [`outer_error`] stage to the group's fold. This circuit
//! folds those collapsed values with the stage's outer quotient under
//! $\mu'$ and, outside the base case, enforces the result equal to the
//! unified instance's $c$, exactly as [`collapse`](super::collapse) does
//! for a fold it verifies whole.
//!
//! ## Base case
//!
//! The verdict is the preamble's, as in `collapse`: both input headers
//! carry the dummy suffix. The circuit registered in `collapse`'s place
//! ([`collapse::Targets`](super::collapse::Targets)) pins a step that takes
//! the base case to the bootstrap step, over the same preamble.
//!
//! ## Staging
//!
//! The circuit ends at [`outer_error`], whose final mask it shares with the
//! hash circuits, after the preamble. It reserves the binding stage and
//! the targets stage and reads neither.
//!
//! ## Instance
//!
//! The unified instance: the circuit reads $\mu'$ from it and covers $c$.
//!
//! [`outer_error`]: super::super::stages::outer_error

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
use ragu_primitives::allocator::Standard;

use super::{
    super::{
        stages::{
            outer_error as native_outer_error, points::BindingStage, preamble as native_preamble,
            targets as native_targets,
        },
        unified::{self, OutputBuilder},
    },
    collapse::Witness,
};
use crate::{internal::revdot, profile::ProfiledCycle};

/// The second layer's circuit of a native fold verified in chunks.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    /// Creates the multi-stage circuit.
    ///
    /// # Panics
    ///
    /// Panics if the profile's `collapse` verifies the fold whole.
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        assert!(
            super::super::is_fold_chunked::<C::Profile>(),
            "a fold verified whole is `collapse`'s"
        );
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
    MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, HEADER_SIZE, FP>
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
        let builder = builder.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let builder = builder.skip_stage::<native_targets::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let outer_error =
            outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        let is_base_case = preamble.is_base_case(dr, allocator)?;

        // The fold of the collapsed values is c, outside the base case.
        let mu_prime = unified_output.mu_prime.read(dr, allocator)?;
        let fold_products = revdot::ClaimFolder::new(&mu_prime);
        let computed_c =
            fold_products.fold_outer::<FP>(dr, &outer_error.error_terms, &outer_error.collapsed)?;
        let witnessed_c = unified_output.c.receive(dr, allocator)?;
        is_base_case
            .not(dr)
            .conditional_enforce_equal(dr, allocator, &witnessed_c, &computed_c)?;

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
