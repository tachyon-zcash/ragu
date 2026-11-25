//! The first layer of a native fold verified in chunks.
//!
//! [`collapse`](super::collapse) verifies both layers of the fold in one
//! circuit, a group of claims at a time. Its first layer grows with the
//! claims, and a profile whose proofs carry many polynomials has more
//! groups than one circuit can verify within the rank's gate budget. Such a
//! profile ([`Chunking`](crate::profile::Chunking)) spreads the groups over
//! these circuits: chunk $j$ takes an equal share of the groups, in order,
//! and for each enforces that folding the group's $k(y)$ targets with the
//! [`inner_error`] stage's quotient under $\mu$ gives the collapsed value
//! the [`outer_error`] stage holds, exactly as `collapse` does.
//!
//! ## Targets
//!
//! The grid of targets is the one `collapse` lays out, in the order
//! [`build`](super::super::claims::build) emits the claims, and a chunk
//! reads its groups' share of it. No target is computed here:
//!
//! - the children's $c$ values are the preamble's;
//! - the unified targets are the [`outer_error`] stage's, which
//!   [`hashes_1`](super::hashes_1) enforces;
//! - the targets `collapse` computes are the [`targets`] stage's, which the
//!   circuit registered in `collapse`'s place
//!   ([`collapse::Targets`](super::collapse::Targets)) holds to the values
//!   it computes;
//! - every other target is a constant.
//!
//! ## Staging
//!
//! The circuit ends at [`inner_error`], under whose final mask the chunks
//! sit, after the preamble, the [`targets`] stage and [`outer_error`]. It
//! reserves the binding stage, the root of the native stage tree, and reads
//! none of it.
//!
//! ## Instance
//!
//! The unified instance, as `collapse`'s: the chunk reads $\mu$ from it and
//! covers no slot.
//!
//! [`inner_error`]: super::super::stages::inner_error
//! [`outer_error`]: super::super::stages::outer_error
//! [`targets`]: super::super::stages::targets

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
use ragu_primitives::{
    Element, GadgetExt as _,
    allocator::Standard,
    vec::{FixedVec, Len},
};

use super::{
    super::{
        claims::{TwoProofKySource, ky_values},
        fold_groups,
        stages::{
            inner_error as native_inner_error, outer_error as native_outer_error,
            points::BindingStage, preamble as native_preamble, targets as native_targets,
        },
        unified::{self, OutputBuilder},
    },
    collapse::Witness,
};
use crate::{internal::revdot, profile::ProfiledCycle};

/// A first-layer chunk of a native fold verified in chunks.
pub struct Circuit<C: Cycle, R, const HEADER_SIZE: usize, FP: revdot::Parameters> {
    chunk: usize,
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
    Circuit<C, R, HEADER_SIZE, FP>
{
    /// Creates chunk `chunk` of the fold's first layer.
    ///
    /// # Panics
    ///
    /// Panics if the profile's fold has no such chunk.
    pub fn new(chunk: usize) -> MultiStage<C::CircuitField, R, Self> {
        assert!(
            chunk < super::super::fold_chunks::<C::Profile>(),
            "no such fold chunk"
        );
        MultiStage::new(Circuit {
            chunk,
            _marker: PhantomData,
        })
    }
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
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
        let builder = builder.skip_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, builder) =
            builder.add_stage::<native_preamble::Stage<C, R, HEADER_SIZE>>()?;
        let (staged, builder) =
            builder.add_stage::<native_targets::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (outer_error, builder) =
            builder.add_stage::<native_outer_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let (inner_error, builder) =
            builder.add_stage::<native_inner_error::Stage<C, R, HEADER_SIZE, FP>>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;
        let staged = staged.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;
        let outer_error =
            outer_error.unenforced(dr, witness.as_ref().map(|w| w.outer_error_witness))?;
        let inner_error =
            inner_error.enforced(dr, witness.as_ref().map(|w| w.inner_error_witness))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let mu = unified_output.mu.read(dr, allocator)?;
        let fold_products = revdot::ClaimFolder::new(&mu);

        // The targets, as `collapse` assembles them, read off the stages
        // that hold them.
        let staged = native_targets::Targets::read::<C::Profile>(&staged);
        let side = |pair: &Option<[Element<'dr, D>; 2]>, child: usize| {
            pair.as_ref().map(|pair| pair[child].clone())
        };
        let ky = TwoProofKySource::new(
            dr,
            preamble.left.unified.c.clone(),
            preamble.right.unified.c.clone(),
            staged.application.clone(),
            &outer_error.left,
            &outer_error.right,
            side(&staged.statement, 0),
            side(&staged.statement, 1),
            side(&staged.binding, 0),
            side(&staged.binding, 1),
            staged.bind_endoscalar[0].clone(),
            staged.bind_endoscalar[1].clone(),
            side(&staged.online_helper, 0),
            side(&staged.online_helper, 1),
        );

        // The grid of targets with the fold randomizer's, from the first
        // node of this chunk's first group on.
        let groups = fold_groups::<C::Profile>(self.chunk);
        assert!(
            groups.end <= FP::NumGroups::len(),
            "the chunk's groups are the fold's"
        );
        let zero = Element::zero(dr);
        let mut ky = revdot::randomized::<_, FP>(
            ky_values::<C::Profile, _>(&ky),
            zero.clone(),
            inner_error.randomizer_c.clone(),
            zero,
        )
        .skip(groups.start * FP::GroupSize::len());

        // Each group's fold must be the collapsed value the outer error
        // stage holds.
        for group in groups {
            let ky = FixedVec::from_fn(|_| ky.next().expect("the grid holds every node"));
            fold_products
                .fold_inner::<FP>(dr, &inner_error.error_terms[group], &ky)?
                .enforce_equal(dr, &outer_error.collapsed[group])?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
