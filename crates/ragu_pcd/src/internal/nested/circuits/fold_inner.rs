//! The first layer of a nested fold verified in chunks.
//!
//! The mirror of the native `fold_inner` circuits. [`collapse`] verifies
//! both layers of the nested fold in one circuit, and its first layer grows
//! with the claims. A profile whose nested fold has more groups than one
//! circuit can verify ([`Chunking`](crate::profile::Chunking)) spreads the
//! groups over these circuits: chunk $j$ takes an equal share of the
//! groups, in order, and for each enforces that folding the group's
//! $k(y_n)$ targets with the `inner_error` stage's error terms under the
//! lifted $\mu$ gives the collapsed value the `outer_error` stage holds,
//! exactly as `collapse` does.
//!
//! The grid of targets is the one `collapse` lays out, in the order
//! [`build`] emits the claims, and a chunk reads its groups' share of it.
//! No target is computed here: the children's $c$ values are the preamble
//! bridge stage's, the targets `collapse` computes are the
//! [`targets`](stages::targets) stage's, which the circuit registered in
//! `collapse`'s place ([`collapse::Targets`](super::collapse::Targets))
//! holds to the values it computes, and every other target is a constant.
//!
//! The circuit ends on the challenge stage, as the instance circuits do,
//! and outputs the nested unified instance, of which it covers no slot.
//!
//! [`collapse`]: super::collapse
//! [`build`]: crate::internal::nested::claims::build

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{
    Element, GadgetExt as _,
    allocator::Standard,
    vec::{FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use super::common;
use crate::{
    internal::{
        nested::{
            FOLD_GROUP_SIZE, NumFoldGroups, RevdotParameters,
            claims::{TwoProofKySource, ky_values},
            fold_chunks, fold_groups,
            stages::{self, challenges},
            unified,
        },
        revdot,
    },
    profile::Profile,
};

/// A first-layer chunk of a nested fold verified in chunks.
pub struct Circuit<C: Affine, R: Rank, P: Profile> {
    chunk: usize,
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Profile> Circuit<C, R, P> {
    /// Creates chunk `chunk` of the fold's first layer.
    ///
    /// # Panics
    ///
    /// Panics if the profile's fold has no such chunk.
    pub fn new(chunk: usize) -> Self {
        assert!(chunk < fold_chunks::<P>(), "no such fold chunk");
        Self {
            chunk,
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> MultiStageCircuit<C::Base, R> for Circuit<C, R, P> {
    type Last = stages::challenges::Stage<C, R, P>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = common::Witness<'source, C, P>;
    type Output = unified::OutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (dr, stages) = common::load_all(dr, &witness)?;

        let allocator = &mut Standard::new();
        let unified = unified::OutputBuilder::new(witness.map(|w| w.instance));

        // The targets, as `collapse` assembles them, read off the stages
        // that hold them.
        let staged = stages::targets::Targets::read::<P>(&stages.targets);
        let side = |pair: &Option<[Element<'dr, D>; 2]>, child: usize| {
            pair.as_ref().map(|pair| pair[child].clone())
        };
        let ky = TwoProofKySource::new(
            dr,
            stages.preamble.left.nested.c.clone(),
            stages.preamble.right.nested.c.clone(),
            staged.unified[0].clone(),
            staged.unified[1].clone(),
            staged.compute_v[0].clone(),
            staged.compute_v[1].clone(),
            side(&staged.online_helper, 0),
            side(&staged.online_helper, 1),
            side(&staged.binding, 0),
            side(&staged.binding, 1),
        );

        // The grid of targets with the fold randomizer's, from the first
        // node of this chunk's first group on.
        let groups = fold_groups::<P>(self.chunk);
        assert!(
            groups.end <= NumFoldGroups::<P>::len(),
            "the chunk's groups are the fold's"
        );
        let zero = Element::zero(dr);
        let mut ky = revdot::randomized::<_, RevdotParameters<P>>(
            ky_values::<P, _>(&ky),
            zero.clone(),
            stages.inner_error.randomizer_c.clone(),
            zero,
        )
        .skip(groups.start * FOLD_GROUP_SIZE);

        // Each group's fold must be the collapsed value witnessed.
        let fold = revdot::ClaimFolder::new(&stages.challenges.pairs[challenges::MU].lift);
        for group in groups {
            let ky = FixedVec::from_fn(|_| ky.next().expect("the grid holds every node"));
            fold.fold_inner::<RevdotParameters<P>>(
                dr,
                &stages.inner_error.error_terms[group],
                &ky,
            )?
            .enforce_equal(dr, &stages.outer_error.collapsed[group])?;
        }

        let (output, instance) = unified.finish(dr, allocator)?;
        Ok(WithAux::new(output, instance))
    }
}
