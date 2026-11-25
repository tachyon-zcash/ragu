//! Targets stage for a nested fold verified in chunks.
//!
//! The mirror of the native targets stage: [`collapse`] verifies the first
//! layer of the nested fold group by group, and a profile whose fold has
//! more groups than one circuit can verify
//! ([`Chunking`](crate::profile::Chunking)) spreads the groups over the
//! [`fold_inner`] circuits. The targets that are not constants `collapse`
//! computes from the preamble bridge stage's copies; this stage carries
//! them to the chunks: the circuit registered in `collapse`'s place
//! enforces each equal to the value it computes, and a chunk reads it
//! here.
//!
//! The values are fixed by that circuit's constraints, so the stage is
//! committed with the circuits' polynomials and needs no place in the
//! transcript. It follows the boundaries stage and precedes the bridge
//! stages, so every instance circuit reserves it.
//!
//! The stage holds nothing for a fold `collapse` verifies whole.
//!
//! [`collapse`]: crate::internal::nested::circuits::collapse
//! [`fold_inner`]: crate::internal::nested::circuits::fold_inner

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use crate::profile::{
    Profile,
    online::stages::{Nested, helper},
};

/// The targets the stage holds for a profile whose fold is verified in
/// chunks: each child's nested unified target and `compute_v` target, and
/// each child's target of every one of the online batch's helper and the
/// binding circuit that the profile has.
pub fn num_targets<P: Profile>() -> usize {
    let extension = crate::profile::nested_extension::<P>();
    4 + 2 * (helper::<P, Nested>().is_some() as usize + extension.binding.is_some() as usize)
}

/// Length type for the stage's values in profile `P`: [`num_targets`] for
/// a fold verified in chunks, and none for a fold `collapse` verifies
/// whole.
pub struct TargetsLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for TargetsLen<P> {
    fn len() -> usize {
        if crate::internal::nested::is_fold_chunked::<P>() {
            num_targets::<P>()
        } else {
            0
        }
    }
}

/// The stage's values by name, in the stage's order: the left child's
/// before the right child's in each pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Targets<T> {
    /// The children's nested unified targets, the `collapse` claims'.
    pub unified: [T; 2],
    /// The children's `compute_v` claims' targets.
    pub compute_v: [T; 2],
    /// The children's online helpers' targets, in a profile with one.
    pub online_helper: Option<[T; 2]>,
    /// The children's binding circuits' targets, in a profile with one.
    pub binding: Option<[T; 2]>,
}

impl<T: Clone> Targets<T> {
    /// Names the stage's `values`, in profile `P`.
    ///
    /// # Panics
    ///
    /// Panics if `values` are not the profile's [`num_targets`].
    pub fn read<P: Profile>(values: &[T]) -> Self {
        assert_eq!(
            values.len(),
            num_targets::<P>(),
            "the stage holds the profile's targets"
        );
        let extension = crate::profile::nested_extension::<P>();
        let mut pairs = values
            .chunks(2)
            .map(|pair| [pair[0].clone(), pair[1].clone()]);
        let unified = pairs.next().expect("the unified targets");
        let compute_v = pairs.next().expect("the compute_v targets");
        let mut pair = |present: bool| present.then(|| pairs.next().expect("a pair per target"));
        Targets {
            unified,
            compute_v,
            online_helper: pair(helper::<P, Nested>().is_some()),
            binding: pair(extension.binding.is_some()),
        }
    }

    /// The stage's values, in the stage's order.
    pub fn into_values(self) -> Vec<T> {
        let mut values = Vec::with_capacity(8);
        values.extend(self.unified);
        values.extend(self.compute_v);
        for pair in [self.online_helper, self.binding].into_iter().flatten() {
            values.extend(pair);
        }
        values
    }
}

/// The targets stage of the nested fuse witness.
pub struct Stage<C: Affine, P: Profile> {
    _marker: PhantomData<(C, P)>,
}

impl<C: Affine, P: Profile> Default for Stage<C, P> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Profile> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, P> {
    type Parent = super::boundaries::Stage<C, P>;
    type Witness<'source> = &'source super::outer_error::Witness<C, P>;
    type OutputKind = Kind![C::Base; FixedVec<Element<'_, _>, TargetsLen<P>>];

    fn values() -> usize {
        TargetsLen::<P>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let allocator = &mut ();
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, allocator, witness.as_ref().map(|w| w.targets[i]))
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::EqAffine;

    use super::*;
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::{Standard, testing::Chunked},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        // Nothing for a fold verified whole.
        assert_eq!(
            <Stage<EqAffine, Standard> as ragu_circuits::staging::Stage<_, R>>::values(),
            0
        );
        assert_stage_values::<_, R, _>(&Stage::<EqAffine, Standard>::default());
        assert_eq!(
            <Stage<EqAffine, Chunked> as ragu_circuits::staging::Stage<_, R>>::values(),
            4
        );
        assert_stage_values::<_, R, _>(&Stage::<EqAffine, Chunked>::default());
    }

    #[test]
    fn targets_round_trip_in_stage_order() {
        let values = [1u8, 2, 3, 4];
        let named = Targets::read::<Chunked>(&values);
        assert_eq!(named.unified, [1, 2]);
        assert_eq!(named.compute_v, [3, 4]);
        assert!(named.online_helper.is_none() && named.binding.is_none());
        assert_eq!(named.into_values(), values);

        let all = Targets {
            unified: [0u8, 1],
            compute_v: [2, 3],
            online_helper: Some([4, 5]),
            binding: Some([6, 7]),
        };
        assert_eq!(all.into_values(), [0, 1, 2, 3, 4, 5, 6, 7]);
    }
}
