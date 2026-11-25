//! Targets stage for a native fold verified in chunks.
//!
//! [`collapse`] verifies the first layer of the fold group by group: it
//! folds each group's $k(y)$ targets with the group's quotient. A profile
//! whose fold has more groups than one circuit can verify
//! ([`Chunking`](crate::profile::Chunking)) spreads the groups over the
//! [`fold_inner`] circuits. Most targets are constants or values of the
//! [`outer_error`] stage, which those circuits read themselves; the rest
//! `collapse` computes from the preamble and the binding stage, and this
//! stage carries them to the chunks: `collapse` enforces each equal to the
//! value it computes, and a chunk reads it here.
//!
//! The values are fixed by `collapse`'s constraints over stages committed
//! before $y$, so the stage is committed with the circuits' polynomials and
//! needs no place in the transcript. It precedes [`outer_error`] in the
//! chain so that `collapse` and the circuits of the second layer end under
//! that stage's final mask and the chunks under [`inner_error`]'s.
//!
//! The stage holds nothing for a fold `collapse` verifies whole.
//!
//! [`collapse`]: super::super::circuits::collapse
//! [`fold_inner`]: super::super::circuits::fold_inner
//! [`outer_error`]: super::outer_error
//! [`inner_error`]: super::inner_error

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{FixedVec, Len},
};

use crate::{
    internal::revdot,
    profile::{
        Profile, ProfiledCycle,
        online::stages::{Native, helper},
    },
};

/// The targets the stage holds for a profile whose fold is verified in
/// chunks: the step's own application target, each child's
/// `bind_endoscalar` target, and each child's target of every one of the
/// statement circuit, the binding circuit and the online batch's helper
/// that the profile has.
pub fn num_targets<P: Profile>() -> usize {
    let extension = crate::profile::native_extension::<P>();
    3 + 2
        * (extension.statement.is_some() as usize
            + extension.binding.is_some() as usize
            + helper::<P, Native>().is_some() as usize)
}

/// Length type for the stage's values in profile `P`: [`num_targets`] for
/// a fold verified in chunks, and none for a fold `collapse` verifies
/// whole.
pub struct TargetsLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for TargetsLen<P> {
    fn len() -> usize {
        if super::super::is_fold_chunked::<P>() {
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
    /// The step's own application claim's target.
    pub application: T,
    /// The children's `bind_endoscalar` claims' targets.
    pub bind_endoscalar: [T; 2],
    /// The children's statement circuits' targets, in a profile with one.
    pub statement: Option<[T; 2]>,
    /// The children's binding circuits' targets, in a profile with one.
    pub binding: Option<[T; 2]>,
    /// The children's online helpers' targets, in a profile with one.
    pub online_helper: Option<[T; 2]>,
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
        let extension = crate::profile::native_extension::<P>();
        let mut pairs = values[3..]
            .chunks(2)
            .map(|pair| [pair[0].clone(), pair[1].clone()]);
        let mut pair = |present: bool| present.then(|| pairs.next().expect("a pair per target"));
        Targets {
            application: values[0].clone(),
            bind_endoscalar: [values[1].clone(), values[2].clone()],
            statement: pair(extension.statement.is_some()),
            binding: pair(extension.binding.is_some()),
            online_helper: pair(helper::<P, Native>().is_some()),
        }
    }

    /// The stage's values, in the stage's order.
    pub fn into_values(self) -> Vec<T> {
        let mut values = Vec::with_capacity(9);
        values.push(self.application);
        values.extend(self.bind_endoscalar);
        for pair in [self.statement, self.binding, self.online_helper]
            .into_iter()
            .flatten()
        {
            values.extend(pair);
        }
        values
    }
}

/// The targets stage of the fuse witness.
#[derive(Default)]
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, FP: revdot::Parameters> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, FP: revdot::Parameters>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, FP>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source super::outer_error::Witness<C, FP>;
    type OutputKind = Kind![C::CircuitField; FixedVec<Element<'_, _>, TargetsLen<C::Profile>>];

    fn values() -> usize {
        TargetsLen::<C::Profile>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
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
    use ragu_core::pasta::Pasta;

    use super::*;
    use crate::{
        internal::{
            native::RevdotParameters,
            tests::{HEADER_SIZE, R, assert_stage_values},
        },
        profile::{Profiled, Standard, testing::Chunked},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        // Nothing for a fold verified whole.
        type Whole = Stage<Pasta, R, { HEADER_SIZE }, RevdotParameters<Standard>>;
        assert_eq!(<Whole as staging::Stage<_, R>>::values(), 0);
        assert_stage_values(&Whole::default());

        type Cut = Stage<Profiled<Pasta, Chunked>, R, { HEADER_SIZE }, RevdotParameters<Chunked>>;
        assert_eq!(<Cut as staging::Stage<_, R>>::values(), 3);
        assert_stage_values(&Cut::default());
    }

    #[test]
    fn targets_round_trip_in_stage_order() {
        let values = [7u8, 1, 2];
        let named = Targets::read::<Chunked>(&values);
        assert_eq!(named.application, 7);
        assert_eq!(named.bind_endoscalar, [1, 2]);
        assert!(named.statement.is_none() && named.binding.is_none());
        assert!(named.online_helper.is_none());
        assert_eq!(named.into_values(), values);

        let all = Targets {
            application: 0u8,
            bind_endoscalar: [1, 2],
            statement: Some([3, 4]),
            binding: Some([5, 6]),
            online_helper: Some([7, 8]),
        };
        assert_eq!(all.into_values(), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
