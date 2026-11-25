//! The stages of an opening program run in chunks.
//!
//! A profile whose `compute_v` is past the rank's gate budget runs its work
//! as a program spread over the [`open`](super::super::circuits::open)
//! circuits (see [`open`](super::super::open)). Two stages serve them,
//! between the preamble and the `query` stage:
//!
//! - [`CarryStage`] holds what the circuits share: the effective $\beta$,
//!   $t(xz)$ and the second layer's interpolation weights, each of which
//!   `compute_v` computes once and enforces here; the online helper's sums;
//!   and the program's state after every chunk, which the chunk that ends
//!   there enforces and the next starts from.
//! - [`BandStage`] holds copies of the `query` and `eval` stages' values
//!   that one circuit reads. A proof carries a polynomial of it per chunk,
//!   and one more for what `compute_v` exports off those stages.
//!
//! Both are committed with the circuits' polynomials. The carry's values
//! are fixed by the circuits' constraints; a band's by its
//! [`open_loading`](super::super::circuits::open_loading) bonding, which
//! holds each copy to the stage wire it copies.
//!
//! Both hold nothing for a profile whose `compute_v` runs the program
//! whole, so the `query` stage follows the preamble as before.

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

use super::super::{
    NumFoldGroups, OpenBandLen, is_opening_chunked, open::State, opening_chunks,
};
use crate::profile::{
    Profile, ProfiledCycle,
    online::stages::{Native, Present},
};

/// The online helper's sums the carry stage holds in profile `P`.
fn num_online_sums<P: Profile>() -> usize {
    Present::<P, Native, 2>::len()
}

/// The carry stage's values, by name.
///
/// The stage holds, in order: the effective $\beta$, $t(xz)$, the online
/// helper's sums, the second layer's weights, one per group, and the
/// program's state after each chunk.
pub struct Carry<'a, T, P: Profile> {
    values: &'a [T],
    _marker: PhantomData<P>,
}

impl<'a, T: Clone, P: Profile> Carry<'a, T, P> {
    /// The values a carry holds in profile `P`.
    pub fn len() -> usize {
        2 + num_online_sums::<P>()
            + NumFoldGroups::<P>::len()
            + opening_chunks::<P>() * State::<T>::LEN
    }

    /// Names the stage's `values`.
    ///
    /// # Panics
    ///
    /// Panics if `values` are not the profile's carry.
    pub fn new(values: &'a [T]) -> Self {
        assert_eq!(values.len(), Self::len(), "the stage holds the carry");
        Carry {
            values,
            _marker: PhantomData,
        }
    }

    /// The effective $\beta$.
    pub fn beta(&self) -> &'a T {
        &self.values[0]
    }

    /// $t(xz)$.
    pub fn txz(&self) -> &'a T {
        &self.values[1]
    }

    /// The online helper's sums.
    pub fn online_fold(&self) -> &'a [T] {
        &self.values[2..2 + num_online_sums::<P>()]
    }

    /// The second layer's interpolation weights, one per group.
    pub fn outer(&self) -> &'a [T] {
        let start = 2 + num_online_sums::<P>();
        &self.values[start..start + NumFoldGroups::<P>::len()]
    }

    /// The program's state after chunk `chunk`.
    ///
    /// # Panics
    ///
    /// Panics if the program has no such chunk.
    pub fn after(&self, chunk: usize) -> State<T> {
        assert!(chunk < opening_chunks::<P>(), "no such opening chunk");
        let start =
            2 + num_online_sums::<P>() + NumFoldGroups::<P>::len() + chunk * State::<T>::LEN;
        State::from_values(&self.values[start..start + State::<T>::LEN])
    }

    /// The carry's values in the stage's order.
    ///
    /// # Panics
    ///
    /// Panics if the parts are not the profile's.
    pub fn assemble(
        beta: T,
        txz: T,
        online_fold: &[T],
        outer: &[T],
        states: &[State<T>],
    ) -> Vec<T> {
        assert_eq!(online_fold.len(), num_online_sums::<P>());
        assert_eq!(outer.len(), NumFoldGroups::<P>::len());
        assert_eq!(states.len(), opening_chunks::<P>());
        let mut values = Vec::with_capacity(Self::len());
        values.push(beta);
        values.push(txz);
        values.extend(online_fold.iter().cloned());
        values.extend(outer.iter().cloned());
        for state in states {
            values.extend(state.values().map(Clone::clone));
        }
        values
    }
}

/// Length type for the carry stage's values in profile `P`: none for a
/// program run whole.
pub struct CarryLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for CarryLen<P> {
    fn len() -> usize {
        if is_opening_chunked::<P>() {
            Carry::<(), P>::len()
        } else {
            0
        }
    }
}

/// The carry stage: what the circuits of an opening program run in chunks
/// share, and the program's state between them.
#[derive(Default)]
pub struct CarryStage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for CarryStage<C, R, HEADER_SIZE>
{
    type Parent = super::preamble::Stage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source [C::CircuitField];
    type OutputKind = Kind![C::CircuitField; FixedVec<Element<'_, _>, CarryLen<C::Profile>>];

    fn values() -> usize {
        CarryLen::<C::Profile>::len()
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
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

/// The band stage: copies of the `query` and `eval` stages' values that
/// one circuit of an opening program run in chunks reads, in the slot order
/// of its [`Schedule`](super::super::open::Schedule) band. Slots past the
/// band's inputs hold zero.
#[derive(Default)]
pub struct BandStage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for BandStage<C, R, HEADER_SIZE>
{
    type Parent = CarryStage<C, R, HEADER_SIZE>;
    type Witness<'source> = &'source [C::CircuitField];
    type OutputKind = Kind![C::CircuitField; FixedVec<Element<'_, _>, OpenBandLen<C::Profile>>];

    fn values() -> usize {
        OpenBandLen::<C::Profile>::len()
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
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::Pasta;

    use super::*;
    use crate::{
        internal::tests::{HEADER_SIZE, R, assert_stage_values},
        profile::{Profiled, Standard, testing::Chunked},
    };

    #[test]
    fn stage_values_match_wire_counts() {
        // Nothing for a program run whole.
        type WholeCarry = CarryStage<Pasta, R, { HEADER_SIZE }>;
        type WholeBand = BandStage<Pasta, R, { HEADER_SIZE }>;
        assert_eq!(<WholeCarry as staging::Stage<_, R>>::values(), 0);
        assert_eq!(<WholeBand as staging::Stage<_, R>>::values(), 0);
        assert_stage_values(&WholeCarry::default());
        assert_stage_values(&WholeBand::default());

        type C = Profiled<Pasta, Chunked>;
        type Carried = CarryStage<C, R, { HEADER_SIZE }>;
        type Banded = BandStage<C, R, { HEADER_SIZE }>;
        assert_eq!(
            <Carried as staging::Stage<_, R>>::values(),
            Carry::<(), Chunked>::len()
        );
        assert_eq!(
            <Banded as staging::Stage<_, R>>::values(),
            Chunked::CHUNKING.native_band
        );
        assert_stage_values(&Carried::default());
        assert_stage_values(&Banded::default());
        let _ = Standard;
    }

    #[test]
    fn a_carry_names_its_values() {
        type P = Chunked;
        let groups = NumFoldGroups::<P>::len();
        let chunks = opening_chunks::<P>();
        let outer: Vec<u32> = (100..100 + groups as u32).collect();
        let states: Vec<State<u32>> = (0..chunks as u32)
            .map(|chunk| State {
                group_a: 1000 * chunk,
                group_b: 1000 * chunk + 1,
                a: 1000 * chunk + 2,
                b: 1000 * chunk + 3,
                f: 1000 * chunk + 4,
                v: 1000 * chunk + 5,
            })
            .collect();
        let values = Carry::<u32, P>::assemble(7, 8, &[], &outer, &states);
        assert_eq!(values.len(), Carry::<u32, P>::len());
        let carry = Carry::<u32, P>::new(&values);
        assert_eq!((*carry.beta(), *carry.txz()), (7, 8));
        assert!(carry.online_fold().is_empty());
        assert_eq!(carry.outer(), outer.as_slice());
        for (chunk, state) in states.iter().enumerate() {
            assert_eq!(&carry.after(chunk), state);
        }
    }
}
