//! Tests that a [`Vec`] of gadgets is to every driver what an array of the
//! same length is: a routine over `Vec<Element>` of length `N` and the same
//! routine over `[Element; N]` give the same segments and fingerprints, the
//! same wiring polynomial and the same trace.
//!
//! This is what lets a gadget have a run-time length: nothing a driver does
//! with a gadget tells the two apart, and the fingerprint tells two lengths
//! apart.

use alloc::vec::Vec;
use core::marker::PhantomData;

use proptest::prelude::*;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, allocator::Standard};

use crate::{
    Circuit, CircuitExt, WithAux, floor_planner, into_wiring_object,
    metrics::{self, DeepFingerprint, RoutineIdentity},
    polynomials::TestRank,
};

/// What both routines run: the square of each element, each plus the sum
/// of the elements before it and tied to the next element by a constraint.
fn body<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    input: &[Element<'dr, D>],
) -> Result<Vec<Element<'dr, D>>> {
    let mut sum = Element::zero(dr);
    let mut output = Vec::with_capacity(input.len());
    for (index, element) in input.iter().enumerate() {
        let square = element.square(dr)?;
        output.push(square.add(dr, &sum));
        sum = sum.add(dr, element);
        if let Some(next) = input.get(index + 1) {
            square.sub(dr, next).sub(dr, &sum).enforce_zero(dr)?;
        }
    }
    Ok(output)
}

/// The routine over an array of `N` elements.
#[derive(Clone)]
struct OverArray<const N: usize>;

impl<const N: usize> Routine<Fp> for OverArray<N> {
    type Input = [PhantomData<Kind![Fp; Element<'_, _>]>; N];
    type Output = [PhantomData<Kind![Fp; Element<'_, _>]>; N];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(body(dr, &input)?
            .try_into()
            .unwrap_or_else(|_| unreachable!("one output for each input")))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// The routine over a `Vec` of elements, of whatever length it is given.
#[derive(Clone)]
struct OverVec;

impl Routine<Fp> for OverVec {
    type Input = PhantomData<Vec<Kind![Fp; Element<'_, _>]>>;
    type Output = PhantomData<Vec<Kind![Fp; Element<'_, _>]>>;
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        body(dr, &input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// A circuit that allocates `N` elements, calls one of the two routines on
/// them twice, the second time on what the first gave, and ties the last
/// output to the first input.
struct Calls<const N: usize> {
    vec: bool,
}

impl<const N: usize> Circuit<Fp> for Calls<N> {
    type Instance<'source> = ();
    type Witness<'source> = [Fp; N];
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<()>
    where
        Self: 'dr,
    {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, [Fp; N]>,
    ) -> Result<WithAux<(), DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let input = (0..N)
            .map(|index| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[index])))
            .collect::<Result<Vec<_>>>()?;
        let output = if self.vec {
            let first = dr.routine(OverVec, input.clone())?;
            dr.routine(OverVec, first)?
        } else {
            let array = |elements: Vec<Element<'dr, D>>| -> [Element<'dr, D>; N] {
                elements
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("N elements"))
            };
            let first = dr.routine(OverArray::<N>, array(input.clone()))?;
            dr.routine(OverArray::<N>, first)?.to_vec()
        };
        if let (Some(last), Some(first)) = (output.last(), input.first()) {
            last.sub(dr, first).enforce_zero(dr)?;
        }
        Ok(WithAux::new((), D::unit()))
    }
}

/// Each segment's gates, constraints and, for a routine, fingerprint.
fn segments<C: Circuit<Fp>>(circuit: &C) -> Result<Vec<(usize, usize, Option<DeepFingerprint>)>> {
    Ok(metrics::eval(circuit)?
        .segments
        .iter()
        .map(|segment| {
            let fingerprint = match segment.identity() {
                RoutineIdentity::Routine(fingerprint) => Some(*fingerprint),
                RoutineIdentity::Root => None,
            };
            (segment.num_gates(), segment.num_constraints(), fingerprint)
        })
        .collect())
}

/// A digest of the wiring polynomial, as a registry hashes it.
fn wiring<C: Circuit<Fp>>(circuit: C) -> Result<Vec<u8>> {
    let object = into_wiring_object::<Fp, _, TestRank>(circuit)?;
    let plan = floor_planner::floor_plan(object.segment_records());
    let mut state = blake2b_simd::Params::new().to_state();
    object.monomials(&plan).hash_into(&mut state);
    Ok(state.finalize().as_bytes().to_vec())
}

/// The values of each segment's gates.
fn trace<const N: usize>(circuit: &Calls<N>, witness: [Fp; N]) -> Result<Vec<[Vec<Fp>; 4]>> {
    Ok(circuit
        .trace(witness)?
        .into_output()
        .segments
        .iter()
        .map(|segment| {
            [
                segment.a.clone(),
                segment.b.clone(),
                segment.c.clone(),
                segment.d.clone(),
            ]
        })
        .collect())
}

/// Holds a `Vec` of `N` elements to an array of `N`, on every driver.
fn a_vec_is_an_array<const N: usize>(witness: [Fp; N]) -> Result<()> {
    let (array, vec) = (Calls::<N> { vec: false }, Calls::<N> { vec: true });
    let found = segments(&vec)?;
    assert_eq!(found, segments(&array)?);
    // The root and the two calls, which are one routine: at one length, the
    // second call has the fingerprint of the first.
    assert_eq!(found.len(), 3);
    assert_eq!(found[1], found[2]);
    assert_eq!(wiring(Calls::<N> { vec: true })?, wiring(array)?);
    assert_eq!(
        trace(&vec, witness)?,
        trace(&Calls::<N> { vec: false }, witness)?
    );
    Ok(())
}

/// The fingerprint of the routine over a `Vec` of `N` elements.
fn fingerprint<const N: usize>() -> Result<DeepFingerprint> {
    Ok(segments(&Calls::<N> { vec: true })?[1]
        .2
        .expect("a routine's segment"))
}

#[test]
fn a_vec_without_gadgets_is_an_empty_array() -> Result<()> {
    a_vec_is_an_array::<0>([])
}

/// One Rust type, one fingerprint for each length the routine reads: a
/// memo that keys on the fingerprint never takes what the routine emits
/// over a `Vec` of one length for what it emits over another.
///
/// The fingerprint is of what a routine emits and of the wires it gives,
/// not of the wires it takes. The routine here reads every element. One
/// that reads only some of them emits the same over inputs of two lengths
/// and has one fingerprint for both, which a memo may share.
#[test]
fn the_fingerprint_tells_lengths_apart() -> Result<()> {
    let fingerprints = [
        fingerprint::<0>()?,
        fingerprint::<1>()?,
        fingerprint::<2>()?,
        fingerprint::<3>()?,
        fingerprint::<8>()?,
        fingerprint::<9>()?,
    ];
    for (index, a) in fingerprints.iter().enumerate() {
        for b in &fingerprints[index + 1..] {
            assert_ne!(a, b);
        }
    }
    Ok(())
}

fn fp() -> impl Strategy<Value = Fp> {
    any::<u64>().prop_map(Fp::from)
}

proptest! {
    #[test]
    fn proptest_a_vec_of_one_is_an_array(witness in proptest::array::uniform1(fp())) {
        a_vec_is_an_array(witness).unwrap();
    }

    #[test]
    fn proptest_a_vec_of_two_is_an_array(witness in proptest::array::uniform2(fp())) {
        a_vec_is_an_array(witness).unwrap();
    }

    #[test]
    fn proptest_a_vec_of_five_is_an_array(witness in proptest::array::uniform5(fp())) {
        a_vec_is_an_array(witness).unwrap();
    }

    #[test]
    fn proptest_a_vec_of_twelve_is_an_array(witness in proptest::array::uniform12(fp())) {
        a_vec_is_an_array(witness).unwrap();
    }
}
