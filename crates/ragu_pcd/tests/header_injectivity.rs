//! Headers whose encoding is not injective, kept as demonstrations of the
//! contract stated on [`Header`].
//!
//! A proof commits only to the field elements of its header, and verifiers
//! bind a [`Pcd`](crate::Pcd)'s data to them by recomputing the encoding from
//! that data. Anyone can attach other data to a proof with
//! [`Proof::carry`](crate::Proof::carry); only the encoding ties the two
//! together. Each header here is buggy on purpose: two distinct values of its
//! `Data` encode to the same field elements, so an honest proof of one
//! verifies when it carries the other.
//!
//! The tests assert that both verifiers accept the relabelled data. That is
//! the expected behavior, not a verifier bug. Ragu cannot tell such values
//! apart, and keeping the encoding injective is the application's obligation.
//! The constraints `encode` emits do not help: `PackedNote` collides two
//! values that both satisfy them, so a verifier that checked them would still
//! accept. Each header's documentation names the `Data` type that avoids its
//! collision.

use core::marker::PhantomData;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Pasta},
    routines::{Prediction, Routine},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::{
    ApplicationBuilder,
    header::{Header, Padding, Suffix},
    internal::ky::output_header,
    step::{Encoded, Index, Oracles, Step},
};

const HEADER_SIZE: usize = 4;

/// Packs a flag and an amount into one element as `2 * amount + flag`. The
/// flag is constrained boolean by `encode`; the amount is unconstrained.
///
/// `Data` is two field elements, so it holds values the encoding confuses: the
/// sum wraps around the field, and every header has a preimage for any flag.
/// With `Data = (bool, u64)` the sum stays below the modulus and determines
/// both values.
struct PackedNote;

impl Header<Fp> for PackedNote {
    const SUFFIX: Suffix = Suffix::new(1);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = (Fp, Fp);
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (flag, amount) = witness.cast();
        let flag = Element::alloc(dr, allocator, flag)?;
        let amount = Element::alloc(dr, allocator, amount)?;
        flag.square(dr)?.sub(dr, &flag).enforce_zero(dr)?;
        Ok(amount.double(dr).add(dr, &flag))
    }
}

/// Returns its input, constrained boolean. Its `Known` prediction, the input's
/// square, agrees with `execute` on booleans, the only inputs `execute`
/// accepts, so the routine itself is correct. On any other input a driver that
/// takes the prediction still receives an output, which is what
/// [`RoutineNote`] trips over.
#[derive(Clone)]
struct PredictedBoolean;

impl Routine<Fp> for PredictedBoolean {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        input.square(dr)?.sub(dr, &input).enforce_zero(dr)?;
        Ok(input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        dr: &mut D,
        input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let square = Element::alloc(dr, &mut (), input.value().map(|value| value.square()))?;
        Ok(Prediction::Known(square, D::unit()))
    }
}

/// Encodes a field element through [`PredictedBoolean`].
///
/// The circuit accepts only 0 and 1, but `Data` is a field element, and
/// verifiers take the routine's prediction in place of executing it, so `-1`
/// encodes to the header of `1`. The fault is the `Data` type, not the
/// routine: with `Data = bool` there is no second value to confuse.
struct RoutineNote;

impl Header<Fp> for RoutineNote {
    const SUFFIX: Suffix = Suffix::new(2);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let value = Element::alloc(dr, allocator, witness)?;
        dr.routine(PredictedBoolean, value)
    }
}

/// Seeds a proof of `H` from its data.
struct Seed<H>(PhantomData<H>);

impl<H: Header<Fp>> Step<Pasta> for Seed<H> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = H::Data;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = H;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, H::Data>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, H, HS>,
        ),
        DriverValue<D, H::Data>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::new(dr, allocator, witness.clone())?;
        Ok(((left, right, output), witness, D::unit()))
    }
}

/// Proves `honest` with [`Seed`], then attaches each of `forged` to the proof
/// in place of the data it was constructed for, and asserts that both
/// verifiers accept the result.
///
/// No part of the proof is modified. Each forged value is first checked to
/// encode, as verifiers recompute the header, to the honest header; that
/// collision is the whole attack.
fn assert_relabelled_data_verifies<H: Header<Fp>>(
    honest: H::Data,
    forged: &[H::Data],
) -> Result<()> {
    let header = output_header::<Pasta, H, HEADER_SIZE>(honest.clone())?;

    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(Seed::<H>(PhantomData))?
        .finalize(crate::pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x908_f1d);

    let (pcd, ()) = app.seed(&mut rng, Seed::<H>(PhantomData), honest)?;
    assert!(app.verify_uncompressed(&pcd, &mut rng)?);
    let compressed = app.compress(&pcd, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);

    for data in forged {
        assert_eq!(
            output_header::<Pasta, H, HEADER_SIZE>(data.clone())?,
            header
        );
        let relabelled = pcd.proof().clone().carry::<H>(data.clone());
        assert!(app.verify_uncompressed(&relabelled, &mut rng)?);
        let relabelled = compressed.proof().clone().carry::<H>(data.clone());
        assert!(app.verify_compressed(&relabelled)?);
    }
    Ok(())
}

/// A proof of `(1, 1000)` verifies carrying `(1 - 2k, 1000 + k)` for any `k`,
/// since both encode to `2001`.
///
/// With `k = 1_000_000` the flag is not boolean, so the circuit would reject
/// the data, but verifiers do not check `encode`'s constraints. With `k = 1/2`
/// the flag is 0 and the data satisfies them, so checking them would not help:
/// the encoding is not injective even on data the circuit accepts. Only a
/// `Data` type that cannot hold either value, `(bool, u64)`, rules them out.
#[test]
fn packed_note_accepts_relabelled_data() -> Result<()> {
    let k = Fp::from(1_000_000);
    let half = Fp::from(2)
        .invert()
        .ok_or_else(|| Error::InvalidWitness("2 is invertible".into()))?;
    assert_relabelled_data_verifies::<PackedNote>(
        (Fp::ONE, Fp::from(1000)),
        &[
            (Fp::ONE - k.double(), Fp::from(1000) + k),
            (Fp::ZERO, Fp::from(1000) + half),
        ],
    )
}

/// A proof of `1` verifies carrying `-1`. The circuit rejects `-1`, but
/// verifiers encode it through the routine's prediction, `(-1)^2 = 1`, to the
/// honest header.
#[test]
fn routine_note_accepts_relabelled_data() -> Result<()> {
    assert_relabelled_data_verifies::<RoutineNote>(Fp::ONE, &[-Fp::ONE])
}
