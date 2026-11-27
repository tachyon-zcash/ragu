//! Each side's verifier as one circuit, cut into pages.
//!
//! A [`WholeCircuit`] loads the side's stages and runs the side's verifier
//! over them ([`Side::verify`]), as the prover's native run does
//! ([`Prepared::run`]). The lifts and digits the verifier writes are held
//! to their stages' wires, which the other side recomputes. Its public
//! output is the points the side exposes for the proof's consumer: the
//! other side's stage commitments the side absorbed or recomputed and the
//! commitments it took of the step's own online polynomials (see
//! [`Binding`](crate::profile::Binding)).
//!
//! The circuit is an unpaged circuit ([`Pageable`]): it has many times the
//! gates of a polynomial at the rank it is proven at, so the pager cuts it
//! ([`cut`]). Each page is a circuit of the side's extension, with a trace
//! polynomial of its own, and loads every stage of the whole circuit, then
//! the circuit's carry stage ([`CarryStage`]), one more stage of the
//! extension, through which the pages pass values to one another. The last
//! page carries the public output, and so is the extension's binding
//! circuit. How many pages a side takes, and how many values its carry
//! stage holds, is the aggregator profile's to state
//! ([`Side::PAGES`]): each page is a polynomial of the proof. The pages
//! are held to the circuit where a registry is built
//! ([`Pages::check`]), before any is registered, so nothing that chose the
//! cuts is trusted.

use alloc::sync::Arc;
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    paging::{CarryStage, Checked, Pageable, Pages, Planned},
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Point,
    vec::{FixedVec, Len},
};

use super::{
    circuits::{Exposed, Prepared},
    side::Side,
    stages::{DigitsStage, Front, LiftsStage, OnlineInputStage, OnlineQueryStage},
    verifier::{Cells, Run, Tables},
};

/// Side `S`'s verifier as one circuit over the side's stages.
pub(crate) struct WholeCircuit<'p, C: Cycle, S, K, R, const HEADER_SIZE: usize> {
    tables: Arc<Tables>,
    params: &'p C::Params,
    _marker: PhantomData<fn() -> (S, K, R)>,
}

impl<C: Cycle, S, K, R, const HEADER_SIZE: usize> Clone
    for WholeCircuit<'_, C, S, K, R, HEADER_SIZE>
{
    fn clone(&self) -> Self {
        WholeCircuit {
            tables: self.tables.clone(),
            params: self.params,
            _marker: PhantomData,
        }
    }
}

/// A side's whole circuit, as the pager and the registry take it.
pub(crate) type Whole<'p, C, S, K, R, const HEADER_SIZE: usize> =
    MultiStage<<S as Side<C>>::F, R, WholeCircuit<'p, C, S, K, R, HEADER_SIZE>>;

impl<'p, C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    WholeCircuit<'p, C, S, K, R, HEADER_SIZE>
{
    /// The circuit of side `S`'s verifier, laid out by `tables`.
    pub(crate) fn new(
        tables: Arc<Tables>,
        params: &'p C::Params,
    ) -> Whole<'p, C, S, K, R, HEADER_SIZE> {
        MultiStage::new(WholeCircuit {
            tables,
            params,
            _marker: PhantomData,
        })
    }
}

impl<C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    MultiStageCircuit<S::F, R> for WholeCircuit<'_, C, S, K, R, HEADER_SIZE>
{
    type Last = DigitsStage<C, S, K, R, HEADER_SIZE>;
    type Instance<'source> = FixedVec<S::P, Exposed<C, S, K>>;
    type Witness<'source> = &'source Prepared<C, S>;
    type Output = Kind![S::F; FixedVec<Point<'_, _, S::P>, Exposed<C, S, K>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Point::alloc(dr, instance.as_ref().map(|points| points[i])))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, S, R>>()?;
        let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, S, R>>()?;
        let (front, dr) = <S as Front<C, K, R, HEADER_SIZE>>::add(dr)?;
        let (lifts, dr) = dr.add_stage::<LiftsStage<C, S, K, R, HEADER_SIZE>>()?;
        let (digits, dr) = dr.add_stage::<DigitsStage<C, S, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        let online_input =
            online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
        let online_query =
            online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
        let front = <S as Front<C, K, R, HEADER_SIZE>>::load(front, dr, &witness)?;
        let lifts = lifts.unenforced(dr, witness.as_ref().map(|w| &w.lifts))?;
        let digits = digits.unenforced(dr, witness.as_ref().map(|w| &w.digits))?;

        let mut run = Run::new(
            &self.tables,
            front.instance(),
            front.messages(),
            [&online_input.elements[..], &online_query.elements[..]],
            Cells::Loaded(&lifts.elements[..]),
            Cells::Loaded(&digits.elements[..]),
            (
                S::generators(self.params),
                S::u(self.params),
                S::poseidon(self.params),
            ),
            witness,
        );
        let exposed = S::verify::<_, K, HEADER_SIZE>(dr, &mut run)?;
        if exposed.len() != S::exposed::<K>() {
            return Err(Error::InvalidWitness(
                "the side's verifier exposes the side's points".into(),
            ));
        }
        Ok(WithAux::new(FixedVec::try_from(exposed)?, D::unit()))
    }
}

/// The values the carry stage of side `S`'s whole circuit holds: what the
/// aggregator profile pins for the side ([`Side::PAGES`]).
pub(crate) struct Carried<C, S>(PhantomData<fn() -> (C, S)>);

impl<C: Cycle, S: Side<C>> Len for Carried<C, S> {
    fn len() -> usize {
        S::PAGES.carry()
    }
}

/// The carry stage of side `S`'s whole circuit: the last stage every page
/// loads, after the digits stage.
pub(crate) type WholeCarry<C, S, K, R, const HEADER_SIZE: usize> =
    CarryStage<<S as Side<C>>::F, R, DigitsStage<C, S, K, R, HEADER_SIZE>, Carried<C, S>>;

impl<C: Cycle, S: Front<C, K, R, HEADER_SIZE>, K: Rank, R: Rank, const HEADER_SIZE: usize>
    Pageable<S::F, R> for WholeCircuit<'_, C, S, K, R, HEADER_SIZE>
{
    type Carry = Carried<C, S>;
}

/// Side `S`'s whole circuit in pages.
pub(crate) type WholePages<'p, C, S, K, R, const HEADER_SIZE: usize> =
    Pages<<S as Side<C>>::F, R, WholeCircuit<'p, C, S, K, R, HEADER_SIZE>>;

/// Cuts side `S`'s whole circuit into the pages the side pins
/// ([`Side::PAGES`]), in polynomials of rank `R`, over the carry stage the
/// side pins. Where the circuit cuts into fewer, some pages hold no gates
/// of its own, so one count holds for every header size.
///
/// # Errors
///
/// Fails if the side's tables cannot be built or the circuit does not cut
/// into those pages over that carry stage.
pub(crate) fn cut<'p, C, S, K, R, const HEADER_SIZE: usize>(
    params: &'p C::Params,
) -> Result<WholePages<'p, C, S, K, R, HEADER_SIZE>>
where
    C: Cycle,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    let tables = super::verifier::tables::<C, S, K, R, HEADER_SIZE>()?;
    let circuit = WholeCircuit::<C, S, K, R, HEADER_SIZE>::new(tables, params);
    match Pages::cut(circuit, S::PAGES.num_pages()) {
        Err(Error::GateBoundExceeded { limit }) => Err(Error::Initialization(
            alloc::format!(
                "the decompression's {:?} leave its whole circuit too little room, in \
                 polynomials of {limit} gates",
                S::PAGES
            )
            .into(),
        )),
        cut => cut,
    }
}

/// The pages of side `S`'s whole circuit, held to the circuit: what a
/// registry build registers, each page at its extension circuit. A build
/// cuts and checks a side once.
///
/// # Errors
///
/// Fails as [`cut`] does, or if the pages are not the circuit's.
pub(crate) fn checked<'p, C, S, K, R, const HEADER_SIZE: usize>(
    params: &'p C::Params,
) -> Result<Checked<S::F, R, WholeCircuit<'p, C, S, K, R, HEADER_SIZE>>>
where
    C: Cycle,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    cut::<C, S, K, R, HEADER_SIZE>(params)?.check()
}

/// Side `S`'s whole circuit in the pages `planned` holds, which the
/// registry build cut it into, for a prover to trace: the circuit is not
/// cut again. Without them it is cut here.
///
/// # Errors
///
/// Fails if the side's tables cannot be built, or as [`cut`] does.
pub(crate) fn planned<'p, C, S, K, R, const HEADER_SIZE: usize>(
    params: &'p C::Params,
    planned: Option<&Planned<S::F>>,
) -> Result<WholePages<'p, C, S, K, R, HEADER_SIZE>>
where
    C: Cycle,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    let Some(planned) = planned else {
        return cut::<C, S, K, R, HEADER_SIZE>(params);
    };
    let tables = super::verifier::tables::<C, S, K, R, HEADER_SIZE>()?;
    let circuit = WholeCircuit::<C, S, K, R, HEADER_SIZE>::new(tables, params);
    Ok(Pages::planned(circuit, planned))
}
