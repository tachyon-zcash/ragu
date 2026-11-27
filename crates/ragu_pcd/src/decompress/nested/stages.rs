//! The scalar-field side's front stages: one stage per run of the
//! compression's transcript ([`RunStage`]), holding the instance's and the
//! messages' values the run covers, committed with a zero alpha for the
//! circuit-field side's transcript to absorb, then the trailing stage
//! ([`TrailingStage`]) with the nested IPA's $c$, the one value no run
//! covers ([`Front`]).

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

#[cfg(test)]
use ragu_circuits::MaskObject;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::{Stage, StageBuilder, StageExt, StageGuard},
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    super::{
        common::{Prepared, View},
        stages::{
            Front, Layout, MESSAGE_SCALARS, OnlineQueryStage, Output, Run, Span, StageShape,
            Values, message_points, no_such_stage, num_runs, runs,
        },
    },
    Nested,
};
use crate::{
    compress::{instance::OPENED, revdot::fold::Derived},
    ipa::IpaCycle,
    profile::{MaskSlot, ProfiledCycle, Registered, Standard},
};

/// Which of the scalar-field side's logical stages a run's values sit in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Where {
    Instance,
    Messages,
}

/// Where a stage of the scalar-field side's front takes its values: the
/// positions of its points and of its elements within the instance's or
/// the messages' ([`Layout`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RunSource {
    pub points: Option<(Where, Span)>,
    pub elements: Option<(Where, Span)>,
}

impl RunSource {
    /// The stage's shape.
    pub(crate) fn shape(&self) -> StageShape {
        StageShape {
            points: self.points.map_or(0, |(_, span)| span.len),
            elements: self.elements.map_or(0, |(_, span)| span.len),
        }
    }

    /// The `i`-th point of the stage, from `instance` and `messages`.
    fn point<F, P: Copy>(&self, instance: &Values<F, P>, messages: &Values<F, P>, i: usize) -> P {
        let (at, span) = self.points.expect("the stage holds points");
        match at {
            Where::Instance => instance.points[span.at(i)],
            Where::Messages => messages.points[span.at(i)],
        }
    }

    /// The `i`-th element of the stage.
    fn element<F: Copy, P>(&self, instance: &Values<F, P>, messages: &Values<F, P>, i: usize) -> F {
        let (at, span) = self.elements.expect("the stage holds elements");
        match at {
            Where::Instance => instance.elements[span.at(i)],
            Where::Messages => messages.elements[span.at(i)],
        }
    }
}

impl Run {
    /// Where the run's values sit in `layout`, the scalar-field side's.
    pub(crate) fn source(self, layout: &Layout) -> RunSource {
        use message_points::*;
        let instance = layout.instance;
        let messages = layout.messages;
        let points = |start: usize, len: usize| RunSource {
            points: Some((
                Where::Messages,
                Span {
                    start: messages.points_of_curve.start + start,
                    len,
                },
            )),
            elements: None,
        };
        let elements = |start: usize, len: usize| RunSource {
            points: None,
            elements: Some((
                Where::Messages,
                Span {
                    start: messages.scalars.start + start,
                    len,
                },
            )),
        };
        match self {
            Run::Commitments => RunSource {
                points: Some((Where::Instance, instance.commitments)),
                elements: None,
            },
            Run::Scalars => RunSource {
                points: None,
                elements: Some((Where::Instance, instance.scalars)),
            },
            Run::Inner => points(INNER, 1),
            Run::Outer => points(OUTER, 1),
            Run::Split => points(P, 2),
            Run::F => points(F, 1),
            Run::SCommitment => points(S_COMMITMENT, 1),
            Run::Round(j) => points(l(j), 2),
            Run::Epsilons => elements(0, 2),
            Run::Openings => elements(2, Derived::ALL.len() + 2),
            Run::Evaluations => elements(4 + Derived::ALL.len(), Derived::ALL.len() + 2 + OPENED),
        }
    }
}

/// Where the scalar-field side's trailing stage takes its value: the
/// nested IPA's $c$, the last of the messages' scalars.
pub(crate) fn trailing_source(layout: &Layout) -> RunSource {
    RunSource {
        points: None,
        elements: Some((
            Where::Messages,
            Span {
                start: layout.messages.scalars.start + MESSAGE_SCALARS - 1,
                len: 1,
            },
        )),
    }
}

/// The scalar-field side's front, by source: the runs' stages in order,
/// then the trailing stage.
pub(crate) fn nested_front<K: Rank>(layout: &Layout) -> Vec<RunSource> {
    runs::<K>()
        .into_iter()
        .map(|run| run.source(layout))
        .chain([trailing_source(layout)])
        .collect()
}

/// The scalar-field side's front stages' values as its verifier reads them,
/// the instance's and the messages', filled stage by stage at the
/// positions each stage's values take ([`RunSource`]).
pub(crate) struct FrontSlots<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    instance_points: Vec<Option<Point<'dr, D, P>>>,
    instance_elements: Vec<Option<Element<'dr, D>>>,
    messages_points: Vec<Option<Point<'dr, D, P>>>,
    messages_elements: Vec<Option<Element<'dr, D>>>,
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> FrontSlots<'dr, D, P> {
    /// Every position of `layout`'s instance and messages, unfilled.
    fn new(layout: &Layout) -> Self {
        FrontSlots {
            instance_points: vec![None; layout.instance.points],
            instance_elements: vec![None; layout.instance.elements],
            messages_points: vec![None; layout.messages.points],
            messages_elements: vec![None; layout.messages.elements],
        }
    }

    /// Fills the positions `source` names with a stage's `output`.
    fn place<LP: Len, LE: Len>(
        &mut self,
        source: &RunSource,
        output: Output<'dr, D, P, LP, LE>,
    ) -> Result<()> {
        let points = output.points.into_inner();
        let elements = output.elements.into_inner();
        match source.points {
            Some((at, span)) => {
                let slots = match at {
                    Where::Instance => &mut self.instance_points,
                    Where::Messages => &mut self.messages_points,
                };
                if points.len() != span.len {
                    return Err(Error::InvalidWitness(
                        "a stage's points fit its span".into(),
                    ));
                }
                for (i, point) in points.into_iter().enumerate() {
                    slots[span.at(i)] = Some(point);
                }
            }
            None if points.is_empty() => {}
            None => return Err(Error::InvalidWitness("a stage without points".into())),
        }
        match source.elements {
            Some((at, span)) => {
                let slots = match at {
                    Where::Instance => &mut self.instance_elements,
                    Where::Messages => &mut self.messages_elements,
                };
                if elements.len() != span.len {
                    return Err(Error::InvalidWitness(
                        "a stage's elements fit its span".into(),
                    ));
                }
                for (i, element) in elements.into_iter().enumerate() {
                    slots[span.at(i)] = Some(element);
                }
            }
            None if elements.is_empty() => {}
            None => return Err(Error::InvalidWitness("a stage without elements".into())),
        }
        Ok(())
    }

    /// The front, every position filled.
    fn finish(self) -> Result<FrontLoaded<'dr, D, P>> {
        fn all<T>(slots: Vec<Option<T>>) -> Result<Vec<T>> {
            slots
                .into_iter()
                .map(|slot| {
                    slot.ok_or_else(|| {
                        Error::InvalidWitness("the front stages fill every position".into())
                    })
                })
                .collect()
        }
        Ok(FrontLoaded {
            instance_points: all(self.instance_points)?,
            instance_elements: all(self.instance_elements)?,
            messages_points: all(self.messages_points)?,
            messages_elements: all(self.messages_elements)?,
        })
    }
}

/// A side's front stages loaded: the instance's and the messages' wires
/// at the layout's positions, whichever stages hold them.
pub(crate) struct FrontLoaded<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    pub instance_points: Vec<Point<'dr, D, P>>,
    pub instance_elements: Vec<Element<'dr, D>>,
    pub messages_points: Vec<Point<'dr, D, P>>,
    pub messages_elements: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> FrontLoaded<'dr, D, P> {
    /// The instance as the side's verifier reads it.
    pub(crate) fn instance(&self) -> View<'_, 'dr, D, P> {
        View {
            points: &self.instance_points,
            elements: &self.instance_elements,
        }
    }

    /// The messages as the side's verifier reads it.
    pub(crate) fn messages(&self) -> View<'_, 'dr, D, P> {
        View {
            points: &self.messages_points,
            elements: &self.messages_elements,
        }
    }
}

impl<C, K, R, const HEADER_SIZE: usize> Front<C, K, R, HEADER_SIZE> for Nested
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    type Last = TrailingStage<C, K, R>;

    fn stages() -> usize {
        num_runs::<K>() + 1
    }

    fn register_stage_mask<'params>(
        index: usize,
        slot: MaskSlot<'params, Self::F, R>,
    ) -> Result<Registered<'params, Self::F, R>> {
        if index < num_runs::<K>() {
            K::Last::register_stage_mask::<C, K, R>(index, slot)
        } else if index == num_runs::<K>() {
            slot.register_stage_mask::<TrailingStage<C, K, R>>()
        } else {
            no_such_stage()
        }
    }

    #[cfg(test)]
    fn stage_mask(index: usize) -> Result<MaskObject<R>> {
        if index < num_runs::<K>() {
            K::Last::stage_mask::<C, K, R>(index)
        } else if index == num_runs::<K>() {
            TrailingStage::<C, K, R>::stage_mask()
        } else {
            no_such_stage()
        }
    }

    fn rx(
        index: usize,
        alpha: Self::F,
        prepared: &Prepared<C, Self>,
    ) -> Result<sparse::Polynomial<Self::F, R>> {
        if index < num_runs::<K>() {
            K::Last::rx::<C, K, R>(index, prepared)
        } else if index == num_runs::<K>() {
            TrailingStage::<C, K, R>::rx(alpha, prepared)
        } else {
            no_such_stage()
        }
    }

    fn zero_alpha(index: usize) -> bool {
        index < num_runs::<K>()
    }
}

/// Loads the scalar-field side's front stages unenforced, its run stages
/// up to `K`'s last and its trailing stage, as the side's verifier reads
/// them: the instance and messages they hold between them.
///
/// # Errors
///
/// Fails as [`StageGuard::unenforced`] does.
pub(crate) fn load_nested_front<'dr, 'source: 'dr, C, K, R, D>(
    runs: <K::Last as RunIndex>::Guards<'dr, C, K, R, D>,
    trailing: StageGuard<'dr, D, R, TrailingStage<C, K, R>>,
    dr: &mut D,
    witness: &DriverValue<D, &'source Prepared<C, Nested>>,
) -> Result<FrontLoaded<'dr, D, C::HostCurve>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
    D: Driver<'dr, F = C::ScalarField>,
{
    let layout = nested_layout::<C, K>();
    let mut slots = FrontSlots::new(&layout);
    K::Last::load::<C, K, R, D>(runs, dr, witness, &mut slots)?;
    let output = trailing.unenforced(dr, witness.as_ref().map(|w| *w))?;
    slots.place(&trailing_source(&layout), output)?;
    slots.finish()
}

/// The scalar-field side's layout for the decompression of a Standard
/// proof at rank `K`.
fn nested_layout<C: Cycle, K: Rank>() -> Layout {
    Layout::nested::<C::ScalarField, Standard, K>()
}

/// Length type for the points of the scalar-field side's run stage `N`.
pub(crate) struct RunPoints<C, K, N>(PhantomData<fn() -> (C, K, N)>);

impl<C: Cycle, K: Rank, N: RunIndex> Len for RunPoints<C, K, N> {
    fn len() -> usize {
        N::source::<C, K>().shape().points
    }
}

/// Length type for the elements of the scalar-field side's run stage `N`.
pub(crate) struct RunElements<C, K, N>(PhantomData<fn() -> (C, K, N)>);

impl<C: Cycle, K: Rank, N: RunIndex> Len for RunElements<C, K, N> {
    fn len() -> usize {
        N::source::<C, K>().shape().elements
    }
}

/// The stage of the scalar-field side holding run `N`'s values of a
/// proof at rank `K`, as a stage of circuits at rank `R`, after the
/// run before it: the points' coordinates first, then the elements, each
/// at one wire, read off the instance's and the messages' positions the
/// run covers. The honest prover commits the stage with a zero alpha to
/// match the run commitment computed during native verification. The mask
/// leaves the alpha and the other wires of its gates free. The transcript
/// absorbs the actual stage commitment, so those coefficients can change the
/// challenges for the same run values.
pub(crate) struct RunStage<C, K, R, N>(PhantomData<fn() -> (C, K, R, N)>);

impl<C, K, R, N> Default for RunStage<C, K, R, N> {
    fn default() -> Self {
        RunStage(PhantomData)
    }
}

impl<C, K, R, N> Stage<C::ScalarField, R> for RunStage<C, K, R, N>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    N: RunIndex,
{
    type Parent = N::Before<C, K, R>;
    type Witness<'source> = &'source Prepared<C, Nested>;
    type OutputKind = Kind![C::ScalarField; Output<'_, _, C::HostCurve, RunPoints<C, K, N>, RunElements<C, K, N>>];

    fn values() -> usize {
        N::source::<C, K>().shape().values()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let source = N::source::<C, K>();
        Ok(Output {
            points: FixedVec::try_from_fn(|i| {
                Point::alloc(
                    dr,
                    witness
                        .as_ref()
                        .map(|w| source.point(&w.instance, &w.messages, i)),
                )
            })?,
            elements: FixedVec::try_from_fn(|i| {
                Element::alloc(
                    dr,
                    &mut (),
                    witness
                        .as_ref()
                        .map(|w| source.element(&w.instance, &w.messages, i)),
                )
            })?,
        })
    }
}

/// The scalar-field side's trailing stage, after the last run's: the
/// nested IPA's $c$, which precedes no challenge, at one wire.
pub(crate) struct TrailingStage<C, K, R>(PhantomData<fn() -> (C, K, R)>);

impl<C, K, R> Default for TrailingStage<C, K, R> {
    fn default() -> Self {
        TrailingStage(PhantomData)
    }
}

impl<C, K, R> Stage<C::ScalarField, R> for TrailingStage<C, K, R>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    type Parent = RunStage<C, K, R, K::Last>;
    type Witness<'source> = &'source Prepared<C, Nested>;
    type OutputKind = Kind![C::ScalarField; Output<'_, _, C::HostCurve, ConstLen<0>, ConstLen<1>>];

    fn values() -> usize {
        1
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::ScalarField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let source = trailing_source(&nested_layout::<C, K>());
        Ok(Output {
            points: FixedVec::try_from_fn(|_| {
                Err(Error::InvalidWitness(
                    "the trailing stage holds no point".into(),
                ))
            })?,
            elements: FixedVec::try_from_fn(|i| {
                Element::alloc(
                    dr,
                    &mut (),
                    witness
                        .as_ref()
                        .map(|w| source.element(&w.instance, &w.messages, i)),
                )
            })?,
        })
    }
}

/// The first run's index, as a type.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Z;

/// The run after `N`'s index, as a type.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Succ<N>(PhantomData<N>);

/// A run's index as a type, so that the run stages chain at the type
/// level: `Z` the first run's, `Succ<N>` the one after `N`'s. The chain
/// up to a run is walked by recursion over the index, which adds and loads
/// every run stage in order and reaches one by its index.
pub(crate) trait RunIndex: Copy + Default + Send + Sync + 'static {
    /// The run's index.
    const INDEX: usize;

    /// The stage before this run's: none for the first run, the run before
    /// it otherwise.
    type Before<C, K, R>: Stage<C::ScalarField, R> + Default + 'static
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    /// The guards of this run's stage and of every run's before it.
    type Guards<'dr, C, K, R, D>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>;

    /// Where the run's values sit, for a proof at rank `K`.
    fn source<C: Cycle, K: Rank>() -> RunSource {
        runs::<K>()[Self::INDEX].source(&nested_layout::<C, K>())
    }

    /// Adds every run stage up to and including this one.
    fn add<'a, 'dr, C, K, R, D, T>(
        dr: StageBuilder<'a, 'dr, D, R, OnlineQueryStage<C, Nested, R>, T>,
    ) -> Result<(
        Self::Guards<'dr, C, K, R, D>,
        StageBuilder<'a, 'dr, D, R, RunStage<C, K, R, Self>, T>,
    )>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>,
        T: Stage<C::ScalarField, R>;

    /// Loads every run stage up to and including this one into `into`.
    fn load<'dr, 'source: 'dr, C, K, R, D>(
        guards: Self::Guards<'dr, C, K, R, D>,
        dr: &mut D,
        witness: &DriverValue<D, &'source Prepared<C, Nested>>,
        into: &mut FrontSlots<'dr, D, C::HostCurve>,
    ) -> Result<()>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>;

    /// Registers run `index`'s stage's mask, for `index` at most this run's.
    fn register_stage_mask<'params, C, K, R>(
        index: usize,
        slot: MaskSlot<'params, C::ScalarField, R>,
    ) -> Result<Registered<'params, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    /// Run `index`'s stage's mask, for `index` at most this run's.
    #[cfg(test)]
    fn stage_mask<C, K, R>(index: usize) -> Result<MaskObject<R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    /// Run `index`'s stage's polynomial over `prepared`, with a zero alpha, for
    /// `index` at most this run's.
    fn rx<C, K, R>(
        index: usize,
        prepared: &Prepared<C, Nested>,
    ) -> Result<sparse::Polynomial<C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;
}

/// Loads run `N`'s stage from its guard into `into`.
fn load_run<'dr, 'source: 'dr, C, K, R, N, D>(
    guard: StageGuard<'dr, D, R, RunStage<C, K, R, N>>,
    dr: &mut D,
    witness: &DriverValue<D, &'source Prepared<C, Nested>>,
    into: &mut FrontSlots<'dr, D, C::HostCurve>,
) -> Result<()>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    N: RunIndex,
    D: Driver<'dr, F = C::ScalarField>,
{
    let output = guard.unenforced(dr, witness.as_ref().map(|w| *w))?;
    into.place(&N::source::<C, K>(), output)
}

impl RunIndex for Z {
    const INDEX: usize = 0;

    type Before<C, K, R>
        = OnlineQueryStage<C, Nested, R>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    type Guards<'dr, C, K, R, D>
        = StageGuard<'dr, D, R, RunStage<C, K, R, Z>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>;

    fn add<'a, 'dr, C, K, R, D, T>(
        dr: StageBuilder<'a, 'dr, D, R, OnlineQueryStage<C, Nested, R>, T>,
    ) -> Result<(
        Self::Guards<'dr, C, K, R, D>,
        StageBuilder<'a, 'dr, D, R, RunStage<C, K, R, Self>, T>,
    )>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>,
        T: Stage<C::ScalarField, R>,
    {
        dr.add_stage::<RunStage<C, K, R, Z>>()
    }

    fn load<'dr, 'source: 'dr, C, K, R, D>(
        guard: Self::Guards<'dr, C, K, R, D>,
        dr: &mut D,
        witness: &DriverValue<D, &'source Prepared<C, Nested>>,
        into: &mut FrontSlots<'dr, D, C::HostCurve>,
    ) -> Result<()>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>,
    {
        load_run::<C, K, R, Z, D>(guard, dr, witness, into)
    }

    fn register_stage_mask<'params, C, K, R>(
        index: usize,
        slot: MaskSlot<'params, C::ScalarField, R>,
    ) -> Result<Registered<'params, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == 0 {
            slot.register_stage_mask::<RunStage<C, K, R, Z>>()
        } else {
            no_such_stage()
        }
    }

    #[cfg(test)]
    fn stage_mask<C, K, R>(index: usize) -> Result<MaskObject<R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == 0 {
            RunStage::<C, K, R, Z>::stage_mask()
        } else {
            no_such_stage()
        }
    }

    fn rx<C, K, R>(
        index: usize,
        prepared: &Prepared<C, Nested>,
    ) -> Result<sparse::Polynomial<C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == 0 {
            RunStage::<C, K, R, Z>::rx(C::ScalarField::ZERO, prepared)
        } else {
            no_such_stage()
        }
    }
}

impl<N: RunIndex> RunIndex for Succ<N> {
    const INDEX: usize = N::INDEX + 1;

    type Before<C, K, R>
        = RunStage<C, K, R, N>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    type Guards<'dr, C, K, R, D>
        = (
        N::Guards<'dr, C, K, R, D>,
        StageGuard<'dr, D, R, RunStage<C, K, R, Succ<N>>>,
    )
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>;

    fn add<'a, 'dr, C, K, R, D, T>(
        dr: StageBuilder<'a, 'dr, D, R, OnlineQueryStage<C, Nested, R>, T>,
    ) -> Result<(
        Self::Guards<'dr, C, K, R, D>,
        StageBuilder<'a, 'dr, D, R, RunStage<C, K, R, Self>, T>,
    )>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>,
        T: Stage<C::ScalarField, R>,
    {
        let (before, dr) = N::add::<C, K, R, D, T>(dr)?;
        let (own, dr) = dr.add_stage::<RunStage<C, K, R, Succ<N>>>()?;
        Ok(((before, own), dr))
    }

    fn load<'dr, 'source: 'dr, C, K, R, D>(
        (before, own): Self::Guards<'dr, C, K, R, D>,
        dr: &mut D,
        witness: &DriverValue<D, &'source Prepared<C, Nested>>,
        into: &mut FrontSlots<'dr, D, C::HostCurve>,
    ) -> Result<()>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
        D: Driver<'dr, F = C::ScalarField>,
    {
        N::load::<C, K, R, D>(before, dr, witness, into)?;
        load_run::<C, K, R, Succ<N>, D>(own, dr, witness, into)
    }

    fn register_stage_mask<'params, C, K, R>(
        index: usize,
        slot: MaskSlot<'params, C::ScalarField, R>,
    ) -> Result<Registered<'params, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == Self::INDEX {
            slot.register_stage_mask::<RunStage<C, K, R, Succ<N>>>()
        } else {
            N::register_stage_mask::<C, K, R>(index, slot)
        }
    }

    #[cfg(test)]
    fn stage_mask<C, K, R>(index: usize) -> Result<MaskObject<R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == Self::INDEX {
            RunStage::<C, K, R, Succ<N>>::stage_mask()
        } else {
            N::stage_mask::<C, K, R>(index)
        }
    }

    fn rx<C, K, R>(
        index: usize,
        prepared: &Prepared<C, Nested>,
    ) -> Result<sparse::Polynomial<C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == Self::INDEX {
            RunStage::<C, K, R, Succ<N>>::rx(C::ScalarField::ZERO, prepared)
        } else {
            N::rx::<C, K, R>(index, prepared)
        }
    }
}

/// A rank whose proofs' runs the scalar-field side's stage chain covers:
/// the chain's length is a type, [`Last`](Self::Last), the last run's
/// index, so the ranks the whole circuits decompress proofs of are the
/// ones named here. The wallet rank's, the wallets'.
pub(crate) trait Runs: Rank {
    /// The last run's index.
    type Last: RunIndex;
}

/// The run index `Succ` applied to `Z` as many times as there are `+`s.
macro_rules! run_index {
    () => { Z };
    (+ $($rest:tt)*) => { Succ<run_index!($($rest)*)> };
}

impl Runs for ragu_circuits::polynomials::WalletRank {
    // Twenty-four runs: ten besides the fourteen rounds'.
    type Last = run_index!(+ + + + + + + + + + + + + + + + + + + + + + +);
}

const _: () = {
    assert!(
        <<ragu_circuits::polynomials::WalletRank as Runs>::Last as RunIndex>::INDEX + 1
            == num_runs::<ragu_circuits::polynomials::WalletRank>(),
        "the wallet rank's chain covers its runs"
    );
};
