//! The compressed proof's data as stages of the decompression proof: what
//! every chunk of a side reads, allocated once per stage polynomial and
//! loaded by each chunk unenforced, the stage's mask binding the layout as
//! it binds the fuse's stages.
//!
//! Each side's stages form a chain of [`ValuesStage`]s, each holding
//! points of the side's curve and elements of its field: the instance
//! stage holds the compressed proof's instance, the messages stage the two
//! reductions' messages, the work stage what passes between chunks, and
//! the transcript stage what only the transcript chunks need, the bridges
//! the compression's transcript absorbs and the sponge's saved states. A
//! chunk loads the stages up to the last it needs, so the transcript
//! stage's cost falls on the transcript chunks alone. A [`Layout`] names
//! where in the instance, messages and transcript stages each part of the
//! proof sits; the [`Schedule`](super::program::Schedule) assigns the work
//! stage's slots and the sponge states'.
//!
//! The circuit-field side holds the nested curve's points as points and
//! the host curve's points and the scalar field's values through their
//! bridges, the commitments over the first nested generators the
//! compression's transcript absorbs; the scalar-field side holds the host
//! curve's points as points and the scalar field's values as elements,
//! and its transcript stage is empty.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::{
    Cycle, FixedGenerators, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{FixedVec, Len},
};
use udon::{
    curve::{Affine as _, EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::side::Side;
use crate::{
    compress::{Messages, instance::OPENED, revdot::fold::Derived},
    internal::{native, nested},
};

/// The nested commitments the instance lists, then the nested registry
/// restriction's, $p$'s and the challenge stage's partial.
pub(crate) const NESTED_POINTS: usize = 2 + nested::RxIndex::NUM + 3;
/// The native commitments the instance lists, then the native registry
/// restriction's and $p$'s.
pub(crate) const NATIVE_POINTS: usize = 2 + native::RxIndex::NUM + 2;
/// The scalar field's values the instance carries, in
/// [`nested_scalars`] order.
pub(crate) const NESTED_SCALARS: usize = 9;
/// The circuit field's values the instance carries, in
/// [`native_scalars`] order.
pub(crate) const NATIVE_SCALARS: usize = 11;
/// One curve's scalar messages: the two $\varepsilon$, the five openings,
/// $p(1/r)$ and $q(r)$, the batch's values and the IPA's $c$.
pub(crate) const MESSAGE_SCALARS: usize =
    2 + Derived::ALL.len() + 2 + (Derived::ALL.len() + 2 + OPENED) + 1;

/// One curve's point messages: the fold's two, $p$, $q$, $f$, $\[S\]$ and
/// the IPA's rounds.
pub(crate) const fn message_points<R: Rank>() -> usize {
    6 + 2 * R::RANK as usize
}

/// Positions of the circuit field's instance values within the
/// circuit-field side's instance scalars.
pub(crate) mod native_scalars {
    pub const OMEGA_J: usize = 0;
    pub const C: usize = 1;
    pub const V: usize = 2;
    pub const LEFT_X: usize = 3;
    pub const LEFT_Y: usize = 4;
    pub const LEFT_ID: usize = 5;
    pub const RIGHT_X: usize = 6;
    pub const RIGHT_Y: usize = 7;
    pub const RIGHT_ID: usize = 8;
    pub const A_AT_U: usize = 9;
    pub const B_AT_U: usize = 10;
}

/// Positions of the scalar field's instance values within the
/// scalar-field side's instance scalars, and of their bridges within the
/// circuit-field side's transcript stage.
pub(crate) mod nested_scalars {
    pub const BRIDGE_ALPHA: usize = 0;
    pub const C: usize = 1;
    pub const V: usize = 2;
    pub const LEFT_X: usize = 3;
    pub const LEFT_Y: usize = 4;
    pub const RIGHT_X: usize = 5;
    pub const RIGHT_Y: usize = 6;
    pub const A_AT_U: usize = 7;
    pub const B_AT_U: usize = 8;
}

/// Positions within one curve's point messages.
pub(crate) mod message_points {
    pub const INNER: usize = 0;
    pub const OUTER: usize = 1;
    pub const P: usize = 2;
    pub const Q: usize = 3;
    pub const F: usize = 4;
    pub const S_COMMITMENT: usize = 5;
    /// The $j$-th round's $L_j$.
    pub const fn l(j: usize) -> usize {
        6 + 2 * j
    }
    /// The $j$-th round's $R_j$.
    pub const fn r(j: usize) -> usize {
        7 + 2 * j
    }
}

/// A run of consecutive positions within a stage's points or elements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Span {
    pub start: usize,
    pub len: usize,
}

impl Span {
    /// The position of the `i`-th entry.
    ///
    /// # Panics
    ///
    /// Panics if `i` is not within the span.
    pub(crate) fn at(self, i: usize) -> usize {
        assert!(i < self.len, "position {i} is within {} entries", self.len);
        self.start + i
    }

    /// Every position, in order.
    pub(crate) fn positions(self) -> impl Iterator<Item = usize> {
        self.start..self.start + self.len
    }
}

/// Lays spans out end to end.
#[derive(Default)]
struct Spans(usize);

impl Spans {
    fn next(&mut self, len: usize) -> Span {
        let span = Span { start: self.0, len };
        self.0 += len;
        span
    }
}

/// Where the instance stage holds each part of the instance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InstanceLayout {
    /// Points: the commitments of the side's curve in the instance's
    /// order, then its registry restriction's and $p$'s, and on the
    /// circuit-field side the challenge stage's partial.
    pub commitments: Span,
    /// Elements: this field's instance values, in [`native_scalars`] or
    /// [`nested_scalars`] order.
    pub scalars: Span,
    /// Elements, circuit-field side: the children's headers and the
    /// statement, the compressed proof's output header.
    pub left_header: Span,
    pub right_header: Span,
    pub output_header: Span,
    pub points: usize,
    pub elements: usize,
}

/// Where the messages stage holds each part of the two curves' messages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MessagesLayout {
    /// Points: the side's curve's point messages, in [`message_points`](mod@message_points)
    /// order.
    pub points_of_curve: Span,
    /// Elements: the other curve's scalar messages, values of this field,
    /// in [`MessageScalars`] order.
    pub scalars: Span,
    pub points: usize,
    pub elements: usize,
}

/// Where the transcript stage holds the bridges, all points; its elements
/// are the sponge states the schedule assigns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TranscriptLayout {
    /// The bridges of the other curve's commitments, in the instance's
    /// order, then of its registry restriction's and $p$'s.
    pub commitment_bridges: Span,
    /// The bridges of the scalar field's instance values, in
    /// [`nested_scalars`] order.
    pub bridged: Span,
    /// The bridges of the other curve's point messages, in
    /// [`message_points`](mod@message_points) order.
    pub point_bridges: Span,
    /// The bridges of the side's curve's scalar messages, in
    /// [`MessageScalars`] order.
    pub scalar_bridges: Span,
    pub points: usize,
}

/// One side's stage layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layout {
    pub instance: InstanceLayout,
    pub messages: MessagesLayout,
    pub transcript: TranscriptLayout,
}

impl Layout {
    /// The circuit-field side's layout.
    pub(crate) fn native<R: Rank, const HEADER_SIZE: usize>() -> Self {
        let mut points = Spans::default();
        let mut elements = Spans::default();
        let instance = InstanceLayout {
            commitments: points.next(NESTED_POINTS),
            scalars: elements.next(NATIVE_SCALARS),
            left_header: elements.next(HEADER_SIZE),
            right_header: elements.next(HEADER_SIZE),
            output_header: elements.next(HEADER_SIZE),
            points: points.0,
            elements: elements.0,
        };
        let mut points = Spans::default();
        let transcript = TranscriptLayout {
            commitment_bridges: points.next(NATIVE_POINTS),
            bridged: points.next(NESTED_SCALARS),
            point_bridges: points.next(message_points::<R>()),
            scalar_bridges: points.next(MESSAGE_SCALARS),
            points: points.0,
        };
        Layout {
            instance,
            messages: Self::messages::<R>(),
            transcript,
        }
    }

    /// The scalar-field side's layout.
    pub(crate) fn nested<R: Rank>() -> Self {
        let mut points = Spans::default();
        let mut elements = Spans::default();
        let instance = InstanceLayout {
            commitments: points.next(NATIVE_POINTS),
            scalars: elements.next(NESTED_SCALARS),
            points: points.0,
            elements: elements.0,
            ..Default::default()
        };
        Layout {
            instance,
            messages: Self::messages::<R>(),
            transcript: TranscriptLayout::default(),
        }
    }

    /// Both sides' messages layout: the side's curve's point messages and
    /// the other curve's scalar messages.
    fn messages<R: Rank>() -> MessagesLayout {
        let mut points = Spans::default();
        let mut elements = Spans::default();
        MessagesLayout {
            points_of_curve: points.next(message_points::<R>()),
            scalars: elements.next(MESSAGE_SCALARS),
            points: points.0,
            elements: elements.0,
        }
    }
}

/// The bridge of scalar-field `values`, as the compression's transcript
/// forms it: their commitment over the first nested generators.
pub(crate) fn bridge<C: Cycle>(params: &C::Params, values: &[C::ScalarField]) -> C::NestedCurve {
    let g = C::nested_generators(params).g();
    let mut acc = g[0] * values[0];
    for (value, base) in values.iter().zip(g).skip(1) {
        acc += *base * *value;
    }
    acc.to_affine()
}

/// The bridge of a host-curve point: of its coordinates.
pub(crate) fn bridge_point<C: Cycle>(params: &C::Params, point: C::HostCurve) -> C::NestedCurve {
    let (x, y) = point
        .coordinates()
        .expect("a commitment is not the identity");
    bridge::<C>(params, &[x, y])
}

/// The scalar messages of one curve in [`MessageScalars`] order.
pub(crate) fn message_scalars<P: Affine>(messages: &Messages<P>) -> Vec<P::Scalar> {
    let r = &messages.reduction;
    let mut scalars = alloc::vec![r.fold.inner_epsilon, r.fold.outer_epsilon];
    scalars.extend(r.openings.iter().copied());
    scalars.push(r.p_at_inverse_r);
    scalars.push(r.q_at_r);
    scalars.extend(messages.batch.evaluations.iter().copied());
    scalars.push(messages.opening.c);
    assert_eq!(scalars.len(), MESSAGE_SCALARS);
    scalars
}

/// The point messages of one curve in [`message_points`](mod@message_points) order.
pub(crate) fn message_points_of<P: Affine>(messages: &Messages<P>) -> Vec<P> {
    let r = &messages.reduction;
    let mut points = alloc::vec![
        r.fold.inner,
        r.fold.outer,
        r.p,
        r.q,
        messages.batch.f,
        messages.opening.s_commitment,
    ];
    for &(l, right) in &messages.opening.rounds {
        points.push(l);
        points.push(right);
    }
    points
}

/// The message scalars of one curve by name, over a slice in the stages'
/// order.
pub(crate) struct MessageScalars<'a, T>(pub &'a [T]);

impl<T> MessageScalars<'_, T> {
    pub(crate) fn inner_epsilon(&self) -> &T {
        &self.0[0]
    }
    pub(crate) fn outer_epsilon(&self) -> &T {
        &self.0[1]
    }
    pub(crate) fn openings(&self) -> &[T] {
        &self.0[2..2 + Derived::ALL.len()]
    }
    pub(crate) fn p_at_inverse_r(&self) -> &T {
        &self.0[2 + Derived::ALL.len()]
    }
    pub(crate) fn q_at_r(&self) -> &T {
        &self.0[3 + Derived::ALL.len()]
    }
    pub(crate) fn evaluations(&self) -> &[T] {
        let start = 4 + Derived::ALL.len();
        &self.0[start..start + Derived::ALL.len() + 2 + OPENED]
    }
    pub(crate) fn c(&self) -> &T {
        &self.0[MESSAGE_SCALARS - 1]
    }
}

/// One side's stage data: points of the side's curve and elements of its
/// field, at the positions a [`Layout`] or a schedule assigns.
#[derive(Clone, Debug)]
pub(crate) struct Values<F, P> {
    pub points: Vec<P>,
    pub elements: Vec<F>,
}

impl<F: Field, P: Affine> Values<F, P> {
    /// Blank values over `points` and `elements` slots, every point
    /// `placeholder` rather than the identity so that it allocates.
    pub(crate) fn blank(points: usize, elements: usize, placeholder: P) -> Self {
        Values {
            points: alloc::vec![placeholder; points],
            elements: alloc::vec![F::ZERO; elements],
        }
    }
}

/// A values stage's wires.
#[derive(Gadget)]
pub(crate) struct Output<'dr, D: Driver<'dr>, P: Affine<Base = D::F>, LP: Len, LE: Len> {
    #[ragu(gadget)]
    pub points: FixedVec<Point<'dr, D, P>, LP>,
    #[ragu(gadget)]
    pub elements: FixedVec<Element<'dr, D>, LE>,
}

/// A stage of one side holding `LP` points and `LE` elements after
/// `Parent`.
pub(crate) struct ValuesStage<C, S, R, Parent, LP, LE>(
    PhantomData<fn() -> (C, S, R, Parent, LP, LE)>,
);

impl<C, S, R, Parent, LP, LE> Default for ValuesStage<C, S, R, Parent, LP, LE> {
    fn default() -> Self {
        ValuesStage(PhantomData)
    }
}

impl<C, S, R, Parent, LP, LE> Stage<S::F, R> for ValuesStage<C, S, R, Parent, LP, LE>
where
    C: Cycle,
    S: Side<C>,
    R: Rank,
    Parent: Stage<S::F, R>,
    LP: Len,
    LE: Len,
{
    type Parent = Parent;
    type Witness<'source> = &'source Values<S::F, S::P>;
    type OutputKind = Kind![S::F; Output<'_, _, S::P, LP, LE>];

    fn values() -> usize {
        2 * LP::len() + LE::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = S::F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Output {
            points: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.points[i]))
            })?,
            elements: FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.elements[i]))
            })?,
        })
    }
}

/// The sizes the schedule fixes: the work stage's points and elements and
/// the transcript stage's elements, the sponge states. The same for every
/// application circuit, so computed for a placeholder.
pub(crate) struct Sizes {
    pub work_points: usize,
    pub work_elements: usize,
    pub states: usize,
}

impl Sizes {
    pub(crate) fn of<C: Cycle, S: Side<C>, R: Rank, const HEADER_SIZE: usize>() -> Self {
        let schedule = S::schedule::<R, HEADER_SIZE>()
            .expect("the schedule is a function of the proof system's constants");
        Sizes {
            work_points: schedule.points,
            work_elements: schedule.elements,
            states: schedule.states,
        }
    }
}

macro_rules! len {
    ($(#[$doc:meta])* $name:ident, |$layout:ident, $sizes:ident| $len:expr) => {
        $(#[$doc])*
        pub(crate) struct $name<C, S, R, const HEADER_SIZE: usize>(PhantomData<fn() -> (C, S, R)>);

        impl<C: Cycle, S: Side<C>, R: Rank, const HEADER_SIZE: usize> Len
            for $name<C, S, R, HEADER_SIZE>
        {
            fn len() -> usize {
                #[allow(unused_variables)]
                let $layout = S::layout::<R, HEADER_SIZE>();
                #[allow(unused_variables)]
                let $sizes = || Sizes::of::<C, S, R, HEADER_SIZE>();
                $len
            }
        }
    };
}

len!(
    /// The instance stage's point count of side `S`.
    InstancePoints, |layout, sizes| layout.instance.points
);
len!(
    /// The instance stage's element count of side `S`.
    InstanceElements, |layout, sizes| layout.instance.elements
);
len!(
    /// The messages stage's point count of side `S`.
    MessagePoints, |layout, sizes| layout.messages.points
);
len!(
    /// The messages stage's element count of side `S`.
    MessageElements, |layout, sizes| layout.messages.elements
);
len!(
    /// The work stage's point count of side `S`: the schedule's.
    WorkPoints, |layout, sizes| sizes().work_points
);
len!(
    /// The work stage's element count of side `S`: the schedule's.
    WorkElements, |layout, sizes| sizes().work_elements
);
len!(
    /// The transcript stage's point count of side `S`: the bridges.
    TranscriptPoints, |layout, sizes| layout.transcript.points
);
len!(
    /// The transcript stage's element count of side `S`: the sponge states
    /// the schedule saves.
    TranscriptElements, |layout, sizes| sizes().states
);

/// The instance stage of side `S`.
pub(crate) type InstanceStage<C, S, R, const HEADER_SIZE: usize> = ValuesStage<
    C,
    S,
    R,
    (),
    InstancePoints<C, S, R, HEADER_SIZE>,
    InstanceElements<C, S, R, HEADER_SIZE>,
>;

/// The messages stage of side `S`, after the instance stage.
pub(crate) type MessagesStage<C, S, R, const HEADER_SIZE: usize> = ValuesStage<
    C,
    S,
    R,
    InstanceStage<C, S, R, HEADER_SIZE>,
    MessagePoints<C, S, R, HEADER_SIZE>,
    MessageElements<C, S, R, HEADER_SIZE>,
>;

/// The work stage of side `S`, after the messages stage.
pub(crate) type WorkStage<C, S, R, const HEADER_SIZE: usize> = ValuesStage<
    C,
    S,
    R,
    MessagesStage<C, S, R, HEADER_SIZE>,
    WorkPoints<C, S, R, HEADER_SIZE>,
    WorkElements<C, S, R, HEADER_SIZE>,
>;

/// The transcript stage of side `S`, after the work stage: loaded by the
/// transcript chunks alone.
pub(crate) type TranscriptStage<C, S, R, const HEADER_SIZE: usize> = ValuesStage<
    C,
    S,
    R,
    WorkStage<C, S, R, HEADER_SIZE>,
    TranscriptPoints<C, S, R, HEADER_SIZE>,
    TranscriptElements<C, S, R, HEADER_SIZE>,
>;
