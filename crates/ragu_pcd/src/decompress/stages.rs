//! The compressed proof's data as stages of the decompression proof: what
//! every chunk of a side reads, allocated once per stage polynomial and
//! loaded by each chunk unenforced, the stage's mask binding the layout as
//! it binds the fuse's stages.
//!
//! Each side's stages form a chain of [`ValuesStage`]s, each holding
//! points of the side's curve and elements of its field: the instance
//! stage holds the compressed proof's instance, the messages stage the two
//! reductions' messages, the lifts stage the lifts of the challenges the
//! side's field checks use, the work stage what passes between chunks, the
//! transcript stage what only the transcript chunks need, the bridges the
//! compression's transcript absorbs and the sponge's saved states, and the
//! digits stage the signed digits of the full-width scalars the other side
//! scales by. A chunk loads the stages up to the last it needs, so the
//! transcript and digits stages' cost falls on the chunks that fill them.
//! A [`Layout`] names where in the instance, messages and transcript
//! stages each part of the proof sits and how many lifts and digits the
//! side holds; the [`Schedule`](super::program::Schedule) assigns the work
//! stage's slots and the sponge states'.
//!
//! The circuit-field side holds the nested curve's points as points and
//! the host curve's points and the scalar field's values through their
//! bridges; the scalar-field side holds the host curve's points as points
//! and the scalar field's values as elements, and its transcript stage is
//! empty.
//!
//! # What binds the sides
//!
//! Four kinds of stage are committed unblinded so that the other side can
//! recompute their commitments from the values it holds, which its binding
//! circuit exposes for the proof's consumer to hold to the stages' actual
//! commitments (see [`Binding`](crate::profile::Binding)):
//!
//! - the scalar-field side's instance and messages stages, whose
//!   commitments the compression's transcript absorbs piecewise: each
//!   bridge is the value at its position in the stage
//!   ([`bridge_positions`]), so the circuit-field side's sum of the bridges
//!   it absorbed is the stage's commitment;
//! - the scalar-field side's lifts stage, which holds the lifts of every
//!   challenge the circuit-field side squeezed, as the fuse's challenge
//!   stage holds its lifts, so the circuit-field side recomputes it by
//!   endoscaling the lifts' generators by the squeezed bits
//!   ([`lifts_degrees`]);
//! - each side's digits stage, which holds the signed digits of the
//!   full-width scalars the other side scales by, so the other side
//!   recomputes it as the signed sum of the digits' generators while it
//!   scales by them ([`digits_degrees`]).
//!
//! The digits stage comes after the work stage, so its generators depend
//! on the work stage's size, which the side's schedule sets, and the
//! other side's schedule names those generators: the stages' lengths
//! therefore take each side's schedule built for its sizes alone
//! ([`Side::sizes`]), which no other side's schedule enters, and the
//! full schedules build on them (see the [`program`](super::program)
//! module).

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{
    polynomials::{AggregatorRank, Rank},
    staging::{Stage, stage_wire_indices, wire_degree, wires_of},
};
use ragu_core::{
    Cycle, Error, FixedGenerators, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec, Len},
};
use udon::{
    curve::{Affine as _, EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{derive::digit_width, program::challenges_per_curve, side::Side};
use crate::{
    compress::{Messages, instance::OPENED, revdot::fold::Derived},
    internal::{native, nested},
    ipa::BridgePositions,
    profile::Profile,
};

/// The nested commitments the instance lists, then the nested registry
/// restriction's, $p$'s and the challenge stage's partial.
pub(crate) const NESTED_POINTS: usize = 2 + nested::RxIndex::NUM + 3;
/// The native commitments the instance lists, then the native registry
/// restriction's and $p$'s: the standard profile's [`native_points_of`].
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
/// The scalar field's values beyond $v$, $c$ and $c b z$ whose digits the
/// circuit-field side scales generators by: the `ab` bridge stage's
/// coefficients, the coordinates of three host-curve commitments and the
/// blinding (see [`ab_layout`](super::program::ab_layout)).
pub(crate) const AB_TERMS: usize = 7;

/// The native commitments a proof in profile `P` lists, then its native
/// registry restriction's and $p$'s: the host-curve points the
/// scalar-field side's instance stage holds.
pub(crate) fn native_points_of<P: Profile>() -> usize {
    2 + native::RxIndex::num::<P>() + 2
}

/// One curve's point messages: the fold's two, $p$, $q$, $f$, $\[S\]$ and
/// the IPA's rounds.
pub(crate) const fn message_points<K: Rank>() -> usize {
    6 + 2 * K::RANK as usize
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
    /// The lifts stage's elements: the lifts of the challenges the side's
    /// field checks use, in the schedule's
    /// [`Regions::lifts`](super::program::Regions::lifts) order.
    pub lifts: usize,
    /// The digits stage's elements: the signed digits of the full-width
    /// scalars of this field the other side scales by, [`digit_width`] per
    /// scalar, in the other side's foreign scalars' order.
    pub digits: usize,
}

impl Layout {
    /// The circuit-field side's layout, over the circuit field `F`: it
    /// lifts the host curve's compression challenges and holds the digits
    /// of its $v$, $c$ and $c b z$ for the scalar-field side.
    pub(crate) fn native<F: Field, K: Rank, const HEADER_SIZE: usize>() -> Self {
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
            point_bridges: points.next(message_points::<K>()),
            scalar_bridges: points.next(MESSAGE_SCALARS),
            points: points.0,
        };
        Layout {
            instance,
            messages: Self::messages::<K>(),
            transcript,
            lifts: challenges_per_curve::<K>(),
            digits: 3 * digit_width::<F>(),
        }
    }

    /// The scalar-field side's layout, over the scalar field `F`, for a
    /// proof in profile `P`: it lifts both curves' compression challenges
    /// and the fuse's $x$, $y$ and $u$, all squeezed on the other side,
    /// and holds the digits of its $v$, $c$ and $c b z$ and of the `ab`
    /// bridge's coefficients for the circuit-field side.
    pub(crate) fn nested<F: Field, P: Profile, K: Rank>() -> Self {
        let mut points = Spans::default();
        let mut elements = Spans::default();
        let instance = InstanceLayout {
            commitments: points.next(native_points_of::<P>()),
            scalars: elements.next(NESTED_SCALARS),
            points: points.0,
            elements: elements.0,
            ..Default::default()
        };
        Layout {
            instance,
            messages: Self::messages::<K>(),
            transcript: TranscriptLayout::default(),
            lifts: 2 * challenges_per_curve::<K>() + 3,
            digits: (3 + AB_TERMS) * digit_width::<F>(),
        }
    }

    /// Both sides' messages layout: the side's curve's point messages and
    /// the other curve's scalar messages.
    fn messages<K: Rank>() -> MessagesLayout {
        let mut points = Spans::default();
        let mut elements = Spans::default();
        MessagesLayout {
            points_of_curve: points.next(message_points::<K>()),
            scalars: elements.next(MESSAGE_SCALARS),
            points: points.0,
            elements: elements.0,
        }
    }
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

/// A stage holding `LP` points of the curve `P` and `LE` elements of its
/// base field `F` after `Parent`, as a stage of circuits at rank `R`: the
/// points' coordinates first, then the elements, each at one wire.
pub(crate) struct ValuesStage<F, P, R, Parent, LP, LE>(
    PhantomData<fn() -> (F, P, R, Parent, LP, LE)>,
);

impl<F, P, R, Parent, LP, LE> Default for ValuesStage<F, P, R, Parent, LP, LE> {
    fn default() -> Self {
        ValuesStage(PhantomData)
    }
}

impl<F, P, R, Parent, LP, LE> Stage<F, R> for ValuesStage<F, P, R, Parent, LP, LE>
where
    F: Field,
    P: Affine<Base = F>,
    R: Rank,
    Parent: Stage<F, R>,
    LP: Len,
    LE: Len,
{
    type Parent = Parent;
    type Witness<'source> = &'source Values<F, P>;
    type OutputKind = Kind![F; Output<'_, _, P, LP, LE>];

    fn values() -> usize {
        2 * LP::len() + LE::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
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

/// The generators a values stage's wires land on at rank `R`: each
/// point's $x$ and $y$, then each element, as its rx polynomial places
/// them.
fn degrees<F, P, R, Parent, LP, LE>() -> Result<(Vec<[usize; 2]>, Vec<usize>)>
where
    F: Field,
    P: Affine<Base = F>,
    R: Rank,
    Parent: Stage<F, R>,
    LP: Len,
    LE: Len,
{
    let wires = stage_wire_indices::<F, R, ValuesStage<F, P, R, Parent, LP, LE>>(|out| {
        let mut wires = wires_of(&out.points)?;
        wires.extend(wires_of(&out.elements)?);
        Ok(wires)
    })?;
    let (points, elements) = wires.split_at(2 * LP::len());
    Ok((
        points
            .chunks(2)
            .map(|xy| [wire_degree::<R>(xy[0]), wire_degree::<R>(xy[1])])
            .collect(),
        elements.iter().map(|&i| wire_degree::<R>(i)).collect(),
    ))
}

/// The sizes the schedule fixes: the work stage's points and elements and
/// the transcript stage's elements, the sponge states. The same for every
/// application circuit, so computed for a placeholder, and from the
/// schedule built for its sizes alone ([`Side::sizes`]), which the digits
/// stage's layout needs before the other side's schedule exists.
pub(crate) struct Sizes {
    pub work_points: usize,
    pub work_elements: usize,
    pub states: usize,
}

impl Sizes {
    pub(crate) fn of<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Self {
        let schedule = S::sizes::<K, R, HEADER_SIZE>()
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
        pub(crate) struct $name<C, S, K, R, const HEADER_SIZE: usize>(
            PhantomData<fn() -> (C, S, K, R)>,
        );

        impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> Len
            for $name<C, S, K, R, HEADER_SIZE>
        {
            fn len() -> usize {
                #[allow(unused_variables)]
                let $layout = S::layout::<K, HEADER_SIZE>();
                #[allow(unused_variables)]
                let $sizes = || Sizes::of::<C, S, K, R, HEADER_SIZE>();
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
    /// The lifts stage's element count of side `S`: the layout's lifts.
    LiftsElements, |layout, sizes| layout.lifts
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
len!(
    /// The digits stage's element count of side `S`: the layout's digits.
    DigitsElements, |layout, sizes| layout.digits
);

/// A stage of side `S` holding `LP` points and `LE` elements after
/// `Parent`, as a stage of chunk circuits at rank `R`.
type SideStage<C, S, R, Parent, LP, LE> =
    ValuesStage<<S as Side<C>>::F, <S as Side<C>>::P, R, Parent, LP, LE>;

/// The instance stage of side `S`.
pub(crate) type InstanceStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    (),
    InstancePoints<C, S, K, R, HEADER_SIZE>,
    InstanceElements<C, S, K, R, HEADER_SIZE>,
>;

/// The messages stage of side `S`, after the instance stage.
pub(crate) type MessagesStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    InstanceStage<C, S, K, R, HEADER_SIZE>,
    MessagePoints<C, S, K, R, HEADER_SIZE>,
    MessageElements<C, S, K, R, HEADER_SIZE>,
>;

/// The lifts stage of side `S`, after the messages stage: elements only,
/// committed unblinded on the scalar-field side, whose lifts the
/// circuit-field side recomputes.
pub(crate) type LiftsStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    MessagesStage<C, S, K, R, HEADER_SIZE>,
    ConstLen<0>,
    LiftsElements<C, S, K, R, HEADER_SIZE>,
>;

/// The work stage of side `S`, after the lifts stage.
pub(crate) type WorkStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    LiftsStage<C, S, K, R, HEADER_SIZE>,
    WorkPoints<C, S, K, R, HEADER_SIZE>,
    WorkElements<C, S, K, R, HEADER_SIZE>,
>;

/// The transcript stage of side `S`, after the work stage: loaded by the
/// transcript chunks alone.
pub(crate) type TranscriptStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    WorkStage<C, S, K, R, HEADER_SIZE>,
    TranscriptPoints<C, S, K, R, HEADER_SIZE>,
    TranscriptElements<C, S, K, R, HEADER_SIZE>,
>;

/// The digits stage of side `S`, after the work stage: elements only,
/// committed unblinded, loaded by the digits chunks alone and recomputed
/// by the other side.
pub(crate) type DigitsStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    WorkStage<C, S, K, R, HEADER_SIZE>,
    ConstLen<0>,
    DigitsElements<C, S, K, R, HEADER_SIZE>,
>;

/// The generator of side `S`'s curve each lift of its lifts stage lands
/// on at rank `R`, by lift: what the other side's circuits endoscale by
/// the challenge's bits to recompute the stage's commitment.
pub(crate) fn lifts_degrees<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>()
-> Result<Vec<usize>> {
    let (_, elements) = degrees::<
        S::F,
        S::P,
        R,
        MessagesStage<C, S, K, R, HEADER_SIZE>,
        ConstLen<0>,
        LiftsElements<C, S, K, R, HEADER_SIZE>,
    >()?;
    Ok(elements)
}

/// The generator of side `S`'s curve each digit of its digits stage lands
/// on at rank `R`, by digit: what the other side's circuits add or
/// subtract, by the digit's sign, to recompute the stage's commitment.
pub(crate) fn digits_degrees<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>()
-> Result<Vec<usize>> {
    let (_, elements) = degrees::<
        S::F,
        S::P,
        R,
        WorkStage<C, S, K, R, HEADER_SIZE>,
        ConstLen<0>,
        DigitsElements<C, S, K, R, HEADER_SIZE>,
    >()?;
    Ok(elements)
}

/// The rank the compression's bridges are laid out at: the aggregator's,
/// whose decompression stages they commit to (see [`bridge_positions`]).
pub(crate) type BridgeRank = AggregatorRank;

/// The host-curve points the scalar-field side's instance stage holds for
/// a proof in profile `P`: [`native_points_of`].
pub(crate) struct BridgeInstancePoints<P>(PhantomData<fn() -> P>);

impl<P: Profile> Len for BridgeInstancePoints<P> {
    fn len() -> usize {
        native_points_of::<P>()
    }
}

/// The host-curve point messages the scalar-field side's messages stage
/// holds for a proof at rank `K`: [`message_points()`].
pub(crate) struct BridgeMessagePoints<K>(PhantomData<fn() -> K>);

impl<K: Rank> Len for BridgeMessagePoints<K> {
    fn len() -> usize {
        message_points::<K>()
    }
}

/// The scalar-field side's instance stage of the decompression of a proof
/// in profile `P`, at the [`BridgeRank`]: the host-curve commitments the
/// instance lists, then the scalar field's instance values.
type NestedInstanceBridge<C, P> = ValuesStage<
    <C as Cycle>::ScalarField,
    <C as Cycle>::HostCurve,
    BridgeRank,
    (),
    BridgeInstancePoints<P>,
    ConstLen<NESTED_SCALARS>,
>;

/// The scalar-field side's messages stage, after its instance stage: the
/// host curve's point messages, then the nested curve's scalar messages.
type NestedMessagesBridge<C, P, K> = ValuesStage<
    <C as Cycle>::ScalarField,
    <C as Cycle>::HostCurve,
    BridgeRank,
    NestedInstanceBridge<C, P>,
    BridgeMessagePoints<K>,
    ConstLen<MESSAGE_SCALARS>,
>;

/// Where the compression's transcript bridges each host-curve point and
/// scalar-field value of a proof in profile `P` at rank `K`: the nested
/// generators the value's wires land on in the scalar-field side's
/// instance and messages stages of the proof's decompression at the
/// [`BridgeRank`], in absorption order, so that the sum of the bridges
/// of a stage's values is the stage's commitment, unblinded.
///
/// The positions are a function of the profile and the rank alone, so a
/// proof's bridges are laid out for the decompression of its profile
/// whether or not one exists: every profile's are formed the same way.
pub(crate) fn bridge_positions<C: Cycle, P: Profile, K: Rank>() -> Result<BridgePositions> {
    let (points, scalars) = bridge_degrees::<C, P, K>()?;
    Ok(BridgePositions::new(points, scalars))
}

/// Checks that the nested generators `params` holds reach every position
/// [`bridge_positions`] lays a proof in profile `P` at rank `K` out at.
/// The positions are the [`BridgeRank`]'s whatever the proof's rank, so
/// tables sized to a smaller rank, the Standard tables among them, stop
/// short of them: an application that compresses needs tables that reach
/// the aggregator rank.
///
/// # Errors
///
/// Fails if a position lies past the last generator.
pub(crate) fn check_bridge_generators<C: Cycle, P: Profile, K: Rank>(
    params: &C::Params,
) -> Result<()> {
    let generators = C::nested_generators(params).g().len();
    let (points, scalars) = bridge_degrees::<C, P, K>()?;
    let last = points
        .iter()
        .flatten()
        .chain(&scalars)
        .max()
        .copied()
        .unwrap_or(0);
    if last >= generators {
        return Err(Error::Initialization(
            alloc::format!(
                "the parameters hold {generators} nested generators but the compression bridges a value at generator {last}: compressing needs tables that reach the aggregator rank, such as `baked_aggregator()`"
            )
            .into(),
        ));
    }
    Ok(())
}

/// The generators [`bridge_positions`] names: each host-curve point's
/// coordinates', then each scalar-field value's, in absorption order.
fn bridge_degrees<C: Cycle, P: Profile, K: Rank>() -> Result<(Vec<[usize; 2]>, Vec<usize>)> {
    let (mut points, mut scalars) = degrees::<
        C::ScalarField,
        C::HostCurve,
        BridgeRank,
        (),
        BridgeInstancePoints<P>,
        ConstLen<NESTED_SCALARS>,
    >()?;
    let (message_points, message_scalars) = degrees::<
        C::ScalarField,
        C::HostCurve,
        BridgeRank,
        NestedInstanceBridge<C, P>,
        BridgeMessagePoints<K>,
        ConstLen<MESSAGE_SCALARS>,
    >()?;
    points.extend(message_points);
    scalars.extend(message_scalars);
    Ok((points, scalars))
}

/// Forms the compression's bridges as [`bridge_positions`] places them,
/// one value after another in absorption order: a host-curve point's
/// coordinates and a scalar-field value each at their generators.
pub(crate) struct Bridger<'a, C: Cycle> {
    g: &'a [C::NestedCurve],
    positions: BridgePositions,
}

impl<'a, C: Cycle> Bridger<'a, C> {
    /// A bridger at the start of the absorption order, for a proof in
    /// profile `P` at rank `K`.
    ///
    /// # Errors
    ///
    /// Fails if `params`' nested generators stop short of the positions
    /// (see [`check_bridge_generators`]).
    pub(crate) fn new<P: Profile, K: Rank>(params: &'a C::Params) -> Result<Self> {
        check_bridge_generators::<C, P, K>(params)?;
        Ok(Bridger {
            g: C::nested_generators(params).g(),
            positions: bridge_positions::<C, P, K>()?,
        })
    }

    /// The bridge of the next host-curve point: its coordinates at their
    /// generators.
    ///
    /// # Errors
    ///
    /// Fails if `point` is the identity, which has no coordinates, or past
    /// the last position.
    pub(crate) fn point(&mut self, point: C::HostCurve) -> Result<C::NestedCurve> {
        let (x, y) = point
            .coordinates()
            .ok_or_else(|| Error::InvalidWitness("a commitment is the identity".into()))?;
        let [dx, dy] = self.positions.point()?;
        Ok((self.g[dx] * x + self.g[dy] * y).to_affine())
    }

    /// The bridge of the next scalar-field value: the value at its
    /// generator.
    ///
    /// # Errors
    ///
    /// Fails past the last position.
    pub(crate) fn scalar(&mut self, value: C::ScalarField) -> Result<C::NestedCurve> {
        let d = self.positions.scalar()?;
        Ok((self.g[d] * value).to_affine())
    }
}

/// The standard profile's bridge layout is the decompression's: the
/// scalar-field side's instance and messages stages at the aggregator
/// rank land on the generators the bridges do.
#[cfg(test)]
pub(crate) fn nested_stage_degrees<C: Cycle, K: Rank, const HEADER_SIZE: usize>()
-> Result<BridgePositions>
where
    super::side::Nested: Side<C, F = C::ScalarField, P = C::HostCurve>,
{
    type Nested = super::side::Nested;
    let (mut points, mut scalars) = degrees::<
        C::ScalarField,
        C::HostCurve,
        BridgeRank,
        (),
        InstancePoints<C, Nested, K, BridgeRank, HEADER_SIZE>,
        InstanceElements<C, Nested, K, BridgeRank, HEADER_SIZE>,
    >()?;
    let (message_points, message_scalars) = degrees::<
        C::ScalarField,
        C::HostCurve,
        BridgeRank,
        InstanceStage<C, Nested, K, BridgeRank, HEADER_SIZE>,
        MessagePoints<C, Nested, K, BridgeRank, HEADER_SIZE>,
        MessageElements<C, Nested, K, BridgeRank, HEADER_SIZE>,
    >()?;
    points.extend(message_points);
    scalars.extend(message_scalars);
    Ok(BridgePositions::new(points, scalars))
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::ProductionRank;
    use ragu_core::pasta::Pasta;

    use super::*;
    use crate::profile::Standard;

    /// The compression bridges a standard-profile proof's values at the
    /// generators the decompression's scalar-field side holds them at, so
    /// the circuit-field side's sums of the bridges are the stages'
    /// commitments.
    #[test]
    fn bridge_positions_are_the_nested_stages() {
        let bridges = bridge_positions::<Pasta, Standard, ProductionRank>().unwrap();
        let stages = nested_stage_degrees::<Pasta, ProductionRank, 4>().unwrap();
        assert_eq!(bridges.points(), stages.points());
        assert_eq!(bridges.scalars(), stages.scalars());
        assert_eq!(
            bridges.points().len(),
            NATIVE_POINTS + message_points::<ProductionRank>()
        );
        assert_eq!(bridges.scalars().len(), NESTED_SCALARS + MESSAGE_SCALARS);
        // Every position is a distinct generator.
        let mut all: Vec<usize> = bridges.points().iter().flatten().copied().collect();
        all.extend(bridges.scalars());
        all.sort_unstable();
        all.dedup();
        assert_eq!(
            all.len(),
            2 * bridges.points().len() + bridges.scalars().len()
        );
    }
}
