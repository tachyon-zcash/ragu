//! The compressed proof's data as stages of the decompression proof: what
//! every chunk of a side reads, allocated once per stage polynomial and
//! loaded by each chunk unenforced, the stage's mask binding the layout as
//! it binds the fuse's stages.
//!
//! Each side's stages form a chain of [`ValuesStage`]s, each holding
//! points of the side's curve and elements of its field. The chain opens
//! with the side's [`Front`]: on the circuit-field side the instance stage,
//! holding the compressed proof's instance, and the messages stage, the
//! two reductions' messages; on the scalar-field side one stage per run of
//! the compression's transcript ([`Run`]), holding the instance's and the
//! messages' values the run covers, then the trailing stage with the
//! nested IPA's $c$, the one value no run covers. After the front come the
//! lifts stage, the lifts of the challenges the side's field checks use,
//! the work stage, what passes between chunks, the transcript stage, what
//! only the transcript chunks need, the sponge's saved states, and the
//! digits stage, the signed digits of the full-width scalars the other
//! side scales by. A chunk loads the stages up to the last it needs, so
//! the transcript and digits stages' cost falls on the chunks that fill
//! them. A [`Layout`] names where in the instance and messages each part
//! of the proof sits, the same positions whichever stages hold them, and
//! how many lifts and digits the side holds; the
//! [`Schedule`](super::program::Schedule) assigns the work stage's slots
//! and the sponge states'.
//!
//! The circuit-field side holds the nested curve's points as points and
//! the circuit field's values as elements; the scalar-field side holds the
//! host curve's points as points and the scalar field's values as
//! elements, and its transcript stage is empty.
//!
//! # What binds the sides
//!
//! The compression's transcript absorbs the scalar field's values, the
//! host curve's points and the nested curve's scalars, as one nested-curve
//! point per run of them before a challenge: the run's commitment at the
//! generators the run's stage lands its values on, unblinded, at the
//! aggregator rank ([`run_degrees`]; see
//! [`CycleTranscript`](crate::ipa::CycleTranscript)). The circuit-field
//! side takes each commitment as a witness point its transcript absorbs
//! and its binding circuit exposes, which the proof's consumer holds to the
//! run stage's actual commitment: the values the scalar-field side's
//! chunks read are then the ones each challenge was squeezed over. Two
//! further kinds of stage are committed unblinded so that the other side
//! can recompute their commitments from the values it holds, which its
//! binding circuit exposes the same way (see
//! [`Binding`](crate::profile::Binding)):
//!
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
//! module). The generators are computed from the stages' shapes alone
//! ([`shape_degrees`]), as [`StageExt::rx`] lays a stage out, so that the
//! compression, which commits the runs for a profile's decompression
//! whether or not one exists, needs no stage type of it.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

#[cfg(test)]
use ragu_circuits::BondingObject;
use ragu_circuits::{
    polynomials::{AggregatorRank, Rank, sparse},
    staging::{Stage, StageBuilder, StageExt, StageGuard},
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Point,
    vec::{ConstLen, FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    derive::digit_width,
    program::challenges_per_curve,
    run::{Prepared, View},
    side::{Native, Nested, Side},
};
use crate::{
    compress::{Messages, instance::OPENED, revdot::fold::Derived},
    internal::{native, nested},
    ipa::IpaCycle,
    profile::{BondingSlot, Profile, ProfiledCycle, Registered, Standard},
};

/// The nested commitments the instance lists, then the nested registry
/// restriction's, $p$'s and the challenge stage's partial.
pub(crate) const NESTED_POINTS: usize = 2 + nested::RxIndex::NUM + 3;
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

/// A run of scalar-field values the compression's transcript commits as
/// one point: the host curve's points and the nested curve's scalars
/// absorbed in a row, which the next circuit-field absorption or challenge
/// ends, in absorption order (see
/// [`CycleTranscript`](crate::ipa::CycleTranscript)). The instance's two
/// runs come before the sampled challenges, the host reduction's before
/// each of its challenges that a point precedes, and the nested
/// reduction's before each of its challenges that scalars precede; its
/// IPA's $c$ precedes no challenge and is never absorbed. Each run is a
/// stage of the scalar-field side ([`RunStage`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Run {
    /// The host commitments the instance lists, its registry restriction's
    /// and $p$'s.
    Commitments,
    /// The scalar field's instance values, in [`nested_scalars`] order.
    Scalars,
    /// The host reduction's inner error commitment.
    Inner,
    /// Its outer error commitment.
    Outer,
    /// Its $p$ and $q$.
    Split,
    /// Its batch's $f$.
    F,
    /// Its IPA's $\[S\]$.
    SCommitment,
    /// Its IPA's $j$-th round, $L_j$ then $R_j$.
    Round(usize),
    /// The nested reduction's two $\varepsilon$.
    Epsilons,
    /// Its derived openings, $p(1/r)$ and $q(r)$.
    Openings,
    /// Its batch's values.
    Evaluations,
}

/// The runs of a proof at rank `K`, in absorption order.
pub(crate) fn runs<K: Rank>() -> Vec<Run> {
    let mut runs = vec![
        Run::Commitments,
        Run::Scalars,
        Run::Inner,
        Run::Outer,
        Run::Split,
        Run::F,
        Run::SCommitment,
    ];
    runs.extend((0..K::RANK as usize).map(Run::Round));
    runs.extend([Run::Epsilons, Run::Openings, Run::Evaluations]);
    assert_eq!(runs.len(), num_runs::<K>());
    runs
}

/// The number of runs of a proof at rank `K`: [`runs`]'s length, one per
/// round of the host curve's IPA and ten besides.
pub(crate) const fn num_runs<K: Rank>() -> usize {
    10 + K::RANK as usize
}

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

/// A stage's size: its points and its elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StageShape {
    pub points: usize,
    pub elements: usize,
}

impl StageShape {
    /// The stage's wires: two per point, one per element.
    pub(crate) const fn values(self) -> usize {
        2 * self.points + self.elements
    }

    /// The stage's gates: two wires each.
    pub(crate) const fn gates(self) -> usize {
        self.values().div_ceil(2)
    }
}

/// The generators the wires of a stage of `shape` land on at rank `R`
/// after `skip` gates, the SYSTEM gate among them: each point's $x$ and
/// $y$, then each element, two wires per gate in order, the even wire of
/// a gate at $2n - 1 - g$ and the odd at $4n - 1 - g$, as
/// [`StageExt::rx`] places a stage's values and `wire_degree` numbers
/// them.
pub(crate) fn shape_degrees<R: Rank>(
    skip: usize,
    shape: StageShape,
) -> (Vec<[usize; 2]>, Vec<usize>) {
    let degree = |wire: usize| {
        let gate = skip + wire / 2;
        if wire.is_multiple_of(2) {
            2 * R::n() - 1 - gate
        } else {
            4 * R::n() - 1 - gate
        }
    };
    let points = (0..shape.points)
        .map(|p| [degree(2 * p), degree(2 * p + 1)])
        .collect();
    let elements = (0..shape.elements)
        .map(|e| degree(2 * shape.points + e))
        .collect();
    (points, elements)
}

/// The gates each stage of a chain of `shapes` skips: the SYSTEM gate,
/// then every earlier stage's.
pub(crate) fn chain_skips(shapes: &[StageShape]) -> Vec<usize> {
    let mut skip = 1;
    shapes
        .iter()
        .map(|shape| {
            let own = skip;
            skip += shape.gates();
            own
        })
        .collect()
}

/// The generators each run's stage of the scalar-field side lands its
/// values on at rank `R`, by run, in the run's absorption order: each
/// point's $x$ and $y$, then each element. What the compression's
/// transcript commits a run at ([`run_bases`]) and the circuit-field side
/// holds the absorbed point to through the run stage's commitment.
pub(crate) fn run_degrees<K: Rank, R: Rank>(layout: &Layout) -> Vec<Vec<usize>> {
    let sources: Vec<RunSource> = runs::<K>()
        .into_iter()
        .map(|run| run.source(layout))
        .collect();
    let shapes: Vec<StageShape> = sources.iter().map(RunSource::shape).collect();
    chain_skips(&shapes)
        .into_iter()
        .zip(shapes)
        .map(|(skip, shape)| {
            let (points, elements) = shape_degrees::<R>(skip, shape);
            points.into_iter().flatten().chain(elements).collect()
        })
        .collect()
}

/// The nested generators the compression's transcript commits each run of
/// a proof at rank `K` in the profile of `C` at: the generators the run's
/// stage lands its values on in the proof's decompression at the
/// aggregator rank ([`run_degrees`]), in absorption order. A profile's
/// runs are laid out whether or not its decompression exists.
///
/// # Errors
///
/// Fails if `params` reaches no generator at a run's position: the
/// Standard tables stop short of the aggregator rank's, and
/// [`IpaCycle::nested_generator`] supplies the baked reach past them.
pub(crate) fn run_bases<C: IpaCycle + ProfiledCycle, K: Rank>(
    params: &C::Params,
) -> Result<Vec<Vec<C::NestedCurve>>> {
    let layout = Layout::nested::<C::ScalarField, C::Profile, K>();
    run_degrees::<K, AggregatorRank>(&layout)
        .into_iter()
        .map(|degrees| {
            degrees
                .into_iter()
                .map(|degree| {
                    C::nested_generator(params, degree).ok_or_else(|| {
                        Error::Initialization(
                            alloc::format!(
                                "the parameters stop short of nested generator {degree}, which a run of the compression's transcript lands on at the aggregator rank"
                            )
                            .into(),
                        )
                    })
                })
                .collect()
        })
        .collect()
}

/// The native commitments a proof in profile `P` lists, then its native
/// registry restriction's and $p$'s: the host-curve points the
/// scalar-field side's instance holds.
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
#[allow(
    dead_code,
    reason = "every position is named; the wire bindings read the children's as a range"
)]
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
/// scalar-field side's instance scalars.
#[allow(
    dead_code,
    reason = "every position is named; the wire bindings read the children's as a range"
)]
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

/// One side's stage layout: the instance's and the messages' positions,
/// which on the scalar-field side the run stages and the trailing stage
/// hold between them ([`Run::source`]). The transcript stage holds no
/// points and the sponge states the schedule assigns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layout {
    pub instance: InstanceLayout,
    pub messages: MessagesLayout,
    /// The lifts stage's elements: the lifts of the challenges the side's
    /// field checks use, in the schedule's
    /// [`Regions::lifts`](super::program::Regions::lifts) order.
    pub lifts: usize,
    /// The digits stage's elements: the signed digits of the full-width
    /// scalars of this field the other side scales by, [`digit_width`]
    /// per scalar, in the other side's foreign scalars' order.
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
        Layout {
            instance,
            messages: Self::messages::<K>(),
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

    /// The instance's shape.
    pub(crate) fn instance_shape(&self) -> StageShape {
        StageShape {
            points: self.instance.points,
            elements: self.instance.elements,
        }
    }

    /// The messages' shape.
    pub(crate) fn messages_shape(&self) -> StageShape {
        StageShape {
            points: self.messages.points,
            elements: self.messages.elements,
        }
    }
}

/// The scalar messages of one curve in [`MessageScalars`] order.
pub(crate) fn message_scalars<P: Affine>(messages: &Messages<P>) -> Vec<P::Scalar> {
    let r = &messages.reduction;
    let mut scalars = vec![r.fold.inner_epsilon, r.fold.outer_epsilon];
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
    let mut points = vec![
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
            points: vec![placeholder; points],
            elements: vec![F::ZERO; elements],
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

/// The sizes the schedule fixes: the work stage's points and elements and
/// the transcript stage's elements, the sponge states. The same for every
/// application circuit, so computed for a placeholder, and from the
/// schedule built for its sizes alone ([`Side::sizes`]), which the digits
/// stage's layout needs before the other side's schedule exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sizes {
    pub work_points: usize,
    pub work_elements: usize,
    pub states: usize,
}

impl Sizes {
    /// Side `S`'s, built once ([`program::sizes`](super::program::sizes)).
    pub(crate) fn of<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Self {
        super::program::sizes::<C, S, K, R, HEADER_SIZE>()
    }

    /// The work stage's shape.
    pub(crate) fn work_shape(&self) -> StageShape {
        StageShape {
            points: self.work_points,
            elements: self.work_elements,
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

/// The instance stage of side `S`: the first stage of the circuit-field
/// side's front, and of the statement circuit, which loads it alone.
pub(crate) type InstanceStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    (),
    InstancePoints<C, S, K, R, HEADER_SIZE>,
    InstanceElements<C, S, K, R, HEADER_SIZE>,
>;

/// The messages stage of side `S`, after the instance stage: the last
/// stage of the circuit-field side's front.
pub(crate) type MessagesStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    InstanceStage<C, S, K, R, HEADER_SIZE>,
    MessagePoints<C, S, K, R, HEADER_SIZE>,
    MessageElements<C, S, K, R, HEADER_SIZE>,
>;

/// The lifts stage of side `S`, after its front: elements only, committed
/// unblinded on the scalar-field side, whose lifts the circuit-field side
/// recomputes.
pub(crate) type LiftsStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    <S as Front<C, K, R, HEADER_SIZE>>::Last,
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

/// The transcript stage of side `S`, after the work stage: the sponge
/// states, elements only, loaded by the transcript chunks alone.
pub(crate) type TranscriptStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    WorkStage<C, S, K, R, HEADER_SIZE>,
    ConstLen<0>,
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

/// The gates side `S`'s lifts stage skips: the SYSTEM gate and its front.
fn lifts_skip<C: Cycle, S: Side<C>, K: Rank, const HEADER_SIZE: usize>() -> usize {
    1 + S::front_shapes::<K, HEADER_SIZE>()
        .iter()
        .map(|shape| shape.gates())
        .sum::<usize>()
}

/// The generator of side `S`'s curve each lift of its lifts stage lands
/// on at rank `R`, by lift: what the other side's circuits endoscale by
/// the challenge's bits to recompute the stage's commitment.
pub(crate) fn lifts_degrees<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>()
-> Vec<usize> {
    let layout = S::layout::<K, HEADER_SIZE>();
    let shape = StageShape {
        points: 0,
        elements: layout.lifts,
    };
    shape_degrees::<R>(lifts_skip::<C, S, K, HEADER_SIZE>(), shape).1
}

/// The generator of side `S`'s curve each digit of its digits stage lands
/// on at rank `R`, by digit: what the other side's circuits add or
/// subtract, by the digit's sign, to recompute the stage's commitment as
/// they scale by the digits.
pub(crate) fn digits_degrees<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>()
-> Vec<usize> {
    let layout = S::layout::<K, HEADER_SIZE>();
    let lifts = StageShape {
        points: 0,
        elements: layout.lifts,
    };
    let work = Sizes::of::<C, S, K, R, HEADER_SIZE>().work_shape();
    let skip = lifts_skip::<C, S, K, HEADER_SIZE>() + lifts.gates() + work.gates();
    let shape = StageShape {
        points: 0,
        elements: layout.digits,
    };
    shape_degrees::<R>(skip, shape).1
}

/// The scalar-field side's front stages' values as its chunks view them,
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
    /// The instance as a chunk views it.
    pub(crate) fn instance(&self) -> View<'_, 'dr, D, P> {
        View {
            points: &self.instance_points,
            elements: &self.instance_elements,
        }
    }

    /// The messages as a chunk views it.
    pub(crate) fn messages(&self) -> View<'_, 'dr, D, P> {
        View {
            points: &self.messages_points,
            elements: &self.messages_elements,
        }
    }
}

/// A side's stages before the lifts stage, as the chain the chunk
/// circuits load first: the instance and messages stages on the
/// circuit-field side; on the scalar-field side one stage per run of the
/// compression's transcript ([`RunStage`]), committed unblinded for the
/// circuit-field side's transcript to absorb, then the trailing stage
/// ([`TrailingStage`]). The hooks and the prover reach each stage by its
/// index in the chain.
pub(crate) trait Front<C: Cycle, K: Rank, R: Rank, const HEADER_SIZE: usize>:
    Side<C>
{
    /// The chain's last stage, the lifts stage's parent.
    type Last: Stage<Self::F, R> + Default + 'static;
    /// The guards of the chain's stages, as [`add`](Self::add) returns
    /// them and [`load`](Self::load) takes them.
    type Guards<'dr, D: Driver<'dr, F = Self::F>>;

    /// The stages in the chain.
    fn stages() -> usize;

    /// Adds the chain's stages to `dr`, in order.
    ///
    /// # Errors
    ///
    /// Fails as [`StageBuilder::add_stage`] does.
    fn add<'a, 'dr, D, T>(
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
    ) -> Result<(
        Self::Guards<'dr, D>,
        StageBuilder<'a, 'dr, D, R, Self::Last, T>,
    )>
    where
        D: Driver<'dr, F = Self::F>,
        T: Stage<Self::F, R>;

    /// Loads the chain's stages unenforced, as the chunks view them.
    ///
    /// # Errors
    ///
    /// Fails as [`StageGuard::unenforced`] does.
    fn load<'dr, 'source: 'dr, D>(
        guards: Self::Guards<'dr, D>,
        dr: &mut D,
        witness: &DriverValue<D, &'source Prepared<C, Self>>,
    ) -> Result<FrontLoaded<'dr, D, Self::P>>
    where
        D: Driver<'dr, F = Self::F>;

    /// Registers stage `index`'s mask into `slot`.
    ///
    /// # Errors
    ///
    /// Fails past the last stage.
    fn register_mask<'params>(
        index: usize,
        slot: BondingSlot<'params, Self::F, R>,
    ) -> Result<Registered<'params, Self::F, R>>;

    /// Stage `index`'s mask.
    ///
    /// # Errors
    ///
    /// Fails past the last stage.
    #[cfg(test)]
    fn mask(index: usize) -> Result<BondingObject<'static, Self::F, R>>;

    /// Stage `index`'s polynomial over `prepared`, blinded by `alpha`,
    /// which a stage committed unblinded ignores.
    ///
    /// # Errors
    ///
    /// Fails past the last stage, or as [`StageExt::rx`] does.
    fn rx(
        index: usize,
        alpha: Self::F,
        prepared: &Prepared<C, Self>,
    ) -> Result<sparse::Polynomial<Self::F, R>>;

    /// Whether stage `index` is committed unblinded, for the other side
    /// to hold a value to its commitment: the run stages.
    fn unblinded(index: usize) -> bool;
}

/// The chain's stages past its end.
fn no_such_stage<T>() -> Result<T> {
    Err(Error::Initialization("no such front stage".into()))
}

impl<C, K, R, const HEADER_SIZE: usize> Front<C, K, R, HEADER_SIZE> for Native
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    type Last = MessagesStage<C, Native, K, R, HEADER_SIZE>;
    type Guards<'dr, D: Driver<'dr, F = Self::F>> = (
        StageGuard<'dr, D, R, InstanceStage<C, Native, K, R, HEADER_SIZE>>,
        StageGuard<'dr, D, R, MessagesStage<C, Native, K, R, HEADER_SIZE>>,
    );

    fn stages() -> usize {
        2
    }

    fn add<'a, 'dr, D, T>(
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
    ) -> Result<(
        Self::Guards<'dr, D>,
        StageBuilder<'a, 'dr, D, R, Self::Last, T>,
    )>
    where
        D: Driver<'dr, F = Self::F>,
        T: Stage<Self::F, R>,
    {
        let (instance, dr) = dr.add_stage::<InstanceStage<C, Native, K, R, HEADER_SIZE>>()?;
        let (messages, dr) = dr.add_stage::<MessagesStage<C, Native, K, R, HEADER_SIZE>>()?;
        Ok(((instance, messages), dr))
    }

    fn load<'dr, 'source: 'dr, D>(
        (instance, messages): Self::Guards<'dr, D>,
        dr: &mut D,
        witness: &DriverValue<D, &'source Prepared<C, Self>>,
    ) -> Result<FrontLoaded<'dr, D, Self::P>>
    where
        D: Driver<'dr, F = Self::F>,
    {
        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let messages = messages.unenforced(dr, witness.as_ref().map(|w| &w.messages))?;
        Ok(FrontLoaded {
            instance_points: instance.points.into_inner(),
            instance_elements: instance.elements.into_inner(),
            messages_points: messages.points.into_inner(),
            messages_elements: messages.elements.into_inner(),
        })
    }

    fn register_mask<'params>(
        index: usize,
        slot: BondingSlot<'params, Self::F, R>,
    ) -> Result<Registered<'params, Self::F, R>> {
        match index {
            0 => slot.register_mask::<InstanceStage<C, Native, K, R, HEADER_SIZE>>(),
            1 => slot.register_mask::<MessagesStage<C, Native, K, R, HEADER_SIZE>>(),
            _ => no_such_stage(),
        }
    }

    #[cfg(test)]
    fn mask(index: usize) -> Result<BondingObject<'static, Self::F, R>> {
        match index {
            0 => InstanceStage::<C, Native, K, R, HEADER_SIZE>::mask(),
            1 => MessagesStage::<C, Native, K, R, HEADER_SIZE>::mask(),
            _ => no_such_stage(),
        }
    }

    fn rx(
        index: usize,
        alpha: Self::F,
        prepared: &Prepared<C, Self>,
    ) -> Result<sparse::Polynomial<Self::F, R>> {
        match index {
            0 => InstanceStage::<C, Native, K, R, HEADER_SIZE>::rx(alpha, &prepared.instance),
            1 => MessagesStage::<C, Native, K, R, HEADER_SIZE>::rx(alpha, &prepared.messages),
            _ => no_such_stage(),
        }
    }

    fn unblinded(_: usize) -> bool {
        false
    }
}

impl<C, K, R, const HEADER_SIZE: usize> Front<C, K, R, HEADER_SIZE> for Nested
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    type Last = TrailingStage<C, K, R>;
    type Guards<'dr, D: Driver<'dr, F = Self::F>> = (
        <K::Last as RunIndex>::Guards<'dr, C, K, R, D>,
        StageGuard<'dr, D, R, TrailingStage<C, K, R>>,
    );

    fn stages() -> usize {
        num_runs::<K>() + 1
    }

    fn add<'a, 'dr, D, T>(
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
    ) -> Result<(
        Self::Guards<'dr, D>,
        StageBuilder<'a, 'dr, D, R, Self::Last, T>,
    )>
    where
        D: Driver<'dr, F = Self::F>,
        T: Stage<Self::F, R>,
    {
        let (runs, dr) = K::Last::add::<C, K, R, D, T>(dr)?;
        let (trailing, dr) = dr.add_stage::<TrailingStage<C, K, R>>()?;
        Ok(((runs, trailing), dr))
    }

    fn load<'dr, 'source: 'dr, D>(
        (runs, trailing): Self::Guards<'dr, D>,
        dr: &mut D,
        witness: &DriverValue<D, &'source Prepared<C, Self>>,
    ) -> Result<FrontLoaded<'dr, D, Self::P>>
    where
        D: Driver<'dr, F = Self::F>,
    {
        let layout = nested_layout::<C, K>();
        let mut slots = FrontSlots::new(&layout);
        K::Last::load::<C, K, R, D>(runs, dr, witness, &mut slots)?;
        let output = trailing.unenforced(dr, witness.as_ref().map(|w| *w))?;
        slots.place(&trailing_source(&layout), output)?;
        slots.finish()
    }

    fn register_mask<'params>(
        index: usize,
        slot: BondingSlot<'params, Self::F, R>,
    ) -> Result<Registered<'params, Self::F, R>> {
        if index < num_runs::<K>() {
            K::Last::register_mask::<C, K, R>(index, slot)
        } else if index == num_runs::<K>() {
            slot.register_mask::<TrailingStage<C, K, R>>()
        } else {
            no_such_stage()
        }
    }

    #[cfg(test)]
    fn mask(index: usize) -> Result<BondingObject<'static, Self::F, R>> {
        if index < num_runs::<K>() {
            K::Last::mask::<C, K, R>(index)
        } else if index == num_runs::<K>() {
            TrailingStage::<C, K, R>::mask()
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

    fn unblinded(index: usize) -> bool {
        index < num_runs::<K>()
    }
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
/// proof at rank `K`, as a stage of chunk circuits at rank `R`, after the
/// run before it: the points' coordinates first, then the elements, each
/// at one wire, read off the instance's and the messages' positions the
/// run covers. Committed unblinded, so that its commitment is the one the
/// compression's transcript absorbed for the run.
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
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
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
    fn register_mask<'params, C, K, R>(
        index: usize,
        slot: BondingSlot<'params, C::ScalarField, R>,
    ) -> Result<Registered<'params, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    /// Run `index`'s stage's mask, for `index` at most this run's.
    #[cfg(test)]
    fn mask<C, K, R>(index: usize) -> Result<BondingObject<'static, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    /// Run `index`'s stage's polynomial over `prepared`, unblinded, for
    /// `index` at most this run's.
    fn rx<C, K, R>(
        index: usize,
        prepared: &Prepared<C, Nested>,
    ) -> Result<sparse::Polynomial<C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;

    /// The generators run `index`'s stage lands its wires on, read off the
    /// stage type, for `index` at most this run's.
    #[cfg(test)]
    fn wire_degrees<C, K, R>(index: usize) -> Result<Vec<usize>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank;
}

/// The generators a run stage lands its wires on at rank `R`, read off the
/// stage type as [`stage_wire_indices`] lays it out.
#[cfg(test)]
fn typed_degrees<C, K, R, N>() -> Result<Vec<usize>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    N: RunIndex,
{
    use ragu_circuits::staging::{stage_wire_indices, wire_degree, wires_of};
    let wires = stage_wire_indices::<C::ScalarField, R, RunStage<C, K, R, N>>(|out| {
        let mut wires = wires_of(&out.points)?;
        wires.extend(wires_of(&out.elements)?);
        Ok(wires)
    })?;
    Ok(wires.into_iter().map(wire_degree::<R>).collect())
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
        = ()
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
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
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

    fn register_mask<'params, C, K, R>(
        index: usize,
        slot: BondingSlot<'params, C::ScalarField, R>,
    ) -> Result<Registered<'params, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == 0 {
            slot.register_mask::<RunStage<C, K, R, Z>>()
        } else {
            no_such_stage()
        }
    }

    #[cfg(test)]
    fn mask<C, K, R>(index: usize) -> Result<BondingObject<'static, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == 0 {
            RunStage::<C, K, R, Z>::mask()
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

    #[cfg(test)]
    fn wire_degrees<C, K, R>(index: usize) -> Result<Vec<usize>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == 0 {
            typed_degrees::<C, K, R, Z>()
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
        dr: StageBuilder<'a, 'dr, D, R, (), T>,
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

    fn register_mask<'params, C, K, R>(
        index: usize,
        slot: BondingSlot<'params, C::ScalarField, R>,
    ) -> Result<Registered<'params, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == Self::INDEX {
            slot.register_mask::<RunStage<C, K, R, Succ<N>>>()
        } else {
            N::register_mask::<C, K, R>(index, slot)
        }
    }

    #[cfg(test)]
    fn mask<C, K, R>(index: usize) -> Result<BondingObject<'static, C::ScalarField, R>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == Self::INDEX {
            RunStage::<C, K, R, Succ<N>>::mask()
        } else {
            N::mask::<C, K, R>(index)
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

    #[cfg(test)]
    fn wire_degrees<C, K, R>(index: usize) -> Result<Vec<usize>>
    where
        C: IpaCycle + ProfiledCycle<Profile = Standard>,
        K: Rank,
        R: Rank,
    {
        if index == Self::INDEX {
            typed_degrees::<C, K, R, Succ<N>>()
        } else {
            N::wire_degrees::<C, K, R>(index)
        }
    }
}

/// A rank whose proofs' runs the scalar-field side's stage chain covers:
/// the chain's length is a type, [`Last`](Self::Last), the last run's
/// index, so the ranks the chunk circuits decompress proofs of are the
/// ones named here. The production rank's, the wallets'.
pub(crate) trait Runs: Rank {
    /// The last run's index.
    type Last: RunIndex;
}

/// The run index `Succ` applied to `Z` as many times as there are `+`s.
macro_rules! run_index {
    () => { Z };
    (+ $($rest:tt)*) => { Succ<run_index!($($rest)*)> };
}

impl Runs for ragu_circuits::polynomials::ProductionRank {
    // Twenty-three runs: ten besides the thirteen rounds'.
    type Last = run_index!(+ + + + + + + + + + + + + + + + + + + + + +);
}

const _: () = {
    assert!(
        <<ragu_circuits::polynomials::ProductionRank as Runs>::Last as RunIndex>::INDEX + 1
            == num_runs::<ragu_circuits::polynomials::ProductionRank>(),
        "the production rank's chain covers its runs"
    );
};

#[cfg(test)]
#[path = "../../tests/decompress_stages.rs"]
mod tests;
