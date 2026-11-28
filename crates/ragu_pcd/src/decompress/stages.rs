//! The compressed proof's data as stages of the decompression proof: what
//! a side's verifier reads, allocated once per stage polynomial and
//! loaded unenforced by the side's circuit, the stage's mask binding the
//! layout as it binds the fuse's stages.
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
//! and the digits stage, the signed digits of the full-width scalars the
//! other side scales by. The side's whole circuit
//! ([`SideCircuit`](super::common::SideCircuit)) loads the chain after
//! the aggregator's two online stages, and every page it is cut into
//! loads every stage in the chain. A [`Layout`]
//! names where in the instance and messages each part
//! of the proof sits, the same positions whichever stages hold them, and
//! how many lifts and digits the side holds. What the verifier computes
//! between reading the stages and writing them is in no stage: it is
//! wires of the circuit's own, which its pages pass each other on its
//! carry stage.
//!
//! The circuit-field side holds the nested curve's points as points and
//! the circuit field's values as elements; the scalar-field side holds the
//! host curve's points as points and the scalar field's values as
//! elements.
//!
//! # What binds the sides
//!
//! The compression's transcript absorbs the scalar field's values, the
//! host curve's points and the nested curve's scalars, as one nested-curve
//! point per run of them before a challenge: the run's commitment at the
//! generators the run's stage lands its values on, with a zero alpha, at the
//! aggregator rank ([`run_degrees`](crate::compress::runs::run_degrees); see
//! [`CycleTranscript`](crate::ipa::CycleTranscript)). The circuit-field
//! side takes each commitment as a witness point its transcript absorbs
//! and its binding circuit, the last page of its whole circuit, exposes,
//! which the proof's consumer holds to the
//! run stage's actual commitment: the values the scalar-field side
//! reads are then the ones each challenge was squeezed over. Two
//! further kinds of stage are committed with a zero alpha so that the other
//! side can recompute their commitments from the values it holds, which its
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
//! The digits stage comes right after the lifts stage, so its generators,
//! which the other side's verifier is laid out by, follow from the side's
//! [`Layout`] alone: neither side's layout waits on the other's (see
//! [`Tables`](super::common::Tables)). The generators are computed from
//! the stages' shapes alone ([`shape_degrees`]), as
//! [`StageExt::rx`](ragu_circuits::staging::StageExt::rx) lays a stage out,
//! so that the compression, which commits the runs for a profile's
//! decompression whether or not one exists, needs no stage type of it.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

#[cfg(test)]
use ragu_circuits::MaskObject;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::Stage,
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
    common::{Prepared, Side, challenges_per_curve},
    gadgets::derive::digit_width,
};
pub(crate) use crate::compress::runs::{
    NESTED_SCALARS, Run, StageShape, native_points_of, num_runs, runs, shape_degrees,
};
use crate::{
    compress::{Messages, instance::OPENED, revdot::fold::Derived},
    internal::nested,
    profile::{MaskSlot, Profile, Registered},
};

/// The nested commitments the instance lists, then the nested registry
/// restriction's, $p$'s and the challenge stage's partial.
pub(crate) const NESTED_POINTS: usize = 2 + nested::RxIndex::NUM + 3;
/// The circuit field's values the instance carries, in
/// [`native_scalars`] order.
pub(crate) const NATIVE_SCALARS: usize = 9;
/// One curve's scalar messages: the two $\varepsilon$, the five openings,
/// $p(1/r)$ and $q(r)$, the batch's values and the IPA's $c$.
pub(crate) const MESSAGE_SCALARS: usize =
    2 + Derived::ALL.len() + 2 + (Derived::ALL.len() + 2 + OPENED) + 1;
/// The scalar field's values beyond $v$, $c$ and $c b z$ whose digits the
/// circuit-field side scales generators by: the `ab` bridge stage's
/// coefficients, the coordinates of three host-curve commitments and the
/// alpha (see [`ab_layout`](super::common::ab_layout)).
pub(crate) const AB_TERMS: usize = 7;

/// Positions within the circuit-field side's step binding, the instance
/// stage's elements that tie the decompression to the step proving it: the
/// flag and the transcript digest that step staged before its challenge.
/// Both are zero in any other step.
pub(crate) mod step {
    pub const FLAG: usize = 0;
    pub const DIGEST: usize = 1;
    pub const LEN: usize = crate::profile::STEP_BINDING;
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
    pub const RIGHT_X: usize = 5;
    pub const RIGHT_Y: usize = 6;
    pub const A_AT_U: usize = 7;
    pub const B_AT_U: usize = 8;
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
    /// Elements, circuit-field side: the statement, the compressed proof's
    /// output header.
    pub output_header: Span,
    /// Elements, circuit-field side: the step binding, in [`step`] order.
    pub step: Span,
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
/// hold between them ([`Run::source`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layout {
    pub instance: InstanceLayout,
    pub messages: MessagesLayout,
    /// The lifts stage's elements: the lifts of the challenges the side's
    /// field checks use, in [`squeezed`](super::common::squeezed) order,
    /// and on the scalar-field side those of the fuse's challenges and of
    /// the other curve's after them.
    pub lifts: usize,
    /// The digits stage's elements: the signed digits of the full-width
    /// scalars of this field the other side scales by, [`digit_width`]
    /// per scalar, in the other side's foreign scalars' order, then the
    /// flags'.
    pub digits: usize,
    /// How many of the digits stage's elements, last, are flags: a signed
    /// digit each, $2 f - 1$ for a flag $f$ of this side the other side
    /// takes.
    pub flags: usize,
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
            output_header: elements.next(HEADER_SIZE),
            step: elements.next(step::LEN),
            points: points.0,
            elements: elements.0,
        };
        Layout {
            instance,
            messages: Self::messages::<K>(),
            lifts: challenges_per_curve::<K>(),
            digits: 3 * digit_width::<F>() + 1,
            flags: 1,
        }
    }

    /// The scalar-field side's layout, over the scalar field `F`, for a
    /// proof in profile `P`: it lifts both curves' compression challenges
    /// and the fuse's $x$, $y$, $u$ and $w$, all squeezed on the other side,
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
            lifts: 2 * challenges_per_curve::<K>() + super::common::fuse::LIFTED.len(),
            digits: (3 + AB_TERMS) * digit_width::<F>(),
            flags: 0,
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
/// field, at the positions a [`Layout`] assigns.
#[derive(Clone, Debug)]
pub(crate) struct Values<F, P> {
    pub points: Vec<P>,
    pub elements: Vec<F>,
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

macro_rules! len {
    ($(#[$doc:meta])* $name:ident, |$layout:ident| $len:expr) => {
        $(#[$doc])*
        pub(crate) struct $name<C, S, K, R, const HEADER_SIZE: usize>(
            PhantomData<fn() -> (C, S, K, R)>,
        );

        impl<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize> Len
            for $name<C, S, K, R, HEADER_SIZE>
        {
            fn len() -> usize {
                let $layout = S::layout::<K, HEADER_SIZE>();
                $len
            }
        }
    };
}

len!(
    /// The instance stage's point count of side `S`.
    InstancePoints, |layout| layout.instance.points
);
len!(
    /// The instance stage's element count of side `S`.
    InstanceElements, |layout| layout.instance.elements
);
len!(
    /// The messages stage's point count of side `S`.
    MessagePoints, |layout| layout.messages.points
);
len!(
    /// The messages stage's element count of side `S`.
    MessageElements, |layout| layout.messages.elements
);
len!(
    /// The lifts stage's element count of side `S`: the layout's lifts.
    LiftsElements, |layout| layout.lifts
);
len!(
    /// The digits stage's element count of side `S`: the layout's digits.
    DigitsElements, |layout| layout.digits
);

/// A stage of side `S` holding `LP` points and `LE` elements after
/// `Parent`, as a stage of circuits at rank `R`.
type SideStage<C, S, R, Parent, LP, LE> =
    ValuesStage<<S as Side<C>>::F, <S as Side<C>>::P, R, Parent, LP, LE>;

/// Length type for side `S`'s online input stage: its values as the fuse
/// lays them out.
pub(crate) struct OnlineInputLen<C, S>(PhantomData<fn() -> (C, S)>);

impl<C: Cycle, S: Side<C>> Len for OnlineInputLen<C, S> {
    fn len() -> usize {
        S::ONLINE.input_stage()
    }
}

/// Length type for side `S`'s online query stage, likewise.
pub(crate) struct OnlineQueryLen<C, S>(PhantomData<fn() -> (C, S)>);

impl<C: Cycle, S: Side<C>> Len for OnlineQueryLen<C, S> {
    fn len() -> usize {
        S::ONLINE.query_stage()
    }
}

/// The aggregator's online input stage of side `S`'s field, as the
/// side's circuits load it: the first stage of every circuit of the
/// side. The fuse commits the stage, before its challenge, and its batch
/// helper loads it too
/// ([`InputStage`](crate::profile::online::stages::InputStage)); this is
/// the same stage, the same values at the same wires, read as elements:
/// the source registry's tag, the inputs
/// ([`online::input`](super::online::input)), then the other side's
/// commitments' coordinates.
pub(crate) type OnlineInputStage<C, S, R> =
    SideStage<C, S, R, (), ConstLen<0>, OnlineInputLen<C, S>>;

/// The aggregator's online query stage of side `S`'s field, after its
/// input stage, likewise
/// ([`QueryStage`](crate::profile::online::stages::QueryStage)): the
/// step's challenges, then the claimed values, among them the wallet
/// registry's evaluations the side reads
/// ([`online::Values`](super::online::Values)), which the step's fuse
/// proves are its restrictions' values.
pub(crate) type OnlineQueryStage<C, S, R> =
    SideStage<C, S, R, OnlineInputStage<C, S, R>, ConstLen<0>, OnlineQueryLen<C, S>>;

/// The instance stage of side `S`, after the online stages: the first
/// stage of the circuit-field side's front, and the last of the statement
/// circuit.
pub(crate) type InstanceStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    OnlineQueryStage<C, S, R>,
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
/// with a zero alpha on the scalar-field side, whose lifts the circuit-field
/// side recomputes.
pub(crate) type LiftsStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    <S as Front<C, K, R, HEADER_SIZE>>::Last,
    ConstLen<0>,
    LiftsElements<C, S, K, R, HEADER_SIZE>,
>;

/// The digits stage of side `S`, after the lifts stage and the last of
/// the side's stages: elements only, committed with a zero alpha, loaded
/// by the last pages of the side's whole circuit alone, where the side
/// writes its digits, and recomputed by the other side.
pub(crate) type DigitsStage<C, S, K, R, const HEADER_SIZE: usize> = SideStage<
    C,
    S,
    R,
    LiftsStage<C, S, K, R, HEADER_SIZE>,
    ConstLen<0>,
    DigitsElements<C, S, K, R, HEADER_SIZE>,
>;

/// The gates side `S`'s lifts stage skips: the SYSTEM gate, the online
/// stages and its front.
fn lifts_skip<C: Cycle, S: Side<C>, K: Rank, const HEADER_SIZE: usize>() -> usize {
    1 + S::ONLINE.prefix_gates()
        + S::front_shapes::<K, HEADER_SIZE>()
            .iter()
            .map(|shape| shape.gates())
            .sum::<usize>()
}

/// The generator of side `S`'s curve each lift of its lifts stage lands
/// on at rank `R`, by lift: what the other side endoscales by the
/// challenge's bits to recompute the stage's commitment.
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
/// on at rank `R`, by digit: what the other side adds or subtracts, by
/// the digit's sign, to recompute the stage's commitment as it scales by
/// the digits.
pub(crate) fn digits_degrees<C: Cycle, S: Side<C>, K: Rank, R: Rank, const HEADER_SIZE: usize>()
-> Vec<usize> {
    let layout = S::layout::<K, HEADER_SIZE>();
    let lifts = StageShape {
        points: 0,
        elements: layout.lifts,
    };
    let skip = lifts_skip::<C, S, K, HEADER_SIZE>() + lifts.gates();
    let shape = StageShape {
        points: 0,
        elements: layout.digits,
    };
    shape_degrees::<R>(skip, shape).1
}

/// A side's stages before the lifts stage, as the chain the side's whole
/// circuit loads after the online stages: the instance and messages stages
/// on the circuit-field side ([`native::stages`](super::native::stages)); on
/// the scalar-field side ([`nested::stages`](super::nested::stages)) one
/// stage per run of the compression's transcript
/// ([`RunStage`](super::nested::stages::RunStage)), committed with a zero
/// alpha for the circuit-field side's transcript to absorb, then the
/// trailing stage ([`TrailingStage`](super::nested::stages::TrailingStage)).
/// The hooks and the prover reach each stage by its index in the chain.
pub(crate) trait Front<C: Cycle, K: Rank, R: Rank, const HEADER_SIZE: usize>:
    Side<C>
{
    /// The chain's last stage, the lifts stage's parent.
    type Last: Stage<Self::F, R> + Default + 'static;

    /// The stages in the chain.
    fn stages() -> usize;

    /// Registers stage `index`'s mask into `slot`.
    ///
    /// # Errors
    ///
    /// Fails past the last stage.
    fn register_stage_mask<'params>(
        index: usize,
        slot: MaskSlot<'params, Self::F, R>,
    ) -> Result<Registered<'params, Self::F, R>>;

    /// Stage `index`'s mask.
    ///
    /// # Errors
    ///
    /// Fails past the last stage.
    #[cfg(test)]
    fn stage_mask(index: usize) -> Result<MaskObject<R>>;

    /// Stage `index`'s polynomial over `prepared` with `alpha`, which a
    /// stage committed with a zero alpha ignores.
    ///
    /// # Errors
    ///
    /// Fails past the last stage, or as
    /// [`StageExt::rx`](ragu_circuits::staging::StageExt::rx) does.
    fn rx(
        index: usize,
        alpha: Self::F,
        prepared: &Prepared<C, Self>,
    ) -> Result<sparse::Polynomial<Self::F, R>>;

    /// Whether stage `index` is committed with a zero alpha, for the other
    /// side to hold a value to its commitment: the run stages.
    fn zero_alpha(index: usize) -> bool;
}

/// The chain's stages past its end.
pub(super) fn no_such_stage<T>() -> Result<T> {
    Err(Error::Initialization("no such front stage".into()))
}
