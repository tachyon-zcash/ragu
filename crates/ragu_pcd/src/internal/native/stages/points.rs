//! The native points stages: the nested-curve commitments the nested batch
//! folds into $P_n$, split by the challenge each must be fixed before, and
//! the walk's endoscalar and interstitials.
//!
//! The nested side keeps its points in one stage committed after $\beta$ and
//! binds that stage to the transcript-absorbed bridge stages with a loading
//! circuit. Here the points *are* the transcript-bound stages: each input
//! stage is committed at the point of the fuse where its points exist, its
//! host-curve commitment rides in the bridge stage absorbed next, and the
//! endoscaling steps read the points where they were committed. So the
//! nested batch's commitments are fixed before the challenges the nested
//! openings are at, exactly as the native batch's are:
//!
//! | stage | holds | fixed before | carried by |
//! |---|---|---|---|
//! | [`BindingStage`] | the children's bridge and challenge-stage commitments, $A_n$, $B_n$, `registry_xy` and $P_n$ | $w$ | `preamble` bridge |
//! | [`ChildrenStage`] | the rest of the children's nested commitments | $w$ | `preamble` bridge |
//! | [`RegistryWxStage`] | $m_n(w_n, x_{i,n}, Y)$ | $y$ | `s_prime` bridge |
//! | [`AbStage`] | $m_n(w_n, X, y_n)$, $A_n$, $B_n$ | $x$ | `ab` bridge |
//! | [`FStage`] | $m_n(W, x_n, y_n)$, $F_n$ | $u$ | `f` bridge |
//!
//! Every point is fixed before the random point it is opened at: the
//! `registry_wy` restriction is opened at $x_n$, and the `registry_xy`
//! restriction is pinned to the registry by the parent's opening at its own
//! $w$, so neither needs a stage of its own before the batching challenge.
//!
//! [`BindingStage`] is the root of the whole native stage tree, so the
//! circuits on the preamble chain reserve it too: that is what lets
//! [`bind_beta`](super::super::circuits::bind_beta) hold the points it
//! walks against what the children exported through their unified
//! instances: their bridge commitments, completed challenge bindings and
//! persistent polynomial commitments. [`WalkStage`], committed after
//! $\beta$, holds the endoscalar's
//! bits and the walk's interstitials and closes the steps' chain; its last
//! interstitial is this step's $P_n$, which
//! [`bind_endoscalar`](super::super::circuits::bind_endoscalar) pins to the
//! step's own [`nested_p_commitment`] slot. That circuit also exports the
//! $A_n$, $B_n$ and `registry_xy` points for the next parent and the decider.
//! Every point stage's curve membership is enforced once, by `bind_endoscalar`.
//!
//! [`nested_p_commitment`]: super::super::unified::Output::nested_p_commitment

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Endoscalar, Point,
    consistent::Consistent,
    vec::{ConstLen, FixedVec, Len},
};
use udon::curve::EndomorphismAffine as Affine;

use super::super::{ENDOSCALINGS_PER_STEP, PointsLen, num_endoscaling_points};
use crate::internal::{
    Side,
    endoscalar::{InputsLen, NumStepsLen, PointsWitness},
    nested,
};

/// Length type for the walk's steps, for a poly count `L`.
pub type NumSteps<L> = NumStepsLen<PointsLen<L>, ENDOSCALINGS_PER_STEP>;

/// Length type for the walk's inputs, the initial point aside, for a poly
/// count `L`.
pub type NumInputs<L> = InputsLen<PointsLen<L>>;

/// The number of points a child contributes to the walk of an application
/// witnessing `polys` polynomials per step: every nested rx commitment, then
/// $a_n$, $b_n$, `registry_xy` and $P_n$.
pub const fn num_child_points(polys: usize) -> usize {
    nested::RxIndex::num(polys) + 4
}

/// Length type for a child's bridge commitments, in transcript order.
pub type BridgesLen = ConstLen<{ nested::RxIndex::BRIDGES.len() }>;

/// Each child's bridge and challenge commitments, plus its four persistent
/// polynomial commitments, are tied to its unified instance.
const NUM_CHILD_BINDINGS: usize = nested::RxIndex::BRIDGES.len() + 5;

/// The points of [`ChildrenStage`]: each child's points in walk order,
/// except the ones [`BindingStage`] ties to its unified instance.
pub const fn num_children_points(polys: usize) -> usize {
    2 * (num_child_points(polys) - NUM_CHILD_BINDINGS)
}

/// Length type for the [`ChildrenStage`] points, for a poly count `L`.
pub struct ChildrenLen<L: Len>(PhantomData<L>);

impl<L: Len> Len for ChildrenLen<L> {
    fn len() -> usize {
        num_children_points(L::len())
    }
}

/// The number of the current step's points at the walk's tail.
const NUM_CURRENT_POINTS: usize = 6;

/// Whether the walk's layout is the nested batch's: the initial $F_n$, each
/// child's points, and the current step's.
pub const fn layout_matches_batch(polys: usize) -> bool {
    num_endoscaling_points(polys) == 1 + 2 * num_child_points(polys) + NUM_CURRENT_POINTS
}

const _: () = assert!(
    layout_matches_batch(0),
    "the walk's layout does not match the nested batch"
);

/// The position of a child's $P_n$ among its points: the last, as
/// [`nested::pcs::child_commitments`] orders them.
const fn child_p(polys: usize) -> usize {
    num_child_points(polys) - 1
}

/// The position of a child's challenge-stage commitment among its points.
fn child_challenges(polys: usize) -> usize {
    nested::RxIndex::ChallengeStage.position(polys)
}

/// Where an input of the walk lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSource {
    /// A child's bridge commitment, in transcript absorption order.
    Bridge(Side, usize),
    /// A child's challenge-stage commitment, in [`BindingStage`].
    Challenges(Side),
    /// A child's $P_n$, in [`BindingStage`].
    P(Side),
    /// A child's persistent $A_n$ commitment.
    ChildA(Side),
    /// A child's persistent $B_n$ commitment.
    ChildB(Side),
    /// A child's persistent registry restriction commitment.
    ChildRegistryXy(Side),
    /// A point of [`ChildrenStage`], by position.
    Children(usize),
    /// One of the two points of [`RegistryWxStage`].
    RegistryWx(usize),
    /// The `registry_wy` point of [`AbStage`].
    RegistryWy,
    /// $A_n$, in [`AbStage`].
    AbA,
    /// $B_n$, in [`AbStage`].
    AbB,
    /// The `registry_xy` point of [`FStage`].
    RegistryXy,
}

/// The source of the walk's `i`-th input (the initial $F_n$ aside), in the
/// order [`nested::pcs::Batch::commitments`] fixes: for each child its
/// nested rx commitments in [`nested::RxIndex::all`] order, then its $a_n$,
/// $b_n$, `registry_xy` and $P_n$; then the current step's two
/// `registry_wx`, `registry_wy`, $A_n$, $B_n$ and `registry_xy`.
///
/// # Panics
///
/// Panics if `i` is not an input index of the walk of an application
/// witnessing `polys` polynomials per step.
pub fn input_source(i: usize, polys: usize) -> InputSource {
    let child_points = num_child_points(polys);
    let nested_rx = nested::RxIndex::num(polys);
    if i < 2 * child_points {
        let side = if i < child_points {
            Side::Left
        } else {
            Side::Right
        };
        let k = i % child_points;
        let challenges = child_challenges(polys);
        if k == challenges {
            return InputSource::Challenges(side);
        }
        if k == child_p(polys) {
            return InputSource::P(side);
        }
        if k >= nested_rx {
            return match k - nested_rx {
                0 => InputSource::ChildA(side),
                1 => InputSource::ChildB(side),
                2 => InputSource::ChildRegistryXy(side),
                _ => unreachable!("P_n was handled above"),
            };
        }
        let id = nested::RxIndex::all(polys)
            .nth(k)
            .expect("k is a nested rx position");
        if let Some(i) = nested::RxIndex::BRIDGES
            .iter()
            .position(|&bridge| bridge == id)
        {
            return InputSource::Bridge(side, i);
        }
        let offset = nested::RxIndex::all(polys)
            .take(k)
            .filter(|id| {
                *id != nested::RxIndex::ChallengeStage && !nested::RxIndex::BRIDGES.contains(id)
            })
            .count();
        let base = match side {
            Side::Left => 0,
            Side::Right => child_points - NUM_CHILD_BINDINGS,
        };
        return InputSource::Children(base + offset);
    }
    match i - 2 * child_points {
        0 => InputSource::RegistryWx(0),
        1 => InputSource::RegistryWx(1),
        2 => InputSource::RegistryWy,
        3 => InputSource::AbA,
        4 => InputSource::AbB,
        5 => InputSource::RegistryXy,
        _ => panic!("input {i} is past the walk"),
    }
}

/// A child's points tied to its native unified instance.
#[derive(Clone, Copy)]
pub struct ChildBindingWitness<C: Affine> {
    pub bridges: [C; nested::RxIndex::BRIDGES.len()],
    pub challenges: C,
    pub a: C,
    pub b: C,
    pub registry_xy: C,
    pub p: C,
}

/// Witness of [`BindingStage`]: the points tied to each child's instance.
#[derive(Clone, Copy)]
pub struct BindingWitness<C: Affine> {
    pub left: ChildBindingWitness<C>,
    pub right: ChildBindingWitness<C>,
}

/// Witness of [`ChildrenStage`].
pub struct ChildrenWitness<C: Affine, L: Len> {
    pub points: FixedVec<C, ChildrenLen<L>>,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<C: Affine, L: Len> Clone for ChildrenWitness<C, L> {
    fn clone(&self) -> Self {
        Self {
            points: self.points.clone(),
        }
    }
}

/// Witness of [`RegistryWxStage`].
#[derive(Clone, Copy)]
pub struct RegistryWxWitness<C: Affine> {
    pub registry_wx0: C,
    pub registry_wx1: C,
}

/// Witness of [`AbStage`].
#[derive(Clone, Copy)]
pub struct AbWitness<C: Affine> {
    pub registry_wy: C,
    pub a: C,
    pub b: C,
}

/// Witness of [`FStage`].
#[derive(Clone, Copy)]
pub struct FWitness<C: Affine> {
    pub registry_xy: C,
    pub f: C,
}

/// Witness of [`WalkStage`]: the endoscalar and the walk's outputs, one per
/// step.
pub struct WalkWitness<C: Affine, L: Len> {
    pub endoscalar: u128,
    pub interstitials: FixedVec<C, NumSteps<L>>,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<C: Affine, L: Len> Clone for WalkWitness<C, L> {
    fn clone(&self) -> Self {
        Self {
            endoscalar: self.endoscalar,
            interstitials: self.interstitials.clone(),
        }
    }
}

impl<C: Affine, L: Len> WalkWitness<C, L> {
    /// The walk's outputs under `endoscalar`, from a simulated walk.
    pub fn new(
        endoscalar: u128,
        walk: PointsWitness<C, PointsLen<L>, ENDOSCALINGS_PER_STEP>,
    ) -> Self {
        Self {
            endoscalar,
            interstitials: walk.interstitials,
        }
    }

    /// The walk's last interstitial: $P_n$.
    pub fn p(&self) -> C {
        *self
            .interstitials
            .last()
            .expect("the walk has at least one step")
    }
}

/// Splits the two children's points, each in the order
/// [`nested::pcs::child_commitments`] fixes, into the binding and children
/// stages' witnesses.
///
/// # Panics
///
/// Panics if either child has other than [`num_child_points`] points.
pub fn children_witnesses<C: Affine, L: Len>(
    left: &[C],
    right: &[C],
) -> (BindingWitness<C>, ChildrenWitness<C, L>) {
    let polys = L::len();
    let child_points = num_child_points(polys);
    let nested_rx = nested::RxIndex::num(polys);
    assert_eq!(left.len(), child_points);
    assert_eq!(right.len(), child_points);
    let bound = |points: &[C]| ChildBindingWitness {
        bridges: core::array::from_fn(|i| points[nested::RxIndex::BRIDGES[i].position(polys)]),
        challenges: points[child_challenges(polys)],
        a: points[nested_rx],
        b: points[nested_rx + 1],
        registry_xy: points[nested_rx + 2],
        p: points[child_p(polys)],
    };
    let rest = |points: &[C]| {
        points
            .iter()
            .enumerate()
            .filter(|&(k, _)| matches!(input_source(k, polys), InputSource::Children(_)))
            .map(|(_, &point)| point)
            .collect::<Vec<_>>()
    };
    let mut points = rest(left);
    points.extend(rest(right));
    (
        BindingWitness {
            left: bound(left),
            right: bound(right),
        },
        ChildrenWitness {
            points: FixedVec::new(points).expect("num_children_points points"),
        },
    )
}

/// The witnesses of every input stage: the walk's inputs, in the stages
/// that commit them.
pub struct Inputs<C: Affine, L: Len> {
    pub binding: BindingWitness<C>,
    pub children: ChildrenWitness<C, L>,
    pub registry_wx: RegistryWxWitness<C>,
    pub ab: AbWitness<C>,
    pub f: FWitness<C>,
}

// A derive would demand `L: Clone`, which a `Len` marker need not be.
impl<C: Affine, L: Len> Clone for Inputs<C, L> {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding,
            children: self.children.clone(),
            registry_wx: self.registry_wx,
            ab: self.ab,
            f: self.f,
        }
    }
}

impl<C: Affine, L: Len> Inputs<C, L> {
    /// Splits the walk's points, the initial $F_n$ first, into the stages.
    ///
    /// # Panics
    ///
    /// Panics if `points` is not [`num_endoscaling_points`] long.
    pub fn from_walk(points: &[C]) -> Self {
        let polys = L::len();
        let child_points = num_child_points(polys);
        assert_eq!(points.len(), num_endoscaling_points(polys));
        let (binding, children) = children_witnesses::<C, L>(
            &points[1..1 + child_points],
            &points[1 + child_points..1 + 2 * child_points],
        );
        let current = &points[1 + 2 * child_points..];
        Self {
            binding,
            children,
            registry_wx: RegistryWxWitness {
                registry_wx0: current[0],
                registry_wx1: current[1],
            },
            ab: AbWitness {
                registry_wy: current[2],
                a: current[3],
                b: current[4],
            },
            f: FWitness {
                registry_xy: current[5],
                f: points[0],
            },
        }
    }

    /// The walk's `i`-th input.
    pub fn input(&self, i: usize) -> C {
        let child = |side| match side {
            Side::Left => &self.binding.left,
            Side::Right => &self.binding.right,
        };
        match input_source(i, L::len()) {
            InputSource::Bridge(side, i) => child(side).bridges[i],
            InputSource::Challenges(side) => child(side).challenges,
            InputSource::P(side) => child(side).p,
            InputSource::ChildA(side) => child(side).a,
            InputSource::ChildB(side) => child(side).b,
            InputSource::ChildRegistryXy(side) => child(side).registry_xy,
            InputSource::Children(k) => self.children.points[k],
            InputSource::RegistryWx(0) => self.registry_wx.registry_wx0,
            InputSource::RegistryWx(_) => self.registry_wx.registry_wx1,
            InputSource::RegistryWy => self.ab.registry_wy,
            InputSource::AbA => self.ab.a,
            InputSource::AbB => self.ab.b,
            InputSource::RegistryXy => self.f.registry_xy,
        }
    }

    /// The walk's points, the initial $F_n$ first.
    pub fn walk(&self) -> Vec<C> {
        core::iter::once(self.f.f)
            .chain((0..NumInputs::<L>::len()).map(|i| self.input(i)))
            .collect()
    }
}

/// A child's walked points that must match its native unified instance.
#[derive(Gadget, Consistent)]
pub struct ChildBinding<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    pub bridges: FixedVec<Point<'dr, D, C>, BridgesLen>,
    #[ragu(gadget)]
    pub challenges: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub p: Point<'dr, D, C>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> ChildBinding<'dr, D, C> {
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildBindingWitness<C>>) -> Result<Self> {
        Ok(Self {
            bridges: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.bridges[i]))
            })?,
            challenges: Point::alloc(dr, witness.as_ref().map(|w| w.challenges))?,
            a: Point::alloc(dr, witness.as_ref().map(|w| w.a))?,
            b: Point::alloc(dr, witness.as_ref().map(|w| w.b))?,
            registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.registry_xy))?,
            p: Point::alloc(dr, witness.as_ref().map(|w| w.p))?,
        })
    }
}

/// Output gadget of [`BindingStage`].
#[derive(Gadget, Consistent)]
pub struct Binding<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    pub left: ChildBinding<'dr, D, C>,
    #[ragu(gadget)]
    pub right: ChildBinding<'dr, D, C>,
}

/// Output gadget of [`ChildrenStage`].
#[derive(Gadget, Consistent)]
pub struct Children<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub points: FixedVec<Point<'dr, D, C>, ChildrenLen<L>>,
}

/// Output gadget of [`RegistryWxStage`].
#[derive(Gadget, Consistent)]
pub struct RegistryWx<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_wx0: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wx1: Point<'dr, D, C>,
}

/// Output gadget of [`AbStage`].
#[derive(Gadget, Consistent)]
pub struct Ab<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_wy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
}

/// Output gadget of [`FStage`].
#[derive(Gadget, Consistent)]
pub struct F<'dr, D: Driver<'dr>, C: Affine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub f: Point<'dr, D, C>,
}

/// Output gadget of [`WalkStage`].
#[derive(Gadget)]
pub struct Walk<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> {
    #[ragu(gadget)]
    pub endoscalar: Endoscalar<'dr, D>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, NumSteps<L>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> Walk<'dr, D, C, L> {
    /// The walk's last interstitial: $P_n$.
    pub fn p(&self) -> &Point<'dr, D, C> {
        self.interstitials
            .last()
            .expect("the walk has at least one step")
    }
}

/// The loaded input stages, viewed as the walk's inputs.
pub struct WalkInputs<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> {
    pub binding: &'a Binding<'dr, D, C>,
    pub children: &'a Children<'dr, D, C, L>,
    pub registry_wx: &'a RegistryWx<'dr, D, C>,
    pub ab: &'a Ab<'dr, D, C>,
    pub f: &'a F<'dr, D, C>,
}

impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, L: Len> WalkInputs<'a, 'dr, D, C, L> {
    /// The walk's initial point, $F_n$.
    pub fn initial(&self) -> &'a Point<'dr, D, C> {
        &self.f.f
    }

    /// The walk's `i`-th input.
    pub fn input(&self, i: usize) -> &'a Point<'dr, D, C> {
        let child = |side| match side {
            Side::Left => &self.binding.left,
            Side::Right => &self.binding.right,
        };
        match input_source(i, L::len()) {
            InputSource::Bridge(side, i) => &child(side).bridges[i],
            InputSource::Challenges(side) => &child(side).challenges,
            InputSource::P(side) => &child(side).p,
            InputSource::ChildA(side) => &child(side).a,
            InputSource::ChildB(side) => &child(side).b,
            InputSource::ChildRegistryXy(side) => &child(side).registry_xy,
            InputSource::Children(k) => &self.children.points[k],
            InputSource::RegistryWx(0) => &self.registry_wx.registry_wx0,
            InputSource::RegistryWx(_) => &self.registry_wx.registry_wx1,
            InputSource::RegistryWy => &self.ab.registry_wy,
            InputSource::AbA => &self.ab.a,
            InputSource::AbB => &self.ab.b,
            InputSource::RegistryXy => &self.f.registry_xy,
        }
    }
}

/// Defines a stage holding curve points, with a `Point` output field per
/// witness field.
macro_rules! points_stage {
    (
        $(#[$meta:meta])*
        $Stage:ident, parent = $Parent:ty, witness = $Witness:ident, output = $Output:ident,
        { $($field:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        pub struct $Stage<C: Affine, L: Len>(PhantomData<(C, L)>);

        impl<C: Affine, L: Len> Default for $Stage<C, L> {
            fn default() -> Self {
                Self(PhantomData)
            }
        }

        impl<C: Affine, R: Rank, L: Len> staging::Stage<C::Base, R> for $Stage<C, L> {
            type Parent = $Parent;
            type Witness<'source> = &'source $Witness<C>;
            type OutputKind = Kind![C::Base; $Output<'_, _, C>];

            fn values() -> usize {
                // (x, y) per point.
                2 * [$(stringify!($field)),+].len()
            }

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                &self,
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<Bound<'dr, D, Self::OutputKind>>
            where
                Self: 'dr,
            {
                Ok($Output {
                    $( $field: Point::alloc(dr, witness.as_ref().map(|w| w.$field))?, )+
                })
            }
        }
    };
}

/// The root of the native stage tree: the children's walked commitments
/// tied to their native unified instances, committed before $w$.
#[derive(Default)]
pub struct BindingStage<C: Affine>(PhantomData<C>);

impl<C: Affine, R: Rank> staging::Stage<C::Base, R> for BindingStage<C> {
    type Parent = ();
    type Witness<'source> = &'source BindingWitness<C>;
    type OutputKind = Kind![C::Base; Binding<'_, _, C>];

    fn values() -> usize {
        4 * NUM_CHILD_BINDINGS
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Binding {
            left: ChildBinding::alloc(dr, witness.as_ref().map(|w| &w.left))?,
            right: ChildBinding::alloc(dr, witness.as_ref().map(|w| &w.right))?,
        })
    }
}

/// The rest of the children's nested commitments, committed before $w$.
pub struct ChildrenStage<C: Affine, L: Len>(PhantomData<(C, L)>);

impl<C: Affine, L: Len> Default for ChildrenStage<C, L> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C: Affine, R: Rank, L: Len> staging::Stage<C::Base, R> for ChildrenStage<C, L> {
    type Parent = BindingStage<C>;
    type Witness<'source> = &'source ChildrenWitness<C, L>;
    type OutputKind = Kind![C::Base; Children<'_, _, C, L>];

    fn values() -> usize {
        2 * num_children_points(L::len())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Children {
            points: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.points[i]))
            })?,
        })
    }
}

points_stage!(
    /// The nested registry's $m_n(w_n, x_{i,n}, Y)$ commitments, committed
    /// before $y$.
    RegistryWxStage, parent = ChildrenStage<C, L>, witness = RegistryWxWitness, output = RegistryWx,
    { registry_wx0, registry_wx1 }
);

points_stage!(
    /// The nested registry's $m_n(w_n, X, y_n)$ commitment and the nested
    /// accumulator's $A_n$ and $B_n$, committed before $x$.
    AbStage, parent = RegistryWxStage<C, L>, witness = AbWitness, output = Ab,
    { registry_wy, a, b }
);

points_stage!(
    /// The nested registry's $m_n(W, x_n, y_n)$ commitment and the nested
    /// quotient's $F_n$, the walk's initial point, committed before $u$.
    FStage, parent = AbStage<C, L>, witness = FWitness, output = F,
    { registry_xy, f }
);

/// The walk's stage: $\beta$'s bits, bound to `pre_beta` by
/// `bind_endoscalar`, and the walk's outputs, one per step, the last of
/// which is $P_n$; committed after $\beta$.
pub struct WalkStage<C: Affine, L: Len>(PhantomData<(C, L)>);

impl<C: Affine, L: Len> Default for WalkStage<C, L> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C: Affine, R: Rank, L: Len> staging::Stage<C::Base, R> for WalkStage<C, L> {
    type Parent = FStage<C, L>;
    type Witness<'source> = &'source WalkWitness<C, L>;
    type OutputKind = Kind![C::Base; Walk<'_, _, C, L>];

    fn values() -> usize {
        // The endoscalar's bits, then (x, y) of one interstitial per step.
        u128::BITS as usize + 2 * NumSteps::<L>::len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Walk {
            endoscalar: Endoscalar::alloc(dr, witness.as_ref().map(|w| w.endoscalar))?,
            interstitials: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.interstitials[i]))
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::{EpAffine, Pasta};

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    type C = <Pasta as ragu_core::Cycle>::NestedCurve;
    type L = ConstLen<0>;

    #[test]
    fn stage_values_match_wire_counts() {
        fn check<const POLYS: usize>() {
            assert_stage_values::<_, R, _>(&ChildrenStage::<C, ConstLen<POLYS>>::default());
            assert_stage_values::<_, R, _>(&RegistryWxStage::<C, ConstLen<POLYS>>::default());
            assert_stage_values::<_, R, _>(&AbStage::<C, ConstLen<POLYS>>::default());
            assert_stage_values::<_, R, _>(&FStage::<C, ConstLen<POLYS>>::default());
            assert_stage_values::<_, R, _>(&WalkStage::<C, ConstLen<POLYS>>::default());
        }
        let _: PhantomData<EpAffine> = PhantomData::<C>;
        assert_stage_values::<_, R, _>(&BindingStage::<C>::default());
        check::<0>();
        check::<1>();
        check::<4>();
        check::<8>();
    }

    /// The walk's layout is the nested batch's at every poly count the
    /// tests run, not only the one the build asserts.
    #[test]
    fn layout_matches_batch_across_poly_counts() {
        for polys in 0..=16 {
            assert!(layout_matches_batch(polys), "polys = {polys}");
        }
    }

    /// Every input has exactly one source, and splitting the walk into the
    /// stages and reading it back is the identity.
    #[test]
    fn walk_round_trips_through_the_stages() {
        use rand::{Rng, SeedableRng, rngs::StdRng};
        use udon::{curve::Projective, field::Field};
        let mut rng = StdRng::seed_from_u64(7);
        let points: Vec<C> = (0..num_endoscaling_points(0))
            .map(|_| {
                (ragu_core::pasta::Ep::generator()
                    * ragu_core::pasta::Fq::random(|bytes| rng.fill_bytes(bytes)))
                .to_affine()
            })
            .collect();
        let inputs = Inputs::<C, L>::from_walk(&points);
        assert_eq!(inputs.walk(), points);

        let mut children = alloc::vec![false; num_children_points(0)];
        let mut sources = Vec::new();
        let mut bindings = 0;
        for i in 0..NumInputs::<L>::len() {
            let source = input_source(i, 0);
            assert!(
                !sources.contains(&source),
                "input source {source:?} used twice"
            );
            sources.push(source);
            match source {
                InputSource::Bridge(..)
                | InputSource::Challenges(_)
                | InputSource::P(_)
                | InputSource::ChildA(_)
                | InputSource::ChildB(_)
                | InputSource::ChildRegistryXy(_) => bindings += 1,
                InputSource::Children(k) => {
                    assert!(!children[k], "child point {k} sourced twice");
                    children[k] = true;
                }
                _ => {}
            }
        }
        assert_eq!(bindings, 2 * NUM_CHILD_BINDINGS);
        assert!(children.iter().all(|&c| c));
    }

    /// A child's $P_n$ is the last of its points, where
    /// [`nested::pcs::child_commitments`] puts it.
    #[test]
    fn child_p_is_the_last_child_point() {
        assert_eq!(input_source(child_p(0), 0), InputSource::P(Side::Left));
        assert_eq!(
            input_source(num_child_points(0) + child_p(0), 0),
            InputSource::P(Side::Right)
        );
        assert!(child_challenges(0) < child_p(0));
    }
}
