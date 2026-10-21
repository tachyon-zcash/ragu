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
//! | [`BindingStage`] | the children's bridge and challenge-stage commitments, $A_n$, $B_n$, `registry_xy`, $P_n$ and nested extension stages | $w$ | `preamble` bridge |
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
//! persistent polynomial commitments; and what lets
//! [`inner_collapse`](super::super::circuits::inner_collapse) take the
//! children's nested extension stage commitments, which it holds the
//! children's binding circuits to through their claims' $k(y)$ (see
//! [`Binding`](crate::profile::Binding)). [`WalkStage`], committed after
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

use super::super::NumPoints;
pub use super::super::NumSteps;
use crate::{
    internal::{
        Side,
        endoscalar::{InputsLen, PointsWitness},
        nested,
    },
    profile::Profile,
};

/// Length type for the walk's inputs, the initial point aside.
pub type NumInputs<P> = InputsLen<NumPoints<P>>;

/// The number of points a child contributes to the walk in profile `P`:
/// every nested rx commitment, then $a_n$, $b_n$, `registry_xy` and $P_n$.
pub fn num_child_points<P: Profile>() -> usize {
    nested::RxIndex::num::<P>() + 4
}

/// Length type for a child's bridge commitments, in transcript order.
pub type BridgesLen = ConstLen<{ nested::RxIndex::BRIDGES.len() }>;

/// The points of [`BindingStage`] per child in profile `P`: its bridge and
/// challenge commitments and its four persistent polynomial commitments,
/// tied to its unified instance, and its nested extension stages, tied to
/// its binding circuit.
pub fn num_child_bindings<P: Profile>() -> usize {
    nested::RxIndex::BRIDGES.len() + 5 + nested::NumExtensionStages::<P>::len()
}

/// The points of [`ChildrenStage`] in profile `P`: each child's points in
/// walk order, except the ones [`BindingStage`] holds.
pub fn num_children_points<P: Profile>() -> usize {
    2 * (num_child_points::<P>() - num_child_bindings::<P>())
}

/// Length type for the [`ChildrenStage`] points.
pub struct ChildrenLen<P: Profile>(PhantomData<P>);

impl<P: Profile> Len for ChildrenLen<P> {
    fn len() -> usize {
        num_children_points::<P>()
    }
}

/// The number of the current step's points at the walk's tail.
const NUM_CURRENT_POINTS: usize = 6;

/// The position of a child's $P_n$ among its points: the last, as
/// [`nested::pcs::child_commitments`] orders them.
fn child_p<P: Profile>() -> usize {
    num_child_points::<P>() - 1
}

/// The position of a child's challenge-stage commitment among its points.
fn child_challenges<P: Profile>() -> usize {
    nested::RxIndex::ChallengeStage.position::<P>()
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
    /// A child's nested extension stage commitment, by stage, in
    /// [`BindingStage`].
    Extension(Side, usize),
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
/// Panics if `i` is not an input index.
pub fn input_source<P: Profile>(i: usize) -> InputSource {
    let num_child_points = num_child_points::<P>();
    if i < 2 * num_child_points {
        let side = if i < num_child_points {
            Side::Left
        } else {
            Side::Right
        };
        let k = i % num_child_points;
        let challenges = child_challenges::<P>();
        if k == challenges {
            return InputSource::Challenges(side);
        }
        if k == child_p::<P>() {
            return InputSource::P(side);
        }
        let nested_rx = nested::RxIndex::num::<P>();
        if k >= nested_rx {
            return match k - nested_rx {
                0 => InputSource::ChildA(side),
                1 => InputSource::ChildB(side),
                2 => InputSource::ChildRegistryXy(side),
                _ => unreachable!("P_n was handled above"),
            };
        }
        let all = nested::RxIndex::all::<P>();
        let id = all[k];
        if let Some(i) = nested::RxIndex::BRIDGES
            .iter()
            .position(|&bridge| bridge == id)
        {
            return InputSource::Bridge(side, i);
        }
        if let nested::RxIndex::ExtensionStage(j) = id {
            return InputSource::Extension(side, j as usize);
        }
        let bound = |id: nested::RxIndex| {
            id == nested::RxIndex::ChallengeStage
                || nested::RxIndex::BRIDGES.contains(&id)
                || matches!(id, nested::RxIndex::ExtensionStage(_))
        };
        let offset = all[..k].iter().filter(|&&id| !bound(id)).count();
        let base = match side {
            Side::Left => 0,
            Side::Right => num_child_points - num_child_bindings::<P>(),
        };
        return InputSource::Children(base + offset);
    }
    match i - 2 * num_child_points {
        0 => InputSource::RegistryWx(0),
        1 => InputSource::RegistryWx(1),
        2 => InputSource::RegistryWy,
        3 => InputSource::AbA,
        4 => InputSource::AbB,
        5 => InputSource::RegistryXy,
        _ => panic!("input {i} is past the walk"),
    }
}

/// A child's points tied to its native unified instance, and its nested
/// extension stages, tied to its binding circuit.
#[derive(Clone)]
pub struct ChildBindingWitness<C: Affine, P: Profile> {
    pub bridges: [C; nested::RxIndex::BRIDGES.len()],
    pub challenges: C,
    pub a: C,
    pub b: C,
    pub registry_xy: C,
    pub p: C,
    /// The child's nested extension stage commitments, by stage.
    pub extension: FixedVec<C, nested::NumExtensionStages<P>>,
}

/// Witness of [`BindingStage`]: the points tied to each child's instance
/// and binding circuit.
#[derive(Clone)]
pub struct BindingWitness<C: Affine, P: Profile> {
    pub left: ChildBindingWitness<C, P>,
    pub right: ChildBindingWitness<C, P>,
}

/// Witness of [`ChildrenStage`].
#[derive(Clone)]
pub struct ChildrenWitness<C: Affine, P: Profile> {
    pub points: FixedVec<C, ChildrenLen<P>>,
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
#[derive(Clone)]
pub struct WalkWitness<C: Affine, P: Profile> {
    pub endoscalar: u128,
    pub interstitials: FixedVec<C, NumSteps<P>>,
}

impl<C: Affine, P: Profile> WalkWitness<C, P> {
    /// The walk's outputs under `endoscalar`, from a simulated walk.
    pub fn new(
        endoscalar: u128,
        walk: PointsWitness<C, NumPoints<P>, super::super::Endoscalings<P>>,
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
            .expect("every walk has at least one interstitial")
    }
}

/// Splits the two children's points, each in the order
/// [`nested::pcs::child_commitments`] fixes, into the binding and children
/// stages' witnesses.
///
/// # Panics
///
/// Panics if either child has other than [`num_child_points`] points.
pub fn children_witnesses<C: Affine, P: Profile>(
    left: &[C],
    right: &[C],
) -> (BindingWitness<C, P>, ChildrenWitness<C, P>) {
    let num_child_points = num_child_points::<P>();
    let nested_rx = nested::RxIndex::num::<P>();
    assert_eq!(left.len(), num_child_points);
    assert_eq!(right.len(), num_child_points);
    let bound = |points: &[C]| ChildBindingWitness {
        bridges: core::array::from_fn(|i| points[nested::RxIndex::BRIDGES[i].position::<P>()]),
        challenges: points[child_challenges::<P>()],
        a: points[nested_rx],
        b: points[nested_rx + 1],
        registry_xy: points[nested_rx + 2],
        p: points[child_p::<P>()],
        extension: FixedVec::from_fn(|j| {
            points[nested::RxIndex::ExtensionStage(j as u32).position::<P>()]
        }),
    };
    let rest = |points: &[C]| {
        points
            .iter()
            .enumerate()
            .filter(|&(k, _)| matches!(input_source::<P>(k), InputSource::Children(_)))
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
#[derive(Clone)]
pub struct Inputs<C: Affine, P: Profile> {
    pub binding: BindingWitness<C, P>,
    pub children: ChildrenWitness<C, P>,
    pub registry_wx: RegistryWxWitness<C>,
    pub ab: AbWitness<C>,
    pub f: FWitness<C>,
}

impl<C: Affine, P: Profile> Inputs<C, P> {
    /// Splits the walk's points, the initial $F_n$ first, into the stages.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != NumPoints::<P>::len()`.
    pub fn from_walk(points: &[C]) -> Self {
        let num_child_points = num_child_points::<P>();
        assert_eq!(points.len(), NumPoints::<P>::len());
        assert_eq!(
            NumPoints::<P>::len(),
            1 + 2 * num_child_points + NUM_CURRENT_POINTS,
            "the walk's layout does not match the nested batch"
        );
        let (binding, children) = children_witnesses::<C, P>(
            &points[1..1 + num_child_points],
            &points[1 + num_child_points..1 + 2 * num_child_points],
        );
        let current = &points[1 + 2 * num_child_points..];
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
        match input_source::<P>(i) {
            InputSource::Bridge(side, i) => child(side).bridges[i],
            InputSource::Challenges(side) => child(side).challenges,
            InputSource::P(side) => child(side).p,
            InputSource::ChildA(side) => child(side).a,
            InputSource::ChildB(side) => child(side).b,
            InputSource::ChildRegistryXy(side) => child(side).registry_xy,
            InputSource::Extension(side, j) => child(side).extension[j],
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
            .chain((0..NumInputs::<P>::len()).map(|i| self.input(i)))
            .collect()
    }
}

/// A child's walked points that must match its native unified instance,
/// and its nested extension stages, which must match its binding circuit's
/// output.
#[derive(Gadget, Consistent)]
pub struct ChildBinding<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
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
    /// The child's nested extension stage commitments, by stage.
    #[ragu(gadget)]
    pub extension: FixedVec<Point<'dr, D, C>, nested::NumExtensionStages<P>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> ChildBinding<'dr, D, C, P> {
    fn alloc(dr: &mut D, witness: DriverValue<D, &ChildBindingWitness<C, P>>) -> Result<Self> {
        Ok(Self {
            bridges: FixedVec::try_from_fn(|i| {
                Point::alloc(dr, witness.as_ref().map(|w| w.bridges[i]))
            })?,
            challenges: Point::alloc(dr, witness.as_ref().map(|w| w.challenges))?,
            a: Point::alloc(dr, witness.as_ref().map(|w| w.a))?,
            b: Point::alloc(dr, witness.as_ref().map(|w| w.b))?,
            registry_xy: Point::alloc(dr, witness.as_ref().map(|w| w.registry_xy))?,
            p: Point::alloc(dr, witness.as_ref().map(|w| w.p))?,
            extension: FixedVec::try_from_fn(|j| {
                Point::alloc(dr, witness.as_ref().map(|w| w.extension[j]))
            })?,
        })
    }
}

/// Output gadget of [`BindingStage`].
#[derive(Gadget, Consistent)]
pub struct Binding<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub left: ChildBinding<'dr, D, C, P>,
    #[ragu(gadget)]
    pub right: ChildBinding<'dr, D, C, P>,
}

/// Output gadget of [`ChildrenStage`].
#[derive(Gadget, Consistent)]
pub struct Children<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub points: FixedVec<Point<'dr, D, C>, ChildrenLen<P>>,
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
pub struct Walk<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    #[ragu(gadget)]
    pub endoscalar: Endoscalar<'dr, D>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, NumSteps<P>>,
}

impl<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> Walk<'dr, D, C, P> {
    /// The walk's last interstitial: $P_n$.
    pub fn p(&self) -> &Point<'dr, D, C> {
        self.interstitials
            .last()
            .expect("every walk has at least one interstitial")
    }
}

/// The loaded input stages, viewed as the walk's inputs.
pub struct WalkInputs<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> {
    pub binding: &'a Binding<'dr, D, C, P>,
    pub children: &'a Children<'dr, D, C, P>,
    pub registry_wx: &'a RegistryWx<'dr, D, C>,
    pub ab: &'a Ab<'dr, D, C>,
    pub f: &'a F<'dr, D, C>,
}

impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Profile> WalkInputs<'a, 'dr, D, C, P> {
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
        match input_source::<P>(i) {
            InputSource::Bridge(side, i) => &child(side).bridges[i],
            InputSource::Challenges(side) => &child(side).challenges,
            InputSource::P(side) => &child(side).p,
            InputSource::ChildA(side) => &child(side).a,
            InputSource::ChildB(side) => &child(side).b,
            InputSource::ChildRegistryXy(side) => &child(side).registry_xy,
            InputSource::Extension(side, j) => &child(side).extension[j],
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
        #[derive(Default)]
        pub struct $Stage<C: Affine, P: Profile>(PhantomData<(C, P)>);

        impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for $Stage<C, P> {
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
/// tied to their native unified instances and to their binding circuits,
/// committed before $w$.
#[derive(Default)]
pub struct BindingStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for BindingStage<C, P> {
    type Parent = ();
    type Witness<'source> = &'source BindingWitness<C, P>;
    type OutputKind = Kind![C::Base; Binding<'_, _, C, P>];

    fn values() -> usize {
        4 * num_child_bindings::<P>()
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
#[derive(Default)]
pub struct ChildrenStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for ChildrenStage<C, P> {
    type Parent = BindingStage<C, P>;
    type Witness<'source> = &'source ChildrenWitness<C, P>;
    type OutputKind = Kind![C::Base; Children<'_, _, C, P>];

    fn values() -> usize {
        2 * num_children_points::<P>()
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
    RegistryWxStage, parent = ChildrenStage<C, P>, witness = RegistryWxWitness, output = RegistryWx,
    { registry_wx0, registry_wx1 }
);

points_stage!(
    /// The nested registry's $m_n(w_n, X, y_n)$ commitment and the nested
    /// accumulator's $A_n$ and $B_n$, committed before $x$.
    AbStage, parent = RegistryWxStage<C, P>, witness = AbWitness, output = Ab,
    { registry_wy, a, b }
);

points_stage!(
    /// The nested registry's $m_n(W, x_n, y_n)$ commitment and the nested
    /// quotient's $F_n$, the walk's initial point, committed before $u$.
    FStage, parent = AbStage<C, P>, witness = FWitness, output = F,
    { registry_xy, f }
);

/// The walk's stage: $\beta$'s bits, bound to `pre_beta` by
/// `bind_endoscalar`, and the walk's outputs, one per step, the last of
/// which is $P_n$; committed after $\beta$.
#[derive(Default)]
pub struct WalkStage<C: Affine, P: Profile>(PhantomData<(C, P)>);

impl<C: Affine, R: Rank, P: Profile> staging::Stage<C::Base, R> for WalkStage<C, P> {
    type Parent = FStage<C, P>;
    type Witness<'source> = &'source WalkWitness<C, P>;
    type OutputKind = Kind![C::Base; Walk<'_, _, C, P>];

    fn values() -> usize {
        // The endoscalar's bits, then (x, y) of one interstitial per step.
        u128::BITS as usize + 2 * NumSteps::<P>::len()
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
    use crate::{
        internal::tests::{R, assert_stage_values},
        profile::Standard,
    };

    type C = <Pasta as ragu_core::Cycle>::NestedCurve;

    #[test]
    fn stage_values_match_wire_counts() {
        let _: PhantomData<EpAffine> = PhantomData::<C>;
        assert_stage_values::<_, R, _>(&BindingStage::<C, Standard>::default());
        assert_stage_values::<_, R, _>(&ChildrenStage::<C, Standard>::default());
        assert_stage_values::<_, R, _>(&RegistryWxStage::<C, Standard>::default());
        assert_stage_values::<_, R, _>(&AbStage::<C, Standard>::default());
        assert_stage_values::<_, R, _>(&FStage::<C, Standard>::default());
        assert_stage_values::<_, R, _>(&WalkStage::<C, Standard>::default());
    }

    /// Every input has exactly one source, and splitting the walk into the
    /// stages and reading it back is the identity.
    #[test]
    fn walk_round_trips_through_the_stages() {
        use rand::{Rng, SeedableRng, rngs::StdRng};
        use udon::{curve::Projective, field::Field};
        let mut rng = StdRng::seed_from_u64(7);
        let points: Vec<C> = (0..crate::internal::native::NUM_ENDOSCALING_POINTS)
            .map(|_| {
                (ragu_core::pasta::Ep::generator()
                    * ragu_core::pasta::Fq::random(|bytes| rng.fill_bytes(bytes)))
                .to_affine()
            })
            .collect();
        let inputs = Inputs::<C, Standard>::from_walk(&points);
        assert_eq!(inputs.walk(), points);

        let mut children = alloc::vec![false; num_children_points::<Standard>()];
        let mut sources = Vec::new();
        let mut bindings = 0;
        for i in 0..NumInputs::<Standard>::len() {
            let source = input_source::<Standard>(i);
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
                | InputSource::ChildRegistryXy(_)
                | InputSource::Extension(..) => bindings += 1,
                InputSource::Children(k) => {
                    assert!(!children[k], "child point {k} sourced twice");
                    children[k] = true;
                }
                _ => {}
            }
        }
        assert_eq!(bindings, 2 * num_child_bindings::<Standard>());
        assert!(children.iter().all(|&c| c));
    }

    /// A child's $P_n$ is the last of its points, where
    /// [`nested::pcs::child_commitments`] puts it.
    #[test]
    fn child_p_is_the_last_child_point() {
        let child_p = child_p::<Standard>();
        assert_eq!(
            input_source::<Standard>(child_p),
            InputSource::P(Side::Left)
        );
        assert_eq!(
            input_source::<Standard>(num_child_points::<Standard>() + child_p),
            InputSource::P(Side::Right)
        );
        assert!(child_challenges::<Standard>() < child_p);
    }
}
