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
//! | [`BindingStage`] | the children's challenge-stage commitments and $P_n$ | $w$ | `preamble` bridge |
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
//! instances, their challenge-stage commitments against the bindings and
//! their $P_n$ against the [`nested_p_commitment`] slots. It is kept to
//! those four points so that the preamble chain stays within its gate
//! budget. [`WalkStage`], committed after $\beta$, holds the endoscalar's
//! bits and the walk's interstitials and closes the steps' chain; its last
//! interstitial is this step's $P_n$, which
//! [`bind_endoscalar`](super::super::circuits::bind_endoscalar) pins to the
//! step's own [`nested_p_commitment`] slot. Every point stage's curve
//! membership is enforced once, by `bind_endoscalar`.
//!
//! [`nested_p_commitment`]: super::super::unified::Output::nested_p_commitment

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
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

use super::super::{ENDOSCALINGS_PER_STEP, NUM_ENDOSCALING_POINTS};
use crate::internal::{
    Side,
    endoscalar::{InputsLen, NumStepsLen, PointsWitness},
    nested,
};

/// Length type for the walk's steps.
pub type NumSteps = NumStepsLen<NUM_ENDOSCALING_POINTS, ENDOSCALINGS_PER_STEP>;

/// Length type for the walk's inputs, the initial point aside.
pub type NumInputs = InputsLen<NUM_ENDOSCALING_POINTS>;

/// The number of points a child contributes to the walk: every nested rx
/// commitment, then $a_n$, $b_n$, `registry_xy` and $P_n$.
pub const NUM_CHILD_POINTS: usize = nested::RxIndex::NUM + 4;

/// The points of [`ChildrenStage`]: each child's points in walk order, the
/// challenge stage's and $P_n$ aside, which [`BindingStage`] holds.
pub const NUM_CHILDREN_POINTS: usize = 2 * (NUM_CHILD_POINTS - 2);

/// Length type for the [`ChildrenStage`] points.
pub type ChildrenLen = ConstLen<NUM_CHILDREN_POINTS>;

/// The number of the current step's points at the walk's tail.
const NUM_CURRENT_POINTS: usize = 6;

const _: () = assert!(
    NUM_ENDOSCALING_POINTS == 1 + 2 * NUM_CHILD_POINTS + NUM_CURRENT_POINTS,
    "the walk's layout does not match the nested batch"
);

/// The position of a child's $P_n$ among its points: the last, as
/// [`nested::pcs::child_commitments`] orders them.
const CHILD_P: usize = NUM_CHILD_POINTS - 1;

/// The position of a child's challenge-stage commitment among its points.
fn child_challenges() -> usize {
    nested::RxIndex::ChallengeStage.position()
}

/// Where an input of the walk lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSource {
    /// A child's challenge-stage commitment, in [`BindingStage`].
    Challenges(Side),
    /// A child's $P_n$, in [`BindingStage`].
    P(Side),
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
/// nested rx commitments in [`nested::RxIndex::ALL`] order, then its $a_n$,
/// $b_n$, `registry_xy` and $P_n$; then the current step's two
/// `registry_wx`, `registry_wy`, $A_n$, $B_n$ and `registry_xy`.
///
/// # Panics
///
/// Panics if `i` is not an input index.
pub fn input_source(i: usize) -> InputSource {
    if i < 2 * NUM_CHILD_POINTS {
        let side = if i < NUM_CHILD_POINTS {
            Side::Left
        } else {
            Side::Right
        };
        let k = i % NUM_CHILD_POINTS;
        let challenges = child_challenges();
        if k == challenges {
            return InputSource::Challenges(side);
        }
        if k == CHILD_P {
            return InputSource::P(side);
        }
        // P_n is the last point, so only the challenge stage can precede k.
        let offset = if k > challenges { k - 1 } else { k };
        let base = match side {
            Side::Left => 0,
            Side::Right => NUM_CHILD_POINTS - 2,
        };
        return InputSource::Children(base + offset);
    }
    match i - 2 * NUM_CHILD_POINTS {
        0 => InputSource::RegistryWx(0),
        1 => InputSource::RegistryWx(1),
        2 => InputSource::RegistryWy,
        3 => InputSource::AbA,
        4 => InputSource::AbB,
        5 => InputSource::RegistryXy,
        _ => panic!("input {i} is past the walk"),
    }
}

/// Witness of [`BindingStage`]: for each child, its challenge-stage
/// commitment and its $P_n$.
#[derive(Clone, Copy)]
pub struct BindingWitness<C: CurveAffine> {
    pub left_challenges: C,
    pub left_p: C,
    pub right_challenges: C,
    pub right_p: C,
}

/// Witness of [`ChildrenStage`].
#[derive(Clone)]
pub struct ChildrenWitness<C: CurveAffine> {
    pub points: FixedVec<C, ChildrenLen>,
}

/// Witness of [`RegistryWxStage`].
#[derive(Clone, Copy)]
pub struct RegistryWxWitness<C: CurveAffine> {
    pub registry_wx0: C,
    pub registry_wx1: C,
}

/// Witness of [`AbStage`].
#[derive(Clone, Copy)]
pub struct AbWitness<C: CurveAffine> {
    pub registry_wy: C,
    pub a: C,
    pub b: C,
}

/// Witness of [`FStage`].
#[derive(Clone, Copy)]
pub struct FWitness<C: CurveAffine> {
    pub registry_xy: C,
    pub f: C,
}

/// Witness of [`WalkStage`]: the endoscalar and the walk's outputs, one per
/// step.
#[derive(Clone)]
pub struct WalkWitness<C: CurveAffine> {
    pub endoscalar: u128,
    pub interstitials: FixedVec<C, NumSteps>,
}

impl<C: CurveAffine> WalkWitness<C> {
    /// The walk's outputs under `endoscalar`, from a simulated walk.
    pub fn new(
        endoscalar: u128,
        walk: PointsWitness<C, NUM_ENDOSCALING_POINTS, ENDOSCALINGS_PER_STEP>,
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
            .expect("NUM_ENDOSCALING_POINTS guarantees at least one interstitial")
    }
}

/// Splits the two children's points, each in the order
/// [`nested::pcs::child_commitments`] fixes, into the binding and children
/// stages' witnesses.
///
/// # Panics
///
/// Panics if either child has other than [`NUM_CHILD_POINTS`] points.
pub fn children_witnesses<C: CurveAffine>(
    left: &[C],
    right: &[C],
) -> (BindingWitness<C>, ChildrenWitness<C>) {
    assert_eq!(left.len(), NUM_CHILD_POINTS);
    assert_eq!(right.len(), NUM_CHILD_POINTS);
    let challenges = child_challenges();
    let rest = |points: &[C]| {
        points
            .iter()
            .enumerate()
            .filter(|&(k, _)| k != challenges && k != CHILD_P)
            .map(|(_, &point)| point)
            .collect::<Vec<_>>()
    };
    let mut points = rest(left);
    points.extend(rest(right));
    (
        BindingWitness {
            left_challenges: left[challenges],
            left_p: left[CHILD_P],
            right_challenges: right[challenges],
            right_p: right[CHILD_P],
        },
        ChildrenWitness {
            points: FixedVec::new(points).expect("NUM_CHILDREN_POINTS points"),
        },
    )
}

/// The witnesses of every input stage: the walk's inputs, in the stages
/// that commit them.
#[derive(Clone)]
pub struct Inputs<C: CurveAffine> {
    pub binding: BindingWitness<C>,
    pub children: ChildrenWitness<C>,
    pub registry_wx: RegistryWxWitness<C>,
    pub ab: AbWitness<C>,
    pub f: FWitness<C>,
}

impl<C: CurveAffine> Inputs<C> {
    /// Splits the walk's points, the initial $F_n$ first, into the stages.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != NUM_ENDOSCALING_POINTS`.
    pub fn from_walk(points: &[C]) -> Self {
        assert_eq!(points.len(), NUM_ENDOSCALING_POINTS);
        let input = |i: usize| points[1 + i];
        let mut binding = BindingWitness {
            left_challenges: C::identity(),
            left_p: C::identity(),
            right_challenges: C::identity(),
            right_p: C::identity(),
        };
        let mut children = Vec::with_capacity(NUM_CHILDREN_POINTS);
        let mut registry_wx = [C::identity(); 2];
        let mut registry_wy = C::identity();
        let mut ab = [C::identity(); 2];
        let mut registry_xy = C::identity();
        for i in 0..NumInputs::len() {
            match input_source(i) {
                InputSource::Challenges(Side::Left) => binding.left_challenges = input(i),
                InputSource::Challenges(Side::Right) => binding.right_challenges = input(i),
                InputSource::P(Side::Left) => binding.left_p = input(i),
                InputSource::P(Side::Right) => binding.right_p = input(i),
                InputSource::Children(k) => {
                    debug_assert_eq!(k, children.len());
                    children.push(input(i));
                }
                InputSource::RegistryWx(k) => registry_wx[k] = input(i),
                InputSource::RegistryWy => registry_wy = input(i),
                InputSource::AbA => ab[0] = input(i),
                InputSource::AbB => ab[1] = input(i),
                InputSource::RegistryXy => registry_xy = input(i),
            }
        }
        Self {
            binding,
            children: ChildrenWitness {
                points: FixedVec::new(children).expect("NUM_CHILDREN_POINTS points"),
            },
            registry_wx: RegistryWxWitness {
                registry_wx0: registry_wx[0],
                registry_wx1: registry_wx[1],
            },
            ab: AbWitness {
                registry_wy,
                a: ab[0],
                b: ab[1],
            },
            f: FWitness {
                registry_xy,
                f: points[0],
            },
        }
    }

    /// The walk's `i`-th input.
    pub fn input(&self, i: usize) -> C {
        match input_source(i) {
            InputSource::Challenges(Side::Left) => self.binding.left_challenges,
            InputSource::Challenges(Side::Right) => self.binding.right_challenges,
            InputSource::P(Side::Left) => self.binding.left_p,
            InputSource::P(Side::Right) => self.binding.right_p,
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
            .chain((0..NumInputs::len()).map(|i| self.input(i)))
            .collect()
    }
}

/// Output gadget of [`BindingStage`].
#[derive(Gadget, Consistent)]
pub struct Binding<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub left_challenges: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub left_p: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub right_challenges: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub right_p: Point<'dr, D, C>,
}

/// Output gadget of [`ChildrenStage`].
#[derive(Gadget, Consistent)]
pub struct Children<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub points: FixedVec<Point<'dr, D, C>, ChildrenLen>,
}

/// Output gadget of [`RegistryWxStage`].
#[derive(Gadget, Consistent)]
pub struct RegistryWx<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_wx0: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub registry_wx1: Point<'dr, D, C>,
}

/// Output gadget of [`AbStage`].
#[derive(Gadget, Consistent)]
pub struct Ab<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_wy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub a: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub b: Point<'dr, D, C>,
}

/// Output gadget of [`FStage`].
#[derive(Gadget, Consistent)]
pub struct F<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub registry_xy: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub f: Point<'dr, D, C>,
}

/// Output gadget of [`WalkStage`].
#[derive(Gadget)]
pub struct Walk<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub endoscalar: Endoscalar<'dr, D>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, NumSteps>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> Walk<'dr, D, C> {
    /// The walk's last interstitial: $P_n$.
    pub fn p(&self) -> &Point<'dr, D, C> {
        self.interstitials
            .last()
            .expect("NUM_ENDOSCALING_POINTS guarantees at least one interstitial")
    }
}

/// The loaded input stages, viewed as the walk's inputs.
pub struct WalkInputs<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pub binding: &'a Binding<'dr, D, C>,
    pub children: &'a Children<'dr, D, C>,
    pub registry_wx: &'a RegistryWx<'dr, D, C>,
    pub ab: &'a Ab<'dr, D, C>,
    pub f: &'a F<'dr, D, C>,
}

impl<'a, 'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> WalkInputs<'a, 'dr, D, C> {
    /// The walk's initial point, $F_n$.
    pub fn initial(&self) -> &'a Point<'dr, D, C> {
        &self.f.f
    }

    /// The walk's `i`-th input.
    pub fn input(&self, i: usize) -> &'a Point<'dr, D, C> {
        match input_source(i) {
            InputSource::Challenges(Side::Left) => &self.binding.left_challenges,
            InputSource::Challenges(Side::Right) => &self.binding.right_challenges,
            InputSource::P(Side::Left) => &self.binding.left_p,
            InputSource::P(Side::Right) => &self.binding.right_p,
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
        pub struct $Stage<C: CurveAffine>(PhantomData<C>);

        impl<C: CurveAffine, R: Rank> staging::Stage<C::Base, R> for $Stage<C> {
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

points_stage!(
    /// The root of the native stage tree: for each child, its challenge-stage
    /// commitment and its $P_n$, committed before $w$.
    BindingStage, parent = (), witness = BindingWitness, output = Binding,
    { left_challenges, left_p, right_challenges, right_p }
);

/// The rest of the children's nested commitments, committed before $w$.
#[derive(Default)]
pub struct ChildrenStage<C: CurveAffine>(PhantomData<C>);

impl<C: CurveAffine, R: Rank> staging::Stage<C::Base, R> for ChildrenStage<C> {
    type Parent = BindingStage<C>;
    type Witness<'source> = &'source ChildrenWitness<C>;
    type OutputKind = Kind![C::Base; Children<'_, _, C>];

    fn values() -> usize {
        2 * NUM_CHILDREN_POINTS
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
    RegistryWxStage, parent = ChildrenStage<C>, witness = RegistryWxWitness, output = RegistryWx,
    { registry_wx0, registry_wx1 }
);

points_stage!(
    /// The nested registry's $m_n(w_n, X, y_n)$ commitment and the nested
    /// accumulator's $A_n$ and $B_n$, committed before $x$.
    AbStage, parent = RegistryWxStage<C>, witness = AbWitness, output = Ab,
    { registry_wy, a, b }
);

points_stage!(
    /// The nested registry's $m_n(W, x_n, y_n)$ commitment and the nested
    /// quotient's $F_n$, the walk's initial point, committed before $u$.
    FStage, parent = AbStage<C>, witness = FWitness, output = F,
    { registry_xy, f }
);

/// The walk's stage: $\beta$'s bits, bound to `pre_beta` by
/// `bind_endoscalar`, and the walk's outputs, one per step, the last of
/// which is $P_n$; committed after $\beta$.
#[derive(Default)]
pub struct WalkStage<C: CurveAffine>(PhantomData<C>);

impl<C: CurveAffine, R: Rank> staging::Stage<C::Base, R> for WalkStage<C> {
    type Parent = FStage<C>;
    type Witness<'source> = &'source WalkWitness<C>;
    type OutputKind = Kind![C::Base; Walk<'_, _, C>];

    fn values() -> usize {
        // The endoscalar's bits, then (x, y) of one interstitial per step.
        u128::BITS as usize + 2 * NumSteps::len()
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
    use ragu_pasta::{EpAffine, Pasta};

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    type C = <Pasta as ragu_arithmetic::Cycle>::NestedCurve;

    #[test]
    fn stage_values_match_wire_counts() {
        let _: PhantomData<EpAffine> = PhantomData::<C>;
        assert_stage_values::<_, R, _>(&BindingStage::<C>::default());
        assert_stage_values::<_, R, _>(&ChildrenStage::<C>::default());
        assert_stage_values::<_, R, _>(&RegistryWxStage::<C>::default());
        assert_stage_values::<_, R, _>(&AbStage::<C>::default());
        assert_stage_values::<_, R, _>(&FStage::<C>::default());
        assert_stage_values::<_, R, _>(&WalkStage::<C>::default());
    }

    /// Every input has exactly one source, and splitting the walk into the
    /// stages and reading it back is the identity.
    #[test]
    fn walk_round_trips_through_the_stages() {
        use ragu_arithmetic::{
            group::{Curve, Group},
            rand::{SeedableRng, rngs::StdRng},
        };
        let mut rng = StdRng::seed_from_u64(7);
        let points: Vec<C> = (0..NUM_ENDOSCALING_POINTS)
            .map(|_| ragu_pasta::Ep::random(&mut rng).to_affine())
            .collect();
        let inputs = Inputs::from_walk(&points);
        assert_eq!(inputs.walk(), points);

        let mut children = alloc::vec![false; NUM_CHILDREN_POINTS];
        let mut binding = [false; 4];
        for i in 0..NumInputs::len() {
            match input_source(i) {
                InputSource::Challenges(Side::Left) => binding[0] = true,
                InputSource::P(Side::Left) => binding[1] = true,
                InputSource::Challenges(Side::Right) => binding[2] = true,
                InputSource::P(Side::Right) => binding[3] = true,
                InputSource::Children(k) => {
                    assert!(!children[k], "child point {k} sourced twice");
                    children[k] = true;
                }
                _ => {}
            }
        }
        assert!(binding.iter().all(|&b| b));
        assert!(children.iter().all(|&c| c));
    }

    /// A child's $P_n$ is the last of its points, where
    /// [`nested::pcs::child_commitments`] puts it.
    #[test]
    fn child_p_is_the_last_child_point() {
        assert_eq!(input_source(CHILD_P), InputSource::P(Side::Left));
        assert_eq!(
            input_source(NUM_CHILD_POINTS + CHILD_P),
            InputSource::P(Side::Right)
        );
        assert!(child_challenges() < CHILD_P);
    }
}
