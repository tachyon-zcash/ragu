//! The endoscaling walk: the stages that hold it and the nested step
//! circuit.
//!
//! The walk computes iterated endoscalar multiplications by Horner's rule.
//! It is a paged walk (see [`paging`]): its unit is
//! [`PointHorner`], `[e] acc + input`, and each step
//! circuit is one page of up to `E` endoscalings, whose result the step
//! holds to its interstitial.
//!
//! The structure separates points into:
//! - `initial`: The walk's initial state, which step 0 starts from
//! - `inputs`: Additional points to endoscale (length = `N::len() - 1`)
//! - `interstitials`: Output points, one per step
//!
//! All steps are uniform: step N initializes from `interstitials[N-1]` (or
//! `initial` for step 0) and iterates over `inputs[E*N..E*(N+1)]`.
//!
//! The step counting and points layout serve both walks of the curve cycle,
//! which differ in their number of points and in how many endoscalings a
//! step can afford beside the stages it reserves, so they are generic over
//! the curve type, the number of points `N` and the endoscalings per step
//! `E`, both as [`Len`] types: a profile sets the endoscalings per step to
//! what its rank's budget fits (see [`Profile`](crate::profile::Profile)).
//! The step circuit here is the nested walk's, reading the endoscalar and
//! points stages; the native walk reads its points from several stages and
//! has its own step in [`native::circuits::endoscaling_step`].
//!
//! [`native::circuits::endoscaling_step`]: crate::internal::native::circuits::endoscaling_step

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStageCircuit, Stage, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS, HoistedEndoscalar, Point, Uendo,
    consistent::Consistent,
    vec::{ConstLen, FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::paging::{self, Grouping, PointHorner};

/// Number of inputs (excluding initial) for a walk over `N` points.
pub struct InputsLen<N: Len>(core::marker::PhantomData<N>);

impl<N: Len> Len for InputsLen<N> {
    fn len() -> usize {
        let num_points = N::len();
        assert!(num_points > 0);
        num_points - 1
    }
}

/// Compute the number of endoscaling steps for `num_points` curve points at
/// `endoscalings` per step: the pages of a walk whose initial state is the
/// first point and whose inputs are the rest.
///
/// This is `ceil((num_points - 1) / endoscalings).max(1)`.
pub(crate) const fn num_steps(endoscalings: usize, num_points: usize) -> usize {
    assert!(num_points > 0);
    paging::num_pages(endoscalings, num_points - 1)
}

/// Number of steps (= interstitials) for a walk over `N` points at `E`
/// endoscalings per step.
pub struct NumStepsLen<N: Len, E: Len>(core::marker::PhantomData<(N, E)>);

impl<N: Len, E: Len> Len for NumStepsLen<N, E> {
    fn len() -> usize {
        num_steps(E::len(), N::len())
    }
}

/// Stage for allocating the endoscalar witness: its bits and, hoisted so
/// that every step selects its digit points in two gates, its per-digit bit
/// products. The nested collapse circuit re-emits the gadget's contracts
/// once.
#[derive(Default)]
pub struct EndoscalarStage;

impl<F: Field, R: Rank> Stage<F, R> for EndoscalarStage {
    type Parent = ();

    fn values() -> usize {
        ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS
    }

    type Witness<'source> = Uendo;
    type OutputKind = Kind![F; HoistedEndoscalar<'_, _>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        HoistedEndoscalar::alloc(dr, witness)
    }
}

/// The stage between [`EndoscalarStage`] and [`PointsStage`] when nothing
/// sits there: no values.
#[derive(Default)]
pub struct NoGap;

impl<F: Field, R: Rank> Stage<F, R> for NoGap {
    type Parent = EndoscalarStage;

    fn values() -> usize {
        0
    }

    type Witness<'source> = ();
    type OutputKind = Kind![F; ()];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(())
    }
}

/// The grouping of a walk in one stage: no groups, no links. The default
/// of every type here.
pub type Whole = ConstLen<0>;

/// The grouping of a walk over `N` points at `E` endoscalings per step
/// into groups of `Q` steps (see [`paging::Grouping`]). A `Q` of zero,
/// [`Whole`], keeps the walk in one points stage.
pub fn grouping<N: Len, E: Len, Q: Len>() -> Grouping {
    Grouping::new(E::len(), InputsLen::<N>::len(), Q::len())
}

/// Length type for the inputs one points stage holds: every input of the
/// walk for [`Whole`], a full group's otherwise.
pub struct GroupInputsLen<N: Len, E: Len, Q: Len>(PhantomData<(N, E, Q)>);

impl<N: Len, E: Len, Q: Len> Len for GroupInputsLen<N, E, Q> {
    fn len() -> usize {
        grouping::<N, E, Q>().group_inputs()
    }
}

/// Length type for the interstitials one points stage holds: one per step
/// of the walk for [`Whole`], one per step of a full group otherwise.
pub struct GroupStepsLen<N: Len, E: Len, Q: Len>(PhantomData<(N, E, Q)>);

impl<N: Len, E: Len, Q: Len> Len for GroupStepsLen<N, E, Q> {
    fn len() -> usize {
        grouping::<N, E, Q>().group_pages()
    }
}

/// Length type for the states the links stage holds: none for [`Whole`],
/// one per group boundary otherwise.
pub struct LinksLen<N: Len, E: Len, Q: Len>(PhantomData<(N, E, Q)>);

impl<N: Len, E: Len, Q: Len> Len for LinksLen<N, E, Q> {
    fn len() -> usize {
        grouping::<N, E, Q>().links()
    }
}

/// Witness for one points stage: a group's entry point, its inputs and its
/// interstitials. For [`Whole`] the one group is the walk.
pub struct PointsWitness<C: Affine, N: Len, E: Len, Q: Len = Whole> {
    /// The state the group starts from: the walk's initial point for the
    /// first group.
    pub initial: C,
    /// The group's inputs. For [`Whole`], length = `N::len() - 1`.
    pub inputs: FixedVec<C, GroupInputsLen<N, E, Q>>,
    /// Interstitial outputs, one per step of the group.
    pub interstitials: FixedVec<C, GroupStepsLen<N, E, Q>>,
}

// The length types are markers, so a derive's `Clone` bounds on them do not
// hold.
impl<C: Affine, N: Len, E: Len, Q: Len> Clone for PointsWitness<C, N, E, Q> {
    fn clone(&self) -> Self {
        PointsWitness {
            initial: self.initial,
            inputs: self.inputs.clone(),
            interstitials: self.interstitials.clone(),
        }
    }
}

impl<C: Affine, N: Len, E: Len> PointsWitness<C, N, E> {
    /// Creates a new `PointsWitness` from points and an endoscalar, for a
    /// walk in one stage.
    ///
    /// The first point becomes `initial`, remaining points become `inputs`,
    /// and `interstitials` are computed by simulating the Horner evaluation.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != N::len()`.
    pub fn new(endoscalar: Uendo, points: &[C]) -> Self {
        let mut walk = WalkWitness::<C, N, E>::new(endoscalar, points);
        walk.groups.pop().expect("a walk in one stage is one group")
    }
}

/// Witness for a whole walk: every group's points stage and the links.
pub struct WalkWitness<C: Affine, N: Len, E: Len, Q: Len = Whole> {
    /// The links stage's states: the walk's initial point, then the state
    /// after each group. Empty for [`Whole`].
    pub links: FixedVec<C, LinksLen<N, E, Q>>,
    /// Each group's points stage.
    pub groups: Vec<PointsWitness<C, N, E, Q>>,
}

impl<C: Affine, N: Len, E: Len, Q: Len> Clone for WalkWitness<C, N, E, Q> {
    fn clone(&self) -> Self {
        WalkWitness {
            links: self.links.clone(),
            groups: self.groups.clone(),
        }
    }
}

impl<C: Affine, N: Len, E: Len, Q: Len> WalkWitness<C, N, E, Q> {
    /// Creates the witness of the walk over `points` under `endoscalar`.
    ///
    /// The first point is the walk's initial point and the rest are its
    /// inputs. [`paging::Grouping::arrange`] computes each group's states.
    /// A short last group's unused inputs hold the initial point.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != N::len()`.
    pub fn new(endoscalar: Uendo, points: &[C]) -> Self {
        let num_points = N::len();
        assert_eq!(points.len(), num_points, "expected {num_points} points");

        let initial = points[0];
        let endoscalar: C::Scalar = ragu_primitives::lift_endoscalar(endoscalar);
        let arranged = grouping::<N, E, Q>().arrange(
            initial.to_projective(),
            &points[1..],
            initial,
            |acc, input| *acc = *acc * endoscalar + input.to_projective(),
        );

        // Batch normalize the projective states to affine.
        let affine = |states: &[<C as udon::curve::Affine>::Projective]| {
            let mut tmp = vec![C::identity(); states.len()];
            C::batch_to_affine(states, &mut tmp);
            tmp
        };
        let links = FixedVec::new(affine(&arranged.links)).expect("correct length");
        let groups = arranged
            .groups
            .into_iter()
            .map(|group| {
                let mut states = group.interstitials;
                states.push(group.entry);
                let mut states = affine(&states);
                let initial = states.pop().expect("the entry state");
                PointsWitness {
                    initial,
                    inputs: FixedVec::new(group.inputs).expect("correct length"),
                    interstitials: FixedVec::new(states).expect("correct length"),
                }
            })
            .collect();

        Self { links, groups }
    }

    /// Returns the walk's result: the state after its last step.
    #[cfg_attr(not(test), expect(dead_code, reason = "no walk is grouped yet"))]
    pub fn result(&self) -> C {
        let grouping = grouping::<N, E, Q>();
        let last = grouping.groups() - 1;
        self.groups[last].interstitials[grouping.pages_of(last) - 1]
    }
}

/// Output gadget containing initial, inputs, and interstitials. See [`PointsWitness`].
#[derive(Gadget, Consistent)]
pub struct Points<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, N: Len, E: Len, Q: Len> {
    #[ragu(gadget)]
    pub initial: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub inputs: FixedVec<Point<'dr, D, C>, GroupInputsLen<N, E, Q>>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, GroupStepsLen<N, E, Q>>,
}

/// Stage for allocating the point witnesses of one group (inputs and
/// interstitials). It follows the gap stage `G`, which follows
/// [`EndoscalarStage`].
///
/// Every group of a walk has its own polynomial of this one stage type, so
/// all groups sit at the same gates and share one stage mask and one final
/// mask. Which group a polynomial holds is in its witness alone. For
/// [`Whole`] the one group is the walk.
pub struct PointsStage<C: Affine, N: Len, E: Len, G = NoGap, Q: Len = Whole>(
    PhantomData<(C, N, E, G, Q)>,
);

impl<C: Affine, N: Len, E: Len, G, Q: Len> Default for PointsStage<C, N, E, G, Q> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C: Affine, R: Rank, N: Len, E: Len, G: Stage<C::Base, R>, Q: Len> Stage<C::Base, R>
    for PointsStage<C, N, E, G, Q>
{
    type Parent = G;

    fn values() -> usize {
        // (x, y) coordinates for initial + inputs + interstitials.
        2 * (1 + GroupInputsLen::<N, E, Q>::len() + GroupStepsLen::<N, E, Q>::len())
    }

    type Witness<'source> = &'source PointsWitness<C, N, E, Q>;
    type OutputKind = Kind![C::Base; Points<'_, _, C, N, E, Q>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let initial = Point::alloc(dr, witness.as_ref().map(|w| w.initial))?;
        let inputs =
            FixedVec::try_from_fn(|i| Point::alloc(dr, witness.as_ref().map(|w| w.inputs[i])))?;
        let interstitials = FixedVec::try_from_fn(|i| {
            Point::alloc(dr, witness.as_ref().map(|w| w.interstitials[i]))
        })?;
        Ok(Points {
            initial,
            inputs,
            interstitials,
        })
    }
}

/// Output gadget of [`LinksStage`]: the walk's initial point, then the
/// state after each group.
#[cfg_attr(not(test), expect(dead_code, reason = "no walk is grouped yet"))]
#[derive(Gadget, Consistent)]
pub struct Links<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, N: Len, E: Len, Q: Len> {
    #[ragu(gadget)]
    pub states: FixedVec<Point<'dr, D, C>, LinksLen<N, E, Q>>,
}

/// Stage for the links of a grouped walk, which chain its groups (see
/// [`paging`](paging#groups)). It follows [`PointsStage`], so a step does
/// not load it: the circuit that checks a group does, and holds the
/// group's entry and exit to it with [`paging::link`].
///
/// For [`Whole`] the stage holds nothing and takes no gates.
#[cfg_attr(not(test), expect(dead_code, reason = "no walk is grouped yet"))]
pub struct LinksStage<C: Affine, N: Len, E: Len, G = NoGap, Q: Len = Whole>(
    PhantomData<(C, N, E, G, Q)>,
);

impl<C: Affine, N: Len, E: Len, G, Q: Len> Default for LinksStage<C, N, E, G, Q> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C: Affine, R: Rank, N: Len, E: Len, G: Stage<C::Base, R>, Q: Len> Stage<C::Base, R>
    for LinksStage<C, N, E, G, Q>
{
    type Parent = PointsStage<C, N, E, G, Q>;

    fn values() -> usize {
        2 * LinksLen::<N, E, Q>::len()
    }

    type Witness<'source> = &'source FixedVec<C, LinksLen<N, E, Q>>;
    type OutputKind = Kind![C::Base; Links<'_, _, C, N, E, Q>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Links {
            states: FixedVec::try_from_fn(|i| Point::alloc(dr, witness.as_ref().map(|w| w[i])))?,
        })
    }
}

/// The loaded endoscalar stage and one group's points stage, as the walk a
/// step of that group is a page of: the group's own walk, from its entry
/// point over its own inputs.
struct Loaded<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, N: Len, E: Len, Q: Len> {
    unit: PointHorner<'a, 'dr, D, C>,
    points: &'a Points<'dr, D, C, N, E, Q>,
    /// The number of inputs of the group the points stage holds.
    num_inputs: usize,
}

impl<'a, 'dr, D: Driver<'dr>, C: Affine<Base = D::F>, N: Len, E: Len, Q: Len> paging::Walk<'dr, D>
    for Loaded<'a, 'dr, D, C, N, E, Q>
{
    type Unit = PointHorner<'a, 'dr, D, C>;

    fn unit(&self) -> &Self::Unit {
        &self.unit
    }

    fn capacity(&self) -> usize {
        E::len()
    }

    fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    fn initial(&self) -> &Point<'dr, D, C> {
        &self.points.initial
    }

    fn input(&self, index: usize) -> &Point<'dr, D, C> {
        &self.points.inputs[index]
    }

    fn interstitial(&self, page: usize) -> &Point<'dr, D, C> {
        &self.points.interstitials[page]
    }
}

/// One step of the endoscaling walk: one page of up to `E` endoscalings.
///
/// - Step 0 initializes from `initial`, iterates over its slice of `inputs[0..E]`
/// - Step N (N > 0) initializes from `interstitials[N-1]`, iterates over
///   `inputs[N*E..(N+1)*E]` (clamped to bounds)
///
/// The circuit constrains that `interstitials[step]` equals the Horner
/// result ([`paging::page`]).
///
/// In a grouped walk the step is a page of its group's own walk: it loads
/// its group's points stage polynomial, and the indices above are within
/// the group ([`group`](Self::group)).
pub struct EndoscalingStep<C: Affine, R: Rank, N: Len, E: Len, G = NoGap, Q: Len = Whole> {
    step: usize,
    _marker: PhantomData<(C, R, N, E, G, Q)>,
}

impl<C: Affine, R: Rank, N: Len, E: Len, G, Q: Len> Clone for EndoscalingStep<C, R, N, E, G, Q> {
    fn clone(&self) -> Self {
        Self {
            step: self.step,
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, N: Len, E: Len, G, Q: Len> EndoscalingStep<C, R, N, E, G, Q> {
    /// Creates a new endoscaling step.
    ///
    /// Panics if `step >= NumStepsLen::<N, E>::len()`.
    pub fn new(step: usize) -> Self {
        let num_steps = NumStepsLen::<N, E>::len();
        assert!(
            step < num_steps,
            "step {} exceeds available steps (num_steps = {})",
            step,
            num_steps
        );
        Self {
            step,
            _marker: PhantomData,
        }
    }

    /// Returns the group the step belongs to: the group whose points stage
    /// polynomial the step loads and its claim takes. Zero for [`Whole`].
    #[cfg_attr(not(test), expect(dead_code, reason = "no walk is grouped yet"))]
    pub fn group(&self) -> usize {
        grouping::<N, E, Q>().locate(self.step).0
    }
}

/// Witness for an endoscaling step.
pub struct EndoscalingStepWitness<'source, C: Affine, N: Len, E: Len, Q: Len = Whole> {
    /// The endoscalar value.
    pub endoscalar: Uendo,
    /// Point witnesses (inputs and interstitials) of the step's group.
    pub points: &'source PointsWitness<C, N, E, Q>,
}

impl<C: Affine, R: Rank, N: Len, E: Len, G, Q: Len> MultiStageCircuit<C::Base, R>
    for EndoscalingStep<C, R, N, E, G, Q>
where
    G: Stage<C::Base, R, Parent = EndoscalarStage> + Default + Send + Sync + 'static,
{
    type Last = PointsStage<C, N, E, G, Q>;
    type Instance<'source> = ();
    type Witness<'source> = EndoscalingStepWitness<'source, C, N, E, Q>;
    type Output = Kind![C::Base; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (endoscalar_guard, dr) = dr.add_stage::<EndoscalarStage>()?;
        let dr = dr.skip_stage::<G>()?;
        let (points_guard, dr) = dr.add_stage::<PointsStage<C, N, E, G, Q>>()?;
        let dr = dr.finish();

        // Stages are loaded unenforced here: the collapse circuit re-emits
        // the walk's contracts once for the whole nested section, the points'
        // curve membership and the hoisted endoscalar's, boolean bits with
        // product wires the products of those bits. This only constrains the
        // Horner accumulation relationship between inputs and interstitials.
        let endoscalar = endoscalar_guard.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?;
        let points = points_guard.unenforced(dr, witness.as_ref().map(|w| w.points))?;

        // The step is one page of its group's walk: from the group's entry
        // point or the previous interstitial, Horner's rule over the step's
        // inputs, held to the step's own interstitial. With only the
        // initial point, the page applies nothing and holds it to the
        // output.
        let grouping = grouping::<N, E, Q>();
        let (group, page) = grouping.locate(self.step);
        paging::page(
            dr,
            &Loaded {
                unit: PointHorner::new(&endoscalar),
                points: &points,
                num_inputs: grouping.inputs_of(group).len(),
            },
            page,
        )?;

        Ok(WithAux::new((), D::unit()))
    }
}

#[cfg(test)]
#[path = "../../../tests/endoscalar_groups.rs"]
mod group_tests;

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ragu_circuits::{
        CircuitExt,
        polynomials::{self},
        staging::{MultiStage, StageExt},
    };
    use ragu_core::{
        Result,
        drivers::emulator::{Emulator, Wired},
        maybe::Maybe,
        pasta::{Ep, EpAffine, EqAffine, Fp, Fq},
    };
    use ragu_primitives::{
        Endoscalar, Uendo,
        vec::{ConstLen, Len},
    };
    use ragu_testing::registry::TestRegistryBuilder;
    use rand::{Rng, RngExt};
    use udon::{
        curve::{Affine, Projective},
        field::Field,
    };

    /// The endoscalings per step these tests lay the walk out with.
    type E = ConstLen<4>;

    use super::{
        EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, InputsLen, NumStepsLen,
        PointsStage, PointsWitness,
    };
    use crate::{
        internal::{nested, tests::assert_stage_values},
        profile::Standard,
    };

    type R = polynomials::WalletRank;

    /// Computes the effective scalar for an endoscalar via emulated `lift`.
    fn compute_effective_scalar(endo: Uendo) -> Fq {
        Emulator::<Wired<Fq>>::emulate_wired(endo, |dr, witness| {
            let e = Endoscalar::alloc(dr, witness)?;
            let scalar = e.lift(dr)?;
            Ok(*scalar.value().take())
        })
        .unwrap()
    }

    /// Computes Horner's rule result using native curve arithmetic.
    ///
    /// For inputs $[s_0, s_1, \ldots, s_N]$ and effective scalar $e$:
    ///
    /// $$\text{result} = e^N \cdot s_0 + e^{N-1} \cdot s_1 + \cdots + e \cdot s_{N-1} + s_N$$
    fn compute_horner_native(endo: Uendo, inputs: &[EpAffine]) -> EpAffine {
        assert!(!inputs.is_empty());
        let e: Fq = compute_effective_scalar(endo);

        let mut acc = inputs[0].to_projective();
        for input in &inputs[1..] {
            acc = acc * e + input.to_projective();
        }
        acc.to_affine()
    }

    /// Helper to compute interstitials for a given set of inputs.
    ///
    /// Takes the initial point and a separate inputs array (length NUM_POINTS - 1),
    /// mirroring the new uniform step structure.
    fn compute_interstitials<const NUM_POINTS: usize>(
        endoscalar: Uendo,
        initial: EpAffine,
        inputs: &[EpAffine],
    ) -> Vec<EpAffine> {
        let num_steps = NumStepsLen::<ConstLen<NUM_POINTS>, E>::len();
        let inputs_len = InputsLen::<ConstLen<NUM_POINTS>>::len();
        let mut interstitials = Vec::with_capacity(num_steps);

        for step in 0..num_steps {
            // Compute input range for this step (uniform across all steps)
            let start = step * E::len();
            let end = (start + E::len()).min(inputs_len);

            // Gather inputs for Horner computation
            let mut step_inputs = Vec::new();

            // Initial accumulator
            if step > 0 {
                step_inputs.push(interstitials[step - 1]);
            } else {
                step_inputs.push(initial);
            }

            // Add inputs for this step
            for input in inputs.iter().skip(start).take(end - start) {
                step_inputs.push(*input);
            }

            interstitials.push(compute_horner_native(endoscalar, &step_inputs));
        }

        interstitials
    }

    #[test]
    fn test_endoscaling_steps() -> Result<()> {
        // Test with 13 total points (1 initial + 12 inputs = 3 steps of 4)
        const NUM_POINTS: usize = 13;
        let num_steps = NumStepsLen::<ConstLen<NUM_POINTS>, E>::len();

        // Generate random endoscalar and base input points.
        let endoscalar = Uendo::random(|| rand::rng().random());
        let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
            (Ep::generator()
                * <Ep as Projective>::Scalar::random(|bytes| rand::rng().fill_bytes(bytes)))
            .to_affine()
        });

        // Compute expected final result via Horner over all base inputs.
        let expected = compute_horner_native(endoscalar, &base_inputs);

        // Construct witness using the constructor
        let points =
            PointsWitness::<EpAffine, ConstLen<NUM_POINTS>, E>::new(endoscalar, &base_inputs);

        // Verify final interstitial matches expected
        assert_eq!(points.interstitials[num_steps - 1], expected);

        // Run each step through the multi-stage circuit and verify correctness.
        for step in 0..num_steps {
            let step_circuit = EndoscalingStep::<EpAffine, R, ConstLen<NUM_POINTS>, E>::new(step);
            let mut builder = TestRegistryBuilder::new();
            let staged_h = builder.register_circuit(MultiStage::new(step_circuit.clone()))?;
            let endo_mask_h =
                builder.register_mask(<EndoscalarStage as StageExt<Fp, R>>::stage_mask()?);
            let pts_mask_h = builder
                .register_mask(PointsStage::<EpAffine, ConstLen<NUM_POINTS>, E>::stage_mask()?);
            let final_mask_h =
                builder
                    .register_mask(PointsStage::<EpAffine, ConstLen<NUM_POINTS>, E>::final_mask()?);
            let registry = builder.finalize()?;

            let staged = MultiStage::new(step_circuit);

            let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(Fp::ZERO, endoscalar)?;
            let points_rx =
                <PointsStage<EpAffine, ConstLen<NUM_POINTS>, E> as StageExt<Fp, R>>::rx(
                    Fp::ZERO,
                    &points,
                )?;
            let final_trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar,
                    points: &points,
                })?
                .into_output();
            let final_rx = registry.assemble(&final_trace, staged_h, Fp::ZERO)?;

            let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

            // Verify revdot identities for each stage.
            assert_eq!(endoscalar_rx.revdot(&registry.y(endo_mask_h, y)), Fp::ZERO);
            assert_eq!(points_rx.revdot(&registry.y(pts_mask_h, y)), Fp::ZERO);
            assert_eq!(final_rx.revdot(&registry.y(final_mask_h, y)), Fp::ZERO);

            // Verify combined circuit identity.
            let mut lhs = final_rx.clone();
            lhs.add_assign(&endoscalar_rx);
            lhs.add_assign(&points_rx);
            assert_eq!(lhs.revdot(&registry.y(staged_h, y)), staged.ky((), y)?);
        }

        Ok(())
    }

    #[test]
    fn test_endoscaling_variable_length() -> Result<()> {
        // Test with 11 total points (1 initial + 10 inputs, not divisible by 4)
        // Step 0: initial + inputs[0..4], output interstitial[0]
        // Step 1: interstitial[0] + inputs[4..8], output interstitial[1]
        // Step 2: interstitial[1] + inputs[8..10], output interstitial[2]
        const NUM_POINTS: usize = 11;
        let num_steps = NumStepsLen::<ConstLen<NUM_POINTS>, E>::len();

        // Verify computed constants match expectations
        // With 10 inputs, we need ceil(10/4) = 3 steps
        assert_eq!(num_steps, 3);
        assert_eq!(NumStepsLen::<ConstLen<NUM_POINTS>, E>::len(), 3);
        assert_eq!(InputsLen::<ConstLen<NUM_POINTS>>::len(), 10);

        // Generate random endoscalar and base input points.
        let endoscalar = Uendo::random(|| rand::rng().random());
        let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
            (Ep::generator()
                * <Ep as Projective>::Scalar::random(|bytes| rand::rng().fill_bytes(bytes)))
            .to_affine()
        });

        // Compute expected final result via Horner over all base inputs.
        let expected = compute_horner_native(endoscalar, &base_inputs);

        // Construct witness using the constructor
        let points =
            PointsWitness::<EpAffine, ConstLen<NUM_POINTS>, E>::new(endoscalar, &base_inputs);

        // Verify final interstitial matches expected
        assert_eq!(points.interstitials[num_steps - 1], expected);

        // Run each step through the multi-stage circuit.
        for step in 0..num_steps {
            let step_circuit = EndoscalingStep::<EpAffine, R, ConstLen<NUM_POINTS>, E>::new(step);
            let mut builder = TestRegistryBuilder::new();
            let staged_h = builder.register_circuit(MultiStage::new(step_circuit.clone()))?;
            builder.register_mask(<EndoscalarStage as StageExt<Fp, R>>::stage_mask()?);
            builder.register_mask(PointsStage::<EpAffine, ConstLen<NUM_POINTS>, E>::stage_mask()?);
            builder.register_mask(PointsStage::<EpAffine, ConstLen<NUM_POINTS>, E>::final_mask()?);
            let registry = builder.finalize()?;

            let staged = MultiStage::new(step_circuit);

            let final_trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar,
                    points: &points,
                })?
                .into_output();
            let final_rx = registry.assemble(&final_trace, staged_h, Fp::ZERO)?;

            let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));

            let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(Fp::ZERO, endoscalar)?;
            let points_rx =
                <PointsStage<EpAffine, ConstLen<NUM_POINTS>, E> as StageExt<Fp, R>>::rx(
                    Fp::ZERO,
                    &points,
                )?;

            // Verify combined circuit identity.
            let mut lhs = final_rx.clone();
            lhs.add_assign(&endoscalar_rx);
            lhs.add_assign(&points_rx);
            assert_eq!(lhs.revdot(&registry.y(staged_h, y)), staged.ky((), y)?);
        }

        Ok(())
    }

    #[test]
    fn test_endoscaling_single_point() -> Result<()> {
        const NUM_POINTS: usize = 1;
        let endoscalar = Uendo::from(7u128);
        let initial = Ep::generator().to_affine();
        let mut points =
            PointsWitness::<EpAffine, ConstLen<NUM_POINTS>, E>::new(endoscalar, &[initial]);
        let step = EndoscalingStep::<EpAffine, R, ConstLen<NUM_POINTS>, E>::new(0);

        let mut builder = TestRegistryBuilder::new();
        let staged_h = builder.register_circuit(MultiStage::new(step.clone()))?;
        builder.register_mask(<EndoscalarStage as StageExt<Fp, R>>::stage_mask()?);
        builder.register_mask(PointsStage::<EpAffine, ConstLen<NUM_POINTS>, E>::stage_mask()?);
        builder.register_mask(PointsStage::<EpAffine, ConstLen<NUM_POINTS>, E>::final_mask()?);
        let registry = builder.finalize()?;
        let staged = MultiStage::new(step);
        let y = Fp::from(7);
        let sy = registry.y(staged_h, y);
        let ky = staged.ky((), y)?;
        let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(Fp::ZERO, endoscalar)?;

        // The one-point walk must accept its initial point and reject a
        // different output, even though it performs no endoscalings.
        for (output, valid) in [(initial, true), (-initial, false)] {
            points.interstitials[0] = output;
            let trace = staged
                .trace(EndoscalingStepWitness {
                    endoscalar,
                    points: &points,
                })?
                .into_output();
            let mut rx = registry.assemble(&trace, staged_h, Fp::ZERO)?;
            let points_rx =
                <PointsStage<EpAffine, ConstLen<NUM_POINTS>, E> as StageExt<Fp, R>>::rx(
                    Fp::ZERO,
                    &points,
                )?;
            rx.add_assign(&endoscalar_rx);
            rx.add_assign(&points_rx);
            assert_eq!(rx.revdot(&sy) == ky, valid);
        }

        Ok(())
    }

    #[test]
    fn test_num_steps_len() {
        // With uniform steps, each step consumes up to 4 inputs.
        // InputsLen = NUM_POINTS - 1, NumSteps = max(ceil(InputsLen / 4), 1)
        // Assumes NUM_POINTS > 0.

        // 1 total point = 0 inputs = 1 step (base case)
        assert_eq!(NumStepsLen::<ConstLen<1>, E>::len(), 1);

        // 2-5 total points = 1-4 inputs = 1 step
        assert_eq!(NumStepsLen::<ConstLen<2>, E>::len(), 1);
        assert_eq!(NumStepsLen::<ConstLen<3>, E>::len(), 1);
        assert_eq!(NumStepsLen::<ConstLen<4>, E>::len(), 1);
        assert_eq!(NumStepsLen::<ConstLen<5>, E>::len(), 1);

        // 6-9 total points = 5-8 inputs = 2 steps
        assert_eq!(NumStepsLen::<ConstLen<6>, E>::len(), 2);
        assert_eq!(NumStepsLen::<ConstLen<7>, E>::len(), 2);
        assert_eq!(NumStepsLen::<ConstLen<8>, E>::len(), 2);
        assert_eq!(NumStepsLen::<ConstLen<9>, E>::len(), 2);

        // 10-13 total points = 9-12 inputs = 3 steps
        assert_eq!(NumStepsLen::<ConstLen<10>, E>::len(), 3);
        assert_eq!(NumStepsLen::<ConstLen<11>, E>::len(), 3);
        assert_eq!(NumStepsLen::<ConstLen<12>, E>::len(), 3);
        assert_eq!(NumStepsLen::<ConstLen<13>, E>::len(), 3);

        // 14-17 total points = 13-16 inputs = 4 steps
        assert_eq!(NumStepsLen::<ConstLen<14>, E>::len(), 4);
        assert_eq!(NumStepsLen::<ConstLen<15>, E>::len(), 4);
        assert_eq!(NumStepsLen::<ConstLen<16>, E>::len(), 4);
        assert_eq!(NumStepsLen::<ConstLen<17>, E>::len(), 4);

        // 18-21 total points = 17-20 inputs = 5 steps
        assert_eq!(NumStepsLen::<ConstLen<18>, E>::len(), 5);
        assert_eq!(NumStepsLen::<ConstLen<19>, E>::len(), 5);
        assert_eq!(NumStepsLen::<ConstLen<20>, E>::len(), 5);
        assert_eq!(NumStepsLen::<ConstLen<21>, E>::len(), 5);
    }

    #[test]
    fn test_input_range() {
        // Helper to get input_range for a given NUM_POINTS and step
        fn range<const NUM_POINTS: usize>(step: usize) -> core::ops::Range<usize> {
            super::paging::range(E::len(), step, InputsLen::<ConstLen<NUM_POINTS>>::len())
        }

        // NUM_POINTS = 1: 0 inputs, 1 step
        // Step 0 has empty range (no inputs to iterate)
        assert_eq!(range::<1>(0), 0..0);

        // NUM_POINTS = 2: 1 input, 1 step
        assert_eq!(range::<2>(0), 0..1);

        // NUM_POINTS = 5: 4 inputs, 1 step (exactly fills one step)
        assert_eq!(range::<5>(0), 0..4);

        // NUM_POINTS = 6: 5 inputs, 2 steps
        // Step 0: inputs[0..4]
        // Step 1: inputs[4..5]
        assert_eq!(range::<6>(0), 0..4);
        assert_eq!(range::<6>(1), 4..5);

        // NUM_POINTS = 9: 8 inputs, 2 steps (exactly fills two steps)
        assert_eq!(range::<9>(0), 0..4);
        assert_eq!(range::<9>(1), 4..8);

        // NUM_POINTS = 11: 10 inputs, 3 steps
        // Step 0: inputs[0..4]
        // Step 1: inputs[4..8]
        // Step 2: inputs[8..10]
        assert_eq!(range::<11>(0), 0..4);
        assert_eq!(range::<11>(1), 4..8);
        assert_eq!(range::<11>(2), 8..10);

        // NUM_POINTS = 13: 12 inputs, 3 steps (exactly fills three steps)
        assert_eq!(range::<13>(0), 0..4);
        assert_eq!(range::<13>(1), 4..8);
        assert_eq!(range::<13>(2), 8..12);

        // NUM_POINTS = 14: 13 inputs, 4 steps
        // Step 3 has only 1 input
        assert_eq!(range::<14>(0), 0..4);
        assert_eq!(range::<14>(1), 4..8);
        assert_eq!(range::<14>(2), 8..12);
        assert_eq!(range::<14>(3), 12..13);
    }

    #[test]
    fn test_points_witness_new() {
        /// Verifies PointsWitness::new produces identical results to manual construction.
        fn check<const NUM_POINTS: usize>() {
            let endoscalar = Uendo::random(|| rand::rng().random());
            let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
                (Ep::generator()
                    * <Ep as Projective>::Scalar::random(|bytes| rand::rng().fill_bytes(bytes)))
                .to_affine()
            });

            // Compute via PointsWitness::new
            let from_new =
                PointsWitness::<EpAffine, ConstLen<NUM_POINTS>, E>::new(endoscalar, &base_inputs);

            // Compute manually using test helper
            let initial = base_inputs[0];
            let inputs_slice = &base_inputs[1..];
            let interstitials_vec =
                compute_interstitials::<NUM_POINTS>(endoscalar, initial, inputs_slice);

            // Verify initial
            assert_eq!(from_new.initial, initial);

            // Verify inputs
            for (a, b) in from_new.inputs.iter().zip(inputs_slice) {
                assert_eq!(a, b);
            }

            // Verify interstitials
            for (a, b) in from_new.interstitials.iter().zip(&interstitials_vec) {
                assert_eq!(a, b);
            }
        }

        // Test edge case: NUM_POINTS == 1 (no inputs, 1 step)
        check::<1>();

        // Test small cases
        check::<2>();
        check::<3>();
        check::<4>();
        check::<5>();

        // Test cases that span multiple steps
        check::<6>();
        check::<9>();
        check::<11>();
        check::<13>();
        check::<14>();
    }

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values::<Fq, R, _>(&EndoscalarStage);
        // The nested walk's points stage as registered, then the layouts the
        // tests above use: a single point, whole steps, a partial last step.
        assert_stage_values::<_, R, _>(&nested::PointsStage::<EqAffine, Standard>::default());
        assert_stage_values::<_, R, _>(&PointsStage::<EpAffine, ConstLen<1>, E>::default());
        assert_stage_values::<_, R, _>(&PointsStage::<EpAffine, ConstLen<13>, E>::default());
        assert_stage_values::<_, R, _>(&PointsStage::<EpAffine, ConstLen<14>, E>::default());
    }
}
