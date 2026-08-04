//! MultiStage circuit implementation for endoscaling operations.
//!
//! This module provides the [`EndoscalingStep`] multi-stage circuit, which computes
//! iterated endoscalar multiplications using Horner's rule. Each step performs
//! up to `E` endoscalings, storing the result in an interstitial slot.
//!
//! The structure separates points into:
//! - `initial`: The base case accumulator for step 0
//! - `inputs`: Additional points to endoscale (length = `P::len() - 1`)
//! - `interstitials`: Output points, one per step
//!
//! All steps are uniform: step N initializes from `interstitials[N-1]` (or
//! `initial` for step 0) and iterates over `inputs[E*N..E*(N+1)]`.
//!
//! The step counting and points layout serve both walks of the curve cycle,
//! which differ in their number of points and in how many endoscalings a
//! step can afford beside the stages it reserves, so they are generic over
//! the curve type, the number of points (a [`Len`] `P`, since an
//! application's hook layout moves it) and the endoscalings per step `E`.
//! The step circuit here is the nested walk's, reading the endoscalar and
//! points stages; the native walk reads its points from several stages and
//! has its own step in [`native::circuits::endoscaling_step`].
//!
//! [`native::circuits::endoscaling_step`]: crate::internal::native::circuits::endoscaling_step

use alloc::vec;
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
    Endoscalar, GadgetExt, NonzeroBank, Point,
    consistent::Consistent,
    vec::{FixedVec, Len},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

/// The range of input indices step `step` walks, out of `num_inputs`, at `E`
/// endoscalings per step.
pub(crate) fn input_range<const E: usize>(
    step: usize,
    num_inputs: usize,
) -> core::ops::Range<usize> {
    let start = step * E;
    let end = (start + E).min(num_inputs);
    start..end
}

/// Number of inputs (excluding initial) for a point count `P`: every point
/// after the first.
pub struct InputsLen<P: Len>(PhantomData<P>);

impl<P: Len> Len for InputsLen<P> {
    fn len() -> usize {
        P::len()
            .checked_sub(1)
            .expect("an accumulation walk starts from a point, so the list is never empty")
    }
}

/// Compute the number of endoscaling steps for `num_points` curve points at
/// `E` endoscalings per step.
///
/// This is `ceil((num_points - 1) / E).max(1)`.
pub(crate) const fn num_steps<const E: usize>(num_points: usize) -> usize {
    assert!(num_points > 0);
    assert!(E > 0);
    let inputs = num_points - 1;
    let steps = inputs.div_ceil(E);
    if steps > 1 { steps } else { 1 }
}

/// Number of steps (= interstitials) for a point count `P` at `E`
/// endoscalings per step: [`num_steps`] at the type level.
pub struct NumStepsLen<P: Len, const E: usize>(PhantomData<P>);

impl<P: Len, const E: usize> Len for NumStepsLen<P, E> {
    fn len() -> usize {
        num_steps::<E>(P::len())
    }
}

/// Stage for allocating the endoscalar witness.
#[derive(Default)]
pub struct EndoscalarStage;

impl<F: Field, R: Rank> Stage<F, R> for EndoscalarStage {
    type Parent = ();

    fn values() -> usize {
        u128::BITS as usize
    }

    type Witness<'source> = u128;
    type OutputKind = Kind![F; Endoscalar<'_, _>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Endoscalar::alloc(dr, witness)
    }
}

/// Witness for the points stage: initial, inputs, and interstitials. Typed
/// by the same [`Len`] as the [`Points`] gadget it witnesses.
pub struct PointsWitness<C: Affine, P: Len, const E: usize> {
    /// Initial accumulator (base case for step 0).
    pub initial: C,
    /// Inputs: every point after the first.
    pub inputs: FixedVec<C, InputsLen<P>>,
    /// Interstitial outputs, one per step.
    pub interstitials: FixedVec<C, NumStepsLen<P, E>>,
}

// A derive would demand `P: Clone`, which a `Len` marker need not be.
impl<C: Affine, P: Len, const E: usize> Clone for PointsWitness<C, P, E> {
    fn clone(&self) -> Self {
        Self {
            initial: self.initial,
            inputs: self.inputs.clone(),
            interstitials: self.interstitials.clone(),
        }
    }
}

impl<C: Affine, P: Len, const E: usize> PointsWitness<C, P, E> {
    /// Creates a new `PointsWitness` from points and an endoscalar.
    ///
    /// The first point becomes `initial`, remaining points become `inputs`,
    /// and `interstitials` are computed by simulating the Horner evaluation.
    ///
    /// # Panics
    ///
    /// Panics if `points` is not `P::len()` long.
    pub fn new(endoscalar: u128, points: &[C]) -> Self {
        assert_eq!(points.len(), P::len(), "expected {} points", P::len());

        let initial = points[0];
        let points = &points[1..];
        let inputs = FixedVec::from_fn(|i| points[i]);

        let endoscalar: C::Scalar = ragu_primitives::lift_endoscalar(endoscalar);

        // Compute interstitials using chunked Horner iteration
        let mut interstitials = vec::Vec::with_capacity(NumStepsLen::<P, E>::len());
        let mut acc = initial.to_projective();

        if points.is_empty() {
            interstitials.push(acc);
        } else {
            for chunk in points.chunks(E) {
                for input in chunk {
                    acc = acc * endoscalar + input.to_projective();
                }
                interstitials.push(acc);
            }
        }

        let interstitials = {
            // Batch normalize projective points to affine
            let mut tmp = vec![C::identity(); interstitials.len()];
            C::batch_to_affine(&interstitials, &mut tmp);
            FixedVec::new(tmp).expect("correct length")
        };

        Self {
            initial,
            inputs,
            interstitials,
        }
    }
}

/// Output gadget containing initial, inputs, and interstitials. See [`PointsWitness`].
#[derive(Gadget, Consistent)]
pub struct Points<'dr, D: Driver<'dr>, C: Affine<Base = D::F>, P: Len, const E: usize> {
    #[ragu(gadget)]
    pub initial: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub inputs: FixedVec<Point<'dr, D, C>, InputsLen<P>>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, NumStepsLen<P, E>>,
}

/// Stage for allocating all point witnesses (inputs and interstitials).
pub struct PointsStage<C: Affine, P: Len, const E: usize>(PhantomData<(C, P)>);

impl<C: Affine, P: Len, const E: usize> Default for PointsStage<C, P, E> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C: Affine, R: Rank, P: Len, const E: usize> Stage<C::Base, R> for PointsStage<C, P, E> {
    type Parent = EndoscalarStage;

    fn values() -> usize {
        // (x, y) coordinates for initial + inputs + interstitials.
        2 * (1 + InputsLen::<P>::len() + NumStepsLen::<P, E>::len())
    }

    type Witness<'source> = &'source PointsWitness<C, P, E>;
    type OutputKind = Kind![C::Base; Points<'_, _, C, P, E>];

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

/// Step-based endoscaling component.
///
/// Each step performs up to `E` endoscalings via Horner's rule:
/// - Step 0 initializes from `initial`, iterates over its slice of `inputs[0..E]`
/// - Step N (N > 0) initializes from `interstitials[N-1]`, iterates over
///   `inputs[N*E..(N+1)*E]` (clamped to bounds)
///
/// The circuit constrains that `interstitials[step]` equals the Horner result.
///
/// `P` is the accumulation's point count, carried as a [`Len`].
pub struct EndoscalingStep<C: Affine, R: Rank, P: Len, const E: usize> {
    step: usize,
    _marker: PhantomData<(C, R, P)>,
}

impl<C: Affine, R: Rank, P: Len, const E: usize> Clone for EndoscalingStep<C, R, P, E> {
    fn clone(&self) -> Self {
        Self {
            step: self.step,
            _marker: PhantomData,
        }
    }
}

impl<C: Affine, R: Rank, P: Len, const E: usize> EndoscalingStep<C, R, P, E> {
    /// Creates a new endoscaling step.
    ///
    /// Panics if `step >= NumStepsLen::<P, E>::len()`.
    pub fn new(step: usize) -> Self {
        let num_steps = NumStepsLen::<P, E>::len();
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

    /// Range of input indices to iterate over in the Horner loop.
    fn input_range(&self) -> core::ops::Range<usize> {
        input_range::<E>(self.step, InputsLen::<P>::len())
    }
}

/// Witness for an endoscaling step.
pub struct EndoscalingStepWitness<'source, C: Affine, P: Len, const E: usize> {
    /// The endoscalar value.
    pub endoscalar: u128,
    /// Point witnesses (inputs and interstitials).
    pub points: &'source PointsWitness<C, P, E>,
}

impl<C: Affine, R: Rank, P: Len, const E: usize> MultiStageCircuit<C::Base, R>
    for EndoscalingStep<C, R, P, E>
{
    type Last = PointsStage<C, P, E>;
    type Instance<'source> = ();
    type Witness<'source> = EndoscalingStepWitness<'source, C, P, E>;
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
        let (points_guard, dr) = dr.add_stage::<PointsStage<C, P, E>>()?;
        let dr = dr.finish();

        // Stages are loaded unenforced here: the export circuit enforces the
        // points' curve membership and the endoscalar's booleanity once for
        // the whole nested section. This only constrains the Horner
        // accumulation relationship between inputs and interstitials.
        let endoscalar = endoscalar_guard.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?;
        let points = points_guard.unenforced(dr, witness.as_ref().map(|w| w.points))?;

        // acc = initial or previous interstitial, depending on step index
        let initial = self
            .step
            .checked_sub(1)
            .map(|i| &points.interstitials[i])
            .unwrap_or(&points.initial)
            .clone();

        let input_range = self.input_range();

        // Horner's rule: scale and add each input. With only the initial
        // point, the empty loop leaves it to be constrained to the output.
        let acc = NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = initial;
            for idx in input_range {
                let scaled = endoscalar.group_scale(dr, &acc)?;
                acc = scaled.add_incomplete(dr, &points.inputs[idx], bank)?;
            }
            Ok(acc)
        })?;

        // Constrain output
        acc.enforce_equal(dr, &points.interstitials[self.step])?;

        Ok(WithAux::new((), D::unit()))
    }
}

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
        Endoscalar,
        vec::{ConstLen, Len},
    };
    use ragu_testing::registry::TestRegistryBuilder;
    use rand::{Rng, RngExt};
    use udon::{
        curve::{Affine, Projective},
        field::Field,
    };

    /// The endoscalings per step these tests lay the walk out with.
    const E: usize = 4;

    use super::{
        EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, InputsLen, NumStepsLen,
        PointsStage, PointsWitness,
    };
    use crate::internal::{nested, tests::assert_stage_values};

    type R = polynomials::ProductionRank;

    /// The points stage at a test point count.
    type Points<const NUM_POINTS: usize> = PointsStage<EpAffine, ConstLen<NUM_POINTS>, E>;
    /// A witness at a test point count.
    type Witness<const NUM_POINTS: usize> = PointsWitness<EpAffine, ConstLen<NUM_POINTS>, E>;
    /// A step at a test point count.
    type Step<const NUM_POINTS: usize> = EndoscalingStep<EpAffine, R, ConstLen<NUM_POINTS>, E>;
    /// The step count at a test point count.
    type Steps<const NUM_POINTS: usize> = NumStepsLen<ConstLen<NUM_POINTS>, E>;

    /// Computes the effective scalar for an endoscalar via emulated `lift`.
    fn compute_effective_scalar(endo: u128) -> Fq {
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
    fn compute_horner_native(endo: u128, inputs: &[EpAffine]) -> EpAffine {
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
        endoscalar: u128,
        initial: EpAffine,
        inputs: &[EpAffine],
    ) -> Vec<EpAffine> {
        let num_steps = Steps::<NUM_POINTS>::len();
        let inputs_len = InputsLen::<ConstLen<NUM_POINTS>>::len();
        let mut interstitials = Vec::with_capacity(num_steps);

        for step in 0..num_steps {
            // Compute input range for this step (uniform across all steps)
            let start = step * E;
            let end = (start + E).min(inputs_len);

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
        let num_steps = Steps::<NUM_POINTS>::len();

        // Generate random endoscalar and base input points.
        let endoscalar: u128 = rand::rng().random();
        let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
            (Ep::generator()
                * <Ep as Projective>::Scalar::random(|bytes| rand::rng().fill_bytes(bytes)))
            .to_affine()
        });

        // Compute expected final result via Horner over all base inputs.
        let expected = compute_horner_native(endoscalar, &base_inputs);

        // Construct witness using the constructor
        let points = Witness::<NUM_POINTS>::new(endoscalar, &base_inputs);

        // Verify final interstitial matches expected
        assert_eq!(points.interstitials[num_steps - 1], expected);

        // Run each step through the multi-stage circuit and verify correctness.
        for step in 0..num_steps {
            let step_circuit = Step::<NUM_POINTS>::new(step);
            let mut builder = TestRegistryBuilder::new();
            let staged_h = builder.register_circuit(MultiStage::new(step_circuit.clone()))?;
            let endo_mask_h = builder.register_bonding(EndoscalarStage::mask()?);
            let pts_mask_h = builder.register_bonding(Points::<NUM_POINTS>::mask()?);
            let final_mask_h = builder.register_bonding(Points::<NUM_POINTS>::final_mask()?);
            let registry = builder.finalize()?;

            let staged = MultiStage::new(step_circuit);

            let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(Fp::ZERO, endoscalar)?;
            let points_rx = <Points<NUM_POINTS> as StageExt<Fp, R>>::rx(Fp::ZERO, &points)?;
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
        let num_steps = Steps::<NUM_POINTS>::len();

        // Verify computed constants match expectations
        // With 10 inputs, we need ceil(10/4) = 3 steps
        assert_eq!(num_steps, 3);
        assert_eq!(Steps::<NUM_POINTS>::len(), 3);
        assert_eq!(InputsLen::<ConstLen<NUM_POINTS>>::len(), 10);

        // Generate random endoscalar and base input points.
        let endoscalar: u128 = rand::rng().random();
        let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
            (Ep::generator()
                * <Ep as Projective>::Scalar::random(|bytes| rand::rng().fill_bytes(bytes)))
            .to_affine()
        });

        // Compute expected final result via Horner over all base inputs.
        let expected = compute_horner_native(endoscalar, &base_inputs);

        // Construct witness using the constructor
        let points = Witness::<NUM_POINTS>::new(endoscalar, &base_inputs);

        // Verify final interstitial matches expected
        assert_eq!(points.interstitials[num_steps - 1], expected);

        // Run each step through the multi-stage circuit.
        for step in 0..num_steps {
            let step_circuit = Step::<NUM_POINTS>::new(step);
            let mut builder = TestRegistryBuilder::new();
            let staged_h = builder.register_circuit(MultiStage::new(step_circuit.clone()))?;
            builder.register_bonding(EndoscalarStage::mask()?);
            builder.register_bonding(Points::<NUM_POINTS>::mask()?);
            builder.register_bonding(Points::<NUM_POINTS>::final_mask()?);
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
            let points_rx = <Points<NUM_POINTS> as StageExt<Fp, R>>::rx(Fp::ZERO, &points)?;

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
        let endoscalar = 7;
        let initial = Ep::generator().to_affine();
        let mut points = Witness::<NUM_POINTS>::new(endoscalar, &[initial]);
        let step = Step::<NUM_POINTS>::new(0);

        let mut builder = TestRegistryBuilder::new();
        let staged_h = builder.register_circuit(MultiStage::new(step.clone()))?;
        builder.register_bonding(EndoscalarStage::mask()?);
        builder.register_bonding(Points::<NUM_POINTS>::mask()?);
        builder.register_bonding(Points::<NUM_POINTS>::final_mask()?);
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
            let points_rx = <Points<NUM_POINTS> as StageExt<Fp, R>>::rx(Fp::ZERO, &points)?;
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
        assert_eq!(Steps::<1>::len(), 1);

        // 2-5 total points = 1-4 inputs = 1 step
        assert_eq!(Steps::<2>::len(), 1);
        assert_eq!(Steps::<3>::len(), 1);
        assert_eq!(Steps::<4>::len(), 1);
        assert_eq!(Steps::<5>::len(), 1);

        // 6-9 total points = 5-8 inputs = 2 steps
        assert_eq!(Steps::<6>::len(), 2);
        assert_eq!(Steps::<7>::len(), 2);
        assert_eq!(Steps::<8>::len(), 2);
        assert_eq!(Steps::<9>::len(), 2);

        // 10-13 total points = 9-12 inputs = 3 steps
        assert_eq!(Steps::<10>::len(), 3);
        assert_eq!(Steps::<11>::len(), 3);
        assert_eq!(Steps::<12>::len(), 3);
        assert_eq!(Steps::<13>::len(), 3);

        // 14-17 total points = 13-16 inputs = 4 steps
        assert_eq!(Steps::<14>::len(), 4);
        assert_eq!(Steps::<15>::len(), 4);
        assert_eq!(Steps::<16>::len(), 4);
        assert_eq!(Steps::<17>::len(), 4);

        // 18-21 total points = 17-20 inputs = 5 steps
        assert_eq!(Steps::<18>::len(), 5);
        assert_eq!(Steps::<19>::len(), 5);
        assert_eq!(Steps::<20>::len(), 5);
        assert_eq!(Steps::<21>::len(), 5);
    }

    #[test]
    fn test_input_range() {
        // Helper to get input_range for a given NUM_POINTS and step
        fn range<const NUM_POINTS: usize>(step: usize) -> core::ops::Range<usize> {
            Step::<NUM_POINTS>::new(step).input_range()
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
            let endoscalar: u128 = rand::rng().random();
            let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
                (Ep::generator()
                    * <Ep as Projective>::Scalar::random(|bytes| rand::rng().fill_bytes(bytes)))
                .to_affine()
            });

            // Compute via PointsWitness::new
            let from_new = Witness::<NUM_POINTS>::new(endoscalar, &base_inputs);

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
        assert_stage_values::<_, R, _>(&nested::PointsStage::<EqAffine, ConstLen<0>>::default());
        assert_stage_values::<_, R, _>(&Points::<1>::default());
        assert_stage_values::<_, R, _>(&Points::<13>::default());
        assert_stage_values::<_, R, _>(&Points::<14>::default());
    }
}
