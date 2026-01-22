//! MultiStage circuit implementation for endoscaling operations.
//!
//! This module provides the [`EndoscalingStep`] multi-stage circuit, which computes
//! iterated endoscalar multiplications using Horner's rule. Each step performs
//! up to 4 endoscalings, storing the result in an interstitial slot.
//!
//! The structure separates points into:
//! - `initial`: The base case accumulator for step 0
//! - `inputs`: Additional points to endoscale (length = NUM_POINTS - 1)
//! - `interstitials`: Output points, one per step
//!
//! All steps are uniform: step N initializes from `interstitials[N-1]` (or
//! `initial` for step 0) and iterates over `inputs[4*N..4*(N+1)]`.
//!
//! This component is reused for both fields in the curve cycle. Because they
//! will vary in the number of steps and points, the code is generic over the
//! curve type and number of points.

use arithmetic::{CurveAffine, Uendo};
use ff::{Field, WithSmallOrderMulGroup};
use pasta_curves::group::{Curve, prime::PrimeCurveAffine};
use ragu_circuits::{
    polynomials::Rank,
    staging::{MultiStageCircuit, Stage, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, Point, compute_endoscalar,
    vec::{FixedVec, Len},
};

use alloc::vec;

/// Number of endoscaling operations per step. This is how many we can fit into
/// a single circuit in our target circuit size.
const ENDOSCALINGS_PER_STEP: usize = 4;

/// Number of inputs (excluding initial) for `NUM_POINTS`.
pub(crate) struct InputsLen<const NUM_POINTS: usize>;

impl<const NUM_POINTS: usize> Len for InputsLen<NUM_POINTS> {
    fn len() -> usize {
        const { assert!(NUM_POINTS > 0) };
        NUM_POINTS - 1
    }
}

/// Number of steps (= interstitials) for `NUM_POINTS`.
pub(crate) struct NumStepsLen<const NUM_POINTS: usize>;

impl<const NUM_POINTS: usize> Len for NumStepsLen<NUM_POINTS> {
    fn len() -> usize {
        InputsLen::<NUM_POINTS>::len()
            .div_ceil(ENDOSCALINGS_PER_STEP)
            // Ensure at least 1 step even when NUM_POINTS == 1 (no inputs).
            .max(1)
    }
}

/// Stage for allocating the endoscalar witness.
#[derive(Default)]
pub struct EndoscalarStage;

impl<F: Field, R: Rank> Stage<F, R> for EndoscalarStage {
    type Parent = ();

    fn values() -> usize {
        Uendo::BITS as usize
    }

    type Witness<'source> = Uendo;
    type OutputKind = Kind![F; Endoscalar<'_, _>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Endoscalar::alloc(dr, witness)
    }
}

/// Witness for the points stage: initial, inputs, and interstitials.
#[derive(Clone)]
pub struct PointsWitness<C: CurveAffine, const NUM_POINTS: usize> {
    /// Initial accumulator (base case for step 0).
    pub initial: C,
    /// Inputs (length = NUM_POINTS - 1).
    pub inputs: FixedVec<C, InputsLen<NUM_POINTS>>,
    /// Interstitial outputs, one per step.
    pub interstitials: FixedVec<C, NumStepsLen<NUM_POINTS>>,
}

impl<C: CurveAffine + PrimeCurveAffine, const NUM_POINTS: usize> PointsWitness<C, NUM_POINTS>
where
    C::Scalar: WithSmallOrderMulGroup<3>,
{
    /// Creates a new `PointsWitness` from points and an endoscalar.
    ///
    /// The first point becomes `initial`, remaining points become `inputs`,
    /// and `interstitials` are computed by simulating the Horner evaluation.
    ///
    /// # Panics
    ///
    /// Panics if `points.len() != NUM_POINTS`.
    pub fn new(endoscalar: Uendo, points: &[C]) -> Self {
        assert_eq!(points.len(), NUM_POINTS, "expected {NUM_POINTS} points");

        let initial = points[0];
        let points = &points[1..];
        let inputs = FixedVec::from_fn(|i| points[i]);

        let endoscalar: C::Scalar = compute_endoscalar(endoscalar);

        // Compute interstitials using chunked Horner iteration
        let mut interstitials = vec::Vec::with_capacity(NumStepsLen::<NUM_POINTS>::len());
        let mut acc = initial.to_curve();

        if points.is_empty() {
            interstitials.push(acc);
        } else {
            // TODO: we can use multiexps in batches here
            for chunk in points.chunks(ENDOSCALINGS_PER_STEP) {
                for input in chunk {
                    acc = acc * endoscalar + input.to_curve();
                }
                interstitials.push(acc);
            }
        }

        let interstitials = {
            // Batch normalize projective points to affine
            let mut tmp = vec![C::identity(); interstitials.len()];
            C::Curve::batch_normalize(&interstitials, &mut tmp);
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
#[derive(Gadget)]
pub struct Points<'dr, D: Driver<'dr>, C: CurveAffine, const NUM_POINTS: usize> {
    #[ragu(gadget)]
    pub initial: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub inputs: FixedVec<Point<'dr, D, C>, InputsLen<NUM_POINTS>>,
    #[ragu(gadget)]
    pub interstitials: FixedVec<Point<'dr, D, C>, NumStepsLen<NUM_POINTS>>,
}

/// Stage for allocating all point witnesses (inputs and interstitials).
#[derive(Default)]
pub struct PointsStage<C: CurveAffine, const NUM_POINTS: usize>(core::marker::PhantomData<C>);

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> Stage<C::Base, R>
    for PointsStage<C, NUM_POINTS>
{
    type Parent = EndoscalarStage;

    fn values() -> usize {
        // (x, y) coordinates for initial + inputs + interstitials.
        2 * (1 + InputsLen::<NUM_POINTS>::len() + NumStepsLen::<NUM_POINTS>::len())
    }

    type Witness<'source> = &'source PointsWitness<C, NUM_POINTS>;
    type OutputKind = Kind![C::Base; Points<'_, _, C, NUM_POINTS>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        let initial = Point::alloc(dr, witness.view().map(|w| w.initial))?;
        let inputs =
            FixedVec::try_from_fn(|i| Point::alloc(dr, witness.view().map(|w| w.inputs[i])))?;
        let interstitials = FixedVec::try_from_fn(|i| {
            Point::alloc(dr, witness.view().map(|w| w.interstitials[i]))
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
/// Each step performs up to [`ENDOSCALINGS_PER_STEP`] endoscalings via Horner's rule:
/// - Step 0 initializes from `initial`, iterates over its slice of `inputs[0..4]`
/// - Step N (N > 0) initializes from `interstitials[N-1]`, iterates over
///   `inputs[N*ENDOSCALINGS_PER_STEP..(N+1)*ENDOSCALINGS_PER_STEP]` (clamped to bounds)
///
/// The circuit constrains that `interstitials[step]` equals the Horner result.
#[derive(Clone)]
pub struct EndoscalingStep<C: CurveAffine, R: Rank, const NUM_POINTS: usize> {
    step: usize,
    _marker: core::marker::PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> EndoscalingStep<C, R, NUM_POINTS> {
    /// Creates a new endoscaling step.
    ///
    /// Panics if `step >= NumStepsLen::<NUM_POINTS>::len()`.
    pub fn new(step: usize) -> Self {
        let num_steps = NumStepsLen::<NUM_POINTS>::len();
        assert!(
            step < num_steps,
            "step {} exceeds available steps (num_steps = {})",
            step,
            num_steps
        );
        Self {
            step,
            _marker: core::marker::PhantomData,
        }
    }

    /// Range of input indices to iterate over in the Horner loop.
    fn input_range(&self) -> core::ops::Range<usize> {
        let start = self.step * ENDOSCALINGS_PER_STEP;
        let end = (start + ENDOSCALINGS_PER_STEP).min(InputsLen::<NUM_POINTS>::len());
        start..end
    }
}

/// Witness for an endoscaling step.
pub struct EndoscalingStepWitness<'source, C: CurveAffine, const NUM_POINTS: usize> {
    /// The endoscalar value.
    pub endoscalar: Uendo,
    /// Point witnesses (inputs and interstitials).
    pub points: &'source PointsWitness<C, NUM_POINTS>,
}

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> MultiStageCircuit<C::Base, R>
    for EndoscalingStep<C, R, NUM_POINTS>
{
    type Final = PointsStage<C, NUM_POINTS>;
    type Instance<'source> = ();
    type Witness<'source> = EndoscalingStepWitness<'source, C, NUM_POINTS>;
    type Output = Kind![C::Base; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::Base>>::Rebind<'dr, D>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let (endoscalar_guard, dr) = dr.add_stage::<EndoscalarStage>()?;
        let (points_guard, dr) = dr.add_stage::<PointsStage<C, NUM_POINTS>>()?;
        let dr = dr.finish();

        // Stages are loaded unenforced here. Curve membership for points and
        // boolean constraints for these stages are enforced by the routing
        // circuits (see #172). This only constrains the Horner accumulation
        // relationship between inputs and interstitials.
        let endoscalar = endoscalar_guard.unenforced(dr, witness.view().map(|w| w.endoscalar))?;
        let points = points_guard.unenforced(dr, witness.view().map(|w| w.points))?;

        // acc = initial or previous interstitial, depending on step index
        let mut acc = self
            .step
            .checked_sub(1)
            .map(|i| &points.interstitials[i])
            .unwrap_or(&points.initial)
            .clone();

        let input_range = self.input_range();

        // We should never be performing more steps than necessary, though the
        // code in that case _should_ fail over to the simple case of just
        // constraining the output to equal the previous value.
        assert!(!input_range.is_empty());

        let mut nonzero_acc = Element::one();

        // Horner's rule: scale and add each input
        for idx in input_range {
            let scaled = endoscalar.group_scale(dr, &acc)?;
            acc = scaled.add_incomplete(dr, &points.inputs[idx], Some(&mut nonzero_acc))?;
        }

        // Ensure that coincident x-coordinates did not occur during point additions.
        nonzero_acc.invert(dr)?;

        // Constrain output
        acc.enforce_equal(dr, &points.interstitials[self.step])?;

        Ok(((), D::just(|| ())))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ENDOSCALINGS_PER_STEP, EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, InputsLen,
        NumStepsLen, PointsStage, PointsWitness,
    };
    use arithmetic::Uendo;
    use ff::Field;
    use pasta_curves::group::{Curve, Group, prime::PrimeCurveAffine};
    use ragu_circuits::{
        CircuitExt,
        polynomials::{self},
        staging::{MultiStage, StageExt},
    };
    use ragu_core::{
        Result,
        drivers::emulator::{Emulator, Wired},
        maybe::Maybe,
    };
    use ragu_pasta::{Ep, EpAffine, Fp, Fq};
    use ragu_primitives::{Endoscalar, vec::Len};
    use rand::{Rng, thread_rng};

    type R = polynomials::R<13>;

    /// Computes the effective scalar for an endoscalar via emulated `field_scale`.
    fn compute_effective_scalar(endo: Uendo) -> Fq {
        Emulator::<Wired<Fq>>::emulate_wired(endo, |dr, witness| {
            let e = Endoscalar::alloc(dr, witness)?;
            let scalar = e.field_scale(dr)?;
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

        let mut acc = inputs[0].to_curve();
        for input in &inputs[1..] {
            acc = acc * e + input.to_curve();
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
        let num_steps = NumStepsLen::<NUM_POINTS>::len();
        let inputs_len = InputsLen::<NUM_POINTS>::len();
        let mut interstitials = Vec::with_capacity(num_steps);

        for step in 0..num_steps {
            // Compute input range for this step (uniform across all steps)
            let start = step * ENDOSCALINGS_PER_STEP;
            let end = (start + ENDOSCALINGS_PER_STEP).min(inputs_len);

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
        let num_steps = NumStepsLen::<NUM_POINTS>::len();

        // Generate random endoscalar and base input points.
        let endoscalar: Uendo = thread_rng().r#gen();
        let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
            (Ep::generator() * <Ep as Group>::Scalar::random(thread_rng())).to_affine()
        });

        // Compute expected final result via Horner over all base inputs.
        let expected = compute_horner_native(endoscalar, &base_inputs);

        // Construct witness using the constructor
        let points = PointsWitness::<EpAffine, NUM_POINTS>::new(endoscalar, &base_inputs);

        // Verify final interstitial matches expected
        assert_eq!(points.interstitials[num_steps - 1], expected);

        // Run each step through the multi-stage circuit and verify correctness.
        for step in 0..num_steps {
            let step_circuit = EndoscalingStep::<EpAffine, R, NUM_POINTS>::new(step);

            let staged = MultiStage::new(step_circuit.clone());

            let endoscalar_mask = EndoscalarStage::mask()?;
            let points_mask = PointsStage::<EpAffine, NUM_POINTS>::mask()?;
            let final_mask = PointsStage::<EpAffine, NUM_POINTS>::final_mask()?;

            let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(endoscalar)?;
            let points_rx = <PointsStage<EpAffine, NUM_POINTS> as StageExt<Fp, R>>::rx(&points)?;
            let key = Fp::ONE;
            let (final_rx, _) = staged.rx::<R>(
                EndoscalingStepWitness {
                    endoscalar,
                    points: &points,
                },
                key,
            )?;

            let staged_s = staged.clone().into_object()?;
            let ky = staged.ky(())?;
            let y = Fp::random(thread_rng());

            // Verify revdot identities for each stage.
            assert_eq!(endoscalar_rx.revdot(&endoscalar_mask.sy(y, key)), Fp::ZERO);
            assert_eq!(points_rx.revdot(&points_mask.sy(y, key)), Fp::ZERO);
            assert_eq!(final_rx.revdot(&final_mask.sy(y, key)), Fp::ZERO);

            // Verify combined circuit identity.
            let mut lhs = final_rx.clone();
            lhs.add_assign(&endoscalar_rx);
            lhs.add_assign(&points_rx);
            assert_eq!(lhs.revdot(&staged_s.sy(y, key)), arithmetic::eval(&ky, y));
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
        let num_steps = NumStepsLen::<NUM_POINTS>::len();

        // Verify computed constants match expectations
        // With 10 inputs, we need ceil(10/4) = 3 steps
        assert_eq!(num_steps, 3);
        assert_eq!(NumStepsLen::<NUM_POINTS>::len(), 3);
        assert_eq!(InputsLen::<NUM_POINTS>::len(), 10);

        // Generate random endoscalar and base input points.
        let endoscalar: Uendo = thread_rng().r#gen();
        let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
            (Ep::generator() * <Ep as Group>::Scalar::random(thread_rng())).to_affine()
        });

        // Compute expected final result via Horner over all base inputs.
        let expected = compute_horner_native(endoscalar, &base_inputs);

        // Construct witness using the constructor
        let points = PointsWitness::<EpAffine, NUM_POINTS>::new(endoscalar, &base_inputs);

        // Verify final interstitial matches expected
        assert_eq!(points.interstitials[num_steps - 1], expected);

        // Run each step through the multi-stage circuit.
        for step in 0..num_steps {
            let step_circuit = EndoscalingStep::<EpAffine, R, NUM_POINTS>::new(step);

            let staged = MultiStage::new(step_circuit.clone());

            let key = Fp::ONE;
            let (final_rx, _) = staged.rx::<R>(
                EndoscalingStepWitness {
                    endoscalar,
                    points: &points,
                },
                key,
            )?;

            let staged_s = staged.clone().into_object()?;
            let ky = staged.ky(())?;
            let y = Fp::random(thread_rng());

            let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(endoscalar)?;
            let points_rx = <PointsStage<EpAffine, NUM_POINTS> as StageExt<Fp, R>>::rx(&points)?;

            // Verify combined circuit identity.
            let mut lhs = final_rx.clone();
            lhs.add_assign(&endoscalar_rx);
            lhs.add_assign(&points_rx);
            assert_eq!(lhs.revdot(&staged_s.sy(y, key)), arithmetic::eval(&ky, y));
        }

        Ok(())
    }

    #[test]
    fn test_num_steps_len() {
        // With uniform steps, each step consumes up to 4 inputs.
        // InputsLen = NUM_POINTS - 1, NumSteps = max(ceil(InputsLen / 4), 1)
        // Assumes NUM_POINTS > 0.

        // 1 total point = 0 inputs = 1 step (base case)
        assert_eq!(NumStepsLen::<1>::len(), 1);

        // 2-5 total points = 1-4 inputs = 1 step
        assert_eq!(NumStepsLen::<2>::len(), 1);
        assert_eq!(NumStepsLen::<3>::len(), 1);
        assert_eq!(NumStepsLen::<4>::len(), 1);
        assert_eq!(NumStepsLen::<5>::len(), 1);

        // 6-9 total points = 5-8 inputs = 2 steps
        assert_eq!(NumStepsLen::<6>::len(), 2);
        assert_eq!(NumStepsLen::<7>::len(), 2);
        assert_eq!(NumStepsLen::<8>::len(), 2);
        assert_eq!(NumStepsLen::<9>::len(), 2);

        // 10-13 total points = 9-12 inputs = 3 steps
        assert_eq!(NumStepsLen::<10>::len(), 3);
        assert_eq!(NumStepsLen::<11>::len(), 3);
        assert_eq!(NumStepsLen::<12>::len(), 3);
        assert_eq!(NumStepsLen::<13>::len(), 3);

        // 14-17 total points = 13-16 inputs = 4 steps
        assert_eq!(NumStepsLen::<14>::len(), 4);
        assert_eq!(NumStepsLen::<15>::len(), 4);
        assert_eq!(NumStepsLen::<16>::len(), 4);
        assert_eq!(NumStepsLen::<17>::len(), 4);

        // 18-21 total points = 17-20 inputs = 5 steps
        assert_eq!(NumStepsLen::<18>::len(), 5);
        assert_eq!(NumStepsLen::<19>::len(), 5);
        assert_eq!(NumStepsLen::<20>::len(), 5);
        assert_eq!(NumStepsLen::<21>::len(), 5);
    }

    #[test]
    fn test_input_range() {
        // Helper to get input_range for a given NUM_POINTS and step
        fn range<const NUM_POINTS: usize>(step: usize) -> core::ops::Range<usize> {
            EndoscalingStep::<EpAffine, R, NUM_POINTS>::new(step).input_range()
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
            let endoscalar: Uendo = thread_rng().r#gen();
            let base_inputs: [EpAffine; NUM_POINTS] = core::array::from_fn(|_| {
                (Ep::generator() * <Ep as Group>::Scalar::random(thread_rng())).to_affine()
            });

            // Compute via PointsWitness::new
            let from_new = PointsWitness::<EpAffine, NUM_POINTS>::new(endoscalar, &base_inputs);

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
}
