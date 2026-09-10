//! The native endoscaling steps: the Horner walk over the nested-curve
//! commitments the nested batch folds into $P_n$, four points per step.
//!
//! The mirror of the nested [`EndoscalingStep`] for the split points layout
//! of [`stages::points`]: step $k$ starts from the previous interstitial (or
//! the initial point for step 0), endoscales it by the endoscalar stage's
//! bits and adds each of its inputs in turn, and enforces the result equal
//! to its own interstitial. The last interstitial is $P_n$.
//!
//! The stages are loaded unenforced: [`bind_endoscalar`](super::bind_endoscalar)
//! binds the endoscalar's bits to `pre_beta` and enforces the inputs' curve
//! membership, and the interstitials are equal to points computed from
//! them.
//!
//! [`EndoscalingStep`]: crate::internal::endoscalar::EndoscalingStep
//! [`stages::points`]: crate::internal::native::stages::points

use core::marker::PhantomData;

use ragu_arithmetic::CurveAffine;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt, NonzeroBank, vec::Len};

use crate::internal::{
    endoscalar::{EndoscalarStage, InputsLen, NumStepsLen, input_range},
    native::stages::points::{
        InputsStage, InputsWitness, InterstitialsStage, InterstitialsWitness,
    },
};

/// One step of the native endoscaling walk.
#[derive(Clone)]
pub struct Circuit<C: CurveAffine, R: Rank, const NUM_POINTS: usize> {
    step: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> Circuit<C, R, NUM_POINTS> {
    /// Creates step `step`.
    ///
    /// # Panics
    ///
    /// Panics if `step` is not a step of the walk over `NUM_POINTS` points.
    pub fn new(step: usize) -> MultiStage<C::Base, R, Self> {
        let num_steps = NumStepsLen::<NUM_POINTS>::len();
        assert!(
            step < num_steps,
            "step {step} exceeds available steps ({num_steps})"
        );
        MultiStage::new(Self {
            step,
            _marker: PhantomData,
        })
    }
}

/// Witness for one step: the endoscalar and both points stages.
pub struct Witness<'a, C: CurveAffine, const NUM_POINTS: usize> {
    pub endoscalar: u128,
    pub inputs: &'a InputsWitness<C, NUM_POINTS>,
    pub interstitials: &'a InterstitialsWitness<C, NUM_POINTS>,
}

impl<C: CurveAffine, R: Rank, const NUM_POINTS: usize> MultiStageCircuit<C::Base, R>
    for Circuit<C, R, NUM_POINTS>
{
    type Last = InterstitialsStage<C, NUM_POINTS>;
    type Instance<'source> = ();
    type Witness<'source> = Witness<'source, C, NUM_POINTS>;
    type Output = Kind![C::Base; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (endoscalar, dr) = dr.add_stage::<EndoscalarStage>()?;
        let (inputs, dr) = dr.add_stage::<InputsStage<C, NUM_POINTS>>()?;
        let (interstitials, dr) = dr.add_stage::<InterstitialsStage<C, NUM_POINTS>>()?;
        let dr = dr.finish();

        let endoscalar = endoscalar.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?;
        let inputs = inputs.unenforced(dr, witness.as_ref().map(|w| w.inputs))?;
        let interstitials =
            interstitials.unenforced(dr, witness.as_ref().map(|w| w.interstitials))?;

        let initial = self
            .step
            .checked_sub(1)
            .map(|i| &interstitials.interstitials[i])
            .unwrap_or(&inputs.initial)
            .clone();

        let range = input_range(self.step, InputsLen::<NUM_POINTS>::len());
        assert!(!range.is_empty());

        let acc = NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = initial;
            for idx in range {
                let scaled = endoscalar.group_scale(dr, &acc)?;
                acc = scaled.add_incomplete(dr, &inputs.inputs[idx], bank)?;
            }
            Ok(acc)
        })?;
        acc.enforce_equal(dr, &interstitials.interstitials[self.step])?;

        Ok(WithAux::new((), D::unit()))
    }
}
