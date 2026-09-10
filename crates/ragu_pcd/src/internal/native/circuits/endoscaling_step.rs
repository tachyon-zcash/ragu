//! The native endoscaling steps: the Horner walk over the nested-curve
//! commitments the nested batch folds into $P_n$,
//! [`ENDOSCALINGS_PER_STEP`] points per step.
//!
//! The mirror of the nested [`EndoscalingStep`] for the split points layout
//! of [`stages::points`]: step $k$ starts from the previous interstitial (or
//! $F_n$ for step 0), endoscales it by the walk stage's endoscalar bits and adds
//! each of its inputs in turn, reading every point from the stage that
//! committed it, and enforces the result equal to its own interstitial. The
//! last interstitial is $P_n$.
//!
//! The stages are loaded unenforced: [`bind_endoscalar`](super::bind_endoscalar)
//! binds the walk stage's endoscalar bits to `pre_beta` and enforces the
//! inputs' curve membership, and the interstitials are equal to points
//! computed from them.
//!
//! [`EndoscalingStep`]: crate::internal::endoscalar::EndoscalingStep
//! [`stages::points`]: crate::internal::native::stages::points

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
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

use super::super::{
    ENDOSCALINGS_PER_STEP,
    stages::points::{
        AbStage, BindingStage, ChildrenStage, FStage, Inputs, NumInputs, NumSteps, RegistryWxStage,
        WalkInputs, WalkStage, WalkWitness,
    },
};
use crate::internal::endoscalar::input_range;

/// One step of the native endoscaling walk.
#[derive(Clone)]
pub struct Circuit<C: Cycle, R: Rank> {
    step: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank> Circuit<C, R> {
    /// Creates step `step`.
    ///
    /// # Panics
    ///
    /// Panics if `step` is not a step of the walk.
    pub fn new(step: usize) -> MultiStage<C::CircuitField, R, Self> {
        let num_steps = NumSteps::len();
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

/// Witness for one step: every points stage.
pub struct Witness<'a, C: Cycle> {
    pub inputs: &'a Inputs<C::NestedCurve>,
    pub walk: &'a WalkWitness<C::NestedCurve>,
}

impl<C: Cycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R> {
    type Last = WalkStage<C::NestedCurve>;
    type Instance<'source> = ();
    type Witness<'source> = Witness<'source, C>;
    type Output = Kind![C::CircuitField; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (binding, dr) = dr.add_stage::<BindingStage<C::NestedCurve>>()?;
        let (children, dr) = dr.add_stage::<ChildrenStage<C::NestedCurve>>()?;
        let (registry_wx, dr) = dr.add_stage::<RegistryWxStage<C::NestedCurve>>()?;
        let (ab, dr) = dr.add_stage::<AbStage<C::NestedCurve>>()?;
        let (f, dr) = dr.add_stage::<FStage<C::NestedCurve>>()?;
        let (walk, dr) = dr.add_stage::<WalkStage<C::NestedCurve>>()?;
        let dr = dr.finish();

        let inputs = witness.as_ref().map(|w| w.inputs);
        let binding = binding.unenforced(dr, inputs.as_ref().map(|i| &i.binding))?;
        let children = children.unenforced(dr, inputs.as_ref().map(|i| &i.children))?;
        let registry_wx = registry_wx.unenforced(dr, inputs.as_ref().map(|i| &i.registry_wx))?;
        let ab = ab.unenforced(dr, inputs.as_ref().map(|i| &i.ab))?;
        let f = f.unenforced(dr, inputs.as_ref().map(|i| &i.f))?;
        let walked = walk.unenforced(dr, witness.as_ref().map(|w| w.walk))?;
        let endoscalar = &walked.endoscalar;
        let interstitials = &walked.interstitials;
        let walk = WalkInputs {
            binding: &binding,
            children: &children,
            registry_wx: &registry_wx,
            ab: &ab,
            f: &f,
        };

        let initial = self
            .step
            .checked_sub(1)
            .map(|i| &interstitials[i])
            .unwrap_or(walk.initial())
            .clone();

        let range = input_range::<ENDOSCALINGS_PER_STEP>(self.step, NumInputs::len());
        assert!(!range.is_empty());

        let acc = NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = initial;
            for idx in range {
                let scaled = endoscalar.group_scale(dr, &acc)?;
                acc = scaled.add_incomplete(dr, walk.input(idx), bank)?;
            }
            Ok(acc)
        })?;
        acc.enforce_equal(dr, &interstitials[self.step])?;

        Ok(WithAux::new((), D::unit()))
    }
}
