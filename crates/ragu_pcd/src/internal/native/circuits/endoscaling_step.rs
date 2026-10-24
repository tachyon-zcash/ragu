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
//! A step exposes no values, but its public output is still the zero suffix
//! every internal circuit carries (see [`unified`]), so its instance
//! polynomial is $k(Y) = 1$ while its linear constraint has no wires. The
//! application `circuit_id` may name any native slot, and the suffix is what
//! stops a step from satisfying an application instance. The nested walk has
//! no such selector and needs no suffix.
//!
//! [`EndoscalingStep`]: crate::internal::endoscalar::EndoscalingStep
//! [`stages::points`]: crate::internal::native::stages::points
//! [`unified`]: crate::internal::native::unified

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, NonzeroBank, WithSuffix, vec::Len};

use super::super::{
    ENDOSCALINGS_PER_STEP,
    stages::points::{
        AbStage, BindingStage, ChildrenStage, FStage, Inputs, NumInputs, NumSteps, RegistryWxStage,
        WalkInputs, WalkStage, WalkWitness,
    },
};
use crate::{framework_hooks::HookConfig, internal::endoscalar::input_range};

/// One step of the native endoscaling walk.
#[derive(Clone)]
pub struct Circuit<C: Cycle, R: Rank, J> {
    step: usize,
    _marker: PhantomData<(C, R, J)>,
}

impl<C: Cycle, R: Rank, J: HookConfig> Circuit<C, R, J> {
    /// Creates step `step`.
    ///
    /// # Panics
    ///
    /// Panics if `step` is not a step of the walk.
    pub fn new(step: usize) -> MultiStage<C::CircuitField, R, Self> {
        let num_steps = NumSteps::<J::PolyWitnesses>::len();
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
pub struct Witness<'a, C: Cycle, J: HookConfig> {
    pub inputs: &'a Inputs<C::NestedCurve, J::PolyWitnesses>,
    pub walk: &'a WalkWitness<C::NestedCurve, J::PolyWitnesses>,
}

impl<C: Cycle, R: Rank, J: HookConfig> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R, J> {
    type Last = WalkStage<C::NestedCurve, J::PolyWitnesses>;
    type Instance<'source> = ();
    type Witness<'source> = Witness<'source, C, J>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, ()>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(WithSuffix::new((), Element::zero(dr)))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (binding, dr) = dr.add_stage::<BindingStage<C::NestedCurve>>()?;
        let (children, dr) = dr.add_stage::<ChildrenStage<C::NestedCurve, J::PolyWitnesses>>()?;
        let (registry_wx, dr) =
            dr.add_stage::<RegistryWxStage<C::NestedCurve, J::PolyWitnesses>>()?;
        let (ab, dr) = dr.add_stage::<AbStage<C::NestedCurve, J::PolyWitnesses>>()?;
        let (f, dr) = dr.add_stage::<FStage<C::NestedCurve, J::PolyWitnesses>>()?;
        let (walk, dr) = dr.add_stage::<WalkStage<C::NestedCurve, J::PolyWitnesses>>()?;
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

        let range =
            input_range::<ENDOSCALINGS_PER_STEP>(self.step, NumInputs::<J::PolyWitnesses>::len());
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

        Ok(WithAux::new(
            WithSuffix::new((), Element::zero(dr)),
            D::unit(),
        ))
    }
}
