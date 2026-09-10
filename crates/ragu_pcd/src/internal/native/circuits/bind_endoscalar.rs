//! Circuit binding the native endoscaling walk's inputs: the endoscalar
//! stage to `pre_beta`, and the points inputs stage to the curve.
//!
//! The endoscaling steps walk the nested batch's commitments with the bits
//! the [`EndoscalarStage`] holds. This circuit reads `pre_beta` from the
//! unified instance, extracts the endoscalar from it exactly as `compute_v`
//! does, and enforces the stage's bits equal to it, so that the walk is by
//! the transcript's $\beta$. It loads the points inputs stage enforced, so
//! that every point the walk consumes lies on the curve. It covers no
//! unified slot: `pre_beta` is `hashes_2`'s.

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
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{Endoscalar, EndoscalarChallenge, GadgetExt as _, allocator::Standard};

use super::super::{
    NUM_ENDOSCALING_POINTS,
    stages::points::{InputsStage, InputsWitness},
    unified::{self, OutputBuilder},
};
use crate::internal::endoscalar::EndoscalarStage;

/// Circuit binding the endoscalar stage's bits to `pre_beta`.
pub struct Circuit<C: Cycle, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank> Circuit<C, R> {
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the binding circuit.
pub struct Witness<'a, C: Cycle> {
    /// The unified instance, for `pre_beta`.
    pub unified: unified::Instance<C>,
    /// The endoscalar stage's value.
    pub endoscalar: u128,
    /// The points inputs stage's value.
    pub inputs: &'a InputsWitness<C::NestedCurve, NUM_ENDOSCALING_POINTS>,
}

impl<C: Cycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R> {
    type Last = InputsStage<C::NestedCurve, NUM_ENDOSCALING_POINTS>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (endoscalar, builder) = builder.add_stage::<EndoscalarStage>()?;
        let (inputs, builder) =
            builder.add_stage::<InputsStage<C::NestedCurve, NUM_ENDOSCALING_POINTS>>()?;
        let dr = builder.finish();
        let staged = endoscalar.unenforced(dr, witness.as_ref().map(|w| w.endoscalar))?;
        // Enforced: every point the walk consumes lies on the curve.
        let _ = inputs.enforced(dr, witness.as_ref().map(|w| w.inputs))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        let pre_beta = unified_output.pre_beta.read(dr, allocator)?;
        let pre_beta = EndoscalarChallenge::from_element(dr, allocator, pre_beta)?;
        let extracted = Endoscalar::extract(pre_beta);
        for (staged, extracted) in staged.bits().zip(extracted.bits()) {
            staged.element().enforce_equal(dr, &extracted.element())?;
        }

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
