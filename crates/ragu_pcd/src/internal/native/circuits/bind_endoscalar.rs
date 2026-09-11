//! Circuit binding the native endoscaling walk at both ends: the walk
//! stage's endoscalar bits to `pre_beta`, every points stage to the curve,
//! and the walk's last interstitial, $P_n$, to the unified instance.
//!
//! The endoscaling steps walk the nested batch's commitments with the bits
//! the [`WalkStage`] holds. This circuit reads `pre_beta` from the unified
//! instance, extracts the endoscalar from it exactly as `compute_v` does,
//! and enforces the stage's bits equal to it, so that the walk is by the
//! transcript's $\beta$. It loads every input stage enforced, so that every
//! point the walk consumes lies on the curve. It covers the
//! [`nested_p_commitment`] slot, enforcing it equal to the walk's last
//! interstitial: a parent walks the cached $P_n$ and holds that copy against
//! this slot in its `bind_beta`, which is what makes the nested batch's
//! commitment the walk's result rather than the prover's choice. `pre_beta`
//! itself is `hashes_2`'s.
//!
//! [`nested_p_commitment`]: unified::Output::nested_p_commitment

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
    stages::points::{
        AbStage, BindingStage, ChildrenStage, FStage, Inputs, RegistryWxStage, WalkStage,
        WalkWitness,
    },
    unified::{self, OutputBuilder},
};

/// Circuit binding the walk stage's endoscalar bits to `pre_beta`, the
/// points stages to the curve and the walk's last interstitial to the
/// instance.
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
    /// The points stages' values.
    pub inputs: &'a Inputs<C::NestedCurve>,
    /// The walk stage's value.
    pub walk: &'a WalkWitness<C::NestedCurve>,
}

impl<C: Cycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R> {
    type Last = WalkStage<C::NestedCurve>;
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
        let (binding, builder) = builder.add_stage::<BindingStage<C::NestedCurve>>()?;
        let (children, builder) = builder.add_stage::<ChildrenStage<C::NestedCurve>>()?;
        let (registry_wx, builder) = builder.add_stage::<RegistryWxStage<C::NestedCurve>>()?;
        let (ab, builder) = builder.add_stage::<AbStage<C::NestedCurve>>()?;
        let (f, builder) = builder.add_stage::<FStage<C::NestedCurve>>()?;
        let (walk, builder) = builder.add_stage::<WalkStage<C::NestedCurve>>()?;
        let dr = builder.finish();

        // Enforced: every point the walk consumes lies on the curve.
        let inputs = witness.as_ref().map(|w| w.inputs);
        let _ = binding.enforced(dr, inputs.as_ref().map(|i| &i.binding))?;
        let _ = children.enforced(dr, inputs.as_ref().map(|i| &i.children))?;
        let _ = registry_wx.enforced(dr, inputs.as_ref().map(|i| &i.registry_wx))?;
        let _ = ab.enforced(dr, inputs.as_ref().map(|i| &i.ab))?;
        let _ = f.enforced(dr, inputs.as_ref().map(|i| &i.f))?;
        let walk = walk.unenforced(dr, witness.as_ref().map(|w| w.walk))?;

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        let pre_beta = unified_output.pre_beta.read(dr, allocator)?;
        let pre_beta = EndoscalarChallenge::from_element(dr, allocator, pre_beta)?;
        let extracted = Endoscalar::extract(pre_beta);
        for (staged, extracted) in walk.endoscalar.bits().zip(extracted.bits()) {
            staged.element().enforce_equal(dr, &extracted.element())?;
        }

        // The walk's last interstitial is P_n: pin it to the instance, where
        // a parent reads it.
        let p = unified_output.nested_p_commitment.receive(dr, allocator)?;
        walk.p().enforce_equal(dr, &p)?;

        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
