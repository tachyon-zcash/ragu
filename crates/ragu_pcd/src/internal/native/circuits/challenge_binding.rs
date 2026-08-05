//! Circuit binding each child's derived challenges to the elements they were
//! derived from: per $(\text{child},\, \text{challenge})$ pair it re-derives
//! $\text{challenge} = \text{Hash}(\text{inputs})$ and enforces equality. The
//! sponge must match
//! [`challenge_of`](crate::internal::challenge::challenge_of) exactly.
//! What the input elements bind is the step author's responsibility — see
//! [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge).

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
use ragu_primitives::{Element, GadgetExt as _, allocator::Standard, poseidon::Sponge};

use super::super::{
    RevdotParameters,
    stages::{challenges, outer_error, preamble},
    unified::{self, OutputBuilder},
};
use crate::{framework_hooks::HookConfig, internal::challenge::domain_tag};

/// See the [module-level documentation](self).
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig> {
    params: &'params C::Params,
    _marker: PhantomData<(R, J)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Circuit<'params, C, R, HEADER_SIZE, J>
{
    pub fn new(params: &'params C::Params) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

/// Witness data for the challenge binding circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// The unified instance, threaded through the internal circuits.
    pub unified: unified::Instance<C>,

    /// Witness for the [`preamble`] stage (unenforced).
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, J>
{
    type Last = challenges::Stage<C, R, HEADER_SIZE, J, RevdotParameters>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
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
        let builder = builder.skip_stage::<preamble::Stage<C, R, HEADER_SIZE, J>>()?;
        let builder =
            builder.skip_stage::<outer_error::Stage<C, R, HEADER_SIZE, J, RevdotParameters>>()?;
        let (challenges, builder) = builder.add_stage::<Self::Last>()?;
        let dr = builder.finish();

        let challenges = challenges.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;

        let domain_tag = domain_tag::<C>();
        for child in [&challenges.left, &challenges.right] {
            for pair in child.iter() {
                let mut sponge = Sponge::new(dr, C::circuit_poseidon(self.params));
                // Absorbed first, exactly as `challenge_of` does.
                Element::constant(dr, domain_tag).write(dr, &mut sponge)?;
                for input in pair.inputs.iter() {
                    input.write(dr, &mut sponge)?;
                }
                let derived = sponge.squeeze(dr)?;
                derived.enforce_equal(dr, &pair.challenge)?;
            }
        }

        let allocator = &mut Standard::new();
        let unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
