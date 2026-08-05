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

/// Re-derives `Hash(inputs)` and enforces it equals `challenge`, absorbing the
/// [`domain_tag`] first as
/// [`challenge_of`](crate::internal::challenge::challenge_of) does.
///
/// Free-standing so that [`Simulator`](ragu_primitives::Simulator), the one
/// driver that reports an unsatisfied constraint, can reach it: staged circuits
/// are out of its reach, because `configure_stage` pre-allocates stage wires as
/// `Coeff::Zero` and injects witness values separately.
fn enforce_binding<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>>(
    dr: &mut D,
    params: &'dr C::Params,
    inputs: &[Element<'dr, D>],
    challenge: &Element<'dr, D>,
) -> Result<()> {
    let mut sponge = Sponge::new(dr, C::circuit_poseidon(params));
    // Absorbed first, exactly as `challenge_of` does.
    Element::constant(dr, domain_tag::<C>()).write(dr, &mut sponge)?;
    for input in inputs {
        input.write(dr, &mut sponge)?;
    }
    let derived = sponge.squeeze(dr)?;
    derived.enforce_equal(dr, challenge)
}

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

        for child in [&challenges.left, &challenges.right] {
            for pair in child.iter() {
                enforce_binding::<D, C>(dr, self.params, &pair.inputs, &pair.challenge)?;
            }
        }

        let allocator = &mut Standard::new();
        let unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ragu_core::Error;
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::Simulator;

    use super::*;
    use crate::internal::challenge::challenge_of;

    fn inputs_of(width: usize) -> Vec<Fp> {
        (1..=width as u64).map(Fp::from).collect()
    }

    /// `Err(InvalidWitness)` when the binding is unsatisfied. Every value is a
    /// constant, so the constraint is all that is under test.
    fn bind(inputs: &[Fp], challenge: Fp) -> Result<()> {
        let inputs = inputs.to_vec();
        Simulator::<Fp>::simulate((), |dr, _| {
            let inputs: Vec<_> = inputs
                .iter()
                .map(|&input| Element::constant(dr, input))
                .collect();
            let challenge = Element::constant(dr, challenge);
            enforce_binding::<_, Pasta>(dr, Pasta::baked(), &inputs, &challenge)
        })?;
        Ok(())
    }

    /// The binding must be unsatisfied. Matched on the variant, because a setup
    /// mistake also yields `Err`.
    fn refuses(inputs: &[Fp], challenge: Fp, at: usize) {
        match bind(inputs, challenge) {
            Err(Error::InvalidWitness(_)) => {}
            other => panic!("at {at}: expected an unsatisfied constraint, got {other:?}"),
        }
    }

    /// The control, and the agreement the two sponges owe each other: what
    /// `challenge_of` derives out of circuit is what this circuit accepts.
    ///
    /// Width zero included: the domain tag is absorbed first, so even an empty
    /// derivation binds a digest.
    #[test]
    fn the_out_of_circuit_derivation_satisfies_the_binding() -> Result<()> {
        for width in 0..4 {
            let inputs = inputs_of(width);
            let honest = challenge_of::<Pasta>(Pasta::baked(), &inputs)?;
            assert!(
                bind(&inputs, honest).is_ok(),
                "width {width}: challenge_of disagrees with the circuit's sponge"
            );
        }
        Ok(())
    }

    /// A challenge that is not its inputs' hash is refused, at every width.
    /// Isolated here: a proof edited the same way also breaks its
    /// `application_ky` fold, so end to end the refusal is not attributable to
    /// this circuit.
    #[test]
    fn a_challenge_that_is_not_its_inputs_hash_is_refused() -> Result<()> {
        for width in 0..4 {
            let inputs = inputs_of(width);
            let honest = challenge_of::<Pasta>(Pasta::baked(), &inputs)?;
            refuses(&inputs, honest + Fp::from(1u64), width);
        }
        Ok(())
    }

    /// The other direction: the inputs are load-bearing, not just the digest.
    #[test]
    fn moving_an_input_breaks_the_binding() -> Result<()> {
        let inputs = inputs_of(2);
        let honest = challenge_of::<Pasta>(Pasta::baked(), &inputs)?;
        for position in 0..inputs.len() {
            let mut edited = inputs.clone();
            edited[position] += Fp::from(1u64);
            refuses(&edited, honest, position);
        }
        Ok(())
    }
}
