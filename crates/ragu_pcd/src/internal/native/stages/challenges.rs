//! The derived challenges, a stage of their own rather than a region of
//! [`preamble`](super::preamble): their only readers (`outer_collapse` and
//! `challenge_binding`) are both on the error branch, where the commitments
//! and poly-queries have readers on both.

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    consistent::Consistent,
    vec::{CollectFixed, Len},
};

use super::preamble::{ChallengeVec, Witness};
use crate::{
    Proof, framework_hooks::HookConfig, instance, internal::fold_revdot::Parameters as RevdotParams,
};

/// The challenges both children derived, in order.
#[derive(Gadget, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, J: HookConfig> {
    #[ragu(gadget)]
    pub left: ChallengeVec<'dr, D, J>,
    #[ragu(gadget)]
    pub right: ChallengeVec<'dr, D, J>,
}

/// The derived challenges of both children.
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig, FP> {
    _marker: PhantomData<(C, R, J, FP)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig, FP> Default
    for Stage<C, R, HEADER_SIZE, J, FP>
{
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig, FP: RevdotParams>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, J, FP>
{
    type Parent = super::outer_error::Stage<C, R, HEADER_SIZE, J, FP>;
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, J>];

    fn values() -> usize {
        // One challenge instance region per child.
        2 * J::layout().challenge_instance_len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(Output {
            left: alloc_challenges::<D, C, R, J>(dr, witness.as_ref().map(|w| w.left.proof))?,
            right: alloc_challenges::<D, C, R, J>(dr, witness.as_ref().map(|w| w.right.proof))?,
        })
    }
}

/// One child's derived challenges, in the order the application circuit's
/// instance exposes them; shared with
/// [`Application::verify`](crate::Application::verify).
pub(crate) fn alloc_challenges<
    'dr,
    D: Driver<'dr, F = C::CircuitField>,
    C: Cycle,
    R: Rank,
    J: HookConfig,
>(
    dr: &mut D,
    proof: DriverValue<D, &Proof<C, R>>,
) -> Result<ChallengeVec<'dr, D, J>> {
    let allocator = &mut ();
    J::ChallengeDerivations::range()
        .map(|i| {
            Ok(instance::Challenge {
                inputs: J::ChallengeWidth::range()
                    .map(|j| {
                        Element::alloc(
                            dr,
                            allocator,
                            proof
                                .as_ref()
                                .map(|p| p.application_challenges()[i].inputs[j]),
                        )
                    })
                    .try_collect_fixed()?,
                challenge: Element::alloc(
                    dr,
                    allocator,
                    proof
                        .as_ref()
                        .map(|p| p.application_challenges()[i].challenge),
                )?,
            })
        })
        .try_collect_fixed()
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{
        AppHooks,
        internal::{
            native::RevdotParameters,
            tests::{HEADER_SIZE, R, assert_stage_values},
        },
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<
            Pasta,
            R,
            { HEADER_SIZE },
            AppHooks<1, 1, 2, 2>,
            RevdotParameters,
        >::default());
    }
}
