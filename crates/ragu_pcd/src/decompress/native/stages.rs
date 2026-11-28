//! The circuit-field side's front stages: the instance stage, holding the
//! compressed proof's instance, and the messages stage, the two
//! reductions' messages ([`Front`]).

#[cfg(test)]
use ragu_circuits::MaskObject;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::Result;

use super::{
    super::{
        common::Prepared,
        stages::{Front, InstanceStage, MessagesStage, no_such_stage},
    },
    Native,
};
use crate::{
    ipa::IpaCycle,
    profile::{MaskSlot, ProfiledCycle, Registered, Standard},
};

impl<C, K, R, const HEADER_SIZE: usize> Front<C, K, R, HEADER_SIZE> for Native
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    type Last = MessagesStage<C, Native, K, R, HEADER_SIZE>;

    fn stages() -> usize {
        2
    }

    fn register_stage_mask<'params>(
        index: usize,
        slot: MaskSlot<'params, Self::F, R>,
    ) -> Result<Registered<'params, Self::F, R>> {
        match index {
            0 => slot.register_stage_mask::<InstanceStage<C, Native, K, R, HEADER_SIZE>>(),
            1 => slot.register_stage_mask::<MessagesStage<C, Native, K, R, HEADER_SIZE>>(),
            _ => no_such_stage(),
        }
    }

    #[cfg(test)]
    fn stage_mask(index: usize) -> Result<MaskObject<R>> {
        match index {
            0 => InstanceStage::<C, Native, K, R, HEADER_SIZE>::stage_mask(),
            1 => MessagesStage::<C, Native, K, R, HEADER_SIZE>::stage_mask(),
            _ => no_such_stage(),
        }
    }

    fn rx(
        index: usize,
        alpha: Self::F,
        prepared: &Prepared<C, Self>,
    ) -> Result<sparse::Polynomial<Self::F, R>> {
        match index {
            0 => InstanceStage::<C, Native, K, R, HEADER_SIZE>::rx(alpha, &prepared.instance),
            1 => MessagesStage::<C, Native, K, R, HEADER_SIZE>::rx(alpha, &prepared.messages),
            _ => no_such_stage(),
        }
    }

    fn zero_alpha(_: usize) -> bool {
        false
    }
}
