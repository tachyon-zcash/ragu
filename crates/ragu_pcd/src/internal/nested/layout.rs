//! Where the nested stages sit in the trace.
//!
//! Each transcript round has one nested stage, whose commitment the
//! transcript absorbs. In the standard profile the stages are one chain,
//! each after its parent, and the instance circuits load all of them:
//!
//! ```text
//! │endoscalar│hash│points│links│preamble│s'│inner│outer│ab│query│f│eval│challenges│
//! ```
//!
//! A profile with a large extension has stages whose sum is more than a
//! trace holds, though no stage is by itself. Such a profile
//! ([`paged`]) lays the same stages side by side: the small
//! stages every circuit reads are a trunk, and each large stage starts at
//! the gate where the trunk ends.
//!
//! ```text
//! │endoscalar│hash│points│links│s'│ab│f│challenges│memory│ preamble          │
//!                                                        │ inner │ outer │
//!                                                        │ query    │ eval   │
//! ```
//!
//! A circuit loads the trunk and one branch, and then its own gates follow.
//! Two stages at the same gates are never loaded by one circuit: the stage
//! builder adds a stage only at the gate after the stage before it. What a
//! circuit of one branch needs from another reaches it through the memory
//! stage (see [`circuits::paged`](super::circuits::paged)).
//!
//! Only the gates change. A stage holds what it holds in the chain, its
//! polynomial has its own commitment, and the transcript absorbs the
//! commitments in the same order. A stage's mask takes the stage's
//! position from [`Stage::skip_gates`], so the mask of a stage in a branch
//! covers the branch's gates.

use ragu_circuits::{
    polynomials::Rank,
    staging::{Stage, StageExt},
};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{LinksStage, MemoryStage, paged, stages};
use crate::profile::Profile;

/// A nested stage whose position depends on the layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    SPrime,
    Ab,
    F,
    Challenges,
    Preamble,
    InnerError,
    Query,
    Eval,
}

/// The gate after stage `S`, where a stage laid after it starts.
pub fn after<F: Field, R: Rank, S: Stage<F, R>>() -> usize {
    S::skip_gates() + S::num_gates()
}

/// The gate at which the stage of `slot` starts in profile `P`, if the
/// profile lays its stages side by side, and `None` if they are one chain
/// and the stage follows its parent.
///
/// The trunk is the chain's first stages, through the links stage, then
/// `s_prime`, `ab`, `f`, the challenge stage and the memory stage. The
/// `preamble`, `inner_error` and `query` stages each start where the trunk
/// ends. The `outer_error` stage follows `inner_error`, its parent, and
/// the `eval` stage follows `query`.
pub fn start<C: Affine, R: Rank, P: Profile>(slot: Slot) -> Option<usize> {
    if !paged::<P>() {
        return None;
    }
    Some(match slot {
        Slot::SPrime => after::<C::Base, R, LinksStage<C, P>>(),
        Slot::Ab => after::<C::Base, R, stages::s_prime::Stage<C, R, P>>(),
        Slot::F => after::<C::Base, R, stages::ab::Stage<C, R, P>>(),
        Slot::Challenges => after::<C::Base, R, stages::f::Stage<C, R, P>>(),
        Slot::Preamble | Slot::InnerError | Slot::Query => {
            after::<C::Base, R, MemoryStage<C, R, P>>()
        }
        Slot::Eval => after::<C::Base, R, stages::query::Stage<C, R, P>>(),
    })
}

/// The gate at which the stage `S` of `slot` starts in profile `P`: its
/// position in the layout of [`start`], or after its parent.
pub fn skip_gates<C: Affine, R: Rank, P: Profile, S: Stage<C::Base, R>>(slot: Slot) -> usize {
    start::<C, R, P>(slot).unwrap_or_else(after::<C::Base, R, S::Parent>)
}
