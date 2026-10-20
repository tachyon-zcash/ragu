//! The decompression circuits as a profile's extension: the layout a
//! profile declares to carry them and the hooks that register them.
//!
//! On the native side the extension is the circuit-field side's chunk
//! circuits, one per run of chunks of its schedule, over its four stages: the
//! instance, messages and work stages every chunk loads, and the transcript
//! stage the transcript chunks load after them. Two final masks bind the
//! chunks by their last stage. After the chunks comes the statement
//! circuit, which loads the instance stage alone and exposes the output
//! header the chunks verified as its public output, under a third final
//! mask (see [`chunk::StatementCircuit`]). On the nested side it is the
//! scalar-field side's chunks over its instance, messages and work stages
//! under one final mask; that side's transcript stage is empty and stays
//! out.
//!
//! The chunk circuits verify a standard-profile compressed proof at rank
//! `K` as circuits at the profile's rank `R`, so the hooks take the base
//! cycle the profile extends and build the circuits over it. A profile's
//! declaration is a constant, so [`Aggregator`](crate::profile::Aggregator)
//! declares the layout from pinned circuit counts ([`native_layout`] and
//! [`nested_layout`]) rather than from the schedule, and the hooks check
//! the pins against the schedule they register.

use alloc::{sync::Arc, vec, vec::Vec};
use core::iter::repeat_n;

use ragu_circuits::{polynomials::Rank, staging::StageExt};
use ragu_core::{Error, Result};

use super::{
    chunk::{self, is_transcript},
    side::{Native, Nested, Side},
    stages::{InstanceStage, MessagesStage, TranscriptStage, WorkStage},
};
use crate::{
    ipa::IpaCycle,
    profile::{BondingSlot, CircuitSlot, Extension, ProfiledCycle, Registered, Standard},
};

/// The instance stage's index among a side's extension stages.
const INSTANCE: u32 = 0;
/// The messages stage's.
const MESSAGES: u32 = 1;
/// The work stage's.
const WORK: u32 = 2;
/// The transcript stage's, on the native side.
const TRANSCRIPT: u32 = 3;

/// The native extension's stages: the instance, messages, work and
/// transcript stages.
pub(crate) const NATIVE_STAGES: usize = 4;
/// The nested extension's stages: the instance, messages and work stages.
pub(crate) const NESTED_STAGES: usize = 3;

/// The native layout of `chunks` chunk circuits whose first `transcript`
/// run the transcript chunks, as the schedule orders them, and the
/// statement circuit after them: every chunk circuit loads the instance,
/// messages and work stages, a transcript one the transcript stage after
/// them, and the statement circuit the instance stage alone. A final mask
/// binds each kind by its last stage: the work stage's, the transcript
/// stage's, then the instance stage's.
///
/// # Panics
///
/// Panics if `transcript` exceeds `chunks`.
pub(crate) fn native_layout(chunks: usize, transcript: usize) -> Extension {
    assert!(
        transcript <= chunks,
        "the transcript chunks are among the chunks"
    );
    let statement = chunks as u32;
    let mut circuits = Vec::with_capacity(chunks + 1);
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, WORK, TRANSCRIPT],
        transcript,
    ));
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, WORK],
        chunks - transcript,
    ));
    circuits.push(vec![INSTANCE]);
    Extension {
        circuits,
        stages: NATIVE_STAGES,
        final_masks: vec![
            (transcript as u32..statement).collect(),
            (0..transcript as u32).collect(),
            vec![statement],
        ],
        statement: Some(statement),
        binding: None,
    }
}

/// The nested layout of `chunks` chunk circuits: every one loads the
/// instance, messages and work stages, under one final mask.
pub(crate) fn nested_layout(chunks: usize) -> Extension {
    Extension {
        circuits: vec![vec![INSTANCE, MESSAGES, WORK]; chunks],
        stages: NESTED_STAGES,
        final_masks: vec![(0..chunks as u32).collect()],
        statement: None,
        binding: None,
    }
}

/// The circuit counts of side `S`'s schedule: its chunk circuits and,
/// first among them, those running transcript chunks.
///
/// # Errors
///
/// Fails if a transcript circuit follows a circuit of another kind, which
/// the layouts do not represent.
fn counts<C, S, K, R, const HEADER_SIZE: usize>() -> Result<(usize, usize)>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    let schedule = S::schedule::<K, R, HEADER_SIZE>()?;
    let circuits = schedule.circuits.len();
    let transcript = (0..circuits)
        .take_while(|&index| is_transcript(&schedule, index))
        .count();
    if (transcript..circuits).any(|index| is_transcript(&schedule, index)) {
        return Err(Error::Initialization(
            "a transcript circuit after the other circuits".into(),
        ));
    }
    Ok((circuits, transcript))
}

/// The native circuit counts for proofs over `C` at rank `K` with
/// `HEADER_SIZE` headers, as chunk circuits at rank `R`: the chunk
/// circuits and, first among them, those running transcript chunks.
pub(crate) fn native_counts<C, K, R, const HEADER_SIZE: usize>() -> Result<(usize, usize)>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    counts::<C, Native, K, R, HEADER_SIZE>()
}

/// The nested circuit count, as [`native_counts`].
///
/// # Errors
///
/// Fails if the nested schedule has a transcript circuit, which its side
/// has no stage for.
pub(crate) fn nested_counts<C, K, R, const HEADER_SIZE: usize>() -> Result<usize>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    let (chunks, transcript) = counts::<C, Nested, K, R, HEADER_SIZE>()?;
    if transcript > 0 {
        return Err(Error::Initialization(
            "a transcript circuit on a side without a transcript stage".into(),
        ));
    }
    Ok(chunks)
}

/// The native extension: the circuit-field side's chunks over its four
/// stages, for proofs over `C` at rank `K` with `HEADER_SIZE` headers, as
/// chunk circuits at rank `R`.
pub(crate) fn native<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    let (chunks, transcript) = native_counts::<C, K, R, HEADER_SIZE>()?;
    Ok(native_layout(chunks, transcript))
}

/// The nested extension: the scalar-field side's chunks over its three
/// stages.
pub(crate) fn nested<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(nested_layout(nested_counts::<C, K, R, HEADER_SIZE>()?))
}

/// Registers chunk circuit `circuit` of side `S` into `slot`: one running
/// transcript chunks as a [`chunk::TranscriptCircuit`], any other as a
/// [`chunk::Circuit`]. `pinned` is the count the profile declared the
/// side's chunk circuits at, with its transcript ones, which the schedule
/// must pack into: the declaration and the circuits are the same list, or
/// the proof carries circuits that never run.
fn register_circuit<'params, C, S, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: (usize, usize),
    slot: CircuitSlot<'params, S::F, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    if counts::<C, S, K, R, HEADER_SIZE>()? != pinned {
        return Err(Error::Initialization(
            "the schedule's circuits are not the declared ones".into(),
        ));
    }
    let schedule = Arc::new(S::schedule::<K, R, HEADER_SIZE>()?);
    if circuit >= schedule.circuits.len() {
        return Err(Error::Initialization("no such circuit".into()));
    }
    if is_transcript(&schedule, circuit) {
        slot.register(chunk::TranscriptCircuit::<C, S, K, R, HEADER_SIZE>::new(
            circuit, schedule, params,
        ))
    } else {
        slot.register(chunk::Circuit::<C, S, K, R, HEADER_SIZE>::new(
            circuit, schedule, params,
        ))
    }
}

/// Registers bonding `bonding` of side `S`: the stages' masks in stage
/// order, then the final mask of the chunks whose last stage is the work
/// stage and, on a side with a transcript stage, of those whose last is
/// the transcript stage and of the statement circuit, whose last is the
/// instance stage.
fn register_bonding<'params, C, S, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    slot: BondingSlot<'params, S::F, R>,
    with_transcript: bool,
) -> Result<Registered<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    type Instance<C, S, K, R, const H: usize> = InstanceStage<C, S, K, R, H>;
    type Messages<C, S, K, R, const H: usize> = MessagesStage<C, S, K, R, H>;
    type Work<C, S, K, R, const H: usize> = WorkStage<C, S, K, R, H>;
    type Transcript<C, S, K, R, const H: usize> = TranscriptStage<C, S, K, R, H>;
    let stages = if with_transcript { 4 } else { 3 };
    let mask = match bonding as u32 {
        INSTANCE => <Instance<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        MESSAGES => <Messages<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        WORK => <Work<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        TRANSCRIPT if with_transcript => {
            <Transcript<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?
        }
        index if index == stages => {
            <Work<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        index if index == stages + 1 && with_transcript => {
            <Transcript<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        index if index == stages + 2 && with_transcript => {
            <Instance<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        _ => return Err(Error::Initialization("no such bonding".into())),
    };
    Ok(slot.register(mask))
}

/// Registers native circuit `circuit` of a side declared at `pinned` chunk
/// circuits and transcript ones: a chunk circuit, or at the index past
/// them the statement circuit; see [`native`] for the layout.
pub(crate) fn register_native_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: (usize, usize),
    slot: CircuitSlot<'params, C::CircuitField, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    if circuit == pinned.0 {
        if native_counts::<C, K, R, HEADER_SIZE>()? != pinned {
            return Err(Error::Initialization(
                "the schedule's circuits are not the declared ones".into(),
            ));
        }
        let schedule = Arc::new(<Native as Side<C>>::schedule::<K, R, HEADER_SIZE>()?);
        return slot
            .register(chunk::StatementCircuit::<C, Native, K, R, HEADER_SIZE>::new(schedule));
    }
    register_circuit::<C, Native, K, R, HEADER_SIZE>(circuit, pinned, slot, params)
}

/// Registers native bonding `bonding`; see [`native`] for the layout.
pub(crate) fn register_native_bonding<'params, C, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    slot: BondingSlot<'params, C::CircuitField, R>,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_bonding::<C, Native, K, R, HEADER_SIZE>(bonding, slot, true)
}

/// Registers nested chunk circuit `circuit` of a side declared at
/// `pinned` chunk circuits; see [`nested`] for the layout.
pub(crate) fn register_nested_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: usize,
    slot: CircuitSlot<'params, C::ScalarField, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_circuit::<C, Nested, K, R, HEADER_SIZE>(circuit, (pinned, 0), slot, params)
}

/// Registers nested bonding `bonding`; see [`nested`] for the layout.
pub(crate) fn register_nested_bonding<'params, C, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    slot: BondingSlot<'params, C::ScalarField, R>,
) -> Result<Registered<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_bonding::<C, Nested, K, R, HEADER_SIZE>(bonding, slot, false)
}

#[cfg(test)]
#[path = "../../tests/decompress_extension.rs"]
mod tests;
