//! The decompression circuits as a profile's extension: the layout a
//! profile declares to carry them and the hooks that register them.
//!
//! On the native side the extension is the circuit-field side's chunk
//! circuits, one per run of chunks of its schedule, over its six stages:
//! the instance, messages, lifts and work stages every chunk loads, the
//! transcript stage the transcript chunks load after them, and the digits
//! stage the digits chunks load after the work stage instead. Three final
//! masks bind the chunks by their last stage. After the chunks come the
//! statement circuit, which loads the instance stage alone and exposes the
//! output header the chunks verified as its public output, under a fourth
//! final mask (see [`chunk::StatementCircuit`]), and the binding circuit,
//! which loads the work stage and exposes the side's recomputations of the
//! scalar-field side's instance, messages, lifts and digits stages, under
//! the work stage's final mask (see [`chunk::BindingCircuit`]). On the
//! nested side it is the scalar-field side's chunks over its five stages,
//! the digits chunks last, under two final masks, and its binding circuit,
//! which exposes its recomputation of the circuit-field side's digits
//! stage; that side's transcript stage is empty and stays out.
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

use ragu_circuits::{polynomials::Rank, registry::RegistryBuilder, staging::StageExt};
use ragu_core::{Error, Result};

use super::{
    chunk::{self, last},
    program::Last,
    side::{Native, Nested, Side},
    stages::{DigitsStage, InstanceStage, LiftsStage, MessagesStage, TranscriptStage, WorkStage},
};
use crate::{
    ipa::IpaCycle,
    profile::{Binding, Extension, ProfiledCycle, Standard},
};

/// The instance stage's index among a side's extension stages.
const INSTANCE: u32 = 0;
/// The messages stage's.
const MESSAGES: u32 = 1;
/// The lifts stage's.
const LIFTS: u32 = 2;
/// The work stage's.
const WORK: u32 = 3;
/// The transcript stage's, on the native side.
const TRANSCRIPT: u32 = 4;
/// The digits stage's: after the transcript stage on the native side,
/// after the work stage on the nested side.
const fn digits_stage(with_transcript: bool) -> u32 {
    if with_transcript { 5 } else { 4 }
}

/// The native extension's stages: the instance, messages, lifts, work,
/// transcript and digits stages.
pub(crate) const NATIVE_STAGES: usize = 6;
/// The nested extension's stages: the instance, messages, lifts, work and
/// digits stages.
pub(crate) const NESTED_STAGES: usize = 5;

/// A side's chunk circuit counts: its chunk circuits and, among them, how
/// many run transcript chunks, first, and how many digits chunks, last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    /// The chunk circuits.
    pub chunks: usize,
    /// How many of them, first, run transcript chunks.
    pub transcript: usize,
    /// How many of them, last, run digits chunks.
    pub digits: usize,
}

impl Counts {
    /// The chunk circuits that load no stage past the work stage.
    const fn work(self) -> usize {
        self.chunks - self.transcript - self.digits
    }
}

/// The native layout of the chunk circuits `counts` describes, as the
/// schedule orders them, and the statement and binding circuits after
/// them: every chunk circuit loads the instance, messages, lifts and work
/// stages, a transcript one the transcript stage after them and a digits
/// one the digits stage, the statement circuit the instance stage alone
/// and the binding circuit the first four. A final mask binds each kind
/// by its last stage: the work stage's, the transcript stage's, the digits
/// stage's, then the instance stage's. The binding circuit recomputes the
/// nested extension's instance, messages, lifts and digits stages.
///
/// # Panics
///
/// Panics if the transcript and digits counts exceed the chunks.
pub(crate) fn native_layout(counts: Counts) -> Extension {
    assert!(
        counts.transcript + counts.digits <= counts.chunks,
        "the transcript and digits chunks are among the chunks"
    );
    let digits = digits_stage(true);
    let statement = counts.chunks as u32;
    let binding = statement + 1;
    let mut circuits = Vec::with_capacity(counts.chunks + 2);
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, LIFTS, WORK, TRANSCRIPT],
        counts.transcript,
    ));
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, LIFTS, WORK],
        counts.work(),
    ));
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, LIFTS, WORK, digits],
        counts.digits,
    ));
    circuits.push(vec![INSTANCE]);
    circuits.push(vec![INSTANCE, MESSAGES, LIFTS, WORK]);
    let transcript = counts.transcript as u32;
    let work = (counts.transcript + counts.work()) as u32;
    Extension {
        circuits,
        stages: NATIVE_STAGES,
        final_masks: vec![
            (transcript..work).chain([binding]).collect(),
            (0..transcript).collect(),
            (work..statement).collect(),
            vec![statement],
        ],
        statement: Some(statement),
        binding: Some(Binding {
            circuit: binding,
            stages: vec![INSTANCE, MESSAGES, LIFTS, digits_stage(false)],
        }),
    }
}

/// The nested layout of the chunk circuits `counts` describes, which runs
/// no transcript chunks, and the binding circuit after them: every chunk
/// circuit loads the instance, messages, lifts and work stages, a digits
/// one the digits stage after them, and the binding circuit the first
/// four, under the work stage's final mask then the digits stage's. The
/// binding circuit recomputes the native extension's digits stage.
///
/// # Panics
///
/// Panics if `counts` has transcript chunks or more digits chunks than
/// chunks.
pub(crate) fn nested_layout(counts: Counts) -> Extension {
    assert_eq!(
        counts.transcript, 0,
        "the scalar-field side runs no transcript chunks"
    );
    assert!(
        counts.digits <= counts.chunks,
        "the digits chunks are among the chunks"
    );
    let digits = digits_stage(false);
    let binding = counts.chunks as u32;
    let work = counts.work() as u32;
    let mut circuits = Vec::with_capacity(counts.chunks + 1);
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, LIFTS, WORK],
        counts.work(),
    ));
    circuits.extend(repeat_n(
        vec![INSTANCE, MESSAGES, LIFTS, WORK, digits],
        counts.digits,
    ));
    circuits.push(vec![INSTANCE, MESSAGES, LIFTS, WORK]);
    Extension {
        circuits,
        stages: NESTED_STAGES,
        final_masks: vec![
            (0..work).chain([binding]).collect(),
            (work..binding).collect(),
        ],
        statement: None,
        binding: Some(Binding {
            circuit: binding,
            stages: vec![digits_stage(true)],
        }),
    }
}

/// The circuit counts of side `S`'s schedule: its chunk circuits and,
/// among them, the transcript ones first and the digits ones last.
///
/// # Errors
///
/// Fails if the circuits are not in that order, which the layouts do not
/// represent.
fn counts<C, S, K, R, const HEADER_SIZE: usize>() -> Result<Counts>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    let schedule = S::schedule::<K, R, HEADER_SIZE>()?;
    let chunks = schedule.circuits.len();
    let kind = |index: usize| last(&schedule, index);
    let transcript = (0..chunks)
        .take_while(|&index| kind(index) == Last::Transcript)
        .count();
    let digits = (0..chunks)
        .rev()
        .take_while(|&index| kind(index) == Last::Digits)
        .count();
    if (transcript..chunks - digits).any(|index| kind(index) != Last::Work) {
        return Err(Error::Initialization(
            "the circuits are not in transcript, work, digits order".into(),
        ));
    }
    Ok(Counts {
        chunks,
        transcript,
        digits,
    })
}

/// The native circuit counts for proofs over `C` at rank `K` with
/// `HEADER_SIZE` headers, as chunk circuits at rank `R`.
pub(crate) fn native_counts<C, K, R, const HEADER_SIZE: usize>() -> Result<Counts>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    counts::<C, Native, K, R, HEADER_SIZE>()
}

/// The nested circuit counts, as [`native_counts`].
///
/// # Errors
///
/// Fails if the nested schedule has a transcript circuit, which its side
/// has no stage for.
pub(crate) fn nested_counts<C, K, R, const HEADER_SIZE: usize>() -> Result<Counts>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    let counts = counts::<C, Nested, K, R, HEADER_SIZE>()?;
    if counts.transcript > 0 {
        return Err(Error::Initialization(
            "a transcript circuit on a side without a transcript stage".into(),
        ));
    }
    Ok(counts)
}

/// The native extension: the circuit-field side's chunks over its six
/// stages, for proofs over `C` at rank `K` with `HEADER_SIZE` headers, as
/// chunk circuits at rank `R`, with its statement and binding circuits.
pub(crate) fn native<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(native_layout(native_counts::<C, K, R, HEADER_SIZE>()?))
}

/// The nested extension: the scalar-field side's chunks over its five
/// stages, with its binding circuit.
pub(crate) fn nested<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(nested_layout(nested_counts::<C, K, R, HEADER_SIZE>()?))
}

/// The schedule of side `S`, checked against the counts the profile
/// declared the side's chunk circuits at: the declaration and the circuits
/// are the same list, or the proof carries circuits that never run.
fn pinned_schedule<C, S, K, R, const HEADER_SIZE: usize>(
    pinned: Counts,
) -> Result<Arc<super::program::Schedule>>
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
    Ok(Arc::new(S::schedule::<K, R, HEADER_SIZE>()?))
}

/// Registers chunk circuit `circuit` of side `S` as an internal circuit
/// of `registry`, by the kind of chunks it runs: a
/// [`chunk::TranscriptCircuit`], a [`chunk::DigitsCircuit`] or a
/// [`chunk::Circuit`].
fn register_circuit<'params, C, S, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    registry: RegistryBuilder<'params, S::F, R>,
    params: &'params C::Params,
) -> Result<RegistryBuilder<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    let schedule = pinned_schedule::<C, S, K, R, HEADER_SIZE>(pinned)?;
    if circuit >= schedule.circuits.len() {
        return Err(Error::Initialization("no such circuit".into()));
    }
    match last(&schedule, circuit) {
        Last::Transcript => {
            registry.register_internal_circuit(
                chunk::TranscriptCircuit::<C, S, K, R, HEADER_SIZE>::new(circuit, schedule, params),
            )
        }
        Last::Digits => {
            registry.register_internal_circuit(
                chunk::DigitsCircuit::<C, S, K, R, HEADER_SIZE>::new(circuit, schedule, params),
            )
        }
        Last::Work => registry.register_internal_circuit(
            chunk::Circuit::<C, S, K, R, HEADER_SIZE>::new(circuit, schedule, params),
        ),
    }
}

/// Registers bonding `bonding` of side `S`: the stages' masks in stage
/// order, then the final mask of the chunks whose last stage is the work
/// stage, on a side with a transcript stage of those whose last is the
/// transcript stage, of those whose last is the digits stage, and on a
/// side with a transcript stage of the statement circuit, whose last is
/// the instance stage.
fn register_bonding<'params, C, S, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    registry: RegistryBuilder<'params, S::F, R>,
    with_transcript: bool,
) -> Result<RegistryBuilder<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    type Instance<C, S, K, R, const H: usize> = InstanceStage<C, S, K, R, H>;
    type Messages<C, S, K, R, const H: usize> = MessagesStage<C, S, K, R, H>;
    type Lifts<C, S, K, R, const H: usize> = LiftsStage<C, S, K, R, H>;
    type Work<C, S, K, R, const H: usize> = WorkStage<C, S, K, R, H>;
    type Transcript<C, S, K, R, const H: usize> = TranscriptStage<C, S, K, R, H>;
    type Digits<C, S, K, R, const H: usize> = DigitsStage<C, S, K, R, H>;
    let stages = if with_transcript {
        NATIVE_STAGES
    } else {
        NESTED_STAGES
    } as u32;
    let digits = digits_stage(with_transcript);
    let bonding = bonding as u32;
    let mask = match bonding {
        INSTANCE => <Instance<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        MESSAGES => <Messages<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        LIFTS => <Lifts<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        WORK => <Work<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        TRANSCRIPT if with_transcript => {
            <Transcript<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?
        }
        index if index == digits => <Digits<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::mask()?,
        index if index == stages => {
            <Work<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        index if index == stages + 1 && with_transcript => {
            <Transcript<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        index if index == stages + 1 && !with_transcript => {
            <Digits<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        index if index == stages + 2 && with_transcript => {
            <Digits<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        index if index == stages + 3 && with_transcript => {
            <Instance<C, S, K, R, HEADER_SIZE> as StageExt<S::F, R>>::final_mask()?
        }
        _ => return Err(Error::Initialization("no such bonding".into())),
    };
    Ok(registry.register_bonding(mask))
}

/// Registers native circuit `circuit` of a side declared at `pinned`
/// chunk circuits: a chunk circuit, at the index past them the statement
/// circuit, and at the next the binding circuit; see [`native`] for the
/// layout.
pub(crate) fn register_native_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    registry: RegistryBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    if circuit == pinned.chunks {
        let schedule = pinned_schedule::<C, Native, K, R, HEADER_SIZE>(pinned)?;
        return registry.register_internal_circuit(chunk::StatementCircuit::<
            C,
            Native,
            K,
            R,
            HEADER_SIZE,
        >::new(schedule));
    }
    if circuit == pinned.chunks + 1 {
        let schedule = pinned_schedule::<C, Native, K, R, HEADER_SIZE>(pinned)?;
        return registry.register_internal_circuit(chunk::BindingCircuit::<
            C,
            Native,
            K,
            R,
            HEADER_SIZE,
        >::new(schedule));
    }
    register_circuit::<C, Native, K, R, HEADER_SIZE>(circuit, pinned, registry, params)
}

/// Registers native bonding `bonding`; see [`native`] for the layout.
pub(crate) fn register_native_bonding<'params, C, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    registry: RegistryBuilder<'params, C::CircuitField, R>,
) -> Result<RegistryBuilder<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_bonding::<C, Native, K, R, HEADER_SIZE>(bonding, registry, true)
}

/// Registers nested circuit `circuit` of a side declared at `pinned`
/// chunk circuits: a chunk circuit, or at the index past them the binding
/// circuit; see [`nested`] for the layout.
pub(crate) fn register_nested_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    registry: RegistryBuilder<'params, C::ScalarField, R>,
    params: &'params C::Params,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    if circuit == pinned.chunks {
        let schedule = pinned_schedule::<C, Nested, K, R, HEADER_SIZE>(pinned)?;
        return registry.register_internal_circuit(chunk::BindingCircuit::<
            C,
            Nested,
            K,
            R,
            HEADER_SIZE,
        >::new(schedule));
    }
    register_circuit::<C, Nested, K, R, HEADER_SIZE>(circuit, pinned, registry, params)
}

/// Registers nested bonding `bonding`; see [`nested`] for the layout.
pub(crate) fn register_nested_bonding<'params, C, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_bonding::<C, Nested, K, R, HEADER_SIZE>(bonding, registry, false)
}

#[cfg(test)]
#[path = "../../tests/decompress_extension.rs"]
mod tests;
