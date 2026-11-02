//! The decompression circuits as a profile's extension: the layout a
//! profile declares to carry them and the hooks that register them.
//!
//! On the native side the extension is the circuit-field side's chunk
//! circuits, one per group of chunks of its schedule, over its six stages:
//! the instance, messages, lifts and work stages every chunk loads, the
//! transcript stage the transcript chunks load after them, and the digits
//! stage the digits chunks load after the work stage instead. Three final
//! masks bind the chunks by their last stage. After the chunks come the
//! statement circuit, which loads the instance stage alone and exposes the
//! output header the chunks verified as its public output, under a fourth
//! final mask (see [`chunk::StatementCircuit`]), and the binding circuit,
//! which loads the work stage and exposes the commitments of the
//! scalar-field side's run stages the transcript absorbed and the side's
//! recomputations of that side's lifts and digits stages, under the work
//! stage's final mask (see [`chunk::BindingCircuit`]). On the nested side
//! it is the scalar-field side's chunks over its stages, one per run of the
//! compression's transcript, then the trailing, lifts, work and digits
//! stages (see [`Front`]), the digits chunks last, under two final masks,
//! and its binding circuit, which exposes its recomputation of the
//! circuit-field side's digits stage; that side's transcript stage is
//! empty and stays out.
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

use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, Result};

use super::{
    chunk::{self, last},
    program::Last,
    side::{Native, Nested, Side},
    stages::{
        DigitsStage, Front, InstanceStage, LiftsStage, Runs, TranscriptStage, WorkStage, num_runs,
    },
};
use crate::{
    ipa::IpaCycle,
    profile::{Binding, BondingSlot, CircuitSlot, Extension, ProfiledCycle, Registered, Standard},
};

/// A side's stage indices among its extension's stages: its front's
/// first, `front` of them, then the lifts and work stages, and after the
/// work stage the transcript stage, on the side with one, and the digits
/// stage. The final masks follow the stages: the work stage's, the
/// transcript stage's on the side with one, the digits stage's, and on
/// that side the instance stage's, the statement circuit's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Indices {
    /// The front stages.
    pub front: usize,
    /// Whether the side has a transcript stage.
    pub with_transcript: bool,
}

impl Indices {
    /// The native side's: the instance and messages stages in front, a
    /// transcript stage after the work stage.
    pub(crate) const fn native() -> Self {
        Indices {
            front: 2,
            with_transcript: true,
        }
    }

    /// The nested side's for a proof of `runs` runs: a stage per run and
    /// the trailing stage in front, no transcript stage.
    pub(crate) const fn nested(runs: usize) -> Self {
        Indices {
            front: runs + 1,
            with_transcript: false,
        }
    }

    pub(crate) const fn lifts(self) -> u32 {
        self.front as u32
    }

    pub(crate) const fn work(self) -> u32 {
        self.front as u32 + 1
    }

    /// The transcript stage's index, on the side with one.
    pub(crate) const fn transcript(self) -> u32 {
        self.front as u32 + 2
    }

    pub(crate) const fn digits(self) -> u32 {
        self.front as u32 + 2 + self.with_transcript as u32
    }

    /// The stages.
    pub(crate) const fn stages(self) -> usize {
        self.front + 3 + self.with_transcript as usize
    }

    /// The stages every chunk circuit loads: the front, lifts and work
    /// stages.
    fn common(self) -> Vec<u32> {
        (0..=self.work()).collect()
    }
}

/// The native extension's stages: the instance, messages, lifts, work,
/// transcript and digits stages.
pub(crate) const NATIVE_STAGES: usize = Indices::native().stages();

/// The nested extension's stages for a proof of `runs` runs: a stage per
/// run, the trailing, lifts, work and digits stages.
pub(crate) const fn nested_stages(runs: usize) -> usize {
    Indices::nested(runs).stages()
}

/// A side's chunk circuit counts: its chunk circuits and, among them, how
/// many run transcript chunks, first, and how many digits chunks, last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    /// The chunk circuits.
    pub circuits: usize,
    /// How many of them, first, run transcript chunks.
    pub transcript: usize,
    /// How many of them, last, run digits chunks.
    pub digits: usize,
}

impl Counts {
    /// The chunk circuits that load no stage past the work stage.
    const fn work(self) -> usize {
        self.circuits - self.transcript - self.digits
    }
}

/// The native layout of the chunk circuits `counts` describes, for proofs
/// of `runs` runs, as the schedule orders them, and the statement and
/// binding circuits after them: every chunk circuit loads the instance,
/// messages, lifts and work stages, a transcript one the transcript stage
/// after them and a digits one the digits stage, the statement circuit
/// the instance stage alone and the binding circuit the first four. A
/// final mask binds each kind by its last stage: the work stage's, the
/// transcript stage's, the digits stage's, then the instance stage's. The
/// binding circuit exposes the nested extension's run stages, which the
/// transcript absorbed, and its recomputations of that extension's lifts
/// and digits stages, in that order.
///
/// # Panics
///
/// Panics if the transcript and digits counts exceed the chunk circuits.
pub(crate) fn native_layout(counts: Counts, runs: usize) -> Extension {
    assert!(
        counts.transcript + counts.digits <= counts.circuits,
        "the transcript and digits circuits are among the chunk circuits"
    );
    let indices = Indices::native();
    let nested = Indices::nested(runs);
    let statement = counts.circuits as u32;
    let binding = statement + 1;
    let mut circuits = Vec::with_capacity(counts.circuits + 2);
    circuits.extend(repeat_n(
        indices
            .common()
            .into_iter()
            .chain([indices.transcript()])
            .collect::<Vec<_>>(),
        counts.transcript,
    ));
    circuits.extend(repeat_n(indices.common(), counts.work()));
    circuits.extend(repeat_n(
        indices
            .common()
            .into_iter()
            .chain([indices.digits()])
            .collect::<Vec<_>>(),
        counts.digits,
    ));
    circuits.push(vec![0]);
    circuits.push(indices.common());
    let transcript = counts.transcript as u32;
    let work = (counts.transcript + counts.work()) as u32;
    Extension {
        circuits,
        stages: indices.stages(),
        final_masks: vec![
            (transcript..work).chain([binding]).collect(),
            (0..transcript).collect(),
            (work..statement).collect(),
            vec![statement],
        ],
        statement: Some(statement),
        binding: Some(Binding {
            circuit: binding,
            stages: (0..runs as u32)
                .chain([nested.lifts(), nested.digits()])
                .collect(),
        }),
    }
}

/// The nested layout of the chunk circuits `counts` describes, for proofs
/// of `runs` runs, which runs no transcript chunks, and the binding
/// circuit after them: every chunk circuit loads the run stages, the
/// trailing stage and the lifts and work stages, a digits one the digits
/// stage after them, and the binding circuit the same stages as the rest,
/// under the work stage's final mask then the digits stage's. The binding
/// circuit recomputes the native extension's digits stage.
///
/// # Panics
///
/// Panics if `counts` has transcript circuits or more digits circuits
/// than chunk circuits.
pub(crate) fn nested_layout(counts: Counts, runs: usize) -> Extension {
    assert_eq!(
        counts.transcript, 0,
        "the scalar-field side runs no transcript chunks"
    );
    assert!(
        counts.digits <= counts.circuits,
        "the digits circuits are among the chunk circuits"
    );
    let indices = Indices::nested(runs);
    let binding = counts.circuits as u32;
    let work = counts.work() as u32;
    let mut circuits = Vec::with_capacity(counts.circuits + 1);
    circuits.extend(repeat_n(indices.common(), counts.work()));
    circuits.extend(repeat_n(
        indices
            .common()
            .into_iter()
            .chain([indices.digits()])
            .collect::<Vec<_>>(),
        counts.digits,
    ));
    circuits.push(indices.common());
    Extension {
        circuits,
        stages: indices.stages(),
        final_masks: vec![
            (0..work).chain([binding]).collect(),
            (work..binding).collect(),
        ],
        statement: None,
        binding: Some(Binding {
            circuit: binding,
            stages: vec![Indices::native().digits()],
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
    let circuits = schedule.circuits.len();
    let kind = |index: usize| last(&schedule, index);
    let transcript = (0..circuits)
        .take_while(|&index| kind(index) == Last::Transcript)
        .count();
    let digits = (0..circuits)
        .rev()
        .take_while(|&index| kind(index) == Last::Digits)
        .count();
    if (transcript..circuits - digits).any(|index| kind(index) != Last::Work) {
        return Err(Error::Initialization(
            "the circuits are not in transcript, work, digits order".into(),
        ));
    }
    Ok(Counts {
        circuits,
        transcript,
        digits,
    })
}

/// The native circuit counts for proofs over `C` at rank `K` with
/// `HEADER_SIZE` headers, as chunk circuits at rank `R`.
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
pub(crate) fn native<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(native_layout(
        native_counts::<C, K, R, HEADER_SIZE>()?,
        num_runs::<K>(),
    ))
}

/// The nested extension: the scalar-field side's chunks over its five
/// stages, with its binding circuit.
#[cfg(test)]
pub(crate) fn nested<C, K, R, const HEADER_SIZE: usize>() -> Result<Extension>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    Ok(nested_layout(
        nested_counts::<C, K, R, HEADER_SIZE>()?,
        num_runs::<K>(),
    ))
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

/// Registers chunk circuit `circuit` of side `S` into `slot`, by the kind
/// of chunks it runs: a
/// [`chunk::TranscriptCircuit`], a [`chunk::DigitsCircuit`] or a
/// [`chunk::Circuit`].
fn register_circuit<'params, C, S, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    slot: CircuitSlot<'params, S::F, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    let schedule = pinned_schedule::<C, S, K, R, HEADER_SIZE>(pinned)?;
    if circuit >= schedule.circuits.len() {
        return Err(Error::Initialization("no such circuit".into()));
    }
    match last(&schedule, circuit) {
        Last::Transcript => slot.register_staged(
            chunk::TranscriptCircuit::<C, S, K, R, HEADER_SIZE>::new(circuit, schedule, params),
        ),
        Last::Digits => slot.register_staged(chunk::DigitsCircuit::<C, S, K, R, HEADER_SIZE>::new(
            circuit, schedule, params,
        )),
        Last::Work => slot.register_staged(chunk::Circuit::<C, S, K, R, HEADER_SIZE>::new(
            circuit, schedule, params,
        )),
    }
}

/// Registers bonding `bonding` of side `S`, by `indices`: the stages'
/// masks in stage order, then the final mask of the chunks whose last
/// stage is the work stage, on a side with a transcript stage of those
/// whose last is the transcript stage, of those whose last is the digits
/// stage, and on a side with a transcript stage of the statement circuit,
/// whose last is the instance stage.
fn register_bonding<'params, C, S, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    slot: BondingSlot<'params, S::F, R>,
    indices: Indices,
) -> Result<Registered<'params, S::F, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    S: Front<C, K, R, HEADER_SIZE>,
    K: Rank,
    R: Rank,
{
    type Instance<C, S, K, R, const H: usize> = InstanceStage<C, S, K, R, H>;
    type Lifts<C, S, K, R, const H: usize> = LiftsStage<C, S, K, R, H>;
    type Work<C, S, K, R, const H: usize> = WorkStage<C, S, K, R, H>;
    type Transcript<C, S, K, R, const H: usize> = TranscriptStage<C, S, K, R, H>;
    type Digits<C, S, K, R, const H: usize> = DigitsStage<C, S, K, R, H>;
    if bonding < indices.front {
        return S::register_mask(bonding, slot);
    }
    let with_transcript = indices.with_transcript;
    let stages = indices.stages() as u32;
    let digits_final = stages + 1 + with_transcript as u32;
    match bonding as u32 {
        index if index == indices.lifts() => slot.register_mask::<Lifts<C, S, K, R, HEADER_SIZE>>(),
        index if index == indices.work() => slot.register_mask::<Work<C, S, K, R, HEADER_SIZE>>(),
        index if with_transcript && index == indices.transcript() => {
            slot.register_mask::<Transcript<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == indices.digits() => {
            slot.register_mask::<Digits<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == stages => slot.register_final_mask::<Work<C, S, K, R, HEADER_SIZE>>(),
        index if with_transcript && index == stages + 1 => {
            slot.register_final_mask::<Transcript<C, S, K, R, HEADER_SIZE>>()
        }
        index if index == digits_final => {
            slot.register_final_mask::<Digits<C, S, K, R, HEADER_SIZE>>()
        }
        index if with_transcript && index == digits_final + 1 => {
            slot.register_final_mask::<Instance<C, S, K, R, HEADER_SIZE>>()
        }
        _ => Err(Error::Initialization("no such bonding".into())),
    }
}

/// Registers native circuit `circuit` of a side declared at `pinned`
/// chunk circuits: a chunk circuit, at the index past them the statement
/// circuit, and at the next the binding circuit; see [`native_layout`]
/// for the layout.
pub(crate) fn register_native_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    slot: CircuitSlot<'params, C::CircuitField, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    if circuit == pinned.circuits {
        let schedule = pinned_schedule::<C, Native, K, R, HEADER_SIZE>(pinned)?;
        return slot.register_staged(
            chunk::StatementCircuit::<C, Native, K, R, HEADER_SIZE>::new(schedule),
        );
    }
    if circuit == pinned.circuits + 1 {
        let schedule = pinned_schedule::<C, Native, K, R, HEADER_SIZE>(pinned)?;
        return slot.register_staged(chunk::BindingCircuit::<C, Native, K, R, HEADER_SIZE>::new(
            schedule,
        ));
    }
    register_circuit::<C, Native, K, R, HEADER_SIZE>(circuit, pinned, slot, params)
}

/// Registers native bonding `bonding`; see [`native_layout`] for the layout.
pub(crate) fn register_native_bonding<'params, C, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    slot: BondingSlot<'params, C::CircuitField, R>,
) -> Result<Registered<'params, C::CircuitField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    register_bonding::<C, Native, K, R, HEADER_SIZE>(bonding, slot, Indices::native())
}

/// Registers nested circuit `circuit` of a side declared at `pinned`
/// chunk circuits: a chunk circuit, or at the index past them the binding
/// circuit; see [`nested_layout`] for the layout.
pub(crate) fn register_nested_circuit<'params, C, K, R, const HEADER_SIZE: usize>(
    circuit: usize,
    pinned: Counts,
    slot: CircuitSlot<'params, C::ScalarField, R>,
    params: &'params C::Params,
) -> Result<Registered<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    if circuit == pinned.circuits {
        let schedule = pinned_schedule::<C, Nested, K, R, HEADER_SIZE>(pinned)?;
        return slot.register_staged(chunk::BindingCircuit::<C, Nested, K, R, HEADER_SIZE>::new(
            schedule,
        ));
    }
    register_circuit::<C, Nested, K, R, HEADER_SIZE>(circuit, pinned, slot, params)
}

/// Registers nested bonding `bonding`; see [`nested_layout`] for the layout.
pub(crate) fn register_nested_bonding<'params, C, K, R, const HEADER_SIZE: usize>(
    bonding: usize,
    slot: BondingSlot<'params, C::ScalarField, R>,
) -> Result<Registered<'params, C::ScalarField, R>>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    register_bonding::<C, Nested, K, R, HEADER_SIZE>(
        bonding,
        slot,
        Indices::nested(num_runs::<K>()),
    )
}

#[cfg(test)]
#[path = "../../tests/decompress_extension.rs"]
mod tests;
