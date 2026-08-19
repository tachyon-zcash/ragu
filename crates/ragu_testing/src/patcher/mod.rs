//! The patcher engine: under-constraint hunting over a recorded constraint
//! graph.
//!
//! The *patcher* (after zksecurity's "Towards Fuzzing Zero-Knowledge Proof
//! Circuits") starts from a satisfying witness, lets a malicious prover
//! rewrite some free advice, and then *repairs* the rest of the witness so
//! every constraint the circuit emitted still holds — propagating the cheat
//! exactly as far as the constraints force it and no further. A cheat that
//! survives repair but changes something the circuit's specification says is
//! determined is an under-constrained-advice bug. This module is the
//! driver-level machinery behind that technique; the policy of *what* to
//! cheat and *which* oracle judges the result belongs to the caller (the
//! `fuzz_advice_patcher` target in `qa/fuzz` for generated gadget programs;
//! `ragu_pcd`'s own tests for the internal recursion circuits).
//!
//! # Pieces
//!
//! * [`Recorder`] — a [`Driver`](ragu_core::drivers::Driver) that captures
//!   the constraint graph ragu emits (gates, pooled-allocation `C · D = 0`
//!   constraints, linear-combination wires, `enforce_zero`s) as a flat list
//!   of [`Event`]s over `usize` wires, alongside the honest wire values.
//!   [`TrackingAllocator`] is the production pooling allocator with
//!   bookkeeping of the wires it wastes.
//! * [`repair`] / [`constraints_hold`] — the repair solver and the
//!   acceptance check over a recorded graph.
//! * [`underconstrained_derived`] — the rank/nullity oracle: derived wires
//!   that can move while every declared free wire is held fixed.
//! * [`discover_free_advice`] — structural discovery of the free-advice
//!   candidates a recorded graph exposes (the wires no constraint derives
//!   from earlier ones).
//! * [`Playback`] — the independent cross-check: re-runs the same synthesis
//!   and verifies an injected witness live, so a recorder capture bug cannot
//!   silently corrupt a verdict.
//! * [`capture`] / [`playback`] — the [`Circuit`](ragu_circuits::Circuit)
//!   entry points: run a circuit's `witness` (and its output serialization)
//!   through the drivers, exposing the wires of its public instance.
//! * [`selftest`] — a planted under-constrained circuit whose signal must
//!   fire, so the soundness direction is never vacuous.
//!
//! Everything is driven through the `Driver` trait alone; the engine never
//! needs to know how a circuit was produced.

mod circuit;
mod discover;
mod recorder;

pub use circuit::{Capture, capture, playback};
pub use discover::discover_free_advice;
pub use recorder::{
    Event, Playback, Recorder, TrackingAllocator, constraints_hold, repair, selftest,
    underconstrained_derived,
};
