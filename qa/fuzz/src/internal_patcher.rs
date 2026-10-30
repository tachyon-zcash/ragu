//! Checks shared by the internal-circuit fuzzer and its PR regressions.
//!
//! Every capture is checked against an honest replay before mutations begin.
//! The patcher engine remains in `ragu_testing::patcher`; this module supplies
//! the PCD boundary checks and mutation policy used by both callers.

use arbitrary::Arbitrary;
use ragu_circuits::Circuit;
use ragu_core::{Result, pasta::Pasta};
use ragu_pcd::fuzzing::patcher::{
    CircuitSpec, InternalCircuitVisitor, OutputRef, Resolution, capture_internal_circuits,
    capture_internal_circuits_bootstrap,
};
use ragu_testing::patcher::{
    Capture, Prepared, ProbeOutcome, capture_with_stage_values, discover_free_advice, forced_by,
    playback,
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::pcd::{self, NativeField};

/// Capture and independently replay the exact honest witness being checked.
pub fn capture_checked<'w, F: Field, Cir: Circuit<F>>(
    name: &str,
    spec: &CircuitSpec,
    circuit: &Cir,
    stage_values: &[F],
    make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
) -> Result<(Capture<F>, Resolution)> {
    let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)
        .unwrap_or_else(|error| panic!("{name}: honest capture failed: {error:?}"));
    assert_eq!(
        cap.stage_wires.len(),
        stage_values.len(),
        "{name}: stage wires"
    );
    assert!(
        playback(circuit, make_witness()?, cap.recorder.values.clone())
            .unwrap_or_else(|error| panic!("{name}: honest playback failed: {error:?}")),
        "{name}: independent playback must accept the captured honest witness",
    );
    if spec.name == "nested_collapse" {
        assert_eq!(
            spec.outputs
                .iter()
                .copied()
                .filter(|output| matches!(output, OutputRef::Instance(2..)))
                .collect::<Vec<_>>(),
            (2..33).map(OutputRef::Instance).collect::<Vec<_>>(),
            "nested collapse must declare x, y, u and every exported point coordinate",
        );
    }
    let resolution = spec.resolve(&cap.instance, &cap.stage_wires)?;
    assert!(!resolution.outputs.is_empty(), "{name}: nothing to watch");
    Ok((cap, resolution))
}

/// The free advice and number of outputs forced by the declared inputs alone.
pub struct BindingCheck {
    pub free: Vec<usize>,
    pub strongly_forced: usize,
}

/// Require the bounded solver to derive every output when other advice is
/// granted, and count how many it can derive from the declared inputs alone.
pub fn check_binding<F: Field>(
    name: &str,
    cap: &Capture<F>,
    resolution: &Resolution,
) -> BindingCheck {
    let rec = &cap.recorder;
    let free = discover_free_advice(&rec.events, &rec.values);
    let mut granted = resolution.inputs.clone();
    granted.extend(
        free.iter()
            .copied()
            .filter(|w| !resolution.outputs.contains(w)),
    );
    let weakly = forced_by(&rec.events, &rec.values, &granted);
    for wire in &resolution.outputs {
        assert!(
            weakly.binary_search(wire).is_ok(),
            "{name}: output wire {wire} is not forced even with other advice granted",
        );
    }
    let strongly = forced_by(&rec.events, &rec.values, &resolution.inputs);
    let strongly_forced = resolution
        .outputs
        .iter()
        .filter(|wire| strongly.binary_search(wire).is_ok())
        .count();
    BindingCheck {
        free,
        strongly_forced,
    }
}

/// How a mutation rewrites a free advice wire. Variant order is part of the
/// existing `fuzz_internal_circuits` corpus encoding.
#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum Mutation {
    AddSmall(u64),
    MulSmall(u64),
    Negate,
    Zero,
    CopyFrom(u16),
}

/// Apply up to eight distinct, effective mutations. A moved output is checked
/// by fresh synthesis before it is reported; solver rejection is inconclusive.
pub fn probe_mutations<F: Field>(
    name: &str,
    prepared: &Prepared<F>,
    cheatable: &[usize],
    mutations: &[(u16, Mutation)],
    replay: impl Fn(&[F]) -> Option<bool>,
) {
    if cheatable.is_empty() {
        return;
    }
    let honest = prepared.honest();
    let mut cheats = Vec::new();
    for (raw, mutation) in mutations.iter().take(8) {
        let wire = cheatable[*raw as usize % cheatable.len()];
        if cheats.iter().any(|(w, _)| *w == wire) {
            continue;
        }
        let mut value = match mutation {
            Mutation::AddSmall(d) => honest[wire] + F::from(*d),
            Mutation::MulSmall(m) => honest[wire] * F::from(*m),
            Mutation::Negate => -honest[wire],
            Mutation::Zero => F::ZERO,
            Mutation::CopyFrom(other) => honest[cheatable[*other as usize % cheatable.len()]],
        };
        if value == honest[wire] {
            value += F::ONE;
        }
        cheats.push((wire, value));
    }
    if cheats.is_empty() {
        cheats.push((cheatable[0], honest[cheatable[0]] + F::ONE));
    }
    let ProbeOutcome::OutputsMoved { witness, moved } = prepared.probe(&cheats) else {
        return;
    };
    match replay(&witness) {
        Some(true) => panic!(
            "INTERNAL CIRCUIT SOUNDNESS SIGNAL in {name} (replay-confirmed): \
             mutations {cheats:?} moved outputs {moved:?} with inputs fixed",
        ),
        Some(false) => panic!(
            "CAPTURE DIVERGENCE in {name}: fresh synthesis rejected the repaired witness \
             for mutations {cheats:?}, outputs {moved:?}",
        ),
        None => panic!("REPLAY UNREACHABLE for {name}: the captured circuit was not revisited"),
    }
}

/// The supported shapes of an internal-circuit capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    Bootstrap,
    Leaves,
    Nodes,
    Lopsided,
}

impl Point {
    pub const ALL: [Self; 4] = [Self::Bootstrap, Self::Leaves, Self::Nodes, Self::Lopsided];

    pub fn name(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Leaves => "leaves",
            Self::Nodes => "nodes",
            Self::Lopsided => "lopsided",
        }
    }

    pub fn minimum_steps(self) -> usize {
        match self {
            Self::Bootstrap => 1,
            Self::Leaves => 2,
            Self::Nodes | Self::Lopsided => 3,
        }
    }

    /// The fuzzer's original fixtures, retained for corpus reproducibility.
    pub fn fixed_case(self) -> CaptureCase {
        let (rng_seed, witnesses) = match self {
            Self::Bootstrap => (0x5eed_0001, [0; 6]),
            Self::Leaves => (0x1eaf_0002, [3, 5, 0, 0, 0, 0]),
            Self::Nodes => (0x0de0_0003, [7, 11, 13, 17, 0, 0]),
            Self::Lopsided => (0x109d_0004, [19, 23, 29, 31, 37, 41]),
        };
        CaptureCase {
            point: self,
            steps: self.minimum_steps(),
            rng_seed,
            witnesses: witnesses.map(NativeField::from),
        }
    }

    pub fn capture<V: InternalCircuitVisitor<Pasta>>(self, visitor: &mut V) -> Result<()> {
        self.fixed_case().capture(visitor)
    }
}

/// A reproducible honest tree. Generated tests vary these fields; applications
/// are local so parallel tests never share `pcd::SyncApp`'s single-thread state.
#[derive(Debug)]
pub struct CaptureCase {
    pub point: Point,
    pub steps: usize,
    pub rng_seed: u64,
    pub witnesses: [NativeField; 6],
}

impl CaptureCase {
    pub fn capture<V: InternalCircuitVisitor<Pasta>>(&self, visitor: &mut V) -> Result<()> {
        assert!((self.point.minimum_steps()..=3).contains(&self.steps));
        let app = pcd::nontrivial_app(self.steps).0;
        let mut rng = StdRng::seed_from_u64(self.rng_seed);
        let leaf = |rng: &mut StdRng, i| {
            app.seed(rng, pcd::witness_leaf(), self.witnesses[i])
                .map(|pair| pair.0)
        };
        let node = |rng: &mut StdRng, i| {
            let left = leaf(rng, i)?;
            let right = leaf(rng, i + 1)?;
            app.fuse(rng, pcd::hash2(), (), left, right)
                .map(|pair| pair.0)
        };
        match self.point {
            Point::Bootstrap => capture_internal_circuits_bootstrap(&app, &mut rng, visitor),
            Point::Leaves => {
                let left = leaf(&mut rng, 0)?;
                let right = leaf(&mut rng, 1)?;
                capture_internal_circuits(&app, &mut rng, pcd::hash2(), (), left, right, visitor)
            }
            Point::Nodes => {
                let left = node(&mut rng, 0)?;
                let right = node(&mut rng, 2)?;
                capture_internal_circuits(&app, &mut rng, pcd::merge2(), (), left, right, visitor)
            }
            Point::Lopsided => {
                let ll = node(&mut rng, 0)?;
                let lr = node(&mut rng, 2)?;
                let deep = app.fuse(&mut rng, pcd::merge2(), (), ll, lr)?.0;
                let shallow = node(&mut rng, 4)?;
                capture_internal_circuits(&app, &mut rng, pcd::merge2(), (), deep, shallow, visitor)
            }
        }
    }
}

#[cfg(test)]
#[path = "internal_patcher_regression.rs"]
mod tests;
