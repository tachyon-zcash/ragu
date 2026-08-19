//! Cross-layer integration tests: decoder → steering → shadow → synthesis →
//! circuit → constraint identity, exercised together.
//!
//! Per-layer properties live with their layers; these tests pin the
//! *coherence* between layers that the fuzz-target oracles rely on:
//!
//! * the revdot constraint identity holds for honest traces of generated
//!   circuits (the accept direction of `fuzz_circuit_revdot_identity`,
//!   over arbitrary generated programs instead of two fixed circuits);
//! * the native shadow's verdict on a mutated witness agrees with the
//!   Simulator's (a deterministic miniature of `fuzz_circuit_cheat`);
//! * the patcher engine's free-advice discovery, working from the recorded
//!   constraint graph alone, reproduces the substrate's own allocation list
//!   (the ground truth `fuzz_advice_patcher`'s discovery cross-check rests
//!   on).

use ff::Field;
use proptest::prelude::*;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, TestRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_pasta::Fp;
use ragu_primitives::{Simulator, allocator::Standard};
use ragu_testing::patcher::{Recorder, TrackingAllocator, constraints_hold, discover_free_advice};

use super::{
    Capabilities, Limits, Op, OpSet, Overrides, Program, ProgramCircuit, native_satisfied,
    program_strategy, shadow_eval, steer, synthesize, synthesize_with_witness,
};

/// Left-hand side of the revdot constraint identity for trace polynomial
/// `r` at `(y, z)`:
/// `r.revdot(r + r.dilate(z) + s(X, y) + t(X, z))`.
///
/// Uses [`Registry::circuit_y`] for the exact per-circuit $s(X, y)$.
fn identity_lhs(
    registry: &Registry<'_, Fp, TestRank>,
    r: &sparse::Polynomial<Fp, TestRank>,
    y: Fp,
    z: Fp,
) -> Fp {
    let mut b = r.clone();
    b.dilate(z);
    b.add_assign(&registry.circuit_y(CircuitIndex::new(0), y));
    b.add_assign(&TestRank::tz(z));
    r.revdot(&b)
}

proptest! {
    /// Honest traces of generated circuits satisfy the revdot identity at
    /// arbitrary evaluation points.
    #[test]
    fn proptest_honest_revdot_identity_holds(
        program in program_strategy(OpSet::ALL, Limits::default().max_ops),
        y_seed in any::<u64>(),
        z_seed in any::<u64>(),
    ) {
        let steered = steer::<Fp>(&program);
        let honest = shadow_eval::<Fp>(&steered, Overrides::none());
        let circuit = ProgramCircuit {
            program: &steered,
            anchors: &honest.anchors,
        };
        let Ok(registry) = RegistryBuilder::<Fp, TestRank>::new()
            .register_circuit(circuit)
            .and_then(|b| b.finalize())
        else {
            // Rank overflow: the program needs more gates than TestRank has.
            return Ok(());
        };
        let trace = circuit
            .trace(steered.preamble.values())
            .expect("honest witness must trace")
            .into_output();
        let r = registry
            .assemble_with_alpha(&trace, CircuitIndex::new(0), Fp::ZERO)
            .expect("honest trace must assemble");

        let y = Fp::from(y_seed);
        let z = Fp::from(z_seed);
        let ky = circuit.ky((), y).expect("ky must evaluate");
        prop_assert_eq!(identity_lhs(&registry, &r, y, z), ky);
    }

    /// Mutating one witness preamble slot: the native shadow's anchor
    /// verdict agrees with the Simulator's accept/reject — the
    /// deterministic miniature of the `fuzz_circuit_cheat` differential.
    ///
    /// `VALUE_FALLIBLE` ops are masked so the mutation cannot shift stack
    /// progression (see the shadow-layer caveat); two anchors are appended
    /// so the verdict is rarely vacuous.
    #[test]
    fn proptest_mutated_witness_simulator_matches_native(
        program in program_strategy(
            OpSet::ALL.without(Capabilities::VALUE_FALLIBLE),
            Limits::default().max_ops - 2,
        ),
        anchor_seeds in any::<[u8; 2]>(),
        cheat_slot_seed in any::<u8>(),
        delta_seed in any::<u64>(),
    ) {
        let mut program = program;
        for seed in anchor_seeds {
            program.ops.push(Op::Anchor(seed));
        }
        let steered = steer::<Fp>(&program);
        let honest = shadow_eval::<Fp>(&steered, Overrides::none());

        // Pick a witness (non-constant) preamble slot to cheat on.
        let witness_slots: Vec<usize> = (0..super::Preamble::LEN)
            .filter(|i| !steered.preamble.is_constant(*i))
            .collect();
        if witness_slots.is_empty() {
            return Ok(());
        }
        let slot = witness_slots[cheat_slot_seed as usize % witness_slots.len()];
        let mut delta = Fp::from(delta_seed);
        if delta == Fp::ZERO {
            delta = Fp::ONE;
        }

        let mut mutated = steered.preamble.values::<Fp>();
        mutated[slot] += delta;

        let native_ok = native_satisfied(
            &steered,
            &honest.anchors,
            Overrides {
                elems: &[(slot, mutated[slot])],
                ..Overrides::none()
            },
        );

        let anchors = honest.anchors.clone();
        let steered_ref = &steered;
        let sim = Simulator::<Fp>::simulate(mutated, |dr, w| {
            synthesize_with_witness(dr, &mut Standard::new(), steered_ref, w, &anchors)?;
            Ok(())
        });

        prop_assert_eq!(
            sim.is_ok(),
            native_ok,
            "Simulator and native oracle disagree on a mutated witness",
        );
    }

    /// Without anchors nothing pins a wire but the gadgets' own constraints,
    /// so the free wires the patcher engine discovers from the recorded graph
    /// alone must be *exactly* the substrate's allocations: the advice, the
    /// pooled `D` wires, and the wasted `b` of each allocation gate (its
    /// `c = a·b` is derived). The one value-dependent exception is an honest
    /// `is_zero(0)`, whose inverse hint is genuinely free at that witness.
    ///
    /// This is the ground truth behind the fuzz target's discovery
    /// cross-check — and the only place discovery is checked against an
    /// independent list, since the circuits it is ultimately for have none.
    #[test]
    fn proptest_discovery_matches_allocations_anchorless(
        program in program_strategy(
            OpSet::ALL.without(Capabilities::ANCHORS),
            Limits::default().max_ops,
        ),
    ) {
        let steered = steer::<Fp>(&program);
        let shadow = shadow_eval::<Fp>(&steered, Overrides::none());
        prop_assume!(!shadow.is_zero_degenerate);

        let mut rec = Recorder::<Fp>::new();
        let mut alloc = TrackingAllocator::default();
        let stacks = synthesize(&mut rec, &mut alloc, &steered, &[])
            .expect("recorder must accept an honest steered program");
        prop_assert!(constraints_hold(&rec.events, &rec.values));

        let mut expected: Vec<usize> = stacks
            .advice_wires
            .iter()
            .copied()
            .chain(rec.extras.iter().copied())
            .chain(alloc.wasted.iter().map(|&(b, _)| b))
            .collect();
        expected.sort_unstable();
        expected.dedup();
        prop_assert_eq!(
            discover_free_advice(&rec.events, &rec.values),
            expected,
            "discovered free wires differ from the substrate's allocations",
        );
    }
}

/// The decoder and the strategies produce programs the whole pipeline
/// accepts end-to-end (decoder flavor of the identity test, ensuring the
/// libFuzzer entry point composes with every layer the same way the
/// proptest entry point does).
#[test]
fn decoded_bytes_run_end_to_end() {
    let data: Vec<u8> = (0..=255u8).cycle().take(700).collect();
    let program = Program::decode(&data, OpSet::ALL, Limits::default());
    let steered = steer::<Fp>(&program);
    let honest = shadow_eval::<Fp>(&steered, Overrides::none());
    let circuit = ProgramCircuit {
        program: &steered,
        anchors: &honest.anchors,
    };
    let sim = Simulator::<Fp>::simulate(steered.preamble.values(), |dr, w| {
        synthesize_with_witness(
            dr,
            &mut Standard::new(),
            circuit.program,
            w,
            circuit.anchors,
        )?;
        Ok(())
    });
    assert!(sim.is_ok(), "decoded program must synthesize honestly");
}
