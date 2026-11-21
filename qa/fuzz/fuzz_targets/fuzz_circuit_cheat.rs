//! The "patcher" technique: mutate one witness input, repair
//! every downstream wire by re-tracing, and demand the assembled
//! constraint identity's verdict match an independent native oracle.
//!
//! # The substrate and the oracle
//!
//! A fuzzer-chosen program over a stack of [`Element`]s and [`Boolean`]s
//! (decoded and synthesized by [`ragu_testing_fuzz::substrate`]) is registered
//! as a [`ProgramCircuit`] and run two ways: through the `Simulator` as a
//! fast synthesis sanity check, and as a real circuit whose trace is
//! assembled and checked with the revdot constraint identity. Alongside it
//! the substrate's native `Fp` shadow plays both the constraint graph
//! (every wire's value) and the oracle (the true semantics, independent of
//! ragu).
//!
//! `Op::Anchor(i)` is the constraint primitive: at honest-build time it
//! captures the native value `v` at stack slot `i`, and in the circuit it
//! emits `enforce_zero(elem[i] - v)` — pinning that wire to its honest
//! value. Anchors are satisfiable by construction, so the honest witness
//! always verifies. Every other op produces a derived wire the patcher's
//! repair (re-tracing on the mutated witness) flows through; only `Anchor`
//! can reject a witness.
//!
//! # Vocabulary
//!
//! The vocabulary is the full grammar minus the value-fallible ops
//! (`Invert`/`Divide`/`AllocRaw`). Masking those out makes stack
//! progression value-independent, so mutating a witness input can never
//! shift which slot an anchor pins or a later op reads — the honest and
//! mutated traces share one registered circuit. (This is a genuine
//! widening over the historical Add/Sub/Mul/Double/Negate/Scale/Anchor
//! set: booleans, conditional select, fold, and `alloc_square` advice now
//! participate.)
//!
//! # The patcher step and the differential assertion
//!
//! 1. Honest: evaluate the native shadow; capture anchor constants;
//!    confirm the Simulator and the constraint identity both accept.
//! 2. Mutate one witness preamble slot by a nonzero delta.
//! 3. Repair: re-trace under the mutated witness (every derived wire
//!    recomputes). Anchors still reference the honest constants, so any
//!    anchor downstream of the cheat now reads a changed value.
//! 4. Compute the native verdict and assemble the mutated trace under the
//!    same circuit wiring.
//! 5. Assert the constraint identity verdict matches `native_satisfied`.
//!    The load-bearing direction is **identity accepts while the oracle
//!    says violated**: ragu accepted a witness that changed a pinned wire,
//!    an under-constrained `enforce_zero`/gadget — a soundness bug. The
//!    converse is a completeness bug, equally caught. The Simulator
//!    verdict is also compared to the identity to catch Simulator-vs-wiring
//!    disagreements.
//!
//! Inputs where the cheat reaches no anchor leave both verdicts
//! `satisfied` — correctly no signal, since an unconstrained input is free
//! to change.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, TestRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_core::pasta::Fp;
use ragu_primitives::{Simulator, allocator::Standard};
use ragu_testing_fuzz::substrate::{
    Capabilities, Limits, OpSet, Overrides, Preamble, Program, ProgramCircuit, native_satisfied,
    shadow_eval, synthesize_with_witness,
};
use udon::field::Field;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    /// Raw program bytes, decoded via [`Program::decode`].
    program: Vec<u8>,
    /// Which witness preamble slot to mutate (reduced mod the witness-slot
    /// count).
    cheat_slot: u8,
    /// Additive perturbation; 0 maps to 1 so the mutation is always real.
    cheat_delta: u64,
    /// Seeds for the two independent evaluation points.
    y_seed: u64,
    z_seed: u64,
}

/// The vocabulary: the full grammar minus value-fallible ops, so stack
/// progression is value-independent and input mutation never shifts slots.
fn opset() -> OpSet {
    OpSet::ALL.without(Capabilities::VALUE_FALLIBLE)
}

/// Left-hand side of the revdot identity for trace polynomial `r` at
/// `(y, z)`: `r.revdot(r + r.dilate(z) + s(X, y) + t(X, z))`, using the
/// registry's exact per-circuit `s(X, y)`.
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

fn evaluation_point(seed: u64, offset: u64) -> Fp {
    let mut point = Fp::from(seed) + Fp::from(offset);
    if point == Fp::ZERO || point == Fp::ONE {
        point += Fp::from(2u64);
    }
    point
}

/// Does the constraint identity accept `witness` for the registered
/// `circuit` at two independent points? Trace, assembly, and `ky` are
/// structural operations for this value-infallible program, so an error is a
/// harness or pipeline bug rather than an iteration to discard.
fn identity_accepts(
    registry: &Registry<'_, Fp, TestRank>,
    circuit: &ProgramCircuit<'_, Fp>,
    witness: [Fp; Preamble::LEN],
    input: &Input,
) -> bool {
    let trace = circuit
        .trace(witness)
        .expect("value-infallible ProgramCircuit trace failed")
        .into_output();
    let r = registry
        .assemble_with_alpha(&trace, CircuitIndex::new(0), Fp::ZERO)
        .expect("registered ProgramCircuit trace failed to assemble");

    let y = evaluation_point(input.y_seed, 2);
    let z = evaluation_point(input.z_seed, 3);
    let y2 = y * Fp::MULTIPLICATIVE_GENERATOR + Fp::from(5u64);
    let z2 = z * Fp::MULTIPLICATIVE_GENERATOR + Fp::from(7u64);

    identity_lhs(registry, &r, y, z)
        == circuit
            .ky((), y)
            .expect("ProgramCircuit::ky failed on a unit instance")
        && identity_lhs(registry, &r, y2, z2)
            == circuit
                .ky((), y2)
                .expect("ProgramCircuit::ky failed on a unit instance")
}

/// Whether the Simulator accepts `witness` for `program` with `anchors`.
fn simulator_accepts(program: &Program, witness: [Fp; Preamble::LEN], anchors: &[Fp]) -> bool {
    Simulator::<Fp>::simulate(witness, |dr, w| {
        synthesize_with_witness(dr, &mut Standard::new(), program, w, anchors)?;
        Ok(())
    })
    .is_ok()
}

fuzz_target!(|input: Input| {
    let program = Program::decode(&input.program, opset(), Limits { max_ops: 64 });

    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!(
            "cheat_slot = {}, cheat_delta = {}\n{program:#?}",
            input.cheat_slot, input.cheat_delta,
        );
        return;
    }
    if program.ops.is_empty() {
        return;
    }

    let honest_witness = program.preamble.values::<Fp>();
    let honest = shadow_eval::<Fp>(&program, Overrides::none());
    let honest_anchors = honest.anchors.clone();

    let circuit = ProgramCircuit {
        program: &program,
        anchors: &honest_anchors,
    };
    let Some(registry) = ragu_testing_fuzz::registry::fits(
        RegistryBuilder::<Fp, TestRank>::new()
            .register_circuit(circuit)
            .and_then(|b| b.finalize()),
    ) else {
        return; // Rank overflow: program too large for TestRank.
    };

    // Completeness sanity: the honest witness verifies and the native
    // oracle agrees. All three hold by construction; a failure is a bug.
    assert!(
        native_satisfied(&program, &honest_anchors, Overrides::none()),
        "honest native oracle disagreed with itself (harness bug): {program:?}"
    );
    assert!(
        simulator_accepts(&program, honest_witness, &honest_anchors),
        "Simulator rejected the honest witness — completeness bug. {program:?}"
    );
    let honest_identity = identity_accepts(&registry, &circuit, honest_witness, &input);
    assert!(
        honest_identity,
        "constraint identity rejected the honest witness — completeness bug. {program:?}"
    );

    // Pick a witness (non-constant) preamble slot to cheat on. Constant
    // slots are circuit structure; mutating them is a no-op for both the
    // circuit and the shadow, so they carry no signal.
    let witness_slots: Vec<usize> = (0..Preamble::LEN)
        .filter(|i| !program.preamble.is_constant(*i))
        .collect();
    if witness_slots.is_empty() {
        return;
    }
    let slot = witness_slots[input.cheat_slot as usize % witness_slots.len()];
    let mut delta = Fp::from(input.cheat_delta);
    if delta == Fp::ZERO {
        delta = Fp::ONE;
    }

    // Patch: mutate the input, repair downstream (re-trace recomputes every
    // derived wire from the new input).
    let mut mutated_witness = honest_witness;
    mutated_witness[slot] += delta;

    let oracle = native_satisfied(
        &program,
        &honest_anchors,
        Overrides {
            elems: &[(slot, mutated_witness[slot])],
            ..Overrides::none()
        },
    );
    let simulator = simulator_accepts(&program, mutated_witness, &honest_anchors);
    let identity = identity_accepts(&registry, &circuit, mutated_witness, &input);

    assert_eq!(
        simulator,
        identity,
        "Simulator and assembled constraint identity disagree after mutating slot \
         {slot} by {delta:?}. Simulator {}, identity {}. Program: {program:?}",
        if simulator { "ACCEPTED" } else { "REJECTED" },
        if identity { "ACCEPTED" } else { "REJECTED" },
    );

    assert_eq!(
        identity,
        oracle,
        "PATCHER SOUNDNESS SIGNAL: after mutating slot \
         {slot} by {delta:?} and repairing downstream, the constraint identity {} the \
         witness but the oracle says it is {}. {}. Program: {program:?}",
        if identity { "ACCEPTED" } else { "REJECTED" },
        if oracle { "satisfied" } else { "VIOLATED" },
        if identity && !oracle {
            "Ragu accepted a witness that changed a pinned wire — an \
             under-constrained constraint/gadget (the soundness direction)"
        } else {
            "Ragu rejected a witness the oracle accepts — a completeness gap"
        },
    );
});
