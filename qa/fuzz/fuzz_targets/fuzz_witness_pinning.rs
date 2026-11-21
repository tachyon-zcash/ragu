//! Witness-pinning soundness oracle: mutate one coefficient of a
//! satisfying trace polynomial and demand the constraint identity reject.
//!
//! This is the constraint-side counterpart to `fuzz_witness_cheat`. That
//! target perturbs values *during* Simulator execution, where every
//! downstream gadget recomputes honestly from the perturbed input — gates
//! self-satisfy by construction, so the Simulator can never expose an
//! under-constrained gadget. The actual soundness question lives on the
//! wiring side: does the constraint system *pin* every witness value the
//! Rust witness generator assigns, or would a prover-chosen substitute
//! pass verification?
//!
//! In Ragu's algebraic formulation (see `fuzz_circuit_revdot_identity`),
//! "witness w satisfies the constraints" is the identity
//!
//! ```text
//! r.revdot(r + r.dilate(z) + s(X, y) + t(X, z)) == circuit.ky(instance, y)
//! ```
//!
//! holding at random `(y, z)`, where `r` is the assembled trace
//! polynomial. The oracle here:
//!
//! 1. Build a satisfying witness and its assembled `r` (alpha = 0).
//! 2. Sanity: the identity holds honestly at two independent `(y, z)`
//!    points (this subsumes `fuzz_circuit_revdot_identity`'s check).
//! 3. Pick one *occupied* coefficient of `r`, add a fuzzer-chosen nonzero
//!    delta, and rebuild the identity with the mutated `r'` — same
//!    instance, same `ky`, a genuinely different witness.
//! 4. Assert the identity now FAILS at one of the two points. If a
//!    changed witness coefficient still satisfies the constraint
//!    identity, nothing in the constraint system pins that wire: a
//!    malicious prover could substitute it freely. That is the
//!    assignment-vs-constraint gap — panic with the offending degree.
//!
//! # The circuit substrate must be fully pinned
//!
//! The step-4 assertion ("mutating any occupied coefficient breaks the
//! identity") is only valid when *every* live wire is constrained — a
//! genuinely free advice wire could take the mutated value and still
//! satisfy the identity, which is correct, not a bug. The original target
//! used two hand-written circuits (`SquareCircuit`, `MySimpleCircuit`) that
//! happen to be fully determined. To run the same oracle over arbitrary
//! generated [`ragu_testing_fuzz::substrate`] programs, we *force* full pinning:
//! after the fuzzer-chosen op body, an `Anchor` is appended for every
//! element slot, pinning each wire to its honest value. Every live trace
//! coefficient is then determined (element wires directly; gate input wires
//! transitively via the mul gates' copy constraints), so any single-
//! coefficient perturbation must be rejected.
//!
//! # Why this has (essentially) no false positives
//!
//! For a pinned coefficient, the mutated identity defect Δ(y, z) is a
//! nonzero polynomial of degree ≤ 8n in y and z, so it vanishes at a
//! random point with probability ~deg/|F| ≈ 2^-245. The fuzzer chooses
//! `y, z` from u64 seeds, so the only *reachable* structured roots are
//! tiny values; we bail on y, z ∈ {0, 1} and additionally require the
//! defect to vanish at a second, affinely independent point before
//! declaring a bug.
//!
//! Mutation is restricted to coefficients that are live for the chosen
//! circuit. The live-degree mask is computed from probe traces of the same
//! circuit under several witnesses, then unioned with the current trace's
//! nonzero coefficients. This avoids mutating structural padding and
//! intentionally-dead allocation slots while still allowing zero-valued
//! live wires in the current trace to be mutated.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_circuits::{
    CircuitExt, Trace,
    polynomials::{Rank, TestRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_core::pasta::Fp;
use ragu_testing_fuzz::substrate::{
    Capabilities, Limits, Op, OpSet, Overrides, Preamble, Program, ProgramCircuit, shadow_eval,
};
use udon::field::Field;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw program bytes for the op body, decoded via [`Program::decode`].
    program: Vec<u8>,
    y_seed: u64,
    z_seed: u64,
    /// Index into the list of occupied coefficient positions of `r`.
    mutate_idx: u16,
    /// Additive perturbation of the chosen coefficient; 0 maps to 1 so the
    /// mutation is always a real change.
    delta_seed: u64,
}

/// Body vocabulary: arithmetic + alloc ops with value-independent stack
/// progression (no value-fallible ops) and no booleans, so probing under
/// different witnesses keeps the same wire layout and anchoring every
/// element fully pins the circuit. Anchors are appended by the harness, not
/// drawn from the fuzzer, so the body mask excludes them.
fn body_opset() -> OpSet {
    OpSet::ALL
        .without(Capabilities::VALUE_FALLIBLE)
        .without(Capabilities::BOOLEAN)
        .without(Capabilities::ANCHORS)
}

/// Build the fully-pinned program: the decoded op body followed by one
/// `Anchor` per element slot. Returns `None` if the body produces no
/// elements beyond the preamble worth pinning (always at least the
/// preamble, so this is just an emptiness guard).
fn pinned_program(body_bytes: &[u8]) -> Program {
    // Cap the body so body + per-element anchors fit within TestRank.
    let body = Program::decode(body_bytes, body_opset(), Limits { max_ops: 16 });
    let elem_count = shadow_eval::<Fp>(&body, Overrides::none()).elems.len();

    let mut ops = body.ops;
    for slot in 0..elem_count {
        // Anchor(slot): pins elems[slot % elen] = elems[slot] (slot < elen,
        // and anchors push nothing so elen is the body's final count).
        ops.push(Op::Anchor(slot as u8));
    }
    Program {
        preamble: body.preamble,
        ops,
    }
}

/// Evaluate the revdot identity left-hand side for trace polynomial `r` at
/// `(y, z)`, using the registry's exact per-circuit `s(X, y)`.
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

fn add_nonzero_degrees(poly: &sparse::Polynomial<Fp, TestRank>, degrees: &mut Vec<usize>) {
    for (degree, coeff) in poly.iter_coeffs().enumerate() {
        if coeff != Fp::ZERO && !degrees.contains(&degree) {
            degrees.push(degree);
        }
    }
}

/// Live-degree mask: probe the circuit with several witnesses and union the
/// nonzero coefficient degrees of each assembled trace. Structure is
/// witness-independent, so a degree occupied under any probe is the same
/// wire slot under every witness. Probe traces need not satisfy the anchors
/// (assembly does not check constraints), so cheap perturbed witnesses
/// suffice to reveal occupancy, including for wires that are zero in the
/// honest trace.
fn live_degrees(
    registry: &Registry<'_, Fp, TestRank>,
    circuit: &ProgramCircuit<'_, Fp>,
    honest_witness: &[Fp; Preamble::LEN],
) -> Vec<usize> {
    let mut degrees = Vec::new();
    let probes: [[Fp; Preamble::LEN]; 3] = [
        *honest_witness,
        core::array::from_fn(|i| honest_witness[i] + Fp::ONE),
        core::array::from_fn(|i| honest_witness[i] * Fp::MULTIPLICATIVE_GENERATOR + Fp::from(7u64)),
    ];
    for w in probes {
        if let Ok(t) = circuit.trace(w)
            && let Ok(poly) =
                registry.assemble_with_alpha(&t.into_output(), CircuitIndex::new(0), Fp::ZERO)
        {
            add_nonzero_degrees(&poly, &mut degrees);
        }
    }
    degrees.sort_unstable();
    degrees
}

fuzz_target!(|input: Input| {
    let program = pinned_program(&input.program);

    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!(
            "y_seed={}, z_seed={}, mutate_idx={}, delta_seed={}\n{program:#?}",
            input.y_seed, input.z_seed, input.mutate_idx, input.delta_seed,
        );
        return;
    }

    // y, z ∈ {0, 1} collapse too much identity structure for the rejection
    // direction; those points are exercised by the accept-direction targets.
    if input.y_seed < 2 || input.z_seed < 2 {
        return;
    }

    let honest_witness = program.preamble.values::<Fp>();
    let honest = shadow_eval::<Fp>(&program, Overrides::none());

    let circuit = ProgramCircuit {
        program: &program,
        anchors: &honest.anchors,
    };
    let Some(registry) = ragu_testing_fuzz::registry::fits(
        RegistryBuilder::<Fp, TestRank>::new()
            .register_circuit(circuit)
            .and_then(|b| b.finalize()),
    ) else {
        return; // Rank overflow: program too large for TestRank.
    };

    let trace: Trace<Fp> = circuit
        .trace(honest_witness)
        .expect("fully-pinned honest ProgramCircuit trace failed")
        .into_output();

    let y = Fp::from(input.y_seed);
    let z = Fp::from(input.z_seed);
    // Second, affinely independent evaluation point. Kills the residual
    // false-positive risk of the fuzzer landing on a structured root of the
    // defect polynomial at the primary point.
    let y2 = y * Fp::MULTIPLICATIVE_GENERATOR + Fp::from(3);
    let z2 = z * Fp::MULTIPLICATIVE_GENERATOR + Fp::from(7);

    let ky = |py: Fp| {
        circuit
            .ky((), py)
            .expect("ProgramCircuit::ky should not fail on the unit instance")
    };

    let r = registry
        .assemble_with_alpha(&trace, CircuitIndex::new(0), Fp::ZERO)
        .expect("assemble_with_alpha failed on a registered, satisfying witness");

    // Sanity (honest identity, both points).
    for (py, pz) in [(y, z), (y2, z2)] {
        assert_eq!(
            ky(py),
            identity_lhs(&registry, &r, py, pz),
            "honest identity violated at y={py:?}, z={pz:?}: {program:?}"
        );
    }

    // Mutate one occupied coefficient. Probe-derived live degrees plus the
    // current trace's nonzero coefficients.
    let mut coeffs: Vec<Fp> = r.iter_coeffs().collect();
    let mut occupied = live_degrees(&registry, &circuit, &honest_witness);
    for (degree, coeff) in coeffs.iter().enumerate() {
        if *coeff != Fp::ZERO && !occupied.contains(&degree) {
            occupied.push(degree);
        }
    }
    if occupied.is_empty() {
        return;
    }
    occupied.sort_unstable();
    let degree = occupied[input.mutate_idx as usize % occupied.len()];
    let mut delta = Fp::from(input.delta_seed);
    if delta == Fp::ZERO {
        delta = Fp::ONE;
    }
    coeffs[degree] += delta;
    let mutated = sparse::Polynomial::<Fp, TestRank>::from_coeffs(coeffs);

    // The mutated witness must be rejected at at least one of the two
    // points. Surviving both means the constraint system never pins the
    // wire behind this coefficient.
    let survives_1 = identity_lhs(&registry, &mutated, y, z) == ky(y);
    let survives_2 = survives_1 && identity_lhs(&registry, &mutated, y2, z2) == ky(y2);

    assert!(
        !survives_2,
        "PINNING VIOLATION: trace coefficient at degree {degree} \
         (n = {}) changed by {delta:?} yet the constraint identity still \
         holds at two independent points (y={y:?}, z={z:?}) and \
         (y2={y2:?}, z2={z2:?}). The constraint system does not pin this \
         wire — a malicious prover could substitute it freely. {program:?}",
        TestRank::n(),
    );
});
