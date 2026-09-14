//! Fuzz the canonical algebraic identity that bridges the witness-driver
//! and wiring/constraint sides of the synthesis pipeline.
//!
//! For a satisfying witness `w` of a registered `Circuit`, with assembled
//! trace polynomial `r`, the identity from
//! `ragu_circuits::tests::test_simple_circuit` is:
//!
//! ```text
//! r.revdot(b) == circuit.ky(instance, y)
//! where b = r + r.dilate(z) + s(X, y) + t(X, z)
//! ```
//!
//! `r` is the witness-side polynomial (assembled trace); `s(X, y)` is the
//! wiring polynomial restricted at `y`; `t(X, z)` is the gate polynomial
//! restricted at `z`; `circuit.ky(instance, y)` is the instance polynomial
//! evaluated at `y`. The equality is what actually proves
//! "this witness satisfies this circuit's constraints" at the
//! algebraic layer; under random `(y, z)` it holds with overwhelming
//! probability iff the witness is satisfying.
//!
//! This is the **accept direction** of the constraint identity: every
//! honest trace of a satisfying witness must satisfy it. (The rejection
//! direction — a mutated trace must *fail* it — is `fuzz_witness_pinning`.)
//!
//! # Circuit substrate
//!
//! The circuit is an arbitrary generated [`ragu_testing_fuzz::substrate`]
//! program, `steer`ed so its honest witness never hits a value-dependent
//! gadget failure, and registered as a [`ProgramCircuit`] with anchors
//! pinned to the honest values (so the honest witness is satisfying by
//! construction). `s(X, y)` comes from the public [`Registry::circuit_y`].
//! This generalizes the original target, which ran two hand-written
//! circuits and derived `s(X, y)` by stripping the registry tag term from
//! `Registry::wy` — a trick valid only for unmasked single-circuit
//! registries. The public `circuit_y` accessor makes that hack
//! unnecessary.
//!
//! ## What this catches
//!
//! - Witness pipeline bugs that produce a `Trace` whose assembled
//!   polynomial fails the algebraic identity — equivalent to "the witness
//!   doesn't satisfy the constraint system."
//! - `Registry::circuit_y` / `Rank::tz` / `Polynomial::revdot` regressions
//!   in the identity's construction.

#![no_main]

use ff::Field;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::{
    CircuitExt,
    polynomials::{Rank, TestRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_testing_fuzz::substrate::{
    Limits, OpSet, Overrides, Program, ProgramCircuit, shadow_eval, steer,
};

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    /// Raw program bytes, decoded via [`Program::decode`].
    program: Vec<u8>,
    y_seed: u64,
    z_seed: u64,
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

fuzz_target!(|input: Input| {
    // The full grammar, steered so the honest witness never skips an op.
    let program = steer::<Fp>(&Program::decode(
        &input.program,
        OpSet::ALL,
        Limits::default(),
    ));

    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!(
            "y_seed={}, z_seed={}\n{program:#?}",
            input.y_seed, input.z_seed
        );
        return;
    }
    if program.ops.is_empty() {
        return;
    }

    let honest = shadow_eval::<Fp>(&program, Overrides::none());
    let circuit = ProgramCircuit {
        program: &program,
        anchors: &honest.anchors,
    };
    let registry = match RegistryBuilder::<Fp, TestRank>::new()
        .register_circuit(circuit)
        .and_then(|b| b.finalize())
    {
        Ok(r) => r,
        Err(_) => return, // Rank overflow: program too large for TestRank.
    };

    let trace = circuit
        .trace(program.preamble.values::<Fp>())
        .expect("honest steered ProgramCircuit trace failed")
        .into_output();
    let r = registry
        .assemble_with_alpha(&trace, CircuitIndex::new(0), Fp::ZERO)
        .expect("assemble_with_alpha failed on a registered, satisfying witness");

    let y = Fp::from(input.y_seed);
    let z = Fp::from(input.z_seed);
    let expected = circuit
        .ky((), y)
        .expect("ProgramCircuit::ky should not fail on the unit instance");
    let actual = identity_lhs(&registry, &r, y, z);

    assert_eq!(
        expected, actual,
        "constraint identity violated for an honest satisfying witness at \
         y={y:?}, z={z:?}: expected_ky={expected:?}, actual_revdot={actual:?}. \
         Program: {program:?}"
    );
});
