//! Fuzz endoscalar extract/lift roundtrip.
//!
//! The endoscalar extraction (ragu_primitives::endoscalar) checks quadratic
//! residuosity of `value + i` for each bit position — the `expect("should
//! produce a square if the other didn't")` at line 101 is a correctness
//! assumption we want to stress-test.
//!
//! Invariants checked:
//! - extract_endoscalar never panics for any valid field element
//! - lift_endoscalar(extract_endoscalar(r)) is deterministic
//! - In-circuit lift agrees with native lift_endoscalar

#![no_main]

use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Element, Endoscalar, Simulator, extract_endoscalar, lift_endoscalar};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Construct a field element from arbitrary bytes
    let mut repr = <Fp as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&data[..32]);
    let Some(r) = Option::from(Fp::from_repr(repr)) else {
        return;
    };

    // Native path: extract then lift — must not panic
    let extracted = extract_endoscalar::<Fp>(r);
    let lifted_native: Fp = lift_endoscalar(extracted);

    // Determinism: same input must produce same output
    let extracted2 = extract_endoscalar::<Fp>(r);
    let lifted_native2: Fp = lift_endoscalar(extracted2);
    assert_eq!(extracted, extracted2, "extract is not deterministic");
    assert_eq!(lifted_native, lifted_native2, "lift is not deterministic");

    // In-circuit path: lift must agree with native
    let result = Simulator::<Fp>::simulate((r, extracted), |dr, witness| {
        let (r_val, _endo_val) = witness.cast();
        let r_elem = Element::alloc(dr, r_val)?;
        let endo = Endoscalar::extract(dr, r_elem)?;

        // Circuit lift must match native lift
        let lifted_circuit = endo.lift(dr)?;
        assert_eq!(
            *lifted_circuit.value().take(),
            lifted_native,
            "circuit lift != native lift"
        );

        Ok(())
    });

    assert!(
        result.is_ok(),
        "endoscalar circuit failed: {:?}",
        result.err()
    );
});
