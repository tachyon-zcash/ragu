//! Fuzz endoscalar extract, lift, and group_scale.
//!
//! Invariants:
//! - `extract_endoscalar` never panics for any valid field element.
//! - `lift_endoscalar(extract_endoscalar(r))` is deterministic.
//! - In-circuit lift agrees with native `lift_endoscalar`.
//! - `group_scale(p)` agrees with `p * lift_endoscalar::<Fq>(endo)`.

#![no_main]

use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_pasta::{EpAffine, Fq};
use ragu_primitives::{Element, Endoscalar, Point, Simulator, extract_endoscalar, lift_endoscalar};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut repr = <Fp as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&data[..32]);
    let Some(r) = Option::from(Fp::from_repr(repr)) else {
        return;
    };

    // Native extract/lift — must not panic
    let extracted = extract_endoscalar::<Fp>(r);
    let lifted_native: Fp = lift_endoscalar(extracted);

    // Determinism
    let extracted2 = extract_endoscalar::<Fp>(r);
    let lifted_native2: Fp = lift_endoscalar(extracted2);
    assert_eq!(extracted, extracted2, "extract is not deterministic");
    assert_eq!(lifted_native, lifted_native2, "lift is not deterministic");

    // Circuit extract/lift agreement + group_scale
    let generator = EpAffine::generator();
    let expected_scalar: Fq = lift_endoscalar(extracted);
    let expected_point: EpAffine = (generator * expected_scalar).into();

    let result = Simulator::<Fp>::simulate((r, extracted, generator), |dr, witness| {
        let (r_val, _endo_val, p_val) = witness.cast();
        let r_elem = Element::alloc(dr, r_val)?;
        let endo = Endoscalar::extract(dr, r_elem)?;

        // Circuit lift must match native lift
        let lifted_circuit = endo.lift(dr)?;
        assert_eq!(
            *lifted_circuit.value().take(),
            lifted_native,
            "circuit lift != native lift"
        );

        // Circuit group_scale must match native p * scalar
        let p = Point::alloc(dr, p_val)?;
        let scaled = endo.group_scale(dr, &p)?;
        assert_eq!(
            scaled.value().take(),
            expected_point,
            "circuit group_scale != native scaling"
        );

        Ok(())
    });

    assert!(
        result.is_ok(),
        "endoscalar circuit failed: {:?}",
        result.err()
    );
});
