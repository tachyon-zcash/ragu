//! Element assertion-gadget fuzz target.
//!
//! Tests `enforce_zero`, `enforce_root_of_unity`, and `invert_with` —
//! the Element gadgets that *assert* something about their input
//! (rather than computing a new value). Each test runs the gadget on
//! both a value that should satisfy the assertion (positive case, expect
//! Simulator `Ok`) and a value that should not (negative case, expect
//! Simulator `Err`). Mismatch with the expected outcome means the
//! gadget is either accepting invalid witnesses (soundness gap) or
//! rejecting valid ones (completeness gap).
//!
//! # Tests
//!
//! `enforce_zero`:
//!   - POS: `alloc(0).enforce_zero()` → Ok
//!   - NEG: `alloc(non_zero).enforce_zero()` → Err
//!
//! `enforce_root_of_unity`:
//!   - POS: `alloc(ROOT_OF_UNITY).enforce_root_of_unity(32)` → Ok
//!     (ROOT_OF_UNITY is the 2^32-th primitive root for Pasta Fp)
//!   - POS: `alloc(ONE).enforce_root_of_unity(0)` → Ok
//!     (k=0 only requires `self == 1`)
//!   - NEG: `alloc(2).enforce_root_of_unity(8)` → Err
//!     (2^(2^8) mod p != 1; 2 is not a 256-th root of unity)
//!
//! `invert_with`:
//!   - POS: `alloc(a).invert_with(a⁻¹)` → Ok, returned element has value
//!     `a⁻¹` (requires `a != 0`)
//!   - NEG: `alloc(a).invert_with(0)` → Err (since `a * 0 = 0 != 1`)
//!   - NEG: `alloc(0).invert_with(_)` → Err (since `0 * _ = 0 != 1`)
//!
//! `Boolean::conditional_enforce_equal`:
//!   - POS: `alloc(true).cee(alloc(a), alloc(a))` → Ok (trivially equal)
//!   - POS: `alloc(false).cee(alloc(a), alloc(b))` → Ok (no enforcement)
//!   - NEG: `alloc(true).cee(alloc(a), alloc(b))` → Err (when `a != b`)

#![no_main]

use arbitrary::Arbitrary;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Boolean, Element, Simulator, allocator::Standard};

#[derive(Arbitrary, Debug)]
struct Input {
    /// 32 bytes parsed as canonical Fp (with low-entropy u64 fallback).
    a_bytes: [u8; 32],
    /// A second Fp value, used as the right-hand side for
    /// conditional_enforce_equal tests.
    b_bytes: [u8; 32],
}

fn parse_fp(bytes: [u8; 32]) -> Fp {
    Option::<Fp>::from(Fp::from_repr(bytes)).unwrap_or_else(|| {
        Fp::from(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    })
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    let a_val = parse_fp(input.a_bytes);
    let b_val = parse_fp(input.b_bytes);

    // ============================================================
    // enforce_zero
    // ============================================================

    // POS: alloc(0).enforce_zero() → Ok
    let r = Simulator::<Fp>::simulate(Fp::ZERO, |dr, witness| {
        let allocator = &mut Standard::new();
        let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        e.enforce_zero(dr)
    });
    assert!(r.is_ok(), "enforce_zero(0) should succeed but returned Err: {:?}", r.err());

    // NEG: alloc(non-zero).enforce_zero() → Err
    if a_val != Fp::ZERO {
        let r = Simulator::<Fp>::simulate(a_val, |dr, witness| {
            let allocator = &mut Standard::new();
            let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
            e.enforce_zero(dr)
        });
        assert!(
            r.is_err(),
            "enforce_zero(non_zero) should fail but returned Ok; a={:?}",
            a_val,
        );
    }

    // ============================================================
    // enforce_root_of_unity
    // ============================================================

    // POS: alloc(ROOT_OF_UNITY).enforce_root_of_unity(32) → Ok
    // (Pasta Fp has 2-adicity 32; ROOT_OF_UNITY is the primitive 2^32-th
    // root of unity.)
    let r = Simulator::<Fp>::simulate(Fp::ROOT_OF_UNITY, |dr, witness| {
        let allocator = &mut Standard::new();
        let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        e.enforce_root_of_unity(dr, 32)
    });
    assert!(
        r.is_ok(),
        "enforce_root_of_unity(ROOT_OF_UNITY, 32) should succeed but returned Err: {:?}",
        r.err(),
    );

    // POS: alloc(ONE).enforce_root_of_unity(0) → Ok
    // (k=0 requires self^(2^0) = self == 1.)
    let r = Simulator::<Fp>::simulate(Fp::ONE, |dr, witness| {
        let allocator = &mut Standard::new();
        let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        e.enforce_root_of_unity(dr, 0)
    });
    assert!(
        r.is_ok(),
        "enforce_root_of_unity(1, 0) should succeed but returned Err: {:?}",
        r.err(),
    );

    // NEG: alloc(2).enforce_root_of_unity(8) → Err
    // (2^(2^8) = 2^256 mod p ≈ 4, which is not 1.)
    let r = Simulator::<Fp>::simulate(Fp::from(2u64), |dr, witness| {
        let allocator = &mut Standard::new();
        let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        e.enforce_root_of_unity(dr, 8)
    });
    assert!(
        r.is_err(),
        "enforce_root_of_unity(2, 8) should fail but returned Ok",
    );

    // ============================================================
    // invert_with
    // ============================================================

    // POS: alloc(a).invert_with(a⁻¹) → Ok, result has value a⁻¹
    if a_val != Fp::ZERO {
        let a_inv: Fp = Option::<Fp>::from(a_val.invert())
            .expect("non-zero Fp must have an inverse");
        let r = Simulator::<Fp>::simulate((a_val, a_inv), |dr, witness| {
            let allocator = &mut Standard::new();
            let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| v.0))?;
            let inv_e = e.invert_with(dr, witness.as_ref().map(|v| v.1))?;
            assert_eq!(
                *inv_e.value().take(),
                a_inv,
                "invert_with returned wrong value: a={:?} expected_inv={:?}",
                a_val,
                a_inv,
            );
            Ok(())
        });
        assert!(
            r.is_ok(),
            "invert_with(a, a⁻¹) should succeed; a={:?} a_inv={:?} err={:?}",
            a_val,
            a_inv,
            r.err(),
        );
    }

    // NEG: alloc(a).invert_with(0) → Err (a * 0 = 0 != 1)
    let r = Simulator::<Fp>::simulate(a_val, |dr, witness| {
        let allocator = &mut Standard::new();
        let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        let _ = e.invert_with(dr, witness.as_ref().map(|_| Fp::ZERO))?;
        Ok(())
    });
    assert!(
        r.is_err(),
        "invert_with(a, 0) should fail (a * 0 = 0 != 1); a={:?}",
        a_val,
    );

    // NEG: alloc(0).invert_with(anything) → Err (0 * _ = 0 != 1)
    let r = Simulator::<Fp>::simulate(Fp::ZERO, |dr, witness| {
        let allocator = &mut Standard::new();
        let e = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        let _ = e.invert_with(dr, witness.as_ref().map(|_| Fp::ONE))?;
        Ok(())
    });
    assert!(
        r.is_err(),
        "invert_with(0, _) should fail (0 * _ = 0 != 1)",
    );

    // ============================================================
    // Boolean::conditional_enforce_equal
    // ============================================================

    // POS: alloc(true).cee(alloc(a), alloc(a)) → Ok (trivially a == a)
    let r = Simulator::<Fp>::simulate(a_val, |dr, witness| {
        let allocator = &mut Standard::new();
        let cond = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| true))?;
        let x = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        let y = Element::alloc(dr, allocator, witness.as_ref().map(|v| *v))?;
        cond.conditional_enforce_equal(dr, allocator, &x, &y)
    });
    assert!(
        r.is_ok(),
        "cee(true, a, a) should succeed; a={:?} err={:?}",
        a_val,
        r.err(),
    );

    // POS: alloc(false).cee(alloc(a), alloc(b)) → Ok (no enforcement)
    let r = Simulator::<Fp>::simulate((a_val, b_val), |dr, witness| {
        let allocator = &mut Standard::new();
        let cond = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| false))?;
        let x = Element::alloc(dr, allocator, witness.as_ref().map(|v| v.0))?;
        let y = Element::alloc(dr, allocator, witness.as_ref().map(|v| v.1))?;
        cond.conditional_enforce_equal(dr, allocator, &x, &y)
    });
    assert!(
        r.is_ok(),
        "cee(false, a, b) should succeed (no enforcement); a={:?} b={:?} err={:?}",
        a_val,
        b_val,
        r.err(),
    );

    // NEG: alloc(true).cee(alloc(a), alloc(b)) → Err when a != b
    if a_val != b_val {
        let r = Simulator::<Fp>::simulate((a_val, b_val), |dr, witness| {
            let allocator = &mut Standard::new();
            let cond = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| true))?;
            let x = Element::alloc(dr, allocator, witness.as_ref().map(|v| v.0))?;
            let y = Element::alloc(dr, allocator, witness.as_ref().map(|v| v.1))?;
            cond.conditional_enforce_equal(dr, allocator, &x, &y)
        });
        assert!(
            r.is_err(),
            "cee(true, a, b) should fail when a != b; a={:?} b={:?}",
            a_val,
            b_val,
        );
    }
});
