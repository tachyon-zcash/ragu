//! IO write/buffer round-trip fuzz target.
//!
//! The `Write` trait serializes a `Gadget` into a sequence of `Element`s
//! written to a `Buffer`. This target allocates a handful of gadget
//! shapes, writes each into a `Vec<Element>` buffer (which itself
//! implements `Buffer`), and asserts that the buffer's resulting length
//! and value sequence match what we hand-compute.
//!
//! Mismatch surfaces bugs in:
//!   - A `Write` impl emitting the wrong number of elements (e.g., a
//!     composite that forgets a field).
//!   - A `Write` impl emitting elements in the wrong order.
//!   - A `Write` impl computing wrong values for a gadget whose
//!     serialized form isn't just its raw wires (e.g., `Boolean`
//!     serializes as its Element form, value 0 or 1).
//!
//! # Coverage
//!
//!   - `Element::write` → 1 element, value matches witness
//!   - `Boolean::write` → 1 element, value is 0 or 1 matching the bool
//!   - `[Element; N]::write` → N elements in order
//!   - `[Boolean; N]::write` → N elements in order
//!   - `()::write` → 0 elements (trivial impl, smoke check)

#![no_main]

use alloc::vec::Vec;

use arbitrary::Arbitrary;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_primitives::{
    Boolean, Element, GadgetExt, Simulator, allocator::Standard,
};

extern crate alloc;

fn parse_fp(bytes: [u8; 32]) -> Fp {
    Option::<Fp>::from(Fp::from_repr(bytes)).unwrap_or_else(|| {
        Fp::from(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    })
}

#[derive(Arbitrary, Debug)]
struct Input {
    a_bytes: [u8; 32],
    b_bytes: [u8; 32],
    c_bytes: [u8; 32],
    bv1: bool,
    bv2: bool,
    bv3: bool,
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
    let c_val = parse_fp(input.c_bytes);

    let r = Simulator::<Fp>::simulate(
        (a_val, b_val, c_val, input.bv1, input.bv2, input.bv3),
        |dr, witness| {
            let allocator = &mut Standard::new();

            // Element::write → 1 element with witness value
            let e_a = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
            let mut buf: Vec<Element<'_, _>> = Vec::new();
            e_a.write(dr, &mut buf)?;
            assert_eq!(buf.len(), 1, "Element::write should produce exactly 1 element");
            assert_eq!(
                *buf[0].value().take(),
                a_val,
                "Element::write value mismatch: expected {:?}",
                a_val,
            );

            // Boolean::write → 1 element with value 0 or 1
            let b_bv = Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.3))?;
            let mut buf: Vec<Element<'_, _>> = Vec::new();
            b_bv.write(dr, &mut buf)?;
            assert_eq!(buf.len(), 1, "Boolean::write should produce exactly 1 element");
            assert_eq!(
                *buf[0].value().take(),
                if input.bv1 { Fp::ONE } else { Fp::ZERO },
                "Boolean::write value mismatch: bv={}",
                input.bv1,
            );

            // [Element; 3]::write → 3 elements in input order
            let elems: [Element<'_, _>; 3] = [
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?,
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?,
                Element::alloc(dr, allocator, witness.as_ref().map(|w| w.2))?,
            ];
            let mut buf: Vec<Element<'_, _>> = Vec::new();
            elems.write(dr, &mut buf)?;
            assert_eq!(buf.len(), 3, "[Element; 3] write should produce 3 elements");
            assert_eq!(*buf[0].value().take(), a_val, "array[0]");
            assert_eq!(*buf[1].value().take(), b_val, "array[1]");
            assert_eq!(*buf[2].value().take(), c_val, "array[2]");

            // [Boolean; 3]::write → 3 elements, each 0 or 1
            let bools: [Boolean<'_, _>; 3] = [
                Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.3))?,
                Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.4))?,
                Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.5))?,
            ];
            let mut buf: Vec<Element<'_, _>> = Vec::new();
            bools.write(dr, &mut buf)?;
            assert_eq!(buf.len(), 3, "[Boolean; 3] write should produce 3 elements");
            assert_eq!(
                *buf[0].value().take(),
                if input.bv1 { Fp::ONE } else { Fp::ZERO },
                "bool array[0]",
            );
            assert_eq!(
                *buf[1].value().take(),
                if input.bv2 { Fp::ONE } else { Fp::ZERO },
                "bool array[1]",
            );
            assert_eq!(
                *buf[2].value().take(),
                if input.bv3 { Fp::ONE } else { Fp::ZERO },
                "bool array[2]",
            );

            // ()::write → 0 elements (trivial impl)
            let mut buf: Vec<Element<'_, _>> = Vec::new();
            ().write(dr, &mut buf)?;
            assert_eq!(buf.len(), 0, "() write should produce 0 elements");

            Ok(())
        },
    );

    assert!(
        r.is_ok(),
        "Simulator returned Err during IO roundtrip: {:?}",
        r.err(),
    );
});
