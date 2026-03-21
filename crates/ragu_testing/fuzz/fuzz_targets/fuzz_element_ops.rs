//! Fuzz arbitrary `Element` and `Boolean` operation sequences through the `Simulator`.
//!
//! Invariants:
//! - The `Simulator` never panics for valid witness values.
//! - Expected failures (invert zero, div by zero) return `Err`, not panic.

#![no_main]

use arbitrary::Arbitrary;
use ff::Field;
use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Boolean, Element, Simulator};

fn special_value(idx: u8) -> Fp {
    match idx % 8 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,                          // p - 1
        3 => Fp::TWO_INV,                        // (p + 1) / 2
        4 => Fp::ROOT_OF_UNITY,                  // 2-adic root of unity
        5 => Fp::MULTIPLICATIVE_GENERATOR,       // smallest generator
        6 => Fp::ROOT_OF_UNITY.square(),          // another root of unity
        _ => Fp::from(u64::MAX),                   // large value near 2^64
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    Add(u8, u8),
    Sub(u8, u8),
    Mul(u8, u8),
    Square(u8),
    Double(u8),
    Negate(u8),
    Invert(u8),
    IsZero(u8),
    DivNonzero(u8, u8),
    Scale(u8, u64),
    Fold(u8, u8, u64),
    AllocConst(u64),
    AllocSpecial(u8),
    AllocSquare(u64),
    BoolAlloc(bool),
    BoolNot(u8),
    BoolAnd(u8, u8),
    ConditionalSelect(u8, u8, u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    seeds: [u64; 4],
    large_seeds: [[u64; 4]; 2],
    /// Indices into `special_value()` for 2 extra initial elements.
    special_seeds: [u8; 2],
    /// Bitmask: if bit i is set, seed i is allocated as a constant instead of witness.
    constant_mask: u8,
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    if input.ops.is_empty() || input.ops.len() > 48 {
        return;
    }

    let mut fes: Vec<Fp> = input.seeds.iter().map(|v| Fp::from(*v)).collect();
    for ls in &input.large_seeds {
        let val = Fp::from(ls[0])
            + Fp::from(ls[1]) * Fp::from(1u64 << 32)
            + Fp::from(ls[2]) * Fp::from(1u64 << 48)
            + Fp::from(ls[3]) * Fp::from(1u64 << 56);
        fes.push(val);
    }
    for ss in &input.special_seeds {
        fes.push(special_value(*ss));
    }

    let _ = Simulator::<Fp>::simulate(fes.clone(), |dr, witness| {
        let mut elems: Vec<Element<'_, _>> = (0..fes.len())
            .map(|i| {
                if input.constant_mask & (1 << (i % 8)) != 0 {
                    Ok(Element::constant(dr, fes[i]))
                } else {
                    Element::alloc(dr, witness.as_ref().map(|v| v[i]))
                }
            })
            .collect::<Result<_, _>>()?;
        let mut bools: Vec<Boolean<'_, _>> = Vec::new();

        for op in &input.ops {
            let elen = elems.len();
            let blen = bools.len();
            if elen == 0 {
                break;
            }

            match *op {
                Op::Add(a, b) => {
                    let (a, b) = (a as usize % elen, b as usize % elen);
                    let r = elems[a].add(dr, &elems[b]);
                    elems.push(r);
                }
                Op::Sub(a, b) => {
                    let (a, b) = (a as usize % elen, b as usize % elen);
                    let r = elems[a].sub(dr, &elems[b]);
                    elems.push(r);
                }
                Op::Mul(a, b) => {
                    let (a, b) = (a as usize % elen, b as usize % elen);
                    if let Ok(r) = elems[a].mul(dr, &elems[b]) {
                        elems.push(r);
                    }
                }
                Op::Square(a) => {
                    let a = a as usize % elen;
                    if let Ok(r) = elems[a].square(dr) {
                        elems.push(r);
                    }
                }
                Op::Double(a) => {
                    let a = a as usize % elen;
                    let r = elems[a].double(dr);
                    elems.push(r);
                }
                Op::Negate(a) => {
                    let a = a as usize % elen;
                    let r = elems[a].negate(dr);
                    elems.push(r);
                }
                Op::Invert(a) => {
                    let a = a as usize % elen;
                    if let Ok(r) = elems[a].invert(dr) {
                        elems.push(r);
                    }
                }
                Op::IsZero(a) => {
                    let a = a as usize % elen;
                    if let Ok(b) = elems[a].is_zero(dr) {
                        bools.push(b);
                    }
                }
                Op::DivNonzero(a, b) => {
                    let (a, b) = (a as usize % elen, b as usize % elen);
                    if let Ok(r) = elems[a].div_nonzero(dr, &elems[b]) {
                        elems.push(r);
                    }
                }
                Op::Scale(a, c) => {
                    let a = a as usize % elen;
                    let r = elems[a].scale(dr, Coeff::Arbitrary(Fp::from(c)));
                    elems.push(r);
                }
                Op::Fold(a, b, s) => {
                    let (a, b) = (a as usize % elen, b as usize % elen);
                    let scale = Element::alloc(dr, witness.as_ref().map(|_| Fp::from(s)))?;
                    if let Ok(r) = Element::fold(dr, [&elems[a], &elems[b]], &scale) {
                        elems.push(r);
                    }
                }
                Op::AllocConst(v) => {
                    let r = Element::constant(dr, Fp::from(v));
                    elems.push(r);
                }
                Op::AllocSpecial(idx) => {
                    let v = special_value(idx);
                    let r = Element::alloc(dr, witness.as_ref().map(|_| v))?;
                    elems.push(r);
                }
                Op::AllocSquare(v) => {
                    if let Ok((root, sq)) = Element::alloc_square(
                        dr,
                        witness.as_ref().map(|_| Fp::from(v)),
                    ) {
                        elems.push(root);
                        elems.push(sq);
                    }
                }
                Op::BoolAlloc(v) => {
                    if let Ok(b) = Boolean::alloc(
                        dr,
                        witness.as_ref().map(|_| v),
                    ) {
                        bools.push(b);
                    }
                }
                Op::BoolNot(a) => {
                    if blen > 0 {
                        let a = a as usize % blen;
                        let r = bools[a].not(dr);
                        bools.push(r);
                    }
                }
                Op::BoolAnd(a, b) => {
                    if blen > 0 {
                        let (a, b) = (a as usize % blen, b as usize % blen);
                        if let Ok(r) = bools[a].and(dr, &bools[b]) {
                            bools.push(r);
                        }
                    }
                }
                Op::ConditionalSelect(cond, a, b) => {
                    if blen > 0 {
                        let cond = cond as usize % blen;
                        let (a, b) = (a as usize % elen, b as usize % elen);
                        if let Ok(r) = bools[cond].conditional_select(
                            dr, &elems[a], &elems[b],
                        ) {
                            elems.push(r);
                        }
                    }
                }
            }

            if elems.len() > 128 {
                elems.truncate(64);
            }
            if bools.len() > 64 {
                bools.truncate(32);
            }
        }
        Ok(())
    });
});
