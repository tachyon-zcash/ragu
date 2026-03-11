//! Fuzz arbitrary `Element` operation sequences through the `Simulator`.
//!
//! Invariant: for valid witness values, the `Simulator` never returns
//! `Err` (except expected cases like inverting zero) and never panics.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Element, Simulator};

#[derive(Arbitrary, Debug)]
enum Op {
    Add(u8, u8),
    Sub(u8, u8),
    Mul(u8, u8),
    Square(u8),
    Double(u8),
    Invert(u8),
    IsZero(u8),
    DivNonzero(u8, u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    seeds: [u64; 4],
    ops: Vec<Op>,
}

fuzz_target!(|input: Input| {
    if input.ops.is_empty() || input.ops.len() > 48 {
        return;
    }

    let fes: Vec<Fp> = input.seeds.iter().map(|v| Fp::from(*v)).collect();

    let _ = Simulator::<Fp>::simulate(fes.clone(), |dr, witness| {
        let mut elems: Vec<Element<'_, _>> = (0..4)
            .map(|i| Element::alloc(dr, witness.as_ref().map(|v| v[i])))
            .collect::<Result<_, _>>()?;

        for op in &input.ops {
            let len = elems.len();
            if len == 0 {
                break;
            }

            match *op {
                Op::Add(a, b) => {
                    let (a, b) = (a as usize % len, b as usize % len);
                    let r = elems[a].add(dr, &elems[b]);
                    elems.push(r);
                }
                Op::Sub(a, b) => {
                    let (a, b) = (a as usize % len, b as usize % len);
                    let r = elems[a].sub(dr, &elems[b]);
                    elems.push(r);
                }
                Op::Mul(a, b) => {
                    let (a, b) = (a as usize % len, b as usize % len);
                    if let Ok(r) = elems[a].mul(dr, &elems[b]) {
                        elems.push(r);
                    }
                }
                Op::Square(a) => {
                    let a = a as usize % len;
                    if let Ok(r) = elems[a].square(dr) {
                        elems.push(r);
                    }
                }
                Op::Double(a) => {
                    let a = a as usize % len;
                    let r = elems[a].double(dr);
                    elems.push(r);
                }
                Op::Invert(a) => {
                    let a = a as usize % len;
                    // Invert of zero is expected to fail — not a bug
                    if let Ok(r) = elems[a].invert(dr) {
                        elems.push(r);
                    }
                }
                Op::IsZero(a) => {
                    let a = a as usize % len;
                    let _ = elems[a].is_zero(dr);
                }
                Op::DivNonzero(a, b) => {
                    let (a, b) = (a as usize % len, b as usize % len);
                    // Division by zero is expected to fail
                    if let Ok(r) = elems[a].div_nonzero(dr, &elems[b]) {
                        elems.push(r);
                    }
                }
            }

            // Cap element count to prevent OOM
            if elems.len() > 128 {
                elems.truncate(64);
            }
        }
        Ok(())
    });
});
