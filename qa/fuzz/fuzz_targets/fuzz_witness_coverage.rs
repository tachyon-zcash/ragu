//! Witness-inspection coverage augmentation POC.
//!
//! Same `Element` / `Boolean` operation dispatch as `fuzz_element_ops`, but
//! with an added coverage-augmentation step at the end of each successful
//! simulation: the final witness state (element values + boolean values) is
//! hashed and the hash is "spread" across branches that SanitizerCoverage's
//! PC-guard instrumentation tracks as edges. The intent is to bias libFuzzer
//! toward exploring distinct *internal witness states* even when the
//! `Simulator`'s Rust-level branches don't differ between inputs.
//!
//! # Why
//!
//! libFuzzer's coverage feedback is edge-based: it tracks which branches
//! the target binary took. The `Simulator` is a Rust interpreter, so it
//! has plenty of native branches (one per `Op` arm, plus error paths
//! inside each gadget), and libFuzzer naturally explores them. But two
//! inputs can take the *same* Rust branches in the simulator and still
//! produce structurally different witnesses — different `is_zero` results,
//! different `ConditionalSelect` outcomes, different element values
//! flowing through downstream ops — that the fuzzer doesn't distinguish.
//!
//! This target augments coverage with a witness-state fingerprint: at the
//! end of each successful simulation, the final element- and boolean-
//! value vectors are hashed to a `u64`, and each set bit of that hash is
//! used to fire a distinct `if` branch under `black_box`. libFuzzer's
//! PC-guard instrumentation then sees those branches as separate edges,
//! and combinations of set bits become new coverage. The fuzzer biases
//! mutation toward inputs that produce previously-unseen witness states.
//!
//! # Comparison protocol
//!
//! Run `fuzz_element_ops` and `fuzz_witness_coverage` for the same wall-
//! clock budget on empty corpora. Compare libFuzzer's reported `cov`
//! (edges), `ft` (features), and especially **corpus size** (saved inputs
//! that triggered new coverage). The augmentation is valuable if the
//! corpus grows faster or the explored input space is more diverse.
//!
//! The augmentation costs ~28% throughput in measured runs (extra hashing
//! plus the 64-branch coverage spray per iteration). It is kept opt-in as
//! a separate target rather than applied to all targets so users can
//! choose the trade-off per campaign.

#![no_main]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::hint::black_box;

use arbitrary::Arbitrary;
use ff::Field;
use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Boolean, Element, Simulator, allocator::Standard};

fn special_value(idx: u8) -> Fp {
    match idx % 16 {
        0 => Fp::ZERO,
        1 => Fp::ONE,
        2 => -Fp::ONE,
        3 => -Fp::from(2),
        4 => Fp::TWO_INV,
        5 => Fp::from(2),
        6 => Fp::from(3),
        7 => Fp::from(7),
        8 => Fp::ROOT_OF_UNITY,
        9 => Fp::ROOT_OF_UNITY.square(),
        10 => Fp::ROOT_OF_UNITY.pow_vartime([4u64]),
        11 => Fp::MULTIPLICATIVE_GENERATOR,
        12 => Fp::MULTIPLICATIVE_GENERATOR.square(),
        13 => Fp::from(1u64 << 32),
        14 => Fp::from(1u64 << 48),
        _ => Fp::from(u64::MAX),
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
    Divide(u8, u8),
    Scale(u8, u64),
    Fold(u8, u8, u64),
    AllocConst(u64),
    AllocSpecial(u8),
    AllocSquare(u64),
    /// Allocate an `Element` whose value is the 32-byte chunk interpreted
    /// as a canonical `Fp` (via `Fp::from_repr`). Lets libFuzzer's
    /// dictionary entries land directly in the witness without going
    /// through the `Arbitrary` `u64`-seed reinterpretation.
    AllocRaw([u8; 32]),
    BoolAlloc(bool),
    BoolNot(u8),
    BoolAnd(u8, u8),
    ConditionalSelect(u8, u8, u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    seeds: [u64; 4],
    large_seeds: [[u64; 4]; 2],
    special_seeds: [u8; 2],
    constant_mask: u8,
    ops: Vec<Op>,
}

/// Hash the final witness state into a single u64.
///
/// Field elements are serialized via `to_repr()` (canonical byte form);
/// booleans are hashed as a `Vec<bool>`. Uses `DefaultHasher` because
/// adversarial hash resistance isn't needed — we only need different
/// witnesses to produce different hashes with overwhelming probability.
fn hash_witness(elems: &[Fp], bools: &[bool]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for fp_val in elems {
        fp_val.to_repr().as_ref().hash(&mut hasher);
    }
    bools.hash(&mut hasher);
    hasher.finish()
}

/// Spread the witness fingerprint across distinct branches that
/// SanitizerCoverage's PC-guard instrumentation tracks as separate edges.
///
/// Each set bit of the hash fires a `black_box(i)` call inside its own
/// `if` arm. Different fingerprints → different combinations of branches
/// taken → libFuzzer perceives new coverage and biases mutation toward
/// inputs that produce previously-unseen witness states.
///
/// `black_box` prevents the compiler from constant-folding the loop body
/// away. The cost is 64 conditional branches per successful run, which is
/// negligible compared to the simulator's overhead.
#[inline(never)]
fn feed_witness_coverage(fingerprint: u64) {
    for i in 0..64 {
        if (fingerprint >> i) & 1 == 1 {
            black_box(i);
        }
    }
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
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
        let allocator = &mut Standard::new();
        let mut elems: Vec<Element<'_, _>> = (0..fes.len())
            .map(|i| {
                if input.constant_mask & (1 << (i % 8)) != 0 {
                    Ok(Element::constant(dr, fes[i]))
                } else {
                    Element::alloc(dr, allocator, witness.as_ref().map(|v| v[i]))
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
                    if let Ok(b) = elems[a].is_zero(dr, allocator) {
                        bools.push(b);
                    }
                }
                Op::Divide(a, b) => {
                    let (a, b) = (a as usize % elen, b as usize % elen);
                    if let Ok(b_nz) = elems[b].clone().enforce_nonzero(dr)
                        && let Ok(r) = elems[a].divide(dr, &b_nz)
                    {
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
                    let scale = Element::alloc(dr, allocator, witness.as_ref().map(|_| Fp::from(s)))?;
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
                    let r = Element::alloc(dr, allocator, witness.as_ref().map(|_| v))?;
                    elems.push(r);
                }
                Op::AllocRaw(bytes) => {
                    let v: Option<Fp> = Fp::from_repr(bytes).into();
                    if let Some(fp) = v {
                        if let Ok(r) =
                            Element::alloc(dr, allocator, witness.as_ref().map(|_| fp))
                        {
                            elems.push(r);
                        }
                    }
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
                    if let Ok(b) = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| v)) {
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

        // Augmentation: hash the final witness state and feed it to
        // libFuzzer's coverage tracker via the branch-on-hash trick.
        let elem_vals: Vec<Fp> = elems.iter().map(|e| *e.value().take()).collect();
        let bool_vals: Vec<bool> = bools.iter().map(|b| b.value().take()).collect();
        let hash = hash_witness(&elem_vals, &bool_vals);
        feed_witness_coverage(hash);

        Ok(())
    });
});
