//! Driver-vs-driver metamorphic fuzz target.
//!
//! Runs the same `Vec<Op>` instruction stream through two `Driver`
//! implementations — `Simulator` and `Emulator<Wired<Fp>>` — and compares
//! the resulting final element-value sequences. Tests the load-bearing
//! invariant that the model driver (which asserts `a*b = c` and
//! `enforce_zero(lc) = 0` inline) and the witness-extraction driver that
//! the synthesis pipeline builds on top of (`Emulator`, used internally by
//! `trace::eval`) process the same gadget code observationally identically.
//!
//! # Oracle
//!
//! After running the same instruction stream through both drivers:
//!
//! - `(Simulator: Ok, Emulator: Ok)` → both succeeded; compare final
//!   element values. Any divergence → **bug** (the two drivers disagree on
//!   what the witness's internal wire values are).
//! - `(Simulator: Err, Emulator: Ok)` → expected: a witness invalid by
//!   `Simulator`'s constraint check would be silently accepted by
//!   `Emulator`, which does not enforce gate equations. Discard.
//! - `(Simulator: Ok, Emulator: Err)` → **bug**: `Simulator` accepted but
//!   `Emulator` couldn't even produce a wire. Would mean a gadget-internal
//!   error path triggered only in `Emulator`, which should be impossible
//!   under the shared gadget code.
//! - `(Simulator: Err, Emulator: Err)` → consistent rejection (e.g. both
//!   hit `Element::invert(0)` or similar gadget-level error). Discard.
//!
//! # What this catches
//!
//! - Subtle differences in how `Simulator::gate` and `Emulator::gate`
//!   handle the same witness closure.
//! - Divergent behavior in `Driver::routine` between the two drivers
//!   (`Simulator::routine` calls `Emulator::predict` internally, then
//!   `routine.execute(self, ...)` — the predict-then-execute split could
//!   diverge if either side has a bug).
//! - Any gadget code that branches on driver type (which it shouldn't, but
//!   this is the load-bearing invariant the test enforces).
//!
//! # What this doesn't catch
//!
//! - Bugs in `trace::eval`'s segment-grouping logic (positional metadata,
//!   not wire values).
//! - Bugs in the trace-polynomial assembly, constraint polynomial emission
//!   (`WiringObject`), or downstream prover/verifier components.
//! - Soundness gaps in the constraint system itself
//!   (`fuzz_soundness_cheat`'s lane).

#![no_main]

use core::cell::RefCell;

use arbitrary::Arbitrary;
use ff::Field;
use ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    drivers::{
        Driver,
        emulator::{Emulator, Wired},
    },
    maybe::{Always, Maybe},
};
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

#[derive(Arbitrary, Debug, Clone, Copy)]
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
    /// Allocate an `Element` whose value is the 32-byte chunk interpreted
    /// as a canonical `Fp` (via `Fp::from_repr`). Lets libFuzzer's
    /// dictionary entries land directly in the witness.
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

/// Final-state fingerprint: every element's value followed by every
/// boolean's value, in stack order.
type Fingerprint = (Vec<Fp>, Vec<bool>);

fn build_seeds(input: &Input) -> Vec<Fp> {
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
    fes
}

/// Generic instruction-stream driver harness.
///
/// Runs the input's `Vec<Op>` against the supplied driver and witness,
/// returning the final stack snapshot. Identical dispatch logic to
/// `fuzz_element_ops` and `fuzz_soundness_cheat`, so the same gadget
/// API surface is exercised in all three targets.
fn run_ops<'dr, D>(
    dr: &mut D,
    witness: &Always<Vec<Fp>>,
    input: &Input,
    fes: &[Fp],
) -> Result<Fingerprint>
where
    D: Driver<'dr, F = Fp, MaybeKind = Always<()>>,
{
    let allocator = &mut Standard::new();
    let mut elems: Vec<Element<'_, D>> = (0..fes.len())
        .map(|i| {
            if input.constant_mask & (1 << (i % 8)) != 0 {
                Ok(Element::constant(dr, fes[i]))
            } else {
                Element::alloc(dr, allocator, witness.as_ref().map(|v| v[i]))
            }
        })
        .collect::<Result<_>>()?;
    let mut bools: Vec<Boolean<'_, D>> = Vec::new();

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

    let elem_vals: Vec<Fp> = elems.iter().map(|e| *e.value().take()).collect();
    let bool_vals: Vec<bool> = bools.iter().map(|b| b.value().take()).collect();
    Ok((elem_vals, bool_vals))
}

/// Run the program through `Simulator`, capturing the final fingerprint
/// on success.
fn run_simulator(input: &Input, fes: &[Fp]) -> Option<Fingerprint> {
    let snapshot: RefCell<Option<Fingerprint>> = RefCell::new(None);
    let sim = Simulator::<Fp>::simulate(fes.to_vec(), |dr, witness| {
        let fp = run_ops(dr, &witness, input, fes)?;
        *snapshot.borrow_mut() = Some(fp);
        Ok(())
    });
    if sim.is_err() {
        return None;
    }
    snapshot.into_inner()
}

/// Run the program through `Emulator<Wired<Fp>>`, capturing the final
/// fingerprint on success.
fn run_emulator(input: &Input, fes: &[Fp]) -> Option<Fingerprint> {
    let snapshot: RefCell<Option<Fingerprint>> = RefCell::new(None);
    let result = Emulator::<Wired<Fp>>::emulate_wired(fes.to_vec(), |dr, witness| {
        let fp = run_ops(dr, &witness, input, fes)?;
        *snapshot.borrow_mut() = Some(fp);
        Ok(())
    });
    if result.is_err() {
        return None;
    }
    snapshot.into_inner()
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

    let fes = build_seeds(&input);

    let sim = run_simulator(&input, &fes);
    let emu = run_emulator(&input, &fes);

    match (&sim, &emu) {
        (None, _) => {
            // Simulator rejected. Discard regardless of what Emulator did:
            // (None, None) is consistent rejection, (None, Some(_)) is the
            // expected case where Simulator's stricter constraint enforcement
            // catches something Emulator silently accepts.
        }
        (Some(_), None) => {
            // Simulator accepted but Emulator failed. Both drivers run the
            // same gadget code with the same witness; the Emulator does
            // *less* enforcement than Simulator, so any gadget-internal Err
            // it hits should also have triggered for Simulator. This is a
            // bug.
            panic!(
                "driver divergence: Simulator accepted, Emulator rejected. Input: {:?}",
                input,
            );
        }
        (Some(s), Some(e)) => {
            // Both drivers ran successfully. The same gadget code with the
            // same witness must produce the same wire values; any
            // disagreement is a model-vs-real driver divergence.
            assert!(
                s == e,
                "driver divergence: Simulator and Emulator produced different \
                 final fingerprints from the same Vec<Op> and witness. \
                 sim={:?}, emu={:?}, input={:?}",
                s,
                e,
                input,
            );
        }
    }
});
