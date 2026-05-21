//! Soundness fuzz target via mid-stream witness cheating.
//!
//! Runs the same instruction stream twice through the `Simulator`: an
//! honest path and a cheat path that, at a fuzzer-chosen point, replaces
//! one element on the stack with a fresh allocation whose value differs
//! from the honest one. After both runs complete, the final element and
//! boolean values are compared.
//!
//! # Why this is the witness-mutation pattern, adapted to Ragu
//!
//! Ragu's `Simulator` checks witness satisfaction inline with synthesis:
//! wires are field values, not indexed slots in a matrix, and there is no
//! `prove(witness)` entry that takes an externally-supplied witness
//! vector. The paper's "mutate slot s, re-prove, observe verifier" pattern
//! translates here to "intercept the value flowing through a gadget,
//! continue the simulation, observe whether the discrepancy is caught."
//! The Simulator's `Ok` is a sound proxy for verifier acceptance under
//! the model-vs-real-driver equivalence assumption that the rest of the
//! crate depends on.

#![no_main]

use core::cell::RefCell;

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

/// How the cheat replaces an element.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum CheatFlavor {
    /// Fresh witness allocation with an arbitrary value. Severs all
    /// constraint history of the previous occupant of this slot.
    Alloc(u64),
    /// Replace with a constant. Severs constraint history and locks the
    /// new value into a constant path.
    Constant(u64),
    /// Fresh witness allocation with a special field value (0, 1, p-1,
    /// roots of unity, generators, …).
    Special(u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    seeds: [u64; 4],
    large_seeds: [[u64; 4]; 2],
    special_seeds: [u8; 2],
    constant_mask: u8,
    ops: Vec<Op>,
    /// Index into `ops` at which to apply the cheat. The cheat replaces
    /// `elems[target_idx]` *before* `ops[cheat_at]` is executed.
    cheat_at: u16,
    /// Index (mod current stack length) of the slot to replace.
    target_idx: u8,
    cheat: CheatFlavor,
}

/// Final-state fingerprint: every element's value followed by every
/// boolean's value, in stack order.
type Fingerprint = (Vec<Fp>, Vec<bool>);

/// Build the initial seed elements identical to fuzz_element_ops.
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

/// Execute the program (with or without the cheat) and return the final
/// fingerprint if the Simulator accepted.
///
/// Returns `None` if the simulator rejected, or if `apply_cheat` was true
/// but the chosen cheat value coincided with the slot's existing value
/// (a degenerate input that would produce a false-positive fingerprint
/// match).
fn run_path(input: &Input, fes: &[Fp], apply_cheat: bool) -> Option<Fingerprint> {
    let snapshot: RefCell<Option<Fingerprint>> = RefCell::new(None);
    let cheat_noop: RefCell<bool> = RefCell::new(false);

    let sim = Simulator::<Fp>::simulate(fes.to_vec(), |dr, witness| {
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

        for (i, op) in input.ops.iter().enumerate() {
            // Apply the cheat *before* executing ops[cheat_at]. We
            // require a non-empty elems stack, otherwise there is
            // nothing to cheat on and the test is degenerate.
            //
            // Clamp the target to indices < 64 so the cheated element
            // survives any future `elems.truncate(64)` call. Otherwise
            // the cheat can be dropped from the stack mid-run, removing
            // it from the final fingerprint and producing a false-
            // positive match.
            if apply_cheat && i == input.cheat_at as usize && !elems.is_empty() {
                let target = (input.target_idx as usize) % elems.len().min(64);
                let original_val: Fp = *elems[target].value().take();
                let cheat_val = match input.cheat {
                    CheatFlavor::Alloc(v) => Fp::from(v),
                    CheatFlavor::Constant(v) => Fp::from(v),
                    CheatFlavor::Special(idx) => special_value(idx),
                };
                if original_val == cheat_val {
                    // No actual cheat — the chosen replacement value
                    // happens to equal what was already there. Fingerprints
                    // would trivially match. Flag and bail out so the
                    // outer harness discards this run.
                    *cheat_noop.borrow_mut() = true;
                    return Ok(());
                }
                let cheated = match input.cheat {
                    CheatFlavor::Alloc(_) | CheatFlavor::Special(_) => Element::alloc(
                        dr,
                        allocator,
                        witness.as_ref().map(|_| cheat_val),
                    )?,
                    CheatFlavor::Constant(_) => Element::constant(dr, cheat_val),
                };
                elems[target] = cheated;
            }

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
                    let scale = Element::alloc(
                        dr,
                        allocator,
                        witness.as_ref().map(|_| Fp::from(s)),
                    )?;
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
                    if let Ok(b) = Boolean::alloc(
                        dr,
                        allocator,
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

        // Capture the final stack state. Element::value and Boolean::value
        // are infallible under the Simulator driver because its MaybeKind
        // is Always.
        let elem_vals: Vec<Fp> = elems.iter().map(|e| *e.value().take()).collect();
        let bool_vals: Vec<bool> = bools.iter().map(|b| b.value().take()).collect();
        *snapshot.borrow_mut() = Some((elem_vals, bool_vals));

        Ok(())
    });

    if sim.is_err() || *cheat_noop.borrow() {
        return None;
    }
    snapshot.into_inner()
}

/// How many elements an Op pushes onto the `elems` stack.
///
/// Used by the TRIAGE_CHEAT path to walk the op stream without actually
/// running the Simulator. Assumes Result-returning ops succeed (worst
/// case for "did the cheat propagate" — gives an upper bound).
fn op_pushes(op: &Op) -> usize {
    match op {
        Op::AllocSquare(_) => 2,
        Op::IsZero(_) | Op::BoolAlloc(_) | Op::BoolNot(_) | Op::BoolAnd(_, _) => 0,
        _ => 1,
    }
}

/// Whether an Op reads `elems[target]` (given the current elem stack length).
fn op_reads_target(op: &Op, target: usize, elens: usize) -> bool {
    if elens == 0 {
        return false;
    }
    let resolves = |a: u8| (a as usize) % elens == target;
    match op {
        Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) | Op::DivNonzero(a, b)
        | Op::Fold(a, b, _) => resolves(*a) || resolves(*b),
        Op::ConditionalSelect(_, a, b) => resolves(*a) || resolves(*b),
        Op::Scale(a, _) | Op::Square(a) | Op::Double(a) | Op::Negate(a)
        | Op::Invert(a) | Op::IsZero(a) => resolves(*a),
        _ => false,
    }
}

/// Triage helper: simulate stack growth through the op stream without
/// invoking the Simulator. Returns `(target_at_cheat, downstream_reads,
/// downstream_ops)` describing how many downstream ops actually reference
/// the cheated slot. A `downstream_reads = 0` result indicates a "dead
/// cheat" — the soundness signal is a false positive.
fn triage_cheat(input: &Input) -> (usize, usize, usize) {
    let mut elens: usize = input.seeds.len() + input.large_seeds.len() + input.special_seeds.len();
    let cheat_at_idx = (input.cheat_at as usize).min(input.ops.len());

    // Walk pre-cheat ops to compute elens at cheat time.
    for op in &input.ops[..cheat_at_idx] {
        if elens == 0 {
            return (0, 0, 0);
        }
        elens += op_pushes(op);
        if elens > 128 {
            elens = 64;
        }
    }

    if elens == 0 {
        return (0, 0, 0);
    }

    let target_at_cheat = (input.target_idx as usize) % elens.min(64);

    let mut downstream_reads = 0usize;
    let mut downstream_ops = 0usize;
    for op in &input.ops[cheat_at_idx..] {
        if elens == 0 {
            break;
        }
        downstream_ops += 1;
        if op_reads_target(op, target_at_cheat, elens) {
            downstream_reads += 1;
        }
        elens += op_pushes(op);
        if elens > 128 {
            elens = 64;
        }
    }

    (target_at_cheat, downstream_reads, downstream_ops)
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    // TRIAGE_CHEAT=1 walks the op stream tracking the cheated slot and
    // reports how many downstream ops reference it. A 0 count means
    // "dead cheat" — the soundness signal is a false positive.
    if std::env::var("TRIAGE_CHEAT").is_ok() {
        let (target_at_cheat, downstream_reads, downstream_ops) = triage_cheat(&input);
        eprintln!(
            "cheat_at = {}\n\
             target_idx = {} → target_at_cheat = {}\n\
             cheat flavor = {:?}\n\
             downstream ops = {}\n\
             downstream reads of cheated slot = {}",
            input.cheat_at,
            input.target_idx,
            target_at_cheat,
            input.cheat,
            downstream_ops,
            downstream_reads,
        );
        if downstream_reads == 0 {
            eprintln!(
                "\nVERDICT: DEAD CHEAT — cheated slot was never read after the \
                 cheat fired. The fingerprint match is structurally trivial; \
                 this is almost certainly a false-positive soundness signal."
            );
        } else {
            eprintln!(
                "\nVERDICT: LIVE CHEAT — cheated slot was read {} times \
                 downstream. If `cargo +nightly fuzz run fuzz_soundness_cheat \
                 <file>` confirms the panic, the gadget on that read path \
                 is plausibly under-constrained.",
                downstream_reads,
            );
        }
        return;
    }
    // Bound program length to keep iterations fast and avoid the truncation
    // path dominating coverage.
    if input.ops.is_empty() || input.ops.len() > 48 {
        return;
    }
    // Cheat must land inside the executable op range, otherwise the cheat
    // is a no-op and fingerprints trivially match.
    if (input.cheat_at as usize) >= input.ops.len() {
        return;
    }

    let fes = build_seeds(&input);

    let honest = match run_path(&input, &fes, false) {
        Some(f) => f,
        None => return,
    };
    let cheated = match run_path(&input, &fes, true) {
        Some(f) => f,
        None => return,
    };

    // Soundness signal: cheat path accepted by Simulator AND its final
    // state is observationally identical to the honest run.
    assert!(
        honest != cheated,
        "soundness signal: cheat at op[{}] target {} flavor {:?} \
         did not perturb the final state; \
         every downstream constraint and observation was insensitive to \
         the swap. Suspect an under-constrained gadget. \
         Input: {:?}",
        input.cheat_at,
        input.target_idx,
        input.cheat,
        input,
    );
});
