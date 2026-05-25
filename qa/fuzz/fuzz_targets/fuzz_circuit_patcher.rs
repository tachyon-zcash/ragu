//! Fuzz-local circuit/output-boundary patcher target.
//!
//! This is the narrower follow-up to `fuzz_witness_cheat`: keep the
//! patcher policy in `qa/fuzz`, but run the repaired witness through a
//! real `Circuit::witness` implementation and compare a chosen public
//! output element rather than the whole final op stack.
//!
//! The circuit here is intentionally a dummy circuit local to this fuzz
//! target. It translates the same `Vec<Op>` abstraction used by
//! `fuzz_witness_cheat` into `Element` and `Boolean` gadget calls. The
//! fuzzer then runs three circuit witnesses:
//!
//! 1. honest witness;
//! 2. unpatched cheated witness;
//! 3. patched cheated witness.
//!
//! A signal fires only when the patched cheated witness is accepted and
//! produces the same selected public output as the honest witness, while
//! the unpatched cheat either rejects or produces a different output.

#![no_main]

use arbitrary::Arbitrary;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_circuits::{Circuit, CircuitExt, WithAux};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Boolean, Element, Simulator, allocator::Standard};
use ragu_testing_fuzz::patcher::{PatchOp, build_patch_plan};

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
    AllocRaw([u8; 32]),
    BoolAlloc(bool),
    BoolNot(u8),
    BoolAnd(u8, u8),
    ConditionalSelect(u8, u8, u8),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum CheatFlavor {
    Alloc(u64),
    Constant(u64),
    Special(u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    seeds: [u64; 4],
    large_seeds: [[u64; 4]; 2],
    special_seeds: [u8; 2],
    ops: Vec<Op>,
    cheat_at: u16,
    target_idx: u8,
    output_idx: u8,
    cheat: CheatFlavor,
}

fn cheat_value(cheat: CheatFlavor) -> Fp {
    match cheat {
        CheatFlavor::Alloc(v) | CheatFlavor::Constant(v) => Fp::from(v),
        CheatFlavor::Special(idx) => special_value(idx),
    }
}

fn patch_op(op: &Op) -> PatchOp {
    match *op {
        Op::Add(a, b) => PatchOp::Add(a, b),
        Op::Sub(a, b) => PatchOp::Sub(a, b),
        Op::Mul(a, b) => PatchOp::Mul(a, b),
        Op::Square(a) => PatchOp::Square(a),
        Op::Double(a) => PatchOp::Double(a),
        Op::Negate(a) => PatchOp::Negate(a),
        Op::Invert(a) => PatchOp::Invert(a),
        Op::IsZero(a) => PatchOp::IsZero(a),
        Op::DivNonzero(a, b) => PatchOp::DivNonzero(a, b),
        Op::Scale(a, c) => PatchOp::Scale(a, Fp::from(c)),
        Op::Fold(a, b, s) => PatchOp::Fold(a, b, Fp::from(s)),
        Op::AllocConst(v) => PatchOp::AllocConst(Fp::from(v)),
        Op::AllocSpecial(idx) => PatchOp::AllocWitness(special_value(idx)),
        Op::AllocSquare(v) => PatchOp::AllocSquare(Fp::from(v)),
        Op::AllocRaw(bytes) => PatchOp::AllocRaw(Fp::from_repr(bytes).into()),
        Op::BoolAlloc(v) => PatchOp::BoolAlloc(v),
        Op::BoolNot(a) => PatchOp::BoolNot(a),
        Op::BoolAnd(a, b) => PatchOp::BoolAnd(a, b),
        Op::ConditionalSelect(cond, a, b) => PatchOp::ConditionalSelect(cond, a, b),
    }
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunMode {
    Honest,
    Cheat,
    Patched,
}

#[derive(Clone, Debug)]
struct PatchCircuit {
    seed_len: usize,
    ops: Vec<Op>,
    mode: RunMode,
    cheat_at: usize,
    target_idx: u8,
    cheat: CheatFlavor,
    cheat_value: Fp,
    replacements: Vec<Vec<(usize, Fp)>>,
    output_idx: usize,
}

impl PatchCircuit {
    fn with_mode(&self, mode: RunMode) -> Self {
        Self {
            mode,
            ..self.clone()
        }
    }
}

impl Circuit<Fp> for PatchCircuit {
    type Instance<'source> = Fp;
    type Witness<'source> = Vec<Fp>;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let mut elems: Vec<Element<'_, _>> = (0..self.seed_len)
            .map(|seed_idx| Element::alloc(dr, allocator, witness.as_ref().map(|v| v[seed_idx])))
            .collect::<Result<_>>()?;
        let mut bools: Vec<Boolean<'_, _>> = Vec::new();

        for (op_idx, op) in self.ops.iter().enumerate() {
            if self.mode != RunMode::Honest && op_idx == self.cheat_at && !elems.is_empty() {
                let target = (self.target_idx as usize) % elems.len().min(64);
                let cheated = match self.cheat {
                    CheatFlavor::Alloc(_) | CheatFlavor::Special(_) => {
                        Element::alloc(dr, allocator, witness.as_ref().map(|_| self.cheat_value))?
                    }
                    CheatFlavor::Constant(_) => Element::constant(dr, self.cheat_value),
                };
                elems[target] = cheated;
            }

            if self.mode == RunMode::Patched {
                for &(slot, value) in self.replacements.get(op_idx).into_iter().flatten() {
                    if slot < elems.len() {
                        elems[slot] =
                            Element::alloc(dr, allocator, witness.as_ref().map(|_| value))?;
                    }
                }
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
                    let scale =
                        Element::alloc(dr, allocator, witness.as_ref().map(|_| Fp::from(s)))?;
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
                        if let Ok(r) = Element::alloc(dr, allocator, witness.as_ref().map(|_| fp)) {
                            elems.push(r);
                        }
                    }
                }
                Op::AllocSquare(v) => {
                    if let Ok((root, sq)) =
                        Element::alloc_square(dr, witness.as_ref().map(|_| Fp::from(v)))
                    {
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
                        if let Ok(r) = bools[cond].conditional_select(dr, &elems[a], &elems[b]) {
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

        let output = elems
            .get(self.output_idx)
            .cloned()
            .ok_or_else(|| Error::InvalidWitness("selected output slot missing".into()))?;
        Ok(WithAux::new(output, D::unit()))
    }
}

fn run_circuit(circuit: PatchCircuit, seeds: &[Fp]) -> Option<Fp> {
    let mut output = None;
    Simulator::<Fp>::simulate(seeds.to_vec(), |dr, witness| {
        let circuit_output = circuit.clone().witness(dr, witness)?.into_output();
        output = Some(*circuit_output.value().take());
        Ok(())
    })
    .ok()?;

    circuit.trace(seeds.to_vec()).ok()?;
    output
}

fuzz_target!(|input: Input| {
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    if input.ops.is_empty() || input.ops.len() > 48 {
        return;
    }

    let seeds = build_seeds(&input);
    let patch_ops: Vec<PatchOp> = input.ops.iter().map(patch_op).collect();
    let cheat_value = cheat_value(input.cheat);
    let patch_plan = match build_patch_plan(
        &seeds,
        &patch_ops,
        input.cheat_at as usize,
        input.target_idx,
        cheat_value,
    ) {
        Some(plan) if plan.repaired_ops > 0 => plan,
        _ => return,
    };

    let observable_elems = patch_plan.observable_elem_indices();
    if observable_elems.is_empty() {
        return;
    }
    let output_idx = observable_elems[input.output_idx as usize % observable_elems.len()];

    let base = PatchCircuit {
        seed_len: seeds.len(),
        ops: input.ops.clone(),
        mode: RunMode::Honest,
        cheat_at: input.cheat_at as usize,
        target_idx: input.target_idx,
        cheat: input.cheat,
        cheat_value,
        replacements: patch_plan.replacements.clone(),
        output_idx,
    };

    let honest_output = match run_circuit(base.with_mode(RunMode::Honest), &seeds) {
        Some(output) => output,
        None => return,
    };
    let unpatched_output = run_circuit(base.with_mode(RunMode::Cheat), &seeds);
    let patched_output = match run_circuit(base.with_mode(RunMode::Patched), &seeds) {
        Some(output) => output,
        None => return,
    };

    if patched_output != patch_plan.final_elems[output_idx] {
        return;
    }
    if unpatched_output == Some(honest_output) {
        return;
    }

    assert_ne!(
        honest_output,
        patched_output,
        "circuit patcher signal: op[{}] target {} output slot {} flavor {:?} \
         accepted after {} downstream repair(s); unpatched output {:?}; input: {:?}",
        input.cheat_at,
        input.target_idx,
        output_idx,
        input.cheat,
        patch_plan.repaired_ops,
        unpatched_output,
        input,
    );
});
