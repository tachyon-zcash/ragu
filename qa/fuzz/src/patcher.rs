use ff::{Field, PrimeField};
use pasta_curves::Fp;

pub type PatchFingerprint = (Vec<Fp>, Vec<bool>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchOp {
    Add(u8, u8),
    Sub(u8, u8),
    Mul(u8, u8),
    Square(u8),
    Double(u8),
    Negate(u8),
    Invert(u8),
    IsZero(u8),
    DivNonzero(u8, u8),
    Scale(u8, Fp),
    Fold(u8, u8, Fp),
    AllocConst(Fp),
    AllocWitness(Fp),
    AllocSquare(Fp),
    AllocRaw(Option<Fp>),
    BoolAlloc(bool),
    BoolNot(u8),
    BoolAnd(u8, u8),
    ConditionalSelect(u8, u8, u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatchPlan {
    pub final_elems: Vec<Fp>,
    pub final_bools: Vec<bool>,
    pub exclude_elems: Vec<bool>,
    pub exclude_bools: Vec<bool>,
    pub replacements: Vec<Vec<(usize, Fp)>>,
    pub repaired_ops: usize,
}

impl PatchPlan {
    pub fn final_fingerprint(&self) -> PatchFingerprint {
        (self.final_elems.clone(), self.final_bools.clone())
    }

    pub fn observable_fingerprint(&self, fingerprint: &PatchFingerprint) -> PatchFingerprint {
        observable_fingerprint(fingerprint, &self.exclude_elems, &self.exclude_bools)
    }

    pub fn observable_len(&self) -> usize {
        self.exclude_elems
            .iter()
            .filter(|exclude| !**exclude)
            .count()
            + self
                .exclude_bools
                .iter()
                .filter(|exclude| !**exclude)
                .count()
    }

    pub fn observable_elem_indices(&self) -> Vec<usize> {
        self.exclude_elems
            .iter()
            .enumerate()
            .filter_map(|(idx, exclude)| (!exclude).then_some(idx))
            .collect()
    }
}

pub fn observable_fingerprint(
    fingerprint: &PatchFingerprint,
    exclude_elems: &[bool],
    exclude_bools: &[bool],
) -> PatchFingerprint {
    let elems = fingerprint
        .0
        .iter()
        .zip(exclude_elems)
        .filter_map(|(value, exclude)| (!exclude).then_some(*value))
        .collect();
    let bools = fingerprint
        .1
        .iter()
        .zip(exclude_bools)
        .filter_map(|(value, exclude)| (!exclude).then_some(*value))
        .collect();
    (elems, bools)
}

pub fn build_patch_plan(
    seeds: &[Fp],
    ops: &[PatchOp],
    cheat_at: usize,
    target_idx: u8,
    cheat_value: Fp,
) -> Option<PatchPlan> {
    if seeds.is_empty() || cheat_at >= ops.len() {
        return None;
    }

    let mut honest = PatchState::new(seeds);
    let mut honest_pre_states = Vec::with_capacity(ops.len());
    for op in ops {
        honest_pre_states.push(honest.snapshot());
        let effect = eval_effect(op, &honest.elems, &honest.bools);
        honest.apply(effect);
    }

    let mut patched = PatchState::new(seeds);
    let mut replacements = vec![Vec::new(); ops.len()];
    let mut repaired_ops = 0usize;
    let mut direct_target = None;
    let mut patchable_from = usize::MAX;

    for (op_idx, op) in ops.iter().enumerate() {
        if patched.elems.is_empty() {
            return None;
        }

        if op_idx == cheat_at {
            let target = (target_idx as usize) % patched.elems.len().min(64);
            if patched.elems[target] == cheat_value {
                return None;
            }
            patched.elems[target] = cheat_value;
            patched.exclude_elems[target] = true;
            direct_target = Some(target);
            patchable_from = patched.elems.len();
        }

        if let Some(target) = direct_target {
            let (honest_elems, honest_bools) = &honest_pre_states[op_idx];
            if repair_op(
                op,
                honest_elems,
                honest_bools,
                &mut patched,
                target,
                patchable_from,
                &mut replacements[op_idx],
            ) {
                repaired_ops += 1;
            }
        }

        let effect = eval_effect(op, &patched.elems, &patched.bools);
        if patched.apply(effect) && direct_target.is_some() {
            patchable_from = patchable_from.min(64);
        }
    }

    Some(PatchPlan {
        final_elems: patched.elems,
        final_bools: patched.bools,
        exclude_elems: patched.exclude_elems,
        exclude_bools: patched.exclude_bools,
        replacements,
        repaired_ops,
    })
}

#[derive(Clone, Debug)]
struct PatchState {
    elems: Vec<Fp>,
    bools: Vec<bool>,
    exclude_elems: Vec<bool>,
    exclude_bools: Vec<bool>,
}

impl PatchState {
    fn new(seeds: &[Fp]) -> Self {
        Self {
            elems: seeds.to_vec(),
            bools: Vec::new(),
            exclude_elems: vec![false; seeds.len()],
            exclude_bools: Vec::new(),
        }
    }

    fn snapshot(&self) -> (Vec<Fp>, Vec<bool>) {
        (self.elems.clone(), self.bools.clone())
    }

    fn apply(&mut self, effect: PatchEffect) -> bool {
        self.elems.extend(effect.elems);
        self.exclude_elems.extend(core::iter::repeat_n(
            false,
            self.elems.len() - self.exclude_elems.len(),
        ));
        self.bools.extend(effect.bools);
        self.exclude_bools.extend(core::iter::repeat_n(
            false,
            self.bools.len() - self.exclude_bools.len(),
        ));

        let mut truncated = false;
        if self.elems.len() > 128 {
            self.elems.truncate(64);
            self.exclude_elems.truncate(64);
            truncated = true;
        }
        if self.bools.len() > 64 {
            self.bools.truncate(32);
            self.exclude_bools.truncate(32);
        }

        truncated
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PatchEffect {
    elems: Vec<Fp>,
    bools: Vec<bool>,
}

fn elem_index(raw: u8, len: usize) -> usize {
    raw as usize % len
}

fn bool_index(raw: u8, len: usize) -> usize {
    raw as usize % len
}

fn eval_effect(op: &PatchOp, elems: &[Fp], bools: &[bool]) -> PatchEffect {
    if elems.is_empty() {
        return PatchEffect::default();
    }

    let mut effect = PatchEffect::default();
    match *op {
        PatchOp::Add(a, b) => {
            let (a, b) = (elem_index(a, elems.len()), elem_index(b, elems.len()));
            effect.elems.push(elems[a] + elems[b]);
        }
        PatchOp::Sub(a, b) => {
            let (a, b) = (elem_index(a, elems.len()), elem_index(b, elems.len()));
            effect.elems.push(elems[a] - elems[b]);
        }
        PatchOp::Mul(a, b) => {
            let (a, b) = (elem_index(a, elems.len()), elem_index(b, elems.len()));
            effect.elems.push(elems[a] * elems[b]);
        }
        PatchOp::Square(a) => {
            let a = elem_index(a, elems.len());
            effect.elems.push(elems[a].square());
        }
        PatchOp::Double(a) => {
            let a = elem_index(a, elems.len());
            effect.elems.push(elems[a].double());
        }
        PatchOp::Negate(a) => {
            let a = elem_index(a, elems.len());
            effect.elems.push(-elems[a]);
        }
        PatchOp::Invert(a) => {
            let a = elem_index(a, elems.len());
            if let Some(inv) = elems[a].invert().into_option() {
                effect.elems.push(inv);
            }
        }
        PatchOp::IsZero(a) => {
            let a = elem_index(a, elems.len());
            effect.bools.push(elems[a] == Fp::ZERO);
        }
        PatchOp::DivNonzero(a, b) => {
            let (a, b) = (elem_index(a, elems.len()), elem_index(b, elems.len()));
            if let Some(b_inv) = elems[b].invert().into_option() {
                effect.elems.push(elems[a] * b_inv);
            }
        }
        PatchOp::Scale(a, c) => {
            let a = elem_index(a, elems.len());
            effect.elems.push(elems[a] * c);
        }
        PatchOp::Fold(a, b, s) => {
            let (a, b) = (elem_index(a, elems.len()), elem_index(b, elems.len()));
            effect.elems.push(elems[a] * s + elems[b]);
        }
        PatchOp::AllocConst(v) | PatchOp::AllocWitness(v) => {
            effect.elems.push(v);
        }
        PatchOp::AllocSquare(v) => {
            effect.elems.push(v);
            effect.elems.push(v.square());
        }
        PatchOp::AllocRaw(v) => {
            if let Some(v) = v {
                effect.elems.push(v);
            }
        }
        PatchOp::BoolAlloc(v) => {
            effect.bools.push(v);
        }
        PatchOp::BoolNot(a) => {
            if !bools.is_empty() {
                let a = bool_index(a, bools.len());
                effect.bools.push(!bools[a]);
            }
        }
        PatchOp::BoolAnd(a, b) => {
            if !bools.is_empty() {
                let (a, b) = (bool_index(a, bools.len()), bool_index(b, bools.len()));
                effect.bools.push(bools[a] & bools[b]);
            }
        }
        PatchOp::ConditionalSelect(cond, a, b) => {
            if !bools.is_empty() {
                let cond = bool_index(cond, bools.len());
                let (a, b) = (elem_index(a, elems.len()), elem_index(b, elems.len()));
                effect
                    .elems
                    .push(if bools[cond] { elems[b] } else { elems[a] });
            }
        }
    }

    effect
}

fn repair_op(
    op: &PatchOp,
    honest_elems: &[Fp],
    honest_bools: &[bool],
    state: &mut PatchState,
    direct_target: usize,
    patchable_from: usize,
    replacements: &mut Vec<(usize, Fp)>,
) -> bool {
    let honest_effect = eval_effect(op, honest_elems, honest_bools);
    let current_effect = eval_effect(op, &state.elems, &state.bools);
    if current_effect == honest_effect {
        return false;
    }

    let Some(&honest_output) = honest_effect.elems.first() else {
        return repair_bool_op(
            op,
            honest_effect.bools.first().copied(),
            state,
            direct_target,
            patchable_from,
            replacements,
        );
    };

    match *op {
        PatchOp::Add(a, b) => {
            let (a, b) = (
                elem_index(a, state.elems.len()),
                elem_index(b, state.elems.len()),
            );
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                a,
                honest_output - state.elems[b],
            ) || patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                b,
                honest_output - state.elems[a],
            )
        }
        PatchOp::Sub(a, b) => {
            let (a, b) = (
                elem_index(a, state.elems.len()),
                elem_index(b, state.elems.len()),
            );
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                a,
                honest_output + state.elems[b],
            ) || patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                b,
                state.elems[a] - honest_output,
            )
        }
        PatchOp::Mul(a, b) => {
            let (a, b) = (
                elem_index(a, state.elems.len()),
                elem_index(b, state.elems.len()),
            );
            if let Some(b_inv) = state.elems[b].invert().into_option() {
                if patch_elem(
                    state,
                    direct_target,
                    patchable_from,
                    replacements,
                    a,
                    honest_output * b_inv,
                ) {
                    return true;
                }
            }
            if let Some(a_inv) = state.elems[a].invert().into_option() {
                if patch_elem(
                    state,
                    direct_target,
                    patchable_from,
                    replacements,
                    b,
                    honest_output * a_inv,
                ) {
                    return true;
                }
            }
            false
        }
        PatchOp::Square(a) => {
            let a = elem_index(a, state.elems.len());
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                a,
                honest_elems[a],
            )
        }
        PatchOp::Double(a) => {
            let a = elem_index(a, state.elems.len());
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                a,
                honest_output * Fp::TWO_INV,
            )
        }
        PatchOp::Negate(a) => {
            let a = elem_index(a, state.elems.len());
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                a,
                -honest_output,
            )
        }
        PatchOp::Invert(a) => {
            let a = elem_index(a, state.elems.len());
            honest_output.invert().into_option().is_some_and(|input| {
                patch_elem(state, direct_target, patchable_from, replacements, a, input)
            })
        }
        PatchOp::DivNonzero(a, b) => {
            let (a, b) = (
                elem_index(a, state.elems.len()),
                elem_index(b, state.elems.len()),
            );
            if state.elems[b] != Fp::ZERO
                && patch_elem(
                    state,
                    direct_target,
                    patchable_from,
                    replacements,
                    a,
                    honest_output * state.elems[b],
                )
            {
                return true;
            }
            if let Some(out_inv) = honest_output.invert().into_option() {
                if patch_elem(
                    state,
                    direct_target,
                    patchable_from,
                    replacements,
                    b,
                    state.elems[a] * out_inv,
                ) {
                    return true;
                }
            }
            false
        }
        PatchOp::Scale(a, c) => {
            let a = elem_index(a, state.elems.len());
            c.invert().into_option().is_some_and(|c_inv| {
                patch_elem(
                    state,
                    direct_target,
                    patchable_from,
                    replacements,
                    a,
                    honest_output * c_inv,
                )
            })
        }
        PatchOp::Fold(a, b, s) => {
            let (a, b) = (
                elem_index(a, state.elems.len()),
                elem_index(b, state.elems.len()),
            );
            if let Some(s_inv) = s.invert().into_option() {
                if patch_elem(
                    state,
                    direct_target,
                    patchable_from,
                    replacements,
                    a,
                    (honest_output - state.elems[b]) * s_inv,
                ) {
                    return true;
                }
            }
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                b,
                honest_output - state.elems[a] * s,
            )
        }
        PatchOp::ConditionalSelect(cond, a, b) => {
            if state.bools.is_empty() {
                return false;
            }
            let cond = bool_index(cond, state.bools.len());
            let selected = if state.bools[cond] { b } else { a };
            let selected = elem_index(selected, state.elems.len());
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                selected,
                honest_output,
            )
        }
        _ => false,
    }
}

fn repair_bool_op(
    op: &PatchOp,
    honest_output: Option<bool>,
    state: &mut PatchState,
    direct_target: usize,
    patchable_from: usize,
    replacements: &mut Vec<(usize, Fp)>,
) -> bool {
    let Some(honest_output) = honest_output else {
        return false;
    };

    match *op {
        PatchOp::IsZero(a) => {
            let a = elem_index(a, state.elems.len());
            let replacement = if honest_output { Fp::ZERO } else { Fp::ONE };
            patch_elem(
                state,
                direct_target,
                patchable_from,
                replacements,
                a,
                replacement,
            )
        }
        _ => false,
    }
}

fn patch_elem(
    state: &mut PatchState,
    direct_target: usize,
    patchable_from: usize,
    replacements: &mut Vec<(usize, Fp)>,
    slot: usize,
    value: Fp,
) -> bool {
    if slot == direct_target || slot < patchable_from {
        return false;
    }

    state.elems[slot] = value;
    state.exclude_elems[slot] = true;
    replacements.push((slot, value));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visible(values: &[Fp], exclude: &[bool]) -> Vec<Fp> {
        values
            .iter()
            .zip(exclude)
            .filter_map(|(value, exclude)| (!exclude).then_some(*value))
            .collect()
    }

    #[test]
    fn repairs_mul_by_patching_downstream_sibling_and_preserves_output() {
        let seeds = [Fp::from(2), Fp::from(3)];
        let ops = [PatchOp::Add(0, 1), PatchOp::Mul(0, 2)];

        let plan = build_patch_plan(&seeds, &ops, 0, 0, Fp::from(5))
            .expect("non-degenerate cheat should produce a patch plan");

        assert_eq!(plan.repaired_ops, 1);
        assert_eq!(plan.final_elems[0], Fp::from(5));
        assert_eq!(plan.final_elems[1], Fp::from(3));
        assert_eq!(plan.final_elems[2] * Fp::from(5), Fp::from(10));
        assert_eq!(plan.final_elems[3], Fp::from(10));
        assert_eq!(plan.exclude_elems, vec![true, false, true, false]);
        assert_eq!(
            visible(&plan.final_elems, &plan.exclude_elems),
            vec![Fp::from(3), Fp::from(10)]
        );
    }

    #[test]
    fn does_not_repair_by_patching_preexisting_sibling() {
        let seeds = [Fp::from(2), Fp::from(3)];
        let ops = [PatchOp::Mul(0, 1)];

        let plan = build_patch_plan(&seeds, &ops, 0, 0, Fp::from(5))
            .expect("non-degenerate cheat should produce a patch plan");

        assert_eq!(plan.repaired_ops, 0);
        assert_eq!(
            plan.final_elems,
            vec![Fp::from(5), Fp::from(3), Fp::from(15)]
        );
        assert_eq!(plan.exclude_elems, vec![true, false, false]);
    }

    #[test]
    fn propagates_when_no_repair_is_available_for_direct_square() {
        let seeds = [Fp::from(2)];
        let ops = [PatchOp::Square(0)];

        let plan = build_patch_plan(&seeds, &ops, 0, 0, Fp::from(3))
            .expect("non-degenerate cheat should produce a patch plan");

        assert_eq!(plan.repaired_ops, 0);
        assert_eq!(plan.final_elems, vec![Fp::from(3), Fp::from(9)]);
        assert_eq!(plan.exclude_elems, vec![true, false]);
        assert_eq!(
            visible(&plan.final_elems, &plan.exclude_elems),
            vec![Fp::from(9)]
        );
    }

    #[test]
    fn rejects_noop_cheat() {
        let seeds = [Fp::from(2)];
        let ops = [PatchOp::Square(0)];

        assert_eq!(build_patch_plan(&seeds, &ops, 0, 0, Fp::from(2)), None);
    }

    #[test]
    fn reports_observable_element_slots() {
        let plan = PatchPlan {
            final_elems: vec![Fp::from(1), Fp::from(2), Fp::from(3)],
            final_bools: vec![true],
            exclude_elems: vec![true, false, false],
            exclude_bools: vec![false],
            replacements: Vec::new(),
            repaired_ops: 0,
        };

        assert_eq!(plan.observable_elem_indices(), vec![1, 2]);
    }
}
