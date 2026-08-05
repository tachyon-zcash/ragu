//! What [`compute_v`](super::compute_v) does before its `f(u)` fold, on behalf
//! of poly-queries.
//!
//! Only the code is separated, not the constraint system: a query's obligation
//! is the quotient $(p(u) - y)/(u - x)$ *inside* that single fold. There is no
//! poly-query circuit to move this to.

use alloc::vec::Vec;
use core::array;

use ragu_arithmetic::Cycle;
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Boolean, Element, allocator::Allocator};

use super::super::stages::{eval as native_eval, preamble as native_preamble};
use crate::{framework_hooks::HookConfig, poly_commitment::HANDLE_WIRES};

/// In `[left, right]` order, matching the fold's trailing block.
pub(super) fn select_evaluations<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    A: Allocator<'dr, D>,
    const HEADER_SIZE: usize,
    J: HookConfig,
>(
    dr: &mut D,
    allocator: &mut A,
    eval: &native_eval::Output<'dr, D, J>,
    preamble: &native_preamble::Output<'dr, D, C, HEADER_SIZE, J>,
) -> Result<[Vec<Element<'dr, D>>; 2]> {
    let mut selected: [Vec<Element<'dr, D>>; 2] = [Vec::new(), Vec::new()];
    for (side, (child_eval, child_preamble)) in
        [(&eval.left, &preamble.left), (&eval.right, &preamble.right)]
            .into_iter()
            .enumerate()
    {
        let handles: Vec<_> = child_preamble
            .witness_polys
            .iter()
            .map(|poly| poly.wires())
            .collect();
        for query in child_preamble.poly_queries.iter() {
            selected[side].push(select_evaluation(
                dr,
                allocator,
                &child_eval.witness_poly_evals,
                &handles,
                &query.com.wires(),
            )?);
        }
    }
    Ok(selected)
}

/// The evaluation of the polynomial `com` names, selected by a one-hot over
/// `handles`. Booleanity, sum-to-one, and `Σ b_j · limb_j == limb` in every
/// limb position are all load-bearing.
///
/// The one-hot is witnessed rather than structural because query `i` of step
/// `S` opens whichever polynomial *that step* chose, and this is one circuit
/// for the whole application: a child may be any step, so the map is not
/// available as structure.
fn select_evaluation<'dr, D: Driver<'dr>, A: Allocator<'dr, D>>(
    dr: &mut D,
    allocator: &mut A,
    evaluations: &[Element<'dr, D>],
    handles: &[[Element<'dr, D>; HANDLE_WIRES]],
    com: &[Element<'dr, D>; HANDLE_WIRES],
) -> Result<Element<'dr, D>> {
    debug_assert_eq!(
        evaluations.len(),
        handles.len(),
        "one evaluation per witnessed polynomial"
    );

    // Prover-side first-match: must set exactly one bit even when several
    // polynomials share a commitment (padding ones do), or sum-to-one fails;
    // equal commitments denote equal polynomials under binding, so any match
    // is sound.
    let matched = {
        let target: [_; HANDLE_WIRES] = array::from_fn(|i| com[i].value());
        let handle_values: Vec<[_; HANDLE_WIRES]> = handles
            .iter()
            .map(|handle| array::from_fn(|i| handle[i].value()))
            .collect();
        D::just(move || {
            let target = target.map(|limb| *limb.take());
            handle_values
                .into_iter()
                .position(|handle| handle.map(|limb| *limb.take()) == target)
                // No match sets no bit; sum-to-one then fails (fail-closed).
                .unwrap_or(usize::MAX)
        })
    };
    let mut bits = Vec::with_capacity(handles.len());
    for j in 0..handles.len() {
        let matched = Maybe::clone(&matched);
        bits.push(Boolean::alloc(
            dr,
            allocator,
            D::just(move || matched.take() == j),
        )?);
    }

    let one = Element::one();
    let mut sum = Element::zero(dr);
    let mut selected = Element::zero(dr);
    let mut selected_limbs: Vec<_> = (0..HANDLE_WIRES).map(|_| Element::zero(dr)).collect();
    for (j, bit) in bits.iter().enumerate() {
        let bit = bit.element();
        sum = sum.add(dr, &bit);

        for (limb, selected_limb) in handles[j].iter().zip(selected_limbs.iter_mut()) {
            let term = bit.mul(dr, limb)?;
            *selected_limb = selected_limb.add(dr, &term);
        }

        let term = bit.mul(dr, &evaluations[j])?;
        selected = selected.add(dr, &term);
    }

    sum.sub(dr, &one).enforce_zero(dr)?;
    for (selected_limb, limb) in selected_limbs.iter().zip(com.iter()) {
        selected_limb.sub(dr, limb).enforce_zero(dr)?;
    }

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use ragu_arithmetic::ff::Field;
    use ragu_core::Error;
    use ragu_pasta::Fp;
    use ragu_primitives::{Simulator, allocator::Standard};

    use super::*;

    fn handle_of(tag: u64) -> [Fp; HANDLE_WIRES] {
        [Fp::from(tag), Fp::from(tag + 1_000)]
    }

    /// Distinct per handle, so the selection is readable off the result.
    fn evaluation_of(j: usize) -> Fp {
        Fp::from(100 + j as u64)
    }

    /// The selected evaluation, or `Err(InvalidWitness)` when a constraint is
    /// unsatisfied — which `Simulator` reports and `Emulator` does not.
    fn select(handles: &[[Fp; HANDLE_WIRES]], com: [Fp; HANDLE_WIRES]) -> Result<Fp> {
        let selected = Cell::new(Fp::ZERO);
        let handles = handles.to_vec();
        Simulator::simulate((), |dr, _| {
            let allocator = &mut Standard::new();
            let evaluations: Vec<_> = (0..handles.len())
                .map(|j| Element::constant(dr, evaluation_of(j)))
                .collect();
            let handle_elements: Vec<[Element<'_, _>; HANDLE_WIRES]> = handles
                .iter()
                .map(|handle| handle.map(|limb| Element::constant(dr, limb)))
                .collect();
            let com = com.map(|limb| Element::constant(dr, limb));

            let out = select_evaluation(dr, allocator, &evaluations, &handle_elements, &com)?;
            selected.set(*out.value().take());
            Ok(())
        })?;
        Ok(selected.get())
    }

    /// The selection must be unsatisfied. Matched on the variant, because a
    /// setup mistake also yields `Err`.
    fn refuses(handles: &[[Fp; HANDLE_WIRES]], com: [Fp; HANDLE_WIRES]) {
        match select(handles, com) {
            Err(Error::InvalidWitness(_)) => {}
            other => panic!("expected an unsatisfied constraint, got {other:?}"),
        }
    }

    /// Every position, not just the first and last.
    #[test]
    fn a_commitment_selects_its_own_polynomials_evaluation() -> Result<()> {
        let handles = [handle_of(7), handle_of(8), handle_of(9)];
        for (j, handle) in handles.iter().enumerate() {
            assert_eq!(
                select(&handles, *handle)?,
                evaluation_of(j),
                "the commitment at position {j} must select position {j}'s evaluation"
            );
        }
        Ok(())
    }

    /// Fail-closed: no match sets no bit, and sum-to-one refuses that. Isolated
    /// here because `compute_f` rejects an unresolvable commitment on
    /// prover-side bookkeeping, ahead of the circuit.
    #[test]
    fn a_commitment_matching_no_handle_is_refused() {
        refuses(&[handle_of(7), handle_of(8)], handle_of(9));
    }

    /// Padded slots all commit to `g[0]`, so equal handles are routine. Exactly
    /// one bit is set; under binding, equal commitments denote equal
    /// polynomials, so the earliest match is as good as any.
    #[test]
    fn duplicate_handles_still_resolve() -> Result<()> {
        let shared = handle_of(7);
        let handles = [shared, shared, handle_of(9)];
        assert_eq!(
            select(&handles, shared)?,
            evaluation_of(0),
            "a first-match one-hot sets exactly one bit, the earliest"
        );
        assert_eq!(select(&handles, handle_of(9))?, evaluation_of(2));
        Ok(())
    }

    /// The equality is per limb, so a handle cannot be half-matched.
    #[test]
    fn a_commitment_matching_one_limb_only_is_refused() {
        let [lo, _] = handle_of(7);
        let [_, hi] = handle_of(8);
        refuses(&[handle_of(7), handle_of(8)], [lo, hi]);
    }
}
