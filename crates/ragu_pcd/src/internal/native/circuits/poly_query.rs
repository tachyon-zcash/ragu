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
