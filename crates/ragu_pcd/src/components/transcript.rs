//! Functions to derive deterministic challenges from polynomial commitments via
//! Poseidon hashing, implementing the Fiat-Shamir transform for the PCD
//! protocol.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// Computation of $w = H(\\text{nested\\_preamble\\_commitment})$.
pub fn derive_w<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_preamble_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_preamble_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Computes $w$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_w<C: Cycle>(
    nested_preamble_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_w::<_, C>(dr, &point, params)?.value().take())
    })
}

/// Computation of $(y, z) = H(w, \\text{nested\\_s\\_prime\\_commitment})$.
pub fn derive_y_z<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    w: &Element<'dr, D>,
    nested_s_prime_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    sponge.absorb(dr, w)?;
    nested_s_prime_commitment.write(dr, &mut sponge)?;
    let y = sponge.squeeze(dr)?;
    let z = sponge.squeeze(dr)?;
    Ok((y, z))
}

/// Computes $(y, z)$ challenges using the [`Emulator`] for use outside of
/// circuit contexts.
pub fn emulate_y_z<C: Cycle>(
    w: C::CircuitField,
    nested_s_prime_commitment: C::NestedCurve,
    params: &C,
) -> Result<(C::CircuitField, C::CircuitField)> {
    Emulator::emulate_wireless((w, nested_s_prime_commitment), |dr, witness| {
        let (w, comm) = witness.cast();
        let w_elem = Element::alloc(dr, w)?;
        let point = Point::alloc(dr, comm)?;
        let (y, z) = derive_y_z::<_, C>(dr, &w_elem, &point, params)?;
        Ok((*y.value().take(), *z.value().take()))
    })
}

/// Computation of $\\alpha = H(\\text{nested\\_query\\_commitment})$.
pub fn derive_alpha<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_query_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_query_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Computes $\\alpha$ challenge using the [`Emulator`] for use outside of
/// circuit contexts.
pub fn emulate_alpha<C: Cycle>(
    nested_query_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_query_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_alpha::<_, C>(dr, &point, params)?.value().take())
    })
}

/// Computation of $u = H(\\alpha, \\text{nested\\_f\\_commitment})$.
pub fn derive_u<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    alpha: &Element<'dr, D>,
    nested_f_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    sponge.absorb(dr, alpha)?;
    nested_f_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Computes $u$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_u<C: Cycle>(
    alpha: C::CircuitField,
    nested_f_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless((alpha, nested_f_commitment), |dr, witness| {
        let (alpha, comm) = witness.cast();
        let alpha_elem = Element::alloc(dr, alpha)?;
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_u::<_, C>(dr, &alpha_elem, &point, params)?
            .value()
            .take())
    })
}

/// Computation of $(\\mu, \\nu) = H(C)$ where $C \in E_p$.
/// 
/// This is used to derive $(\mu, \nu)$ from
/// $\\text{nested\\_error\\_m\\_commitment}$ and $(\mu', \nu')$ from
/// $\\text{nested\\_error\\_n\\_commitment}$.
pub fn derive_mu_nu<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_error_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_error_commitment.write(dr, &mut sponge)?;
    let mu = sponge.squeeze(dr)?;
    let nu = sponge.squeeze(dr)?;
    Ok((mu, nu))
}

/// Computes $(\\mu, \\nu)$ challenges using the [`Emulator`] for use outside of
/// circuit contexts.
pub fn emulate_mu_nu<C: Cycle>(
    nested_error_commitment: C::NestedCurve,
    params: &C,
) -> Result<(C::CircuitField, C::CircuitField)> {
    Emulator::emulate_wireless(nested_error_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let (mu, nu) = derive_mu_nu::<_, C>(dr, &point, params)?;
        Ok((*mu.value().take(), *nu.value().take()))
    })
}

/// Computation of $x = H(\\nu', \\text{nested\\_ab\\_commitment})$.
pub fn derive_x<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nu_prime: &Element<'dr, D>,
    nested_ab_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    sponge.absorb(dr, nu_prime)?;
    nested_ab_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Computes $x$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_x<C: Cycle>(
    nu_prime: C::CircuitField,
    nested_ab_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless((nu_prime, nested_ab_commitment), |dr, witness| {
        let (nu_prime, comm) = witness.cast();
        let nu_prime = Element::alloc(dr, nu_prime)?;
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_x::<_, C>(dr, &nu_prime, &point, params)?
            .value()
            .take())
    })
}

/// Computation of $\\beta = H(\\text{nested\\_eval\\_commitment})$.
pub fn derive_beta<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_eval_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_eval_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Computes $\\beta$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_beta<C: Cycle>(
    nested_eval_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_eval_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_beta::<_, C>(dr, &point, params)?.value().take())
    })
}
