//! Verifier-consulted kernels.
//!
//! The [`Backend`](ragu_backend::Backend) trait has a single set of methods,
//! and the prover uses all of them. The verifiers also use polynomial and
//! registry evaluations, commitments, and MSMs through the selected backend's
//! `Verifier`. This includes the compressed verifier's transcript bridges,
//! batch commitments, and IPA checks. `AcceleratedBackend` selects its own
//! kernels for verification; `AcceleratedProver` selects `ReferenceBackend`.
//! Overrides of verifier-consulted kernels belong in this module and are
//! reached from the `Backend` impl in the crate root by delegation, so code
//! that can influence an acceptance decision can be reviewed and tested here.

use alloc::vec::Vec;

use udon::curve::Affine;

/// Computes independent MSMs, truncating each input to its shorter operand.
pub(crate) fn msm_batch<
    'a,
    C: Affine,
    A: IntoIterator<Item = &'a C::Scalar>,
    Bases: IntoIterator<Item = &'a C>,
    const N: usize,
>(
    inputs: [(A, Bases); N],
) -> [C::Projective; N]
where
    Bases::IntoIter: Clone + Sync,
{
    let inputs = inputs.map(|(coeffs, bases)| {
        let coeffs: Vec<_> = coeffs.into_iter().copied().collect();
        let bases: Vec<_> = bases.into_iter().copied().collect();
        let len = coeffs.len().min(bases.len());
        (coeffs.into_iter().take(len), bases.into_iter().take(len))
    });
    ragu_core::msm_batch(inputs)
}

/// Schedules independent work without changing the items' original slots.
pub(crate) fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
    ragu_core::for_each_mut(values, |index, value, _| work(index, value));
}
