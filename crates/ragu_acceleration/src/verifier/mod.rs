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

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_core::PreparedMsm;
use udon::{curve::Affine, field::Field};

pub(crate) fn registry_wxy_over_domain<F: Field, R: Rank>(
    registry: &Registry<'_, F, R>,
    x: F,
    y: F,
) -> alloc::vec::Vec<F> {
    registry.wxy_over_domain_parallel(x, y)
}

pub(crate) fn registry_circuits_xy<F: Field, R: Rank>(
    registry: &Registry<'_, F, R>,
    circuits: &[CircuitIndex],
    x: F,
    y: F,
) -> alloc::vec::Vec<F> {
    registry.circuits_xy_parallel(circuits, x, y)
}

pub(crate) fn registry_at_x<F: Field, R: Rank>(
    registry: &RegistryAt<'_, F, R>,
    x: F,
) -> sparse::Polynomial<F, R> {
    registry.x_parallel(x)
}

pub(crate) fn registry_at_y<F: Field, R: Rank>(
    registry: &RegistryAt<'_, F, R>,
    y: F,
) -> sparse::Polynomial<F, R> {
    registry.y_parallel(y)
}

pub(crate) fn registry_wxy<F: Field, R: Rank>(
    registry: &Registry<'_, F, R>,
    w: F,
    x: F,
    y: F,
) -> F {
    registry.at(w).xy_parallel(x, y)
}

pub(crate) fn prepare_msm<C: Affine>(bases: &[C]) -> Option<PreparedMsm<C>> {
    PreparedMsm::new(bases)
}

pub(crate) fn msm_prepared<C: Affine>(
    coeffs: alloc::vec::Vec<C::Scalar>,
    bases: &PreparedMsm<C>,
) -> C::Projective {
    bases.evaluate(coeffs)
}

/// Computes independent MSMs, panicking before any of them if an input's
/// operands differ in length.
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
    ragu_core::msm_batch(
        inputs.map(|(coeffs, bases)| (coeffs.into_iter().copied(), bases.into_iter().copied())),
    )
}

/// Schedules independent work without changing the items' original slots.
pub(crate) fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
    ragu_core::for_each_mut(values, work);
}
