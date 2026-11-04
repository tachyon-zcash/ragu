//! # `ragu_acceleration`
//!
//! Optimized implementations of Ragu's computational backend.
//!
//! Both types share a [`ragu_backend::Backend`] implementation. `ragu_pcd`'s sealed
//! `SelectableBackend::Verifier` mapping pairs [`AcceleratedBackend`] with itself
//! and [`AcceleratedProver`] with [`ragu_backend::ReferenceBackend`]. Ordinary and
//! compressed verification call the mapped backend directly.
//!
//! Overrides fall back to the defaults of [`ragu_backend::Backend`] where a
//! method has none. Independent Pasta MSMs share Udon's batch planner,
//! scratch, and execution budget; the reference backend runs them separately.
//! Independent polynomial work also uses Udon's scoped scheduler rather than
//! the reference backend's serial loop.
//! Fixed Pasta generators can retain cached endomorphism coordinates across
//! verifier MSMs. Other single MSMs and FFTs retain the defaults, which use Udon.
//! The opt-in `large-msm-tables` feature retains 64-layer generator tables,
//! trading startup work and memory for less repeated verifier MSM work; see
//! [`PreparedMsm`] for the storage bound.
//! Overrides of the kernels that `ragu_pcd`'s verifier consults belong in
//! [`verifier`], which carries a stricter review and testing bar than
//! prover-only overrides. An override arrives with its differential test
//! against the default it replaces; `ragu_pcd`'s `backend_equivalence` tests hold
//! [`AcceleratedProver`] to the reference end to end.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(feature = "multicore")]
use alloc::vec::Vec;

use ragu_backend::Backend;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_core::{MsmWorkspace, PreparedMsm};
use udon::{curve::Affine, field::Field};

pub mod verifier;

/// Ragu's accelerated computational backend, for proving and verification.
///
/// Independent Pasta MSMs share Udon's batch planner, producing the same
/// results as [`ragu_backend::ReferenceBackend`]'s separate calls. Selecting
/// this backend in `ragu_pcd` also uses its verifier-consulted kernels
/// (see [`verifier`]) when verifying proofs. Select [`AcceleratedProver`]
/// to keep verification on the reference kernels.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedBackend;

/// [`AcceleratedBackend`] for proving, with verification on the reference
/// kernels.
///
/// Uses the same proving kernels as [`AcceleratedBackend`], including batched
/// MSMs; the two differ only in which backend `ragu_pcd` consults when verifying.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceleratedProver;

// Define the overrides once so both backends always use the same proving
// kernels. `ragu_pcd` selects their verification backends separately.
macro_rules! impl_accelerated_backends {
    ($($method:item)*) => {
        impl Backend for AcceleratedBackend {
            $($method)*
        }

        impl Backend for AcceleratedProver {
            $($method)*
        }
    };
}

impl_accelerated_backends! {
    fn registry_wxy_over_domain<F: Field, R: Rank>(registry: &Registry<'_, F, R>, x: F, y: F) -> alloc::vec::Vec<F> {
        verifier::registry_wxy_over_domain(registry, x, y)
    }

    fn registry_circuits_xy<F: Field, R: Rank>(registry: &Registry<'_, F, R>, circuits: &[CircuitIndex], x: F, y: F) -> alloc::vec::Vec<F> {
        verifier::registry_circuits_xy(registry, circuits, x, y)
    }

    fn registry_at_x<F: Field, R: Rank>(registry: &RegistryAt<'_, F, R>, x: F) -> sparse::Polynomial<F, R> {
        verifier::registry_at_x(registry, x)
    }

    fn registry_at_y<F: Field, R: Rank>(registry: &RegistryAt<'_, F, R>, y: F) -> sparse::Polynomial<F, R> {
        verifier::registry_at_y(registry, y)
    }

    fn registry_wxy<F: Field, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        verifier::registry_wxy(registry, w, x, y)
    }

    #[cfg(feature = "multicore")]
    fn map<I: IntoIterator, T: Send>(
        inputs: I,
        work: impl Fn(I::Item) -> T + Sync,
    ) -> impl Iterator<Item = T>
    where
        I::Item: Send,
    {
        let mut jobs: Vec<_> = inputs
            .into_iter()
            .map(|input| (Some(input), None))
            .collect();
        Self::for_each_mut(&mut jobs, |_, (input, output)| {
            *output = Some(work(input.take().expect("each input is visited once")));
        });
        jobs.into_iter()
            .map(|(_, output)| output.expect("each output is initialized"))
    }

    fn prepare_msm<C: Affine>(bases: &[C]) -> Option<PreparedMsm<C>> {
        verifier::prepare_msm(bases)
    }

    fn msm_prepared<C: Affine>(coeffs: alloc::vec::Vec<C::Scalar>, bases: &PreparedMsm<C>, workspace: &mut MsmWorkspace) -> C::Projective {
        verifier::msm_prepared(coeffs, bases, workspace)
    }

    fn msm_batch<
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
        verifier::msm_batch(inputs)
    }

    fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
        verifier::for_each_mut(values, work);
    }
}
