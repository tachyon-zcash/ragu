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
//! Single MSMs and FFTs retain the defaults, which also use Udon.
//! Overrides of the kernels that `ragu_pcd`'s verifier consults belong in
//! [`verifier`], which carries a stricter review and testing bar than
//! prover-only overrides. An override arrives with its differential test
//! against the default it replaces; `ragu_pcd`'s `backend_equivalence` tests hold
//! [`AcceleratedProver`] to the reference end to end.
//!
//! With the `gpu` feature, [`AcceleratedProver`] also commits to polynomials
//! on a CUDA device, which holds a table of window multiples for each set of
//! fixed generators. A request the device cannot serve, including every
//! request on a machine without one, is computed by the CPU kernels above
//! with the same result. [`AcceleratedBackend`] does not use the device: its
//! kernels are also the verifier's. The feature needs the CUDA compiler at
//! build time; without it the crate builds as if the feature were off.

#![no_std]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(feature = "multicore", ragu_cuda))]
use alloc::vec::Vec;

use ragu_backend::Backend;
#[cfg(ragu_cuda)]
use ragu_circuits::polynomials::{Rank, sparse};
#[cfg(ragu_cuda)]
use ragu_core::FixedGenerators;
use udon::curve::Affine;
#[cfg(ragu_cuda)]
use udon::field::Field;

#[cfg(ragu_cuda)]
mod gpu;
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

// Define the shared overrides once so both backends use the same CPU
// kernels. `ragu_pcd` selects their verification backends separately. The
// `prover` overrides belong to `AcceleratedProver` alone, whose verifier is
// the reference backend, so they never reach an acceptance decision.
macro_rules! impl_accelerated_backends {
    (shared { $($method:item)* } prover { $($prover:item)* }) => {
        impl Backend for AcceleratedBackend {
            $($method)*
        }

        impl Backend for AcceleratedProver {
            $($method)*
            $($prover)*
        }
    };
}

impl_accelerated_backends! {
shared {
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
prover {
    #[cfg(ragu_cuda)]
    fn sparse_commit<F: Field, C: Affine<Scalar = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Projective {
        let bases = generators.g();
        assert!(bases.len() >= R::num_coeffs());
        if let Some([commitment]) = gpu::commit_batch([poly], generators) {
            return commitment;
        }
        Self::msm(
            poly.iter_stored_coeffs()
                .map(|(_, coefficient)| coefficient),
            poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
        )
    }

    #[cfg(ragu_cuda)]
    fn poly_device<F: Field, R: Rank>() -> Option<alloc::boxed::Box<dyn ragu_backend::PolyDevice<F, R>>> {
        gpu::poly_device()
    }

    #[cfg(ragu_cuda)]
    fn sparse_commit_many<C: Affine, R: Rank, G: FixedGenerators<C>>(
        polys: &[&sparse::Polynomial<C::Scalar, R>],
        generators: &G,
    ) -> Vec<C::Projective> {
        assert!(generators.g().len() >= R::num_coeffs());
        if let Some(commitments) = gpu::commit_many(polys, generators) {
            return commitments;
        }
        polys
            .iter()
            .map(|poly| Self::sparse_commit(poly, generators))
            .collect()
    }

    #[cfg(ragu_cuda)]
    fn device_commit<C: Affine, R: Rank, G: FixedGenerators<C>>(
        device: &mut dyn ragu_backend::PolyDevice<C::Scalar, R>,
        slots: &[ragu_backend::Slot],
        generators: &G,
    ) -> Option<(Vec<sparse::Polynomial<C::Scalar, R>>, Vec<C::Projective>)> {
        assert!(generators.g().len() >= R::num_coeffs());
        gpu::device_commit(device, slots, generators)
    }

    #[cfg(ragu_cuda)]
    fn sparse_commit_many_start<C: Affine, R: Rank, G: FixedGenerators<C>>(
        polys: &[&sparse::Polynomial<C::Scalar, R>],
        generators: &G,
    ) -> Option<alloc::boxed::Box<dyn ragu_backend::StartedCommitments<C::Projective>>> {
        assert!(generators.g().len() >= R::num_coeffs());
        gpu::start_many(polys, generators)
    }

    #[cfg(ragu_cuda)]
    fn sparse_commit_batch<C: Affine, R: Rank, G: FixedGenerators<C>, const N: usize>(
        polys: [&sparse::Polynomial<C::Scalar, R>; N],
        generators: &G,
    ) -> [C::Projective; N] {
        let bases = generators.g();
        assert!(bases.len() >= R::num_coeffs());
        if let Some(commitments) = gpu::commit_batch(polys, generators) {
            return commitments;
        }
        Self::msm_batch(polys.map(|poly| {
            (
                poly.iter_stored_coeffs()
                    .map(|(_, coefficient)| coefficient),
                poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
            )
        }))
    }
}
}
