//! # `ragu_backend`
//!
//! Computational backend interfaces for Ragu.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};
use ragu_core::FixedGenerators;
use udon::{curve::Affine, fft::Domain, field::Field};

/// A statically dispatched implementation of Ragu's computational operations.
///
/// Every method has a correctness-first default. Implementations may override
/// individual methods, but must return exactly the same result as the default
/// implementation for the same inputs.
/// Canonical circuit and protocol data is constructed before it reaches these
/// methods; a backend only changes how the requested computation is performed.
/// Implementing this low-level trait does not make a downstream type selectable
/// by `ragu_pcd`; application execution is restricted to Ragu-owned backends.
///
/// Backends are currently selected by type and cannot carry per-application
/// state. If implementations need device handles or caches, Ragu can store the
/// selected backend as a value while retaining static dispatch.
pub trait Backend: Clone + Copy + Debug + Default + Send + Sync + 'static {
    /// Evaluates a sparse polynomial at `point`.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::eval`] exactly.
    fn sparse_eval<F: Field, R: Rank>(poly: &sparse::Polynomial<F, R>, point: F) -> F {
        poly.eval(point)
    }

    /// Computes the reverse inner product of two sparse polynomials.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::revdot`] exactly.
    fn sparse_revdot<F: Field, R: Rank>(
        lhs: &sparse::Polynomial<F, R>,
        rhs: &sparse::Polynomial<F, R>,
    ) -> F {
        lhs.revdot(rhs)
    }

    /// Commits to a sparse polynomial in projective form.
    ///
    /// The correctness-first implementation dispatches its MSM through
    /// [`Backend::msm`], so overriding MSM also accelerates polynomial
    /// commitments.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::commit`] exactly.
    fn sparse_commit<F: Field, C: Affine<Scalar = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Projective {
        assert!(generators.g().len() >= R::num_coeffs());
        let bases = generators.g();

        Self::msm(
            poly.iter_stored_coeffs()
                .map(|(_, coefficient)| coefficient),
            poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
        )
    }

    /// Commits to independent sparse polynomials, returning results in input order.
    ///
    /// Inputs borrow the stored coefficients and generators without allocating.
    /// Execution goes through [`Self::msm_batch`], whose default performs each
    /// MSM separately and retains [`Self::msm`] overrides.
    ///
    /// # Correctness
    ///
    /// Each output must match [`sparse::Polynomial::commit`] exactly.
    fn sparse_commit_batch<C: Affine, R: Rank, G: FixedGenerators<C>, const N: usize>(
        polys: [&sparse::Polynomial<C::Scalar, R>; N],
        generators: &G,
    ) -> [C::Projective; N] {
        let bases = generators.g();
        assert!(bases.len() >= R::num_coeffs());
        Self::msm_batch(polys.map(|poly| {
            (
                poly.iter_stored_coeffs()
                    .map(|(_, coefficient)| coefficient),
                poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
            )
        }))
    }

    /// Commits to a sparse polynomial and normalizes the result to affine.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::commit_to_affine`] exactly.
    fn sparse_commit_to_affine<F: Field, C: Affine<Scalar = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C {
        Self::sparse_commit(poly, generators).into()
    }

    /// Computes the registry restriction $m(W, x, y)$.
    ///
    /// Callers that also need the $W$-domain evaluations can reach for
    /// [`registry_wxy_over_domain`](Self::registry_wxy_over_domain) and
    /// [`registry_interpolate_xy`](Self::registry_interpolate_xy) directly,
    /// sharing a single per-circuit pass between the two representations.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Registry::xy`] exactly.
    fn registry_xy<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        Self::registry_interpolate_xy(registry, Self::registry_wxy_over_domain(registry, x, y))
    }

    /// Evaluates the registry polynomial over its $W$-domain at $X = x$,
    /// $Y = y$.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Registry::wxy_over_domain`] exactly.
    fn registry_wxy_over_domain<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> Vec<F> {
        registry.wxy_over_domain(x, y)
    }

    /// Interpolates $W$-domain evaluations into the monomial-basis polynomial
    /// $m(W, x, y)$.
    ///
    /// The default dispatches the inverse transform through [`Backend::ifft`].
    ///
    /// # Correctness
    ///
    /// Overrides must match [`Registry::interpolate_xy`] exactly.
    fn registry_interpolate_xy<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        evals: Vec<F>,
    ) -> sparse::Polynomial<F, R> {
        registry.interpolate_xy_with(evals, Self::ifft)
    }

    /// Computes the circuit restriction $s_i(X, y)$ selected by `circuit`.
    fn registry_circuit_y<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.circuit_y(circuit, y)
    }

    /// Computes the registry restriction $m(w, x, Y)$.
    fn registry_at_x<F: Field, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        x: F,
    ) -> sparse::Polynomial<F, R> {
        registry.x(x)
    }

    /// Computes the registry restriction $m(w, X, y)$.
    fn registry_at_y<F: Field, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.y(y)
    }

    /// Evaluates the registry polynomial at $(w, x, y)$.
    fn registry_wxy<F: Field, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        registry.wxy(w, x, y)
    }

    /// Transforms natural-order coefficients into natural-order domain evaluations.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`ragu_core::fft`] exactly, including rejecting an
    /// input whose length differs from the domain size before mutating it.
    fn fft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
        ragu_core::fft(domain, values);
    }

    /// Transforms natural-order domain evaluations into normalized coefficients.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`ragu_core::ifft`] exactly. The inverse includes
    /// division by the domain size and rejects an input of the wrong length
    /// before mutating it.
    fn ifft<F: Field>(domain: Domain<F>, values: &mut Vec<F>) {
        ragu_core::ifft(domain, values);
    }

    /// Computes the multiscalar multiplication
    /// $\langle \mathbf{a}, \mathbf{G} \rangle$.
    ///
    /// # Correctness
    ///
    /// Inputs are truncated to the shorter iterator. Overrides must match
    /// [`Affine::msm`] on those paired elements exactly.
    fn msm<
        'a,
        C: Affine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Projective
    where
        Bases::IntoIter: Clone + Sync,
    {
        let coeffs: Vec<C::Scalar> = coeffs.into_iter().copied().collect();
        let bases: Vec<C> = bases.into_iter().copied().collect();
        let len = coeffs.len().min(bases.len());
        ragu_core::msm(coeffs.into_iter().take(len), bases.into_iter().take(len))
    }

    /// Computes independent MSMs, returning results in input order.
    ///
    /// The default calls [`Self::msm`] for each input, retaining MSM overrides.
    /// Backends may override this method to schedule the MSMs together.
    ///
    /// # Correctness
    ///
    /// Each input is truncated to its shorter iterator, as in [`Self::msm`].
    /// Outputs must match separate calls to that method exactly.
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
        inputs.map(|(coeffs, bases)| Self::msm(coeffs, bases))
    }

    /// Maps a finite set of independent inputs to results in input order.
    ///
    /// The default is an ordinary lazy iterator, with no job buffer. Backends
    /// may collect the inputs and evaluate them concurrently before returning.
    /// Consequently, `work` must be independent of execution order and must not
    /// have protocol side effects such as consuming transcript or RNG state.
    /// Callers must not rely on unevaluated work when consuming only a prefix.
    ///
    /// # Correctness
    ///
    /// Collecting all results must match `inputs.into_iter().map(work)` exactly,
    /// with one call per input and results in the original input order.
    fn map<I: IntoIterator, T: Send>(
        inputs: I,
        work: impl Fn(I::Item) -> T + Sync,
    ) -> impl Iterator<Item = T>
    where
        I::Item: Send,
    {
        inputs.into_iter().map(work)
    }

    /// Applies independent work to each item's original index and mutable slot.
    ///
    /// The default visits items serially. Backends may schedule them concurrently.
    /// The callback's result for each item must be independent of visitation order.
    ///
    /// # Correctness
    ///
    /// On success, each item must be visited exactly once with its original index,
    /// and the items must retain their original order. If the callback panics,
    /// some items may remain unvisited.
    fn for_each_mut<T: Send>(values: &mut [T], work: impl Fn(usize, &mut T) + Sync) {
        for (index, value) in values.iter_mut().enumerate() {
            work(index, value);
        }
    }
}

/// The backend used by default throughout Ragu.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceBackend;

impl Backend for ReferenceBackend {}
