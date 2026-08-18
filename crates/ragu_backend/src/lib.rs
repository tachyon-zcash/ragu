//! # `ragu_backend`
//!
//! Computational backend interfaces for Ragu.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use ragu_arithmetic::{
    CurveAffine, DeferredField, FixedGenerators, PoseidonPermutation,
    ff::{Field, PrimeField},
};
use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::{CircuitIndex, Registry, RegistryAt},
};

/// A statically dispatched implementation of Ragu's computational operations.
///
/// Every method has a correctness-first default. Implementations may override
/// individual methods, but must return exactly the same result as the default
/// implementation for the same inputs.
/// Canonical circuit and protocol data is constructed before it reaches these
/// methods; a backend only changes how the requested computation is performed.
///
/// Backends are currently selected by type and cannot carry per-application
/// state. If implementations need device handles or caches, Ragu can store the
/// selected backend as a value while retaining static dispatch.
pub trait Backend: Send + Sync + 'static {
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
    fn sparse_revdot<F: DeferredField, R: Rank>(
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
    fn sparse_commit<F: Field, C: CurveAffine<ScalarExt = F>, R: Rank, G: FixedGenerators<C>>(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C::Curve {
        assert!(generators.g().len() >= R::num_coeffs());
        let bases = generators.g();

        Self::msm(
            poly.iter_stored_coeffs()
                .map(|(_, coefficient)| coefficient),
            poly.iter_stored_coeffs().map(|(index, _)| &bases[index]),
        )
    }

    /// Commits to a sparse polynomial and normalizes the result to affine.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`sparse::Polynomial::commit_to_affine`] exactly.
    fn sparse_commit_to_affine<
        F: Field,
        C: CurveAffine<ScalarExt = F>,
        R: Rank,
        G: FixedGenerators<C>,
    >(
        poly: &sparse::Polynomial<F, R>,
        generators: &G,
    ) -> C {
        Self::sparse_commit(poly, generators).into()
    }

    /// Computes the registry restriction $m(W, x, y)$.
    fn registry_xy<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        x: F,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.xy(x, y)
    }

    /// Computes the circuit restriction $s_i(X, y)$ selected by `circuit`.
    fn registry_circuit_y<F: PrimeField, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.circuit_y(circuit, y)
    }

    /// Computes the registry restriction $m(w, x, Y)$.
    fn registry_at_x<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        x: F,
    ) -> sparse::Polynomial<F, R> {
        registry.x(x)
    }

    /// Computes the registry restriction $m(w, X, y)$.
    fn registry_at_y<F: PrimeField, R: Rank>(
        registry: &RegistryAt<'_, F, R>,
        y: F,
    ) -> sparse::Polynomial<F, R> {
        registry.y(y)
    }

    /// Evaluates the registry polynomial at $(w, x, y)$.
    fn registry_wxy<F: PrimeField, R: Rank>(registry: &Registry<'_, F, R>, w: F, x: F, y: F) -> F {
        registry.wxy(w, x, y)
    }

    /// Applies the out-of-circuit Poseidon permutation to `state`.
    ///
    /// # Correctness
    ///
    /// Overrides must match [`ragu_arithmetic::poseidon_permute`] exactly.
    fn poseidon_permute<F: Field, P: PoseidonPermutation<F>>(params: &P, state: &mut [F]) {
        ragu_arithmetic::poseidon_permute(params, state);
    }

    /// Computes the multiscalar multiplication
    /// $\langle \mathbf{a}, \mathbf{G} \rangle$.
    ///
    /// # Correctness
    ///
    /// The caller must ensure that `coeffs` and `bases` yield the same number
    /// of elements. Overrides must match [`ragu_arithmetic::msm`] exactly.
    fn msm<
        'a,
        C: CurveAffine,
        A: IntoIterator<Item = &'a C::Scalar>,
        Bases: IntoIterator<Item = &'a C>,
    >(
        coeffs: A,
        bases: Bases,
    ) -> C::Curve
    where
        Bases::IntoIter: Clone + Sync,
    {
        ragu_arithmetic::msm(coeffs, bases)
    }
}

/// The correctness-first backend used by default throughout Ragu.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceBackend;

impl Backend for ReferenceBackend {}
