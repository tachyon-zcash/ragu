//! Commits to the collapsed revdot claim polynomials $A$ and $B$.
//!
//! Both vector sides use the same two-layer Lagrange weights. Each weight
//! $\lambda_i$ is the product of the claim's weight within its group at $\mu$
//! and its group's weight at $\mu'$. Missing claims are zero-padded.
//!
//! This sets the $A$ and $B$ polynomial fields on the [`ProofBuilder`],
//! which contain the claimed (folded) revdot polynomials.
//!
//! ### Relationship to constituent polynomials
//!
//! $A(X)$ and $B(X)$ are folded linear combinations of the individual circuit
//! and stage `rx` polynomials:
//!
//! - $A(X) = \sum_i \lambda_i r_i(X)$
//! - $B(X) = \sum_i \lambda_i b_i(X)$ where
//!   $b\_i(X) = r\_i(XZ) + s\_{y,i}(X) + t\_z(X)$
//!
//! ### Evaluation point and dilation
//!
//! During verification, the verifier recomputes $A$ and $B$ at specific points
//! from individual $r\_i$ evaluations witnessed in the query stage.
//!
//! $A$'s terms don't involve $Z$-dilation: $A(p) = \sum_i \lambda_i r_i(p)$
//! for any point $p$, requiring only $\{r\_i(p)\}$ evaluations. $B$'s terms
//! involve $Z$-dilation: $b\_i(p) = r\_i(pZ) + s\_y(p) + t\_z(p)$, so $B(p)$
//! requires $\{r\_i(pZ)\}$ evaluations.
//!
//! $A$ is checked at $xz$ and $B$ at $x$. Since $A$ has no dilation,
//! $A(xz) = \sum_i \lambda_i r_i(xz)$ reuses the same $\{r\_i(xz)\}$
//! evaluations that $B(x)$ already needs, eliminating separate
//! $r\_i(x)$ queries.
//!
//! ### Nested accumulator
//!
//! The second layer of the nested fold happens here too, producing the
//! nested accumulator polynomials $A\_n(X)$, $B\_n(X)$ over the scalar
//! field. Their commitments live on the nested curve and are computed by
//! committing the polynomials directly, then committed, with the nested
//! $m_n(w_n, X, y_n)$ restriction's, in the native points stage the
//! endoscaling walk reads them from, whose commitment the `ab` bridge
//! carries: they are fixed before $x$ is squeezed, as $A$ and $B$ are.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use udon::curve::Affine;

use super::{
    _04_inner_error::NestedRegistryWy,
    claims::{FoldKey, NativeFuseProofSource, TrackedPoly},
};
use crate::{
    Application,
    internal::{fold_revdot, native, nested},
    profile::ProfiledCycle,
    proof::ProofBuilder,
};

type NativeNumGroups<P> = <native::RevdotParameters<P> as fold_revdot::Parameters>::NumGroups;
type NestedNumGroups<P> = <nested::RevdotParameters<P> as fold_revdot::Parameters>::NumGroups;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_ab<'dr, D, RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        native_a: FixedVec<
            TrackedPoly<'_, FoldKey, C::CircuitField, R>,
            NativeNumGroups<C::Profile>,
        >,
        native_b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups<C::Profile>>,
        nested_a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        nested_b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        native_source: &NativeFuseProofSource<'_, C, R>,
        mu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        self.compute_native_ab(native_a, native_b, native_source, mu_prime, builder)?;
        self.compute_nested_ab(nested_a, nested_b, mu_prime, builder)?;
        self.commit_native_points_ab(
            rng,
            nested_registry_wy.commitment,
            builder.nested_a_commitment(),
            builder.nested_b_commitment(),
            builder,
        )?;
        Ok(())
    }

    /// Applies the second layer of the nested fold, producing the nested
    /// accumulator polynomials.
    ///
    /// The nested $\mu'$ is derived from the native challenge
    /// (see [`nested::challenge`]), which the transcript squeezes only after
    /// the bridge carrying the layer-2 error terms is absorbed.
    fn compute_nested_ab<'dr, D>(
        &self,
        a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups<C::Profile>>,
        native_mu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let nested_mu_prime = nested::challenge::<C>(*native_mu_prime.value().take())?;

        let a_poly = fold_revdot::fold_outer::<_, _, nested::RevdotParameters<C::Profile>>(
            a,
            nested_mu_prime,
        );
        let b_poly = fold_revdot::fold_outer::<_, _, nested::RevdotParameters<C::Profile>>(
            b,
            nested_mu_prime,
        );

        builder.set_nested_a_poly(a_poly);
        builder.set_nested_b_poly(b_poly);

        Ok(())
    }

    fn compute_native_ab<'dr, D>(
        &self,
        a: FixedVec<TrackedPoly<'_, FoldKey, C::CircuitField, R>, NativeNumGroups<C::Profile>>,
        b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups<C::Profile>>,
        native_source: &NativeFuseProofSource<'_, C, R>,
        mu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let mu_prime = *mu_prime.value().take();

        let TrackedPoly {
            poly: a_poly,
            decomp: a_decomp,
        } = fold_revdot::fold_outer::<_, _, native::RevdotParameters<C::Profile>>(a, mu_prime);
        let a_poly = a_poly.into_owned();

        let b_poly =
            fold_revdot::fold_outer::<_, _, native::RevdotParameters<C::Profile>>(b, mu_prime);
        let host_gen = C::host_generators(self.params);

        // Compute a_commitment from decomposition: small MSM over known
        // commitments, resolved directly from the child proofs rather than
        // full polynomial-degree MSM.
        let a_commitment_proj = {
            // Deduplicate terms by key, summing coefficients.
            // TODO: O(n²) linear scan; switch to HashMap or sort-based dedup
            // if the number of terms grows beyond current M×N ≈ 108.
            let mut entries: Vec<(FoldKey, C::CircuitField)> = Vec::new();
            for &(key, coeff) in &a_decomp.terms {
                if let Some(entry) = entries.iter_mut().find(|(k, _)| *k == key) {
                    entry.1 += coeff;
                } else {
                    entries.push((key, coeff));
                }
            }

            let mut msm: Vec<(C::CircuitField, C::HostCurve)> = Vec::with_capacity(entries.len());
            for (key, coeff) in entries {
                let commitment = native_source.get(key);
                msm.push((coeff, commitment));
            }

            B::msm(msm.iter().map(|(c, _)| c), msm.iter().map(|(_, b)| b))
        };

        let mut commitments = [<C::HostCurve as Affine>::identity(); 2];
        <C::HostCurve as Affine>::batch_to_affine(
            &[a_commitment_proj, B::sparse_commit(&b_poly, host_gen)],
            &mut commitments,
        );
        let [a_commitment, b_commitment] = commitments;

        builder.set_native_a_poly(a_poly, a_commitment);
        builder.set_native_b_poly(b_poly, b_commitment);

        Ok(())
    }
}
