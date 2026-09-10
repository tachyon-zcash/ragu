//! Commits to the collapsed revdot claim polynomials $A$ and $B$.
//!
//! This sets the $A$ and $B$ polynomial fields on the [`ProofBuilder`],
//! which contain the claimed (folded) revdot polynomials.
//!
//! ### Relationship to constituent polynomials
//!
//! $A(X)$ and $B(X)$ are folded linear combinations of the individual circuit
//! and stage `rx` polynomials:
//!
//! - $A(X) = \text{fold}\_{\mu}(r\_i(X))$
//! - $B(X) = \text{fold}\_{\mu\nu}(b\_i(X))$ where
//!   $b\_i(X) = r\_i(XZ) + s\_{y,i}(X) + t\_z(X)$
//!
//! ### Evaluation point and dilation
//!
//! During verification, the verifier recomputes $A$ and $B$ at specific points
//! from individual $r\_i$ evaluations witnessed in the query stage.
//!
//! $A$'s terms don't involve $Z$-dilation: $A(p) = \text{fold}\_{\mu}(r\_i(p))$
//! for any point $p$, requiring only $\{r\_i(p)\}$ evaluations. $B$'s terms
//! involve $Z$-dilation: $b\_i(p) = r\_i(pZ) + s\_y(p) + t\_z(p)$, so $B(p)$
//! requires $\{r\_i(pZ)\}$ evaluations.
//!
//! $A$ is checked at $xz$ and $B$ at $x$. Since $A$ has no dilation,
//! $A(xz) = \text{fold}(r\_i(xz))$ reuses the same $\{r\_i(xz)\}$
//! evaluations that $B(x)$ already needs, eliminating separate
//! $r\_i(x)$ queries.
//!
//! ### Nested accumulator
//!
//! The second layer of the nested fold happens here too, producing the
//! nested accumulator polynomials $A\_n(X)$, $B\_n(X)$ over the scalar
//! field. Their commitments live on the nested curve and are computed by
//! committing the polynomials directly; nothing binds them yet, so they are
//! not bridged anywhere.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};

use super::claims::{FoldKey, NativeFuseProofSource, TrackedPoly};
use crate::{
    Application,
    internal::{fold_revdot, native, nested},
    proof::ProofBuilder,
};

type NativeNumGroups = <native::RevdotParameters as fold_revdot::Parameters>::NumGroups;
type NestedNumGroups = <nested::RevdotParameters as fold_revdot::Parameters>::NumGroups;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(super) fn compute_ab<'dr, D>(
        &self,
        native_a: FixedVec<TrackedPoly<'_, FoldKey, C::CircuitField, R>, NativeNumGroups>,
        native_b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups>,
        nested_a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
        nested_b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
        native_source: &NativeFuseProofSource<'_, C, R>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        self.compute_native_ab(
            native_a,
            native_b,
            native_source,
            mu_prime,
            nu_prime,
            builder,
        )?;
        self.compute_nested_ab(nested_a, nested_b, mu_prime, nu_prime, builder)?;

        Ok(())
    }

    /// Applies the second layer of the nested fold, producing the nested
    /// accumulator polynomials.
    ///
    /// The nested $\mu'$ and $\nu'$ are derived from the native challenges
    /// (see [`nested::challenge`]), which the transcript squeezes only after
    /// the bridge carrying the layer-2 error terms is absorbed.
    fn compute_nested_ab<'dr, D>(
        &self,
        a: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
        b: FixedVec<sparse::Polynomial<C::ScalarField, R>, NestedNumGroups>,
        native_mu_prime: &Element<'dr, D>,
        native_nu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let nested_mu_prime = nested::challenge::<C>(*native_mu_prime.value().take())?;
        let nested_nu_prime = nested::challenge::<C>(*native_nu_prime.value().take())?;
        let nested_mu_prime_inv = nested_mu_prime
            .invert()
            .expect("nested mu_prime must be non-zero");
        let nested_mu_prime_nu_prime = nested_mu_prime * nested_nu_prime;

        let a_poly =
            fold_revdot::fold_outer::<_, _, nested::RevdotParameters>(a, nested_mu_prime_inv);
        let b_poly =
            fold_revdot::fold_outer::<_, _, nested::RevdotParameters>(b, nested_mu_prime_nu_prime);

        builder.set_nested_a_poly(a_poly);
        builder.set_nested_b_poly(b_poly);

        Ok(())
    }

    fn compute_native_ab<'dr, D>(
        &self,
        a: FixedVec<TrackedPoly<'_, FoldKey, C::CircuitField, R>, NativeNumGroups>,
        b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups>,
        native_source: &NativeFuseProofSource<'_, C, R>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<()>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let mu_prime = *mu_prime.value().take();
        let nu_prime = *nu_prime.value().take();
        let mu_prime_inv = mu_prime.invert().expect("mu_prime must be non-zero");
        let mu_prime_nu_prime = mu_prime * nu_prime;

        let TrackedPoly {
            poly: a_poly,
            decomp: a_decomp,
        } = fold_revdot::fold_outer::<_, _, native::RevdotParameters>(a, mu_prime_inv);
        let a_poly = a_poly.into_owned();

        let b_poly =
            fold_revdot::fold_outer::<_, _, native::RevdotParameters>(b, mu_prime_nu_prime);
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

        let [a_commitment, b_commitment] = ragu_arithmetic::batch_to_affine([
            a_commitment_proj,
            B::sparse_commit(&b_poly, host_gen),
        ]);

        builder.set_native_a_poly(a_poly, a_commitment);
        builder.set_native_b_poly(b_poly, b_commitment);

        Ok(())
    }
}
