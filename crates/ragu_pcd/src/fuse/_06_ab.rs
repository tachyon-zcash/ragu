//! Commits to the collapsed revdot claim polynomials $A$ and $B$.
//!
//! This creates the [`proof::AB`] component of the proof, which contains the
//! claimed (folded) revdot polynomials $A$ and $B$.
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

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, sparse},
    staging::StageExt,
};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;

use alloc::vec::Vec;

use crate::{
    Application,
    internal::{fold_revdot, native, nested},
    proof,
};

use super::claims::{FoldKey, FuseProofSource, TrackedPoly};

type NativeNumGroups = <native::RevdotParameters as fold_revdot::Parameters>::NumGroups;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_ab<'dr, D>(
        &self,
        rng: &mut impl CryptoRng,
        a: FixedVec<TrackedPoly<'_, FoldKey, C::CircuitField, R>, NativeNumGroups>,
        b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups>,
        source: &FuseProofSource<'_, C, R>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
    ) -> Result<proof::AB<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField>,
    {
        let native = self.compute_native_ab(a, b, source, mu_prime, nu_prime)?;

        let bridge = proof::Bridge::commit(
            self.params,
            nested::stages::ab::Stage::<C::HostCurve, R>::rx(
                C::ScalarField::random(&mut *rng),
                &nested::stages::ab::Witness {
                    a: native.a_commitment,
                    b: native.b_commitment,
                },
            )?,
        );

        Ok(proof::AB { native, bridge })
    }

    fn compute_native_ab<'dr, D>(
        &self,
        a: FixedVec<TrackedPoly<'_, FoldKey, C::CircuitField, R>, NativeNumGroups>,
        b: FixedVec<sparse::Polynomial<C::CircuitField, R>, NativeNumGroups>,
        source: &FuseProofSource<'_, C, R>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
    ) -> Result<proof::NativeAB<C, R>>
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
                let commitment = source.get(key);
                msm.push((coeff, commitment));
            }

            ragu_arithmetic::mul(msm.iter().map(|(c, _)| c), msm.iter().map(|(_, b)| b))
        };

        let [a_commitment, b_commitment] =
            ragu_arithmetic::batch_to_affine([a_commitment_proj, b_poly.commit(host_gen)]);

        let c = a_poly.revdot(&b_poly);

        Ok(proof::NativeAB {
            a_poly,
            a_commitment,
            b_poly,
            b_commitment,
            c,
        })
    }
}
