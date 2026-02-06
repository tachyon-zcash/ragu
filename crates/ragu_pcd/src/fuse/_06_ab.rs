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

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    polynomials::{Rank, structured},
    staging::StageExt,
};
use ragu_core::{
    Result,
    drivers::Driver,
    maybe::{Always, Maybe},
};
use ragu_primitives::{Element, vec::FixedVec};
use rand::CryptoRng;

use crate::{
    Application,
    circuits::nested,
    components::fold_revdot::{self, NativeParameters},
    proof,
};

type NativeN = <NativeParameters as fold_revdot::Parameters>::N;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub(super) fn compute_ab<'dr, D, RNG: CryptoRng>(
        &self,
        rng: &mut RNG,
        a: FixedVec<structured::Polynomial<C::CircuitField, R>, NativeN>,
        b: FixedVec<structured::Polynomial<C::CircuitField, R>, NativeN>,
        mu_prime: &Element<'dr, D>,
        nu_prime: &Element<'dr, D>,
    ) -> Result<proof::AB<C, R>>
    where
        D: Driver<'dr, F = C::CircuitField, MaybeKind = Always<()>>,
    {
        let mu_prime = *mu_prime.value().take();
        let nu_prime = *nu_prime.value().take();
        let mu_prime_inv = mu_prime.invert().expect("mu_prime must be non-zero");
        let mu_prime_nu_prime = mu_prime * nu_prime;

        let a_poly = fold_revdot::fold_polys_n::<_, R, NativeParameters>(a, mu_prime_inv);
        let a_blind = C::CircuitField::random(&mut *rng);
        let a_commitment = a_poly.commit(C::host_generators(self.params), a_blind);

        let b_poly = fold_revdot::fold_polys_n::<_, R, NativeParameters>(b, mu_prime_nu_prime);
        let b_blind = C::CircuitField::random(&mut *rng);
        let b_commitment = b_poly.commit(C::host_generators(self.params), b_blind);

        let c = a_poly.revdot(&b_poly);

        let nested_ab_witness = nested::stages::ab::Witness {
            a: a_commitment,
            b: b_commitment,
        };
        let nested_rx = nested::stages::ab::Stage::<C::HostCurve, R>::rx(&nested_ab_witness)?;
        let nested_blind = C::ScalarField::random(&mut *rng);
        let nested_commitment = nested_rx.commit(C::nested_generators(self.params), nested_blind);

        Ok(proof::AB {
            a_poly,
            a_blind,
            a_commitment,
            b_poly,
            b_blind,
            b_commitment,
            c,
            nested_rx,
            nested_blind,
            nested_commitment,
        })
    }
}
