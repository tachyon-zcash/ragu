//! Nested f prover phase.
use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Cycle, Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::Element;

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    protocol::{nested, nested::pcs},
    prover::{
        fuse::nested::{inner_error::NestedRegistryWy, s_prime::NestedSPrime},
        proof_builder::ProofBuilder,
    },
};

/// Ephemeral nested-field data for $f_n(X)$, used only during the fuse step.
pub(in crate::prover::fuse) struct NestedF<C: Cycle, R: Rank> {
    pub(in crate::prover::fuse) poly: sparse::Polynomial<C::ScalarField, R>,
    pub(in crate::prover::fuse) commitment: C::NestedCurve,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Builds $f_n(X)$: the $\alpha_n$-batched quotients of every opening
    /// in the nested batch, in [`pcs::Batch::queries`] order.
    pub(in crate::prover::fuse) fn compute_nested_f(
        &self,
        batch: &pcs::Batch<'_, C, R>,
        challenges: pcs::Challenges<C::ScalarField>,
        alpha: C::ScalarField,
    ) -> NestedF<C, R> {
        use udon::polynomial::divide_linear_rev;

        let iters: Vec<_> = batch
            .queries(challenges)
            .map(|(poly, point)| divide_linear_rev(poly.iter_coeffs(), point))
            .collect();

        let poly = alpha_batched_quotients::<_, R>(iters, alpha);
        let commitment = B::sparse_commit_to_affine(&poly, C::nested_generators(self.params));

        NestedF { poly, commitment }
    }

    /// The nested batch this step opens, over the nested polynomials the
    /// builder has committed so far.
    pub(in crate::prover::fuse) fn nested_batch<'a>(
        &self,
        builder: &'a ProofBuilder<'_, C, R, B>,
        nested_s_prime: &'a NestedSPrime<C, R>,
        nested_registry_wy: &'a NestedRegistryWy<C, R>,
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
    ) -> pcs::Batch<'a, C, R> {
        pcs::Batch {
            left,
            right,
            registry_wx0: &nested_s_prime.registry_wx0_poly,
            registry_wx1: &nested_s_prime.registry_wx1_poly,
            registry_wy: &nested_registry_wy.poly,
            registry_xy: builder.nested_registry_xy_poly(),
            a: builder.nested_a_poly(),
            b: builder.nested_b_poly(),
            online_fq: builder.online_fq_polynomials(),
        }
    }

    /// The nested challenges this step's openings are at, derived from the
    /// native ones (see [`nested::challenge`]).
    pub(in crate::prover::fuse) fn nested_challenges<'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        w: &Element<'dr, D>,
        x: &Element<'dr, D>,
        y: &Element<'dr, D>,
        z: &Element<'dr, D>,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
    ) -> Result<pcs::Challenges<C::ScalarField>> {
        Ok(pcs::Challenges {
            w: nested::challenge::<C>(*w.value().take())?,
            x: nested::challenge::<C>(*x.value().take())?,
            y: nested::challenge::<C>(*y.value().take())?,
            z: nested::challenge::<C>(*z.value().take())?,
            left: pcs::ChildChallenges::of(left)?,
            right: pcs::ChildChallenges::of(right)?,
        })
    }
}

use crate::prover::fuse::quotient::alpha_batched_quotients;
