//! Native ab prover phase.
use alloc::vec::Vec;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver, maybe::Maybe};
use ragu_primitives::{Element, vec::FixedVec};
use udon::curve::Affine;

use crate::{
    Application,
    profile::ProfiledCycle,
    protocol::{fold_revdot, native},
    prover::{
        fuse::claims::{FoldKey, NativeFuseProofSource, TrackedPoly},
        proof_builder::ProofBuilder,
    },
};

pub(in crate::prover::fuse) type NativeNumGroups<P> =
    <native::RevdotParameters<P> as fold_revdot::Parameters>::NumGroups;

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    pub(in crate::prover::fuse) fn compute_native_ab<'dr, D>(
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
