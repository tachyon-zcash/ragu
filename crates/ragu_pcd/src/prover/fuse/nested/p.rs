//! Nested p prover phase.

use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use ragu_primitives::{Uendo, lift_endoscalar};

use crate::{
    Application, Proof,
    profile::ProfiledCycle,
    prover::{
        fuse::nested::{f::NestedF, inner_error::NestedRegistryWy, s_prime::NestedSPrime},
        proof_builder::ProofBuilder,
    },
};

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Accumulates the nested batch into $p_n(X)$, in [`pcs::Batch::evaluated`](crate::protocol::nested::pcs::Batch::evaluated)
    /// order after $f_n$, and runs the native endoscaling over the committed
    /// points: $P_n$ is the walk's last interstitial, which the native steps
    /// enforce and `bind_endoscalar` pins to the unified instance.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::prover::fuse) fn compute_nested_p<RNG: rand::CryptoRng>(
        &self,
        rng: &mut RNG,
        beta_endo: Uendo,
        left: &Proof<C, R>,
        right: &Proof<C, R>,
        nested_s_prime: &NestedSPrime<C, R>,
        nested_registry_wy: &NestedRegistryWy<C, R>,
        nested_f: &NestedF<C, R>,
        native_points: &NativeInputs<C>,
        builder: &mut ProofBuilder<'_, C, R, B>,
    ) -> Result<NativeWalk<C>> {
        let beta: C::ScalarField = lift_endoscalar(beta_endo);
        let batch = self.nested_batch(builder, nested_s_prime, nested_registry_wy, left, right);

        let mut poly = nested_f.poly.clone();
        for evaluated in batch.evaluated() {
            poly.scale(beta);
            poly.add_assign(evaluated);
        }

        let (p_commitment, walk) =
            self.compute_native_endoscaling(rng, beta_endo, native_points, builder)?;
        // A child can carry a polynomial inconsistent with its cached point.
        // Keep the debug consistency check fallible for such witnesses.
        #[cfg(debug_assertions)]
        if B::sparse_commit_to_affine(&poly, C::nested_generators(self.params)) != p_commitment {
            return Err(ragu_core::Error::InvalidWitness(
                "nested P does not match its accumulated polynomial".into(),
            ));
        }
        builder.set_nested_p_poly(poly, p_commitment);

        Ok(walk)
    }
}

use crate::prover::fuse::native::p::{NativeInputs, NativeWalk};
