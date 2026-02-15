//! Compressed proof structures and operations.

use alloc::vec::Vec;
use arithmetic::{CurveAffine, Cycle};
use ff::PrimeField;
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use rand::CryptoRng;

use super::transcript::Transcript;
use super::{prover, verifier};
use crate::proof::Proof;

/// IPA proof (O(log n) size).
#[derive(Clone, Debug)]
pub struct IpaProof<C: CurveAffine> {
    /// Commitment to blinding polynomial S.
    pub s_commitment: C,
    /// Cross-term commitments (L_j, R_j) per round.
    pub rounds: Vec<(C, C)>,
    /// Final coefficient.
    pub c: C::ScalarExt,
    /// Blinding factor.
    pub f: C::ScalarExt,
}

/// Succinct proof for external verification.
#[derive(Clone, Debug)]
pub struct CompressedProof<C: Cycle> {
    /// P polynomial commitment.
    pub p_commitment: C::HostCurve,
    /// Evaluation point.
    pub u: C::CircuitField,
    /// Claimed evaluation P(u).
    pub v: C::CircuitField,
    /// IPA opening proof.
    pub ipa: IpaProof<C::HostCurve>,
    /// Challenge x.
    pub x: C::CircuitField,
    /// Challenge y.
    pub y: C::CircuitField,
    /// A polynomial commitment.
    pub a_commitment: C::HostCurve,
    /// B polynomial commitment.
    pub b_commitment: C::HostCurve,
    /// Inner product A·B.
    pub c: C::CircuitField,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> crate::Application<'_, C, R, HEADER_SIZE> {
    /// Compress an uncompressed proof into succinct form.
    pub fn compress<RNG: CryptoRng + rand::RngCore>(
        &self,
        proof: &Proof<C, R>,
        rng: &mut RNG,
    ) -> Result<CompressedProof<C>>
    where
        C::CircuitField: PrimeField,
    {
        let mut transcript = Transcript::<C>::new(C::circuit_poseidon(self.params));

        // Absorb P polynomial claim
        transcript.absorb_point(&proof.p.commitment);
        transcript.absorb_scalar(&proof.challenges.u);
        transcript.absorb_scalar(&proof.p.v);

        // Absorb A·B inner product claim
        transcript.absorb_point(&proof.ab.a_commitment);
        transcript.absorb_point(&proof.ab.b_commitment);
        transcript.absorb_scalar(&proof.ab.c);

        // Absorb challenges
        transcript.absorb_scalar(&proof.challenges.x);
        transcript.absorb_scalar(&proof.challenges.y);

        let ipa = prover::create_proof::<C, _, _>(
            C::host_generators(self.params),
            rng,
            &mut transcript,
            &proof.p.poly,
            proof.p.blind,
            proof.challenges.u,
        );

        Ok(CompressedProof {
            p_commitment: proof.p.commitment,
            u: proof.challenges.u,
            v: proof.p.v,
            ipa,
            x: proof.challenges.x,
            y: proof.challenges.y,
            a_commitment: proof.ab.a_commitment,
            b_commitment: proof.ab.b_commitment,
            c: proof.ab.c,
        })
    }

    /// Verify a compressed proof.
    pub fn verify_compressed(&self, compressed: &CompressedProof<C>) -> Result<bool>
    where
        C::CircuitField: PrimeField,
    {
        let mut transcript = Transcript::<C>::new(C::circuit_poseidon(self.params));

        // Absorb P polynomial claim
        transcript.absorb_point(&compressed.p_commitment);
        transcript.absorb_scalar(&compressed.u);
        transcript.absorb_scalar(&compressed.v);

        // Absorb A·B inner product claim
        transcript.absorb_point(&compressed.a_commitment);
        transcript.absorb_point(&compressed.b_commitment);
        transcript.absorb_scalar(&compressed.c);

        // Absorb challenges
        transcript.absorb_scalar(&compressed.x);
        transcript.absorb_scalar(&compressed.y);

        Ok(verifier::verify_proof::<C, _>(
            C::host_generators(self.params),
            &mut transcript,
            compressed.p_commitment,
            compressed.u,
            compressed.v,
            &compressed.ipa,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::ApplicationBuilder;
    use ragu_circuits::polynomials::R;
    use ragu_pasta::Pasta;
    use rand::{SeedableRng, rngs::StdRng};

    type TestR = R<13>;
    const HEADER_SIZE: usize = 4;

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create test application")
    }

    #[test]
    fn test_compress_and_verify() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(54321);

        let proof = app.trivial_proof();
        let compressed = app.compress(&proof, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed).unwrap());
    }
}
