//! Compressed proof structures and operations.

use alloc::vec::Vec;
use ff::{Field, PrimeField};
use ragu_arithmetic::{CurveAffine, Cycle, FixedGenerators, mul, revdot_poly};
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
    /// IPA opening proof for P(u) = v.
    pub ipa: IpaProof<C::HostCurve>,
    /// Challenge x.
    pub x: C::CircuitField,
    /// Challenge y.
    pub y: C::CircuitField,
    /// A polynomial commitment.
    pub a_commitment: C::HostCurve,
    /// B polynomial commitment.
    pub b_commitment: C::HostCurve,
    /// Inner product A·B (claimed value).
    pub c: C::CircuitField,
    /// Commitment to revdot reduction polynomial p where p(0) = c.
    pub p_ab_commitment: C::HostCurve,
    /// IPA opening proof for p(0) = c.
    pub ipa_ab: IpaProof<C::HostCurve>,
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
        let generators = C::host_generators(self.params);
        let mut transcript = Transcript::<C>::new(C::circuit_poseidon(self.params));

        // Compute the revdot reduction polynomial p where p(0) = revdot(a, b) = c
        let a_coeffs: Vec<_> = proof.ab.a_poly.iter_coeffs().collect();
        let b_coeffs: Vec<_> = proof.ab.b_poly.iter_coeffs().collect();
        let p_ab_coeffs = revdot_poly(&a_coeffs, &b_coeffs);

        // Commit to p_ab with fresh blinding factor
        let p_ab_blind = C::CircuitField::random(&mut *rng);
        let p_ab_commitment = mul(
            p_ab_coeffs.iter().chain(Some(&p_ab_blind)),
            generators
                .g()
                .iter()
                .take(p_ab_coeffs.len())
                .chain(Some(generators.h())),
        )
        .into();

        // Absorb P polynomial claim
        transcript.absorb_point(&proof.p.commitment);
        transcript.absorb_scalar(&proof.challenges.u);
        transcript.absorb_scalar(&proof.p.v);

        // Absorb A·B inner product claim and revdot reduction commitment
        transcript.absorb_point(&proof.ab.a_commitment);
        transcript.absorb_point(&proof.ab.b_commitment);
        transcript.absorb_scalar(&proof.ab.c);
        transcript.absorb_point(&p_ab_commitment);

        // Absorb challenges
        transcript.absorb_scalar(&proof.challenges.x);
        transcript.absorb_scalar(&proof.challenges.y);

        // IPA proof for P(u) = v
        let ipa = prover::create_proof::<C, _, _>(
            generators,
            rng,
            &mut transcript,
            &proof.p.poly,
            proof.p.blind,
            proof.challenges.u,
        );

        // IPA proof for p_ab(0) = c
        let ipa_ab = prover::create_proof::<C, _, _>(
            generators,
            rng,
            &mut transcript,
            &p_ab_coeffs,
            p_ab_blind,
            C::CircuitField::ZERO, // evaluating at 0
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
            p_ab_commitment,
            ipa_ab,
        })
    }

    /// Verify a compressed proof.
    pub fn verify_compressed(&self, compressed: &CompressedProof<C>) -> Result<bool>
    where
        C::CircuitField: PrimeField,
    {
        let generators = C::host_generators(self.params);
        let mut transcript = Transcript::<C>::new(C::circuit_poseidon(self.params));

        // Absorb P polynomial claim
        transcript.absorb_point(&compressed.p_commitment);
        transcript.absorb_scalar(&compressed.u);
        transcript.absorb_scalar(&compressed.v);

        // Absorb A·B inner product claim and revdot reduction commitment
        transcript.absorb_point(&compressed.a_commitment);
        transcript.absorb_point(&compressed.b_commitment);
        transcript.absorb_scalar(&compressed.c);
        transcript.absorb_point(&compressed.p_ab_commitment);

        // Absorb challenges
        transcript.absorb_scalar(&compressed.x);
        transcript.absorb_scalar(&compressed.y);

        // Verify IPA proof for P(u) = v
        let p_ok = verifier::verify_proof::<C, _>(
            generators,
            &mut transcript,
            compressed.p_commitment,
            compressed.u,
            compressed.v,
            &compressed.ipa,
        );

        // Verify IPA proof for p_ab(0) = c
        let ab_ok = verifier::verify_proof::<C, _>(
            generators,
            &mut transcript,
            compressed.p_ab_commitment,
            C::CircuitField::ZERO, // evaluating at 0
            compressed.c,
            &compressed.ipa_ab,
        );

        Ok(p_ok && ab_ok)
    }
}

#[cfg(test)]
mod tests {
    use crate::ApplicationBuilder;
    use ragu_arithmetic::{Cycle, revdot_poly};
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

    #[test]
    fn test_revdot_reduction_correctness() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(12345);

        let proof = app.trivial_proof();

        // Verify that revdot(a, b) = c
        let a_coeffs: Vec<_> = proof.ab.a_poly.iter_coeffs().collect();
        let b_coeffs: Vec<_> = proof.ab.b_poly.iter_coeffs().collect();
        let revdot: <Pasta as Cycle>::CircuitField = a_coeffs
            .iter()
            .zip(b_coeffs.iter().rev())
            .map(|(&x, &y)| x * y)
            .sum();
        assert_eq!(revdot, proof.ab.c, "revdot(a, b) should equal c");

        // Verify p(0) = revdot(a, b)
        let p = revdot_poly(&a_coeffs, &b_coeffs);
        assert_eq!(p[0], revdot, "p(0) should equal revdot(a, b)");

        // Compress and verify
        let compressed = app.compress(&proof, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed).unwrap());
    }
}
