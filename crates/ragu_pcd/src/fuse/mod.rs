//! Proof fusion implementation for combining child proofs.
//!
//! Implements the core [`Application::fuse`] operation that takes two child
//! proofs and produces a new proof, computing each proof component in sequence.

mod _01_application;
mod _02_preamble;
mod _03_s_prime;
mod _04_inner_error;
mod _05_outer_error;
mod _06_ab;
mod _07_query;
mod _08_f;
mod _09_eval;
mod _10_p;
mod _11_circuits;
pub(crate) mod claims;

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, vec::CollectFixed};
use rand::CryptoRng;

use crate::{
    Application, Pcd, Proof, RAGU_TAG, internal::transcript::Transcript, proof, step::Step,
};

use claims::FuseProofSource;

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Fuse two [`Pcd`] into one using a provided [`Step`].
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness data for the [`Step`]
    /// * `left`: the left [`Pcd`] to fuse in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right [`Pcd`] to fuse in this step; must correspond to
    ///   the [`Step::Right`] header.
    pub fn fuse<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        let (left, right, application, application_data, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let (preamble, preamble_witness) =
            self.compute_preamble(rng, &left, &right, &application)?;
        let preamble_commitment = Point::constant(&mut dr, preamble.bridge.commitment)?;
        preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());

        let s_prime = self.compute_s_prime(rng, &native_registry, &left, &right)?;
        let s_prime_commitment = Point::constant(&mut dr, s_prime.bridge.commitment)?;
        s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let source = FuseProofSource {
            left: &left,
            right: &right,
        };

        let (inner_error, inner_error_witness, claims) =
            self.inner_error_terms(rng, &native_registry, &y, &z, &source)?;
        let inner_error_commitment = Point::constant(&mut dr, inner_error.bridge.commitment)?;
        inner_error_commitment.write(&mut dr, &mut transcript)?;

        // Clone-then-save: `save_state` consumes the transcript, but we need
        // the original to keep squeezing. Both paths apply the same permutation.
        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = transcript.challenge(&mut dr)?;
        let nu = transcript.challenge(&mut dr)?;

        let (outer_error, outer_error_witness, a, b) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &inner_error_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
        )?;
        let outer_error_commitment = Point::constant(&mut dr, outer_error.bridge.commitment)?;
        outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        let ab = self.compute_ab(rng, a, b, &source, &mu_prime, &nu_prime)?;
        let ab_commitment = Point::constant(&mut dr, ab.bridge.commitment)?;
        ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let (query, query_witness) =
            self.compute_query(rng, &w, &x, &y, &z, &inner_error, &left, &right)?;
        let query_commitment = Point::constant(&mut dr, query.bridge.commitment)?;
        query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let f = self.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &s_prime,
            &inner_error,
            &ab,
            &query,
            &left,
            &right,
        )?;
        let f_commitment = Point::constant(&mut dr, f.bridge.commitment)?;
        f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let (eval, eval_witness) =
            self.compute_eval(rng, &u, &left, &right, &s_prime, &inner_error, &ab, &query)?;
        let eval_commitment = Point::constant(&mut dr, eval.bridge.commitment)?;
        eval_commitment.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.challenge(&mut dr)?;

        let p = self.compute_p(
            &pre_beta,
            &u,
            &left,
            &right,
            &s_prime,
            &inner_error,
            &ab,
            &query,
            &f,
        )?;

        let challenges = proof::Challenges::new(
            &w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u, &pre_beta,
        );

        let circuits = self.compute_internal_circuits(
            rng,
            &preamble,
            &s_prime,
            &outer_error,
            &inner_error,
            &ab,
            &query,
            &f,
            &eval,
            &p,
            &preamble_witness,
            &outer_error_witness,
            &inner_error_witness,
            &query_witness,
            &eval_witness,
            &challenges,
        )?;

        let proof = Proof {
            application,
            preamble,
            s_prime,
            inner_error,
            outer_error,
            ab,
            query,
            f,
            eval,
            p,
            challenges,
            circuits,
        };

        Ok((proof.carry(application_data), application_aux))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApplicationBuilder;
    use crate::header::{Header, Suffix};
    use crate::step::{Encoded, Index, Step};
    use arithmetic::Cycle;
    use ragu_circuits::polynomials::R;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{GadgetKind, Kind},
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::Element;
    use rand::{SeedableRng, rngs::StdRng};

    type TestR = R<13>;
    const HEADER_SIZE: usize = 4;

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(200);
        type Data<'source> = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data<'source>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, witness)
        }
    }

    // Seed step: creates initial proofs from trivial inputs
    struct SeedStep;

    impl Step<Pasta> for SeedStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = Fp;
        type Aux<'source> = Fp;
        type Left = ();
        type Right = ();
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Fp>,
            _left: DriverValue<D, ()>,
            _right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
        )> {
            let output_enc = Encoded::new(dr, witness.clone())?;
            Ok((
                (
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                    output_enc,
                ),
                witness,
            ))
        }
    }

    // Fuse step: merges two TestHeader proofs
    struct FuseStep;

    impl Step<Pasta> for FuseStep {
        const INDEX: Index = Index::new(1);
        type Witness<'source> = ();
        type Aux<'source> = Fp;
        type Left = TestHeader;
        type Right = TestHeader;
        type Output = TestHeader;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
            &self,
            dr: &mut D,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            _right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
        )> {
            let left_enc = Encoded::new(dr, left.clone())?;
            let right_enc = Encoded::new(dr, left.clone())?;
            let output_enc = Encoded::new(dr, left.clone())?;
            Ok(((left_enc, right_enc, output_enc), left))
        }
    }

    fn create_test_app() -> crate::Application<'static, Pasta, TestR, HEADER_SIZE> {
        let pasta = Pasta::baked();
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(SeedStep)
            .expect("seed step registration should succeed")
            .register(FuseStep)
            .expect("fuse step registration should succeed")
            .finalize(pasta)
            .expect("finalization should succeed")
    }

    #[test]
    fn fuse_completes_without_error() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1234);

        // Seed two proofs with test data
        let left = app
            .seed(&mut rng, SeedStep, Fp::from(10u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(20u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        // Fuse the two proofs - exercisingg all 11 fuse stages
        let fused = app.fuse(&mut rng, FuseStep, (), left, right);
        assert!(fused.is_ok(), "fuse should complete without error");
    }

    #[test]
    fn fuse_application_commitment_matches_polynomial() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(5678);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(1u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(2u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        // Verify application commitment matches rx polynomial
        let expected_commitment = proof
            .application
            .rx
            .commit(Pasta::host_generators(app.params), proof.application.blind);
        assert_eq!(
            proof.application.commitment, expected_commitment,
            "application commitment should match polynomial commitment"
        );
    }

    #[test]
    fn fuse_preamble_commitment_matches_polynomial() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(9012);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(3u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(4u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        // Verify preamble native commitment matches rx polynomial
        let expected_commitment = proof.preamble.native_rx.commit(
            Pasta::host_generators(app.params),
            proof.preamble.native_blind,
        );
        assert_eq!(
            proof.preamble.native_commitment, expected_commitment,
            "preamble native commitment should match polynomial commitment"
        );
    }

    #[test]
    fn fuse_ab_commitment_matches_polynomial() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(3456);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(5u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(6u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        // Verify A polynomial commitment
        let expected_a = proof
            .ab
            .a_poly
            .commit(Pasta::host_generators(app.params), proof.ab.a_blind);
        assert_eq!(
            proof.ab.a_commitment, expected_a,
            "AB a_commitment should match polynomial commitment"
        );

        // Verify B polynomial commitment
        let expected_b = proof
            .ab
            .b_poly
            .commit(Pasta::host_generators(app.params), proof.ab.b_blind);
        assert_eq!(
            proof.ab.b_commitment, expected_b,
            "AB b_commitment should match polynomial commitment"
        );
    }

    #[test]
    fn fuse_p_evaluation_matches_polynomial() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(7890);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(7u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(8u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        // Verify p(u) = v
        let u = proof.challenges.u;
        let expected_v = proof.p.poly.eval(u);
        assert_eq!(
            proof.p.v, expected_v,
            "p.v should equal p(u) polynomial evaluation"
        );
    }

    #[test]
    fn fuse_error_m_commitment_matches_polynomial() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(1111);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(9u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(10u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        // Verify error_m native commitment
        let expected = proof.error_m.native_rx.commit(
            Pasta::host_generators(app.params),
            proof.error_m.native_blind,
        );
        assert_eq!(
            proof.error_m.native_commitment, expected,
            "error_m native commitment should match polynomial commitment"
        );
    }

    #[test]
    fn fuse_query_commitment_matches_polynomial() {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(2222);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(11u64))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(12u64))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        // Verify query native commitment
        let expected = proof
            .query
            .native_rx
            .commit(Pasta::host_generators(app.params), proof.query.native_blind);
        assert_eq!(
            proof.query.native_commitment, expected,
            "query native commitment should match polynomial commitment"
        );
    }
}
