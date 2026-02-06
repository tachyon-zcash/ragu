//! Proof fusion implementation for combining child proofs.
//!
//! Implements the core [`Application::fuse`] operation that takes two child
//! proofs and produces a new proof, computing each proof component in sequence.

mod _01_application;
mod _02_preamble;
mod _03_s_prime;
mod _04_error_m;
mod _05_error_n;
mod _06_ab;
mod _07_query;
mod _08_f;
mod _09_eval;
mod _10_p;
mod _11_circuits;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::{Rank, structured},
    registry::CircuitIndex,
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{GadgetExt, Point, poseidon::Sponge, vec::CollectFixed};
use rand::CryptoRng;

use crate::{
    Application, Pcd, Proof,
    components::claims::{Source, native::RxComponent},
    proof,
    step::Step,
};

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
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        let (left, right, application, application_aux) =
            self.compute_application_proof(rng, step, witness, left, right)?;

        let mut dr = Emulator::execute();
        let mut transcript = Sponge::new(&mut dr, C::circuit_poseidon(self.params));

        let (preamble, preamble_witness) =
            self.compute_preamble(rng, &left, &right, &application)?;
        Point::constant(&mut dr, preamble.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let w = transcript.squeeze(&mut dr)?;

        let s_prime = self.compute_s_prime(rng, &w, &left, &right)?;
        Point::constant(&mut dr, s_prime.nested_s_prime_commitment)?
            .write(&mut dr, &mut transcript)?;
        let y = transcript.squeeze(&mut dr)?;
        let z = transcript.squeeze(&mut dr)?;

        let (error_m, error_m_witness, claims) =
            self.compute_errors_m(rng, &w, &y, &z, &left, &right)?;
        Point::constant(&mut dr, error_m.nested_commitment)?.write(&mut dr, &mut transcript)?;

        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = transcript.squeeze(&mut dr)?;
        let nu = transcript.squeeze(&mut dr)?;

        let (error_n, error_n_witness, a, b) = self.compute_errors_n(
            rng,
            &preamble_witness,
            &error_m_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
        )?;
        Point::constant(&mut dr, error_n.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.squeeze(&mut dr)?;
        let nu_prime = transcript.squeeze(&mut dr)?;

        let ab = self.compute_ab(rng, a, b, &mu_prime, &nu_prime)?;
        Point::constant(&mut dr, ab.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let x = transcript.squeeze(&mut dr)?;

        let (query, query_witness) =
            self.compute_query(rng, &w, &x, &y, &z, &error_m, &left, &right)?;
        Point::constant(&mut dr, query.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let alpha = transcript.squeeze(&mut dr)?;

        let f = self.compute_f(
            rng, &w, &y, &z, &x, &alpha, &s_prime, &error_m, &ab, &query, &left, &right,
        )?;
        Point::constant(&mut dr, f.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let u = transcript.squeeze(&mut dr)?;

        let (eval, eval_witness) =
            self.compute_eval(rng, &u, &left, &right, &s_prime, &error_m, &ab, &query)?;
        Point::constant(&mut dr, eval.nested_commitment)?.write(&mut dr, &mut transcript)?;
        let pre_beta = transcript.squeeze(&mut dr)?;

        let p = self.compute_p(
            &pre_beta, &u, &left, &right, &s_prime, &error_m, &ab, &query, &f,
        )?;

        let challenges = proof::Challenges::new(
            &w, &y, &z, &mu, &nu, &mu_prime, &nu_prime, &x, &alpha, &u, &pre_beta,
        );

        let circuits = self.compute_internal_circuits(
            rng,
            &preamble,
            &s_prime,
            &error_n,
            &error_m,
            &ab,
            &query,
            &f,
            &eval,
            &p,
            &preamble_witness,
            &error_n_witness,
            &error_m_witness,
            &query_witness,
            &eval_witness,
            &challenges,
        )?;

        Ok((
            Proof {
                application,
                preamble,
                s_prime,
                error_n,
                error_m,
                ab,
                query,
                f,
                eval,
                p,
                challenges,
                circuits,
            },
            application_aux,
        ))
    }
}

pub(crate) struct FuseProofSource<'rx, C: Cycle, R: Rank> {
    pub(crate) left: &'rx Proof<C, R>,
    pub(crate) right: &'rx Proof<C, R>,
}

impl<'rx, C: Cycle, R: Rank> Source for FuseProofSource<'rx, C, R> {
    type RxComponent = RxComponent;
    type Rx = &'rx structured::Polynomial<C::CircuitField, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
        use RxComponent::*;
        let (left_poly, right_poly) = match component {
            AbA => (&self.left.ab.a_poly, &self.right.ab.a_poly),
            AbB => (&self.left.ab.b_poly, &self.right.ab.b_poly),
            Application => (&self.left.application.rx, &self.right.application.rx),
            Hashes1 => (
                &self.left.circuits.hashes_1_rx,
                &self.right.circuits.hashes_1_rx,
            ),
            Hashes2 => (
                &self.left.circuits.hashes_2_rx,
                &self.right.circuits.hashes_2_rx,
            ),
            PartialCollapse => (
                &self.left.circuits.partial_collapse_rx,
                &self.right.circuits.partial_collapse_rx,
            ),
            FullCollapse => (
                &self.left.circuits.full_collapse_rx,
                &self.right.circuits.full_collapse_rx,
            ),
            ComputeV => (
                &self.left.circuits.compute_v_rx,
                &self.right.circuits.compute_v_rx,
            ),
            Preamble => (
                &self.left.preamble.native_rx,
                &self.right.preamble.native_rx,
            ),
            ErrorM => (&self.left.error_m.native_rx, &self.right.error_m.native_rx),
            ErrorN => (&self.left.error_n.native_rx, &self.right.error_n.native_rx),
            Query => (&self.left.query.native_rx, &self.right.query.native_rx),
            Eval => (&self.left.eval.native_rx, &self.right.eval.native_rx),
        };
        [left_poly, right_poly].into_iter()
    }

    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
        [
            self.left.application.circuit_id,
            self.right.application.circuit_id,
        ]
        .into_iter()
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
            let right_enc = Encoded::new(dr, right.clone())?;
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
