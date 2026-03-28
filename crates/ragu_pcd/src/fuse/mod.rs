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
    /// The provided `step` must have been previously registered with this
    /// [`Application`] via [`ApplicationBuilder::register`](crate::ApplicationBuilder::register).
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
    use crate::proof::Pcd;
    use crate::step::{Encoded, Index, Step};
    use ragu_circuits::polynomials::R;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::Kind,
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{Element, poseidon::Sponge};
    use rand::{SeedableRng, rngs::StdRng};

    type TestR = R<13>;
    const HEADER_SIZE: usize = 4;

    struct TestHeader;

    impl Header<Fp> for TestHeader {
        const SUFFIX: Suffix = Suffix::new(200);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>>(
            dr: &mut D,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Element<'dr, D>> {
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
            DriverValue<D, Fp>,
        )> {
            let output_enc = Encoded::new(dr, witness.clone())?;
            Ok((
                (
                    Encoded::from_gadget(()),
                    Encoded::from_gadget(()),
                    output_enc,
                ),
                witness.clone(),
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
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Self::Left, HS>,
                Encoded<'dr, D, Self::Right, HS>,
                Encoded<'dr, D, Self::Output, HS>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, Fp>,
        )> {
            let left_enc = Encoded::new(dr, left.clone())?;
            let right_enc = Encoded::new(dr, right.clone())?;
            let mut sponge = Sponge::new(dr, Pasta::circuit_poseidon(Pasta::baked()));
            sponge.absorb(dr, left_enc.as_gadget())?;
            sponge.absorb(dr, right_enc.as_gadget())?;
            let output = sponge.squeeze(dr)?;
            let output_value = output.value().map(|v| *v);
            let output_enc = Encoded::from_gadget(output);

            Ok((
                (left_enc, right_enc, output_enc),
                output_value.clone(),
                output_value,
            ))
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

    fn seed_and_fuse(
        seed: u64,
        left: u64,
        right: u64,
    ) -> (
        Application<'static, Pasta, TestR, HEADER_SIZE>,
        Pcd<Pasta, TestR, TestHeader>,
    ) {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(seed);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(left))
            .expect("seed should succeed")
            .0;

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(right))
            .expect("seed should succeed")
            .0;

        let (pcd, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        (app, pcd)
    }

    #[test]
    fn fuse_commitment_bindings_match_polynomials() {
        let (app, pcd) = seed_and_fuse(1234, 10, 20);
        let proof = pcd.proof();
        let host = Pasta::host_generators(app.params);
        let nested = Pasta::nested_generators(app.params);

        macro_rules! assert_host_commit {
            ($poly:expr, $blind:expr, $commitment:expr) => {
                assert_eq!($poly.commit_to_affine(host, $blind), $commitment);
            };
        }

        macro_rules! assert_nested_commit {
            ($poly:expr, $blind:expr, $commitment:expr) => {
                assert_eq!($poly.commit_to_affine(nested, $blind), $commitment);
            };
        }

        assert_host_commit!(
            proof.application.rx_triple.rx,
            proof.application.rx_triple.blind,
            proof.application.rx_triple.commitment
        );
        assert_host_commit!(
            proof.preamble.native.rx,
            proof.preamble.native.blind,
            proof.preamble.native.commitment
        );
        assert_nested_commit!(
            proof.preamble.bridge.rx,
            proof.preamble.bridge.blind,
            proof.preamble.bridge.commitment
        );
        assert_host_commit!(
            proof.s_prime.native.registry_wx0_poly,
            proof.s_prime.native.registry_wx0_blind,
            proof.s_prime.native.registry_wx0_commitment
        );
        assert_host_commit!(
            proof.s_prime.native.registry_wx1_poly,
            proof.s_prime.native.registry_wx1_blind,
            proof.s_prime.native.registry_wx1_commitment
        );
        assert_nested_commit!(
            proof.s_prime.bridge.rx,
            proof.s_prime.bridge.blind,
            proof.s_prime.bridge.commitment
        );
        assert_host_commit!(
            proof.inner_error.native.registry_wy_poly,
            proof.inner_error.native.registry_wy_blind,
            proof.inner_error.native.registry_wy_commitment
        );
        assert_host_commit!(
            proof.inner_error.native.rx_triple.rx,
            proof.inner_error.native.rx_triple.blind,
            proof.inner_error.native.rx_triple.commitment
        );
        assert_nested_commit!(
            proof.inner_error.bridge.rx,
            proof.inner_error.bridge.blind,
            proof.inner_error.bridge.commitment
        );
        assert_host_commit!(
            proof.outer_error.native.rx,
            proof.outer_error.native.blind,
            proof.outer_error.native.commitment
        );
        assert_nested_commit!(
            proof.outer_error.bridge.rx,
            proof.outer_error.bridge.blind,
            proof.outer_error.bridge.commitment
        );
        assert_host_commit!(
            proof.ab.native.a_poly,
            proof.ab.native.a_blind,
            proof.ab.native.a_commitment
        );
        assert_host_commit!(
            proof.ab.native.b_poly,
            proof.ab.native.b_blind,
            proof.ab.native.b_commitment
        );
        assert_nested_commit!(
            proof.ab.bridge.rx,
            proof.ab.bridge.blind,
            proof.ab.bridge.commitment
        );
        assert_host_commit!(
            proof.query.native.registry_xy_poly,
            proof.query.native.registry_xy_blind,
            proof.query.native.registry_xy_commitment
        );
        assert_host_commit!(
            proof.query.native.rx_triple.rx,
            proof.query.native.rx_triple.blind,
            proof.query.native.rx_triple.commitment
        );
        assert_nested_commit!(
            proof.query.bridge.rx,
            proof.query.bridge.blind,
            proof.query.bridge.commitment
        );
        assert_host_commit!(
            proof.f.native.poly,
            proof.f.native.blind,
            proof.f.native.commitment
        );
        assert_nested_commit!(
            proof.f.bridge.rx,
            proof.f.bridge.blind,
            proof.f.bridge.commitment
        );
        assert_host_commit!(
            proof.eval.native.rx,
            proof.eval.native.blind,
            proof.eval.native.commitment
        );
        assert_nested_commit!(
            proof.eval.bridge.rx,
            proof.eval.bridge.blind,
            proof.eval.bridge.commitment
        );
        assert_host_commit!(
            proof.circuits.hashes_1.rx,
            proof.circuits.hashes_1.blind,
            proof.circuits.hashes_1.commitment
        );
        assert_host_commit!(
            proof.circuits.hashes_2.rx,
            proof.circuits.hashes_2.blind,
            proof.circuits.hashes_2.commitment
        );
        assert_host_commit!(
            proof.circuits.inner_collapse.rx,
            proof.circuits.inner_collapse.blind,
            proof.circuits.inner_collapse.commitment
        );
        assert_host_commit!(
            proof.circuits.outer_collapse.rx,
            proof.circuits.outer_collapse.blind,
            proof.circuits.outer_collapse.commitment
        );
        assert_host_commit!(
            proof.circuits.compute_v.rx,
            proof.circuits.compute_v.blind,
            proof.circuits.compute_v.commitment
        );
        assert_host_commit!(
            proof.p.native.poly,
            proof.p.native.blind,
            proof.p.native.commitment
        );
    }

    #[test]
    fn fuse_p_evaluation_matches_polynomial() {
        let (_app, pcd) = seed_and_fuse(5678, 1, 2);
        let proof = pcd.proof();
        let u = proof.challenges.u;
        assert_eq!(proof.p.native.v, proof.p.native.poly.eval(u));
    }
}
