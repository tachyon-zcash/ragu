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
    use ragu_arithmetic::Cycle;
    use ragu_circuits::polynomials::R;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::Kind,
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
            right: DriverValue<D, Fp>,
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

    fn seed_and_fuse(
        seed: u64,
        left: u64,
        right: u64,
    ) -> (
        Application<'static, Pasta, TestR, HEADER_SIZE>,
        Proof<Pasta, TestR>,
    ) {
        let app = create_test_app();
        let mut rng = StdRng::seed_from_u64(seed);

        let left = app
            .seed(&mut rng, SeedStep, Fp::from(left))
            .expect("seed should succeed");
        let left = left.0.carry(left.1);

        let right = app
            .seed(&mut rng, SeedStep, Fp::from(right))
            .expect("seed should succeed");
        let right = right.0.carry(right.1);

        let (proof, _) = app
            .fuse(&mut rng, FuseStep, (), left, right)
            .expect("fuse should succeed");

        (app, proof)
    }

    #[test]
    fn fuse_commitment_bindings_match_polynomials() {
        let (app, proof) = seed_and_fuse(1234, 10, 20);
        let host = Pasta::host_generators(app.params);
        let nested = Pasta::nested_generators(app.params);

        assert_eq!(
            proof.application.commitment,
            proof.application.rx.commit(host, proof.application.blind)
        );

        assert_eq!(
            proof.preamble.native_commitment,
            proof
                .preamble
                .native_rx
                .commit(host, proof.preamble.native_blind)
        );
        assert_eq!(
            proof.preamble.nested_commitment,
            proof
                .preamble
                .nested_rx
                .commit(nested, proof.preamble.nested_blind)
        );

        assert_eq!(
            proof.s_prime.registry_wx0_commitment,
            proof
                .s_prime
                .registry_wx0_poly
                .commit(host, proof.s_prime.registry_wx0_blind)
        );
        assert_eq!(
            proof.s_prime.registry_wx1_commitment,
            proof
                .s_prime
                .registry_wx1_poly
                .commit(host, proof.s_prime.registry_wx1_blind)
        );
        assert_eq!(
            proof.s_prime.nested_s_prime_commitment,
            proof
                .s_prime
                .nested_s_prime_rx
                .commit(nested, proof.s_prime.nested_s_prime_blind)
        );

        assert_eq!(
            proof.error_m.registry_wy_commitment,
            proof
                .error_m
                .registry_wy_poly
                .commit(host, proof.error_m.registry_wy_blind)
        );
        assert_eq!(
            proof.error_m.native_commitment,
            proof
                .error_m
                .native_rx
                .commit(host, proof.error_m.native_blind)
        );
        assert_eq!(
            proof.error_m.nested_commitment,
            proof
                .error_m
                .nested_rx
                .commit(nested, proof.error_m.nested_blind)
        );

        assert_eq!(
            proof.error_n.native_commitment,
            proof
                .error_n
                .native_rx
                .commit(host, proof.error_n.native_blind)
        );
        assert_eq!(
            proof.error_n.nested_commitment,
            proof
                .error_n
                .nested_rx
                .commit(nested, proof.error_n.nested_blind)
        );

        assert_eq!(
            proof.ab.a_commitment,
            proof.ab.a_poly.commit(host, proof.ab.a_blind)
        );
        assert_eq!(
            proof.ab.b_commitment,
            proof.ab.b_poly.commit(host, proof.ab.b_blind)
        );
        assert_eq!(
            proof.ab.nested_commitment,
            proof.ab.nested_rx.commit(nested, proof.ab.nested_blind)
        );

        assert_eq!(
            proof.query.registry_xy_commitment,
            proof
                .query
                .registry_xy_poly
                .commit(host, proof.query.registry_xy_blind)
        );
        assert_eq!(
            proof.query.native_commitment,
            proof.query.native_rx.commit(host, proof.query.native_blind)
        );
        assert_eq!(
            proof.query.nested_commitment,
            proof
                .query
                .nested_rx
                .commit(nested, proof.query.nested_blind)
        );

        assert_eq!(proof.f.commitment, proof.f.poly.commit(host, proof.f.blind));
        assert_eq!(
            proof.f.nested_commitment,
            proof.f.nested_rx.commit(nested, proof.f.nested_blind)
        );

        assert_eq!(
            proof.eval.native_commitment,
            proof.eval.native_rx.commit(host, proof.eval.native_blind)
        );
        assert_eq!(
            proof.eval.nested_commitment,
            proof.eval.nested_rx.commit(nested, proof.eval.nested_blind)
        );

        assert_eq!(
            proof.circuits.hashes_1_commitment,
            proof
                .circuits
                .hashes_1_rx
                .commit(host, proof.circuits.hashes_1_blind)
        );
        assert_eq!(
            proof.circuits.hashes_2_commitment,
            proof
                .circuits
                .hashes_2_rx
                .commit(host, proof.circuits.hashes_2_blind)
        );
        assert_eq!(
            proof.circuits.partial_collapse_commitment,
            proof
                .circuits
                .partial_collapse_rx
                .commit(host, proof.circuits.partial_collapse_blind)
        );
        assert_eq!(
            proof.circuits.full_collapse_commitment,
            proof
                .circuits
                .full_collapse_rx
                .commit(host, proof.circuits.full_collapse_blind)
        );
        assert_eq!(
            proof.circuits.compute_v_commitment,
            proof
                .circuits
                .compute_v_rx
                .commit(host, proof.circuits.compute_v_blind)
        );

        assert_eq!(proof.p.commitment, proof.p.poly.commit(host, proof.p.blind));
    }

    #[test]
    fn fuse_p_evaluation_matches_polynomial() {
        let (_app, proof) = seed_and_fuse(5678, 1, 2);
        let u = proof.challenges.u;
        assert_eq!(proof.p.v, proof.p.poly.eval(u));
    }
}
