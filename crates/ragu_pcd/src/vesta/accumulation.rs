use crate::accumulator::CycleAccumulator;
use crate::engine::CycleEngine;
use crate::nested_encoding::b_stage::BInnerStage;
use crate::nested_encoding::d_stage::{ChallengeCompositeCircuit, D1InnerStage, D2InnerStage};
use crate::transcript::AccumulationTranscript;
use crate::utilities::dummy_circuits::Circuits;
use crate::vesta::structures::{A, B, SPrime, SPrimePrime};
use arithmetic::{CurveAffine, Cycle, FixedGenerators};
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::{
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::{Error, Result};
use ragu_pasta::Fp;
use rand::rngs::OsRng;
use rand::thread_rng;

impl<'a, C: Cycle + Default, R: Rank> CycleEngine<'a, C, R> {
    /// Executes the Vesta-side accumulation step.
    ///
    /// This is an Fp round: computations occur over Fp, and commitments
    /// are made on the Vesta host curve.
    pub fn accumulation_vesta(
        mesh: &Mesh<'_, C::CircuitField, R>,
        witnesses: &[C::CircuitField],
        acc1: &CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
        acc2: &CycleAccumulator<C::HostCurve, C::NestedCurve, R>,
        cycle: &C,
    ) -> Result<()>
    where
        C: Cycle<CircuitField = Fp>,
    {
        // Mirror the dummy circuits instantiated in the mesh.
        const N: usize = 4;
        let circuits = Circuits::new();
        let circuit_list = [&circuits.s3, &circuits.s4, &circuits.s10, &circuits.s19];

        // Intantiate a DUMMY transcript object.
        let mut transcript = AccumulationTranscript::<C::CircuitField>::new();

        // TODO: Determine the endoscaling operations, representing deferreds from the other curve.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process the application circuits. The witness polynomials
        // r(X) are over Fp, and produce commitments to Vesta points.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut a_polys = Vec::with_capacity(N + 2);
        let mut ky = Vec::with_capacity(N);

        for (&witness, circuit) in witnesses.iter().zip(circuit_list.iter()) {
            let (rx_poly, instance) = circuit.rx::<R>(witness)?;
            let blinding = C::CircuitField::random(OsRng);
            let commitment = rx_poly.commit(cycle.host_generators(), blinding);

            a_polys.push(A {
                poly: rx_poly,
                blinding,
                commitment,
            });

            ky.push(circuit.ky(instance)?);
        }

        // Append the previous A accumulator polynomials.
        a_polys.push(A {
            poly: acc1.accumulator.witness.a_poly.clone(),
            blinding: acc1.accumulator.witness.a_blinding,
            commitment: acc1.accumulator.instance.a,
        });
        a_polys.push(A {
            poly: acc2.accumulator.witness.a_poly.clone(),
            blinding: acc2.accumulator.witness.a_blinding,
            commitment: acc2.accumulator.instance.a,
        });

        // TRANSCRIPT: Absorb instance values (ky).
        for instance in &ky {
            instance.iter().for_each(|&s| transcript.absorb_scalar(s));
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Construct B staging polynomial. This uses a two-layer nested encoding.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Collect application circuit commitments (Vesta points).
        let a_commitments: [C::HostCurve; N + 2] = a_polys
            .iter()
            .map(|c| c.commitment)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(N))?;

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments.
        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).

        type BStagingPolynomial<C, const N: usize> = BInnerStage<C, N>;

        let b_inner_rx = <BStagingPolynomial<C::HostCurve, { N + 2 }> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&a_commitments)?;

        let b_blinding = C::ScalarField::random(OsRng);
        let b_nested_commitment = b_inner_rx.commit(cycle.nested_generators(), b_blinding);

        // TRANSCRIPT: Absorb B stage commitment before deriving w challenge.
        transcript.absorb_point(b_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: W challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Derive w challenge from B commitment using Poseidon hash.
        //
        // NOTE: for now, this is a placeholder that we'll replace with an actual
        // call to Poseidon. We compute this off-circuit that allows us to continue
        // with the computation, similiar to predict(), and then later verify
        // it was computed properly inside the circuit.
        let binding = b_nested_commitment.coordinates().unwrap();
        let w_challenge = binding.x();

        // TRANSCRIPT: Absorb w challenge.
        transcript.absorb_scalar(*w_challenge);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: S' Mesh Polynomials
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S': M(w, x_i, Y) polynomials for mesh consistency checks.
        let s1_poly_acc1 = mesh.wx(*w_challenge, acc1.accumulator.instance.x.0);
        let s1_blinding_acc1 = C::CircuitField::random(thread_rng());
        let s1_commitment_acc1 = s1_poly_acc1.commit(cycle.host_generators(), s1_blinding_acc1);

        let s1_poly_acc2 = mesh.wx(*w_challenge, acc2.accumulator.instance.x.0);
        let s1_blinding_acc2 = C::CircuitField::random(thread_rng());
        let s1_commitment_acc2 = s1_poly_acc2.commit(cycle.host_generators(), s1_blinding_acc2);

        let s_prime = [
            SPrime {
                poly: s1_poly_acc1,
                blinding: s1_blinding_acc1,
                commitment: s1_commitment_acc1,
            },
            SPrime {
                poly: s1_poly_acc2,
                blinding: s1_blinding_acc2,
                commitment: s1_commitment_acc2,
            },
        ];

        let s_prime_commitments = [s_prime[0].commitment, s_prime[1].commitment];

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: D1 Two-Layer Nested Encoding
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER (Fq): Staging polynomial witnesses 2 Vesta S' commitments.
        // OUTER LAYER (Pallas): Commit to staging polynomial using nested generators.

        let d1_inner_rx = <D1InnerStage<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &s_prime_commitments,
        )?;

        let d1_blinding = C::ScalarField::random(OsRng);
        let d1_nested_commitment = d1_inner_rx.commit(cycle.nested_generators(), d1_blinding);

        transcript.absorb_point(d1_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Y challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Derive y challenge from D1 commitment using Poseidon hash.
        let binding = d1_nested_commitment.coordinates().unwrap();
        let y_challenge = binding.x();

        // TRANSCRIPT: Absorb w challenge.
        transcript.absorb_scalar(*y_challenge);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: S'' Mesh Polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S'': M(w, X, y_i) polynomial for mesh consistency checks.
        let s2_poly = mesh.wy(*w_challenge, *y_challenge);
        let s2_blinding = C::CircuitField::random(thread_rng());
        let s2_commitment = s2_poly.commit(cycle.host_generators(), s2_blinding);

        let s2 = SPrimePrime {
            poly: s2_poly,
            blinding: s2_blinding,
            commitment: s2_commitment,
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: D2 Two-Layer Nested Encoding
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER (Fq): Staging polynomial witnesses 1 Vesta S' commitments.
        // OUTER LAYER (Pallas): Commit to staging polynomial using nested generators.

        let d2_inner_rx =
            <D2InnerStage<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s2_commitment])?;

        let d2_blinding = C::ScalarField::random(OsRng);
        let d2_nested_commitment = d2_inner_rx.commit(cycle.nested_generators(), d2_blinding);

        transcript.absorb_point(d2_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Z challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Derive z challenge from D2 commitment using Poseidon hash.
        let binding = d2_nested_commitment.coordinates().unwrap();
        let z_challenge = binding.x();

        // TRANSCRIPT: Absorb z hallenge.
        transcript.absorb_scalar(*z_challenge);

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Composite circuit: verify all challenges in-circuit.
        ///////////////////////////////////////////////////////////////////////////////////////

        use crate::nested_encoding::d_stage::CompositeChallengeWitness;

        let composite_witness = CompositeChallengeWitness {
            b_nested_commitment,
            d1_nested_commitment,
            d2_nested_commitment,
        };

        let composite_circuit =
            Staged::<Fp, R, _>::new(ChallengeCompositeCircuit::<C::NestedCurve>::new());

        let (composite_rx, composite_aux) = composite_circuit.rx::<R>(composite_witness)?;

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Compute B polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        let circuit_ids: [C::CircuitField; N] =
            core::array::from_fn(|i| C::CircuitField::from(i as u64));

        let tz = R::tz(*z_challenge);
        let mut b_poly: Vec<B<C::HostCurve, R>> = a_polys
            .iter()
            .take(N) // Only application circuits, not accumulators yet
            .zip(circuit_ids.iter())
            .map(|(a, &circuit_id)| {
                let mut b_poly = a.poly.clone();
                b_poly.dilate(*z_challenge);
                b_poly.add_assign(&tz);
                b_poly.add_assign(&mesh.wy(circuit_id, *y_challenge));

                let b_blinding = C::CircuitField::random(thread_rng());
                let b_commitment = b_poly.commit(cycle.host_generators(), b_blinding);

                B {
                    poly: b_poly,
                    blinding: b_blinding,
                    commitment: b_commitment,
                }
            })
            .collect();

        // Append existing accumulator B polynomials.
        b_poly.push(B {
            poly: acc1.accumulator.witness.b_poly.clone(),
            blinding: acc1.accumulator.witness.b_blinding,
            commitment: acc1.accumulator.instance.b,
        });

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Compute error terms.
        ///////////////////////////////////////////////////////////////////////////////////////

        // The prover computes all of the cross products a_i . b_j for i
        // != j. This is done before the verifier selects the random challenges
        // mu and nu.
        let len = a_polys.len();
        let mut cross_products = Vec::new();
        for i in 0..len {
            for j in 0..len {
                if i != j {
                    let cross = a_polys[i].poly.revdot(&b_poly[j].poly);
                    cross_products.push(cross);
                }
            }
        }

        // D3 STAGING POLYNOMIAL: Nested encoding for error terms.
        type D4StagingPolynomial<C, const N: usize> = BInnerStage<C, N>;

        let mut cross_commitments = Vec::new();
        for cross_scalar in &cross_products {
            let blinding = C::CircuitField::random(OsRng);
            let commitment = cycle
                .host_generators()
                .short_commit(*cross_scalar, blinding);
            cross_commitments.push(commitment);
        }

        const CROSS_COUNT: usize = (N + 2) * (N + 1);
        let cross_array: [C::HostCurve; CROSS_COUNT] = cross_commitments
            .try_into()
            .map_err(|_| Error::CircuitBoundExceeded(CROSS_COUNT))?;

        let d3_inner_rx = <D2InnerStage<C::HostCurve, CROSS_COUNT> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&cross_array)?;

        let d3_blinding = C::ScalarField::random(OsRng);
        let d3_nested_commitment = d3_inner_rx.commit(cycle.nested_generators(), d3_blinding);

        // TRANSCRIPT: Absorb D3 stage commitment.
        transcript.absorb_point(d3_nested_commitment);

        Ok(())
    }
}
