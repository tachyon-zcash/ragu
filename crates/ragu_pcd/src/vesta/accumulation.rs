use crate::accumulator::CycleAccumulator;
use crate::engine::CycleEngine;
use crate::nested_encoding::b_stage::{BIndirectionStage, BInnerStage, BNestedEncodingCircuit};
use crate::nested_encoding::d_stage::{
    D1InnerStage, D2InnerStage, DIndirectionStage, DNestedEncodingCircuit, DNestedEncodingWitness,
    ErrorInnerStage,
};
use crate::transcript::AccumulationTranscript;
use crate::utilities::dummy_circuits::Circuits;
use crate::vesta::structures::{CommittedPolynomial, CommittedStructured};
use arithmetic::{Cycle, FixedGenerators};
use ff::Field;
use ragu_circuits::CircuitExt;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::polynomials::structured;
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

        // Instantiate new accumulator object, which contains the prover's split accumulator witness and instance parts.
        let cycle_accumulator = CycleAccumulator::<C::HostCurve, C::NestedCurve, R>::base(
            mesh,
            cycle.host_generators(),
        );

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process endoscalars.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Determine the endoscaling operations, representing deferreds from the other curve.

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Process `StagedObjects`.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TODO: Check the staged objects for staging consistency.

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Process the application circuits. The witness polynomials
        // r(X) are over Fp, and produce commitments to Vesta points.
        ///////////////////////////////////////////////////////////////////////////////////////

        let mut a_polys = Vec::with_capacity(N + 2);
        let mut ky = Vec::with_capacity(N);

        for (&witness, circuit) in witnesses.iter().zip(circuit_list.iter()) {
            let (rx_poly, instance) = circuit.rx::<R>(witness)?;
            let blinding = C::CircuitField::random(OsRng);
            let commitment = rx_poly.commit(cycle.host_generators(), blinding);

            // r(X) witness polynomial.
            a_polys.push(CommittedPolynomial {
                poly: rx_poly,
                blind: blinding,
                commitment,
            });

            // k(Y) constraint polynomial.
            ky.push(circuit.ky(instance)?);
        }

        // Append the previous accumulator A polynomials.
        a_polys.push(CommittedPolynomial {
            poly: acc1.accumulator.witness.a_poly.clone(),
            blind: acc1.accumulator.witness.a_blinding,
            commitment: acc1.accumulator.instance.a,
        });
        a_polys.push(CommittedPolynomial {
            poly: acc2.accumulator.witness.a_poly.clone(),
            blind: acc2.accumulator.witness.a_blinding,
            commitment: acc2.accumulator.instance.a,
        });

        // TRANSCRIPT: Absorb k(Y) constraint evaluations.
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

        type BStagingPolynomial<C, const N: usize> = BInnerStage<C, N>;

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the Vesta commitments to r(X).
        let b_inner_rx = <BStagingPolynomial<C::HostCurve, { N + 2 }> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&a_commitments)?;

        // NESTED ENCODING: Commit to the *partial* staging polynomial using Pallas generators (nested curve).
        let b_blinding = C::ScalarField::random(OsRng);
        let b_nested_commitment = b_inner_rx.commit(cycle.nested_generators(), b_blinding);

        // TRANSCRIPT: Absorb B stage commitment before deriving w challenge.
        transcript.absorb_point(b_nested_commitment);

        // STAGED CIRCUIT: This simply allocates the partial nested commitment point inside the staged circuit.
        let b_circuit = Staged::<Fp, R, _>::new(BNestedEncodingCircuit::<C::NestedCurve>::new());
        let (b_rx, _b_aux) = b_circuit.rx::<R>(b_nested_commitment)?;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable, partially nested commitment for use in the transcript.
        let b_staged_circuit_blinding = C::CircuitField::random(OsRng);
        let b_staged_circuit_commitment =
            b_rx.commit(cycle.host_generators(), b_staged_circuit_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the B staged circuit Vesta commitment.
        let b_staged_circuit_inner = <BIndirectionStage<C::HostCurve> as StageExt<
            C::ScalarField,
            R,
        >>::rx(b_staged_circuit_commitment)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let b_staged_circuit_nested_blinding = C::ScalarField::random(OsRng);
        let b_staged_circuit_nested_commitment = b_staged_circuit_inner
            .commit(cycle.nested_generators(), b_staged_circuit_nested_blinding);

        transcript.absorb_point(b_staged_circuit_nested_commitment);
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Construct D staging polynomial. This uses a two-layer nested encoding.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: W challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // Derive w challenge from B commitment using Poseidon hash.
        //
        // NOTE: for now, this is a placeholder that we'll replace with an actual
        // call to Poseidon. We compute this off-circuit that allows us to continue
        // with the computation, similiar to predict(), and then later verify
        // it was computed properly inside the circuit.

        // TRANSCRIPT: Squeeze w challenge.
        let w_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S' Mesh Polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S': For each previous accumulator, compute M(w, x_i, Y) for checking mesh consistency.
        let s1_poly_acc1 = mesh.wx(w_challenge, acc1.accumulator.instance.x.0);
        let s1_blinding_acc1 = C::CircuitField::random(thread_rng());
        let s1_commitment_acc1 = s1_poly_acc1.commit(cycle.host_generators(), s1_blinding_acc1);

        let s1_poly_acc2 = mesh.wx(w_challenge, acc2.accumulator.instance.x.0);
        let s1_blinding_acc2 = C::CircuitField::random(thread_rng());
        let s1_commitment_acc2 = s1_poly_acc2.commit(cycle.host_generators(), s1_blinding_acc2);

        let s_prime = [
            CommittedPolynomial {
                poly: s1_poly_acc1,
                blind: s1_blinding_acc1,
                commitment: s1_commitment_acc1,
            },
            CommittedPolynomial {
                poly: s1_poly_acc2,
                blind: s1_blinding_acc2,
                commitment: s1_commitment_acc2,
            },
        ];

        let s_prime_commitments = [s_prime[0].commitment, s_prime[1].commitment];

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: D1 Two-Layer Nested Encoding.
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S' Vesta commitments.
        let d1_inner_rx = <D1InnerStage<C::HostCurve, 2> as StageExt<C::ScalarField, R>>::rx(
            &s_prime_commitments,
        )?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d1_blinding = C::ScalarField::random(OsRng);
        let d1_nested_commitment = d1_inner_rx.commit(cycle.nested_generators(), d1_blinding);

        transcript.absorb_point(d1_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Y challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze y challenge.
        let y_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: S'' Mesh Polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        // COMPUTE S'': M(w, X, y) polynomial for final mesh consistency checks.
        let s2_poly = mesh.wy(w_challenge, y_challenge);
        let s2_blinding = C::CircuitField::random(thread_rng());
        let s2_commitment = s2_poly.commit(cycle.host_generators(), s2_blinding);

        // Append previous accumulator revdot claims as diagonal terms.
        let mut ky: Vec<Fp> = ky
            .iter()
            .map(|ky| arithmetic::eval(ky, y_challenge))
            .collect();
        ky.push(acc1.accumulator.instance.c);
        ky.push(acc2.accumulator.instance.c);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: D2 Two-Layer Nested Encoding
        //////////////////////////////////////////////////////////////////////////////////////

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the S'' Vesta commitment.
        let d2_inner_rx =
            <D2InnerStage<C::HostCurve, 1> as StageExt<C::ScalarField, R>>::rx(&[s2_commitment])?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d2_blinding = C::ScalarField::random(OsRng);
        let d2_nested_commitment = d2_inner_rx.commit(cycle.nested_generators(), d2_blinding);

        transcript.absorb_point(d2_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Z challenge derivation.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze z challenge.
        let z_challenge = transcript.squeeze();

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute B polynomials for revdot verification.
        //
        //  For each application circuit: B_i(X) = A_i(X) * z + t(X,z) + M(circuit_id, X, y),
        //  and this construction ensures: A_i (revdot) B_i = k_i(y).
        ///////////////////////////////////////////////////////////////////////////////////////

        let circuit_ids: [C::CircuitField; N] =
            core::array::from_fn(|i| C::CircuitField::from(i as u64));

        let tz = R::tz(z_challenge);
        let mut b_polys: Vec<CommittedStructured<R, C::HostCurve>> = a_polys
            .iter()
            .take(N)
            .zip(circuit_ids.iter())
            .map(|(a, &circuit_id)| {
                let mut b_poly = a.poly.clone();
                b_poly.dilate(z_challenge);
                b_poly.add_assign(&tz);
                b_poly.add_assign(&mesh.wy(circuit_id, y_challenge));

                let b_blinding = C::CircuitField::random(thread_rng());
                let b_commitment = b_poly.commit(cycle.host_generators(), b_blinding);

                CommittedPolynomial {
                    poly: b_poly,
                    blind: b_blinding,
                    commitment: b_commitment,
                }
            })
            .collect();

        // Append existing accumulator B polynomials.
        b_polys.push(CommittedPolynomial {
            poly: acc1.accumulator.witness.b_poly.clone(),
            blind: acc1.accumulator.witness.b_blinding,
            commitment: acc1.accumulator.instance.b,
        });
        b_polys.push(CommittedPolynomial {
            poly: acc2.accumulator.witness.b_poly.clone(),
            blind: acc2.accumulator.witness.b_blinding,
            commitment: acc2.accumulator.instance.b,
        });

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute error / slack term (from folding multiple revdot checks)
        // before computing the u and v evaluations.
        ///////////////////////////////////////////////////////////////////////////////////////

        // The prover computes all of the cross products a_i . b_j for i != j.
        let len = a_polys.len();
        let mut cross_products = Vec::new();
        for i in 0..len {
            for j in 0..len {
                if i != j {
                    let cross = a_polys[i].poly.revdot(&b_polys[j].poly);
                    cross_products.push(cross);
                }
            }
        }

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

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the cross-terms Vesta commitment.
        let d3_inner_rx = <ErrorInnerStage<C::HostCurve, CROSS_COUNT> as StageExt<
            C::ScalarField,
            R,
        >>::rx(&cross_array)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d3_blinding = C::ScalarField::random(OsRng);
        let d3_nested_commitment = d3_inner_rx.commit(cycle.nested_generators(), d3_blinding);

        // TRANSCRIPT: Absorb D3 stage commitment.
        transcript.absorb_point(d3_nested_commitment);

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Challenge circuit: verify w, y, and z challenges in-circuit.
        ///////////////////////////////////////////////////////////////////////////////////////

        let d_witness = DNestedEncodingWitness {
            b_nested_commitment,
            w_challenge,
            d1_nested_commitment,
            y_challenge,
            d2_nested_commitment,
            z_challenge,
        };

        let d_circuit = Staged::<Fp, R, _>::new(DNestedEncodingCircuit::<C::NestedCurve>::new());
        let (d_rx, _d_aux) = d_circuit.rx::<R>(d_witness)?;

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // LAYER OF INDIRECTION: We now introduce another nested commitment layer to produce
        // an Fp-hashable, partially nested commitment for use in the transcript.
        let d_staged_circuit_blinding = C::CircuitField::random(OsRng);
        let d_staged_circuit_commitment =
            d_rx.commit(cycle.host_generators(), d_staged_circuit_blinding);

        // INNER LAYER: Staging polynomial (over Fq) that witnesses the D staged circuit Vesta commitment.
        let d_staged_circuit_inner = <DIndirectionStage<C::HostCurve> as StageExt<
            C::ScalarField,
            R,
        >>::rx(d_staged_circuit_commitment)?;

        // NESTED ENCODING: Commit to the staging polynomial using Pallas generators (nested curve).
        let d_staged_circuit_nested_blinding = C::ScalarField::random(OsRng);
        let d_staged_circuit_nested_commitment = d_staged_circuit_inner
            .commit(cycle.nested_generators(), d_staged_circuit_nested_blinding);

        transcript.absorb_point(d_staged_circuit_nested_commitment);
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // PHASE: Construct E staging polynomial.
        ///////////////////////////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: mu and nu challenge derivation for checking revdot claims are correct.
        ///////////////////////////////////////////////////////////////////////////////////////

        // TRANSCRIPT: Squeeze mu challenge.
        let mu_challenge = transcript.squeeze();

        // TRANSCRIPT: Absorb mu challenge.
        transcript.absorb_scalar(mu_challenge);

        // TRANSCRIPT: Squeeze nu challenge.
        let nu_challenge = transcript.squeeze();

        let mu_inv = mu_challenge.invert().unwrap();
        let munu = mu_challenge * nu_challenge;

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Folding A and B polynomials into single polynomials.
        ///////////////////////////////////////////////////////////////////////////////////////

        let a_poly = structured::Polynomial::fold(a_polys.iter().map(|p| &p.poly), mu_inv);
        let a_blinding = C::CircuitField::random(OsRng);
        let a_commitment = a_poly.commit(cycle.host_generators(), a_blinding);

        let a_folded = CommittedPolynomial {
            poly: a_poly,
            blind: a_blinding,
            commitment: a_commitment,
        };

        let b_poly = structured::Polynomial::fold(a_polys.iter().map(|p| &p.poly), munu);
        let b_blinding = C::CircuitField::random(OsRng);
        let b_commitment = b_poly.commit(cycle.host_generators(), b_blinding);

        let b_folded = CommittedPolynomial {
            poly: b_poly,
            blind: b_blinding,
            commitment: b_commitment,
        };

        ///////////////////////////////////////////////////////////////////////////////////////
        // TASK: Compute C. The expected value of c = a.revdot(b).
        ///////////////////////////////////////////////////////////////////////////////////////

        Ok(())
    }
}
