use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    CircuitExt,
    mesh::{Mesh, omega_j},
    polynomials::Rank,
    staging::{StageExt, Staged},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::{Element, GadgetExt, Point, Sponge, vec::Len};
use rand::Rng;

use alloc::vec;
use core::marker::PhantomData;

use crate::{
    Pcd, Proof,
    circuits::{self, internal_circuit_index},
    step::{Step, adapter::Adapter},
};

pub fn merge<'source, C: Cycle, R: Rank, RNG: Rng, S: Step<C>, const HEADER_SIZE: usize>(
    num_application_steps: usize,
    circuit_mesh: &Mesh<'_, C::CircuitField, R>,
    params: &C,
    rng: &mut RNG,
    step: S,
    witness: S::Witness<'source>,
    left: Pcd<'source, C, R, S::Left>,
    right: Pcd<'source, C, R, S::Right>,
) -> Result<(Proof<C, R>, S::Aux<'source>)> {
    let host_generators = params.host_generators();
    let nested_generators = params.nested_generators();
    let circuit_poseidon = params.circuit_poseidon();

    let fake_x0 = C::CircuitField::from(42);
    // let fake_y0 = C::CircuitField::from(43);

    let fake_x1 = C::CircuitField::from(44);
    // let fake_y1 = C::CircuitField::from(45);

    // The preamble stage contains public inputs for circuits over the
    // C::CircuitField.
    let preamble_rx = stages::native_preamble::Preamble::<C::CircuitField, R>::rx(())?;
    let preamble_blind = C::CircuitField::random(&mut *rng);
    let preamble_commitment = preamble_rx.commit(host_generators, preamble_blind);

    // We must compute a nested commitment to the preamble for hashing.
    let nested_preamble_rx =
        stages::nested_preamble::Stage::<C::HostCurve, R>::rx(preamble_commitment)?;
    let nested_preamble_blind = C::ScalarField::random(&mut *rng);
    let nested_preamble_commitment =
        nested_preamble_rx.commit(nested_generators, nested_preamble_blind);

    // Compute w = H(nested_preamble_commitment)
    let w: C::CircuitField = Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let mut sponge = Sponge::new(dr, circuit_poseidon);
        point.write(dr, &mut sponge)?;
        Ok(*sponge.squeeze(dr)?.value().take())
    })?;

    // Given w, we can compute m(w, x_i, Y) for i = 0, 1 and commit to each.
    let mesh_wx0 = circuit_mesh.wx(w, fake_x0);
    let mesh_wx0_blind = C::CircuitField::random(&mut *rng);
    let mesh_wx0_commitment = mesh_wx0.commit(host_generators, mesh_wx0_blind);
    let mesh_wx1 = circuit_mesh.wx(w, fake_x1);
    let mesh_wx1_blind = C::CircuitField::random(&mut *rng);
    let mesh_wx1_commitment = mesh_wx1.commit(host_generators, mesh_wx1_blind);

    // We compute a nested commitment to s' = m(w, x_i, Y) for i = 0, 1.
    let nested_s_prime_rx = stages::nested_s_prime::Stage::<C::HostCurve, R>::rx((
        mesh_wx0_commitment,
        mesh_wx1_commitment,
    ))?;
    let nested_s_prime_blind = C::ScalarField::random(&mut *rng);
    let nested_s_prime_commitment =
        nested_s_prime_rx.commit(nested_generators, nested_s_prime_blind);

    // Compute (y, z) = H(w, nested_s_prime_commitment)
    let (y, z): (C::CircuitField, C::CircuitField) =
        Emulator::emulate_wireless((w, nested_s_prime_commitment), |dr, witness| {
            let (w, comm) = witness.cast();
            let w_elem = Element::alloc(dr, w)?;
            let point = Point::alloc(dr, comm)?;
            let mut sponge = Sponge::new(dr, circuit_poseidon);
            sponge.absorb(dr, &w_elem)?;
            point.write(dr, &mut sponge)?;
            let y = *sponge.squeeze(dr)?.value().take();
            let z = *sponge.squeeze(dr)?.value().take();
            Ok((y, z))
        })?;

    // Given (w, y), we can compute m(w, X, y) and commit to it.
    let mesh_wy = circuit_mesh.wy(w, y);
    let mesh_wy_blind = C::CircuitField::random(&mut *rng);
    let mesh_wy_commitment = mesh_wy.commit(host_generators, mesh_wy_blind);

    // We compute a nested commitment to S'' = m(w, X, y).
    let nested_s_doubleprime_rx =
        stages::nested_s_doubleprime::Stage::<C::HostCurve, R>::rx(mesh_wy_commitment)?;
    let nested_s_doubleprime_blind = C::ScalarField::random(&mut *rng);
    let nested_s_doubleprime_commitment =
        nested_s_doubleprime_rx.commit(nested_generators, nested_s_doubleprime_blind);

    // The error stage follows the preamble stage. It contains (w, y, z), S'',
    // and the error terms.
    //
    // Later, circuit_c is responsible for verifying that (w, y, z) are computed
    // correctly, and computing the `c` value given (mu, nu) as public inputs,
    // computed later.
    let error_witness = stages::native_error::Witness {
        z,
        nested_s_doubleprime_commitment,
        error_terms: ragu_primitives::vec::FixedVec::try_from(vec![
            C::CircuitField::ZERO;
            stages::native_error::ErrorTerms::len(
            )
        ])?,
    };
    let error_rx = stages::native_error::Error::<C::NestedCurve, R>::rx(&error_witness)?;
    let error_blind = C::CircuitField::random(&mut *rng);
    let error_commitment = error_rx.commit(host_generators, error_blind);

    // Compute a nested commitment to the error stage.
    let nested_error_rx = stages::nested_error::Stage::<C::HostCurve, R>::rx(error_commitment)?;
    let nested_error_blind = C::ScalarField::random(&mut *rng);
    let nested_error_commitment = nested_error_rx.commit(nested_generators, nested_error_blind);

    // Compute (mu, nu) = H(nested_error_commitment). Note that the error stage
    // does not contain nested_s_prime_commitment, but is bound to it because
    // (y, z) are outputs of hashing w and nested_s_prime_commitment, and those
    // values are inside the stage.
    let (mu, nu): (C::CircuitField, C::CircuitField) =
        Emulator::emulate_wireless(nested_error_commitment, |dr, comm| {
            let point = Point::alloc(dr, comm)?;
            let mut sponge = Sponge::new(dr, circuit_poseidon);
            point.write(dr, &mut sponge)?;
            let mu = *sponge.squeeze(dr)?.value().take();
            let nu = *sponge.squeeze(dr)?.value().take();
            Ok((mu, nu))
        })?;

    // Compute the A/B polynomials (depend on mu, nu).
    // TODO: For now, stub out fake A and B polynomials.
    let a = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
    let b = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();

    // Commit to A and B, then create the nested commitment.
    let a_blind = C::CircuitField::random(&mut *rng);
    let a_commitment = a.commit(host_generators, a_blind);
    let b_blind = C::CircuitField::random(&mut *rng);
    let b_commitment = b.commit(host_generators, b_blind);

    let nested_ab_rx =
        stages::nested_ab::Stage::<C::HostCurve, R>::rx((a_commitment, b_commitment))?;
    let nested_ab_blind = C::ScalarField::random(&mut *rng);
    let nested_ab_commitment = nested_ab_rx.commit(nested_generators, nested_ab_blind);

    let x: C::CircuitField =
        Emulator::emulate_wireless((mu, nested_ab_commitment), |dr, witness| {
            let (mu, comm) = witness.cast();
            let mu_elem = Element::alloc(dr, mu)?;
            let point = Point::alloc(dr, comm)?;
            let mut sponge = Sponge::new(dr, circuit_poseidon);
            sponge.absorb(dr, &mu_elem)?;
            point.write(dr, &mut sponge)?;
            Ok(*sponge.squeeze(dr)?.value().take())
        })?;

    // Compute commitment to mesh polynomial at (x, y).
    let mesh_xy = circuit_mesh.xy(x, y);
    let mesh_xy_blind = C::CircuitField::random(&mut *rng);
    let mesh_xy_commitment = mesh_xy.commit(host_generators, mesh_xy_blind);

    let nested_s_rx = stages::nested_s::Stage::<C::HostCurve, R>::rx(mesh_xy_commitment)?;
    let nested_s_blind = C::ScalarField::random(&mut *rng);
    let nested_s_commitment = nested_s_rx.commit(nested_generators, nested_s_blind);

    let query_witness = stages::native_query::Witness {
        x,
        nested_s_commitment,
        queries: ragu_primitives::vec::FixedVec::try_from(vec![
            C::CircuitField::ZERO;
            stages::native_query::Queries::len(
            )
        ])?,
    };
    let query_rx = stages::native_query::Query::<C::NestedCurve, R>::rx(&query_witness)?;
    let query_blind = C::CircuitField::random(&mut *rng);
    let query_commitment = query_rx.commit(host_generators, query_blind);
    let nested_query_rx = stages::nested_query::Stage::<C::HostCurve, R>::rx(query_commitment)?;
    let nested_query_blind = C::ScalarField::random(&mut *rng);
    let nested_query_commitment = nested_query_rx.commit(nested_generators, nested_query_blind);

    let alpha: C::CircuitField =
        Emulator::emulate_wireless(nested_query_commitment, |dr, comm| {
            let point = Point::alloc(dr, comm)?;
            let mut sponge = Sponge::new(dr, circuit_poseidon);
            point.write(dr, &mut sponge)?;
            Ok(*sponge.squeeze(dr)?.value().take())
        })?;

    // Compute the F polynomial commitment (stubbed for now).
    let f = ragu_circuits::polynomials::structured::Polynomial::<C::CircuitField, R>::new();
    let f_blind = C::CircuitField::random(&mut *rng);
    let f_commitment = f.commit(host_generators, f_blind);

    let nested_f_rx = stages::nested_f::Stage::<C::HostCurve, R>::rx(f_commitment)?;
    let nested_f_blind = C::ScalarField::random(&mut *rng);
    let nested_f_commitment = nested_f_rx.commit(nested_generators, nested_f_blind);

    let u: C::CircuitField =
        Emulator::emulate_wireless((alpha, nested_f_commitment), |dr, witness| {
            let (alpha, comm) = witness.cast();
            let alpha_elem = Element::alloc(dr, alpha)?;
            let point = Point::alloc(dr, comm)?;
            let mut sponge = Sponge::new(dr, circuit_poseidon);
            sponge.absorb(dr, &alpha_elem)?;
            point.write(dr, &mut sponge)?;
            Ok(*sponge.squeeze(dr)?.value().take())
        })?;

    let eval_witness = stages::native_eval::Witness {
        u,
        evals: ragu_primitives::vec::FixedVec::try_from(vec![
            C::CircuitField::ZERO;
            stages::native_eval::Evals::len()
        ])?,
    };
    let eval_rx = stages::native_eval::Eval::<C::NestedCurve, R>::rx(&eval_witness)?;
    let eval_blind = C::CircuitField::random(&mut *rng);
    let eval_commitment = eval_rx.commit(host_generators, eval_blind);
    let nested_eval_rx = stages::nested_eval::Stage::<C::HostCurve, R>::rx(eval_commitment)?;
    let nested_eval_blind = C::ScalarField::random(&mut *rng);
    let nested_eval_commitment = nested_eval_rx.commit(nested_generators, nested_eval_blind);

    let beta: C::CircuitField = Emulator::emulate_wireless(nested_eval_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let mut sponge = Sponge::new(dr, circuit_poseidon);
        point.write(dr, &mut sponge)?;
        Ok(*sponge.squeeze(dr)?.value().take())
    })?;

    // Create the unified instance for circuit_c and circuit_v.
    let unified_instance = &crate::circuits::unified::Instance {
        nested_preamble_commitment,
        w,
        nested_s_prime_commitment,
        y,
        z,
        nested_s_doubleprime_commitment,
        nested_error_commitment,
        mu,
        nu,
        nested_ab_commitment,
        nested_s_commitment,
        nested_query_commitment,
        alpha,
        nested_f_commitment,
        u,
        nested_eval_commitment,
        beta,
    };

    // Compute circuit_c witness polynomial (verifies w, y, z).
    let circuit_c = crate::circuits::circuit_c::Circuit::<C, R>::new(circuit_poseidon);
    let circuit_c_witness = crate::circuits::circuit_c::Witness {
        unified_instance,
        error_witness: &error_witness,
    };
    let circuit_c_staged = Staged::new(circuit_c);
    let (circuit_c_rx, _) = circuit_c_staged.rx::<R>(circuit_c_witness, circuit_mesh.get_key())?;

    // Compute circuit_v witness polynomial (verifies mu, nu, x, alpha, u, beta).
    let circuit_v = crate::circuits::circuit_v::Circuit::<C, R>::new(circuit_poseidon);
    let circuit_v_witness = crate::circuits::circuit_v::Witness {
        unified_instance,
        query_witness: &query_witness,
        eval_witness: &eval_witness,
    };
    let circuit_v_staged = Staged::new(circuit_v);
    let (circuit_v_rx, _) = circuit_v_staged.rx::<R>(circuit_v_witness, circuit_mesh.get_key())?;

    // Compute ky once - both circuit_c and circuit_v share the same Instance/Output types,
    // so they produce identical k(y) polynomials.
    let ky = Staged::new(crate::circuits::circuit_c::Circuit::<C, R>::new(
        circuit_poseidon,
    ))
    .ky(unified_instance)?;

    // Assert that ky[1] == 0 (ensured by the `zero` field at the end of Output).
    assert_eq!(ky[1], C::CircuitField::ZERO);

    // Assert that circuit_c rx is valid.
    {
        let tmp_y = C::CircuitField::random(&mut *rng);
        let tmp_z = C::CircuitField::random(&mut *rng);

        // Combine preamble and error stage polynomials with circuit_c.
        let mut combined_rx = preamble_rx.clone();
        combined_rx.add_assign(&error_rx);
        combined_rx.add_assign(&circuit_c_rx);

        let circuit_id = omega_j(internal_circuit_index(
            num_application_steps,
            circuits::circuit_c::CIRCUIT_ID,
        ) as u32);
        let sy = circuit_mesh.wy(circuit_id, tmp_y);
        let tz = R::tz(tmp_z);

        let mut rhs = combined_rx.clone();
        rhs.dilate(tmp_z);
        rhs.add_assign(&sy);
        rhs.add_assign(&tz);

        assert_eq!(combined_rx.revdot(&rhs), arithmetic::eval(ky.iter(), tmp_y));
    }

    // Assert that circuit_v rx is valid.
    {
        let tmp_y = C::CircuitField::random(&mut *rng);
        let tmp_z = C::CircuitField::random(&mut *rng);

        // Combine preamble, query, and eval stage polynomials with circuit_v.
        let mut combined_rx = preamble_rx.clone();
        combined_rx.add_assign(&query_rx);
        combined_rx.add_assign(&eval_rx);
        combined_rx.add_assign(&circuit_v_rx);

        let circuit_id = omega_j(internal_circuit_index(
            num_application_steps,
            circuits::circuit_v::CIRCUIT_ID,
        ) as u32);
        let sy = circuit_mesh.wy(circuit_id, tmp_y);
        let tz = R::tz(tmp_z);

        let mut rhs = combined_rx.clone();
        rhs.dilate(tmp_z);
        rhs.add_assign(&sy);
        rhs.add_assign(&tz);

        assert_eq!(combined_rx.revdot(&rhs), arithmetic::eval(ky.iter(), tmp_y));
    }

    let circuit_id = S::INDEX.circuit_index(Some(num_application_steps))?;
    let circuit = Adapter::<C, S, R, HEADER_SIZE>::new(step);
    let (rx, aux) = circuit.rx::<R>((left.data, right.data, witness), circuit_mesh.get_key())?;

    let ((left_header, right_header), aux) = aux;

    Ok((
        Proof {
            circuit_id,
            left_header: left_header.into_inner(),
            right_header: right_header.into_inner(),
            rx,
            _marker: PhantomData,
        },
        aux,
    ))
}

pub mod stages {
    /// Generates a simple nested stage that witnesses a single curve point.
    ///
    /// The `parent` argument specifies the Parent stage type for this stage.
    /// Use `()` for stages with no parent, or a path like `super::nested_preamble::Stage`
    /// for stages that depend on another.
    macro_rules! define_nested_point_stage {
        (
            $(#[$meta:meta])*
            $mod_name:ident,
            parent = $parent:ty
        ) => {
            pub mod $mod_name {
                //! Nested stage for merge operations.

                use arithmetic::CurveAffine;
                use ragu_circuits::polynomials::Rank;
                use ragu_core::{
                    Result,
                    drivers::{Driver, DriverValue},
                    gadgets::{GadgetKind, Kind},
                };
                use ragu_primitives::Point;

                use core::marker::PhantomData;

                $(#[$meta])*
                pub struct Stage<C: CurveAffine, R> {
                    _marker: PhantomData<(C, R)>,
                }

                impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Stage<C, R> {
                    type Parent = $parent;
                    type Witness<'source> = C;
                    type OutputKind = Kind![C::Base; Point<'_, _, C>];

                    fn values() -> usize {
                        2
                    }

                    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
                        dr: &mut D,
                        witness: DriverValue<D, Self::Witness<'source>>,
                    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
                    where
                        Self: 'dr,
                    {
                        Point::alloc(dr, witness)
                    }
                }
            }
        };
    }

    // Use macro to generate the 7 identical nested point stages
    // All currently have Parent = (), but this can change in the future
    define_nested_point_stage!(
        /// The nested preamble stage witnesses the commitment point from the preamble stage.
        nested_preamble,
        parent = ()
    );
    define_nested_point_stage!(
        /// The nested s stage witnesses the mesh polynomial commitment at (x, y).
        nested_s,
        parent = ()
    );
    define_nested_point_stage!(
        /// The nested s'' stage witnesses the mesh polynomial commitment at (w, y).
        nested_s_doubleprime,
        parent = ()
    );
    define_nested_point_stage!(
        /// The nested error stage witnesses the error commitment point.
        nested_error,
        parent = ()
    );
    define_nested_point_stage!(
        /// The nested query stage witnesses the query commitment point.
        nested_query,
        parent = ()
    );
    define_nested_point_stage!(
        /// The nested eval stage witnesses the eval commitment point.
        nested_eval,
        parent = ()
    );
    define_nested_point_stage!(
        /// The nested F stage witnesses the F polynomial commitment point.
        nested_f,
        parent = ()
    );

    // Keep these as separate files (different structure - two points each):
    pub mod nested_ab;
    pub mod nested_s_prime;

    // Keep other stages as separate files:
    pub mod native_error;
    pub mod native_eval;
    pub mod native_preamble;
    pub mod native_query;
}
