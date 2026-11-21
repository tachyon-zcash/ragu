//! Prover bootstrap construction.
use alloc::{vec, vec::Vec};

use ragu_circuits::{
    polynomials::{Rank, sparse},
    registry::CircuitIndex,
    staging::StageExt,
};
use ragu_primitives::{
    extract_endoscalar, lift_endoscalar,
    vec::{FixedVec, Len},
};
use udon::field::Field;

use crate::{
    fuse::prover::proof_builder::ProofBuilder,
    header::NUM_ONLINE_FP_POLYS,
    profile::{Profile, ProfiledCycle},
    protocol::{
        native,
        native::{RxIndex, online, stages::points::Inputs},
        nested,
        nested::{NumPoints, online as online_fq},
    },
};

/// The Horner fold of `polys` under `beta`, the first weighted highest: the
/// batch polynomial whose commitment the endoscaling walk over the
/// polynomials' commitments computes.
fn beta_fold<F: Field, R: Rank>(
    polys: &[&sparse::Polynomial<F, R>],
    beta: F,
) -> sparse::Polynomial<F, R> {
    let (first, rest) = polys.split_first().expect("at least one polynomial");
    rest.iter().fold((*first).clone(), |mut acc, poly| {
        acc.scale(beta);
        acc.add_assign(poly);
        acc
    })
}

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    crate::Application<'params, C, R, HEADER_SIZE, B>
{
    /// A synthesized dummy that stands in for the absent predecessors when
    /// bootstrapping.
    ///
    /// This proof does not verify on its own; it is only ever consumed by the
    /// internal [`Bootstrap`](crate::step::internal::bootstrap::Bootstrap) step, whose
    /// fuse is the base case and therefore does not enforce its children's
    /// claims. It carries the [`Dummy`] header so that it can occupy that
    /// step's input slots.
    ///
    /// [`Dummy`]: crate::header::Dummy
    pub(crate) fn dummy_pcd(&self) -> Pcd<C, R, crate::header::Dummy> {
        self.dummy_proof().carry(())
    }

    pub(crate) fn dummy_proof(&self) -> Proof<C, R> {
        let ones_host = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::CircuitField::ONE);
            view.b.push(C::CircuitField::ONE);
            view.c.push(C::CircuitField::ONE);
            view.d.push(C::CircuitField::ONE);
            view.build()
        };
        let host_commitment =
            B::sparse_commit_to_affine(&ones_host, C::host_generators(self.params));
        let ones_nested = {
            let mut view = sparse::View::<_, R, _>::trace();
            view.a.push(C::ScalarField::ONE);
            view.b.push(C::ScalarField::ONE);
            view.c.push(C::ScalarField::ONE);
            view.d.push(C::ScalarField::ONE);
            view.build()
        };

        // registry_xy must be the actual registry evaluation (fuse cross-checks it).
        let registry_xy_poly = B::registry_xy(
            &self.native_registry,
            C::CircuitField::ONE,
            C::CircuitField::ONE,
        );
        // The nested counterpart, at the nested counterparts of the all-one
        // challenges below: a parent opens it at its own nested w.
        let nested_one = nested::challenge::<C>(C::CircuitField::ONE)
            .expect("one is in the endoscalar challenge range");
        let nested_registry_xy_poly = B::registry_xy(&self.nested_registry, nested_one, nested_one);
        // The all-one challenges, and their lifts on the nested side. One is
        // an interpolation node of the quotient fold, so a fold at these
        // challenges selects claim 1 alone. That is harmless: a dummy is never
        // verified on its own, and the bootstrap step that consumes it leaves
        // its c unconstrained.
        let challenges = nested::Challenges {
            w: C::CircuitField::ONE,
            y: C::CircuitField::ONE,
            z: C::CircuitField::ONE,
            mu: C::CircuitField::ONE,
            mu_prime: C::CircuitField::ONE,
            x: C::CircuitField::ONE,
            alpha: C::CircuitField::ONE,
            u: C::CircuitField::ONE,
            pre_beta: C::CircuitField::ONE,
        };
        let lifts = challenges
            .lifts::<C>()
            .expect("one is in the endoscalar challenge range");
        let (challenge_lifts, beta_lift) =
            lifts.split_at(crate::protocol::nested::stages::challenges::NUM);
        // A dummy proof has synthetic traces and a fixed +1 sign. Use the
        // same witness for its binding partials and challenge stage.
        let nested_challenges = crate::protocol::nested::stages::challenges::Witness {
            lifts: FixedVec::new(challenge_lifts.to_vec()).expect("NUM challenge lifts"),
            base_case_sign: C::ScalarField::ONE,
            beta: beta_lift[0],
        };

        let mut builder = ProofBuilder::<C, R, B>::new(self.params, C::ScalarField::ONE);

        builder.set_circuit_id(CircuitIndex::new(0));

        builder.set_left_header(vec![C::CircuitField::ZERO; HEADER_SIZE]);
        builder.set_right_header(vec![C::CircuitField::ZERO; HEADER_SIZE]);

        // Native rx polynomials (all trivial ones)
        builder.set_native_application_rx(ones_host.clone());
        builder.set_native_application_stage_rx(ones_host.clone());
        builder.set_native_preamble_rx(ones_host.clone());
        builder.set_native_inner_error_rx(ones_host.clone());
        builder.set_native_outer_error_rx(ones_host.clone());
        builder.set_native_a_poly(ones_host.clone(), host_commitment);
        builder.set_native_b_poly(ones_host.clone(), host_commitment);
        builder.set_native_query_rx(ones_host.clone());
        builder.set_native_registry_xy_poly(registry_xy_poly);
        // This dummy proof uses padding: every online slot is
        // padding, opened at the all-one challenge to its value one.
        builder.set_online_polynomials(core::array::from_fn(|_| online::padding()));
        builder.set_online_openings(online::queries_at(C::CircuitField::ONE, |_, _| {
            C::CircuitField::ONE
        }));
        // The eval stage carries the binding partial sums over the challenge
        // lifts, and the instance their completion; a dummy proof's are
        // those of the all-one challenges.
        let binding = crate::protocol::native::stages::eval::BindingPartials::compute::<C, R, B>(
            self.params,
            &nested_challenges,
        );
        builder.set_nested_challenges_partial(binding.binding);
        builder.set_native_eval_rx(
            crate::protocol::native::stages::eval::Stage::<C, R, HEADER_SIZE>::rx(
                C::CircuitField::ONE,
                &crate::protocol::native::stages::eval::Witness::<C>::trivial(binding),
            )
            .expect("trivial eval rx"),
        );
        // native_p_poly: deferred until after endoscaling computation,
        // since the real p commitment is the PointsStage last interstitial.
        builder.set_native_hashes_1_rx(ones_host.clone());
        builder.set_native_hashes_2_rx(ones_host.clone());
        builder.set_native_collapse_rx(ones_host.clone());
        builder.set_native_compute_v_rx(ones_host.clone());
        builder.set_native_bind_challenges_rxs(vec![ones_host.clone(); native::NUM_BINDERS]);
        builder.set_native_bind_beta_rx(ones_host.clone());
        builder.set_native_bind_endoscalar_rx(ones_host.clone());
        // The dummy carries the profile's extension polynomials as it does
        // the fuse's own circuits', as all-ones traces.
        let extension = C::Profile::native_extension();
        builder.set_native_extension_circuit_rxs(vec![ones_host.clone(); extension.circuits.len()]);
        builder.set_native_extension_stage_rxs(vec![ones_host.clone(); extension.stages]);

        // Nested accumulator: a trivial claim (all-ones traces), so that a
        // dummy child contributes a well-formed raw claim to its parent's
        // nested fold. The nested batch is trivial too, except for the
        // registry restriction a parent opens. Commitments are computed
        // lazily by the builder, except P_n, which the native walk below
        // computes.
        builder.set_nested_a_poly(ones_nested.clone());
        builder.set_nested_b_poly(ones_nested.clone());
        builder.set_nested_registry_xy_poly(nested_registry_xy_poly);

        let beta_endo = extract_endoscalar(C::CircuitField::ONE)
            .expect("one should satisfy the endoscalar challenge range");
        let mut trivial_rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed([0u8; 32]);

        // The native walk over placeholder nested-curve points, in the
        // nested batch's order, delegated to the real helpers so this
        // trivial setup cannot drift from the prover path. Its result is
        // this proof's P_n.
        // Every placeholder is the commitment of a polynomial this proof
        // holds, so that p_n is their beta-fold and P_n its commitment, as
        // a parent's batch requires of a child.
        builder.set_online_fq_polynomials(
            (0..C::Profile::ONLINE_FQ_POLYS)
                .map(|_| online_fq::placeholder())
                .collect(),
        );
        let (nested_p_poly, nested_p_commitment) = {
            let nested_commitment =
                B::sparse_commit_to_affine(&ones_nested, C::nested_generators(self.params));
            let registry_xy_commitment = builder.nested_registry_xy_commitment();
            let mut points = Vec::with_capacity(native::NumPoints::<C::Profile>::len());
            let mut polys: Vec<&sparse::Polynomial<C::ScalarField, R>> =
                Vec::with_capacity(native::NumPoints::<C::Profile>::len());
            let mut push = |point, poly| {
                points.push(point);
                polys.push(poly);
            };
            let registry_xy = builder.nested_registry_xy_poly();
            push(nested_commitment, &ones_nested); // f_n
            for _ in 0..2 {
                for _ in nested::RxIndex::all::<C::Profile>() {
                    push(nested_commitment, &ones_nested);
                }
                push(nested_commitment, &ones_nested); // a
                push(nested_commitment, &ones_nested); // b
                push(registry_xy_commitment, registry_xy); // registry_xy
                push(nested_commitment, &ones_nested); // p placeholder
            }
            push(nested_commitment, &ones_nested); // registry_wx0
            push(nested_commitment, &ones_nested); // registry_wx1
            push(nested_commitment, &ones_nested); // registry_wy
            push(nested_commitment, &ones_nested); // a
            push(nested_commitment, &ones_nested); // b
            push(registry_xy_commitment, registry_xy); // registry_xy
            for (poly, &commitment) in builder
                .online_fq_polynomials()
                .iter()
                .zip(builder.online_fq_commitments())
            {
                push(commitment, poly); // the step's own online Fq polynomial
            }
            let poly = beta_fold(&polys, lift_endoscalar(beta_endo));
            let inputs = Inputs::from_walk(&points);
            self.commit_native_points_stages(&mut trivial_rng, &inputs, &mut builder)
                .expect("trivial native points stages");
            let (commitment, _) = self
                .compute_native_endoscaling(&mut trivial_rng, beta_endo, &inputs, &mut builder)
                .expect("trivial native endoscaling");
            (poly, commitment)
        };
        builder.set_nested_p_poly(nested_p_poly, nested_p_commitment);

        // Commit the same synthetic challenge witness used for the binding
        // partials above, without blinding.
        builder.set_nested_challenges_rx(
            crate::protocol::nested::stages::challenges::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ZERO,
                &nested_challenges,
            )
            .expect("trivial challenge stage rx"),
        );
        builder.set_nested_collapse_rx(ones_nested.clone());
        builder.set_nested_compute_v_rx(ones_nested.clone());
        let extension = C::Profile::nested_extension();
        builder
            .set_nested_extension_circuit_rxs(vec![ones_nested.clone(); extension.circuits.len()]);
        builder.set_nested_extension_stage_rxs(vec![ones_nested; extension.stages]);

        // Bridge polynomials: compute via Stage::rx() with trivial witnesses
        // so that traces are valid for their witnesses (not just ones).
        // The cached bridge (ab) is already computed lazily by the builder
        // via cached_bridge! with a proper witness.
        //
        // Order: s_prime, inner_error, outer_error, query, f, eval first
        // (independent of p_commitment), then endoscaling (computes
        // p_commitment), then preamble (needs p_commitment for
        // ChildWitness.p), then native_p_poly.
        let nested_gen = C::nested_generators(self.params);
        {
            let rx =
                crate::protocol::nested::stages::s_prime::Stage::<C::HostCurve, R, C::Profile>::rx(
                    C::ScalarField::ONE,
                    &crate::protocol::nested::stages::s_prime::Witness {
                        registry_wx0: host_commitment,
                        registry_wx1: host_commitment,
                        native_points_registry_wx: builder.native_points_registry_wx_commitment(),
                    },
                )
                .expect("trivial s_prime rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_s_prime_rx(rx, commitment);
        }
        {
            let rx = crate::protocol::nested::stages::inner_error::Stage::<
                C::HostCurve,
                R,
                C::Profile,
            >::rx(
                C::ScalarField::ONE,
                &crate::protocol::nested::stages::inner_error::Witness {
                    native_inner_error: host_commitment,
                    registry_wy: host_commitment,
                    // A dummy proof folds nothing, so its nested fold has
                    // no error terms.
                    error_terms: FixedVec::from_fn(|_| FixedVec::from_fn(|_| C::ScalarField::ZERO)),
                },
            )
            .expect("trivial inner_error rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_inner_error_rx(rx, commitment);
        }
        {
            let rx = crate::protocol::nested::stages::outer_error::Stage::<
                C::HostCurve,
                R,
                C::Profile,
            >::rx(
                C::ScalarField::ONE,
                &crate::protocol::nested::stages::outer_error::Witness {
                    native_outer_error: builder.native_outer_error_commitment(),
                    error_terms: FixedVec::from_fn(|_| C::ScalarField::ZERO),
                    collapsed: FixedVec::from_fn(|_| C::ScalarField::ZERO),
                },
            )
            .expect("trivial outer_error rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_outer_error_rx(rx, commitment);
        }
        {
            let rx =
                crate::protocol::nested::stages::query::Stage::<C::HostCurve, R, C::Profile>::rx(
                    C::ScalarField::ONE,
                    &crate::protocol::nested::stages::query::Witness {
                        native_query: builder.native_query_commitment(),
                        registry_xy: builder.native_registry_xy_commitment(),
                        nested: crate::protocol::nested::stages::query::Evaluations::zero(),
                    },
                )
                .expect("trivial query rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_query_rx(rx, commitment);
        }
        {
            let rx = crate::protocol::nested::stages::f::Stage::<C::HostCurve, R, C::Profile>::rx(
                C::ScalarField::ONE,
                &crate::protocol::nested::stages::f::Witness {
                    native_f: host_commitment,
                    native_points_f: builder.native_points_f_commitment(),
                },
            )
            .expect("trivial f rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_f_rx(rx, commitment);
        }
        {
            let rx =
                crate::protocol::nested::stages::eval::Stage::<C::HostCurve, R, C::Profile>::rx(
                    C::ScalarField::ONE,
                    &crate::protocol::nested::stages::eval::Witness {
                        native_eval: builder.native_eval_commitment(),
                        nested: crate::protocol::nested::stages::eval::Evaluations::zero(),
                    },
                )
                .expect("trivial eval rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_eval_rx(rx, commitment);
        }

        // Build trivial PointsStage inputs in `_10_p` accumulation order
        // and delegate to `compute_endoscaling` so this trivial setup
        // cannot silently drift from the real prover path.
        // As on the nested side: every placeholder is the commitment of a
        // polynomial this proof holds, p is their beta-fold, and P is the
        // walk's result, which is then p's commitment.
        let (p_poly, p_commitment) = {
            let mut points = Vec::with_capacity(NumPoints::<C::Profile>::len());
            let mut polys: Vec<&sparse::Polynomial<C::CircuitField, R>> =
                Vec::with_capacity(NumPoints::<C::Profile>::len());
            let mut push = |point, poly| {
                points.push(point);
                polys.push(poly);
            };
            let registry_xy_commitment = builder.native_registry_xy_commitment();
            let registry_xy = builder.native_registry_xy_poly();
            let online_commitments = builder.online_commitments();
            let online = builder.online_polynomials();

            // Initial: native_f commitment.
            push(host_commitment, &ones_host);

            // Per-child block: all per-child commitments are
            // `host_commitment` (ones_host), except registry_xy which
            // has its own commitment.
            for _ in 0..2 {
                for _ in RxIndex::all::<C::Profile>() {
                    push(host_commitment, &ones_host);
                }
                push(host_commitment, &ones_host); // AbA
                push(host_commitment, &ones_host); // AbB
                push(registry_xy_commitment, registry_xy); // RegistryXY
                push(host_commitment, &ones_host); // P placeholder
            }

            // Current-step bridge inputs.
            push(host_commitment, &ones_host); // registry_wx0
            push(host_commitment, &ones_host); // registry_wx1
            push(host_commitment, &ones_host); // registry_wy
            push(host_commitment, &ones_host); // a
            push(host_commitment, &ones_host); // b
            push(registry_xy_commitment, registry_xy); // native_registry_xy
            // The six online slots: every one is this proof's own padding,
            // as the children of the bootstrap fuse that opens them hold it.
            for _ in 0..3 {
                for i in 0..NUM_ONLINE_FP_POLYS {
                    push(online_commitments[i], &online[i]);
                }
            }

            let poly = beta_fold(&polys, lift_endoscalar(beta_endo));
            let (commitment, _) = self
                .compute_endoscaling(
                    &mut trivial_rng,
                    beta_endo,
                    &points,
                    C::ScalarField::ONE,
                    C::ScalarField::ONE,
                    &mut builder,
                )
                .expect("trivial endoscaling");
            (poly, commitment)
        };

        // Set native_p_poly with the real accumulated commitment.
        builder.set_native_p_poly(p_poly, p_commitment);

        // Preamble bridge: computed last because ChildWitness.p needs
        // the real p_commitment from endoscaling.
        {
            let registry_xy_commitment = builder.native_registry_xy_commitment();
            let trivial_child_witness = crate::protocol::nested::stages::preamble::ChildWitness {
                application: host_commitment,
                hashes_1: host_commitment,
                hashes_2: host_commitment,
                collapse: host_commitment,
                compute_v: host_commitment,
                bind_challenges: [host_commitment; native::NUM_BINDERS],
                bind_beta: host_commitment,
                bind_endoscalar: host_commitment,
                extension_circuits: FixedVec::from_fn(|_| host_commitment),
                extension_stages: FixedVec::from_fn(|_| host_commitment),
                endoscaling_steps: FixedVec::from_fn(|_| host_commitment),
                points_walk: host_commitment,
                stashed_preamble: host_commitment,
                stashed_inner_error: host_commitment,
                stashed_outer_error: host_commitment,
                stashed_query: host_commitment,
                stashed_eval: host_commitment,
                stashed_ab_a: host_commitment,
                stashed_ab_b: host_commitment,
                stashed_registry_xy: registry_xy_commitment,
                stashed_p: p_commitment,
                stashed_points_binding: host_commitment,
                stashed_points_preamble: host_commitment,
                stashed_points_registry_wx: host_commitment,
                stashed_points_ab: host_commitment,
                stashed_points_f: host_commitment,
                stashed_online_commitments: builder.online_commitments(),
                stashed_application_stage: builder.native_application_stage_commitment(),
                // What a parent will read off this proof as its nested
                // instance scalars: a trivial "child" is this proof itself.
                nested: crate::protocol::nested::stages::preamble::NestedValues {
                    c: builder.nested_c(),
                    v: B::sparse_eval(builder.nested_p_poly(), nested_one),
                    x: nested_one,
                    y: nested_one,
                    u: nested_one,
                },
            };
            let rx = crate::protocol::nested::stages::preamble::Stage::<
                C::HostCurve,
                R,
                C::Profile,
            >::rx(
                C::ScalarField::ONE,
                &crate::protocol::nested::stages::preamble::Witness {
                    native_preamble: host_commitment,
                    native_points_binding: builder.native_points_binding_commitment(),
                    native_points_preamble: builder.native_points_preamble_commitment(),
                    online_commitments: builder.online_commitments(),
                    application_stage: builder.native_application_stage_commitment(),
                    left: trivial_child_witness.clone(),
                    right: trivial_child_witness,
                },
            )
            .expect("trivial preamble rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_preamble_rx(rx, commitment);

            let o1 = builder.online_commitments()[NUM_ONLINE_FP_POLYS - 1];
            let rx = crate::protocol::nested::stages::bridge_hash::rx::<C::HostCurve, R>(o1)
                .expect("trivial bridge-hash rx");
            let commitment = B::sparse_commit_to_affine(&rx, nested_gen);
            builder.set_bridge_hash_rx(rx, commitment);
        }

        // Challenges (all ones for trivial)
        builder.set_w(C::CircuitField::ONE);
        builder.set_y(C::CircuitField::ONE);
        builder.set_z(C::CircuitField::ONE);
        builder.set_mu(C::CircuitField::ONE);
        builder.set_mu_prime(C::CircuitField::ONE);
        builder.set_x(C::CircuitField::ONE);
        builder.set_alpha(C::CircuitField::ONE);
        builder.set_u(C::CircuitField::ONE);
        builder.set_pre_beta(C::CircuitField::ONE);

        // Commitments are computed lazily by the builder from the polynomials.
        builder.build().expect("dummy proof construction failed")
    }
}

use crate::{Pcd, Proof};
