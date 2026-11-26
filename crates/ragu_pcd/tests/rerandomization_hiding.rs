//! What a rerandomized proof holds of the proof it was made from.
//!
//! A fuse stores what it reads of its children as stage values, so one pass
//! through the rerandomization step leaves the input's commitments and
//! challenges in its output. `Application::rerandomize` runs two passes.
//! These tests take a proof apart into the field elements it holds and look
//! for the input's among them, and they check part of what the second pass
//! relies on: that every polynomial of the first pass's proof is dense,
//! carries its three free coefficients or holds only what the proof shows
//! anyway, and that the second pass's fold randomizer moves the
//! claim-dependent quotient directions at the sampled inputs, also when
//! its shown $A$ and $B$ tie it to the first pass's.
//! The rest of the argument, in the documentation of the `fuse::randomizer`
//! module, is not tested here.
//!
//! These are checks of the mechanism. None of them tests a distribution.

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Error,
    pasta::{EpAffine, EqAffine, Fp, Fq},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use super::{
    Proof,
    recursive_propagation_tests::support::{self, C, Merge, R, Seed, TestPcd},
};
use crate::{fuse::randomizer::observed, step::internal::rerandomize::Rerandomize};

/// How a polynomial of a proof keeps what it holds from whoever sees a
/// commitment to it and two of its evaluations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A trace or a stage with its three free coefficients drawn at random.
    Blinded,
    /// A polynomial the fuse's randomizers were folded into: the folded $A$
    /// and $B$ and the batched $p$.
    Dense,
    /// A function of values the proof shows as they are: its challenges,
    /// its own commitments, its online polynomials.
    Shown,
}

/// A proof taken apart, by field.
struct Parts<'a> {
    native: Vec<(&'static str, Kind, &'a sparse::Polynomial<Fp, R>)>,
    nested: Vec<(&'static str, Kind, &'a sparse::Polynomial<Fq, R>)>,
    /// Commitments on the host curve, whose coordinates are scalar-field
    /// elements.
    host: Vec<EqAffine>,
    /// Commitments on the nested curve, whose coordinates are
    /// circuit-field elements.
    nested_points: Vec<EpAffine>,
    /// The challenges and the accumulator's values.
    circuit_scalars: Vec<Fp>,
    scalar_scalars: Vec<Fq>,
    /// What the online polynomials alone determine, which a rerandomization
    /// carries over: their commitments and the bridge hash's.
    online_host: Vec<EqAffine>,
    online_nested: Vec<EpAffine>,
}

impl<'a> Parts<'a> {
    /// Takes `proof` apart. The pattern names every field, so that a field
    /// added to [`Proof`] is classified here before this compiles.
    fn of(proof: &'a Proof<C, R>) -> Self {
        use Kind::*;

        let Proof {
            bridge_alpha,
            circuit_id: _,
            nested_mesh_claims,
            nested_online_fold,
            native_mesh_claims,
            native_online_fold,
            nested_online_commitments,
            native_online_commitments,
            native_source_out,
            nested_source_out,
            native_preamble_rx,
            native_inner_error_rx,
            native_outer_error_rx,
            native_a_poly,
            native_b_poly,
            native_query_rx,
            native_registry_xy_poly,
            native_eval_rx,
            native_p_poly,
            native_hashes_1_rx,
            native_hashes_2_rx,
            native_collapse_rx,
            native_compute_v_rx,
            native_bind_challenges_rxs,
            native_bind_beta_rx,
            native_bind_endoscalar_rx,
            native_endoscaling_step_rxs,
            native_extension_circuit_rxs,
            native_extension_stage_rxs,
            native_points_binding_rx,
            native_points_preamble_rx,
            native_points_registry_wx_rx,
            native_points_ab_rx,
            native_points_f_rx,
            native_points_walk_rx,
            online_polynomials,
            step_binding,
            bridge_preamble_rx,
            bridge_hash_rx,
            bridge_s_prime_rx,
            bridge_inner_error_rx,
            bridge_outer_error_rx,
            bridge_query_rx,
            bridge_f_rx,
            bridge_eval_rx,
            bridge_ab_rx,
            nested_endoscaling_step_rxs,
            nested_extension_circuit_rxs,
            nested_extension_stage_rxs,
            nested_paged_stage_rxs,
            nested_step_rxs,
            nested_endoscalar_rx,
            nested_points_rx,
            nested_a_poly,
            nested_b_poly,
            nested_registry_xy_poly,
            nested_p_poly,
            nested_challenges_rx,
            nested_challenges_partial,
            nested_collapse_rx,
            nested_compute_v_rx,
            nested_endoscaling_step_commitments,
            nested_extension_circuit_commitments,
            nested_extension_stage_commitments,
            nested_paged_stage_commitments,
            nested_step_commitments,
            nested_endoscalar_commitment,
            nested_points_commitment,
            nested_a_commitment,
            nested_b_commitment,
            nested_registry_xy_commitment,
            nested_p_commitment,
            nested_challenges_commitment,
            nested_collapse_commitment,
            nested_compute_v_commitment,
            w,
            y,
            z,
            mu,
            mu_prime,
            x,
            alpha,
            u,
            pre_beta,
            native_preamble_commitment,
            native_inner_error_commitment,
            native_outer_error_commitment,
            native_a_commitment,
            native_b_commitment,
            native_query_commitment,
            native_registry_xy_commitment,
            native_eval_commitment,
            native_p_commitment,
            native_hashes_1_commitment,
            native_hashes_2_commitment,
            native_collapse_commitment,
            native_compute_v_commitment,
            native_bind_challenges_commitments,
            native_bind_beta_commitment,
            native_bind_endoscalar_commitment,
            native_endoscaling_step_commitments,
            native_extension_circuit_commitments,
            native_extension_stage_commitments,
            native_points_binding_commitment,
            native_points_preamble_commitment,
            native_points_registry_wx_commitment,
            native_points_ab_commitment,
            native_points_f_commitment,
            native_points_walk_commitment,
            online_commitments,
            bridge_preamble_commitment,
            bridge_hash_commitment,
            bridge_s_prime_commitment,
            bridge_inner_error_commitment,
            bridge_outer_error_commitment,
            bridge_query_commitment,
            bridge_f_commitment,
            bridge_eval_commitment,
            bridge_ab_commitment,
        } = proof;

        // The standard profile has no extension, no source mesh and no
        // online batch, so these hold nothing that would need classifying.
        assert!(
            nested_mesh_claims.is_empty()
                && nested_online_fold.is_empty()
                && native_mesh_claims.is_empty()
                && native_online_fold.is_empty()
                && nested_online_commitments.is_empty()
                && native_online_commitments.is_empty()
                && native_source_out.is_empty()
                && nested_source_out.is_empty()
                && native_extension_circuit_rxs.is_empty()
                && native_extension_stage_rxs.is_empty()
                && nested_extension_circuit_rxs.is_empty()
                && nested_extension_stage_rxs.is_empty()
                && nested_paged_stage_rxs.is_empty()
                && nested_step_rxs.is_empty()
                && native_extension_circuit_commitments.is_empty()
                && native_extension_stage_commitments.is_empty()
                && nested_extension_circuit_commitments.is_empty()
                && nested_extension_stage_commitments.is_empty()
                && nested_paged_stage_commitments.is_empty()
                && nested_step_commitments.is_empty()
                && step_binding.is_empty(),
            "the standard profile stores none of a profile's own values"
        );

        let mut native = Vec::from([
            ("native_preamble_rx", Blinded, native_preamble_rx),
            ("native_inner_error_rx", Blinded, native_inner_error_rx),
            ("native_outer_error_rx", Blinded, native_outer_error_rx),
            ("native_a_poly", Dense, native_a_poly),
            ("native_b_poly", Dense, native_b_poly),
            ("native_query_rx", Blinded, native_query_rx),
            // m(W, x, y), a function of the challenges.
            ("native_registry_xy_poly", Shown, native_registry_xy_poly),
            ("native_eval_rx", Blinded, native_eval_rx),
            ("native_p_poly", Dense, native_p_poly),
            ("native_hashes_1_rx", Blinded, native_hashes_1_rx),
            ("native_hashes_2_rx", Blinded, native_hashes_2_rx),
            ("native_collapse_rx", Blinded, native_collapse_rx),
            ("native_compute_v_rx", Blinded, native_compute_v_rx),
            ("native_bind_beta_rx", Blinded, native_bind_beta_rx),
            (
                "native_bind_endoscalar_rx",
                Blinded,
                native_bind_endoscalar_rx,
            ),
            (
                "native_points_binding_rx",
                Blinded,
                native_points_binding_rx,
            ),
            (
                "native_points_preamble_rx",
                Blinded,
                native_points_preamble_rx,
            ),
            (
                "native_points_registry_wx_rx",
                Blinded,
                native_points_registry_wx_rx,
            ),
            ("native_points_ab_rx", Blinded, native_points_ab_rx),
            ("native_points_f_rx", Blinded, native_points_f_rx),
            ("native_points_walk_rx", Blinded, native_points_walk_rx),
        ]);
        native.extend(
            native_bind_challenges_rxs
                .iter()
                .map(|rx| ("native_bind_challenges_rxs", Blinded, rx)),
        );
        native.extend(
            native_endoscaling_step_rxs
                .iter()
                .map(|rx| ("native_endoscaling_step_rxs", Blinded, rx)),
        );
        native.extend(
            online_polynomials
                .iter()
                .map(|poly| ("online_polynomials", Shown, poly)),
        );

        let mut nested = Vec::from([
            ("bridge_preamble_rx", Blinded, &**bridge_preamble_rx),
            // The stage of the last online commitment, with no alpha: the
            // hash is a function of the commitment alone.
            ("bridge_hash_rx", Shown, &**bridge_hash_rx),
            ("bridge_s_prime_rx", Blinded, &**bridge_s_prime_rx),
            ("bridge_inner_error_rx", Blinded, &**bridge_inner_error_rx),
            ("bridge_outer_error_rx", Blinded, &**bridge_outer_error_rx),
            ("bridge_query_rx", Blinded, &**bridge_query_rx),
            ("bridge_f_rx", Blinded, &**bridge_f_rx),
            ("bridge_eval_rx", Blinded, &**bridge_eval_rx),
            // The stage of the proof's own A and B commitments, under an
            // alpha the proof stores.
            ("bridge_ab_rx", Shown, &*bridge_ab_rx.0),
            ("nested_endoscalar_rx", Blinded, nested_endoscalar_rx),
            ("nested_points_rx", Blinded, &**nested_points_rx),
            ("nested_a_poly", Dense, nested_a_poly),
            ("nested_b_poly", Dense, nested_b_poly),
            ("nested_registry_xy_poly", Shown, nested_registry_xy_poly),
            ("nested_p_poly", Dense, nested_p_poly),
            // The lifts of the challenges, with no alpha.
            ("nested_challenges_rx", Shown, nested_challenges_rx),
            ("nested_collapse_rx", Blinded, nested_collapse_rx),
            ("nested_compute_v_rx", Blinded, nested_compute_v_rx),
        ]);
        nested.extend(
            nested_endoscaling_step_rxs
                .iter()
                .map(|rx| ("nested_endoscaling_step_rxs", Blinded, rx)),
        );

        let mut host = Vec::from([
            native_preamble_commitment.0,
            native_inner_error_commitment.0,
            native_outer_error_commitment.0,
            native_a_commitment.0,
            native_b_commitment.0,
            native_query_commitment.0,
            native_registry_xy_commitment.0,
            native_eval_commitment.0,
            native_p_commitment.0,
            native_hashes_1_commitment.0,
            native_hashes_2_commitment.0,
            native_collapse_commitment.0,
            native_compute_v_commitment.0,
            native_bind_beta_commitment.0,
            native_bind_endoscalar_commitment.0,
            native_points_binding_commitment.0,
            native_points_preamble_commitment.0,
            native_points_registry_wx_commitment.0,
            native_points_ab_commitment.0,
            native_points_f_commitment.0,
            native_points_walk_commitment.0,
        ]);
        host.extend(native_bind_challenges_commitments.iter().map(|c| c.0));
        host.extend(native_endoscaling_step_commitments.iter().map(|c| c.0));

        let mut nested_points = Vec::from([
            *nested_challenges_partial,
            nested_endoscalar_commitment.0,
            nested_points_commitment.0,
            nested_a_commitment.0,
            nested_b_commitment.0,
            nested_registry_xy_commitment.0,
            nested_p_commitment.0,
            nested_challenges_commitment.0,
            nested_collapse_commitment.0,
            nested_compute_v_commitment.0,
            *bridge_preamble_commitment,
            *bridge_s_prime_commitment,
            *bridge_inner_error_commitment,
            *bridge_outer_error_commitment,
            *bridge_query_commitment,
            *bridge_f_commitment,
            *bridge_eval_commitment,
            bridge_ab_commitment.0,
        ]);
        nested_points.extend(nested_endoscaling_step_commitments.iter().map(|c| c.0));

        Parts {
            native,
            nested,
            host,
            nested_points,
            circuit_scalars: Vec::from([
                *w,
                *y,
                *z,
                *mu,
                *mu_prime,
                *x,
                *alpha,
                *u,
                *pre_beta,
                proof.native_c(),
                proof.v(),
            ]),
            scalar_scalars: Vec::from([
                *bridge_alpha,
                proof.nested_c(),
                proof.nested_v().expect("the challenges lift"),
            ]),
            online_host: online_commitments.iter().map(|c| c.0).collect(),
            online_nested: Vec::from([*bridge_hash_commitment]),
        }
    }

    /// The proof's own values, the ones a fuse over it reads: its
    /// commitments' coordinates, its challenges and its accumulator's
    /// values. What its online polynomials determine is left out.
    fn own(&self) -> OwnValues {
        OwnValues {
            circuit: (self.circuit_scalars.iter().copied())
                .chain(self.nested_points.iter().flat_map(coordinates))
                .map(|value| value.to_bytes().as_ref().to_vec())
                .collect(),
            scalar: (self.scalar_scalars.iter().copied())
                .chain(self.host.iter().flat_map(coordinates))
                .map(|value| value.to_bytes().as_ref().to_vec())
                .collect(),
        }
    }

    /// Every circuit-field element the proof holds.
    fn circuit_field(&self) -> impl Iterator<Item = Fp> + '_ {
        (self.native.iter())
            .flat_map(|(_, _, poly)| poly.iter_coeffs())
            .chain(self.circuit_scalars.iter().copied())
            .chain(
                (self.nested_points.iter())
                    .chain(&self.online_nested)
                    .flat_map(coordinates),
            )
    }

    /// Every scalar-field element the proof holds.
    fn scalar_field(&self) -> impl Iterator<Item = Fq> + '_ {
        (self.nested.iter())
            .flat_map(|(_, _, poly)| poly.iter_coeffs())
            .chain(self.scalar_scalars.iter().copied())
            .chain(
                (self.host.iter())
                    .chain(&self.online_host)
                    .flat_map(coordinates),
            )
    }

    /// Asserts that every polynomial is hidden as its [`Kind`] says.
    fn assert_hidden(&self) {
        fn check<F: Field>(name: &str, kind: Kind, poly: &sparse::Polynomial<F, R>) {
            let coeffs: Vec<F> = poly.iter_coeffs().collect();
            let n = R::n();
            match kind {
                Kind::Blinded => assert!(
                    [2 * n - 1, n, 3 * n]
                        .iter()
                        .all(|&free| coeffs[free] != F::ZERO),
                    "{name} lacks a free coefficient"
                ),
                Kind::Dense => assert!(
                    coeffs.iter().all(|coeff| *coeff != F::ZERO),
                    "{name} has a zero coefficient"
                ),
                Kind::Shown => {}
            }
        }
        for (name, kind, poly) in &self.native {
            check(name, *kind, poly);
        }
        for (name, kind, poly) in &self.nested {
            check(name, *kind, poly);
        }
    }
}

/// A proof's own values, by field, as canonical bytes.
struct OwnValues {
    circuit: BTreeSet<Vec<u8>>,
    scalar: BTreeSet<Vec<u8>>,
}

impl OwnValues {
    /// How many elements of `proof`, by field, are among these values.
    fn found_in(&self, proof: &Parts<'_>) -> (usize, usize) {
        (
            proof
                .circuit_field()
                .filter(|value| self.circuit.contains(value.to_bytes().as_ref()))
                .count(),
            proof
                .scalar_field()
                .filter(|value| self.scalar.contains(value.to_bytes().as_ref()))
                .count(),
        )
    }
}

fn coordinates<P: Affine>(point: &P) -> impl Iterator<Item = P::Base> {
    point.coordinates().into_iter().flat_map(|(x, y)| [x, y])
}

/// A proof with two generations beneath it.
fn input(app: &support::App, rng: &mut StdRng) -> TestPcd {
    let left = app.seed(rng, Seed::new(), Fp::from(3)).unwrap().0;
    let right = app.seed(rng, Seed::new(), Fp::from(5)).unwrap().0;
    app.fuse(rng, Merge::new(), Fp::from(7), left, right)
        .unwrap()
        .0
}

/// One pass of `Application::rerandomize`.
fn pass(app: &support::App, rng: &mut StdRng, pcd: TestPcd) -> TestPcd {
    app.fuse(rng, Rerandomize::new(), (), pcd, app.bootstrap_pcd())
        .unwrap()
        .0
}

/// One pass leaves the input's own values in its output as they are, in
/// both fields. Two leave none, and carry the header's data and online
/// commitments over.
#[test]
fn two_passes_leave_none_of_the_inputs_values() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7e12_a9d0);
        let input = input(app, &mut rng);
        let own = Parts::of(input.proof()).own();
        assert!(own.circuit.len() > 40 && own.scalar.len() > 40);

        let once = pass(app, &mut rng, input.clone());
        let (circuit, scalar) = own.found_in(&Parts::of(once.proof()));
        assert!(
            circuit > 0 && scalar > 0,
            "one pass shows the input's values: found {circuit} and {scalar}"
        );

        let twice = app.rerandomize(input.clone(), &mut rng).unwrap();
        assert!(app.verify_uncompressed(&twice, &mut rng).unwrap());
        assert_eq!(own.found_in(&Parts::of(twice.proof())), (0, 0));
        assert_eq!(twice.data(), input.data());
        assert_eq!(
            twice.proof().online_commitments(),
            input.proof().online_commitments()
        );
    });
}

/// Every polynomial of either pass's proof is dense, carries its three
/// free coefficients or holds only what the proof shows anyway. The second
/// pass exposes each of the first pass's polynomials on its own as a
/// commitment and two evaluations, which is what three free coefficients
/// hide.
#[test]
fn each_pass_hides_its_polynomials() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7e12_a9d1);
        let input = input(app, &mut rng);
        let once = pass(app, &mut rng, input);
        Parts::of(once.proof()).assert_hidden();
        let twice = pass(app, &mut rng, once);
        Parts::of(twice.proof()).assert_hidden();
    });
}

/// Rerandomization enforces its input's claims in both passes, and its
/// randomizers' claims beside them change nothing of that: an input that
/// does not verify has no rerandomization that does. The inputs are a
/// child that never ran and a proof carried under other data than its own.
#[test]
fn an_invalid_input_stays_invalid() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7e12_a9d3);
        let honest = input(app, &mut rng);
        let relabelled = honest.proof().clone().carry(*honest.data() + Fp::ONE);
        for invalid in [support::dummy_as_value(app), relabelled] {
            assert!(!app.verify_differential(&invalid, &mut rng).unwrap());
            let once = pass(app, &mut rng, invalid.clone());
            assert!(!app.verify_differential(&once, &mut rng).unwrap());
            let twice = app.rerandomize(invalid, &mut rng).unwrap();
            assert!(!app.verify_differential(&twice, &mut rng).unwrap());
        }
    });
}

#[test]
fn a_child_with_a_mismatched_bridge_alpha_is_rejected() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7e12_a9d4);
        let honest = input(app, &mut rng);
        assert!(app.verify_differential(&honest, &mut rng).unwrap());

        let mut proof = honest.proof().clone();
        proof.bridge_alpha += Fq::ONE;
        let bytes = proof.to_bytes().unwrap();
        let invalid: TestPcd = Proof::from_bytes(&bytes).unwrap().carry(*honest.data());
        assert!(!app.verify_differential(&invalid, &mut rng).unwrap());

        for (left, right) in [
            (invalid.clone(), honest.clone()),
            (honest.clone(), invalid.clone()),
        ] {
            assert!(matches!(
                app.fuse(&mut rng, Merge::new(), Fp::ONE, left, right),
                Err(Error::InvalidWitness(_))
            ));
        }
        assert!(matches!(
            app.rerandomize(invalid, &mut rng),
            Err(Error::InvalidWitness(_))
        ));
    });
}

/// Stops watching when the test that started it ends, by returning or by
/// panicking.
struct Watch;

impl Drop for Watch {
    fn drop(&mut self) {
        observed::watch(false);
    }
}

/// The second pass's fold randomizers move the claim-dependent quotient
/// directions for this input. The local rank is also checked with the
/// randomizers tied to the first pass's $A$ and $B$ by the second pass's
/// shown $A$ and $B$. This checks a Jacobian at fixed challenges; it does
/// not show that the joint output distribution hides every valid input.
#[test]
fn the_second_pass_randomizers_reach_every_quotient() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7e12_a9d2);
        let input = input(app, &mut rng);
        let once = pass(app, &mut rng, input);

        let _watch = Watch;
        observed::watch(true);
        pass(app, &mut rng, once);
        let reaches = observed::reaches();

        // The native fold and then the nested one: a coefficient per claim
        // and one per group that holds a claim.
        assert_eq!(
            reaches.iter().map(|r| r.coefficients).collect::<Vec<_>>(),
            [95 + 14, 82 + 11]
        );
        for reach in reaches {
            assert_eq!(reach.rank, reach.coefficients);
            // The last occupied group has empty nodes. Its quotient fixes
            // the randomizer target's variation; with the folded A and B
            // fixed at the tested non-node challenges, the fold identity
            // also ties the first child's target
            // to the quotients. The first claim adds one local direction,
            // not two independent target directions.
            assert_eq!(reach.accumulator, reach.coefficients + 1);
        }
    });
}

/// What a chosen input could put in the stages of the first pass that hold
/// its values, beside the free coefficients the rerandomizer draws.
#[derive(Clone, Copy, Debug)]
enum Chosen {
    /// Nothing: every coefficient but the free ones is zero.
    Nothing,
    /// The bootstrap proof's own stage, whose mask claim the second pass
    /// folds together with the first pass's.
    Bootstrap,
}

impl Chosen {
    /// `own` with every coefficient but its free ones replaced.
    fn apply<F: Field>(
        self,
        own: &sparse::Polynomial<F, R>,
        bootstrap: &sparse::Polynomial<F, R>,
    ) -> sparse::Polynomial<F, R> {
        let n = R::n();
        let free = [2 * n - 1, n, 3 * n];
        sparse::Polynomial::from_coeffs(
            own.iter_coeffs()
                .zip(bootstrap.iter_coeffs())
                .enumerate()
                .map(|(i, (own, bootstrap))| match self {
                    _ if free.contains(&i) => own,
                    Chosen::Nothing => F::ZERO,
                    Chosen::Bootstrap => bootstrap,
                })
                .collect(),
        )
    }
}

/// The sampled folds' claim-dependent quotient directions are reached.
fn assert_reached(reaches: Vec<observed::Reach>) {
    assert_eq!(
        reaches.iter().map(|r| r.coefficients).collect::<Vec<_>>(),
        [95 + 14, 82 + 11]
    );
    for reach in reaches {
        assert_eq!(reach.rank, reach.coefficients);
        assert_eq!(reach.accumulator, reach.coefficients + 1);
    }
}

/// The first pass's own randomizers reach every quotient coefficient of its
/// folds, so the quotient coefficients its inner error stages hold are free
/// for the second pass's folded $B$ to rest on. And the second pass's reach
/// does not depend on what an input puts in the stages of the first pass
/// that hold the input's values: its preamble, the two points stages holding
/// the input's nested commitments and its preamble bridge. It stays full
/// when those hold nothing but their free coefficients, or the bootstrap
/// proof's contents, and for an input seeded straight from the bootstrap.
#[test]
fn chosen_stage_contents_leave_every_quotient_reached() {
    support::with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x7e12_a9d4);
        let input = input(app, &mut rng);

        let _watch = Watch;
        observed::watch(true);
        let once = pass(app, &mut rng, input);
        assert_reached(observed::reaches());

        let bootstrap = app.bootstrap_proof();
        for chosen in [Chosen::Nothing, Chosen::Bootstrap] {
            let (mut proof, data) = once.clone().into_parts();
            proof.native_preamble_rx =
                chosen.apply(&proof.native_preamble_rx, &bootstrap.native_preamble_rx);
            proof.native_points_binding_rx = chosen.apply(
                &proof.native_points_binding_rx,
                &bootstrap.native_points_binding_rx,
            );
            proof.native_points_preamble_rx = chosen.apply(
                &proof.native_points_preamble_rx,
                &bootstrap.native_points_preamble_rx,
            );
            proof.bridge_preamble_rx =
                Arc::new(chosen.apply(&proof.bridge_preamble_rx, &bootstrap.bridge_preamble_rx));
            observed::watch(true);
            pass(app, &mut rng, proof.carry(data));
            assert_reached(observed::reaches());
        }

        let seeded = app.seed(&mut rng, Seed::new(), Fp::from(11)).unwrap().0;
        let once = pass(app, &mut rng, seeded);
        observed::watch(true);
        pass(app, &mut rng, once);
        assert_reached(observed::reaches());
    });
}
