//! Round trips of the IPA prover and verifier on both curves of the cycle,
//! rejection of tampered openings, and agreement of the deferred-generator
//! path with the direct check. Each curve's suite runs on the fuse's
//! transcript through the view that curve's IPA uses.
//!
//! Small parameters keep the PR gate quick; one full-size round trip per
//! curve over the baked generators is `#[ignore]`d for the heavy-tests run.

use ragu_pasta::Pasta;

use super::{CycleTranscript, IPA_TAG};

const K: u32 = 8;

/// A transcript that has seen nothing but the domain tag.
fn fresh() -> CycleTranscript<'static, Pasta> {
    CycleTranscript::new(Pasta::baked(), IPA_TAG).unwrap()
}

/// The suite for one curve of the cycle, given its scalar field, its
/// generators accessor on [`Pasta`], and the [`CycleTranscript`] view its
/// IPA uses.
macro_rules! ipa_tests {
    ($name:ident, $curve:ty, $field:ty, $generators_ty:ident, $generators_fn:ident, $side:ident) => {
        mod $name {
            use alloc::vec::Vec;

            use proptest::prelude::*;
            use ragu_arithmetic::{
                CurveAffine, Cycle, eval,
                ff::Field,
                group::Curve,
                rand::{SeedableRng, rngs::StdRng},
            };
            use ragu_circuits::polynomials::{Rank, TestRank, sparse};
            use ragu_pasta::Pasta;

            use super::{K, fresh};
            use crate::ipa::{
                Blind, CycleTranscript, Guard, IpaProof, IpaTranscript, MSM, Params, prover,
                verifier,
            };

            type C = $curve;
            type F = $field;

            fn generators() -> &'static <Pasta as Cycle>::$generators_ty {
                Pasta::$generators_fn(Pasta::baked())
            }

            fn params(k: u32) -> Params<C> {
                Params::with_k(generators(), k)
            }

            fn random_poly(n: usize, rng: &mut StdRng) -> Vec<F> {
                (0..n).map(|_| F::random(&mut *rng)).collect()
            }

            /// A transcript that has seen the common inputs: the commitment
            /// being opened, the point, and the claimed value.
            fn transcript_for(commitment: C, x: F, v: F) -> CycleTranscript<'static, Pasta> {
                let mut transcript = fresh();
                {
                    let mut side = transcript.$side();
                    side.write_point(commitment).unwrap();
                    side.write_scalar(x).unwrap();
                    side.write_scalar(v).unwrap();
                }
                transcript
            }

            /// The prover's side: commit to `poly` under `blind`, open it at
            /// `x`, and return the claim with its proof.
            fn open(
                params: &Params<C>,
                poly: &[F],
                blind: Blind<F>,
                x: F,
                rng: &mut StdRng,
            ) -> (C, F, IpaProof<C>) {
                let commitment = params.commit(poly, blind).to_affine();
                let v = eval(poly.iter(), x);

                let mut transcript = transcript_for(commitment, x, v);
                let proof =
                    prover::create_proof(params, rng, &mut transcript.$side(), poly, blind, x)
                        .unwrap();
                (commitment, v, proof)
            }

            /// The verifier's side up to the guard, on a transcript that saw
            /// `x_seen` as the point.
            fn verify_seeing<'a>(
                params: &'a Params<C>,
                commitment: C,
                x_seen: F,
                x: F,
                v: F,
                proof: &IpaProof<C>,
            ) -> crate::Result<Guard<'a, C>> {
                let mut transcript = transcript_for(commitment, x_seen, v);
                let mut msm = MSM::new(params);
                msm.append_term(F::ONE, commitment);
                verifier::verify_proof(params, msm, &mut transcript.$side(), proof, x, v)
            }

            /// The verifier's side up to the guard.
            fn verify<'a>(
                params: &'a Params<C>,
                commitment: C,
                x: F,
                v: F,
                proof: &IpaProof<C>,
            ) -> Guard<'a, C> {
                verify_seeing(params, commitment, x, x, v, proof).unwrap()
            }

            /// The verifier's side through the direct linear-time check.
            fn check(params: &Params<C>, commitment: C, x: F, v: F, proof: &IpaProof<C>) -> bool {
                verify(params, commitment, x, v, proof)
                    .use_challenges()
                    .eval()
            }

            /// A claim with its proof, on `K`-sized parameters, under a random
            /// blind.
            fn opening(params: &Params<C>, seed: u64) -> (C, F, F, IpaProof<C>) {
                let mut rng = StdRng::seed_from_u64(seed);
                let poly = random_poly(1 << K, &mut rng);
                let blind = Blind(F::random(&mut rng));
                let x = F::random(&mut rng);
                let (commitment, v, proof) = open(params, &poly, blind, x, &mut rng);
                (commitment, x, v, proof)
            }

            #[test]
            fn round_trip() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 1);
                assert!(check(&params, commitment, x, v, &proof));
            }

            #[test]
            fn round_trip_without_blinding() {
                let params = params(K);
                let mut rng = StdRng::seed_from_u64(2);
                let poly = random_poly(1 << K, &mut rng);
                let x = F::random(&mut rng);
                let (commitment, v, proof) = open(&params, &poly, Blind(F::ZERO), x, &mut rng);
                assert!(check(&params, commitment, x, v, &proof));
            }

            #[test]
            fn rejects_wrong_value() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 3);
                assert!(!check(&params, commitment, x, v + F::ONE, &proof));
            }

            #[test]
            fn rejects_wrong_point() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 4);
                assert!(!check(&params, commitment, x + F::ONE, v, &proof));
            }

            #[test]
            fn rejects_wrong_commitment() {
                let params = params(K);
                let (_, x, v, proof) = opening(&params, 5);
                let mut rng = StdRng::seed_from_u64(6);
                let other = params
                    .commit(&random_poly(1 << K, &mut rng), Blind(F::ZERO))
                    .to_affine();
                assert!(!check(&params, other, x, v, &proof));
            }

            #[test]
            fn rejects_wrong_blind() {
                let params = params(K);
                let mut rng = StdRng::seed_from_u64(7);
                let poly = random_poly(1 << K, &mut rng);
                let blind = Blind(F::random(&mut rng));
                let x = F::random(&mut rng);
                let (commitment, v, _) = open(&params, &poly, blind, x, &mut rng);

                // A proof made under a different blind than the commitment.
                let other = Blind(blind.0 + F::ONE);
                let (_, _, proof) = open(&params, &poly, other, x, &mut rng);
                assert!(!check(&params, commitment, x, v, &proof));
            }

            #[test]
            fn rejects_tampered_proof() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 8);

                let mut tampered = proof.clone();
                tampered.c += F::ONE;
                assert!(!check(&params, commitment, x, v, &tampered));

                let mut tampered = proof.clone();
                tampered.f += F::ONE;
                assert!(!check(&params, commitment, x, v, &tampered));

                let mut tampered = proof.clone();
                let (l, r) = tampered.rounds[0];
                tampered.rounds[0] = (r, l);
                assert!(!check(&params, commitment, x, v, &tampered));

                let mut tampered = proof;
                tampered.s_commitment = commitment;
                assert!(!check(&params, commitment, x, v, &tampered));
            }

            #[test]
            fn rejects_mismatched_params() {
                let full = params(K);
                let (commitment, x, v, proof) = opening(&full, 9);

                // Parameters one size down: the proof has one round too many.
                let smaller = params(K - 1);
                assert!(verify_seeing(&smaller, commitment, x, x, v, &proof).is_err());

                // A proof with one round too few.
                let mut truncated = proof;
                truncated.rounds.pop();
                assert!(verify_seeing(&full, commitment, x, x, v, &truncated).is_err());
            }

            #[test]
            fn rejects_transcript_mismatch() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 10);

                // The verifier's transcript saw a different point than the one
                // it checks the opening at, so its challenges diverge from the
                // prover's.
                let guard = verify_seeing(&params, commitment, x + F::ONE, x, v, &proof).unwrap();
                assert!(!guard.use_challenges().eval());
            }

            #[test]
            fn deferred_generator_agrees_with_direct_check() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 11);
                let guard = verify(&params, commitment, x, v, &proof);

                let g = guard.compute_g();
                let (msm, accumulator) = guard.clone().use_g(g);
                assert!(msm.eval());
                assert_eq!(accumulator.g, g);
                assert_eq!(accumulator.u.len(), K as usize);

                let (msm, _) = guard.use_g(params.g[0]);
                assert!(!msm.eval());
            }

            #[test]
            fn proof_is_deterministic() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 12);
                let (commitment_again, x_again, v_again, proof_again) = opening(&params, 12);
                assert_eq!(commitment, commitment_again);
                assert_eq!((x, v), (x_again, v_again));
                assert_eq!(proof, proof_again);
            }

            /// A zero-blind `Params::commit` is the native commitment
            /// `sparse::Polynomial` computes under the same generators,
            /// coefficient $i$ on generator $i$, so the IPA opens exactly what
            /// the proof system commits to.
            #[test]
            fn commitment_matches_native_commitment() {
                let params = Params::with_k(generators(), TestRank::RANK);
                assert_eq!(params.g.len(), TestRank::num_coeffs());
                let mut rng = StdRng::seed_from_u64(13);
                let coeffs = random_poly(TestRank::num_coeffs(), &mut rng);

                let ipa = params.commit(&coeffs, Blind(F::ZERO)).to_affine();
                let native = sparse::Polynomial::<F, TestRank>::from_coeffs(coeffs)
                    .commit_to_affine(generators());
                assert_eq!(ipa, native);
            }

            /// halo2's `msm_arithmetic` test; both Pasta curves are
            /// $y^2 = x^3 + 5$, so $(-1, 2)$ lies on either.
            #[test]
            fn msm_arithmetic() {
                type Base = <C as CurveAffine>::Base;

                let base = C::from_xy(-Base::ONE, Base::from(2)).unwrap();
                let base_viol = (base + base).to_affine();

                let params = params(4);
                let mut a = MSM::new(&params);
                a.append_term(F::ONE, base);
                // a = [1] P
                assert!(!a.clone().eval());
                a.append_term(F::ONE, base);
                // a = [1+1] P
                assert!(!a.clone().eval());
                a.append_term(-F::ONE, base_viol);
                // a = [1+1] P + [-1] 2P
                assert!(a.clone().eval());
                let b = a.clone();

                // Append a point that is the negation of an existing one.
                a.append_term(F::from(4), -base);
                // a = [1+1-4] P + [-1] 2P
                assert!(!a.clone().eval());
                a.append_term(F::from(2), base_viol);
                // a = [1+1-4] P + [-1+2] 2P
                assert!(a.clone().eval());

                // Add two MSMs with common bases.
                a.scale(F::from(3));
                a.add_msm(&b);
                // a = [3*(1+1)+(1+1-4)] P + [3*(-1)+(-1+2)] 2P
                assert!(a.clone().eval());

                let mut c = MSM::new(&params);
                c.append_term(F::from(2), base);
                c.append_term(F::ONE, -base_viol);
                // c = [2] P + [1] (-2P)
                assert!(c.clone().eval());
                // Add two MSMs with bases that differ only in sign.
                a.add_msm(&c);
                assert!(a.eval());
            }

            #[test]
            #[ignore]
            fn round_trip_full_size() {
                let params = Params::new(generators());
                let mut rng = StdRng::seed_from_u64(14);
                let poly = random_poly(params.n as usize, &mut rng);
                let blind = Blind(F::random(&mut rng));
                let x = F::random(&mut rng);
                let (commitment, v, proof) = open(&params, &poly, blind, x, &mut rng);
                assert!(check(&params, commitment, x, v, &proof));
                assert!(!check(&params, commitment, x, v + F::ONE, &proof));
            }

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(12))]

                /// Honest openings verify and a single corrupted coefficient
                /// is rejected, across sizes down to the one-round case.
                #[test]
                fn round_trips_and_rejects_corruption(
                    k in 1u32..=5,
                    seed in any::<u64>(),
                    index in any::<usize>(),
                ) {
                    let params = params(k);
                    let mut rng = StdRng::seed_from_u64(seed);
                    let n = 1usize << k;
                    let poly = random_poly(n, &mut rng);
                    let blind = Blind(F::random(&mut rng));
                    let x = F::random(&mut rng);
                    let (commitment, v, proof) = open(&params, &poly, blind, x, &mut rng);
                    prop_assert!(check(&params, commitment, x, v, &proof));

                    // Open a polynomial that differs from the committed one in
                    // one coefficient; the claimed value is recomputed
                    // honestly for it.
                    let mut corrupted = poly.clone();
                    corrupted[index % n] += F::ONE;
                    let (_, v_corrupted, proof_corrupted) =
                        open(&params, &corrupted, blind, x, &mut rng);
                    prop_assert!(!check(&params, commitment, x, v_corrupted, &proof_corrupted));
                }
            }
        }
    };
}

ipa_tests!(
    host,
    ragu_pasta::EqAffine,
    ragu_pasta::Fp,
    HostGenerators,
    host_generators,
    host
);
ipa_tests!(
    nested,
    ragu_pasta::EpAffine,
    ragu_pasta::Fq,
    NestedGenerators,
    nested_generators,
    nested
);

/// Both IPAs share one chain: what the host side absorbs moves the nested
/// side's next challenge, and vice versa.
#[test]
fn sides_share_one_transcript() {
    use ragu_arithmetic::{Cycle, FixedGenerators};

    use crate::ipa::IpaTranscript;

    let host_point = Pasta::host_generators(Pasta::baked()).g()[0];
    let nested_point = Pasta::nested_generators(Pasta::baked()).g()[0];

    let mut a = fresh();
    let nested_after_nothing = a.nested().squeeze_challenge().unwrap();

    let mut b = fresh();
    b.host().write_point(host_point).unwrap();
    let nested_after_host = b.nested().squeeze_challenge().unwrap();
    assert_ne!(nested_after_nothing, nested_after_host);

    let mut c = fresh();
    c.nested().write_point(nested_point).unwrap();
    let host_after_nested = c.host().squeeze_challenge().unwrap();
    let mut d = fresh();
    let host_after_nothing = d.host().squeeze_challenge().unwrap();
    assert_ne!(host_after_nothing, host_after_nested);

    // The nested challenge is the lift of the host one at the same state.
    let mut e = fresh();
    let host = e.host().squeeze_challenge().unwrap();
    let mut f = fresh();
    let nested = f.nested().squeeze_challenge().unwrap();
    assert_eq!(
        nested,
        crate::internal::nested::challenge::<Pasta>(host).unwrap()
    );
}
