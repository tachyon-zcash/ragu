//! Round trips of the IPA prover and verifier on both curves of the cycle,
//! rejection of tampered openings, and agreement of the deferred-generator
//! path with the direct check. Each curve's suite runs on the fuse's
//! transcript through the view that curve's IPA uses.
//!
//! Small parameters keep the PR gate quick; one full-size round trip per
//! curve over the baked generators is `#[ignore]`d for the heavy-tests run.

use ragu_core::{
    Error,
    pasta::{Fp, Fq, Pasta},
};
use udon::field::Field;

use super::{CycleTranscript, IPA_TAG, transcript::convert_challenge};

const K: u32 = 8;

/// A transcript that has seen nothing but the domain tag.
fn fresh() -> CycleTranscript<'static, Pasta> {
    CycleTranscript::new(crate::pasta::baked(), IPA_TAG).unwrap()
}

/// The suite for one curve of the cycle, given its scalar field, its
/// generators accessor on [`Pasta`], and the [`CycleTranscript`] view its
/// IPA uses.
macro_rules! ipa_tests {
    ($name:ident, $curve:ty, $field:ty, $generators_ty:ident, $generators_fn:ident, $u_fn:ident, $side:ident) => {
        mod $name {
            use alloc::vec::Vec;

            use proptest::prelude::*;
            use ragu_backend::ReferenceBackend;
            use ragu_circuits::polynomials::{Rank, TestRank, sparse};
            use ragu_core::{Cycle, Error, FixedGenerators, pasta::Pasta};
            use rand::{Rng, SeedableRng, rngs::StdRng};
            use udon::{
                curve::{Affine, Projective},
                field::Field,
                polynomial::evaluate_iter,
            };

            use super::{K, fresh};
            use crate::ipa::{
                CycleTranscript, Guard, IpaCycle, IpaProof, IpaTranscript, MSM, Params, prover,
                verifier,
            };

            type C = $curve;
            type F = $field;

            /// Supplies a zero at one IPA round to exercise an exceptional
            /// challenge without searching for a real transcript preimage.
            struct ZeroRoundTranscript {
                round: usize,
                drawn: usize,
            }

            impl IpaTranscript<C> for ZeroRoundTranscript {
                fn write_point(&mut self, _: C) -> crate::Result<()> {
                    Ok(())
                }

                fn write_scalar(&mut self, _: F) -> crate::Result<()> {
                    Ok(())
                }

                fn squeeze_challenge(&mut self) -> crate::Result<F> {
                    // xi and z precede the round challenges.
                    let zero = self.drawn == self.round + 2;
                    self.drawn += 1;
                    Ok(if zero {
                        F::ZERO
                    } else {
                        F::from(self.drawn as u64 + 1)
                    })
                }
            }

            fn generators() -> &'static <Pasta as Cycle>::$generators_ty {
                Pasta::$generators_fn(crate::pasta::baked())
            }

            fn u() -> C {
                *Pasta::$u_fn(crate::pasta::baked())
            }

            fn params(k: u32) -> Params<C> {
                Params::with_k(generators(), u(), k)
            }

            fn random_poly(n: usize, rng: &mut StdRng) -> Vec<F> {
                (0..n)
                    .map(|_| F::random(|bytes| rng.fill_bytes(bytes)))
                    .collect()
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

            /// The prover's side: commit to `poly`, open it at
            /// `x`, and return the claim with its proof.
            fn open(params: &Params<C>, poly: &[F], x: F, rng: &mut StdRng) -> (C, F, IpaProof<C>) {
                let commitment = params.commit(poly).to_affine();
                let v = evaluate_iter(poly.iter(), x);

                let mut transcript = transcript_for(commitment, x, v);
                let proof =
                    prover::create_proof(params, rng, &mut transcript.$side(), poly, x).unwrap();
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

            /// A claim with its proof on the provided parameters.
            fn opening(params: &Params<C>, seed: u64) -> (C, F, F, IpaProof<C>) {
                let mut rng = StdRng::seed_from_u64(seed);
                let poly = random_poly(params.n as usize, &mut rng);
                let x = F::random(|bytes| rng.fill_bytes(bytes));
                let (commitment, v, proof) = open(params, &poly, x, &mut rng);
                (commitment, x, v, proof)
            }

            #[test]
            fn round_trip() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 1);
                assert!(check(&params, commitment, x, v, &proof));
            }

            #[test]
            fn rejects_blinded_commitment_after_recomputing_transcript() {
                let params = params(K);
                let mut rng = StdRng::seed_from_u64(0x462);
                let poly = random_poly(1 << K, &mut rng);
                let x = F::random(|bytes| rng.fill_bytes(bytes));
                let v = evaluate_iter(&poly, x);
                let blind = F::from(0x462);

                // Both the old W and another public base: changing the
                // blinding generator must not restore blinded openings.
                for base in [*generators().h(), params.u] {
                    let commitment = (params.commit(&poly) + &(base * blind)).to_affine();
                    let mut transcript = transcript_for(commitment, x, v);
                    let proof =
                        prover::create_proof(&params, &mut rng, &mut transcript.$side(), &poly, x)
                            .unwrap();
                    let mut msm = verify(&params, commitment, x, v, &proof).use_challenges();
                    assert!(!msm.clone().eval());

                    // The real transcript and round folds agree. Precisely
                    // the unaccounted-for blind remains in the final MSM;
                    // reinstating a free cancellation term would accept it.
                    msm.append_term(-blind, base);
                    assert!(msm.eval());
                }
            }

            #[test]
            fn rejects_forged_value_or_mask() {
                let params = params(K);
                let mut rng = StdRng::seed_from_u64(0x463);
                let poly = random_poly(1 << K, &mut rng);
                let commitment = params.commit(&poly).to_affine();
                let x = F::from(7);
                let value = evaluate_iter(&poly, x);

                // Try omitting the evaluation-binding round terms, lying
                // about the value, using s(x) != 0, and combining both lies.
                for (value_error, mask_at_x, round_u) in [
                    (F::ONE, F::ZERO, false),
                    (F::ONE, F::ZERO, true),
                    (F::ZERO, F::ONE, true),
                    (F::ONE, F::ONE, true),
                ] {
                    let claimed = value + value_error;
                    let mut transcript = transcript_for(commitment, x, claimed);
                    let mut side = transcript.$side();
                    let mut mask = random_poly(1 << K, &mut rng);
                    let mask_value = evaluate_iter(&mask, x);
                    mask[0] += mask_at_x - mask_value;
                    let s_commitment = params.commit(&mask).to_affine();
                    side.write_point(s_commitment).unwrap();
                    let xi = side.squeeze_challenge().unwrap();
                    let z = side.squeeze_challenge().unwrap();
                    let mut coefficients: Vec<_> =
                        poly.iter().zip(&mask).map(|(p, s)| *p + xi * s).collect();
                    coefficients[0] -= claimed;
                    let mut g = params.g.clone();
                    let mut powers: Vec<_> =
                        core::iter::successors(Some(F::ONE), |power| Some(*power * x))
                            .take(coefficients.len())
                            .collect();
                    let mut rounds = Vec::new();

                    // Construct fresh rounds for the malicious polynomial;
                    // the verifier sees exactly the same transcript.
                    while coefficients.len() > 1 {
                        let half = coefficients.len() / 2;
                        let mut l = C::msm(&coefficients[half..], &g[..half]);
                        let mut r = C::msm(&coefficients[..half], &g[half..]);
                        if round_u {
                            let cross_l =
                                F::sum_of_products_slice(&coefficients[half..], &powers[..half]);
                            let cross_r =
                                F::sum_of_products_slice(&coefficients[..half], &powers[half..]);
                            l += &(params.u * (z * cross_l));
                            r += &(params.u * (z * cross_r));
                        }
                        let (l, r) = (l.to_affine(), r.to_affine());
                        side.write_point(l).unwrap();
                        side.write_point(r).unwrap();
                        rounds.push((l, r));
                        let u = side.squeeze_challenge().unwrap();
                        let inverse = u.invert().unwrap();
                        for i in 0..half {
                            let high = coefficients[i + half];
                            coefficients[i] += inverse * high;
                            let high_power = powers[i + half];
                            powers[i] += u * high_power;
                            g[i] = (g[i].to_projective() + &(g[i + half] * u)).to_affine();
                        }
                        coefficients.truncate(half);
                        g.truncate(half);
                        powers.truncate(half);
                    }
                    let proof = IpaProof {
                        s_commitment,
                        rounds,
                        c: coefficients[0],
                    };
                    side.write_scalar(proof.c).unwrap();
                    let mut msm = verify(&params, commitment, x, claimed, &proof).use_challenges();
                    assert!(!msm.clone().eval());

                    // Control: cancel exactly the remaining U coefficient.
                    // With the round terms present, the residual binds
                    // p(x) - v + xi s(x), so s cannot freely repair a lie.
                    let correction = if round_u {
                        z * (-value_error + xi * mask_at_x)
                    } else {
                        z * proof.c * powers[0]
                    };
                    msm.add_to_u_scalar(correction);
                    assert!(msm.eval());
                }
            }

            #[test]
            fn rejects_wrong_value() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 3);
                assert!(!check(&params, commitment, x, v + F::ONE, &proof));
            }

            #[test]
            fn prover_rejects_zero_round_challenge() {
                let params = params(K);
                let mut rng = StdRng::seed_from_u64(15);
                let poly = random_poly(params.n as usize, &mut rng);
                for round in 0..K as usize {
                    let mut transcript = ZeroRoundTranscript { round, drawn: 0 };
                    assert!(matches!(
                        prover::create_proof(
                            &params,
                            &mut rng,
                            &mut transcript,
                            &poly,
                            F::from(7),
                        ),
                        Err(Error::InvalidWitness(_))
                    ));
                }
            }

            #[test]
            fn verifier_rejects_zero_round_challenge() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 16);
                for round in 0..K as usize {
                    let mut transcript = ZeroRoundTranscript { round, drawn: 0 };
                    let mut msm = MSM::new(&params);
                    msm.append_term(F::ONE, commitment);
                    assert!(matches!(
                        verifier::verify_proof(&params, msm, &mut transcript, &proof, x, v),
                        Err(Error::InvalidWitness(_))
                    ));
                }
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
                let other = params.commit(&random_poly(1 << K, &mut rng)).to_affine();
                assert!(!check(&params, other, x, v, &proof));
            }

            #[test]
            fn rejects_tampered_proof() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 8);

                let mut tampered = proof.clone();
                tampered.c += F::ONE;
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
            fn proof_is_deterministic_with_fixed_rng() {
                let params = params(K);
                let (commitment, x, v, proof) = opening(&params, 12);
                let (commitment_again, x_again, v_again, proof_again) = opening(&params, 12);
                assert_eq!(commitment, commitment_again);
                assert_eq!((x, v), (x_again, v_again));
                assert_eq!(proof, proof_again);
            }

            /// `Params::commit` is the native commitment
            /// `sparse::Polynomial` computes under the same generators,
            /// coefficient $i$ on generator $i$, so the IPA opens exactly what
            /// the proof system commits to.
            #[test]
            fn commitment_matches_native_commitment() {
                let params = Params::with_k(generators(), u(), TestRank::RANK);
                assert_eq!(params.g.len(), TestRank::num_coeffs());
                let mut rng = StdRng::seed_from_u64(13);
                let coeffs = random_poly(TestRank::num_coeffs(), &mut rng);

                let ipa = params.commit(&coeffs).to_affine();
                let native = sparse::Polynomial::<F, TestRank>::from_coeffs(coeffs)
                    .commit_to_affine(generators());
                assert_eq!(ipa, native);
            }

            #[test]
            fn msm_matches_serial_adapter() {
                use crate::ipa::msm::multiexp;

                let mut rng = StdRng::seed_from_u64(15);
                let mut scalars = random_poly(8193, &mut rng);
                let g = generators().g();
                let mut bases: Vec<_> = (0..scalars.len()).map(|i| g[i % g.len()]).collect();
                for (i, (scalar, base)) in scalars.iter_mut().zip(&mut bases).enumerate() {
                    match i % 7 {
                        0 => *scalar = F::ZERO,
                        1 => *scalar = F::ONE,
                        2 => *scalar = -F::ONE,
                        3 => *base = C::identity(),
                        4 => *base = -g[0],
                        5 => *base = g[0],
                        _ => {}
                    }
                }

                // Include empty, small and large inputs, and lengths that
                // do not divide evenly among the workers.
                let expected: Vec<_> = [0, 1, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1025, 8193]
                    .into_iter()
                    .map(|n| (n, C::msm(&scalars[..n], &bases[..n])))
                    .collect();

                // Separate cancellation pairs with one zero term in the middle.
                let cancelling_scalars: Vec<_> = scalars[..256]
                    .iter()
                    .copied()
                    .chain(core::iter::once(F::ZERO))
                    .chain(scalars[..256].iter().map(|scalar| -*scalar))
                    .collect();
                let cancelling_bases: Vec<_> = bases[..256]
                    .iter()
                    .copied()
                    .chain(core::iter::once(C::identity()))
                    .chain(bases[..256].iter().copied())
                    .collect();

                let check = || {
                    for &(n, expected) in &expected {
                        assert_eq!(multiexp::<_, ReferenceBackend>(&scalars[..n], &bases[..n]), expected, "MSM length {n}");
                    }
                    assert!(multiexp::<_, ReferenceBackend>(&cancelling_scalars, &cancelling_bases).is_identity());
                };

                #[cfg(feature = "multicore")]
                for workers in [1, 2, 3, 7] {
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap()
                        .install(&check);
                }
                #[cfg(not(feature = "multicore"))]
                check();
            }

            #[test]
            #[should_panic(expected = "msm operands must have equal length")]
            fn msm_rejects_mismatched_lengths() {
                crate::ipa::msm::multiexp::<_, ReferenceBackend>(&[F::ONE; 256], &[u(); 255]);
            }

            #[cfg(feature = "multicore")]
            #[test]
            fn proof_is_independent_of_worker_count() {
                let params = params(K + 1);
                let open_with_workers = |workers| {
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(workers)
                        .build()
                        .unwrap()
                        .install(|| opening(&params, 16))
                };
                let expected = open_with_workers(1);
                for workers in [2, 3, 7] {
                    let actual = open_with_workers(workers);
                    assert_eq!(actual, expected);
                    assert!(check(&params, actual.0, actual.1, actual.2, &actual.3));
                }
            }

            /// halo2's `msm_arithmetic` test; both Pasta curves are
            /// $y^2 = x^3 + 5$, so $(-1, 2)$ lies on either.
            #[test]
            fn msm_arithmetic() {
                type Base = <C as Affine>::Base;

                let base = C::from_xy(-Base::ONE, Base::from(2)).unwrap();
                let base_viol = (base.to_projective() + &base.to_projective()).to_affine();

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
                let params = Params::new(generators(), u());
                let mut rng = StdRng::seed_from_u64(14);
                let poly = random_poly(params.n as usize, &mut rng);
                let x = F::random(|bytes| rng.fill_bytes(bytes));
                let (commitment, v, proof) = open(&params, &poly, x, &mut rng);
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
                    let x = F::random(|bytes| rng.fill_bytes(bytes));
                    let (commitment, v, proof) = open(&params, &poly, x, &mut rng);
                    prop_assert!(check(&params, commitment, x, v, &proof));

                    // Open a polynomial that differs from the committed one in
                    // one coefficient; the claimed value is recomputed
                    // honestly for it.
                    let mut corrupted = poly.clone();
                    corrupted[index % n] += F::ONE;
                    let (_, v_corrupted, proof_corrupted) =
                        open(&params, &corrupted, x, &mut rng);
                    prop_assert!(!check(&params, commitment, x, v_corrupted, &proof_corrupted));
                }
            }
        }
    };
}

ipa_tests!(
    host,
    <Pasta as ragu_core::Cycle>::HostCurve,
    ragu_core::pasta::Fp,
    HostGenerators,
    host_generators,
    host_u,
    host
);
ipa_tests!(
    nested,
    <Pasta as ragu_core::Cycle>::NestedCurve,
    ragu_core::pasta::Fq,
    NestedGenerators,
    nested_generators,
    nested_u,
    nested
);

/// Both IPAs share one chain: what the host side absorbs moves the nested
/// side's next challenge, and vice versa.
#[test]
fn sides_share_one_transcript() {
    use ragu_core::{Cycle, FixedGenerators};

    use crate::ipa::IpaTranscript;

    let host_point = Pasta::host_generators(crate::pasta::baked()).g()[0];
    let nested_point = Pasta::nested_generators(crate::pasta::baked()).g()[0];

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

    // Each side consumes a separate squeeze from the shared stream. The
    // nested challenge preserves its own squeeze's canonical integer,
    // including the bits above the endoscalar width.
    let mut e = fresh();
    let first = e.host().squeeze_challenge().unwrap();
    let second = e.host().squeeze_challenge().unwrap();
    let mut f = fresh();
    let host = f.host().squeeze_challenge().unwrap();
    let nested = f.nested().squeeze_challenge().unwrap();
    assert_eq!(host, first);
    assert_eq!(Field::to_bytes(&nested), Field::to_bytes(&second));
    assert_ne!(Field::to_bytes(&nested), Field::to_bytes(&host));
    assert!(
        Field::to_le_bits(&nested).as_ref()[128..254]
            .iter()
            .any(|bit| *bit)
    );
}

#[test]
fn nested_challenge_preserves_full_width() {
    fn check<F: Field, T: Field>() {
        let check_value = |value: F| {
            let converted: T = convert_challenge(value).unwrap();
            assert_eq!(value.to_le_bits().as_ref(), converted.to_le_bits().as_ref());
        };

        check_value(F::ZERO);
        let mut power = F::ONE;
        for _ in 0..F::CAPACITY.min(T::CAPACITY) {
            check_value(power);
            power = power.double();
        }
        check_value(power - F::ONE);
    }

    check::<Fp, Fq>();
    check::<Fq, Fp>();
}

#[test]
fn nested_challenge_rejects_out_of_range() {
    fn check<F: Field, T: Field>() {
        let mut limit = F::ONE;
        for _ in 0..F::CAPACITY.min(T::CAPACITY) {
            limit = limit.double();
        }
        for value in [limit, limit + F::ONE, -F::ONE] {
            assert!(matches!(
                convert_challenge::<F, T>(value),
                Err(Error::InvalidWitness(_))
            ));
        }
    }

    check::<Fp, Fq>();
    check::<Fq, Fp>();
}
