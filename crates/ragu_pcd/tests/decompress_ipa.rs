//! The IPA's scalar gadget against the native verifier, both curves of a
//! real compressed proof: on the native points and the $G'$ the native
//! verifier derives, its scalars make the final check's multi-scalar
//! multiplication the identity exactly when the native verifier accepts.

use alloc::vec::Vec;

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::Rank;
use ragu_core::{Cycle, Result, maybe::Maybe, pasta::Pasta};
use ragu_primitives::Simulator;
use udon::{curve::Affine, field::Field};

use super::{Challenges, Messages, verify};
use crate::{
    compress::batch::{self, Batched},
    decompress::support::{Setup, TestR, alloc, alloc_all},
    ipa::{self, IpaCycle, IpaProof, IpaTranscript, MSM, Params},
};

/// The gadget's scalars, by value.
struct Scalars<F> {
    g_0: F,
    s_commitment: F,
    rounds: Vec<(F, F)>,
    u: F,
    g_prime: F,
}

/// Replays the IPA's messages on `t` as the verifier does, returning the
/// challenges it squeezes: $\xi$, $z$ and the rounds'.
fn replay<C: Affine>(
    proof: &IpaProof<C>,
    t: &mut impl IpaTranscript<C>,
) -> (C::Scalar, C::Scalar, Vec<C::Scalar>) {
    t.write_point(proof.s_commitment).unwrap();
    let xi = t.squeeze_challenge().unwrap();
    let z = t.squeeze_challenge().unwrap();
    let mut rounds = Vec::with_capacity(proof.rounds.len());
    for &(l, r) in &proof.rounds {
        t.write_point(l).unwrap();
        t.write_point(r).unwrap();
        rounds.push(t.squeeze_challenge().unwrap());
    }
    t.write_scalar(proof.c).unwrap();
    (xi, z, rounds)
}

/// What the gadget produces for the claim at `point` with `value`.
fn simulate<F: Field>(
    point: F,
    value: F,
    (xi, z, rounds): (F, F, Vec<F>),
    c: F,
) -> Result<Scalars<F>> {
    let mut out = None;
    Simulator::simulate((), |dr, _| {
        let point = alloc(dr, point)?;
        let value = alloc(dr, value)?;
        let challenges = Challenges {
            xi: alloc(dr, xi)?,
            z: alloc(dr, z)?,
            rounds: alloc_all(dr, rounds.iter().copied())?,
        };
        let messages = Messages { c: alloc(dr, c)? };
        let scalars = verify(dr, &point, &value, &challenges, &messages)?;
        let value = |element: &ragu_primitives::Element<'_, Simulator<F>>| *element.value().take();
        out = Some(Scalars {
            g_0: value(&scalars.g_0),
            s_commitment: value(&scalars.s_commitment),
            rounds: scalars
                .rounds
                .iter()
                .map(|(inverse, u_j)| (value(inverse), value(u_j)))
                .collect(),
            u: value(&scalars.u),
            g_prime: value(&scalars.g_prime),
        });
        Ok(())
    })?;
    Ok(out.expect("the simulation ran"))
}

/// Whether the gadget's `scalars` on `proof`'s points, the batched `claim`
/// under one and `g_prime`, make the final check's multi-scalar
/// multiplication the identity.
fn accepts<C: Affine>(
    params: &Params<C>,
    claim: &Batched<C>,
    proof: &IpaProof<C>,
    g_prime: C,
    scalars: &Scalars<C::Scalar>,
) -> bool {
    let mut msm = MSM::new(params);
    msm.append_term(C::Scalar::ONE, claim.commitment);
    msm.add_constant_term(scalars.g_0);
    msm.append_term(scalars.s_commitment, proof.s_commitment);
    for (&(l, r), &(inverse, u_j)) in proof.rounds.iter().zip(&scalars.rounds) {
        msm.append_term(inverse, l);
        msm.append_term(u_j, r);
    }
    msm.add_to_u_scalar(scalars.u);
    msm.append_term(scalars.g_prime, g_prime);
    msm.eval::<ReferenceBackend>()
}

/// The honest proof and two tamperings: a wrong $c$, which the transcript
/// takes last, and a wrong $L_0$, which moves every round challenge.
fn proofs<C: Affine>(honest: &IpaProof<C>) -> [(IpaProof<C>, bool); 3] {
    let mut wrong_c = honest.clone();
    wrong_c.c += C::Scalar::ONE;
    let mut wrong_round = honest.clone();
    wrong_round.rounds[0].0 = wrong_round.rounds[0].1;
    [
        (honest.clone(), true),
        (wrong_c, false),
        (wrong_round, false),
    ]
}

#[test]
fn native_ipa_scalars_match_the_verifier() {
    let setup = Setup::new();
    let params = Params::with_k(
        Pasta::host_generators(crate::pasta::baked()),
        *Pasta::host_u(crate::pasta::baked()),
        TestR::RANK,
    );
    let at_ipa = || {
        let (mut t, sampled, nested_sampled) = setup.transcript();
        let openings = setup.native_openings(&mut t, &sampled, nested_sampled.y);
        let claim = batch::verify::<_, ReferenceBackend, _>(
            &openings.commitments,
            &openings.claims,
            &setup.proof.native.batch,
            &mut t.host(),
        )
        .unwrap();
        (t, claim)
    };
    let claim = at_ipa().1;

    for (proof, expected) in proofs(&setup.proof.native.opening) {
        let (mut t, _) = at_ipa();
        let mut msm = MSM::new(&params);
        msm.append_term(<Pasta as Cycle>::CircuitField::ONE, claim.commitment);
        let guard = ipa::verify_proof(
            &params,
            msm,
            &mut t.host(),
            &proof,
            claim.point,
            claim.value,
        )
        .unwrap();
        let g_prime = guard.compute_g::<ReferenceBackend>();
        assert_eq!(guard.use_challenges().eval::<ReferenceBackend>(), expected);

        let (mut t, _) = at_ipa();
        let challenges = replay(&proof, &mut t.host());
        let scalars = simulate(claim.point, claim.value, challenges, proof.c).unwrap();
        assert_eq!(
            accepts(&params, &claim, &proof, g_prime, &scalars),
            expected
        );
    }
}

#[test]
fn nested_ipa_scalars_match_the_verifier() {
    let setup = Setup::new();
    let params = Params::with_k(
        Pasta::nested_generators(crate::pasta::baked()),
        *Pasta::nested_u(crate::pasta::baked()),
        TestR::RANK,
    );
    let at_ipa = || {
        let (mut t, native_sampled, sampled) = setup.transcript();
        setup.run_native(&mut t, &native_sampled, sampled.y);
        let openings = setup.nested_openings(&mut t, &sampled, native_sampled.y);
        let claim = batch::verify::<_, ReferenceBackend, _>(
            &openings.commitments,
            &openings.claims,
            &setup.proof.nested.batch,
            &mut t.nested(),
        )
        .unwrap();
        (t, claim)
    };
    let claim = at_ipa().1;

    for (proof, expected) in proofs(&setup.proof.nested.opening) {
        let (mut t, _) = at_ipa();
        let mut msm = MSM::new(&params);
        msm.append_term(<Pasta as Cycle>::ScalarField::ONE, claim.commitment);
        let guard = ipa::verify_proof(
            &params,
            msm,
            &mut t.nested(),
            &proof,
            claim.point,
            claim.value,
        )
        .unwrap();
        let g_prime = guard.compute_g::<ReferenceBackend>();
        assert_eq!(guard.use_challenges().eval::<ReferenceBackend>(), expected);

        let (mut t, _) = at_ipa();
        let challenges = replay(&proof, &mut t.nested());
        let scalars = simulate(claim.point, claim.value, challenges, proof.c).unwrap();
        assert_eq!(
            accepts(&params, &claim, &proof, g_prime, &scalars),
            expected
        );
    }
}
