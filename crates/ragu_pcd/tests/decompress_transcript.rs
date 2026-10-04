//! The transcript gadget against the native transcript on a real
//! compressed proof: over the allocated instance, header and messages,
//! with the bridges the native transcript forms allocated as points, it
//! squeezes every challenge the native verifier squeezes on both curves,
//! each as the lift of the endoscalar the native squeeze yields, and
//! follows a tampered message as the native transcript does.

use alloc::vec::Vec;

use ragu_backend::{Backend, ReferenceBackend};
use ragu_core::{
    Cycle, FixedGenerators, Result,
    drivers::Driver,
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, Point, Simulator, extract_endoscalar, lift_endoscalar};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use super::{Challenges, Child, Instance, Messages, NestedChild, replay};
use crate::{
    compress::{self, Sampled},
    decompress::support::{
        EpAffine, EqAffine, Setup, alloc, alloc_all, replay_batch, replay_ipa, replay_reduction,
    },
};

type Dr = Simulator<Fp>;

/// The native transcript's bridge of `values`: their commitment over the
/// nested generators.
fn bridge(values: &[Fq]) -> EpAffine {
    let g = Pasta::nested_generators(crate::pasta::baked()).g();
    ReferenceBackend::msm(values, &g[..values.len()]).to_affine()
}

/// The bridge of a host-curve point: of its coordinates.
fn bridge_point(point: EqAffine) -> EpAffine {
    let (x, y) = point
        .coordinates()
        .expect("a commitment is not the identity");
    bridge(&[x, y])
}

fn point(dr: &mut Dr, point: EpAffine) -> Result<Point<'static, Dr, EpAffine>> {
    Point::alloc(dr, <Dr as Driver>::just(|| point))
}

fn bridged(dr: &mut Dr, scalar: Fq) -> Result<Point<'static, Dr, EpAffine>> {
    point(dr, bridge(&[scalar]))
}

fn points(
    dr: &mut Dr,
    points: impl IntoIterator<Item = EpAffine>,
) -> Result<Vec<Point<'static, Dr, EpAffine>>> {
    points.into_iter().map(|p| point(dr, p)).collect()
}

/// The instance allocated as the transcript gadget takes it.
fn instance(
    dr: &mut Dr,
    instance: &compress::instance::Instance<Pasta>,
) -> Result<Instance<'static, Dr, EpAffine>> {
    let child = |dr: &mut Dr, child: compress::instance::Child<Fp>| {
        Ok::<_, ragu_core::Error>(Child {
            x: alloc(dr, child.x)?,
            y: alloc(dr, child.y)?,
            id: alloc(dr, child.id)?,
        })
    };
    let nested_child = |dr: &mut Dr, child: compress::instance::NestedChild<Fq>| {
        Ok::<_, ragu_core::Error>(NestedChild {
            x: bridged(dr, child.x)?,
            y: bridged(dr, child.y)?,
        })
    };
    Ok(Instance {
        circuit_id: alloc(dr, instance.circuit_id.omega_j())?,
        left_header: alloc_all(dr, instance.left_header.iter().copied())?,
        right_header: alloc_all(dr, instance.right_header.iter().copied())?,
        native: points(dr, instance.native.iter().map(|&p| bridge_point(p)))?,
        native_registry_xy: point(dr, bridge_point(instance.native_registry_xy))?,
        native_p: point(dr, bridge_point(instance.native_p))?,
        nested: points(dr, instance.nested.iter().copied())?,
        nested_registry_xy: point(dr, instance.nested_registry_xy)?,
        nested_p: point(dr, instance.nested_p)?,
        nested_challenges_partial: point(dr, instance.nested_challenges_partial)?,
        bridge_alpha: bridged(dr, instance.bridge_alpha)?,
        c: alloc(dr, instance.c)?,
        v: alloc(dr, instance.v)?,
        nested_c: bridged(dr, instance.nested_c)?,
        nested_v: bridged(dr, instance.nested_v)?,
        left: child(dr, instance.left)?,
        right: child(dr, instance.right)?,
        a_at_u: alloc(dr, instance.a_at_u)?,
        b_at_u: alloc(dr, instance.b_at_u)?,
        nested_left: nested_child(dr, instance.nested_left)?,
        nested_right: nested_child(dr, instance.nested_right)?,
        nested_a_at_u: bridged(dr, instance.nested_a_at_u)?,
        nested_b_at_u: bridged(dr, instance.nested_b_at_u)?,
    })
}

/// The host curve's messages allocated: scalars as elements, points by
/// their bridges.
fn native_messages(
    dr: &mut Dr,
    messages: &compress::Messages<EqAffine>,
) -> Result<Messages<Element<'static, Dr>, Point<'static, Dr, EpAffine>>> {
    let reduction = &messages.reduction;
    let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
    for &(l, r) in &messages.opening.rounds {
        rounds.push((point(dr, bridge_point(l))?, point(dr, bridge_point(r))?));
    }
    Ok(Messages {
        inner: point(dr, bridge_point(reduction.fold.inner))?,
        outer: point(dr, bridge_point(reduction.fold.outer))?,
        inner_epsilon: alloc(dr, reduction.fold.inner_epsilon)?,
        outer_epsilon: alloc(dr, reduction.fold.outer_epsilon)?,
        p: point(dr, bridge_point(reduction.p))?,
        q: point(dr, bridge_point(reduction.q))?,
        openings: alloc_all(dr, reduction.openings.iter().copied())?,
        p_at_inverse_r: alloc(dr, reduction.p_at_inverse_r)?,
        q_at_r: alloc(dr, reduction.q_at_r)?,
        f: point(dr, bridge_point(messages.batch.f))?,
        evaluations: alloc_all(dr, messages.batch.evaluations.iter().copied())?,
        s_commitment: point(dr, bridge_point(messages.opening.s_commitment))?,
        rounds,
        c: alloc(dr, messages.opening.c)?,
    })
}

/// The nested curve's messages allocated: points as points, scalars by
/// their bridges.
fn nested_messages(
    dr: &mut Dr,
    messages: &compress::Messages<EpAffine>,
) -> Result<Messages<Point<'static, Dr, EpAffine>, Point<'static, Dr, EpAffine>>> {
    let reduction = &messages.reduction;
    let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
    for &(l, r) in &messages.opening.rounds {
        rounds.push((point(dr, l)?, point(dr, r)?));
    }
    let mut openings = Vec::with_capacity(reduction.openings.len());
    for &opened in &reduction.openings {
        openings.push(bridged(dr, opened)?);
    }
    let mut evaluations = Vec::with_capacity(messages.batch.evaluations.len());
    for &value in &messages.batch.evaluations {
        evaluations.push(bridged(dr, value)?);
    }
    Ok(Messages {
        inner: point(dr, reduction.fold.inner)?,
        outer: point(dr, reduction.fold.outer)?,
        inner_epsilon: bridged(dr, reduction.fold.inner_epsilon)?,
        outer_epsilon: bridged(dr, reduction.fold.outer_epsilon)?,
        p: point(dr, reduction.p)?,
        q: point(dr, reduction.q)?,
        openings,
        p_at_inverse_r: bridged(dr, reduction.p_at_inverse_r)?,
        q_at_r: bridged(dr, reduction.q_at_r)?,
        f: point(dr, messages.batch.f)?,
        evaluations,
        s_commitment: point(dr, messages.opening.s_commitment)?,
        rounds,
        c: bridged(dr, messages.opening.c)?,
    })
}

/// One curve's native challenges in the gadget's order.
struct Native<F> {
    sampled: Sampled<F>,
    rest: Vec<F>,
}

impl<F: Field> Native<F> {
    fn new(
        sampled: Sampled<F>,
        (weights, rho, r): (compress::revdot::fold::Weights<F>, F, F),
        (alpha, u, beta): (F, F, F),
        (xi, z, rounds): (F, F, Vec<F>),
    ) -> Self {
        let mut rest = alloc::vec![
            weights.mu,
            weights.nu,
            weights.mu_prime,
            weights.nu_prime,
            rho,
            r,
            alpha,
            u,
            beta,
            xi,
            z,
        ];
        rest.extend(rounds);
        Native { sampled, rest }
    }
}

/// The lift into the circuit field of the endoscalar a raw squeeze yields,
/// on either curve: what the gadget's `lift` must be.
fn lifted<F: Field>(raw: F) -> Fp {
    lift_endoscalar(extract_endoscalar(raw).expect("a squeeze is in range"))
}

/// The gadget's challenges' lifts in the same order, by value.
fn flatten(challenges: &Challenges<'static, Dr>) -> (Vec<Fp>, Vec<Fp>) {
    let value = |challenge: &super::Challenge<'static, Dr>| *challenge.lift.value().take();
    let sampled = [
        &challenges.sampled.w,
        &challenges.sampled.y,
        &challenges.sampled.z,
        &challenges.sampled.sigma,
    ]
    .map(value)
    .to_vec();
    let mut rest = [
        &challenges.weights.mu,
        &challenges.weights.nu,
        &challenges.weights.mu_prime,
        &challenges.weights.nu_prime,
        &challenges.rho,
        &challenges.r,
        &challenges.alpha,
        &challenges.u,
        &challenges.beta,
        &challenges.xi,
        &challenges.z,
    ]
    .map(value)
    .to_vec();
    rest.extend(challenges.rounds.iter().map(value));
    (sampled, rest)
}

/// Replays `proof`'s transcript natively, as raw squeezes, and in the
/// gadget, and compares every challenge's lift.
fn check(setup: &Setup, proof: &compress::CompressedProof<Pasta>) {
    let mut t = setup.absorbed();
    let native_sampled = Sampled::squeeze(&mut t.host()).unwrap();
    let nested_sampled = Sampled::squeeze(&mut t.nested()).unwrap();
    let native = Native::new(
        native_sampled,
        replay_reduction(&proof.native.reduction, &mut t.host()),
        replay_batch(&proof.native.batch, &mut t.host()),
        replay_ipa(&proof.native.opening, &mut t.host()),
    );
    let nested = Native::new(
        nested_sampled,
        replay_reduction(&proof.nested.reduction, &mut t.nested()),
        replay_batch(&proof.nested.batch, &mut t.nested()),
        replay_ipa(&proof.nested.opening, &mut t.nested()),
    );

    let dr = Simulator::simulate((), |dr, _| {
        let instance = instance(dr, &proof.instance)?;
        let header = alloc_all(dr, setup.header.iter().copied())?;
        let native_messages = native_messages(dr, &proof.native)?;
        let nested_messages = nested_messages(dr, &proof.nested)?;
        let (host, scalar) = replay(
            dr,
            Pasta::circuit_poseidon(crate::pasta::baked()),
            &instance,
            &header,
            &native_messages,
            &nested_messages,
        )?;

        let (sampled, rest) = flatten(&host);
        let Sampled { w, y, z, sigma } = native.sampled;
        assert_eq!(sampled, [w, y, z, sigma].map(lifted).to_vec());
        assert_eq!(
            rest,
            native
                .rest
                .iter()
                .map(|&raw| lifted(raw))
                .collect::<Vec<_>>()
        );

        let (sampled, rest) = flatten(&scalar);
        let Sampled { w, y, z, sigma } = nested.sampled;
        assert_eq!(sampled, [w, y, z, sigma].map(lifted).to_vec());
        assert_eq!(
            rest,
            nested
                .rest
                .iter()
                .map(|&raw| lifted(raw))
                .collect::<Vec<_>>()
        );
        Ok(())
    })
    .unwrap();
    std::println!(
        "transcript: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
}

#[test]
fn squeezes_the_native_challenges() {
    let setup = Setup::new();
    check(&setup, &setup.proof);
}

#[test]
fn follows_a_tampered_message() {
    let setup = Setup::new();
    let mut tampered = setup.proof.clone();
    tampered.native.reduction.fold.inner_epsilon += Fp::ONE;
    tampered.nested.batch.evaluations[1] += Fq::ONE;
    check(&setup, &tampered);
}
