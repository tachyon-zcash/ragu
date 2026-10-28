//! The transcript gadget against the native transcript on a real
//! compressed proof: over the allocated instance, header and messages,
//! with the bridges the native transcript forms allocated as points, it
//! squeezes every challenge the native verifier squeezes on both curves,
//! each as the lift of the endoscalar the native squeeze yields, and
//! follows a tampered message as the native transcript does.

use alloc::vec::Vec;

use ragu_core::{
    Cycle, Result,
    drivers::Driver,
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, Point, Simulator, extract_endoscalar, lift_endoscalar};
use udon::field::Field;

use super::{Challenges, Child, Instance, Messages, NestedChild, replay};
use crate::{
    compress::{self, Sampled},
    decompress::{
        side::{Native as NativeSide, Side},
        stages::{Layout, MessageScalars, message_points, nested_scalars},
        support::{
            EpAffine, EqAffine, HEADER_SIZE, Setup, TestR, alloc, alloc_all, replay_batch,
            replay_ipa, replay_reduction,
        },
    },
};

type Dr = Simulator<Fp>;

/// The bridges the native transcript forms for `proof`, as the
/// circuit-field side's transcript stage holds them, by the layout's
/// spans.
struct Bridges {
    points: Vec<EpAffine>,
    layout: Layout,
}

impl Bridges {
    fn of(proof: &compress::CompressedProof<Pasta>) -> Self {
        Bridges {
            points: <NativeSide as Side<Pasta>>::transcript::<TestR>(
                crate::pasta::baked_aggregator(),
                &proof.instance,
                proof,
            )
            .unwrap()
            .points,
            layout: <NativeSide as Side<Pasta>>::layout::<TestR, HEADER_SIZE>(),
        }
    }

    /// The bridge of the `i`-th host commitment.
    fn commitment(&self, i: usize) -> EpAffine {
        self.points[self.layout.transcript.commitment_bridges.at(i)]
    }

    /// The bridge of the `i`-th scalar-field instance value.
    fn scalar(&self, i: usize) -> EpAffine {
        self.points[self.layout.transcript.bridged.at(i)]
    }

    /// The bridge of the `i`-th host point message.
    fn message_point(&self, i: usize) -> EpAffine {
        self.points[self.layout.transcript.point_bridges.at(i)]
    }

    /// The bridges of the nested curve's scalar messages, by name.
    fn message_scalars(&self) -> MessageScalars<'_, EpAffine> {
        let span = self.layout.transcript.scalar_bridges;
        MessageScalars(&self.points[span.start..span.start + span.len])
    }
}

fn point(dr: &mut Dr, point: EpAffine) -> Result<Point<'static, Dr, EpAffine>> {
    Point::alloc(dr, <Dr as Driver>::just(|| point))
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
    bridges: &Bridges,
) -> Result<Instance<'static, Dr, EpAffine>> {
    let child = |dr: &mut Dr, child: compress::instance::Child<Fp>| {
        Ok::<_, ragu_core::Error>(Child {
            x: alloc(dr, child.x)?,
            y: alloc(dr, child.y)?,
            id: alloc(dr, child.id)?,
        })
    };
    let listed = instance.native.len();
    Ok(Instance {
        circuit_id: alloc(dr, instance.circuit_id.omega_j())?,
        left_header: alloc_all(dr, instance.left_header.iter().copied())?,
        right_header: alloc_all(dr, instance.right_header.iter().copied())?,
        native: points(dr, (0..listed).map(|i| bridges.commitment(i)))?,
        native_registry_xy: point(dr, bridges.commitment(listed))?,
        native_p: point(dr, bridges.commitment(listed + 1))?,
        nested: points(dr, instance.nested.iter().copied())?,
        nested_registry_xy: point(dr, instance.nested_registry_xy)?,
        nested_p: point(dr, instance.nested_p)?,
        nested_challenges_partial: point(dr, instance.nested_challenges_partial)?,
        bridge_alpha: point(dr, bridges.scalar(nested_scalars::BRIDGE_ALPHA))?,
        c: alloc(dr, instance.c)?,
        v: alloc(dr, instance.v)?,
        nested_c: point(dr, bridges.scalar(nested_scalars::C))?,
        nested_v: point(dr, bridges.scalar(nested_scalars::V))?,
        left: child(dr, instance.left)?,
        right: child(dr, instance.right)?,
        a_at_u: alloc(dr, instance.a_at_u)?,
        b_at_u: alloc(dr, instance.b_at_u)?,
        nested_left: NestedChild {
            x: point(dr, bridges.scalar(nested_scalars::LEFT_X))?,
            y: point(dr, bridges.scalar(nested_scalars::LEFT_Y))?,
        },
        nested_right: NestedChild {
            x: point(dr, bridges.scalar(nested_scalars::RIGHT_X))?,
            y: point(dr, bridges.scalar(nested_scalars::RIGHT_Y))?,
        },
        nested_a_at_u: point(dr, bridges.scalar(nested_scalars::A_AT_U))?,
        nested_b_at_u: point(dr, bridges.scalar(nested_scalars::B_AT_U))?,
    })
}

/// The host curve's messages allocated: scalars as elements, points by
/// their bridges.
fn native_messages(
    dr: &mut Dr,
    messages: &compress::Messages<EqAffine>,
    bridges: &Bridges,
) -> Result<Messages<Element<'static, Dr>, Point<'static, Dr, EpAffine>>> {
    use message_points::*;
    let reduction = &messages.reduction;
    let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
    for j in 0..messages.opening.rounds.len() {
        rounds.push((
            point(dr, bridges.message_point(l(j)))?,
            point(dr, bridges.message_point(r(j)))?,
        ));
    }
    Ok(Messages {
        inner: point(dr, bridges.message_point(INNER))?,
        outer: point(dr, bridges.message_point(OUTER))?,
        inner_epsilon: alloc(dr, reduction.fold.inner_epsilon)?,
        outer_epsilon: alloc(dr, reduction.fold.outer_epsilon)?,
        p: point(dr, bridges.message_point(P))?,
        q: point(dr, bridges.message_point(Q))?,
        openings: alloc_all(dr, reduction.openings.iter().copied())?,
        p_at_inverse_r: alloc(dr, reduction.p_at_inverse_r)?,
        q_at_r: alloc(dr, reduction.q_at_r)?,
        f: point(dr, bridges.message_point(F))?,
        evaluations: alloc_all(dr, messages.batch.evaluations.iter().copied())?,
        s_commitment: point(dr, bridges.message_point(S_COMMITMENT))?,
        rounds,
        c: alloc(dr, messages.opening.c)?,
    })
}

/// The nested curve's messages allocated: points as points, scalars by
/// their bridges.
fn nested_messages(
    dr: &mut Dr,
    messages: &compress::Messages<EpAffine>,
    bridges: &Bridges,
) -> Result<Messages<Point<'static, Dr, EpAffine>, Point<'static, Dr, EpAffine>>> {
    let reduction = &messages.reduction;
    let scalars = bridges.message_scalars();
    let mut rounds = Vec::with_capacity(messages.opening.rounds.len());
    for &(l, r) in &messages.opening.rounds {
        rounds.push((point(dr, l)?, point(dr, r)?));
    }
    let openings = points(dr, scalars.openings().iter().copied())?;
    let evaluations = points(dr, scalars.evaluations().iter().copied())?;
    Ok(Messages {
        inner: point(dr, reduction.fold.inner)?,
        outer: point(dr, reduction.fold.outer)?,
        inner_epsilon: point(dr, *scalars.inner_epsilon())?,
        outer_epsilon: point(dr, *scalars.outer_epsilon())?,
        p: point(dr, reduction.p)?,
        q: point(dr, reduction.q)?,
        openings,
        p_at_inverse_r: point(dr, *scalars.p_at_inverse_r())?,
        q_at_r: point(dr, *scalars.q_at_r())?,
        f: point(dr, messages.batch.f)?,
        evaluations,
        s_commitment: point(dr, messages.opening.s_commitment)?,
        rounds,
        c: point(dr, *scalars.c())?,
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

    let bridges = Bridges::of(proof);
    let dr = Simulator::simulate((), |dr, _| {
        let instance = instance(dr, &proof.instance, &bridges)?;
        let header = alloc_all(dr, setup.header.iter().copied())?;
        let native_messages = native_messages(dr, &proof.native, &bridges)?;
        let nested_messages = nested_messages(dr, &proof.nested, &bridges)?;
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
