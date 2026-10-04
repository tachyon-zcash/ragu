//! The derived commitments against the native verifier, both curves of a
//! real compressed proof: over the instance's commitments as points and
//! the challenges as endoscalars, the chains give the commitments the
//! native verifier derives and the batched commitment it forms, a
//! full-width scalar's digits scale a point by it, and the IPA's final
//! check holds exactly when the native verifier accepts.

use alloc::vec::Vec;

use ragu_backend::ReferenceBackend;
use ragu_circuits::{polynomials::Rank, registry::CircuitIndex};
use ragu_core::{
    Cycle, Result,
    drivers::Driver,
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Endoscalar, NonzeroBank, Point, Simulator, extract_endoscalar};
use udon::{
    curve::{EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{
    Claim, Digits, Fixed, Opening, Scalars, batched, enforce_opening, fold, native_claims,
    nested_claims, scale,
};
use crate::{
    compress::{
        Lifted, Messages,
        batch::{self, Batched},
        revdot::{
            Openings,
            claims::{self, Shape},
            fold::{self as fold_native, Derived, Weights},
        },
    },
    decompress::support::{HEADER_SIZE, Setup, TestR, replay_batch, replay_ipa, replay_reduction},
    ipa::{self, IpaCycle, IpaTranscript, MSM, Params},
};

/// $b = \prod_j (1 + u_j x^{2^{k-1-j}})$, as the IPA verifier computes it.
fn b_at<F: Field>(x: F, u: &[F]) -> F {
    let mut b = F::ONE;
    let mut cur = x;
    for u_j in u.iter().rev() {
        b *= F::ONE + *u_j * cur;
        cur = cur.square();
    }
    b
}

/// One curve's challenges that scale points, in transcript order.
struct Challenges<F> {
    z: F,
    weights: Weights<F>,
    beta: F,
    xi: F,
    ipa_z: F,
    rounds: Vec<F>,
}

/// One curve's side of the verifier: what the gadgets take, raw and lifted
/// challenges, and what the native verifier derives.
struct Side<C: Affine> {
    commitments: Vec<C>,
    shapes: Vec<Shape<usize, C::Scalar>>,
    masked: Vec<usize>,
    circuit_id: Option<CircuitIndex>,
    messages: Messages<C>,
    openings: Openings<C>,
    raw: Challenges<C::Scalar>,
    lifted: Challenges<C::Scalar>,
    derived: Vec<C>,
    batched: Batched<C>,
    g_prime: C,
    params: Params<C>,
}

/// Reads one curve's challenges off a transcript standing where its
/// reduction starts, with `z` already sampled.
fn read<C: Affine>(
    z: C::Scalar,
    messages: &Messages<C>,
    t: &mut impl IpaTranscript<C>,
) -> Challenges<C::Scalar> {
    let (weights, _, _) = replay_reduction(&messages.reduction, t);
    let (_, _, beta) = replay_batch(&messages.batch, t);
    let (xi, ipa_z, rounds) = replay_ipa(&messages.opening, t);
    Challenges {
        z,
        weights,
        beta,
        xi,
        ipa_z,
        rounds,
    }
}

fn native_side(setup: &Setup) -> Side<<Pasta as Cycle>::HostCurve> {
    let instance = &setup.proof.instance;
    let registry = &setup.app.native_registry;
    let messages = setup.proof.native.clone();

    let (mut t, sampled, nested_sampled) = setup.transcript();
    let openings = setup.native_openings(&mut t, &sampled, nested_sampled.y);
    let batched = batch::verify::<_, ReferenceBackend, _>(
        &openings.commitments,
        &openings.claims,
        &messages.batch,
        &mut Lifted(t.host()),
    )
    .unwrap();
    let params = Params::with_k(
        Pasta::host_generators(crate::pasta::baked()),
        *Pasta::host_u(crate::pasta::baked()),
        TestR::RANK,
    );
    let mut msm = MSM::new(&params);
    msm.append_term(Fp::ONE, batched.commitment);
    let guard = ipa::verify_proof(
        &params,
        msm,
        &mut Lifted(t.host()),
        &messages.opening,
        batched.point,
        batched.value,
    )
    .unwrap();
    let g_prime = guard.compute_g::<ReferenceBackend>();
    assert!(guard.use_challenges().eval::<ReferenceBackend>());

    let (mut t, sampled, _) = setup.transcript();
    let lifted = read(sampled.z, &messages, &mut Lifted(t.host()));
    let mut t = setup.absorbed();
    let raw_sampled = crate::compress::Sampled::squeeze(&mut t.host()).unwrap();
    crate::compress::Sampled::squeeze(&mut t.nested()).unwrap();
    let raw = read(raw_sampled.z, &messages, &mut t.host());

    let masked = instance
        .native_bindings::<TestR, ReferenceBackend, HEADER_SIZE>(
            &setup.challenges,
            registry,
            sampled.sigma,
        )
        .unwrap();
    let shapes = claims::native_shapes(instance.circuit_id, lifted.z, &masked).unwrap();
    let position = |component| crate::compress::revdot::native_position(component);
    let shapes = shapes
        .into_iter()
        .map(|shape| Shape {
            kind: shape.kind,
            a: shape
                .a
                .into_iter()
                .map(|(w, id)| (w, position(id)))
                .collect(),
            b: shape
                .b
                .into_iter()
                .map(|(w, id)| (w, position(id)))
                .collect(),
        })
        .collect::<Vec<_>>();
    let derived = fold_native::commitments::<_, ReferenceBackend, _>(
        &shapes,
        &lifted.weights,
        |position| instance.native[position],
        &messages.reduction.fold,
    );

    Side {
        commitments: instance.native.clone(),
        shapes,
        masked: masked.iter().map(|m| position(m.poly)).collect(),
        circuit_id: Some(instance.circuit_id),
        messages,
        openings,
        raw,
        lifted,
        derived,
        batched,
        g_prime,
        params,
    }
}

fn nested_side(setup: &Setup) -> Side<<Pasta as Cycle>::NestedCurve> {
    let instance = &setup.proof.instance;
    let registry = &setup.app.nested_registry;
    let messages = setup.proof.nested.clone();

    let (mut t, native_sampled, sampled) = setup.transcript();
    setup.run_native(&mut t, &native_sampled, sampled.y);
    let openings = setup.nested_openings(&mut t, &sampled, native_sampled.y);
    let batched = batch::verify::<_, ReferenceBackend, _>(
        &openings.commitments,
        &openings.claims,
        &messages.batch,
        &mut Lifted(t.nested()),
    )
    .unwrap();
    let params = Params::with_k(
        Pasta::nested_generators(crate::pasta::baked()),
        *Pasta::nested_u(crate::pasta::baked()),
        TestR::RANK,
    );
    let mut msm = MSM::new(&params);
    msm.append_term(Fq::ONE, batched.commitment);
    let guard = ipa::verify_proof(
        &params,
        msm,
        &mut Lifted(t.nested()),
        &messages.opening,
        batched.point,
        batched.value,
    )
    .unwrap();
    let g_prime = guard.compute_g::<ReferenceBackend>();
    assert!(guard.use_challenges().eval::<ReferenceBackend>());

    let (mut t, native_sampled, sampled) = setup.transcript();
    setup.run_native(&mut t, &native_sampled, sampled.y);
    let lifted = read(sampled.z, &messages, &mut Lifted(t.nested()));
    // The raw squeezes: the same schedule on an unlifted view, the native
    // side run through its lifted one so that the sponge stands where it
    // does for the verifier.
    let mut t = setup.absorbed();
    let native_sampled = crate::compress::Sampled::squeeze(&mut Lifted(t.host())).unwrap();
    let raw_sampled = crate::compress::Sampled::squeeze(&mut t.nested()).unwrap();
    setup.run_native(&mut t, &native_sampled, sampled.y);
    let raw = read(raw_sampled.z, &messages, &mut t.nested());

    let masked = instance
        .nested_bindings::<TestR, ReferenceBackend>(&setup.challenges, registry, sampled.sigma)
        .unwrap();
    let shapes = claims::nested_shapes(lifted.z, &masked).unwrap();
    let position = |component| crate::compress::revdot::nested_position(component);
    let shapes = shapes
        .into_iter()
        .map(|shape| Shape {
            kind: shape.kind,
            a: shape
                .a
                .into_iter()
                .map(|(w, id)| (w, position(id)))
                .collect(),
            b: shape
                .b
                .into_iter()
                .map(|(w, id)| (w, position(id)))
                .collect(),
        })
        .collect::<Vec<_>>();
    let derived = fold_native::commitments::<_, ReferenceBackend, _>(
        &shapes,
        &lifted.weights,
        |position| instance.nested[position],
        &messages.reduction.fold,
    );

    Side {
        commitments: instance.nested.clone(),
        shapes,
        masked: masked.iter().map(|m| position(m.poly)).collect(),
        circuit_id: None,
        messages,
        openings,
        raw,
        lifted,
        derived,
        batched,
        g_prime,
        params,
    }
}

type Dr<C> = Simulator<<C as udon::curve::Affine>::Base>;

fn endoscalar<'dr, C: Affine>(dr: &mut Dr<C>, raw: C::Scalar) -> Result<Endoscalar<'dr, Dr<C>>> {
    let endo = extract_endoscalar(raw).expect("a squeeze is in range");
    Endoscalar::alloc(dr, <Dr<C> as Driver>::just(|| endo))
}

fn point<'dr, C: Affine>(dr: &mut Dr<C>, point: C) -> Result<Point<'dr, Dr<C>, C>> {
    Point::alloc(dr, <Dr<C> as Driver>::just(|| point))
}

fn points<'dr, C: Affine>(
    dr: &mut Dr<C>,
    points: impl IntoIterator<Item = C>,
) -> Result<Vec<Point<'dr, Dr<C>, C>>> {
    points.into_iter().map(|p| point(dr, p)).collect()
}

/// The claims' points on `side`'s curve, through the side's builder.
fn claims_of<'dr, C: Affine>(
    dr: &mut Dr<C>,
    side: &Side<C>,
    commitments: &[Point<'dr, Dr<C>, C>],
    z: &Endoscalar<'dr, Dr<C>>,
    bank: &mut NonzeroBank<'dr, Dr<C>>,
    native: bool,
) -> Result<Vec<Claim<'dr, Dr<C>, C>>> {
    if native {
        let masked = side.masked.iter().map(|&position| {
            crate::compress::revdot::native_components()
                .nth(position)
                .expect("a native component")
        });
        native_claims(
            dr,
            commitments,
            side.circuit_id.expect("the native side has a circuit"),
            z,
            masked,
            bank,
        )
    } else {
        let masked = side.masked.iter().map(|&position| {
            crate::compress::revdot::nested_components()
                .nth(position)
                .expect("a nested component")
        });
        nested_claims(dr, commitments, z, masked, bank)
    }
}

/// The chains derive what the native verifier derives: the fold's three
/// commitments and the batched commitment.
fn check_derived<C: Affine>(side: &Side<C>, native: bool) -> Simulator<C::Base> {
    Simulator::simulate((), |dr, _| {
        let commitments = points(dr, side.commitments.iter().copied())?;
        let z = endoscalar::<C>(dr, side.raw.z)?;
        let weights = Weights {
            mu: endoscalar::<C>(dr, side.raw.weights.mu)?,
            nu: endoscalar::<C>(dr, side.raw.weights.nu)?,
            mu_prime: endoscalar::<C>(dr, side.raw.weights.mu_prime)?,
            nu_prime: endoscalar::<C>(dr, side.raw.weights.nu_prime)?,
        };
        let beta = endoscalar::<C>(dr, side.raw.beta)?;
        NonzeroBank::scope(dr, |dr, bank| {
            let claims = claims_of(dr, side, &commitments, &z, bank, native)?;
            assert_eq!(claims.len(), side.shapes.len());
            for (claim, shape) in claims.iter().zip(&side.shapes) {
                assert_eq!(claim.kind, shape.kind);
            }

            let derived = fold(dr, &claims, &weights, bank)?;
            for (which, (point, expected)) in
                Derived::ALL.iter().zip(derived.iter().zip(&side.derived))
            {
                assert_eq!(point.value().take(), *expected, "{which:?}");
            }

            let f = point(dr, side.messages.batch.f)?;
            let opened = points(dr, side.openings.commitments.iter().copied())?;
            let h = batched(dr, &f, &opened, &beta, bank)?;
            assert_eq!(h.value().take(), side.batched.commitment);
            Ok(())
        })
    })
    .expect("the derivations satisfy the circuit")
}

/// The IPA's final check over the native verifier's points holds for the
/// honest proof and fails for a wrong $c$.
fn check_opening<C: Affine>(side: &Side<C>, c: C::Scalar) -> Result<Simulator<C::Base>> {
    let lifted = &side.lifted;
    let b = b_at(side.batched.point, &lifted.rounds);
    let cbz = c * b * lifted.ipa_z;
    let inverse_scaled: Vec<C> = side
        .messages
        .opening
        .rounds
        .iter()
        .zip(&lifted.rounds)
        .map(|(&(l, _), u_j)| (l * u_j.invert().expect("a round challenge is nonzero")).to_affine())
        .collect();

    Simulator::simulate((), |dr, _| {
        let h = point(dr, side.batched.commitment)?;
        let mut rounds = Vec::new();
        for &(l, r) in &side.messages.opening.rounds {
            rounds.push((point(dr, l)?, point(dr, r)?));
        }
        let opening = Opening {
            s_commitment: point(dr, side.messages.opening.s_commitment)?,
            rounds,
            inverse_scaled: points(dr, inverse_scaled.iter().copied())?,
            g_prime: point(dr, side.g_prime)?,
        };
        let xi = endoscalar::<C>(dr, side.raw.xi)?;
        let u = side
            .raw
            .rounds
            .iter()
            .map(|&raw| endoscalar::<C>(dr, raw))
            .collect::<Result<Vec<_>>>()?;
        let scalars = Scalars {
            v: Digits::alloc(dr, <Dr<C> as Driver>::just(|| side.batched.value))?,
            c: Digits::alloc(dr, <Dr<C> as Driver>::just(|| c))?,
            cbz: Digits::alloc(dr, <Dr<C> as Driver>::just(|| cbz))?,
        };
        let fixed = Fixed {
            g_0: side.params.g[0],
            u: side.params.u,
            offset: side.params.g[1],
        };
        NonzeroBank::scope(dr, |dr, bank| {
            enforce_opening(dr, &h, &opening, &xi, &u, &scalars, fixed, bank)
        })
    })
}

/// A scalar's digits scale a point by it.
fn check_scale<C: Affine>(side: &Side<C>) {
    let k = side.batched.value;
    let g = side.params.g[2];
    let offset = side.params.g[1];
    let expected = (g * k).to_affine();
    Simulator::simulate((), |dr, _| {
        let g = point(dr, g)?;
        let digits = Digits::alloc(dr, <Dr<C> as Driver>::just(|| k))?;
        let scaled = NonzeroBank::scope(dr, |dr, bank| scale(dr, &g, &digits, offset, bank))?;
        assert_eq!(scaled.value().take(), expected);
        Ok(())
    })
    .unwrap();
}

#[test]
fn native_commitments_derive_in_circuit() {
    let setup = Setup::new();
    let side = native_side(&setup);
    let dr = check_derived(&side, true);
    std::println!(
        "native derivations: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
    check_scale(&side);
    let dr = check_opening(&side, side.messages.opening.c).expect("the honest opening holds");
    std::println!(
        "native opening: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
    assert!(check_opening(&side, side.messages.opening.c + Fp::ONE).is_err());
}

#[test]
fn nested_commitments_derive_in_circuit() {
    let setup = Setup::new();
    let side = nested_side(&setup);
    let dr = check_derived(&side, false);
    std::println!(
        "nested derivations: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
    check_scale(&side);
    let dr = check_opening(&side, side.messages.opening.c).expect("the honest opening holds");
    std::println!(
        "nested opening: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
    assert!(check_opening(&side, side.messages.opening.c + Fq::ONE).is_err());
}
