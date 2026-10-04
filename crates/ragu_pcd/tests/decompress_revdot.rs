//! The revdot reduction's gadget against the native verifier, both curves
//! of a real compressed proof: the honest messages satisfy the circuit,
//! which leaves the opening claims the native verifier leaves, and a
//! tampered message violates it.

use alloc::{boxed::Box, vec::Vec};

use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::ProductionRank,
    registry::{CircuitIndex, Registry},
};
use ragu_core::{
    Result,
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::Simulator;
use udon::{curve::Affine, field::Field};

use super::{Binding, Challenges, Messages, Public, verify};
use crate::{
    compress::revdot::{
        self, Openings, Reduction,
        claims::{self, Kind, Masked, Shape},
        fold::{Derived, Weights},
    },
    decompress::support::{
        EpAffine, EqAffine, HEADER_SIZE, Setup, TestR, alloc, alloc_all, replay_reduction,
    },
    internal::{native, nested},
};

/// What the gadget takes on one curve, natively, and the native verifier
/// to compare it with. The challenges depend on the reduction's messages,
/// so they are replayed per reduction.
struct Side<'a, F: Field, Id, C: Affine> {
    registry: &'a Registry<'a, F, TestR>,
    shapes: Vec<Shape<Id, F>>,
    targets: Vec<F>,
    masked: Vec<Masked<Id, F>>,
    sigma: F,
    y: F,
    z: F,
    /// The reduction's challenges, replayed on the transcript as the
    /// verifier reaches it.
    replay: Box<dyn Fn(&Reduction<C>) -> (Weights<F>, F, F) + 'a>,
    /// The native verifier on a reduction, as `verify_compressed` runs it.
    native: Box<dyn Fn(&Reduction<C>) -> Option<Openings<C>> + 'a>,
}

/// Each named circuit's restriction at $(r, y)$.
fn restrictions<F: Field, Id>(
    shapes: &[Shape<Id, F>],
    registry: &Registry<'_, F, ProductionRank>,
    r: F,
    y: F,
) -> Vec<(CircuitIndex, F)> {
    let mut circuits: Vec<CircuitIndex> = Vec::new();
    for shape in shapes {
        if let Kind::Circuit(circuit) | Kind::Bonding(circuit) = shape.kind
            && !circuits.contains(&circuit)
        {
            circuits.push(circuit);
        }
    }
    circuits
        .into_iter()
        .map(|circuit| {
            (
                circuit,
                ReferenceBackend::registry_wxy(registry, circuit.omega_j(), r, y),
            )
        })
        .collect()
}

fn native_side(setup: &Setup) -> Side<'_, Fp, native::RxComponent, EqAffine> {
    let instance = &setup.proof.instance;
    let registry = &setup.app.native_registry;

    let (_, sampled, nested_sampled) = setup.transcript();
    let (targets, _) = setup.targets(sampled.y, nested_sampled.y);
    let masked = instance
        .native_bindings::<TestR, ReferenceBackend, HEADER_SIZE>(
            &setup.challenges,
            registry,
            sampled.sigma,
        )
        .unwrap();
    let shapes = claims::native_shapes(instance.circuit_id, sampled.z, &masked).unwrap();
    let targets: Vec<Fp> = native::claims::ky_values(&targets)
        .take(shapes.len())
        .collect();

    let replay = |reduction: &Reduction<EqAffine>| {
        let (mut t, _, _) = setup.transcript();
        replay_reduction(reduction, &mut t.host())
    };
    let native = {
        let masked = masked.clone();
        move |reduction: &Reduction<EqAffine>| {
            let (mut t, sampled, nested_sampled) = setup.transcript();
            revdot::verify_native::<Pasta, TestR, ReferenceBackend>(
                instance.circuit_id,
                |component| instance.native_commitment(component),
                registry,
                sampled.y,
                sampled.z,
                &setup.targets(sampled.y, nested_sampled.y).0,
                &masked,
                reduction,
                &mut t.host(),
            )
            .unwrap()
        }
    };

    Side {
        registry,
        shapes,
        targets,
        masked,
        sigma: sampled.sigma,
        y: sampled.y,
        z: sampled.z,
        replay: Box::new(replay),
        native: Box::new(native),
    }
}

fn nested_side(setup: &Setup) -> Side<'_, Fq, nested::RxComponent, EpAffine> {
    let instance = &setup.proof.instance;
    let registry = &setup.app.nested_registry;

    let (_, native_sampled, sampled) = setup.transcript();
    let (_, targets) = setup.targets(native_sampled.y, sampled.y);
    let masked = instance
        .nested_bindings::<TestR, ReferenceBackend>(&setup.challenges, registry, sampled.sigma)
        .unwrap();
    let shapes = claims::nested_shapes(sampled.z, &masked).unwrap();
    let targets: Vec<Fq> = nested::claims::ky_values(&targets)
        .take(shapes.len())
        .collect();

    let replay = |reduction: &Reduction<EpAffine>| {
        let (mut t, native_sampled, sampled) = setup.transcript();
        setup.run_native(&mut t, &native_sampled, sampled.y);
        replay_reduction(reduction, &mut t.nested())
    };
    let native = {
        let masked = masked.clone();
        move |reduction: &Reduction<EpAffine>| {
            let (mut t, native_sampled, sampled) = setup.transcript();
            setup.run_native(&mut t, &native_sampled, sampled.y);
            revdot::verify_nested::<Pasta, TestR, ReferenceBackend>(
                |component| instance.nested_commitment(component),
                registry,
                sampled.y,
                sampled.z,
                &setup.targets(native_sampled.y, sampled.y).1,
                &masked,
                reduction,
                &mut t.nested(),
            )
            .unwrap()
        }
    };

    Side {
        registry,
        shapes,
        targets,
        masked,
        sigma: sampled.sigma,
        y: sampled.y,
        z: sampled.z,
        replay: Box::new(replay),
        native: Box::new(native),
    }
}

/// Runs the gadget on `side` with the reduction's scalar `messages` under
/// the simulator, which enforces every constraint. Returns the opening
/// claims it leaves, by value, and the simulator for its counts.
fn simulate<F: Field, Id, C: Affine<Scalar = F>>(
    side: &Side<'_, F, Id, C>,
    messages: &Reduction<C>,
) -> Result<(Vec<revdot::OpeningClaim<F>>, Simulator<F>)> {
    let (weights, rho, r) = (side.replay)(messages);
    let restrictions = restrictions(&side.shapes, side.registry, r, side.y);
    let mut claims = Vec::new();
    let dr = Simulator::simulate((), |dr, _| {
        let sigma = alloc(dr, side.sigma)?;
        let public = Public {
            kinds: side.shapes.iter().map(|shape| shape.kind).collect(),
            targets: alloc_all(dr, side.targets.iter().copied())?,
            restrictions: restrictions
                .iter()
                .map(|&(circuit, value)| Ok((circuit, alloc(dr, value)?)))
                .collect::<Result<_>>()?,
            bindings: side
                .masked
                .iter()
                .map(|masked| {
                    Ok(Binding {
                        degrees: masked.wires.iter().map(|&(degree, _)| degree).collect(),
                        expected: alloc_all(dr, masked.wires.iter().map(|&(_, value)| value))?,
                    })
                })
                .collect::<Result<_>>()?,
            sigma,
        };
        let challenges = Challenges {
            z: alloc(dr, side.z)?,
            weights: Weights {
                mu: alloc(dr, weights.mu)?,
                nu: alloc(dr, weights.nu)?,
                mu_prime: alloc(dr, weights.mu_prime)?,
                nu_prime: alloc(dr, weights.nu_prime)?,
            },
            rho: alloc(dr, rho)?,
            r: alloc(dr, r)?,
        };
        let messages = Messages {
            inner_epsilon: alloc(dr, messages.fold.inner_epsilon)?,
            outer_epsilon: alloc(dr, messages.fold.outer_epsilon)?,
            openings: alloc_all(dr, messages.openings.iter().copied())?,
            p_at_inverse_r: alloc(dr, messages.p_at_inverse_r)?,
            q_at_r: alloc(dr, messages.q_at_r)?,
        };

        let openings = verify::<_, TestR>(dr, &public, &challenges, &messages)?;
        claims = openings
            .iter()
            .map(|claim| revdot::OpeningClaim {
                poly: claim.poly,
                point: *claim.point.value().take(),
                value: *claim.value.value().take(),
            })
            .collect();
        Ok(())
    })?;
    Ok((claims, dr))
}

/// The gadget agrees with the native verifier on `reduction`: both reject
/// it, or both accept it and leave the same opening claims. Returns
/// whether it was accepted.
fn agree<F: Field, Id, C: Affine<Scalar = F>>(
    side: &Side<'_, F, Id, C>,
    reduction: &Reduction<C>,
) -> bool {
    let native = (side.native)(reduction);
    match simulate(side, reduction) {
        Ok((claims, _)) => {
            let native = native.expect("the native verifier accepts what the circuit accepts");
            assert_eq!(
                claims, native.claims,
                "the circuit leaves the native openings"
            );
            true
        }
        Err(_) => {
            assert!(
                native.is_none(),
                "the native verifier rejects what the circuit rejects"
            );
            false
        }
    }
}

/// Every single-message tampering the native verifier rejects, as a
/// change to the honest reduction.
fn tamperings<C: Affine>(honest: &Reduction<C>) -> Vec<Reduction<C>> {
    let mut tampered = Vec::new();
    for change in [
        (|r: &mut Reduction<C>| r.fold.inner_epsilon += C::Scalar::ONE) as fn(&mut Reduction<C>),
        |r| r.fold.outer_epsilon += C::Scalar::ONE,
        |r| r.openings[Derived::A as usize] += C::Scalar::ONE,
        |r| r.openings[Derived::Dilated as usize] += C::Scalar::ONE,
        |r| r.openings[Derived::B as usize] += C::Scalar::ONE,
        |r| r.openings[Derived::Inner as usize] += C::Scalar::ONE,
        |r| r.openings[Derived::Outer as usize] += C::Scalar::ONE,
        |r| r.p_at_inverse_r += C::Scalar::ONE,
        |r| r.q_at_r += C::Scalar::ONE,
    ] {
        let mut reduction = honest.clone();
        change(&mut reduction);
        tampered.push(reduction);
    }
    tampered
}

/// The honest reduction satisfies the circuit, which leaves the native
/// verifier's opening claims, and the circuit agrees with the native
/// verifier on every tampering, each of which it rejects: a tampered
/// message moves the challenges squeezed after it, so even one that
/// enters the target alone breaks the split identity.
fn check<F: Field, Id, C: Affine<Scalar = F>>(
    side: &Side<'_, F, Id, C>,
    honest: &Reduction<C>,
) -> Simulator<F> {
    assert!(agree(side, honest), "the honest reduction holds");
    for tampered in tamperings(honest) {
        assert!(!agree(side, &tampered), "a tampered message is rejected");
    }
    simulate(side, honest).unwrap().1
}

#[test]
fn native_reduction_holds_in_circuit() {
    let setup = Setup::new();
    let dr = check(&native_side(&setup), &setup.proof.native.reduction);
    std::println!(
        "native: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
}

#[test]
fn nested_reduction_holds_in_circuit() {
    let setup = Setup::new();
    let dr = check(&nested_side(&setup), &setup.proof.nested.reduction);
    std::println!(
        "nested: {} gates, {} constraints",
        dr.num_gates(),
        dr.num_constraints()
    );
}
