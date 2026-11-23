//! The gadgets against the native verifier, on both curves of a real
//! compressed proof.

mod revdot {
    //! The revdot reduction's gadget against the native verifier, both curves
    //! of a real compressed proof: the honest messages satisfy the circuit,
    //! which leaves the opening claims the native verifier leaves, and a
    //! tampered message violates it.

    use alloc::{boxed::Box, vec::Vec};

    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_circuits::{
        polynomials::WalletRank,
        registry::{CircuitIndex, Registry},
    };
    use ragu_core::{
        Result,
        maybe::Maybe,
        pasta::{Fp, Fq, Pasta},
    };
    use ragu_primitives::Simulator;
    use udon::{curve::Affine, field::Field};

    use super::super::revdot::{Binding, Challenges, Messages, Public, verify};
    use crate::{
        compress::{
            Lifted,
            revdot::{
                self, Openings, Reduction,
                claims::{self, Kind, Masked, Shape},
                fold::{Derived, Weights},
            },
        },
        decompress::support::{
            EpAffine, EqAffine, HEADER_SIZE, Setup, TestR, alloc, alloc_all, replay_reduction,
        },
        internal::{native, nested},
        profile::Standard,
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
        registry: &Registry<'_, F, WalletRank>,
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
            .unwrap()
            .masked;
        let shapes = claims::native_shapes::<Standard, _>(sampled.z, &masked).unwrap();
        let targets: Vec<Fp> = native::claims::ky_values::<Standard, _>(&targets)
            .take(shapes.len())
            .collect();

        let replay = |reduction: &Reduction<EqAffine>| {
            let (mut t, _, _) = setup.transcript();
            replay_reduction(reduction, &mut Lifted(t.host()))
        };
        let native = {
            let masked = masked.clone();
            move |reduction: &Reduction<EqAffine>| {
                let (mut t, sampled, nested_sampled) = setup.transcript();
                revdot::verify_native::<Pasta, TestR, ReferenceBackend>(
                    |component| instance.native_commitment(component),
                    registry,
                    sampled.y,
                    sampled.z,
                    &setup.targets(sampled.y, nested_sampled.y).0,
                    &masked,
                    reduction,
                    &mut Lifted(t.host()),
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
            .unwrap()
            .masked;
        let shapes = claims::nested_shapes::<Standard, _>(sampled.z, &masked).unwrap();
        let targets: Vec<Fq> = nested::claims::ky_values::<Standard, _>(&targets)
            .take(shapes.len())
            .collect();

        let replay = |reduction: &Reduction<EpAffine>| {
            let (mut t, native_sampled, sampled) = setup.transcript();
            setup.run_native(&mut t, &native_sampled, sampled.y);
            replay_reduction(reduction, &mut Lifted(t.nested()))
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
                    &mut Lifted(t.nested()),
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
            (|r: &mut Reduction<C>| r.fold.inner_epsilon += C::Scalar::ONE)
                as fn(&mut Reduction<C>),
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
}

mod batch {
    //! The batch's gadget against the native verifier, both curves of a real
    //! compressed proof: on the openings the reductions leave, it computes
    //! the native verifier's point and value and weights that combine $\[f\]$
    //! and the commitments into its batched commitment, honest or tampered,
    //! and fails to witness a point the native verifier rejects.

    use alloc::vec::Vec;

    use ragu_backend::{Backend, ReferenceBackend};
    use ragu_core::{Result, maybe::Maybe};
    use ragu_primitives::Simulator;
    use udon::{curve::Affine, field::Field};

    use super::super::batch::{Challenges, Messages, verify};
    use crate::{
        compress::{
            Lifted,
            batch::{self, Batch, Batched},
            revdot::{OpeningClaim, Openings},
        },
        decompress::support::{Setup, alloc, alloc_all, replay_batch},
    };

    /// What the gadget produces on `claims` over `polys` committed
    /// polynomials, by value: the point, the value and the weights.
    fn simulate<F: Field>(
        claims: &[OpeningClaim<F>],
        polys: usize,
        evaluations: &[F],
        (alpha, u, beta): (F, F, F),
    ) -> Result<(F, F, Vec<F>)> {
        let mut out = None;
        Simulator::simulate((), |dr, _| {
            let claims: Vec<OpeningClaim<_>> = claims
                .iter()
                .map(|claim| {
                    Ok(OpeningClaim {
                        poly: claim.poly,
                        point: alloc(dr, claim.point)?,
                        value: alloc(dr, claim.value)?,
                    })
                })
                .collect::<Result<_>>()?;
            let challenges = Challenges {
                alpha: alloc(dr, alpha)?,
                u: alloc(dr, u)?,
                beta: alloc(dr, beta)?,
            };
            let messages = Messages {
                evaluations: alloc_all(dr, evaluations.iter().copied())?,
            };
            let batched = verify(dr, &claims, polys, &challenges, &messages)?;
            out = Some((
                *batched.point.value().take(),
                *batched.value.value().take(),
                batched
                    .weights
                    .iter()
                    .map(|weight| *weight.value().take())
                    .collect(),
            ));
            Ok(())
        })?;
        Ok(out.expect("the simulation ran"))
    }

    /// The gadget on `batch` over `openings` under `challenges` agrees with
    /// the native verifier's `expected` claim: the same point and value, and
    /// weights combining $\[f\]$ and the commitments into its commitment.
    fn check<F: Field, C: Affine<Scalar = F>>(
        openings: &Openings<C>,
        batch: &Batch<C>,
        challenges: (F, F, F),
        expected: &Batched<C>,
    ) {
        let (point, value, weights) = simulate(
            &openings.claims,
            openings.commitments.len(),
            &batch.evaluations,
            challenges,
        )
        .expect("the batch satisfies the circuit");
        assert_eq!(point, expected.point);
        assert_eq!(value, expected.value);
        let points: Vec<C> = core::iter::once(batch.f)
            .chain(openings.commitments.iter().copied())
            .collect();
        let commitment: C = ReferenceBackend::msm(&weights, &points).into();
        assert_eq!(commitment, expected.commitment);
    }

    /// A tampered value at $u$ moves $v$ in both: the batch leaves it for the
    /// IPA.
    fn tampered<C: Affine>(batch: &Batch<C>) -> Batch<C> {
        let mut tampered = batch.clone();
        tampered.evaluations[2] += C::Scalar::ONE;
        tampered
    }

    /// With a claim's point moved onto $u$, neither side can form the
    /// quotient.
    fn onto_u<F: Field, C: Affine<Scalar = F>>(openings: &Openings<C>, u: F) -> Openings<C> {
        let mut moved = openings.clone();
        moved.claims[0].point = u;
        moved
    }

    #[test]
    fn native_batch_matches_the_verifier() {
        let setup = Setup::new();
        let at_batch = || {
            let (mut t, sampled, nested_sampled) = setup.transcript();
            let openings = setup.native_openings(&mut t, &sampled, nested_sampled.y);
            (t, openings)
        };
        let challenges = |batch: &Batch<_>| replay_batch(batch, &mut Lifted(at_batch().0.host()));
        let expected = |openings: &Openings<_>, batch: &Batch<_>| {
            batch::verifier::verify::<_, ReferenceBackend, _>(
                &openings.commitments,
                &openings.claims,
                batch,
                &mut Lifted(at_batch().0.host()),
            )
        };

        let openings = at_batch().1;
        for batch in [
            setup.proof.native.batch.clone(),
            tampered(&setup.proof.native.batch),
        ] {
            check(
                &openings,
                &batch,
                challenges(&batch),
                &expected(&openings, &batch).unwrap(),
            );
        }

        let batch = &setup.proof.native.batch;
        let challenges = challenges(batch);
        let moved = onto_u(&openings, challenges.1);
        assert!(expected(&moved, batch).is_err());
        assert!(
            simulate(
                &moved.claims,
                moved.commitments.len(),
                &batch.evaluations,
                challenges
            )
            .is_err()
        );
    }

    #[test]
    fn nested_batch_matches_the_verifier() {
        let setup = Setup::new();
        let at_batch = || {
            let (mut t, native_sampled, sampled) = setup.transcript();
            setup.run_native(&mut t, &native_sampled, sampled.y);
            let openings = setup.nested_openings(&mut t, &sampled, native_sampled.y);
            (t, openings)
        };
        let challenges = |batch: &Batch<_>| replay_batch(batch, &mut Lifted(at_batch().0.nested()));
        let expected = |openings: &Openings<_>, batch: &Batch<_>| {
            batch::verifier::verify::<_, ReferenceBackend, _>(
                &openings.commitments,
                &openings.claims,
                batch,
                &mut Lifted(at_batch().0.nested()),
            )
        };

        let openings = at_batch().1;
        for batch in [
            setup.proof.nested.batch.clone(),
            tampered(&setup.proof.nested.batch),
        ] {
            check(
                &openings,
                &batch,
                challenges(&batch),
                &expected(&openings, &batch).unwrap(),
            );
        }

        let batch = &setup.proof.nested.batch;
        let challenges = challenges(batch);
        let moved = onto_u(&openings, challenges.1);
        assert!(expected(&moved, batch).is_err());
        assert!(
            simulate(
                &moved.claims,
                moved.commitments.len(),
                &batch.evaluations,
                challenges
            )
            .is_err()
        );
    }
}

mod ipa {
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

    use super::super::ipa::{Challenges, Messages, verify};
    use crate::{
        compress::{
            Lifted,
            batch::{self, Batched},
        },
        decompress::support::{Setup, TestR, alloc, alloc_all, replay_ipa},
        ipa::{self, IpaCycle, IpaProof, MSM, Params},
    };

    /// The gadget's scalars, by value.
    struct Scalars<F> {
        g_0: F,
        s_commitment: F,
        rounds: Vec<(F, F)>,
        u: F,
        g_prime: F,
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
            let value =
                |element: &ragu_primitives::Element<'_, Simulator<F>>| *element.value().take();
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
            let claim = batch::verifier::verify::<_, ReferenceBackend, _>(
                &openings.commitments,
                &openings.claims,
                &setup.proof.native.batch,
                &mut Lifted(t.host()),
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
                &mut Lifted(t.host()),
                &proof,
                claim.point,
                claim.value,
            )
            .unwrap();
            let g_prime = guard.compute_g::<ReferenceBackend>();
            assert_eq!(guard.use_challenges().eval::<ReferenceBackend>(), expected);

            let (mut t, _) = at_ipa();
            let challenges = replay_ipa(&proof, &mut Lifted(t.host()));
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
            let claim = batch::verifier::verify::<_, ReferenceBackend, _>(
                &openings.commitments,
                &openings.claims,
                &setup.proof.nested.batch,
                &mut Lifted(t.nested()),
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
                &mut Lifted(t.nested()),
                &proof,
                claim.point,
                claim.value,
            )
            .unwrap();
            let g_prime = guard.compute_g::<ReferenceBackend>();
            assert_eq!(guard.use_challenges().eval::<ReferenceBackend>(), expected);

            let (mut t, _) = at_ipa();
            let challenges = replay_ipa(&proof, &mut Lifted(t.nested()));
            let scalars = simulate(claim.point, claim.value, challenges, proof.c).unwrap();
            assert_eq!(
                accepts(&params, &claim, &proof, g_prime, &scalars),
                expected
            );
        }
    }
}

mod derive {
    //! The derived commitments against the native verifier, both curves of a
    //! real compressed proof: over the instance's commitments as points and
    //! the challenges as endoscalars, the chains give the commitments the
    //! native verifier derives and the batched commitment it forms, a
    //! full-width scalar's digits scale a point by it, and the IPA's final
    //! check, over the $G'$ the native verifier derives, holds exactly when
    //! the native verifier accepts.

    use alloc::vec::Vec;

    use ragu_backend::ReferenceBackend;
    use ragu_circuits::polynomials::Rank;
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

    use super::super::derive::{
        Claim, Digits, Fixed, Opening, Scalars, batched, enforce_opening, fold, native_claims,
        nested_claims, scale, scale_chain, scale_offset,
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
        decompress::support::{
            HEADER_SIZE, Setup, TestR, replay_batch, replay_ipa, replay_reduction,
        },
        ipa::{self, IpaCycle, IpaTranscript, MSM, Params},
        profile::Standard,
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
        let batched = batch::verifier::verify::<_, ReferenceBackend, _>(
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
            .unwrap()
            .masked;
        let shapes = claims::native_shapes::<Standard, _>(lifted.z, &masked).unwrap();
        let position = |component| crate::compress::revdot::native_position::<Standard>(component);
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
        let batched = batch::verifier::verify::<_, ReferenceBackend, _>(
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
            .unwrap()
            .masked;
        let shapes = claims::nested_shapes::<Standard, _>(lifted.z, &masked).unwrap();
        let position = |component| crate::compress::revdot::nested_position::<Standard>(component);
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

    fn endoscalar<'dr, C: Affine>(
        dr: &mut Dr<C>,
        raw: C::Scalar,
    ) -> Result<Endoscalar<'dr, Dr<C>>> {
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
                crate::compress::revdot::native_components::<Standard>()
                    .nth(position)
                    .expect("a native component")
            });
            native_claims(dr, commitments, z, masked, bank)
        } else {
            let masked = side.masked.iter().map(|&position| {
                crate::compress::revdot::nested_components::<Standard>()
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
            .map(|(&(l, _), u_j)| {
                (l * u_j.invert().expect("a round challenge is nonzero")).to_affine()
            })
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

    /// The IPA final check's three scalars can each be zero. Distinct retained
    /// offsets keep every intermediate point affine and cancel in the sum.
    fn check_zero_scalars<C: Affine>(side: &Side<C>) {
        let points = [side.params.g[0], side.g_prime, side.params.u];
        let offset = side.params.g[1];
        for zero in 0..3 {
            let mut values = [C::Scalar::ONE; 3];
            values[zero] = C::Scalar::ZERO;
            let expected =
                (points[0] * values[0] + points[1] * values[1] + points[2] * values[2]).to_affine();
            Simulator::simulate((), |dr, _| {
                let actual = NonzeroBank::scope(dr, |dr, bank| {
                    let mut terms = Vec::new();
                    for i in 0..3 {
                        let point = Point::constant(dr, points[i])?;
                        let digits = Digits::alloc(dr, <Dr<C> as Driver>::just(|| values[i]))?;
                        let shifted_offset = (offset * C::Scalar::from(1u64 << i)).to_affine();
                        terms.push(scale_chain(
                            dr,
                            &point,
                            &digits,
                            None,
                            shifted_offset,
                            bank,
                        )?);
                    }
                    let mut terms = terms.into_iter();
                    let mut acc = terms.next().expect("three terms");
                    for term in terms {
                        acc = acc.add_incomplete(dr, &term, bank)?;
                    }
                    let correction =
                        (scale_offset(offset, super::super::derive::digit_width::<C::Scalar>())
                            * C::Scalar::from(7))
                        .to_affine();
                    let correction = Point::constant(dr, correction)?.negate(dr);
                    acc.add_incomplete(dr, &correction, bank)
                })?;
                assert_eq!(actual.value().take(), expected);
                Ok(())
            })
            .expect("a zero IPA scalar still has an affine final point");
        }
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
        check_zero_scalars(&side);
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
        check_zero_scalars(&side);
        let dr = check_opening(&side, side.messages.opening.c).expect("the honest opening holds");
        std::println!(
            "nested opening: {} gates, {} constraints",
            dr.num_gates(),
            dr.num_constraints()
        );
        assert!(check_opening(&side, side.messages.opening.c + Fq::ONE).is_err());
    }
}
