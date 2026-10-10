//! Regression checks for shared verifier targets and the statement that
//! connects Fuse's replayed challenges to the compression transcript.

use alloc::{format, string::ToString, vec, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{ProductionRank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, allocator::Allocator};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{
    instance::Instance,
    revdot::{claims, nested_position},
};
use crate::{
    Pcd, Proof, RAGU_TAG,
    header::{Header, Suffix},
    internal::{ky, native, nested},
    ipa::{CycleTranscript, IPA_TAG, IpaTranscript},
    proof::recursive_propagation_tests::support::{
        App, HEADER_SIZE, Merge, Seed, TestPcd, UnitLeft, UnitRight, Value, with_app,
    },
};

fn check_targets<H: Header<Fp>>(
    app: &App,
    pcd: &Pcd<Pasta, ProductionRank, H>,
    label: &str,
    rng: &mut StdRng,
) {
    assert!(app.verify(pcd, &mut *rng).unwrap(), "{label}");
    let compressed = app.compress(pcd, &mut *rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap(), "{label}");
    let instance = &compressed.proof().instance;
    let mut transcript = CycleTranscript::<Pasta>::new(crate::pasta::baked(), RAGU_TAG).unwrap();
    let challenges = instance.challenges(&mut transcript).unwrap().unwrap();
    let header = ky::output_header::<Pasta, H, HEADER_SIZE>(pcd.data().clone()).unwrap();
    let native_count = claims::native_shapes(instance.circuit_ids, Fp::ONE, &[])
        .unwrap()
        .len();
    let nested_count = claims::nested_shapes(Fq::ONE, &[]).unwrap().len();

    for (y, nested_y) in [
        (Fp::ZERO, Fq::ZERO),
        (Fp::ONE, Fq::ONE),
        (-Fp::ONE, -Fq::ONE),
        (
            Fp::random(|bytes| rng.fill_bytes(bytes)),
            Fq::random(|bytes| rng.fill_bytes(bytes)),
        ),
    ] {
        let expected = ky::native_ky::<Pasta, ProductionRank, H, HEADER_SIZE>(pcd, y).unwrap();
        let expected_nested = ky::NestedKy {
            c: pcd.proof().nested_c(),
            unified: ky::nested_ky(pcd.proof(), nested_y).unwrap(),
        };
        let (native, nested) = instance
            .targets::<HEADER_SIZE>(&challenges, &header, y, nested_y)
            .unwrap();

        // The decider derives native c from the polynomials themselves;
        // compression carries it as the first target of its opening proof.
        assert_eq!(expected.c, None, "{label}");
        assert_eq!(native.c, Some(pcd.proof().native_c()), "{label}");
        assert_eq!(native.application, expected.application, "{label}");
        assert_eq!(native.unified_bridge, expected.unified_bridge, "{label}");
        assert_eq!(native.unified, expected.unified, "{label}");
        assert_eq!(nested.c, expected_nested.c, "{label}");
        assert_eq!(nested.unified, expected_nested.unified, "{label}");

        // Compare the finite target lists consumed by the claim builders,
        // including the raw claim's position relative to the circuit claims.
        let targets: Vec<_> = native::claims::ky_values(&native)
            .take(native_count)
            .collect();
        let decider_targets: Vec<_> = native::claims::ky_values(&expected)
            .take(native_count - 1)
            .collect();
        assert_eq!(targets[0], pcd.proof().native_c(), "{label}");
        assert_eq!(&targets[1..], decider_targets.as_slice(), "{label}");
        assert_eq!(
            nested::claims::ky_values(&nested)
                .take(nested_count)
                .collect::<Vec<_>>(),
            nested::claims::ky_values(&expected_nested)
                .take(nested_count)
                .collect::<Vec<_>>(),
            "{label}"
        );
    }
}

#[test]
fn targets_match_the_decider_across_proof_shapes() {
    with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x462_2026);
        let bootstrap = app.bootstrap_pcd();
        let (left, ()) = app.seed(&mut rng, Seed::new(), Fp::from(3)).unwrap();
        let (right, ()) = app.seed(&mut rng, Seed::new(), Fp::from(5)).unwrap();
        let (fused, ()) = app
            .fuse(
                &mut rng,
                Merge::new(),
                Fp::from(7),
                left.clone(),
                right.clone(),
            )
            .unwrap();
        let (unit_left, ()) = app
            .fuse(
                &mut rng,
                UnitLeft::new(),
                Fp::from(11),
                bootstrap.clone(),
                right,
            )
            .unwrap();
        let (unit_right, ()) = app
            .fuse(
                &mut rng,
                UnitRight::new(),
                Fp::from(13),
                left.clone(),
                bootstrap.clone(),
            )
            .unwrap();

        check_targets(app, &bootstrap, "bootstrap", &mut rng);
        for (name, pcd) in [
            ("seeded", &left),
            ("fused", &fused),
            ("unit left", &unit_left),
            ("unit right", &unit_right),
        ] {
            check_targets(app, pcd, name, &mut rng);
        }
    });
}

const HEADER_ERROR: &str = "regression test header error";

struct RejectHeader;

impl Header<Fp> for RejectHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        _: &mut D,
        _: &mut A,
        _: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Err(Error::InvalidWitness(HEADER_ERROR.into()))
    }
}

fn rejects_edit(
    app: &App,
    pcd: &TestPcd,
    label: &str,
    edit: impl FnOnce(&mut Proof<Pasta, ProductionRank>),
) {
    let mut proof = pcd.proof().clone();
    edit(&mut proof);
    let result = app.verify(
        &proof.carry::<Value>(*pcd.data()),
        StdRng::seed_from_u64(0xA11CE),
    );
    assert!(matches!(result, Ok(false)), "{label}: {result:?}");
}

#[test]
fn decider_rejects_malformed_inputs_and_propagates_header_errors() {
    with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x462_2026);
        let (left, ()) = app.seed(&mut rng, Seed::new(), Fp::from(3)).unwrap();
        let (right, ()) = app.seed(&mut rng, Seed::new(), Fp::from(5)).unwrap();
        let (pcd, ()) = app
            .fuse(&mut rng, Merge::new(), Fp::from(7), left, right)
            .unwrap();
        assert!(app.verify(&pcd, StdRng::seed_from_u64(0xA11CE)).unwrap());

        macro_rules! bump {
            ($field:ident, $one:expr) => {
                rejects_edit(app, &pcd, stringify!($field), |proof| proof.$field += $one);
            };
        }
        bump!(w, Fp::ONE);
        bump!(y, Fp::ONE);
        bump!(z, Fp::ONE);
        bump!(mu, Fp::ONE);
        bump!(nu, Fp::ONE);
        bump!(mu_prime, Fp::ONE);
        bump!(nu_prime, Fp::ONE);
        bump!(x, Fp::ONE);
        bump!(alpha, Fp::ONE);
        bump!(u, Fp::ONE);
        bump!(pre_beta, Fp::ONE);
        bump!(bridge_alpha, Fq::ONE);

        for left in [true, false] {
            for length in [0, 1, 2, 3, 5] {
                rejects_edit(
                    app,
                    &pcd,
                    &format!("left={left}, header length={length}"),
                    |proof| {
                        let header = if left {
                            &mut proof.left_header
                        } else {
                            &mut proof.right_header
                        };
                        header.resize(length, Fp::ZERO);
                    },
                );
            }
            rejects_edit(
                app,
                &pcd,
                &format!("left={left}, header content"),
                |proof| {
                    let header = if left {
                        &mut proof.left_header
                    } else {
                        &mut proof.right_header
                    };
                    header[0] += Fp::ONE;
                },
            );
        }
        rejects_edit(app, &pcd, "out-of-domain circuit", |proof| {
            proof.circuit_ids[0] = CircuitIndex::new(u32::MAX as usize);
        });
        rejects_edit(app, &pcd, "nonliftable pre_beta", |proof| {
            proof.pre_beta = -Fp::ONE
        });

        macro_rules! bump_poly {
            ($field:ident, $one:expr) => {
                rejects_edit(app, &pcd, stringify!($field), |proof| {
                    proof
                        .$field
                        .add_assign(&sparse::Polynomial::from_coeffs(vec![$one]));
                });
            };
        }
        bump_poly!(native_a_poly, Fp::ONE);
        bump_poly!(native_b_poly, Fp::ONE);
        bump_poly!(native_p_poly, Fp::ONE);
        bump_poly!(native_preamble_rx, Fp::ONE);
        bump_poly!(native_eval_rx, Fp::ONE);
        bump_poly!(native_query_rx, Fp::ONE);
        bump_poly!(nested_a_poly, Fq::ONE);
        bump_poly!(nested_b_poly, Fq::ONE);
        bump_poly!(nested_p_poly, Fq::ONE);
        bump_poly!(nested_challenges_rx, Fq::ONE);

        let changed_output = pcd.proof().clone().carry::<Value>(*pcd.data() + Fp::ONE);
        assert!(!app.verify(&changed_output, &mut rng).unwrap());
        let failed_header = pcd.proof().clone().carry::<RejectHeader>(*pcd.data());
        assert!(matches!(
            app.verify(&failed_header, &mut rng),
            Err(Error::InvalidWitness(error)) if error.to_string() == HEADER_ERROR
        ));
    });
}

#[test]
fn output_header_preserves_padding_capacity_and_errors() {
    let unit_suffix = Fp::from(<() as Header<Fp>>::SUFFIX.get());
    assert_eq!(
        ky::output_header::<Pasta, (), 1>(()).unwrap(),
        vec![unit_suffix]
    );
    assert_eq!(
        ky::output_header::<Pasta, (), HEADER_SIZE>(()).unwrap(),
        vec![Fp::ZERO, Fp::ZERO, Fp::ZERO, unit_suffix]
    );
    for value in [Fp::ZERO, Fp::ONE, -Fp::ONE, Fp::from(91)] {
        assert!(matches!(
            ky::output_header::<Pasta, Value, 1>(value),
            Err(Error::MalformedEncoding(_))
        ));
        assert_eq!(
            ky::output_header::<Pasta, Value, 2>(value).unwrap(),
            vec![value, Fp::from(Value::SUFFIX.get())]
        );
        assert_eq!(
            ky::output_header::<Pasta, Value, HEADER_SIZE>(value).unwrap(),
            vec![value, Fp::ZERO, Fp::ZERO, Fp::from(Value::SUFFIX.get())]
        );
    }
    assert!(matches!(
        ky::output_header::<Pasta, RejectHeader, HEADER_SIZE>(Fp::ONE),
        Err(Error::InvalidWitness(error)) if error.to_string() == HEADER_ERROR
    ));
}

/// Each bridge commitment and the number of Fuse challenges drawn after it.
fn fuse_schedule() -> [(nested::RxIndex, usize); 8] {
    use nested::RxIndex::*;
    [
        (BridgePreamble, 1),
        (BridgeSPrime, 2),
        (BridgeInnerError, 2),
        (BridgeOuterError, 2),
        (BridgeAB, 1),
        (BridgeQuery, 1),
        (BridgeF, 1),
        (BridgeEval, 1),
    ]
}

/// Replay without the pre_beta range check, so a changed bridge can be
/// checked even when the last draw falls outside the endoscalar range.
fn raw_fuse_challenges(instance: &Instance<Pasta>) -> Vec<Fp> {
    let mut transcript = CycleTranscript::<Pasta>::new(crate::pasta::baked(), RAGU_TAG).unwrap();
    let mut challenges = Vec::new();
    for (id, count) in fuse_schedule() {
        transcript
            .nested()
            .write_point(instance.nested[nested_position(nested::RxComponent::Rx(id))])
            .unwrap();
        for _ in 0..count {
            challenges.push(transcript.host().squeeze_challenge().unwrap());
        }
    }
    challenges
}

fn first_ipa_challenge(instance: &Instance<Pasta>, header: &[Fp]) -> Fp {
    super::transcript::<_, ReferenceBackend>(crate::pasta::baked(), instance, header)
        .unwrap()
        .host()
        .squeeze_challenge()
        .unwrap()
}

fn statement_challenge(tag: &[u8], instance: &Instance<Pasta>, header: &[Fp]) -> Fp {
    let mut transcript = CycleTranscript::<Pasta>::new(crate::pasta::baked(), tag).unwrap();
    instance.absorb(&mut transcript).unwrap();
    for &value in header {
        transcript.host().write_scalar(value).unwrap();
    }
    transcript.host().squeeze_challenge().unwrap()
}

#[test]
fn every_fuse_input_is_bound_before_compression_challenges() {
    with_app(|app| {
        let mut rng = StdRng::seed_from_u64(0x462_C011);
        let (pcd, ()) = app.seed(&mut rng, Seed::new(), Fp::from(19)).unwrap();
        let compressed = app.compress(&pcd, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed).unwrap());
        let instance = &compressed.proof().instance;
        let header = ky::output_header::<Pasta, Value, HEADER_SIZE>(*pcd.data()).unwrap();
        let baseline_fuse = raw_fuse_challenges(instance);
        let mut replay = CycleTranscript::<Pasta>::new(crate::pasta::baked(), RAGU_TAG).unwrap();
        assert_eq!(
            baseline_fuse.as_slice(),
            &instance
                .challenges(&mut replay)
                .unwrap()
                .unwrap()
                .in_order()
        );
        let baseline_ipa = first_ipa_challenge(instance, &header);
        assert_eq!(
            baseline_ipa,
            statement_challenge(IPA_TAG, instance, &header)
        );
        assert_ne!(
            baseline_ipa,
            statement_challenge(RAGU_TAG, instance, &header)
        );

        let mut prefix = 0;
        for (id, draws) in fuse_schedule() {
            let mut changed = instance.clone();
            let position = nested_position(nested::RxComponent::Rx(id));
            changed.nested[position] = -changed.nested[position];
            let changed_fuse = raw_fuse_challenges(&changed);
            assert_eq!(&changed_fuse[..prefix], &baseline_fuse[..prefix], "{id:?}");
            for j in prefix..baseline_fuse.len() {
                assert_ne!(
                    changed_fuse[j], baseline_fuse[j],
                    "{id:?}: downstream draw {j}"
                );
            }
            assert_ne!(
                first_ipa_challenge(&changed, &header),
                baseline_ipa,
                "{id:?}"
            );
            let mut altered = compressed.proof().clone();
            altered.instance = changed;
            assert!(
                matches!(
                    app.verify_compressed(&altered.carry::<Value>(*pcd.data())),
                    Ok(false)
                ),
                "{id:?}"
            );
            prefix += draws;
        }
        assert_eq!(prefix, baseline_fuse.len());

        // The accumulator and output header bind compression even though
        // they do not change the commitments used to replay Fuse.
        let mut changed = instance.clone();
        changed.c += Fp::ONE;
        assert_eq!(raw_fuse_challenges(&changed), baseline_fuse);
        assert_ne!(first_ipa_challenge(&changed, &header), baseline_ipa);
        let mut altered = compressed.proof().clone();
        altered.instance = changed;
        assert!(matches!(
            app.verify_compressed(&altered.carry::<Value>(*pcd.data())),
            Ok(false)
        ));
        let mut changed_header = header.clone();
        changed_header[0] += Fp::ONE;
        assert_ne!(first_ipa_challenge(instance, &changed_header), baseline_ipa);
        assert!(matches!(
            app.verify_compressed(
                &compressed
                    .proof()
                    .clone()
                    .carry::<Value>(*pcd.data() + Fp::ONE)
            ),
            Ok(false)
        ));
    });
}
