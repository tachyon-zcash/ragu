//! The verifier-corruption vocabulary, swept against real proofs.
//!
//! `qa/fuzz`'s `fuzz_verify_reject`, `fuzz_verify_reject_full` and
//! `fuzz_pcd_lifecycle` all rest on one contract: when
//! [`Proof::corrupt`](ragu_pcd::Proof::corrupt) reports
//! [`Binding::MustReject`], `verify` must not accept. A wrong classification
//! can either skip a required rejection check or report a false positive.
//!
//! So the contract is pinned here instead, over the whole vocabulary and over
//! proofs of two shapes: a `WitnessLeaf` seed, and a `Merge2` fuse of two
//! `Hash2` nodes, whose accumulators and headers are the nondegenerate ones.
//!
//! What is deliberately *not* a fixture is
//! [`dummy_proof`](ragu_pcd::Application::test_dummy_proof): `verify`
//! rejects it outright, so asserting that a corrupted copy is rejected asserts
//! nothing. [`the_dummy_proof_does_not_verify`] pins that, because a fuzz
//! target that starts from it passes vacuously.

mod nontrivial_support;

use nontrivial_support::{C, HEADER_SIZE, R, app};
use ragu_core::Result;
use ragu_pasta::{Fp, Fq, Pasta};
use ragu_pcd::{
    Application, ApplicationBuilder, Proof,
    fuzzing::corrupt::{
        Binding, BridgeCommitment, Challenge, Corruption, NativeCommitment, NativeRx,
        NestedAccumulator, NestedCommitment, NestedRx, RxComponent, Side,
    },
};
use ragu_testing::pcd::nontrivial::{InternalNode, LeafNode};
use rand::{SeedableRng, rngs::StdRng};

/// Which header a fixture's proof carries, so it can be verified again after
/// corruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Leaf,
    Deep,
}

struct Fixture {
    shape: Shape,
    proof: Proof<C, R>,
    data: Fp,
}

impl Fixture {
    fn verify(&self, app: &Application<'_, C, R, HEADER_SIZE>, seed: u64) -> Result<bool> {
        let proof = self.proof.clone();
        let rng = StdRng::seed_from_u64(seed);
        match self.shape {
            Shape::Leaf => app.verify(&proof.carry::<LeafNode>(self.data), rng),
            Shape::Deep => app.verify(&proof.carry::<InternalNode>(self.data), rng),
        }
    }
}

/// The application the dummy fixture belongs to: no registered steps, so
/// circuit id zero — which every dummy proof carries — names no application
/// circuit.
fn empty_app() -> Application<'static, C, R, HEADER_SIZE> {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .finalize(Pasta::baked())
        .expect("the empty application must build")
}

/// A leaf and a fuse of two fuses, in the application that registers the
/// steps they use.
fn fixtures(app: &Application<'_, C, R, HEADER_SIZE>) -> Vec<Fixture> {
    let mut rng = StdRng::seed_from_u64(0x1eaf);
    let (leaf_proof, leaf_data) = nontrivial_support::leaf(app, &mut rng, 42).into_parts();
    let (deep_proof, deep_data) = nontrivial_support::deep(app).into_parts();

    vec![
        Fixture {
            shape: Shape::Leaf,
            proof: leaf_proof,
            data: leaf_data,
        },
        Fixture {
            shape: Shape::Deep,
            proof: deep_proof,
            data: deep_data,
        },
    ]
}

/// Every corruption the vocabulary can express, at the coefficient indices
/// that matter: zero, both sides of the circuit claim's `t_z` boundary, and
/// the last coefficient. Every nonzero coefficient edit leaves a stale
/// commitment, including those outside the `t_z` region.
fn vocabulary() -> Vec<Corruption<C>> {
    let n = Proof::<C, R>::num_bound_coeffs();
    let total = Proof::<C, R>::num_coeffs();
    let coeffs = [0, n - 1, n, total - 1];
    let delta = Fp::from(7u64);
    let nested_delta = Fq::from(7u64);

    let mut out = vec![
        // Out of the registry's domain, and in it but not the honest id.
        Corruption::CircuitId(u32::MAX),
        Corruption::CircuitId(1),
        Corruption::SwapHeaders,
    ];

    for side in [Side::Left, Side::Right] {
        for index in 0..HEADER_SIZE {
            out.push(Corruption::HeaderElement { side, index, delta });
        }
        // Shorter, longer, and past any plausible header.
        for len in [0, HEADER_SIZE - 1, HEADER_SIZE + 1, 64] {
            out.push(Corruption::HeaderLen { side, len });
        }
    }

    for which in Challenge::ALL {
        // A value no honest proof carries in that slot: the dummy fixture's
        // challenges are one, and a real proof's are the transcript's.
        out.push(Corruption::Challenge(which, Fp::from(0xc0ffee_u64)));
    }

    for which in BridgeCommitment::ALL {
        out.push(Corruption::NegateBridgeCommitment(which));
    }
    out.push(Corruption::NegateChallengesPartial);

    for which in NativeCommitment::ALL {
        out.push(Corruption::NegateNativeCommitment(which));
    }
    for which in NestedCommitment::ALL {
        out.push(Corruption::NegateNestedCommitment(which));
    }
    out.push(Corruption::RescaleNativeAccumulator(Fp::from(5u64)));
    out.push(Corruption::RescaleNestedAccumulator(Fq::from(5u64)));

    let mut components = vec![RxComponent::AbA, RxComponent::AbB];
    components.extend(NativeRx::ALL.map(RxComponent::Rx));
    for component in components {
        for coeff in coeffs {
            out.push(Corruption::NativeCoeff {
                component,
                coeff,
                delta,
            });
        }
    }

    for coeff in coeffs {
        out.push(Corruption::RegistryXyCoeff { coeff, delta });
        out.push(Corruption::PCoeff { coeff, delta });
    }

    for index in NestedRx::ALL {
        for coeff in coeffs {
            out.push(Corruption::NestedCoeff {
                index,
                coeff,
                delta: nested_delta,
            });
        }
    }

    for which in NestedAccumulator::ALL {
        for coeff in coeffs {
            out.push(Corruption::NestedAccumulatorCoeff {
                which,
                coeff,
                delta: nested_delta,
            });
        }
    }

    for coeff in coeffs {
        out.push(Corruption::NestedRegistryXyCoeff {
            coeff,
            delta: nested_delta,
        });
        out.push(Corruption::NestedPCoeff {
            coeff,
            delta: nested_delta,
        });
    }

    out
}

/// Honest proofs and no-op edits verify. Effective coefficient edits must be
/// classified `MustReject`, and every `MustReject` edit must be rejected.
#[test]
fn corruptions_that_bind_the_verifier_are_rejected() {
    let app = app();
    let cases = fixtures(&app);
    let vocabulary = vocabulary();

    let mut bound = 0usize;
    for fixture in &cases {
        assert!(
            matches!(fixture.verify(&app, 1234), Ok(true)),
            "the {:?} fixture must verify before anything is corrupted",
            fixture.shape,
        );

        for corruption in &vocabulary {
            let mut corrupted = Fixture {
                shape: fixture.shape,
                proof: fixture.proof.clone(),
                data: fixture.data,
            };
            let described = format!("{corruption:?}");
            let binding = corrupted.proof.corrupt(clone_corruption(corruption));
            // These coefficient edits all have nonzero deltas and in-range
            // indices. Require rejection even if the classifier says they
            // are unbound, then check the classification itself.
            let coefficient_edit = matches!(
                corruption,
                Corruption::NativeCoeff { .. }
                    | Corruption::RegistryXyCoeff { .. }
                    | Corruption::PCoeff { .. }
                    | Corruption::NestedCoeff { .. }
                    | Corruption::NestedAccumulatorCoeff { .. }
                    | Corruption::NestedRegistryXyCoeff { .. }
                    | Corruption::NestedPCoeff { .. }
            );
            if !coefficient_edit && binding != Binding::MustReject {
                continue;
            }
            bound += 1;
            assert!(
                !matches!(corrupted.verify(&app, 1234), Ok(true)),
                "the verifier accepted a corrupted {:?} proof: {described}",
                fixture.shape,
            );
            assert_eq!(
                binding,
                Binding::MustReject,
                "a coefficient edit with a stale commitment was classified Unbound: {described}",
            );
        }

        for (coeff, delta) in [(0, 0u64), (Proof::<C, R>::num_coeffs(), 7), (usize::MAX, 7)] {
            for corruption in [
                Corruption::NativeCoeff {
                    component: RxComponent::Rx(NativeRx::Application),
                    coeff,
                    delta: Fp::from(delta),
                },
                Corruption::NestedCoeff {
                    index: NestedRx::BridgeEval,
                    coeff,
                    delta: Fq::from(delta),
                },
            ] {
                let mut unchanged = Fixture {
                    shape: fixture.shape,
                    proof: fixture.proof.clone(),
                    data: fixture.data,
                };
                assert_eq!(unchanged.proof.corrupt(corruption), Binding::Unbound);
                assert!(matches!(unchanged.verify(&app, 1234), Ok(true)));
            }
        }
    }

    // A sweep that classified nothing would pass vacuously.
    assert!(
        bound > cases.len() * 20,
        "only {bound} corruptions bound the verifier across {} fixtures — the sweep is \
         near-vacuous and proves little",
        cases.len(),
    );
}

/// The synthesized dummy the Bootstrap base case consumes is not a proof
/// `verify` accepts — in the empty application or any other.
///
/// A corruption harness that starts from it proves nothing: the rejection it
/// asserts holds before the corruption. `qa/fuzz`'s proof-level targets build
/// their fixtures with `seed` and `fuse` and check each one verifies for
/// exactly this reason.
#[test]
fn the_dummy_proof_does_not_verify() {
    for verifier in [empty_app(), app()] {
        let proof = verifier.test_dummy_proof();
        assert!(
            !matches!(
                verifier.verify(&proof.carry::<()>(()), StdRng::seed_from_u64(1234)),
                Ok(true)
            ),
            "the dummy proof verified — corrupting it would then be a meaningful test, \
             and the fuzz targets should be pointed back at it",
        );
    }
}

/// Two corruptions at once still reject, and the deduplication the fuzz
/// harnesses rely on is what keeps them from cancelling: applying the same
/// header edit twice with opposite deltas restores the honest proof, which
/// the verifier is then right to accept.
#[test]
fn coordinated_corruptions_reject_and_cancelling_ones_do_not() {
    let app = app();
    let fixture = fixtures(&app)
        .into_iter()
        .find(|f| f.shape == Shape::Deep)
        .expect("the deep fixture must be built");

    let mut both = Fixture {
        shape: fixture.shape,
        proof: fixture.proof.clone(),
        data: fixture.data,
    };
    let first = both.proof.corrupt(Corruption::HeaderElement {
        side: Side::Left,
        index: 0,
        delta: Fp::from(3u64),
    });
    let second = both
        .proof
        .corrupt(Corruption::Challenge(Challenge::Mu, Fp::from(0xbadu64)));
    assert_eq!(first, Binding::MustReject);
    assert_eq!(second, Binding::MustReject);
    assert!(
        !matches!(both.verify(&app, 99), Ok(true)),
        "the verifier accepted a proof with two independent corruptions",
    );

    let mut cancelled = Fixture {
        shape: fixture.shape,
        proof: fixture.proof.clone(),
        data: fixture.data,
    };
    cancelled.proof.corrupt(Corruption::HeaderElement {
        side: Side::Left,
        index: 0,
        delta: Fp::from(3u64),
    });
    cancelled.proof.corrupt(Corruption::HeaderElement {
        side: Side::Left,
        index: 0,
        delta: -Fp::from(3u64),
    });
    assert!(
        matches!(cancelled.verify(&app, 99), Ok(true)),
        "two cancelling edits leave an honest proof, which must still verify — this is \
         why the fuzz harnesses deduplicate corruptions by target",
    );
}

/// `Corruption` is not `Clone` (its payloads are curve points and field
/// elements from the cycle), so the sweep rebuilds each one it re-applies.
fn clone_corruption(corruption: &Corruption<C>) -> Corruption<C> {
    match *corruption {
        Corruption::CircuitId(id) => Corruption::CircuitId(id),
        Corruption::HeaderElement { side, index, delta } => {
            Corruption::HeaderElement { side, index, delta }
        }
        Corruption::HeaderLen { side, len } => Corruption::HeaderLen { side, len },
        Corruption::SwapHeaders => Corruption::SwapHeaders,
        Corruption::Challenge(which, value) => Corruption::Challenge(which, value),
        Corruption::NegateBridgeCommitment(which) => Corruption::NegateBridgeCommitment(which),
        Corruption::NegateChallengesPartial => Corruption::NegateChallengesPartial,
        Corruption::NegateNativeCommitment(which) => Corruption::NegateNativeCommitment(which),
        Corruption::NegateNestedCommitment(which) => Corruption::NegateNestedCommitment(which),
        Corruption::RescaleNativeAccumulator(scale) => Corruption::RescaleNativeAccumulator(scale),
        Corruption::RescaleNestedAccumulator(scale) => Corruption::RescaleNestedAccumulator(scale),
        Corruption::NativeCoeff {
            component,
            coeff,
            delta,
        } => Corruption::NativeCoeff {
            component,
            coeff,
            delta,
        },
        Corruption::RegistryXyCoeff { coeff, delta } => {
            Corruption::RegistryXyCoeff { coeff, delta }
        }
        Corruption::PCoeff { coeff, delta } => Corruption::PCoeff { coeff, delta },
        Corruption::NestedCoeff {
            index,
            coeff,
            delta,
        } => Corruption::NestedCoeff {
            index,
            coeff,
            delta,
        },
        Corruption::NestedAccumulatorCoeff {
            which,
            coeff,
            delta,
        } => Corruption::NestedAccumulatorCoeff {
            which,
            coeff,
            delta,
        },
        Corruption::NestedRegistryXyCoeff { coeff, delta } => {
            Corruption::NestedRegistryXyCoeff { coeff, delta }
        }
        Corruption::NestedPCoeff { coeff, delta } => Corruption::NestedPCoeff { coeff, delta },
    }
}
