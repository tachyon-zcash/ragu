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
//! Each corruption is also judged through the stripped form, which drops the
//! derived fields: a derived edit vanishes and the proof verifies again,
//! while a primary edit is kept and must still be rejected. Trace
//! coefficients beyond the claims' guaranteed reach are the exception; see
//! [`stripped_verdict`].
//!
//! This entire suite is ignored in the platform matrix and runs in the
//! dedicated Linux PR job with `--test corruption -- --include-ignored`.
//!
//! What is deliberately *not* a fixture is
//! [`dummy_proof`](ragu_pcd::Application::test_dummy_proof): `verify`
//! rejects it outright, so asserting that a corrupted copy is rejected asserts
//! nothing. [`the_dummy_proof_does_not_verify`] pins that, because a fuzz
//! target that starts from it passes vacuously.

mod nontrivial_support;

use std::sync::OnceLock;

use nontrivial_support::{C, HEADER_SIZE, R, app};
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

#[derive(Clone)]
struct Fixture {
    shape: Shape,
    proof: Proof<C, R>,
    data: Fp,
}

impl Fixture {
    /// The verifier's verdict. A corrupted proof must be rejected, not make
    /// the verifier fail, so an error fails the test rather than counting as
    /// a rejection.
    fn verify(self, app: &Application<'_, C, R, HEADER_SIZE>, seed: u64) -> bool {
        let proof = self.proof;
        let rng = StdRng::seed_from_u64(seed);
        match self.shape {
            Shape::Leaf => app.verify(&proof.carry::<LeafNode>(self.data), rng),
            Shape::Deep => app.verify(&proof.carry::<InternalNode>(self.data), rng),
        }
        .expect("verify must not error")
    }

    /// The verdict on the proof stripped to its primary fields, which drops
    /// every derived one.
    fn verify_stripped(self, app: &Application<'_, C, R, HEADER_SIZE>, seed: u64) -> bool {
        let stripped = self.proof.strip();
        let rng = StdRng::seed_from_u64(seed);
        match self.shape {
            Shape::Leaf => app.verify_stripped::<_, LeafNode>(&stripped, &self.data, rng),
            Shape::Deep => app.verify_stripped::<_, InternalNode>(&stripped, &self.data, rng),
        }
        .expect("verify_stripped must not error")
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

/// Each test uses the same application and deterministic honest fixtures.
/// Share the proofs across groups, and only ever corrupt private clones.
fn fixture(app: &Application<'_, C, R, HEADER_SIZE>, shape: Shape) -> &'static Fixture {
    static LEAF: OnceLock<Fixture> = OnceLock::new();
    static DEEP: OnceLock<Fixture> = OnceLock::new();
    let cache = match shape {
        Shape::Leaf => &LEAF,
        Shape::Deep => &DEEP,
    };
    cache.get_or_init(|| {
        let (proof, data) = match shape {
            Shape::Leaf => {
                let mut rng = StdRng::seed_from_u64(0x1eaf);
                nontrivial_support::leaf(app, &mut rng, 42).into_parts()
            }
            Shape::Deep => nontrivial_support::deep(app).into_parts(),
        };
        Fixture { shape, proof, data }
    })
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CorruptionGroup {
    HeadersAndChallenges,
    CommitmentsAndAccumulators,
    NativePolynomials,
    NestedPolynomials,
}

impl CorruptionGroup {
    /// Every vocabulary entry belongs to exactly one independently run group.
    fn of(corruption: &Corruption<C>) -> Self {
        match corruption {
            Corruption::CircuitId(_)
            | Corruption::HeaderElement { .. }
            | Corruption::HeaderLen { .. }
            | Corruption::SwapHeaders
            | Corruption::Challenge(..) => Self::HeadersAndChallenges,
            Corruption::NegateBridgeCommitment(_)
            | Corruption::NegateChallengesPartial
            | Corruption::NegateNativeCommitment(_)
            | Corruption::NegateNestedCommitment(_)
            | Corruption::RescaleNativeAccumulator(_)
            | Corruption::RescaleNestedAccumulator(_) => Self::CommitmentsAndAccumulators,
            Corruption::NativeCoeff { .. }
            | Corruption::RegistryXyCoeff { .. }
            | Corruption::PCoeff { .. } => Self::NativePolynomials,
            Corruption::NestedCoeff { .. }
            | Corruption::NestedAccumulatorCoeff { .. }
            | Corruption::NestedRegistryXyCoeff { .. }
            | Corruption::NestedPCoeff { .. } => Self::NestedPolynomials,
        }
    }
}

/// The verdict the stripped form must reach on a corruption, or `None` where
/// the sweep holds it to none.
///
/// Stripping a proof drops an edit to a derived field, which the expansion
/// then derives honestly, so the proof verifies again; it keeps an edit to
/// a primary field, which must still be rejected. The exception is a trace
/// coefficient at or beyond [`Proof::num_bound_coeffs`]: the working form
/// rejects that edit for its stale commitment alone, the stripped form
/// recomputes the commitment, and whether a claim still reaches the
/// coefficient depends on the circuit's wiring, so those go unasserted.
/// Below the bound every circuit claim's $t_z$ term reaches the coefficient
/// at the verifier's fresh $z$.
fn stripped_verdict(corruption: &Corruption<C>) -> Option<bool> {
    let bound = Proof::<C, R>::num_bound_coeffs();
    match corruption {
        // Derived fields, the `ab` bridge and challenge stage polynomials
        // among them: stripping drops the edit.
        Corruption::Challenge(..)
        | Corruption::NegateBridgeCommitment(_)
        | Corruption::NegateChallengesPartial
        | Corruption::NegateNativeCommitment(_)
        | Corruption::NegateNestedCommitment(_)
        | Corruption::NestedCoeff {
            index: NestedRx::BridgeAB | NestedRx::ChallengeStage,
            ..
        } => Some(true),
        // Trace coefficients: asserted only where a claim is guaranteed to
        // reach them.
        Corruption::NativeCoeff {
            component: RxComponent::Rx(_),
            coeff,
            ..
        }
        | Corruption::NestedCoeff { coeff, .. } => (*coeff < bound).then_some(false),
        // Every other primary field, the accumulator, `registry_xy` and $p$
        // polynomials included, which the verifier evaluates at points it
        // samples or derives.
        _ => Some(false),
    }
}

/// Effective coefficient edits must be classified `MustReject`, and every
/// `MustReject` edit must be rejected, with an honest control in each group.
fn check_corruptions(shape: Shape, group: CorruptionGroup) {
    let app = app();
    let fixture = fixture(&app, shape);
    let vocabulary = vocabulary();

    assert!(
        fixture.clone().verify(&app, 1234),
        "the {shape:?} fixture must verify before anything is corrupted",
    );

    let mut bound = 0usize;
    for corruption in vocabulary
        .iter()
        .filter(|corruption| CorruptionGroup::of(corruption) == group)
    {
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
        let expected_stripped = stripped_verdict(corruption);
        let to_strip = expected_stripped.is_some().then(|| corrupted.clone());
        assert!(
            !corrupted.verify(&app, 1234),
            "the verifier accepted a corrupted {:?} proof: {described}",
            fixture.shape,
        );
        // The same edit judged through the stripped form; see `stripped_verdict`.
        if let (Some(expected), Some(to_strip)) = (expected_stripped, to_strip) {
            assert_eq!(
                to_strip.verify_stripped(&app, 1234),
                expected,
                "the stripped form's verdict on a corrupted {:?} proof is not the expected one: \
                 {described}",
                fixture.shape,
            );
        }
        assert_eq!(
            binding,
            Binding::MustReject,
            "a coefficient edit with a stale commitment was classified Unbound: {described}",
        );
    }

    // Retain the sweep's non-vacuity check in each polynomial group and
    // require the smaller structural groups to exercise a rejection too.
    let minimum = match group {
        CorruptionGroup::NativePolynomials | CorruptionGroup::NestedPolynomials => 20,
        _ => 0,
    };
    assert!(
        bound > minimum,
        "only {bound} corruptions bound the verifier for {shape:?} / {group:?}",
    );
}

/// Zero deltas and out-of-range coefficient edits must leave a valid proof.
fn check_no_op_edits(shape: Shape) {
    let app = app();
    let fixture = fixture(&app, shape);
    assert!(fixture.clone().verify(&app, 1234));

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
            assert!(unchanged.verify(&app, 1234));
        }
    }
}

macro_rules! corruption_tests {
    ($module:ident, $shape:expr) => {
        mod $module {
            use super::*;

            #[test]
            #[ignore = "corruption suite: run by the Linux corruption job"]
            fn headers_and_challenges_reject() {
                check_corruptions($shape, CorruptionGroup::HeadersAndChallenges);
            }

            #[test]
            #[ignore = "corruption suite: run by the Linux corruption job"]
            fn commitments_and_accumulators_reject() {
                check_corruptions($shape, CorruptionGroup::CommitmentsAndAccumulators);
            }

            #[test]
            #[ignore = "corruption suite: run by the Linux corruption job"]
            fn native_polynomials_reject() {
                check_corruptions($shape, CorruptionGroup::NativePolynomials);
            }

            #[test]
            #[ignore = "corruption suite: run by the Linux corruption job"]
            fn nested_polynomials_reject() {
                check_corruptions($shape, CorruptionGroup::NestedPolynomials);
            }

            #[test]
            #[ignore = "corruption suite: run by the Linux corruption job"]
            fn no_op_edits_verify() {
                check_no_op_edits($shape);
            }
        }
    };
}

corruption_tests!(leaf, Shape::Leaf);
corruption_tests!(deep, Shape::Deep);

/// The synthesized dummy the Bootstrap base case consumes is not a proof
/// `verify` accepts — in the empty application or any other.
///
/// A corruption harness that starts from it proves nothing: the rejection it
/// asserts holds before the corruption. `qa/fuzz`'s proof-level targets build
/// their fixtures with `seed` and `fuse` and check each one verifies for
/// exactly this reason.
#[test]
#[ignore = "corruption suite: run by the Linux corruption job"]
fn the_dummy_proof_does_not_verify() {
    for verifier in [empty_app(), app()] {
        let proof = verifier.test_dummy_proof();
        assert!(
            !verifier
                .verify(&proof.carry::<()>(()), StdRng::seed_from_u64(1234))
                .expect("verify must not error"),
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
#[ignore = "corruption suite: run by the Linux corruption job"]
fn coordinated_corruptions_reject_and_cancelling_ones_do_not() {
    let app = app();
    let fixture = fixture(&app, Shape::Deep);

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
        !both.verify(&app, 99),
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
        cancelled.verify(&app, 99),
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
