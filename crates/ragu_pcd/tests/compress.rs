//! The compressed proof against the decider: what the decider accepts
//! compresses into a proof the compressed verifier accepts, what the decider
//! rejects for the instance's sake compresses into one it rejects, and a
//! tampered message or the wrong data is rejected.

use alloc::vec;

use ragu_circuits::{
    polynomials::{ProductionRank, sparse},
    registry::CircuitIndex,
    staging::{StageReader, stage_wire_indices, wires_of},
};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{CompressedPcd, CompressedProof};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    compress::revdot::{native_position, nested_position},
    header::{Header, Suffix},
    internal::{native, nested},
    proof::recursive_propagation_tests::support::{self, Cache},
    step::{Encoded, Index, Step},
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;
type App = Application<'static, Pasta, TestR, HEADER_SIZE>;
type NativeEval = native::stages::eval::Stage<Pasta, TestR, HEADER_SIZE>;

/// A header carrying one field element.
struct Value;

impl Header<Fp> for Value {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// A seed step outputting its witness as a [`Value`] header.
struct Seed;

impl Step<Pasta> for Seed {
    const INDEX: Index = Index::new(0);
    type Shared = ();
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        (),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        Ok((
            (
                Encoded::new(dr, allocator, left)?,
                Encoded::new(dr, allocator, right)?,
                Encoded::new(dr, allocator, witness.clone())?,
            ),
            (),
            witness,
            D::unit(),
        ))
    }
}

fn app() -> App {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .register(Seed)
        .expect("register seed step")
        .finalize(crate::pasta::baked())
        .expect("failed to create test application")
}

fn decides<H: Header<Fp>>(app: &App, pcd: &Pcd<Pasta, TestR, H>, seed: u64) -> bool {
    app.verify(pcd, StdRng::seed_from_u64(seed))
        .expect("verify should not error")
}

fn compress<H: Header<Fp>>(
    app: &App,
    pcd: &Pcd<Pasta, TestR, H>,
    seed: u64,
) -> CompressedPcd<Pasta, H> {
    app.compress(pcd, &mut StdRng::seed_from_u64(seed))
        .expect("compress should not error")
}

fn accepts<H: Header<Fp>>(app: &App, pcd: &CompressedPcd<Pasta, H>) -> bool {
    app.verify_compressed(pcd)
        .expect("verify_compressed should not error")
}

#[test]
fn accepts_what_the_decider_accepts() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(1);
    let bootstrap = app.bootstrap_pcd();
    let rerandomized = app
        .rerandomize(app.bootstrap_pcd(), &mut rng)
        .expect("rerandomize");
    for (pcd, case) in [(bootstrap, "bootstrap"), (rerandomized, "rerandomized")] {
        assert!(decides(&app, &pcd, 2), "{case}: the decider accepts");
        assert!(
            accepts(&app, &compress(&app, &pcd, 3)),
            "{case}: the compressed verifier accepts"
        );
    }

    // A proof over data, and the compressed proof attests that data.
    let (seeded, ()) = app.seed(&mut rng, Seed, Fp::from(7)).expect("seed");
    assert!(decides(&app, &seeded, 4));
    let compressed = compress(&app, &seeded, 5);
    assert_eq!(*compressed.data(), Fp::from(7));
    assert!(accepts(&app, &compressed));
    let (proof, _) = compressed.into_parts();
    assert!(!accepts(&app, &proof.carry::<Value>(Fp::from(8))));
}

#[test]
fn rejects_what_the_decider_rejects() {
    let app = app();
    let (seeded, ()) = app
        .seed(&mut StdRng::seed_from_u64(1), Seed, Fp::from(7))
        .expect("seed");
    let edited = |edit: fn(&App, &mut Proof<Pasta, TestR>)| {
        let (mut proof, data) = seeded.clone().into_parts();
        edit(&app, &mut proof);
        proof.carry::<Value>(data)
    };
    let corruptions: [(&str, fn(&App, &mut Proof<Pasta, TestR>)); 6] = [
        ("circuit id out of the domain", |_, p| {
            p.circuit_ids[0] = CircuitIndex::new(u32::MAX as usize)
        }),
        ("left header too long", |_, p| p.left_header.push(Fp::ZERO)),
        ("right header too short", |_, p| {
            p.right_header.pop();
        }),
        ("left header element", |_, p| p.left_header[0] += Fp::ONE),
        ("polynomial with a stale commitment", |_, p| {
            p.native_a_poly
                .add_assign(&sparse::Polynomial::from_coeffs(vec![Fp::ONE]))
        }),
        // The eval stage's m(w, u, y) wire, which the instance does not
        // carry, with the stage recommitted: every commitment stays
        // consistent with its polynomial, so every opening holds and the
        // claims reject the proof instead, through the eval stage's wire
        // binding and through the export claim over the stale copy of the
        // eval commitment that the bridge still holds.
        ("stage wire with a refreshed commitment", |app, p| {
            let wire = stage_wire_indices::<Fp, TestR, NativeEval>(|out| {
                wires_of(&out.evaluations.registry_wy)
            })
            .expect("the eval stage lays out")[0];
            let held = StageReader::<Fp, TestR>::new(&p.native_eval_rx).read(wire);
            support::set_wires(&mut p.native_eval_rx, &[wire], &[held + Fp::ONE]);
            support::recommit(app, p, Cache::NativeEval);
        }),
    ];
    for (case, edit) in corruptions {
        let pcd = edited(edit);
        assert!(!decides(&app, &pcd, 2), "{case}: the decider rejects");
        assert!(
            !accepts(&app, &compress(&app, &pcd, 3)),
            "{case}: the compressed verifier rejects"
        );
    }
}

#[test]
fn accepts_a_stale_stored_challenge_the_decider_rejects() {
    // Intended: the decider holds a proof's stored challenges to its
    // transcript, but the stored challenges are not part of the statement.
    // The instance carries none, and the compressed verifier rederives them
    // from the bridge commitments, so a proof whose polynomials were built
    // under the transcript's challenges compresses into a proof of the
    // honest instance. The compressor itself reads the stored `w`, `x`, `y`
    // and `u` for the wire bindings, the openings and $v$, so this holds for
    // a stored challenge it does not consume; a stale one of those four
    // compresses into a proof the verifier rejects instead.
    let app = app();
    let (mut proof, ()) = app.bootstrap_pcd().into_parts();
    proof.mu += Fp::ONE;
    let pcd = proof.carry::<()>(());
    assert!(!decides(&app, &pcd, 2));
    assert!(accepts(&app, &compress(&app, &pcd, 3)));
}

#[test]
fn rejects_malformed_messages_without_error() {
    let app = app();
    let compressed = compress(&app, &app.bootstrap_pcd(), 462);
    assert!(accepts(&app, &compressed));
    let (proof, ()) = compressed.into_parts();
    let corruptions: &[(&str, fn(&mut CompressedProof<Pasta>))] = &[
        ("native IPA identity S", |p| {
            p.native.opening.s_commitment = Default::default()
        }),
        ("nested IPA identity S", |p| {
            p.nested.opening.s_commitment = Default::default()
        }),
        ("zero nested IPA coefficient", |p| {
            p.nested.opening.c = Fq::ZERO
        }),
        ("zero nested instance c", |p| p.instance.nested_c = Fq::ZERO),
        ("native reduction identity p", |p| {
            p.native.reduction.p = Default::default()
        }),
        ("identity fuse bridge", |p| {
            let bridge = nested_position(nested::RxComponent::Rx(nested::RxIndex::BridgePreamble));
            p.instance.nested[bridge] = Default::default();
        }),
        ("identity native accumulator", |p| {
            p.instance.native[native_position(native::RxComponent::AbA)] = Default::default()
        }),
        ("identity native registry restriction", |p| {
            p.instance.native_registry_xy = Default::default()
        }),
        ("identity nested accumulator", |p| {
            p.instance.nested[nested_position(nested::RxComponent::AbA)] = Default::default()
        }),
        ("nested reduction identity p", |p| {
            p.nested.reduction.p = Default::default()
        }),
        ("native batch identity quotient", |p| {
            p.native.batch.f = Default::default()
        }),
        ("nested batch identity quotient", |p| {
            p.nested.batch.f = Default::default()
        }),
        ("native IPA identity L", |p| {
            p.native.opening.rounds[0].0 = Default::default()
        }),
        ("nested IPA identity R", |p| {
            p.nested.opening.rounds[0].1 = Default::default()
        }),
        ("zero nested reduction opening", |p| {
            p.nested.reduction.openings[0] = Fq::ZERO
        }),
        ("native fold identity E", |p| {
            p.native.reduction.fold.inner = Default::default()
        }),
        ("zero nested batched value", |p| {
            p.nested.batch.evaluations[0] = Fq::ZERO
        }),
    ];
    for &(case, edit) in corruptions {
        let mut tampered = proof.clone();
        edit(&mut tampered);
        let result = app.verify_compressed(&tampered.carry::<()>(()));
        assert!(matches!(result, Ok(false)), "{case}: {result:?}");
    }
}

#[test]
fn propagates_header_encoding_errors() {
    struct FailingHeader<const LEGACY_ERROR: bool>;

    impl<const LEGACY_ERROR: bool> Header<Fp> for FailingHeader<LEGACY_ERROR> {
        const SUFFIX: Suffix = Suffix::new(1);
        type Data = ();
        type Output = ();

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            _: &mut D,
            _: &mut A,
            _: DriverValue<D, ()>,
        ) -> Result<()> {
            Err(if LEGACY_ERROR {
                Error::InvalidWitness("header encoding failed".into())
            } else {
                Error::Initialization("header encoding failed".into())
            })
        }
    }

    let app = app();
    let (proof, ()) = compress(&app, &app.bootstrap_pcd(), 1).into_parts();
    assert!(matches!(
        app.verify_compressed(&proof.clone().carry::<FailingHeader<true>>(())),
        Err(Error::InvalidWitness(_))
    ));
    assert!(matches!(
        app.verify_compressed(&proof.carry::<FailingHeader<false>>(())),
        Err(Error::Initialization(_))
    ));
}

#[test]
fn rejects_tampered_messages() {
    let app = app();
    let (proof, ()) = compress(&app, &app.bootstrap_pcd(), 1).into_parts();
    let tamper = |case: &str, edit: &dyn Fn(&mut CompressedProof<Pasta>)| {
        let mut tampered = proof.clone();
        edit(&mut tampered);
        assert!(!accepts(&app, &tampered.carry::<()>(())), "{case}");
    };

    // The instance.
    tamper("accumulator value", &|p| p.instance.c += Fp::ONE);
    tamper("batch value", &|p| p.instance.v += Fp::ONE);
    tamper("nested accumulator value", &|p| {
        p.instance.nested_c += Fq::ONE
    });
    tamper("nested batch value", &|p| p.instance.nested_v += Fq::ONE);
    tamper("eval stage wire", &|p| p.instance.a_at_u += Fp::ONE);
    tamper("nested eval stage wire", &|p| {
        p.instance.nested_b_at_u += Fq::ONE
    });
    tamper("preamble stage wire", &|p| p.instance.left.x += Fp::ONE);
    tamper("nested preamble stage wire", &|p| {
        p.instance.nested_right.y += Fq::ONE
    });
    tamper("bridge blinding", &|p| p.instance.bridge_alpha += Fq::ONE);
    tamper("native commitment", &|p| {
        let hashes_1 = native_position(native::RxComponent::Rx(native::RxIndex::Hashes1));
        let hashes_2 = native_position(native::RxComponent::Rx(native::RxIndex::Hashes2));
        p.instance.native[hashes_1] = p.instance.native[hashes_2]
    });
    tamper("nested commitment", &|p| {
        p.instance.nested[0] = p.instance.nested[1]
    });
    tamper("registry restriction commitment", &|p| {
        p.instance.native_registry_xy = p.instance.native_p
    });
    tamper("nested batch commitment", &|p| {
        p.instance.nested_p = p.instance.nested_registry_xy
    });
    tamper("challenge stage commitment", &|p| {
        p.instance.nested_challenges_partial = -p.instance.nested_challenges_partial
    });
    tamper("bridge commitment", &|p| {
        let bridge = nested_position(nested::RxComponent::Rx(nested::RxIndex::BridgeAB));
        p.instance.nested[bridge] = -p.instance.nested[bridge];
    });
    tamper("header element", &|p| p.instance.right_header[0] += Fp::ONE);
    tamper("header length", &|p| p.instance.left_header.push(Fp::ZERO));
    tamper("circuit id", &|p| {
        p.instance.circuit_ids[0] = CircuitIndex::new(u32::MAX as usize)
    });
    tamper("missing commitment", &|p| {
        p.instance.native.pop();
    });

    // The reduction.
    tamper("error commitment", &|p| {
        p.native.reduction.fold.inner = p.native.reduction.fold.outer
    });
    tamper("nested error commitment", &|p| {
        p.nested.reduction.fold.outer = p.nested.reduction.fold.inner
    });
    tamper("weighted error terms", &|p| {
        p.native.reduction.fold.inner_epsilon += Fp::ONE
    });
    tamper("nested weighted error terms", &|p| {
        p.nested.reduction.fold.outer_epsilon += Fq::ONE
    });
    tamper("p commitment", &|p| {
        p.native.reduction.p = p.native.reduction.q
    });
    tamper("nested q commitment", &|p| {
        p.nested.reduction.q = p.nested.reduction.p
    });
    tamper("an opening at r", &|p| {
        p.native.reduction.openings[0] += Fp::ONE
    });
    tamper("a nested opening at rz", &|p| {
        p.nested.reduction.openings[1] += Fq::ONE
    });
    tamper("p at 1/r", &|p| {
        p.native.reduction.p_at_inverse_r += Fp::ONE
    });
    tamper("nested q at r", &|p| p.nested.reduction.q_at_r += Fq::ONE);
    tamper("missing opening", &|p| {
        p.native.reduction.openings.pop();
    });

    // The batch.
    tamper("quotient commitment", &|p| {
        p.native.batch.f = p.native.reduction.p
    });
    tamper("a nested batched value", &|p| {
        p.nested.batch.evaluations[1] += Fq::ONE
    });
    tamper("missing batched value", &|p| {
        p.native.batch.evaluations.pop();
    });

    // The IPA.
    tamper("final coefficient", &|p| p.native.opening.c += Fp::ONE);
    tamper("nested final coefficient", &|p| {
        p.nested.opening.c += Fq::ONE
    });
    tamper("a round", &|p| {
        let (l, r) = p.native.opening.rounds[0];
        p.native.opening.rounds[0] = (r, l);
    });
    tamper("missing nested round", &|p| {
        p.nested.opening.rounds.pop();
    });
    tamper("blinding commitment", &|p| {
        p.native.opening.s_commitment = p.native.opening.rounds[0].0
    });
}
