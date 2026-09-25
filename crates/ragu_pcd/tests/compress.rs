//! The compressed proof against the decider: what the decider accepts
//! compresses into a proof the compressed verifier accepts, what the decider
//! rejects for the instance's sake compresses into one it rejects, and a
//! tampered message or the wrong data is rejected.

use alloc::vec;

use ragu_arithmetic::{
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::{
    polynomials::{ProductionRank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Fq, Pasta};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};

use super::{CompressedPcd, CompressedProof};
use crate::{
    Application, ApplicationBuilder, Pcd, Proof,
    compress::revdot::nested_position,
    header::{Header, Suffix},
    internal::nested,
    step::{Encoded, Index, Step},
};

type TestR = ProductionRank;
const HEADER_SIZE: usize = 4;
type App = Application<'static, Pasta, TestR, HEADER_SIZE>;

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
            witness,
            D::unit(),
        ))
    }
}

fn app() -> App {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .register(Seed)
        .expect("register seed step")
        .finalize(Pasta::baked())
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
    let edited = |edit: fn(&mut Proof<Pasta, TestR>)| {
        let (mut proof, data) = seeded.clone().into_parts();
        edit(&mut proof);
        proof.carry::<Value>(data)
    };
    let corruptions: [(&str, fn(&mut Proof<Pasta, TestR>)); 5] = [
        ("circuit id out of the domain", |p| {
            p.circuit_id = CircuitIndex::new(u32::MAX as usize)
        }),
        ("left header too long", |p| p.left_header.push(Fp::ZERO)),
        ("right header too short", |p| {
            p.right_header.pop();
        }),
        ("left header element", |p| p.left_header[0] += Fp::ONE),
        ("polynomial with a stale commitment", |p| {
            p.native_a_poly
                .add_assign(&sparse::Polynomial::from_coeffs(vec![Fp::ONE]))
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
fn stored_challenges_are_not_part_of_the_instance() {
    // The decider holds a proof's stored challenges to its transcript. The
    // instance carries no challenges: the compressed verifier rederives
    // them from the bridge commitments, so a proof whose stored challenge
    // disagrees with its transcript compresses into a proof of the honest
    // instance.
    let app = app();
    let (mut proof, ()) = app.bootstrap_pcd().into_parts();
    proof.mu += Fp::ONE;
    let pcd = proof.carry::<()>(());
    assert!(!decides(&app, &pcd, 2));
    assert!(accepts(&app, &compress(&app, &pcd, 3)));
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
        p.instance.native[3] = p.instance.native[4]
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
        p.instance.circuit_id = CircuitIndex::new(u32::MAX as usize)
    });
    tamper("missing commitment", &|p| {
        p.instance.native.pop();
    });

    // The reduction.
    tamper("p commitment", &|p| {
        p.native.reduction.p = p.native.reduction.q
    });
    tamper("nested q commitment", &|p| {
        p.nested.reduction.q = p.nested.reduction.p
    });
    tamper("an opening at r", &|p| {
        p.native.reduction.openings[0].at_r += Fp::ONE
    });
    tamper("a nested opening at rz", &|p| {
        p.nested.reduction.openings[2].at_rz += Fq::ONE
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
    tamper("nested blinding factor", &|p| p.nested.opening.f += Fq::ONE);
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
