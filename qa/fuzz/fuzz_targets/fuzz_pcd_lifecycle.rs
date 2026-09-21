//! The end-to-end PCD lifecycle, from a randomly shaped tree to a verdict.
//!
//! Every other proof-level target starts from a fixture somebody else built.
//! This one runs the whole lifecycle per input: pick which steps the
//! application registers, pick a tree shape those steps admit, seed its
//! leaves from fuzzer-chosen witnesses, fuse it together, verify every proof
//! along the way, optionally rerandomize the root — and then corrupt the root
//! and check the applicable corruption verdicts.
//!
//! # What varies
//!
//! * **The registry.** [`Step::INDEX`] forces registration order, so an
//!   application registers a prefix of `WitnessLeaf`, `Hash2`, `Merge2`. Which
//!   prefix decides both the wiring polynomial the application circuit is
//!   checked against and which trees are buildable at all. The three
//!   applications are built once, in `init`; `finalize` registers every
//!   internal circuit and is far too slow to repeat per input.
//! * **The shape.** A leaf; a fuse of two leaves; a fuse of two such nodes; or
//!   an asymmetric fuse of one of those with a plain node. The shapes are
//!   enumerated rather than grown from a recursive grammar because the header
//!   types admit only these: `Hash2` takes two `LeafNode`s, `Merge2` two
//!   `InternalNode`s.
//! * **The witnesses**, one per leaf, and the RNG seed every proof is built
//!   with — which drives all of the blinding.
//!
//! # Invariants
//!
//! * Seeding and fusing an honest tree never fails.
//! * Every honest proof verifies, at every level, and still verifies after
//!   rerandomization.
//! * Individually classified corruptions reject; no-op controls accept.
//!   Combined edits are exercised without assuming rejection verdicts compose.
//!
//! An iteration here costs seconds, not microseconds: it is a randomized
//! integration test that libFuzzer steers, and the corpus it accumulates is
//! a set of tree shapes rather than a set of byte strings.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_pcd::{Application, Pcd};
use ragu_testing::pcd::nontrivial::{InternalNode, LeafNode};
use ragu_testing_fuzz::pcd::{self, C, Fixture, HEADER_SIZE, NativeField, R, Shape, SyncApp};
use rand::{SeedableRng, rngs::StdRng};

/// At most this many corruptions per input; see `fuzz_verify_reject`.
const MAX_CORRUPTIONS: usize = 4;

/// The three applications, indexed by how many steps they register.
static APPS: LazyLock<[SyncApp; 3]> = LazyLock::new(|| {
    [
        pcd::nontrivial_app(1),
        pcd::nontrivial_app(2),
        pcd::nontrivial_app(3),
    ]
});

/// The tree shapes the registered steps admit, in increasing cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Plan {
    /// One `WitnessLeaf` seed.
    Leaf,
    /// `Hash2` over two leaves: one fuse, two seeds.
    Node,
    /// `Merge2` over two nodes: three fuses, four seeds.
    Deep,
    /// `Merge2` over a `Deep` and a `Node`: an unbalanced tree whose two
    /// children carry accumulators of different depth. Five fuses, six seeds.
    Lopsided,
}

impl Plan {
    /// The plans buildable with the first `steps` of the step set.
    fn available(steps: usize) -> &'static [Plan] {
        match steps {
            1 => &[Plan::Leaf],
            2 => &[Plan::Leaf, Plan::Node],
            _ => &[Plan::Leaf, Plan::Node, Plan::Deep, Plan::Lopsided],
        }
    }
}

/// Draws witnesses for the leaves, cycling the fuzzer's list (and falling
/// back to the leaf's ordinal when it gave none) so a plan always has as many
/// as it needs.
struct Witnesses<'a> {
    values: &'a [u64],
    next: usize,
}

impl Witnesses<'_> {
    fn draw(&mut self) -> NativeField {
        let i = self.next;
        self.next += 1;
        let raw = if self.values.is_empty() {
            i as u64
        } else {
            self.values[i % self.values.len()]
        };
        NativeField::from(raw)
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// How many steps the application registers, resolved into `1..=3`.
    steps: u8,
    /// Which of the available plans to build, modulo their count.
    plan: u8,
    /// The leaf witnesses, cycled to cover the plan's leaves.
    witnesses: Vec<u64>,
    /// Rerandomize the root before verifying it again.
    rerandomize: bool,
    /// The corruptions to apply to the finished root.
    corruptions: Vec<pcd::FuzzCorruption>,
    /// Seeds every proof's blinding, and the verifier's challenges.
    rng_seed: u64,
}

type App = Application<'static, C, R, HEADER_SIZE>;

/// Seeds one leaf and checks it verifies.
fn seed_leaf(
    app: &App,
    rng: &mut StdRng,
    witnesses: &mut Witnesses<'_>,
    verify_seed: u64,
) -> Pcd<C, R, LeafNode> {
    let (pcd, ()) = app
        .seed(rng, pcd::witness_leaf(), witnesses.draw())
        .expect("seeding an honest leaf must succeed");
    assert_honest(app, &pcd, Shape::Leaf, verify_seed);
    pcd
}

/// Fuses two leaves into a node and checks it verifies.
fn build_node(
    app: &App,
    rng: &mut StdRng,
    witnesses: &mut Witnesses<'_>,
    verify_seed: u64,
) -> Pcd<C, R, InternalNode> {
    let left = seed_leaf(app, rng, witnesses, verify_seed);
    let right = seed_leaf(app, rng, witnesses, verify_seed);
    let (pcd, ()) = app
        .fuse(rng, pcd::hash2(), (), left, right)
        .expect("fusing two honest leaves must succeed");
    assert_honest(app, &pcd, Shape::Node, verify_seed);
    pcd
}

/// Fuses two internal nodes and checks the result verifies.
fn merge(
    app: &App,
    rng: &mut StdRng,
    left: Pcd<C, R, InternalNode>,
    right: Pcd<C, R, InternalNode>,
    verify_seed: u64,
) -> Pcd<C, R, InternalNode> {
    let (pcd, ()) = app
        .fuse(rng, pcd::merge2(), (), left, right)
        .expect("fusing two honest nodes must succeed");
    assert_honest(app, &pcd, Shape::Deep, verify_seed);
    pcd
}

/// Every honest proof must verify, at every level of the tree.
fn assert_honest<H: ragu_pcd::header::Header<NativeField>>(
    app: &App,
    pcd: &Pcd<C, R, H>,
    shape: Shape,
    verify_seed: u64,
) {
    assert!(
        matches!(
            app.verify(pcd, StdRng::seed_from_u64(verify_seed)),
            Ok(true)
        ),
        "the verifier rejected an honest {} proof",
        shape.name(),
    );
}

// The three applications are paid for in `init`, before libFuzzer starts
// timing units.
fuzz_target!(
    init: {
        if std::env::var("DEBUG_INPUT").is_err() {
            LazyLock::force(&APPS);
        }
    },
    |input: Input| {
        if std::env::var("DEBUG_INPUT").is_ok() {
            eprintln!("{input:#?}");
            return;
        }

        let steps = 1 + input.steps as usize % 3;
        let app = &APPS[steps - 1].0;
        let plans = Plan::available(steps);
        let plan = plans[input.plan as usize % plans.len()];

        let mut rng = StdRng::seed_from_u64(input.rng_seed);
        // A separate seed for the verifier, re-derived at every check, so the
        // challenges it samples do not shift as the tree's blinding consumes
        // more or less randomness.
        let verify_seed = input.rng_seed ^ 0x5645_5249_4659;
        let mut witnesses = Witnesses {
            values: &input.witnesses,
            next: 0,
        };
        // Build the tree, verifying every proof on the way up, and reduce it
        // to the root's proof plus the header data it carries.
        let (shape, proof, data) = match plan {
            Plan::Leaf => {
                let (proof, data) = seed_leaf(app, &mut rng, &mut witnesses, verify_seed)
                    .into_parts();
                (Shape::Leaf, proof, data)
            }
            Plan::Node => {
                let node = build_node(app, &mut rng, &mut witnesses, verify_seed);
                let node = maybe_rerandomize(app, node, input.rerandomize, &mut rng, verify_seed);
                let (proof, data) = node.into_parts();
                (Shape::Node, proof, data)
            }
            Plan::Deep => {
                let left = build_node(app, &mut rng, &mut witnesses, verify_seed);
                let right = build_node(app, &mut rng, &mut witnesses, verify_seed);
                let root = merge(app, &mut rng, left, right, verify_seed);
                let root = maybe_rerandomize(app, root, input.rerandomize, &mut rng, verify_seed);
                let (proof, data) = root.into_parts();
                (Shape::Deep, proof, data)
            }
            Plan::Lopsided => {
                let ll = build_node(app, &mut rng, &mut witnesses, verify_seed);
                let lr = build_node(app, &mut rng, &mut witnesses, verify_seed);
                let left = merge(app, &mut rng, ll, lr, verify_seed);
                let right = build_node(app, &mut rng, &mut witnesses, verify_seed);
                let root = merge(app, &mut rng, left, right, verify_seed);
                let root = maybe_rerandomize(app, root, input.rerandomize, &mut rng, verify_seed);
                let (proof, data) = root.into_parts();
                (Shape::Deep, proof, data)
            }
        };

        // Close the loop: the honest root that just verified must stop
        // verifying once a corruption binds the verifier.
        let original = Fixture { shape, proof, data };
        let mut fixture = original.clone();
        let (applied, binding) =
            pcd::apply(&mut fixture.proof, &input.corruptions, MAX_CORRUPTIONS);
        if applied.is_empty() {
            return;
        }
        pcd::assert_rejected(
            app,
            &original,
            &fixture,
            &applied,
            binding,
            verify_seed,
        );
    }
);

/// Rerandomizes `pcd` when asked, checking the result still verifies.
///
/// Rerandomization is part of the lifecycle and rebuilds the root through a
/// fuse with the seeded trivial proof, so it exercises a path no plain fuse
/// reaches.
fn maybe_rerandomize(
    app: &App,
    pcd: Pcd<C, R, InternalNode>,
    yes: bool,
    rng: &mut StdRng,
    verify_seed: u64,
) -> Pcd<C, R, InternalNode> {
    if !yes {
        return pcd;
    }
    let pcd = app
        .rerandomize(pcd, rng)
        .expect("rerandomizing an honest proof must succeed");
    assert_honest(app, &pcd, Shape::Node, verify_seed);
    pcd
}
