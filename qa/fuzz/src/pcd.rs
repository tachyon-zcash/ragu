//! Shared PCD fixtures and the verifier-corruption vocabulary.
//!
//! Three targets work on finished [`Proof`]s: `fuzz_verify_reject` corrupts a
//! cached leaf, `fuzz_verify_reject_full` corrupts cached fused proofs, and
//! `fuzz_pcd_lifecycle` builds fresh trees and corrupts what it built. They
//! share the application fixtures, the proof shapes, and the [`Arbitrary`]
//! vocabulary that decodes fuzzer bytes into
//! [`ragu_pcd::fuzzing::corrupt::Corruption`] — so a corruption added once is
//! reachable from all three.
//!
//! # No fixture is the dummy proof
//!
//! Ragu's synthesized dummy proof is the placeholder the internal Bootstrap
//! step consumes, not a proof the verifier accepts: `verify` returns
//! `Ok(false)` for it in any application. Corrupting it and asserting
//! non-acceptance therefore asserts nothing — the assertion holds before the
//! corruption too. Every fixture here is a proof that verifies, and both
//! [`leaf_fixture`] and [`fused_fixtures`] check that before handing any of
//! them out.

use arbitrary::Arbitrary;
use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::Pasta;
use ragu_pcd::{
    Application, ApplicationBuilder, Proof,
    fuzzing::corrupt::{
        Binding, BridgeCommitment, Challenge, Corruption, NativeRx, NestedRx, RxComponent, Side,
    },
};
use ragu_testing::pcd::nontrivial::{Hash2, InternalNode, LeafNode, Merge2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

/// The cycle every PCD target works over.
pub type C = Pasta;
/// The polynomial rank every PCD target works over.
pub type R = ProductionRank;
/// The header size every PCD target's application is built with.
pub const HEADER_SIZE: usize = 4;

/// The native field.
pub type NativeField = <Pasta as Cycle>::CircuitField;
/// The nested field.
pub type NestedField = <Pasta as Cycle>::ScalarField;

/// The application, wrapped so a `LazyLock` can hold it.
///
/// [`Application`] holds a `OnceCell` (`seeded_trivial`, memoizing the
/// rerandomization fixture), which breaks auto-`Sync`.
pub struct SyncApp(pub Application<'static, C, R, HEADER_SIZE>);

// SAFETY: libFuzzer drives `fuzz_target!` on a single thread, so the
// `OnceCell` inside is never touched concurrently — not even on the very
// first call that initializes it. No PCD target spawns worker threads or
// hands the application to one. If one ever does, this must be revisited.
unsafe impl Sync for SyncApp {}

/// Poseidon parameters for the baked Pasta cycle.
fn poseidon() -> &'static <Pasta as Cycle>::CircuitPoseidon {
    Pasta::circuit_poseidon(Pasta::baked())
}

/// The seeding step.
pub fn witness_leaf() -> WitnessLeaf<'static, C> {
    WitnessLeaf {
        poseidon_params: poseidon(),
    }
}

/// The step that fuses two leaves.
pub fn hash2() -> Hash2<'static, C> {
    Hash2 {
        poseidon_params: poseidon(),
    }
}

/// The step that fuses two internal nodes.
pub fn merge2() -> Merge2<'static, C> {
    Merge2 {
        poseidon_params: poseidon(),
    }
}

/// An application with the first `steps` of the nontrivial step set
/// registered, in the order their `Index`es demand: `WitnessLeaf`, `Hash2`,
/// `Merge2`.
///
/// `steps` is clamped to `1..=3`. Which steps are registered bounds the trees
/// that can be built over the application: one step seeds leaves only, two
/// reach a fuse of leaves, three reach a fuse of those.
pub fn nontrivial_app(steps: usize) -> SyncApp {
    let mut builder = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(witness_leaf())
        .expect("registering the seeding step must succeed");
    if steps >= 2 {
        builder = builder
            .register(hash2())
            .expect("registering the leaf-fusing step must succeed");
    }
    if steps >= 3 {
        builder = builder
            .register(merge2())
            .expect("registering the node-fusing step must succeed");
    }
    SyncApp(
        builder
            .finalize(Pasta::baked())
            .expect("the nontrivial application must build"),
    )
}

/// Which header a proof's carried data belongs to, and thus how it must be
/// re-wrapped to be verified again after corruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A `WitnessLeaf` seed, carrying a [`LeafNode`] header.
    Leaf,
    /// A `Hash2` fuse of two leaves, carrying an [`InternalNode`] header.
    Node,
    /// A `Merge2` fuse of two nodes, carrying an [`InternalNode`] header.
    ///
    /// The distinction from [`Shape::Node`] is not in the header but in what
    /// the proof accumulated: a fuse of two leaves and a fuse of two nodes
    /// carry different recursion histories.
    Deep,
}

impl Shape {
    /// A name for panic messages.
    pub fn name(self) -> &'static str {
        match self {
            Shape::Leaf => "leaf",
            Shape::Node => "node",
            Shape::Deep => "deep",
        }
    }
}

/// An honest proof, the data it carries, and which header that data belongs
/// to.
pub struct Fixture {
    /// Which header the proof carries.
    pub shape: Shape,
    /// The proof itself.
    pub proof: Proof<C, R>,
    /// The header data the proof's output header encodes.
    pub data: NativeField,
}

impl Clone for Fixture {
    fn clone(&self) -> Self {
        Fixture {
            shape: self.shape,
            proof: self.proof.clone(),
            data: self.data,
        }
    }
}

impl Fixture {
    /// Verify this fixture's proof under the header its shape names.
    ///
    /// Clones the proof, since [`Proof::carry`] consumes it and a fixture is
    /// verified many times.
    pub fn verify(&self, app: &Application<'_, C, R, HEADER_SIZE>, rng: StdRng) -> Result<bool> {
        let proof = self.proof.clone();
        match self.shape {
            Shape::Leaf => app.verify(&proof.carry::<LeafNode>(self.data), rng),
            Shape::Node | Shape::Deep => app.verify(&proof.carry::<InternalNode>(self.data), rng),
        }
    }
}

/// Checks every fixture verifies before it is handed out, so no target can
/// start from a proof the verifier already rejects.
fn checked(app: &Application<'_, C, R, HEADER_SIZE>, fixtures: Vec<Fixture>) -> Vec<Fixture> {
    for fixture in &fixtures {
        assert!(
            matches!(
                fixture.verify(app, StdRng::seed_from_u64(0xf1_47u64)),
                Ok(true)
            ),
            "the honest {} fixture must verify",
            fixture.shape.name(),
        );
    }
    fixtures
}

/// Seeds one leaf.
pub fn seed(app: &Application<'_, C, R, HEADER_SIZE>, rng: &mut StdRng, witness: u64) -> LeafPcd {
    app.seed(rng, witness_leaf(), NativeField::from(witness))
        .expect("seeding a leaf must succeed")
        .0
}

/// Fuses two freshly seeded leaves.
pub fn node(
    app: &Application<'_, C, R, HEADER_SIZE>,
    rng: &mut StdRng,
    l: u64,
    r: u64,
) -> InternalPcd {
    let (left, right) = (seed(app, rng, l), seed(app, rng, r));
    app.fuse(rng, hash2(), (), left, right)
        .expect("fusing two leaves must succeed")
        .0
}

/// A proof carrying a [`LeafNode`] header.
pub type LeafPcd = ragu_pcd::Pcd<C, R, LeafNode>;
/// A proof carrying an [`InternalNode`] header.
pub type InternalPcd = ragu_pcd::Pcd<C, R, InternalNode>;

/// The cheapest fixture that actually verifies: one `WitnessLeaf` seed.
///
/// `fuzz_verify_reject` works from this one, so its per-input cost is a clone,
/// a corruption and a verify.
pub fn leaf_fixture(app: &Application<'_, C, R, HEADER_SIZE>) -> Fixture {
    let mut rng = StdRng::seed_from_u64(0x1eaf);
    let (proof, data) = seed(app, &mut rng, 42).into_parts();
    checked(
        app,
        vec![Fixture {
            shape: Shape::Leaf,
            proof,
            data,
        }],
    )
    .pop()
    .expect("one fixture was built")
}

/// The fused fixtures: a `Hash2` over two leaves, and a `Merge2` over two such
/// nodes.
///
/// The two differ in more than depth: their children carry different recursion
/// histories. Each is built from its own RNG seed and its own witness values,
/// so the pair is not two views of one arithmetic accident.
pub fn fused_fixtures(app: &Application<'_, C, R, HEADER_SIZE>) -> Vec<Fixture> {
    let mut rng = StdRng::seed_from_u64(0x0de);
    let (proof, data) = node(app, &mut rng, 7, 11).into_parts();
    let shallow = Fixture {
        shape: Shape::Node,
        proof,
        data,
    };

    let mut rng = StdRng::seed_from_u64(0xdeeb);
    let (left, right) = (node(app, &mut rng, 13, 17), node(app, &mut rng, 19, 23));
    let (proof, data) = app
        .fuse(&mut rng, merge2(), (), left, right)
        .expect("fusing two nodes must succeed")
        .0
        .into_parts();
    let deep = Fixture {
        shape: Shape::Deep,
        proof,
        data,
    };

    checked(app, vec![shallow, deep])
}

/// A fuzzer-chosen corruption, before it is resolved against a proof.
///
/// Every field is taken modulo the space it addresses, so no input is
/// rejected out of hand and the fuzzer's mutations stay meaningful. The
/// `bound` flags steer a coefficient index into the low `n` coefficients,
/// where a circuit claim's $t_z$ term makes rejection mandatory — see
/// [`ragu_pcd::fuzzing::corrupt`].
#[derive(Arbitrary, Debug, Clone)]
pub enum FuzzCorruption {
    /// Replace the circuit id.
    CircuitId {
        /// The raw choice.
        raw: u32,
        /// Fold it into the registry's domain rather than leaving it wild.
        /// An out-of-domain id is rejected by the very first check in
        /// `verify`, so without this almost every draw would stop there and
        /// the id would never reach the instance.
        in_domain: bool,
    },
    /// Perturb one element of a child header.
    HeaderElement {
        /// Right child rather than left.
        right: bool,
        /// Which element, resolved modulo twice the header size so both
        /// in-range and out-of-range indices come up.
        index: u8,
        /// What to add.
        delta: u64,
    },
    /// Resize a child header.
    HeaderLen {
        /// Right child rather than left.
        right: bool,
        /// The new length, resolved modulo twice the header size so it
        /// straddles the length the verifier demands.
        len: u8,
    },
    /// Exchange the two child headers.
    SwapHeaders,
    /// Overwrite a verifier challenge.
    Challenge {
        /// Which challenge.
        which: u8,
        /// The new value.
        value: u64,
    },
    /// Negate a bridge commitment.
    NegateBridgeCommitment {
        /// Which commitment.
        which: u8,
    },
    /// Perturb one coefficient of a native polynomial.
    NativeCoeff {
        /// Which polynomial.
        component: u8,
        /// Which coefficient.
        coeff: u16,
        /// What to add.
        delta: u64,
        /// Steer the coefficient into the bound region.
        bound: bool,
    },
    /// Perturb one coefficient of the `registry_xy` polynomial.
    RegistryXyCoeff {
        /// Which coefficient.
        coeff: u16,
        /// What to add.
        delta: u64,
    },
    /// Perturb one coefficient of the `p` polynomial.
    PCoeff {
        /// Which coefficient.
        coeff: u16,
        /// What to add.
        delta: u64,
    },
    /// Perturb one coefficient of a nested polynomial.
    NestedCoeff {
        /// Which polynomial.
        index: u8,
        /// Which coefficient.
        coeff: u16,
        /// What to add.
        delta: u64,
        /// Steer the coefficient into the bound region.
        bound: bool,
    },
}

/// The native polynomials a corruption can address, in a stable order.
fn native_components() -> Vec<RxComponent> {
    let mut all = vec![RxComponent::AbA, RxComponent::AbB];
    all.extend(NativeRx::ALL.map(RxComponent::Rx));
    all
}

/// A nonzero field element, so a "perturb by delta" corruption always
/// perturbs.
fn nonzero<F: Field + From<u64>>(v: u64) -> F {
    let v = F::from(v);
    if v == F::ZERO { F::ONE } else { v }
}

/// Resolves a coefficient index into the rank's coefficient space, optionally
/// steering it into the low `n` coefficients a circuit claim binds.
fn coeff_index(raw: u16, bound: bool) -> usize {
    let modulus = if bound {
        Proof::<C, R>::num_bound_coeffs()
    } else {
        Proof::<C, R>::num_coeffs()
    };
    raw as usize % modulus
}

/// Resolves a header index or length, modulo twice the header size so that
/// roughly half the draws land in range and the rest probe past it.
fn header_index(raw: u8) -> usize {
    raw as usize % (2 * HEADER_SIZE)
}

/// Resolves a circuit id, either into the registry's domain or left wild.
///
/// The domain is not exposed, so `in_domain` folds into a range comfortably
/// inside it: the applications here register at most three steps, which puts
/// the registry at 32 circuits.
fn circuit_id(raw: u32, in_domain: bool) -> u32 {
    if in_domain { raw % 32 } else { raw }
}

impl FuzzCorruption {
    /// A key identifying what this corruption edits.
    ///
    /// Coordinated corruptions are deduplicated by this key: two edits to the
    /// same component can cancel — add a delta, then subtract it — and leave
    /// an honest proof that the verifier is right to accept. Edits to
    /// *different* components cancel only if the verifier's freshly sampled
    /// challenge is a root of their difference, which is the same negligible
    /// event every other classification rests on.
    pub fn target(&self) -> (u8, usize) {
        match *self {
            FuzzCorruption::CircuitId { .. } => (0, 0),
            FuzzCorruption::HeaderElement { right, index, .. } => {
                (1, usize::from(right) << 16 | header_index(index))
            }
            FuzzCorruption::HeaderLen { right, .. } => (2, usize::from(right)),
            FuzzCorruption::SwapHeaders => (3, 0),
            FuzzCorruption::Challenge { which, .. } => (4, which as usize % Challenge::ALL.len()),
            FuzzCorruption::NegateBridgeCommitment { which } => {
                (5, which as usize % BridgeCommitment::ALL.len())
            }
            FuzzCorruption::NativeCoeff {
                component,
                coeff,
                bound,
                ..
            } => (
                6,
                (component as usize % native_components().len()) << 16 | coeff_index(coeff, bound),
            ),
            FuzzCorruption::RegistryXyCoeff { coeff, .. } => (7, coeff_index(coeff, false)),
            FuzzCorruption::PCoeff { coeff, .. } => (8, coeff_index(coeff, false)),
            FuzzCorruption::NestedCoeff {
                index,
                coeff,
                bound,
                ..
            } => (
                9,
                (index as usize % NestedRx::ALL.len()) << 16 | coeff_index(coeff, bound),
            ),
        }
    }

    /// Resolve this choice into a [`Corruption`] over the Pasta cycle.
    pub fn resolve(&self) -> Corruption<C> {
        let side = |right: bool| if right { Side::Right } else { Side::Left };
        match *self {
            FuzzCorruption::CircuitId { raw, in_domain } => {
                Corruption::CircuitId(circuit_id(raw, in_domain))
            }
            FuzzCorruption::HeaderElement {
                right,
                index,
                delta,
            } => Corruption::HeaderElement {
                side: side(right),
                index: header_index(index),
                delta: nonzero(delta),
            },
            FuzzCorruption::HeaderLen { right, len } => Corruption::HeaderLen {
                side: side(right),
                len: header_index(len),
            },
            FuzzCorruption::SwapHeaders => Corruption::SwapHeaders,
            FuzzCorruption::Challenge { which, value } => Corruption::Challenge(
                Challenge::ALL[which as usize % Challenge::ALL.len()],
                NativeField::from(value),
            ),
            FuzzCorruption::NegateBridgeCommitment { which } => Corruption::NegateBridgeCommitment(
                BridgeCommitment::ALL[which as usize % BridgeCommitment::ALL.len()],
            ),
            FuzzCorruption::NativeCoeff {
                component,
                coeff,
                delta,
                bound,
            } => {
                let all = native_components();
                Corruption::NativeCoeff {
                    component: all[component as usize % all.len()],
                    coeff: coeff_index(coeff, bound),
                    delta: nonzero(delta),
                }
            }
            FuzzCorruption::RegistryXyCoeff { coeff, delta } => Corruption::RegistryXyCoeff {
                coeff: coeff_index(coeff, false),
                delta: nonzero(delta),
            },
            FuzzCorruption::PCoeff { coeff, delta } => Corruption::PCoeff {
                coeff: coeff_index(coeff, false),
                delta: nonzero(delta),
            },
            FuzzCorruption::NestedCoeff {
                index,
                coeff,
                delta,
                bound,
            } => Corruption::NestedCoeff {
                index: NestedRx::ALL[index as usize % NestedRx::ALL.len()],
                coeff: coeff_index(coeff, bound),
                delta: nonzero::<NestedField>(delta),
            },
        }
    }
}

/// Applies `choices` to `proof`, deduplicated by
/// [`target`](FuzzCorruption::target), and reports whether any of them bound
/// the verifier.
///
/// Returns the corruptions actually applied alongside the verdict, so a
/// panic message can name them.
pub fn apply(
    proof: &mut Proof<C, R>,
    choices: &[FuzzCorruption],
    limit: usize,
) -> (Vec<FuzzCorruption>, Binding) {
    let mut seen: Vec<(u8, usize)> = Vec::new();
    let mut applied = Vec::new();
    let mut binding = Binding::Unbound;
    for choice in choices.iter().take(limit) {
        let target = choice.target();
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        if proof.corrupt(choice.resolve()) == Binding::MustReject {
            binding = Binding::MustReject;
        }
        applied.push(choice.clone());
    }
    (applied, binding)
}

/// Asserts the verifier's response to a corrupted fixture.
///
/// `verify` must never accept a corruption that bound it, and must never
/// panic on one that did not — an internal error is a rejection, not a
/// crash.
pub fn assert_rejected(
    app: &Application<'_, C, R, HEADER_SIZE>,
    fixture: &Fixture,
    applied: &[FuzzCorruption],
    binding: Binding,
    rng: StdRng,
) {
    let result = fixture.verify(app, rng);
    if binding == Binding::MustReject {
        assert!(
            !matches!(result, Ok(true)),
            "the verifier accepted a corrupted {} proof: {applied:?}",
            fixture.shape.name(),
        );
    }
}
