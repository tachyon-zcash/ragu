//! Registry construction beyond one circuit at index zero.
//!
//! A single-circuit registry at index zero leaves several parts of `Registry`
//! unexercised: the four-category concatenation order, the
//! `CircuitIndex`-to-`omega_j` mapping at a non-zero index, the domain
//! padding when the count is not a power of two, or the rank's circuit
//! ceiling.
//!
//! This target fuzzes those. It registers a fuzzer-chosen sequence of
//! circuits across all four categories, at a fuzzer-chosen rank, and checks
//! the invariants the rest of the system reads the registry through.
//!
//! # Oracles
//!
//! ## Category concatenation order
//!
//! `RegistryBuilder::finalize` documents its order — internal circuits,
//! bonding, internal steps, application steps — and notes that it *must*
//! match `InternalCircuitIndex::ALL` in `ragu_pcd`, which derives a
//! `CircuitIndex` from position. The builder therefore has to group by
//! category, not by call order. Registering the same multiset in two
//! different interleavings that preserve each category's internal sequence
//! must produce byte-identical registries; the target checks that via
//! `Registry::tag`.
//!
//! ## Path agreement on the registry polynomial
//!
//! `Registry` exposes the same polynomial through two evaluation paths:
//!
//! - `xy(x, y)` builds an evaluation vector over the registry's W-domain,
//!   including the tag term at every domain point, then interpolates it
//!   with an IFFT.
//! - `wxy(w, x, y)` goes through `at(w)`, which uses cached Lagrange
//!   coefficients and never forms the full polynomial.
//!
//! So `xy(x, y).eval(w) == wxy(w, x, y)` for every `w`, and the two
//! restrictions `wy(w, y).eval(x)` and `wx(w, x).eval(y)` must agree with
//! `wxy` as well. This is not an abstract identity: `ragu_pcd`'s verifier
//! checks exactly this relation between `native_registry_xy_poly().eval(w)`
//! and `native_registry.wxy(w, x, y)` (see `verify.rs`), so a divergence
//! here is a divergence in a live consensus check. With one circuit at
//! index zero the IFFT is close to a no-op; with several, at a rank whose
//! domain is genuinely larger than the circuit count, it is not.
//!
//! ## Index mapping and domain padding
//!
//! `circuit_y(i, y).eval(x)` must equal `circuit_xy(i, x, y)` — again two
//! routes, polynomial-then-evaluate versus direct scalar. And every index
//! below the domain size must report `circuit_in_domain`, including the
//! padding indices above the registered count, which carry the zero
//! polynomial rather than being absent.
//!
//! ## The rank ceiling
//!
//! `finalize` returns `Error::CircuitBoundExceeded` when the circuit count
//! passes `R::num_coeffs()`. The boundary is reachable at test rank (128
//! coefficients) and is probed exactly there — see `probe_capacity` below.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_circuits::polynomials::Rank;
use ragu_circuits::registry::{CircuitIndex, RegistryBuilder};
use ragu_testing_fuzz::params::{Fp, RankChoice, TestRank};
use ragu_testing_fuzz::substrate::{
    Limits, OpSet, Overrides, Program, ProgramCircuit, shadow_eval, steer,
};
use ragu_testing_fuzz::with_rank;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Registering a circuit synthesizes it, so the count is what sets this
/// target's cost per input. Six is enough to cross a power-of-two domain
/// boundary twice (1→2, 2→4, 4→8) and to put several circuits in every
/// category, without making a production-rank input unaffordable.
const MAX_REGISTRATIONS: usize = 6;

/// `REGISTRY_STATS=1` reports how much of each input actually reaches an
/// oracle. A target whose assertions are all reachable-but-never-reached
/// passes for the wrong reason, and there is no way to tell from the outside.
static RUNS: AtomicUsize = AtomicUsize::new(0);
static BUILT: AtomicUsize = AtomicUsize::new(0);
static MULTI_CATEGORY: AtomicUsize = AtomicUsize::new(0);
/// Inputs where some category holds two or more circuits *and* their
/// programs differ — the only inputs for which the ordering oracle can
/// discriminate at all.
static ORDER_DISCRIMINATING: AtomicUsize = AtomicUsize::new(0);
static PRODUCTION_RANK: AtomicUsize = AtomicUsize::new(0);
static CAPACITY_PROBES: AtomicUsize = AtomicUsize::new(0);

fn bump(c: &AtomicUsize) {
    if stats_on() {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

fn stats_on() -> bool {
    std::env::var("REGISTRY_STATS").is_ok()
}

fn report() {
    let runs = RUNS.fetch_add(1, Ordering::Relaxed) + 1;
    if runs % (1 << 12) != 0 {
        return;
    }
    eprintln!(
        "[registry] runs {runs}: built {}, multi-category {}, order-discriminating {}, \
         production-rank {}, capacity probes {}",
        BUILT.load(Ordering::Relaxed),
        MULTI_CATEGORY.load(Ordering::Relaxed),
        ORDER_DISCRIMINATING.load(Ordering::Relaxed),
        PRODUCTION_RANK.load(Ordering::Relaxed),
        CAPACITY_PROBES.load(Ordering::Relaxed),
    );
}

/// Which of `RegistryBuilder`'s four buckets a registration goes into.
///
/// The variants are in the builder's own concatenation order, which is the
/// order `finalize` promises and `InternalCircuitIndex::ALL` depends on.
#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    /// `register_internal_circuit`: system circuits for the PCD construction.
    Internal,
    /// `register_bonding`: a bonding polynomial, `s(X, 0) = 0`.
    Bonding,
    /// `register_internal_step`: rerandomize, trivial, and friends.
    InternalStep,
    /// `register_circuit`: user-defined step circuits.
    Application,
}

#[derive(Arbitrary, Debug)]
struct Registration {
    category: Category,
    /// Bytes decoded into a `Program`. Ignored for `Category::Bonding`,
    /// whose entry is a stage mask rather than a generated program.
    program: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    rank: RankChoice,
    registrations: Vec<Registration>,
    /// Challenges. Raw bytes, reduced into the field by the harness.
    x: [u8; 32],
    y: [u8; 32],
    w: [u8; 32],
    /// Probe the rank's circuit ceiling this input.
    ///
    /// Gated behind a fuzzer bit because the probe registers
    /// `num_coeffs() + 1` circuits, which is 129 synthesis passes at test
    /// rank — cheap enough to run sometimes, far too slow to run always.
    probe_capacity: bool,
}

/// Reduces 32 fuzzer bytes into a field element.
///
/// `from_repr` rejects non-canonical encodings, and a rejected challenge
/// would silently turn into a skip; folding into a wide reduction instead
/// keeps every input meaningful.
fn to_field(bytes: &[u8; 32]) -> Fp {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes);
    <Fp as ff::FromUniformBytes<64>>::from_uniform_bytes(&wide)
}

fuzz_target!(|input: Input| {
    if stats_on() {
        report();
        if input.rank == RankChoice::Production {
            bump(&PRODUCTION_RANK);
        }
    }
    with_rank!(input.rank, |R| {
        run::<R>(&input);
    });
});

fn run<R: Rank>(input: &Input) {
    let regs = &input.registrations[..input.registrations.len().min(MAX_REGISTRATIONS)];
    if regs.is_empty() {
        return;
    }

    // Decode first and hold the programs alive: `ProgramCircuit` borrows
    // its program, and the registry borrows the circuits.
    let programs: Vec<Program> = regs
        .iter()
        .map(|r| steer::<Fp>(&Program::decode(&r.program, OpSet::ALL, Limits::default())))
        .collect();
    // Anchors come from the honest shadow, matching what every other
    // program-backed target registers.
    let anchors: Vec<Vec<Fp>> = programs
        .iter()
        .map(|p| shadow_eval::<Fp>(p, Overrides::none()).anchors)
        .collect();

    let Some(registry) = build::<R>(regs, &programs, &anchors) else {
        // Rank overflow or an unsynthesizable program: not a finding.
        return;
    };
    bump(&BUILT);
    if regs.iter().any(|r| r.category != regs[0].category) {
        bump(&MULTI_CATEGORY);
    }
    if stats_on() && order_discriminating(regs, &programs) {
        bump(&ORDER_DISCRIMINATING);
    }

    let n = registry.num_circuits();
    assert_eq!(
        n,
        regs.len(),
        "registry lost or invented a circuit: registered {}, holds {n}",
        regs.len(),
    );

    // ---- Concatenation order is by category, not by call order ----
    //
    // Re-register the same circuits with the categories visited in a
    // different interleaving. Each category's internal sequence is
    // preserved, so a builder that groups by category must land on the
    // identical registry; one that appended in call order would not.
    let mut reordered: Vec<&Registration> = Vec::with_capacity(regs.len());
    let mut reordered_programs: Vec<&Program> = Vec::with_capacity(regs.len());
    let mut reordered_anchors: Vec<&Vec<Fp>> = Vec::with_capacity(regs.len());
    for category in [
        Category::Application,
        Category::InternalStep,
        Category::Bonding,
        Category::Internal,
    ] {
        for (i, r) in regs.iter().enumerate() {
            if r.category == category {
                reordered.push(r);
                reordered_programs.push(&programs[i]);
                reordered_anchors.push(&anchors[i]);
            }
        }
    }
    if let Some(permuted) = build_borrowed::<R>(&reordered, &reordered_programs, &reordered_anchors)
    {
        assert_eq!(
            registry.tag(),
            permuted.tag(),
            "registration order changed the registry: `finalize` is documented to \
             concatenate by category (internal, bonding, internal steps, application), \
             and `InternalCircuitIndex::ALL` in ragu_pcd derives indices from that order",
        );
    }

    // ---- The registry polynomial agrees across its access paths ----
    let x = to_field(&input.x);
    let y = to_field(&input.y);
    let w = to_field(&input.w);

    let xy_poly = registry.xy(x, y);
    let direct = registry.wxy(w, x, y);
    assert_eq!(
        xy_poly.eval(w),
        direct,
        "registry.xy(x, y).eval(w) != registry.wxy(w, x, y) — the IFFT path and the \
         cached-Lagrange path disagree. ragu_pcd's verifier checks exactly this \
         relation on native_registry_xy_poly; a mismatch is a consensus divergence. \
         ({n} circuits, rank {})",
        R::RANK,
    );
    assert_eq!(
        registry.wy(w, y).eval(x),
        direct,
        "registry.wy(w, y).eval(x) != registry.wxy(w, x, y) ({n} circuits, rank {})",
        R::RANK,
    );
    assert_eq!(
        registry.wx(w, x).eval(y),
        direct,
        "registry.wx(w, x).eval(y) != registry.wxy(w, x, y) ({n} circuits, rank {})",
        R::RANK,
    );

    // ---- Per-index mapping, including the padding indices ----
    //
    // The domain is the next power of two at or above the circuit count, so
    // indices between `n` and the domain size carry the zero polynomial and
    // must still be addressable. Walking to the domain size rather than to
    // `n` is what puts those padding points under test.
    let domain_size = 1usize << n.next_power_of_two().trailing_zeros();
    for i in 0..domain_size {
        let idx = CircuitIndex::new(i);
        assert!(
            registry.circuit_in_domain(idx),
            "index {i} is below the domain size {domain_size} but reports out of domain",
        );
        assert_eq!(
            registry.circuit_y(idx, y).eval(x),
            registry.circuit_xy(idx, x, y),
            "circuit_y({i}, y).eval(x) != circuit_xy({i}, x, y) — the per-index \
             polynomial and scalar paths disagree ({n} circuits, rank {})",
            R::RANK,
        );
    }

    // ---- The rank ceiling ----
    if input.probe_capacity {
        bump(&CAPACITY_PROBES);
        probe_capacity::<R>();
    }
}

/// Whether the ordering oracle can discriminate on this input: some
/// category must hold two circuits whose programs actually differ.
/// Otherwise permuting is a no-op and the assertion passes vacuously.
fn order_discriminating(regs: &[Registration], programs: &[Program]) -> bool {
    for category in [
        Category::Internal,
        Category::Bonding,
        Category::InternalStep,
        Category::Application,
    ] {
        let members: Vec<&Program> = regs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.category == category)
            .map(|(i, _)| &programs[i])
            .collect();
        if members.len() >= 2 && members.iter().any(|p| p.ops != members[0].ops) {
            return true;
        }
    }
    false
}

/// Builds the registry described by `regs`, or `None` when a program will
/// not synthesize into this rank.
fn build<'a, R: Rank>(
    regs: &'a [Registration],
    programs: &'a [Program],
    anchors: &'a [Vec<Fp>],
) -> Option<ragu_circuits::registry::Registry<'a, Fp, R>> {
    let borrowed: Vec<&Registration> = regs.iter().collect();
    let ps: Vec<&Program> = programs.iter().collect();
    let ans: Vec<&Vec<Fp>> = anchors.iter().collect();
    build_borrowed::<R>(&borrowed, &ps, &ans)
}

fn build_borrowed<'a, R: Rank>(
    regs: &[&'a Registration],
    programs: &[&'a Program],
    anchors: &[&'a Vec<Fp>],
) -> Option<ragu_circuits::registry::Registry<'a, Fp, R>> {
    let mut builder = RegistryBuilder::<Fp, R>::new();
    for ((reg, program), anchor) in regs.iter().zip(programs).zip(anchors) {
        let circuit = ProgramCircuit {
            program,
            anchors: anchor.as_slice(),
        };
        builder = match reg.category {
            Category::Internal => builder.register_internal_circuit(circuit).ok()?,
            Category::InternalStep => builder.register_internal_step(circuit).ok()?,
            Category::Application => builder.register_circuit(circuit).ok()?,
            // A bonding entry is a stage mask, not a generated program: the
            // category exists in the concatenation order and has to be
            // occupied for the ordering oracle to mean anything, but its
            // contents are structural.
            Category::Bonding => builder.register_bonding(bonding_mask::<R>()?),
        };
    }
    builder.finalize().ok()
}

/// A bonding object to occupy `RegistryBuilder`'s bonding bucket.
fn bonding_mask<'a, R: Rank>() -> Option<ragu_circuits::BondingObject<'a, Fp, R>> {
    use ragu_circuits::staging::StageExt;
    <stage::Mask2 as StageExt<Fp, R>>::mask().ok()
}

/// Checks that `finalize` refuses one circuit past the rank's capacity and
/// accepts exactly at it.
///
/// Only meaningful at test rank: `ProductionRank::num_coeffs()` is 8192, and
/// registering 8193 circuits to watch the check fire would cost more than
/// the rest of the campaign put together.
fn probe_capacity<R: Rank>() {
    if R::num_coeffs() != TestRank::num_coeffs() {
        return;
    }
    let limit = R::num_coeffs();
    // An op-less program is the cheapest circuit that still registers.
    let empty = Program::decode(&[], OpSet::ALL, Limits { max_ops: 0 });
    let anchors: Vec<Fp> = Vec::new();

    let at_limit = fill::<R>(&empty, &anchors, limit);
    assert!(
        at_limit.is_some(),
        "registry refused {limit} circuits, which is exactly R::num_coeffs()",
    );
    let past_limit = fill::<R>(&empty, &anchors, limit + 1);
    assert!(
        past_limit.is_none(),
        "registry accepted {} circuits, past the rank capacity of {limit} — \
         finalize is documented to return Error::CircuitBoundExceeded",
        limit + 1,
    );
}

fn fill<'a, R: Rank>(
    program: &'a Program,
    anchors: &'a [Fp],
    count: usize,
) -> Option<ragu_circuits::registry::Registry<'a, Fp, R>> {
    let mut builder = RegistryBuilder::<Fp, R>::new();
    for _ in 0..count {
        builder = builder
            .register_circuit(ProgramCircuit { program, anchors })
            .ok()?;
    }
    builder.finalize().ok()
}

/// A minimal two-wire stage, used only to mint a bonding object.
mod stage {
    use core::marker::PhantomData;
    use ragu_circuits::polynomials::Rank;
    use ragu_circuits::staging::Stage;
    use ragu_core::Result;
    use ragu_core::drivers::{Driver, DriverValue};
    use ragu_core::gadgets::{Bound, Gadget};
    use ragu_core::maybe::Maybe;
    use ragu_primitives::Element;
    use ragu_testing_fuzz::params::Fp;

    #[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write)]
    pub struct TwoWires<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        pub a: Element<'dr, D>,
        #[ragu(gadget)]
        pub b: Element<'dr, D>,
    }

    /// Two independent witness wires. The smallest thing that is still a
    /// stage; its contents do not matter, only that it produces a valid
    /// bonding polynomial. Generic over rank so the bonding category is
    /// populated at whichever rank the input chose.
    #[derive(Default)]
    pub struct Mask2;

    impl<R: Rank> Stage<Fp, R> for Mask2 {
        type Parent = ();
        type Witness<'source> = (Fp, Fp);
        type OutputKind =
            <TwoWires<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            2
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            let a = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.0))?;
            let b = Element::alloc(dr, &mut (), witness.as_ref().map(|w| w.1))?;
            Ok(TwoWires { a, b })
        }
    }
}
