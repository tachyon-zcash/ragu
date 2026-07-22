//! Does per-step proving cost depend on how much work a step does?
//!
//! Hypothesis under test: within a *single fixed application*, every step of a
//! given kind costs about the same to prove, regardless of the number of gates
//! it fills, because the dominant cost is the fixed recursion pipeline
//! (preamble, error terms, query, dense `f` commitment) rather than the step's
//! own trace.
//!
//! This test is a self-contained knob-turning harness: it defines its own
//! headers and steps, and each step's workload is an independent compile-time
//! const generic (the number of Poseidon permutations). Flip a knob and re-run
//! to observe how gate count moves while proving time stays ~flat.
//!
//! The PCD tree:
//!   * `LeafA<KA>`  — seed step, near-empty when `KA = 0`.
//!   * `LeafB<KB>`  — seed step, near-full when `KB = 7` (the cap).
//!   * `Fuse1<K1>`  — fuse `A` (left) with `B` (right).
//!   * `Fuse2<K2>`  — `Fuse1` with left/right swapped: fuse `B` (left), `A` (right).
//!   * `FuseF<KF>`  — final fuse of the two sibling outputs (two *internal* proofs).
//!
//! `Fuse1` vs `Fuse2` isolates whether left/right ordering matters; `FuseF`
//! (fusing internal proofs) vs the sibling fuses (fusing leaves) isolates
//! leaf-vs-internal input cost.

use std::time::{Duration, Instant};

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    ApplicationBuilder,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};
use rand::{SeedableRng, rngs::StdRng};

const HEADER_SIZE: usize = 4;

// Timing configuration.
const WARMUP: usize = 1;
/// Iterations per sweep point (kept small — a sweep rebuilds and proves at
/// every point).
const SWEEP_ITERS: usize = 3;
/// Value at which the non-swept step knobs are held while one step is swept.
const BASE: usize = 1;

// --- Distinct headers, one per step output -------------------------------

/// Output header of `LeafA`.
struct HeaderA;
/// Output header of `LeafB`.
struct HeaderB;
/// Output header of `Fuse1`.
struct Header1;
/// Output header of `Fuse2`.
struct Header2;
/// Output header of `FuseF`.
struct HeaderF;

impl<F: Field> Header<F> for HeaderA {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

impl<F: Field> Header<F> for HeaderB {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

impl<F: Field> Header<F> for Header1 {
    const SUFFIX: Suffix = Suffix::new(2);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

impl<F: Field> Header<F> for Header2 {
    const SUFFIX: Suffix = Suffix::new(3);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

impl<F: Field> Header<F> for HeaderF {
    const SUFFIX: Suffix = Suffix::new(4);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

// --- Shared circuit helpers ----------------------------------------------

/// Chains `k` independent Poseidon permutations starting from `input`, using a
/// fresh sponge each iteration so total work is exactly `k` permutations.
fn chain_poseidons<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    mut current: Element<'dr, D>,
    k: usize,
) -> Result<Element<'dr, D>> {
    for _ in 0..k {
        let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
            dr,
            Pasta::circuit_poseidon(Pasta::baked()),
        );
        sponge.absorb(dr, &current)?;
        current = sponge.squeeze(dr)?;
    }
    Ok(current)
}

/// Combines two input elements with `k` total Poseidon permutations. The first
/// permutation absorbs both inputs; the remaining `k - 1` chain from the result.
/// `k = 0` does no hashing and returns the left input (both are still allocated
/// by the caller).
fn fuse_elements<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    left: &Element<'dr, D>,
    right: &Element<'dr, D>,
    k: usize,
) -> Result<Element<'dr, D>> {
    if k == 0 {
        return Ok(left.clone());
    }
    let mut sponge = Sponge::<'_, _, <Pasta as Cycle>::CircuitPoseidon>::new(
        dr,
        Pasta::circuit_poseidon(Pasta::baked()),
    );
    sponge.absorb(dr, left)?;
    sponge.absorb(dr, right)?;
    let combined = sponge.squeeze(dr)?;
    chain_poseidons(dr, combined, k - 1)
}

// --- Step 1: LeafA -------------------------------------------------------

struct LeafA<const K: usize>;

impl<const K: usize> Step<Pasta> for LeafA<K> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HeaderA;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let leaf = Element::alloc(dr, allocator, witness)?;
        let out = chain_poseidons(dr, leaf, K)?;
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

// --- Step 2: LeafB -------------------------------------------------------

struct LeafB<const K: usize>;

impl<const K: usize> Step<Pasta> for LeafB<K> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HeaderB;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let leaf = Element::alloc(dr, allocator, witness)?;
        let out = chain_poseidons(dr, leaf, K)?;
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

// --- Step 3: Fuse1 (A left, B right) -------------------------------------

struct Fuse1<const K: usize>;

impl<const K: usize> Step<Pasta> for Fuse1<K> {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = HeaderA;
    type Right = HeaderB;
    type Output = Header1;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let out = fuse_elements(dr, left.as_gadget(), right.as_gadget(), K)?;
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

// --- Step 4: Fuse2 (Fuse1 with left/right swapped: B left, A right) ------

struct Fuse2<const K: usize>;

impl<const K: usize> Step<Pasta> for Fuse2<K> {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = HeaderB;
    type Right = HeaderA;
    type Output = Header2;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let out = fuse_elements(dr, left.as_gadget(), right.as_gadget(), K)?;
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

// --- Step 5: FuseF (final fuse of the two sibling outputs) ---------------

struct FuseF<const K: usize>;

impl<const K: usize> Step<Pasta> for FuseF<K> {
    const INDEX: Index = Index::new(4);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Header1;
    type Right = Header2;
    type Output = HeaderF;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let out = fuse_elements(dr, left.as_gadget(), right.as_gadget(), K)?;
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

// --- Reporting -----------------------------------------------------------

fn summarize(times: &[Duration]) -> (f64, f64) {
    let min = times.iter().min().unwrap().as_secs_f64() * 1e3;
    let mean = times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / times.len() as f64 * 1e3;
    (min, mean)
}

/// Build the fixed-shape 5-step application with every step parameterized by the
/// given knobs, prove each step `iters` times (after `WARMUP` warmups), and
/// print a detailed per-step block: gate/constraint counts and min/mean proving
/// time for `LeafA`, `LeafB`, `Fuse1`, `Fuse2`, and `FuseF`.
///
/// The circuit *count* is fixed at five regardless of the knobs, so the registry
/// domain (`num_circuits`, `log2_circuits`) is identical across configurations —
/// only the parameterized steps' trace density changes, isolating the gate-count
/// effect from the fixed recursion pipeline. The printed block echoes all five
/// knobs so the output fully reflects the parameterization.
fn sweep_point<
    const LEAF_A: usize,
    const LEAF_B: usize,
    const FUSE_1: usize,
    const FUSE_2: usize,
    const FUSE_F: usize,
>(
    iters: usize,
) -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(LeafA::<LEAF_A>)?
        .register(LeafB::<LEAF_B>)?
        .register(Fuse1::<FUSE_1>)?
        .register(Fuse2::<FUSE_2>)?
        .register(FuseF::<FUSE_F>)?
        .finalize(pasta)?;

    // Application circuits are registered last (after internal circuits, masks,
    // and internal steps), so the five step circuits are the final five indices
    // in registration order: LeafA, LeafB, Fuse1, Fuse2, FuseF.
    let reg = app.native_registry();
    let base = reg.num_circuits() - 5;
    let gate_counts: Vec<(usize, usize)> = (0..5)
        .map(|i| reg.constraint_counts(CircuitIndex::new(base + i)))
        .collect();

    let mut rng = StdRng::seed_from_u64(1234);

    // Warmup: also triggers any lazy one-time initialization for this fresh app.
    for _ in 0..WARMUP {
        let (a, _) = app.seed(&mut rng, LeafA::<LEAF_A>, Fp::from(1u64))?;
        let (b, _) = app.seed(&mut rng, LeafB::<LEAF_B>, Fp::from(1u64))?;
        let (n1, _) = app.fuse(&mut rng, Fuse1::<FUSE_1>, (), a.clone(), b.clone())?;
        let (n2, _) = app.fuse(&mut rng, Fuse2::<FUSE_2>, (), b, a)?;
        let _ = app.fuse(&mut rng, FuseF::<FUSE_F>, (), n1, n2)?;
    }

    let mut leaf_a_t = Vec::new();
    let mut leaf_b_t = Vec::new();
    let mut fuse1_t = Vec::new();
    let mut fuse2_t = Vec::new();
    let mut fusef_t = Vec::new();

    for i in 0..iters {
        let seed = Fp::from(i as u64 + 7);

        let t = Instant::now();
        let (a, _) = app.seed(&mut rng, LeafA::<LEAF_A>, seed)?;
        leaf_a_t.push(t.elapsed());

        let t = Instant::now();
        let (b, _) = app.seed(&mut rng, LeafB::<LEAF_B>, seed)?;
        leaf_b_t.push(t.elapsed());

        let t = Instant::now();
        let (n1, _) = app.fuse(&mut rng, Fuse1::<FUSE_1>, (), a.clone(), b.clone())?;
        fuse1_t.push(t.elapsed());

        let t = Instant::now();
        let (n2, _) = app.fuse(&mut rng, Fuse2::<FUSE_2>, (), b, a)?;
        fuse2_t.push(t.elapsed());

        let t = Instant::now();
        let (_f, _) = app.fuse(&mut rng, FuseF::<FUSE_F>, (), n1, n2)?;
        fusef_t.push(t.elapsed());
    }

    // The step column carries each step's parameter (e.g. `LeafB<7>`), so the
    // whole configuration is visible by reading down the block.
    let rows = [
        (
            std::format!("LeafA={LEAF_A}"),
            &gate_counts[0],
            summarize(&leaf_a_t),
        ),
        (
            std::format!("LeafB={LEAF_B}"),
            &gate_counts[1],
            summarize(&leaf_b_t),
        ),
        (
            std::format!("Fuse1={FUSE_1}"),
            &gate_counts[2],
            summarize(&fuse1_t),
        ),
        (
            std::format!("Fuse2={FUSE_2}"),
            &gate_counts[3],
            summarize(&fuse2_t),
        ),
        (
            std::format!("FuseF={FUSE_F}"),
            &gate_counts[4],
            summarize(&fusef_t),
        ),
    ];

    std::println!("\n[iters={iters}]");
    std::println!("{:<10}{:>10}{:>10}{:>11}{:>11}", "step", "gates", "constr", "min(ms)", "avg(ms)");
    for (name, (gates, constraints), (min, mean)) in rows {
        std::println!("{name:<10}{gates:>10}{constraints:>10}{min:>11.1}{mean:>11.1}");
    }
    Ok(())
}

// One test per step: sweep that step's parameter from empty to the gate cap
// while holding the others at `BASE`. In each block the swept step's row shows
// its gate count climbing while every step's proving time stays roughly flat.

#[test]
fn sweep_leaf_a() -> Result<()> {
    sweep_point::<0, BASE, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<1, BASE, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<3, BASE, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<5, BASE, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<7, BASE, BASE, BASE, BASE>(SWEEP_ITERS)?;
    Ok(())
}

#[test]
fn sweep_leaf_b() -> Result<()> {
    sweep_point::<BASE, 0, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, 1, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, 3, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, 5, BASE, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, 7, BASE, BASE, BASE>(SWEEP_ITERS)?;
    Ok(())
}

#[test]
fn sweep_fuse1() -> Result<()> {
    sweep_point::<BASE, BASE, 0, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, 1, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, 3, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, 5, BASE, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, 7, BASE, BASE>(SWEEP_ITERS)?;
    Ok(())
}

#[test]
fn sweep_fuse2() -> Result<()> {
    sweep_point::<BASE, BASE, BASE, 0, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, 1, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, 3, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, 5, BASE>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, 7, BASE>(SWEEP_ITERS)?;
    Ok(())
}

#[test]
fn sweep_fusef() -> Result<()> {
    sweep_point::<BASE, BASE, BASE, BASE, 0>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, BASE, 1>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, BASE, 3>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, BASE, 5>(SWEEP_ITERS)?;
    sweep_point::<BASE, BASE, BASE, BASE, 7>(SWEEP_ITERS)?;
    Ok(())
}
