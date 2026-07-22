//! Investigation A: does proving cost grow with the *size* of the PCD tree when
//! every node reuses the same step and header types (case 1 of the complexity
//! gradient)?
//!
//! Builds a balanced binary tree of increasing depth from a fixed, reused set of
//! steps: `Leaf` (seed), `LeafFuse` (lifts a leaf pair to an internal node), and
//! `NodeFuse` (self-chains internal nodes). The registered set is fixed at 3
//! steps / 2 headers regardless of depth, so only the executed node count varies.
//! Expectation: per-node cost is flat (PCD proofs are constant-size), so total
//! time grows ~linearly with node count while the registry stays unchanged.
//!
//! Run with (serialized so the timings don't contend):
//!   cargo test --features multicore -p ragu_pcd --release --test num_steps \
//!       -- --nocapture --test-threads=1

use std::time::{Duration, Instant};

use ff::Field;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    Application, ApplicationBuilder, Pcd,
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};
use rand::{SeedableRng, rngs::StdRng};

const HEADER_SIZE: usize = 4;
const WARMUP: usize = 1;
const ITERS: usize = 2;

// --- Headers (both plain) ------------------------------------------------

/// Leaf output header.
struct LeafHeader;
/// Internal / root node output header (self-chaining).
struct NodeHeader;

impl<F: Field> Header<F> for LeafHeader {
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

impl<F: Field> Header<F> for NodeHeader {
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

// --- Steps (all plain, reused at every node) -----------------------------

/// Minimal seed leaf (one allocation).
struct Leaf;

impl Step<Pasta> for Leaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = LeafHeader;

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
        let output_data = leaf.value().map(|v| *v);
        let output = Encoded::from_gadget(leaf);
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

/// Lifts a pair of leaves to an internal node (minimal — no hashing).
struct LeafFuse;

impl Step<Pasta> for LeafFuse {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = LeafHeader;
    type Right = LeafHeader;
    type Output = NodeHeader;

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
        let l: &Element<'dr, D> = left.as_gadget();
        let out = l.clone();
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Self-chains two internal nodes into one (minimal — no hashing).
struct NodeFuse;

impl Step<Pasta> for NodeFuse {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = NodeHeader;
    type Right = NodeHeader;
    type Output = NodeHeader;

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
        let l: &Element<'dr, D> = left.as_gadget();
        let out = l.clone();
        let output_data = out.value().map(|v| *v);
        let output = Encoded::from_gadget(out);
        Ok(((left, right, output), output_data, D::unit()))
    }
}

fn summarize(times: &[Duration]) -> (f64, f64) {
    let min = times.iter().min().unwrap().as_secs_f64() * 1e3;
    let mean = times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / times.len() as f64 * 1e3;
    (min, mean)
}

/// Build and prove a balanced binary tree of the given `depth` (>= 1). Returns
/// the root proof. Uniform `NodeHeader` return type at every depth means the
/// recursion needs no const-generic arithmetic.
fn build_subtree(
    app: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>,
    rng: &mut StdRng,
    depth: u32,
) -> Result<Pcd<Pasta, ProductionRank, NodeHeader>> {
    let v = Fp::from(7u64);
    if depth == 1 {
        let a = app.seed(rng, Leaf, v)?.0;
        let b = app.seed(rng, Leaf, v)?.0;
        Ok(app.fuse(rng, LeafFuse, (), a, b)?.0)
    } else {
        let l = build_subtree(app, rng, depth - 1)?;
        let r = build_subtree(app, rng, depth - 1)?;
        Ok(app.fuse(rng, NodeFuse, (), l, r)?.0)
    }
}

/// Prove a depth-`d` tree `ITERS` times and print `depth`, node count, timing.
fn measure(app: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>, depth: u32) -> Result<()> {
    let nodes = (1u64 << (depth + 1)) - 1; // 2^(d+1) - 1

    let mut rng = StdRng::seed_from_u64(1234);
    for _ in 0..WARMUP {
        build_subtree(app, &mut rng, depth)?;
    }

    let mut t = Vec::new();
    for _ in 0..ITERS {
        let start = Instant::now();
        build_subtree(app, &mut rng, depth)?;
        t.push(start.elapsed());
    }

    let (min, mean) = summarize(&t);
    let per_node = mean / nodes as f64;
    std::println!("{depth:>10}{nodes:>10}{min:>11.1}{mean:>11.1}{per_node:>11.1}");
    Ok(())
}

/// Sweep the tree depth (node count) with a fixed, reused step/header set.
#[test]
fn sweep_num_steps() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(LeafFuse)?
        .register(NodeFuse)?
        .finalize(pasta)?;

    let total = app.native_registry().num_circuits();
    let log2 = total.next_power_of_two().trailing_zeros();
    std::println!(
        "\n(registered 3 steps -> {total} circuits, log2 {log2}, fixed across sweep; iters={ITERS})"
    );
    std::println!(
        "{:>10}{:>10}{:>11}{:>11}{:>11}",
        "depth",
        "nodes",
        "min(ms)",
        "avg(ms)",
        "per-node"
    );

    measure(&app, 1)?;
    measure(&app, 2)?;
    measure(&app, 3)?;
    measure(&app, 4)?;
    Ok(())
}
