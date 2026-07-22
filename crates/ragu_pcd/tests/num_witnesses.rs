//! Investigation: does proving a PCD *tree* cost more as each step holds more
//! witnesses (allocated wires)?
//!
//! Builds a depth-2 binary tree — 4 leaves -> 2 inner fuses -> 1 root (7 proofs)
//! — where each leaf allocates `N` witness elements and does no hashing or
//! multiplication. This isolates the witness/wire dimension from the
//! multiplication-gate dimension. The application shape is fixed (3 registered
//! step types), so only the leaves' wire count varies across the sweep.
//! Expectation: total tree proving time stays roughly flat, since allocations
//! are cheap sparse-commitment coefficients and the fixed recursion pipeline
//! dominates.
//!
//! Run with (serialized so the timings don't contend):
//!   cargo test --features multicore -p ragu_pcd --release --test num_witnesses \
//!       -- --nocapture --test-threads=1

use std::time::{Duration, Instant};

use ff::Field;
use ragu_circuits::{polynomials::ProductionRank, registry::CircuitIndex};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{
    Application, ApplicationBuilder,
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
const SWEEP_ITERS: usize = 3;

/// Leaf output header.
struct LeafHdr;
/// Inner-fuse output header.
struct MidHdr;
/// Root-fuse output header.
struct RootHdr;

impl<F: Field> Header<F> for LeafHdr {
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

impl<F: Field> Header<F> for MidHdr {
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

impl<F: Field> Header<F> for RootHdr {
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

/// Seed leaf that allocates exactly `N` witness elements (no hashing) and
/// outputs the last. Each allocation is one wire.
struct Leaf<const N: usize>;

impl<const N: usize> Step<Pasta> for Leaf<N> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = LeafHdr;

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
        let mut last = Element::alloc(dr, allocator, witness)?;
        for _ in 1..N {
            let v = last.value().map(|x| *x);
            last = Element::alloc(dr, allocator, v)?;
        }
        let output_data = last.value().map(|v| *v);
        let output = Encoded::from_gadget(last);
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

/// Inner fuse: combines two leaves into a mid node (minimal — no hashing).
struct MidFuse;

impl Step<Pasta> for MidFuse {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = LeafHdr;
    type Right = LeafHdr;
    type Output = MidHdr;

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

/// Root fuse: combines the two mid nodes into the root (minimal — no hashing).
struct RootFuse;

impl Step<Pasta> for RootFuse {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = MidHdr;
    type Right = MidHdr;
    type Output = RootHdr;

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

/// Build and prove the full depth-2 tree: 4 leaves -> 2 inner fuses -> 1 root.
fn build_tree<const N: usize>(
    app: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>,
    rng: &mut StdRng,
) -> Result<()> {
    let v = Fp::from(7u64);
    let l0 = app.seed(rng, Leaf::<N>, v)?.0;
    let l1 = app.seed(rng, Leaf::<N>, v)?.0;
    let l2 = app.seed(rng, Leaf::<N>, v)?.0;
    let l3 = app.seed(rng, Leaf::<N>, v)?.0;
    let m0 = app.fuse(rng, MidFuse, (), l0, l1)?.0;
    let m1 = app.fuse(rng, MidFuse, (), l2, l3)?.0;
    let _root = app.fuse(rng, RootFuse, (), m0, m1)?.0;
    Ok(())
}

/// Build the 3-step application whose leaves each hold `N` witnesses, then time
/// building the whole tree. Prints witness count, the leaf's gate/constraint
/// counts, and min/mean tree-proving time.
fn sweep_point<const N: usize>() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .register(Leaf::<N>)?
        .register(MidFuse)?
        .register(RootFuse)?
        .finalize(pasta)?;

    let reg = app.native_registry();
    // Application circuits are the last three; the leaf is the first of them.
    let (leaf_gates, leaf_constr) =
        reg.constraint_counts(CircuitIndex::new(reg.num_circuits() - 3));

    let mut rng = StdRng::seed_from_u64(1234);
    for _ in 0..WARMUP {
        build_tree::<N>(&app, &mut rng)?;
    }

    let mut t = Vec::new();
    for _ in 0..SWEEP_ITERS {
        let start = Instant::now();
        build_tree::<N>(&app, &mut rng)?;
        t.push(start.elapsed());
    }

    let (min, mean) = summarize(&t);
    std::println!("{N:>10}{leaf_gates:>10}{leaf_constr:>10}{min:>11.1}{mean:>11.1}");
    Ok(())
}

/// Sweep the per-leaf witness count from 1 up toward the wire cap and watch how
/// total tree proving time responds. Each allocation costs ~half a gate
/// (`gates ~= N/2 + 1`), so the ceiling is ~4092 allocations; 4096 already
/// exceeds the 2048-gate bound, so the top point is 4000 (≈2001 gates).
#[test]
fn sweep_num_witnesses() -> Result<()> {
    std::println!("\n[iters={SWEEP_ITERS}]");
    std::println!(
        "{:>10}{:>10}{:>10}{:>11}{:>11}",
        "witnesses",
        "gates",
        "constr",
        "min(ms)",
        "avg(ms)"
    );
    sweep_point::<1>()?;
    sweep_point::<{ 1 << 9 }>()?;
    sweep_point::<{ 1 << 10 }>()?;
    sweep_point::<{ 1 << 11 }>()?;
    sweep_point::<{ (1 << 12) - 4 }>()?;
    sweep_point::<{ 1 << 12 }>().expect_err("should bust");
    Ok(())
}
