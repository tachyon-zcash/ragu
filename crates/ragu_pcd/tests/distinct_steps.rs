//! Investigation B: does *executing* many distinct step types that share one
//! header raise per-node proving cost?
//!
//! Builds a left-leaning chain: a seed leaf, then at each level a distinct
//! `Filler<const I>` seed is folded into the accumulator via a shared `Fuse`
//! (everything on a single self-chaining header). Every registered filler is
//! actually executed. Sweeping the chain length N grows both the executed node
//! count and the number of distinct step circuits, so we report **per-node**
//! time: if it stays flat, distinct step *types* cost nothing beyond the node
//! itself. Compare with `distinct_headers.rs` (each filler carries its own
//! header) to isolate header multiplicity.
//!
//! Run with (serialized so the timings don't contend):
//!   cargo test --features multicore -p ragu_pcd --release --test distinct_steps \
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
const ITERS: usize = 2;

// --- One shared, self-chaining header ------------------------------------

/// Every node (leaf, filler, fuse output) carries this one header.
struct NodeHeader;

impl<F: Field> Header<F> for NodeHeader {
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

// --- Steps ---------------------------------------------------------------

/// Seed leaf anchoring the chain.
struct Leaf;

impl Step<Pasta> for Leaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = NodeHeader;

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

/// Shared fuse that folds a filler into the accumulator (minimal, self-chaining).
struct Fuse;

impl Step<Pasta> for Fuse {
    const INDEX: Index = Index::new(1);
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

/// A distinct seed step per `I` (`INDEX = I + 2`), all sharing `NodeHeader`.
/// Each one folded into the chain is executed, so N of them = N distinct step
/// circuits with one header.
struct Filler<const I: usize>;

impl<const I: usize> Step<Pasta> for Filler<I> {
    const INDEX: Index = Index::new(I + 2);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = NodeHeader;

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

fn summarize(times: &[Duration]) -> (f64, f64) {
    let min = times.iter().min().unwrap().as_secs_f64() * 1e3;
    let mean = times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / times.len() as f64 * 1e3;
    (min, mean)
}

/// Time `build` (which proves a chain that folds in `n` distinct fillers →
/// `2n + 1` nodes) and print `n`, node count, total circuits, `log2`, and
/// total / per-node time.
fn measure(
    app: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>,
    n: usize,
    build: impl Fn(&Application<'_, Pasta, ProductionRank, HEADER_SIZE>, &mut StdRng) -> Result<()>,
) -> Result<()> {
    let nodes = 2 * n + 1;
    let total = app.native_registry().num_circuits();
    let log2 = total.next_power_of_two().trailing_zeros();

    let mut rng = StdRng::seed_from_u64(1234);
    for _ in 0..WARMUP {
        build(app, &mut rng)?;
    }

    let mut t = Vec::new();
    for _ in 0..ITERS {
        let start = Instant::now();
        build(app, &mut rng)?;
        t.push(start.elapsed());
    }

    let (_min, mean) = summarize(&t);
    let per_node = mean / nodes as f64;
    std::println!("{n:>8}{nodes:>8}{total:>10}{log2:>6}{mean:>11.1}{per_node:>11.1}");
    Ok(())
}

/// One sweep point: register `Leaf` + `Fuse` + the listed distinct fillers, then
/// prove a chain that folds each filler in once. Both lists are the same literals.
macro_rules! sweep {
    ($pasta:expr, $n:expr $(; $i:literal)*) => {{
        #[allow(unused_mut)]
        let mut b = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
            .register(Leaf)?
            .register(Fuse)?;
        $( b = b.register(Filler::<$i>)?; )*
        let app = b.finalize($pasta)?;
        measure(&app, $n, |app, rng| {
            let v = Fp::from(7u64);
            let mut acc = app.seed(rng, Leaf, v)?.0;
            $(
                let f = app.seed(rng, Filler::<$i>, v)?.0;
                acc = app.fuse(rng, Fuse, (), acc, f)?.0;
            )*
            let _ = acc;
            Ok(())
        })?;
    }};
}

/// Sweep the number of distinct fuse-fed step types actually executed in the
/// chain. `total circuits = N + 17`, so N = 16 crosses the `log2` 5 → 6 boundary.
#[test]
fn sweep_distinct_steps() -> Result<()> {
    let pasta = Pasta::baked();
    std::println!("\n[shared header, iters={ITERS}]");
    std::println!(
        "{:>8}{:>8}{:>10}{:>6}{:>11}{:>11}",
        "steps", "nodes", "circuits", "log2", "avg(ms)", "per-node"
    );

    sweep!(pasta, 1; 0);
    sweep!(pasta, 4; 0; 1; 2; 3);
    sweep!(pasta, 8; 0; 1; 2; 3; 4; 5; 6; 7);
    sweep!(pasta, 16; 0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15);
    Ok(())
}
