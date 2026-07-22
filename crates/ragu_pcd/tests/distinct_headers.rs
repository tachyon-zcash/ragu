//! Investigation C: does *executing* a chain whose every level carries a
//! distinct header raise per-node proving cost?
//!
//! Identical shape to `distinct_steps.rs` — a left-leaning chain folding a fresh
//! seed in at each level — EXCEPT each level produces its own distinct header
//! `Hdr<const I>` via a distinct `Fuse<IN, OUT>`. A depth-N chain threads N + 1
//! distinct headers through N distinct fuse circuits, all executed. Sweeping N
//! grows the executed node count, so we report **per-node** time; comparing it
//! to `distinct_steps.rs` (one shared header) at equal N isolates the marginal
//! cost of header multiplicity.
//!
//! Run with (serialized so the timings don't contend):
//!   cargo test --features multicore -p ragu_pcd --release --test distinct_headers \
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

// --- One distinct header per level ---------------------------------------

/// Level-`I` node header (`Suffix::new(I)`). Leaves are `Hdr<0>`; each fuse
/// lifts its accumulator from `Hdr<IN>` to `Hdr<OUT>`.
struct Hdr<const I: usize>;

impl<const I: usize, F: Field> Header<F> for Hdr<I> {
    const SUFFIX: Suffix = Suffix::new(I);
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

/// Seed leaf; every folded-in leaf (and the anchor) is `Hdr<0>`.
struct Leaf;

impl Step<Pasta> for Leaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Hdr<0>;

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

/// Folds an `Hdr<0>` leaf into an `Hdr<IN>` accumulator, producing `Hdr<OUT>`.
/// `INDEX = OUT`, so registering `Fuse<0,1>, Fuse<1,2>, …` is sequential.
struct Fuse<const IN: usize, const OUT: usize>;

impl<const IN: usize, const OUT: usize> Step<Pasta> for Fuse<IN, OUT> {
    const INDEX: Index = Index::new(OUT);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Hdr<IN>;
    type Right = Hdr<0>;
    type Output = Hdr<OUT>;

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

/// Time `build` (which proves an N-level chain → `2n + 1` nodes) and print
/// `n`, node count, total circuits, `log2`, and total / per-node time.
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

/// One sweep point: register `Leaf` + the listed per-level fuses, then prove a
/// chain that lifts through each distinct header. `acc` is re-bound (shadowed)
/// each level because its header type changes from `Hdr<IN>` to `Hdr<OUT>`.
macro_rules! sweep {
    ($pasta:expr, $n:expr $(; $in:literal => $out:literal)*) => {{
        #[allow(unused_mut)]
        let mut b = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
            .register(Leaf)?;
        $( b = b.register(Fuse::<$in, $out>)?; )*
        let app = b.finalize($pasta)?;
        measure(&app, $n, |app, rng| {
            let v = Fp::from(7u64);
            let acc = app.seed(rng, Leaf, v)?.0;
            $(
                let leaf = app.seed(rng, Leaf, v)?.0;
                let acc = app.fuse(rng, Fuse::<$in, $out>, (), acc, leaf)?.0;
            )*
            let _ = acc;
            Ok(())
        })?;
    }};
}

/// Sweep the number of distinct headers threaded through the chain. `total
/// circuits = N + 16`, so N = 16 crosses the `log2` 5 → 6 boundary.
#[test]
fn sweep_distinct_headers() -> Result<()> {
    let pasta = Pasta::baked();
    std::println!("\n[distinct headers, iters={ITERS}]");
    std::println!(
        "{:>8}{:>8}{:>10}{:>6}{:>11}{:>11}",
        "levels", "nodes", "circuits", "log2", "avg(ms)", "per-node"
    );

    sweep!(pasta, 1; 0 => 1);
    sweep!(pasta, 4; 0 => 1; 1 => 2; 2 => 3; 3 => 4);
    sweep!(pasta, 8; 0 => 1; 1 => 2; 2 => 3; 3 => 4; 4 => 5; 5 => 6; 6 => 7; 7 => 8);
    sweep!(pasta, 16;
        0 => 1; 1 => 2; 2 => 3; 3 => 4; 4 => 5; 5 => 6; 6 => 7; 7 => 8;
        8 => 9; 9 => 10; 10 => 11; 11 => 12; 12 => 13; 13 => 14; 14 => 15; 15 => 16);
    Ok(())
}
