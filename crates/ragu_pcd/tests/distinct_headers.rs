//! Investigation C: does registering many *distinct step types that each carry a
//! distinct header* raise per-proof cost (case 4 of the complexity gradient)?
//!
//! Identical to `distinct_steps.rs` in every way — same fixed used tree (seed two
//! leaves -> one fuse, 3 proofs), same `N` registered-but-unused fillers, same
//! circuit count at equal `N` — EXCEPT each `Filler<const I>` outputs its own
//! `FillerHeader<const I>` instead of a shared one. So comparing this file's
//! timings to `distinct_steps.rs` at equal `N` isolates the marginal cost of
//! header multiplicity at fixed circuit count. This is the const-param'd
//! distinct-steps-and-headers case hypothesized to "should increase" complexity.
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
const ITERS: usize = 3;

// --- Headers -------------------------------------------------------------

/// Leaf / used-fuse header (plain). The used tree is homogeneous in it.
struct LeafHeader;
/// Per-filler header, one distinct type per index (`Suffix::new(I + 2)`).
struct FillerHeader<const I: usize>;

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

impl<const I: usize, F: Field> Header<F> for FillerHeader<I> {
    const SUFFIX: Suffix = Suffix::new(I + 2);
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

/// Plain seed leaf (one allocation).
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

/// The one fuse actually executed by the measured tree (minimal, self-chaining).
struct UsedFuse;

impl Step<Pasta> for UsedFuse {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = LeafHeader;
    type Right = LeafHeader;
    type Output = LeafHeader;

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

/// Registered-but-unused filler seed step, `INDEX = I + 2`, each with its own
/// distinct `FillerHeader<I>` — so `N` fillers add `N` circuits AND `N` headers.
struct Filler<const I: usize>;

impl<const I: usize> Step<Pasta> for Filler<I> {
    const INDEX: Index = Index::new(I + 2);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = FillerHeader<I>;

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

/// Build an application with `Leaf` + `UsedFuse` plus the listed fillers (each
/// bringing its own header), then finalize. Requires the enclosing fn to return
/// `Result`.
macro_rules! app_with_fillers {
    ($pasta:expr $(, $i:literal)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut b = ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
            .register(Leaf)?
            .register(UsedFuse)?;
        $( b = b.register(Filler::<$i>)?; )*
        b.finalize($pasta)?
    }};
}

fn summarize(times: &[Duration]) -> (f64, f64) {
    let min = times.iter().min().unwrap().as_secs_f64() * 1e3;
    let mean = times.iter().map(|d| d.as_secs_f64()).sum::<f64>() / times.len() as f64 * 1e3;
    (min, mean)
}

/// The fixed measured work: seed two leaves and fuse them (3 proofs).
fn build_used(app: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>, rng: &mut StdRng) -> Result<()> {
    let v = Fp::from(7u64);
    let a = app.seed(rng, Leaf, v)?.0;
    let b = app.seed(rng, Leaf, v)?.0;
    let _ = app.fuse(rng, UsedFuse, (), a, b)?.0;
    Ok(())
}

/// Time the fixed tree in `app` and print `N` (registered fillers = distinct
/// headers), total circuits, `log2`, and min/mean time.
fn measure(
    app: &Application<'_, Pasta, ProductionRank, HEADER_SIZE>,
    n_fillers: usize,
) -> Result<()> {
    let total = app.native_registry().num_circuits();
    let log2 = total.next_power_of_two().trailing_zeros();

    let mut rng = StdRng::seed_from_u64(1234);
    for _ in 0..WARMUP {
        build_used(app, &mut rng)?;
    }

    let mut t = Vec::new();
    for _ in 0..ITERS {
        let start = Instant::now();
        build_used(app, &mut rng)?;
        t.push(start.elapsed());
    }

    let (min, mean) = summarize(&t);
    std::println!("{n_fillers:>10}{total:>10}{log2:>10}{min:>11.1}{mean:>11.1}");
    Ok(())
}

/// Sweep the number of distinct registered fillers, each with its own header.
/// Same circuit totals as `distinct_steps.rs` (`N + 17`), so compare row-for-row.
#[test]
fn sweep_distinct_headers() -> Result<()> {
    let pasta = Pasta::baked();
    std::println!("\n[distinct headers, iters={ITERS}]");
    std::println!("{:>10}{:>10}{:>10}{:>11}{:>11}", "fillers", "circuits", "log2", "min(ms)", "avg(ms)");

    measure(&app_with_fillers!(pasta), 0)?;
    measure(&app_with_fillers!(pasta, 0, 1, 2, 3, 4, 5, 6, 7), 8)?;
    measure(
        &app_with_fillers!(pasta, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
        15,
    )?;
    measure(
        &app_with_fillers!(pasta, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        16,
    )?;
    Ok(())
}
