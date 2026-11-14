//! One production-rank fuse, timed end to end and by stage.
//!
//! Run with
//! `cargo bench -p ragu_pcd --features multicore,stage-timing --bench fuse_experiment`.
//!
//! The timed region is one `Application::fuse` call together with the clones
//! of its two children. Setup, child construction, verification and
//! compression are outside it. Every timed proof is verified uncompressed and
//! compressed, and every proof of a configuration must have the same bytes.
//!
//! Environment:
//!
//! * `FUSE_WORKERS`: worker threads (default 10).
//! * `FUSE_SAMPLES`: fuses per pass (default 16).
//! * `FUSE_PASSES`: passes over the backends, alternating order (default 2).
//! * `FUSE_BACKENDS`: comma-separated subset of `reference`, `accelerated`
//!   (default `accelerated`).
//! * `FUSE_WORKLOAD`: `leaf` fuses `Hash2` over two seeded `WitnessLeaf`
//!   proofs (default); `merge` fuses `Merge2` over two `Hash2` proofs.

use std::{
    collections::BTreeMap,
    hint::black_box,
    time::{Duration, Instant},
};

use ragu_acceleration::AcceleratedProver;
use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{ApplicationBuilder, SelectableBackend};
use ragu_testing::pcd::nontrivial;
use rand::{SeedableRng, rngs::StdRng};

/// Stages in pipeline order, as `Application::fuse` marks them.
const STAGES: [&str; 13] = [
    "clone",
    "application",
    "preamble",
    "s_prime",
    "inner_error",
    "outer_error",
    "ab",
    "query",
    "f",
    "eval",
    "p",
    "circuits",
    "build",
];

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().expect("a number"))
        .unwrap_or(default)
}

fn fingerprint(bytes: &[u8]) -> String {
    let hash = blake2b_simd::Params::new().hash_length(8).hash(bytes);
    hash.to_hex().to_string()
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort();
    let mid = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        (samples[mid - 1] + samples[mid]) / 2
    } else {
        samples[mid]
    }
}

struct Outcome {
    median: Duration,
    min: Duration,
    max: Duration,
    /// Mean processor time of one timed region, over every thread.
    cpu: Duration,
    stages: BTreeMap<&'static str, Duration>,
    /// Mean total and count per fuse of each recorded span.
    spans: BTreeMap<&'static str, (Duration, usize)>,
    fingerprint: String,
}

/// The processor time this process has used so far, over every thread.
fn cpu_time() -> Duration {
    let mut total = 0u64;
    if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
        for task in tasks.flatten() {
            if let Ok(stat) = std::fs::read_to_string(task.path().join("schedstat")) {
                total += stat
                    .split_whitespace()
                    .next()
                    .and_then(|ns| ns.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
    }
    Duration::from_nanos(total)
}

fn run<B: SelectableBackend>(workload: &str, samples: usize) -> Outcome {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let app = ApplicationBuilder::<Pasta, ProductionRank, 4>::new()
        .with_backend::<B>()
        .register(nontrivial::WitnessLeaf { poseidon_params })
        .unwrap()
        .register(nontrivial::Hash2 { poseidon_params })
        .unwrap()
        .register(nontrivial::Merge2 { poseidon_params })
        .unwrap()
        .finalize(pasta)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(1234);
    let [l1, l2, l3, l4] = [1, 2, 3, 4].map(|value| {
        app.seed(
            &mut rng,
            nontrivial::WitnessLeaf { poseidon_params },
            Fp::from(value),
        )
        .unwrap()
        .0
    });

    let mut totals = Vec::with_capacity(samples);
    let mut cpu = Duration::ZERO;
    let mut stages: BTreeMap<&'static str, Duration> = BTreeMap::new();
    let mut spans: BTreeMap<&'static str, (Duration, usize)> = BTreeMap::new();
    let mut prints = Vec::with_capacity(samples);

    // One timed fuse: returns the proof bytes and both verification results.
    macro_rules! sample {
        ($step:expr, $left:expr, $right:expr) => {{
            let mut rng = StdRng::seed_from_u64(5678);
            ragu_pcd::timing::take_spans();
            let cpu_before = cpu_time();
            let start = Instant::now();
            let (left, right) = ($left.clone(), $right.clone());
            let cloned = start.elapsed();
            let (proof, _) = app
                .fuse(&mut rng, $step, (), black_box(left), black_box(right))
                .unwrap();
            totals.push(start.elapsed());
            *stages.entry("clone").or_default() += cloned;
            cpu += cpu_time().saturating_sub(cpu_before);
            for (name, elapsed) in ragu_pcd::timing::take() {
                *stages.entry(name).or_default() += elapsed;
            }
            for (name, elapsed) in ragu_pcd::timing::take_spans() {
                let span = spans.entry(name).or_default();
                span.0 += elapsed;
                span.1 += 1;
            }
            assert!(
                app.verify_uncompressed(&proof, StdRng::seed_from_u64(0xfeed))
                    .unwrap()
            );
            let compressed = app
                .compress(&proof, &mut StdRng::seed_from_u64(0xc0de))
                .unwrap();
            assert!(app.verify_compressed(&compressed).unwrap());
            prints.push(fingerprint(&proof.proof().to_bytes().unwrap()));
        }};
    }

    match workload {
        "leaf" => {
            // One untimed fuse first, so lazily built tables are not charged
            // to the first sample.
            let warm = (l1.clone(), l2.clone());
            app.fuse(
                &mut StdRng::seed_from_u64(5678),
                nontrivial::Hash2 { poseidon_params },
                (),
                warm.0,
                warm.1,
            )
            .unwrap();
            ragu_pcd::timing::take();
            for _ in 0..samples {
                sample!(nontrivial::Hash2 { poseidon_params }, l1, l2);
            }
        }
        "merge" => {
            let (left, _) = app
                .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l1, l2)
                .unwrap();
            let (right, _) = app
                .fuse(&mut rng, nontrivial::Hash2 { poseidon_params }, (), l3, l4)
                .unwrap();
            ragu_pcd::timing::take();
            for _ in 0..samples {
                sample!(nontrivial::Merge2 { poseidon_params }, left, right);
            }
        }
        other => panic!("unknown FUSE_WORKLOAD {other}"),
    }

    assert!(
        prints.iter().all(|print| print == &prints[0]),
        "proofs differ between runs: {prints:?}"
    );
    for elapsed in stages.values_mut() {
        *elapsed /= samples as u32;
    }
    for span in spans.values_mut() {
        span.0 /= samples as u32;
        span.1 /= samples;
    }
    Outcome {
        cpu: cpu / samples as u32,
        spans,
        min: *totals.iter().min().unwrap(),
        max: *totals.iter().max().unwrap(),
        median: median(&mut totals),
        stages,
        fingerprint: prints.swap_remove(0),
    }
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn main() {
    let workers = env_usize("FUSE_WORKERS", 10);
    let samples = env_usize("FUSE_SAMPLES", 16);
    let passes = env_usize("FUSE_PASSES", 2);
    let workload = std::env::var("FUSE_WORKLOAD").unwrap_or_else(|_| "leaf".into());
    let backends = std::env::var("FUSE_BACKENDS").unwrap_or_else(|_| "accelerated".into());
    let mut backends: Vec<&str> = backends.split(',').collect();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .unwrap();
    println!("workload={workload} workers={workers} samples={samples} passes={passes}");

    let mut prints: BTreeMap<String, String> = BTreeMap::new();
    for pass in 1..=passes {
        for backend in &backends {
            let outcome = pool.install(|| match *backend {
                "reference" => run::<ReferenceBackend>(&workload, samples),
                "accelerated" => run::<AcceleratedProver>(&workload, samples),
                other => panic!("unknown backend {other}"),
            });
            println!(
                "pass {pass} {backend:<12} median {:9.2} ms  (min {:.2}, max {:.2})  fingerprint {}",
                ms(outcome.median),
                ms(outcome.min),
                ms(outcome.max),
                outcome.fingerprint,
            );
            let staged: Duration = outcome.stages.values().sum();
            for stage in STAGES {
                if let Some(elapsed) = outcome.stages.get(stage) {
                    println!(
                        "    {stage:<12} {:9.2} ms  {:5.1}%",
                        ms(*elapsed),
                        100.0 * elapsed.as_secs_f64() / staged.as_secs_f64(),
                    );
                }
            }
            println!("    {:<12} {:9.2} ms", "all stages", ms(staged));
            println!(
                "    {:<12} {:9.2} ms  (the fuse's return and drops)",
                "remainder",
                ms(outcome.median.saturating_sub(staged)),
            );
            println!(
                "    {:<12} {:9.2} ms  ({:.1} cores busy on average)",
                "cpu time",
                ms(outcome.cpu),
                outcome.cpu.as_secs_f64() / outcome.median.as_secs_f64(),
            );
            for (name, (elapsed, count)) in &outcome.spans {
                println!("      {name:<34} {:8.2} ms  x{count}", ms(*elapsed));
            }
            prints.insert(backend.to_string(), outcome.fingerprint);
        }
        backends.reverse();
    }

    let mut distinct: Vec<&String> = prints.values().collect();
    distinct.dedup();
    assert!(
        distinct.len() == 1,
        "backends produced different proofs: {prints:?}"
    );
}
