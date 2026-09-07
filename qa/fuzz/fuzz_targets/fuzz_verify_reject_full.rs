//! Fuzz the verifier with corrupted *fused* proofs.
//!
//! `fuzz_verify_reject` corrupts a seeded leaf. This target runs the same
//! corruption vocabulary against proofs that fused something — a `Hash2` over
//! two leaves, and a `Merge2` over two of those — so checks see multiple
//! recursion depths and accumulated proof histories.
//!
//! Both fixtures are built once, in libFuzzer's `init`, and cloned per input;
//! building the deeper one runs five fuses, which no per-input budget could
//! afford.
//!
//! Invariant: as `fuzz_verify_reject` — `verify()` never panics, and never
//! accepts a corruption that bound it.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_testing_fuzz::pcd::{self, Fixture, SyncApp};
use rand::{SeedableRng, rngs::StdRng};

/// At most this many corruptions per input; see `fuzz_verify_reject`.
const MAX_CORRUPTIONS: usize = 4;

/// The application every fixture is built in: all three nontrivial steps
/// registered, so `Merge2` is reachable.
static APP: LazyLock<SyncApp> = LazyLock::new(|| pcd::nontrivial_app(3));

/// The honest proofs, built from real seeds and fuses and checked to verify.
static FIXTURES: LazyLock<Vec<Fixture>> = LazyLock::new(|| pcd::fused_fixtures(&APP.0));

#[derive(Arbitrary, Debug)]
struct Input {
    /// Which fixture to corrupt, modulo the fixture count.
    fixture: u8,
    corruptions: Vec<pcd::FuzzCorruption>,
    rng_seed: u64,
}

// The fixtures are paid for in `init`, before libFuzzer starts timing units,
// so the first input is not reported as a slow unit and written to
// `artifacts/`.
fuzz_target!(
    init: {
        if std::env::var("DEBUG_INPUT").is_err() {
            LazyLock::force(&FIXTURES);
        }
    },
    |input: Input| {
        if std::env::var("DEBUG_INPUT").is_ok() {
            eprintln!("{input:#?}");
            return;
        }
        let app = &APP.0;
        let fixtures: &Vec<Fixture> = &FIXTURES;

        let mut fixture = fixtures[input.fixture as usize % fixtures.len()].clone();
        let (applied, binding) =
            pcd::apply(&mut fixture.proof, &input.corruptions, MAX_CORRUPTIONS);
        if applied.is_empty() {
            return;
        }

        let rng = StdRng::seed_from_u64(input.rng_seed);
        pcd::assert_rejected(app, &fixture, &applied, binding, rng);
    }
);
