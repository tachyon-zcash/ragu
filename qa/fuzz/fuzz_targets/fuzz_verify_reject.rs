//! Fuzz the verifier with corrupted proofs.
//!
//! Applies fuzzer-chosen corruptions to a valid leaf proof, one or several at
//! a time. A leaf is the cheapest proof `verify` actually accepts, so the
//! per-input cost is a clone, a corruption and a verify — this is the target
//! that explores the corruption vocabulary at speed.
//! `fuzz_verify_reject_full` runs the same vocabulary against fused proofs,
//! whose accumulators are not degenerate.
//!
//! Invariant: `verify()` never panics, and never accepts a corruption that
//! bound it (`Ok(false)` or `Err` are both rejections). A corruption the
//! verifier is *not* obliged to notice — a blinding coefficient no claim
//! binds — is still exercised, but its verdict is not asserted; see
//! [`ragu_pcd::fuzzing::corrupt`] for how the two are told apart.
//!
//! This target used to corrupt Ragu's synthesized dummy proof. That fixture is
//! the placeholder the internal Bootstrap step consumes, and `verify` rejects
//! it outright — so "the verifier did not accept the corrupted proof" held
//! before the corruption too, and every assertion passed vacuously.
//! [`ragu_testing_fuzz::pcd`] now checks each fixture verifies before handing
//! it over.

#![no_main]

use std::sync::LazyLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ragu_testing_fuzz::pcd::{self, Fixture, SyncApp};
use rand::{SeedableRng, rngs::StdRng};

/// At most this many corruptions per input. Enough for the coordinated
/// mutations that need a second edit to reach a check, bounded so one input
/// cannot rewrite the whole proof into noise.
const MAX_CORRUPTIONS: usize = 4;

/// One registered step is all a leaf needs.
static APP: LazyLock<SyncApp> = LazyLock::new(|| pcd::nontrivial_app(1));

/// The cached honest leaf. Seeding one runs the full endoscaling pipeline
/// (over a second per call), but the result is deterministic from `&APP.0`.
/// Cloning the cached value is orders of magnitude faster than rebuilding, so
/// the hot path is clone + corrupt + verify rather than build + corrupt +
/// verify.
static LEAF: LazyLock<Fixture> = LazyLock::new(|| pcd::leaf_fixture(&APP.0));

#[derive(Arbitrary, Debug)]
struct Input {
    corruptions: Vec<pcd::FuzzCorruption>,
    rng_seed: u64,
}

// The fixture is paid for in `init`, before libFuzzer starts timing units, so
// the first input is not reported as a slow unit and written to `artifacts/`.
fuzz_target!(
    init: {
        if std::env::var("DEBUG_INPUT").is_err() {
            LazyLock::force(&LEAF);
        }
    },
    |input: Input| {
        // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful
        // for triaging crash artifacts. See README.md "DEBUG_INPUT env var".
        if std::env::var("DEBUG_INPUT").is_ok() {
            eprintln!("{input:#?}");
            return;
        }
        let app = &APP.0;

        let mut fixture = LEAF.clone();
        let (applied, binding) =
            pcd::apply(&mut fixture.proof, &input.corruptions, MAX_CORRUPTIONS);
        if applied.is_empty() {
            return;
        }

        let rng = StdRng::seed_from_u64(input.rng_seed);
        pcd::assert_rejected(app, &fixture, &applied, binding, rng);
    }
);
