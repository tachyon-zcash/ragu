//! Fuzz the verifier with corrupted proofs.
//!
//! Creates a valid trivial proof once at startup, then applies fuzzer-chosen
//! corruptions and asserts `verify()` never panics. Each [`Corruption`] variant
//! targets a different verification check (commitment, evaluation, revdot
//! claims, registry lookup, header size).
//!
//! Invariant: `verify()` must never panic regardless of proof contents.
//! Corrupted proofs must be rejected (`Ok(false)`) or produce `Err`.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Pasta;
use ragu_pcd::{ApplicationBuilder, test_utils::Corruption};
use rand::{SeedableRng, rngs::StdRng};

use std::sync::LazyLock;

type C = Pasta;
type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// Wrapper to satisfy `Sync` for `Application` (which contains `OnceCell`).
/// Safe because libfuzzer is single-threaded.
struct SyncApp(ragu_pcd::Application<'static, C, R, HEADER_SIZE>);
// SAFETY: libfuzzer runs the fuzz target on a single thread.
unsafe impl Sync for SyncApp {}

static APP: LazyLock<SyncApp> = LazyLock::new(|| {
    let pasta = Pasta::baked();
    SyncApp(
        ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .finalize(pasta)
            .expect("failed to create application"),
    )
});

#[derive(Arbitrary, Debug)]
enum FuzzCorruption {
    PBlind(u64),
    PEval(u64),
    AbC(u64),
    CircuitId(u32),
    ChallengeU(u64),
    ChallengeX(u64),
    ChallengeY(u64),
    LeftHeaderLen(u8),
    RightHeaderLen(u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    corruption: FuzzCorruption,
    rng_seed: u64,
}

fuzz_target!(|input: Input| {
    let app = &APP.0;

    let mut proof = app.test_trivial_proof();

    let corruption = match input.corruption {
        FuzzCorruption::PBlind(v) => Corruption::PBlind(Fp::from(v)),
        FuzzCorruption::PEval(v) => Corruption::PEval(Fp::from(v)),
        FuzzCorruption::AbC(v) => Corruption::AbC(Fp::from(v)),
        FuzzCorruption::CircuitId(v) => Corruption::CircuitId(v),
        FuzzCorruption::ChallengeU(v) => Corruption::ChallengeU(Fp::from(v)),
        FuzzCorruption::ChallengeX(v) => Corruption::ChallengeX(Fp::from(v)),
        FuzzCorruption::ChallengeY(v) => Corruption::ChallengeY(Fp::from(v)),
        FuzzCorruption::LeftHeaderLen(v) => Corruption::LeftHeaderLen(v as usize),
        FuzzCorruption::RightHeaderLen(v) => Corruption::RightHeaderLen(v as usize),
    };

    proof.corrupt(corruption);

    let pcd = proof.carry::<()>(());
    let rng = StdRng::seed_from_u64(input.rng_seed);

    // Must never panic. Corrupted proofs should be rejected.
    let _ = app.verify(&pcd, rng);
});
