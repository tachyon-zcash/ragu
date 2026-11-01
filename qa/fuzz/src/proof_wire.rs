//! Byte-boundary fuzzing through the production proof verification paths.
//!
//! A tiny control input mutates a valid proof generated once per process. This
//! reaches beyond the fixed envelope without committing a multi-megabyte proof.
//! Raw inputs exercise envelope and dimension checks independently of the seed
//! generator. Full raw payload decoding also needs an input limit large enough
//! for the encoded proof; mutation modes reach payloads beyond that limit.
use std::sync::LazyLock;

use ragu_pcd::{CompressedProof, Proof};
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};

use crate::pcd::{self, NativeField, SyncApp};

static APP: LazyLock<SyncApp> = LazyLock::new(|| pcd::nontrivial_app(1));
static SEED: LazyLock<Seed> = LazyLock::new(|| {
    let app = &APP.0;
    let mut rng = StdRng::seed_from_u64(0x77697265);
    let proof = pcd::seed(app, &mut rng, 42);
    let compressed = app.compress(&proof, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
    Seed {
        data: *proof.data(),
        proof: proof.proof().to_bytes().unwrap(),
        compressed: compressed.proof().to_bytes().unwrap(),
    }
});

struct Seed {
    data: NativeField,
    proof: Vec<u8>,
    compressed: Vec<u8>,
}

/// Which wire payload the target exercises.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Proof,
    Compressed,
}

/// Materialize the valid seed once before exercising target inputs.
pub fn initialize() {
    LazyLock::force(&SEED);
}

/// Evidence used by the CI smoke test: decoding alone is not verification.
#[derive(Default, Debug)]
pub struct Outcome {
    pub decoded: bool,
    pub verified: Option<bool>,
}

// The first byte selects raw bytes, unchanged seed, sparse XOR edits, truncation,
// append, or a canonical scalar replacement. Only 32 edits / 128 appended bytes
// are admitted. Raw mode copies at most the fuzzer's input limit; mutation modes
// copy a fixed-size seed. No input can request a fresh proof tree.
fn candidate(kind: Kind, input: &[u8]) -> Vec<u8> {
    let seed = match kind {
        Kind::Proof => &SEED.proof,
        Kind::Compressed => &SEED.compressed,
    };
    let (&mode, edits) = input.split_first().unwrap_or((&0, &[]));
    if mode % 6 == 0 {
        return edits.to_vec();
    }
    let mut bytes = seed.clone();
    match mode % 6 {
        1 => {}
        2 => {
            for edit in edits.chunks_exact(5).take(32) {
                let offset =
                    u32::from_le_bytes(edit[..4].try_into().unwrap()) as usize % bytes.len();
                bytes[offset] ^= edit[4];
            }
        }
        3 => {
            let mut count = [0; 4];
            for (dst, src) in count.iter_mut().zip(edits) {
                *dst = *src;
            }
            bytes.truncate(u32::from_le_bytes(count) as usize % bytes.len());
        }
        4 => bytes.extend_from_slice(if edits.is_empty() {
            &[0]
        } else {
            &edits[..edits.len().min(128)]
        }),
        // Zero is canonical in the first proof scalar (bridge alpha) and
        // final compressed scalar (nested IPA c). These edits reach beyond
        // representation checks. The envelope is version 3 (28 bytes).
        5 => {
            let offset = match kind {
                Kind::Proof => 28,
                Kind::Compressed => bytes.len() - 32,
            };
            bytes[offset..offset + 32].fill(0);
        }
        _ => unreachable!(),
    }
    bytes
}

/// Decode, enforce a canonical byte round trip, and invoke the production path.
/// A changed input may still be a valid proof: acceptance is not itself a bug.
/// Panics, noncanonical successful decoding, or rejection of the untouched seed
/// are bugs. Errors from compression or verification are valid rejection.
pub fn exercise(kind: Kind, input: &[u8]) -> Outcome {
    let bytes = candidate(kind, input);
    let app = &APP.0;
    let mut outcome = Outcome::default();
    match kind {
        Kind::Proof => {
            if let Ok(decoded) = Proof::from_bytes(&bytes) {
                outcome.decoded = true;
                assert!(
                    decoded.to_bytes().unwrap() == bytes,
                    "noncanonical proof encoding"
                );
                let mut rng = StdRng::seed_from_u64(0xdec0de);
                if let Ok(compressed) =
                    app.compress(&decoded.carry::<LeafNode>(SEED.data), &mut rng)
                {
                    outcome.verified = Some(app.verify_compressed(&compressed).unwrap_or(false));
                }
            }
        }
        Kind::Compressed => {
            if let Ok(decoded) = CompressedProof::from_bytes(&bytes) {
                outcome.decoded = true;
                assert!(
                    decoded.to_bytes().unwrap() == bytes,
                    "noncanonical compressed encoding"
                );
                outcome.verified = Some(
                    app.verify_compressed(&decoded.carry::<LeafNode>(SEED.data))
                        .unwrap_or(false),
                );
            }
        }
    }
    if input.first().is_some_and(|mode| mode % 6 == 1) {
        assert_eq!(
            outcome.verified,
            Some(true),
            "untouched {kind:?} proof rejected"
        );
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "production-rank proof generation; run in release in CI"]
    fn decode_to_verify_smoke() {
        initialize();
        // The control inputs: raw bytes that are no proof, the unchanged seed
        // and a canonical scalar replacement.
        const RAW: &[u8] = b"\x00bad proof";
        const VALID: &[u8] = &[1];
        const SCALAR: &[u8] = &[5];
        for kind in [Kind::Proof, Kind::Compressed] {
            assert!(!exercise(kind, RAW).decoded);
            assert_eq!(exercise(kind, VALID).verified, Some(true));
            assert!(exercise(kind, SCALAR).decoded);
            assert!(!exercise(kind, &[3]).decoded);
            assert!(!exercise(kind, &[4]).decoded);
            assert!(!exercise(kind, &[2, 0, 0, 0, 0, 1]).decoded);
        }
        // A changed final IPA coefficient remains decodable and must reach
        // the real verifier. Do not generalize this to all possible mutations.
        assert_eq!(exercise(Kind::Compressed, &[5]).verified, Some(false));
    }
}
