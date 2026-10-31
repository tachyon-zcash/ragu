//! Byte-boundary fuzzing through the production proof verification paths.
//!
//! A tiny control input mutates a valid proof generated once per process. This
//! reaches beyond the fixed envelope without committing a multi-megabyte proof.
//! Raw inputs still exercise the decoder independently of the seed generator.
use std::sync::LazyLock;

use ragu_pcd::ProofContext;
use ragu_testing::pcd::nontrivial::LeafNode;
use rand::{SeedableRng, rngs::StdRng};

use crate::pcd::{self, NativeField, SyncApp};

static APP: LazyLock<SyncApp> = LazyLock::new(|| pcd::nontrivial_app(1));
static SEED: LazyLock<Seed> = LazyLock::new(|| {
    let app = &APP.0;
    let mut rng = StdRng::seed_from_u64(0x77697265);
    let proof = pcd::seed(app, &mut rng, 42);
    let format = app.proof_format(context());
    let compressed = app.compress(&proof, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
    Seed {
        data: *proof.data(),
        proof: format.encode(proof.proof()).unwrap(),
        compressed: format.encode_compressed(compressed.proof()).unwrap(),
    }
});

struct Seed {
    data: NativeField,
    proof: Vec<u8>,
    compressed: Vec<u8>,
}

fn context() -> ProofContext {
    ProofContext {
        suite: [31; 32],
        application: [47; 32],
    }
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
// are admitted. No input can request an unbounded allocation or fresh proof tree.
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
        // representation checks. The envelope is version 2 (124 bytes).
        5 => {
            let offset = match kind {
                Kind::Proof => 124,
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
    let format = app.proof_format(context());
    let mut outcome = Outcome::default();
    match kind {
        Kind::Proof => {
            if let Ok(decoded) = format.decode(&bytes) {
                outcome.decoded = true;
                assert!(
                    format.encode(&decoded).unwrap() == bytes,
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
            if let Ok(decoded) = format.decode_compressed(&bytes) {
                outcome.decoded = true;
                assert!(
                    format.encode_compressed(&decoded).unwrap() == bytes,
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
        for (kind, inputs) in [
            (
                Kind::Proof,
                [
                    include_bytes!("../regressions/fuzz_proof_wire/raw").as_slice(),
                    include_bytes!("../regressions/fuzz_proof_wire/valid").as_slice(),
                    include_bytes!("../regressions/fuzz_proof_wire/scalar").as_slice(),
                ],
            ),
            (
                Kind::Compressed,
                [
                    include_bytes!("../regressions/fuzz_compressed_wire/raw").as_slice(),
                    include_bytes!("../regressions/fuzz_compressed_wire/valid").as_slice(),
                    include_bytes!("../regressions/fuzz_compressed_wire/scalar").as_slice(),
                ],
            ),
        ] {
            assert!(!exercise(kind, inputs[0]).decoded);
            assert_eq!(exercise(kind, inputs[1]).verified, Some(true));
            assert!(exercise(kind, inputs[2]).decoded);
            assert!(!exercise(kind, &[3]).decoded);
            assert!(!exercise(kind, &[4]).decoded);
            assert!(!exercise(kind, &[2, 0, 0, 0, 0, 1]).decoded);
        }
        // A changed final IPA coefficient remains decodable and must reach
        // the real verifier. Do not generalize this to all possible mutations.
        assert_eq!(exercise(Kind::Compressed, &[5]).verified, Some(false));
    }
}
