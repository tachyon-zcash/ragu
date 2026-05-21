//! Emit a libFuzzer dictionary of Ragu's field-element constants.
//!
//! Run from the fuzz crate root:
//!
//!     cargo run --release --bin extract_dict > dict.txt
//!
//! The resulting `dict.txt` is then passed to libFuzzer via the `-dict=`
//! command-line flag. libFuzzer's mutation engine uses dictionary entries
//! as candidate splicing values, which surfaces interesting bit patterns
//! (Poseidon round constants, generators, special field values) that the
//! fuzzer would have near-zero chance of guessing randomly.
//!
//! Entries are emitted in libFuzzer dictionary format: each line is a
//! quoted byte string with `\xNN` escapes for every byte. Names are
//! omitted; libFuzzer doesn't use them for anything we care about.

use ff::{Field, PrimeField};
use ragu_arithmetic::PoseidonPermutation;
use ragu_pasta::{Fp, Fq, PoseidonFp, PoseidonFq};

/// Print an `Fp` (or `Fq`) value as a libFuzzer dictionary entry.
fn emit_repr(label: &str, idx: usize, bytes: &[u8]) {
    print!("# {label}[{idx}]\n\"");
    for b in bytes {
        print!("\\x{:02x}", b);
    }
    println!("\"");
}

fn emit_fp(label: &str, idx: usize, v: Fp) {
    emit_repr(label, idx, v.to_repr().as_ref());
}

fn emit_fq(label: &str, idx: usize, v: Fq) {
    emit_repr(label, idx, v.to_repr().as_ref());
}

fn main() {
    println!("# Auto-generated libFuzzer dictionary of Ragu field-element constants.");
    println!("# Regenerate via: cargo run --release --bin extract_dict > dict.txt");
    println!();

    // Special Fp values. Mirrors the 16-entry `special_value` tables in
    // each fuzz target — keep both lists in sync.
    emit_fp("fp_special", 0, Fp::ZERO);
    emit_fp("fp_special", 1, Fp::ONE);
    emit_fp("fp_special", 2, -Fp::ONE);
    emit_fp("fp_special", 3, -Fp::from(2));
    emit_fp("fp_special", 4, Fp::TWO_INV);
    emit_fp("fp_special", 5, Fp::from(2));
    emit_fp("fp_special", 6, Fp::from(3));
    emit_fp("fp_special", 7, Fp::from(7));
    emit_fp("fp_special", 8, Fp::ROOT_OF_UNITY);
    emit_fp("fp_special", 9, Fp::ROOT_OF_UNITY.square());
    emit_fp("fp_special", 10, Fp::ROOT_OF_UNITY.pow_vartime([4u64]));
    emit_fp("fp_special", 11, Fp::MULTIPLICATIVE_GENERATOR);
    emit_fp("fp_special", 12, Fp::MULTIPLICATIVE_GENERATOR.square());
    emit_fp("fp_special", 13, Fp::from(1u64 << 32));
    emit_fp("fp_special", 14, Fp::from(1u64 << 48));
    emit_fp("fp_special", 15, Fp::from(u64::MAX));

    // Special Fq values. Same table on the Vesta side.
    emit_fq("fq_special", 0, Fq::ZERO);
    emit_fq("fq_special", 1, Fq::ONE);
    emit_fq("fq_special", 2, -Fq::ONE);
    emit_fq("fq_special", 3, -Fq::from(2));
    emit_fq("fq_special", 4, Fq::TWO_INV);
    emit_fq("fq_special", 5, Fq::from(2));
    emit_fq("fq_special", 6, Fq::from(3));
    emit_fq("fq_special", 7, Fq::from(7));
    emit_fq("fq_special", 8, Fq::ROOT_OF_UNITY);
    emit_fq("fq_special", 9, Fq::ROOT_OF_UNITY.square());
    emit_fq("fq_special", 10, Fq::ROOT_OF_UNITY.pow_vartime([4u64]));
    emit_fq("fq_special", 11, Fq::MULTIPLICATIVE_GENERATOR);
    emit_fq("fq_special", 12, Fq::MULTIPLICATIVE_GENERATOR.square());
    emit_fq("fq_special", 13, Fq::from(1u64 << 32));
    emit_fq("fq_special", 14, Fq::from(1u64 << 48));
    emit_fq("fq_special", 15, Fq::from(u64::MAX));

    // Poseidon Fp round constants.
    let pfp = PoseidonFp;
    let mut idx = 0;
    for round in pfp.round_constants() {
        for v in round {
            emit_fp("fp_round_const", idx, *v);
            idx += 1;
        }
    }

    // Poseidon Fp MDS matrix.
    let mut idx = 0;
    for row in pfp.mds_matrix() {
        for v in row {
            emit_fp("fp_mds", idx, *v);
            idx += 1;
        }
    }

    // Poseidon Fq round constants.
    let pfq = PoseidonFq;
    let mut idx = 0;
    for round in pfq.round_constants() {
        for v in round {
            emit_fq("fq_round_const", idx, *v);
            idx += 1;
        }
    }

    // Poseidon Fq MDS matrix.
    let mut idx = 0;
    for row in pfq.mds_matrix() {
        for v in row {
            emit_fq("fq_mds", idx, *v);
            idx += 1;
        }
    }
}
