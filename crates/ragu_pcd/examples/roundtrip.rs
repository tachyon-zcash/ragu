//! A wallet proof's round trip through an aggregator.
//!
//! A wallet application at the production rank proves two leaves and
//! compresses each, as a wallet does for the wire. An aggregator
//! application at the aggregator rank decompresses each compressed proof
//! into a proof of its own over the same data, fuses the two as the
//! children of its own step and compresses the result, which verifies as
//! any compressed proof does. Every proof system call is timed, on the
//! single-threaded reference backend unless `--features multicore`
//! selects the parallel one.
//!
//! ```text
//! cargo run --release -p ragu_pcd --example roundtrip
//! ```

use std::time::Instant;

use ragu_circuits::polynomials::{AggregatorRank, ProductionRank, Rank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder,
    profile::{Aggregator, Decompression, Profiled},
};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

/// The headers' size in field elements, the same for both applications.
const HEADER_SIZE: usize = 4;

/// The aggregator's cycle: the wallet's curves under the aggregator
/// profile.
type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;

/// Runs `f`, printing `label` and how long it took.
fn timed<T>(label: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let start = Instant::now();
    let value = f()?;
    println!("  {label:<40} {:>6.2} s", start.elapsed().as_secs_f64());
    Ok(value)
}

fn main() -> Result<()> {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let mut rng = StdRng::seed_from_u64(0);

    println!(
        "wallet: the standard profile at rank {}",
        ProductionRank::RANK
    );
    let wallet = timed("finalize", || {
        ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?
            .finalize(pasta)
    })?;

    // Two transactions: a leaf each, proved and compressed for the wire.
    let mut leaves = Vec::new();
    let mut compressed = Vec::new();
    for value in [42u64, 7] {
        let (leaf, _) = timed("seed a leaf", || {
            wallet.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(value))
        })?;
        let proof = timed("compress", || wallet.compress(&leaf, &mut rng))?;
        let accepted = timed("verify_compressed", || wallet.verify_compressed(&proof))?;
        assert!(accepted, "the wallet's compressed proof verifies");
        leaves.push(leaf);
        compressed.push(proof);
    }

    println!(
        "aggregator: the aggregator profile at rank {}",
        AggregatorRank::RANK
    );
    let poseidon_params = Agg::circuit_poseidon(pasta);
    let decompression = timed("canonical decompression", || {
        Decompression::new(wallet, &mut rng)
    })?;
    let aggregator = timed("finalize", || {
        ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?
            .finalize_with(pasta, decompression)
    })?;

    // Each compressed proof decompresses into a proof of the aggregator
    // over the same data, which the aggregator verifies as its own.
    let mut nodes = Vec::new();
    for (leaf, proof) in leaves.iter().zip(&compressed) {
        let node = timed("decompress", || aggregator.decompress(&mut rng, proof))?;
        assert_eq!(node.data(), leaf.data(), "the data round-trips");
        let accepted = timed("verify (uncompressed)", || {
            aggregator.verify(&node, &mut rng)
        })?;
        assert!(accepted, "the decompressed proof verifies");
        nodes.push(node);
    }

    // The two decompressed proofs fuse as the children of the aggregator's
    // own step, and the result compresses: one proof for both transactions.
    let right = nodes.pop().expect("two decompressed proofs");
    let left = nodes.pop().expect("two decompressed proofs");
    let (parent, _) = timed("fuse the two", || {
        aggregator.fuse(&mut rng, Hash2 { poseidon_params }, (), left, right)
    })?;
    let proof = timed("compress", || aggregator.compress(&parent, &mut rng))?;
    let accepted = timed("verify_compressed", || aggregator.verify_compressed(&proof))?;
    assert!(accepted, "the aggregator's compressed proof verifies");

    println!("round trip complete: two wallet proofs in one aggregator proof");
    Ok(())
}
