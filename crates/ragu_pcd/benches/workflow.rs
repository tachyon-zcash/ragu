//! Fixed wallet workload used by qa/bench/run.py.
//! JSON lines retain every operation, proof shape, and deterministic digest.

use std::time::Instant;

use ragu_acceleration::AcceleratedBackend;
use ragu_circuits::polynomials::{WalletRank, Rank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder, CompressedProof, Proof,
    profile::{ProfiledCycle, Shape},
};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const H: usize = 4;
const SEED: u64 = 0;
const INPUTS: [u64; 2] = [42, 7];

fn timed<T>(
    profile: &str,
    step: &str,
    iteration: usize,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let start = Instant::now();
    let result = f()?;
    println!(
        "{{\"kind\":\"timing\",\"profile\":\"{profile}\",\"step\":\"{step}\",\"iteration\":{iteration},\"seconds\":{:.9}}}",
        start.elapsed().as_secs_f64()
    );
    Ok(result)
}

fn ordinary<C: ProfiledCycle, R: Rank>(label: &str, proof: &Proof<C, R>) {
    let bytes = proof.to_bytes().expect("ordinary proof encodes");
    println!(
        "{{\"kind\":\"proof\",\"label\":\"{label}\",\"bytes\":{},\"digest\":\"{}\"}}",
        bytes.len(),
        blake2b_simd::blake2b(&bytes).to_hex()
    );
}

fn compressed<C: ProfiledCycle, R: Rank>(profile: &str, label: &str, proof: &CompressedProof<C>) {
    let bytes = proof.to_bytes().expect("compressed proof encodes");
    let shape = Shape::of::<C::Profile>();
    let polynomials = shape.polynomials() + ragu_pcd::header::NUM_ONLINE_FP_POLYS + shape.online_fq;
    let points = polynomials + 4 * R::RANK as usize + 13;
    // The envelope and circuit index occupy 32 bytes; remaining fields
    // are canonical 32-byte Pasta points and scalars.
    assert_eq!((bytes.len() - 32) % 32, 0);
    let scalars = (bytes.len() - 32) / 32 - points;
    println!(
        "{{\"kind\":\"shape\",\"profile\":\"{profile}\",\"label\":\"{label}\",\"rank\":{},\"polynomials\":{polynomials},\"points\":{points},\"scalars\":{scalars},\"compressed_bytes\":{},\"ordinary_bytes\":{},\"digest\":\"{}\"}}",
        R::RANK,
        bytes.len(),
        Proof::<C, R>::encoded_len::<H>(),
        blake2b_simd::blake2b(&bytes).to_hex()
    );
}

fn main() -> Result<()> {
    let params = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(params);
    let mut rng = StdRng::seed_from_u64(SEED);
    let wallet = timed("wallet", "finalize", 0, || {
        ApplicationBuilder::<Pasta, WalletRank, H, AcceleratedBackend>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?
            .finalize(params)
    })?;
    let mut leaves = Vec::new();
    for (i, value) in INPUTS.into_iter().enumerate() {
        let (leaf, _) = timed("wallet", "seed", i, || {
            wallet.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(value))
        })?;
        assert!(timed("wallet", "verify_uncompressed", i, || wallet
            .verify_uncompressed(&leaf, &mut rng))?);
        let proof = timed("wallet", "compress", i, || wallet.compress(&leaf, &mut rng))?;
        assert!(timed("wallet", "verify_compressed", i, || wallet
            .verify_compressed(&proof))?);
        compressed::<_, WalletRank>("wallet", &format!("leaf_{i}"), proof.proof());
        leaves.push(leaf);
    }
    let (wallet_parent, _) = timed("wallet", "fuse", 0, || {
        wallet.fuse(
            &mut rng,
            Hash2 { poseidon_params },
            (),
            leaves[0].clone(),
            leaves[1].clone(),
        )
    })?;
    assert!(wallet.verify_uncompressed(&wallet_parent, &mut rng)?);
    ordinary("wallet_parent", wallet_parent.proof());
    println!("{{\"kind\":\"rng\",\"value\":{}}}", rng.random::<u64>());
    // Inspect the pool after measurement: doing this before finalize would
    // move thread-pool initialization out of the startup timing.
    #[cfg(feature = "multicore")]
    let workers = maybe_rayon::current_num_threads();
    #[cfg(not(feature = "multicore"))]
    let workers = 1;
    println!(
        "{{\"kind\":\"configuration\",\"workers\":{workers},\"asm_feature\":{},\"seed\":{SEED},\"header\":{H},\"inputs\":[42,7],\"backend\":\"AcceleratedBackend\"}}",
        cfg!(feature = "asm")
    );
    println!("{{\"kind\":\"complete\",\"accepted\":true}}");
    Ok(())
}
