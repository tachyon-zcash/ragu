//! Fixed wallet/aggregator workload used by qa/bench/run.py.
//! JSON lines retain every operation, proof shape, and deterministic digest.

use std::time::Instant;

use ragu_acceleration::AcceleratedBackend;
use ragu_circuits::polynomials::{AggregatorRank, Rank, WalletRank};
use ragu_core::{
    Cycle, Result,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    ApplicationBuilder, CompressedProof, Proof,
    header::NUM_ONLINE_FP_POLYS,
    profile::{Aggregator, Decompression, Profile, Profiled, ProfiledCycle, STEP_BINDING, Shape},
};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const H: usize = 4;
const SEED: u64 = 0;
const INPUTS: [u64; 2] = [42, 7];

type Agg = Profiled<Pasta, Aggregator<H>>;

/// Requests commitment tables when `RAGU_BENCH_COMMITMENT_TABLES=1`.
///
/// The same workload builds every revision the runner compares. A revision
/// whose builder has `with_commitment_tables` resolves the call to it, since
/// inherent methods take precedence; one that predates the tables falls back
/// to this no-op.
#[allow(dead_code)]
trait CommitmentTables: Sized {
    fn with_commitment_tables(self) -> Self {
        self
    }
}

impl CommitmentTables for ApplicationBuilder<'_, Pasta, WalletRank, H, AcceleratedBackend> {}
impl CommitmentTables for ApplicationBuilder<'_, Agg, AggregatorRank, H, AcceleratedBackend> {}

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

/// Counts the fields in `wire/compressed.rs` using the public profile layout.
/// The workload also builds on revisions that predate this benchmark.
fn compressed_shape<P: Profile, R: Rank>() -> (usize, usize, usize) {
    let shape = Shape::of::<P>();
    let native = P::native_extension();
    let bound_commitments = native.binding.map_or(0, |binding| binding.online.len());
    let bound_openings = P::nested_extension()
        .binding
        .map_or(0, |binding| binding.openings.len());
    let step_binding = if native.statement.is_some() {
        STEP_BINDING - 1
    } else {
        0
    };

    // Instance commitments: each rx, both a and b on each side, registry_xy
    // and p on each side, nested_challenges_partial, and the online slots.
    let mut points =
        shape.native_rx + shape.nested_rx + 4 + 5 + NUM_ONLINE_FP_POLYS + bound_commitments;
    // Instance scalars: bridge_alpha, c and v on each side, four child (x, y)
    // pairs, four a/b evaluations, and the step and exported opening values.
    let mut scalars = 5 + 8 + 4 + step_binding + 2 * bound_openings;

    for (online, mesh) in [
        (P::NATIVE_ONLINE, P::NATIVE_MESH),
        (P::NESTED_ONLINE, P::NESTED_MESH),
    ] {
        points += online.polynomials.len();
        scalars += 2 * usize::from(!online.is_empty());
        if let Some(mesh) = mesh {
            scalars += mesh.claims_len() + mesh.polynomial_indices().len();
        }

        // Reduction (4 points, 9 scalars), batch (1 point, 11 scalars
        // plus the mesh evaluations counted above), and IPA (the initial
        // point, two points per round, and the final scalar).
        points += 4 + 1 + 1 + 2 * R::RANK as usize;
        scalars += 9 + 11 + 1;
    }
    (shape.polynomials(), points, scalars)
}

fn compressed<C: ProfiledCycle, R: Rank>(profile: &str, label: &str, proof: &CompressedProof<C>) {
    let bytes = proof.to_bytes().expect("compressed proof encodes");
    let (polynomials, points, scalars) = compressed_shape::<C::Profile, R>();
    // The envelope and circuit index occupy 32 bytes together. Check the
    // independently counted points and scalars against the encoded length.
    assert_eq!(bytes.len(), 32 + 32 * (points + scalars));
    println!(
        "{{\"kind\":\"shape\",\"profile\":\"{profile}\",\"label\":\"{label}\",\"rank\":{},\"polynomials\":{polynomials},\"points\":{points},\"scalars\":{scalars},\"compressed_bytes\":{},\"ordinary_bytes\":{},\"digest\":\"{}\"}}",
        R::RANK,
        bytes.len(),
        Proof::<C, R>::encoded_len(),
        blake2b_simd::blake2b(&bytes).to_hex()
    );
}

fn main() -> Result<()> {
    let params = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Pasta::circuit_poseidon(params);
    let mut rng = StdRng::seed_from_u64(SEED);
    let tables = std::env::var_os("RAGU_BENCH_COMMITMENT_TABLES").is_some_and(|v| v == "1");
    let wallet = timed("wallet", "finalize", 0, || {
        let builder = ApplicationBuilder::<Pasta, WalletRank, H, AcceleratedBackend>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?;
        let builder = if tables {
            builder.with_commitment_tables()
        } else {
            builder
        };
        builder.finalize(params)
    })?;
    let mut leaves = Vec::new();
    let mut proofs = Vec::new();
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
        proofs.push(proof);
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
    let context = timed("aggregator", "canonical_preparation", 0, || {
        Decompression::new(wallet, &mut rng)
    })?;
    let poseidon_params = Agg::circuit_poseidon(params);
    let aggregator = timed("aggregator", "finalize", 0, || {
        let builder = ApplicationBuilder::<Agg, AggregatorRank, H, AcceleratedBackend>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?;
        let builder = if tables {
            builder.with_commitment_tables()
        } else {
            builder
        };
        builder.finalize_with(params, context)
    })?;
    let mut nodes = Vec::new();
    for (i, proof) in proofs.iter().enumerate() {
        let node = timed("aggregator", "decompress", i, || {
            aggregator.decompress(&mut rng, proof)
        })?;
        assert_eq!(node.data(), leaves[i].data());
        assert!(timed("aggregator", "verify_uncompressed", i, || {
            aggregator.verify_uncompressed(&node, &mut rng)
        })?);
        ordinary(&format!("decompressed_{i}"), node.proof());
        nodes.push(node);
    }
    let right = nodes.pop().unwrap();
    let left = nodes.pop().unwrap();
    let (parent, _) = timed("aggregator", "fuse", 0, || {
        aggregator.fuse(&mut rng, Hash2 { poseidon_params }, (), left, right)
    })?;
    assert!(timed("aggregator", "verify_fused_uncompressed", 0, || {
        aggregator.verify_uncompressed(&parent, &mut rng)
    })?);
    ordinary("aggregator_parent", parent.proof());
    let proof = timed("aggregator", "compress", 0, || {
        aggregator.compress(&parent, &mut rng)
    })?;
    assert!(timed("aggregator", "verify_compressed", 0, || aggregator
        .verify_compressed(&proof))?);
    compressed::<_, AggregatorRank>("aggregator", "parent", proof.proof());
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
