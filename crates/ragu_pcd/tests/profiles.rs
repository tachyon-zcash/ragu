//! Two profiles in one binary: a standard-profile application over `Pasta`
//! at the wallet rank and an aggregator-profile application over the
//! same curves at the aggregator rank, each proving, verifying and
//! compressing its own proofs, the aggregator's with the decompression
//! circuits over the wallet application's canonical compressed proof. A
//! wallet's compressed proof enters the aggregator through its
//! decompression step, as a child its own steps fuse. The cycles are
//! distinct types, so neither application accepts the other's proofs.

use core::convert::Infallible;

use ragu_circuits::{
    polynomials::{AggregatorRank, Rank, WalletRank},
    registry::RegistryBuilder,
};
use ragu_core::{
    Cycle, Error, Result,
    pasta::{Fp, Fq, Pasta, PastaParams},
};
use ragu_pcd::{
    Application, ApplicationBuilder,
    ipa::IpaCycle,
    profile::{Aggregator, Decompression, Profiled, ProfiledCycle, Shape, Standard},
};
use ragu_testing::pcd::nontrivial::{Hash2, WitnessLeaf};
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};

const HEADER_SIZE: usize = 4;

/// Makes the wallet proof's first random field draw, `bridge_alpha`, zero.
struct FirstZero {
    first: bool,
    rest: StdRng,
}

impl TryRng for FirstZero {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        if core::mem::take(&mut self.first) {
            Ok(0)
        } else {
            Ok(self.rest.next_u32())
        }
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        if core::mem::take(&mut self.first) {
            Ok(0)
        } else {
            Ok(self.rest.next_u64())
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        if core::mem::take(&mut self.first) {
            dst.fill(0);
        } else {
            self.rest.fill_bytes(dst);
        }
        Ok(())
    }
}

impl TryCryptoRng for FirstZero {}

/// The wallet application: the standard profile at the wallet rank.
fn wallet() -> Result<Application<'static, Pasta, WalletRank, HEADER_SIZE>> {
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize(pasta)
}

fn prove_verify_compress<C, R>(app: &Application<'_, C, R, HEADER_SIZE>, seed: u64) -> Result<()>
where
    C: Cycle<Params = PastaParams, CircuitField = Fp> + ProfiledCycle + IpaCycle,
    R: Rank,
{
    let mut rng = StdRng::seed_from_u64(seed);
    let poseidon_params = C::circuit_poseidon(ragu_pcd::pasta::baked());
    let (leaf, _) = app.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(42))?;
    let (node, _) = app.fuse(&mut rng, Hash2 { poseidon_params }, (), leaf.clone(), leaf)?;
    assert!(app.verify_uncompressed(&node, &mut rng)?);
    let compressed = app.compress(&node, &mut rng)?;
    assert!(app.verify_compressed(&compressed)?);
    Ok(())
}

#[test]
fn both_profiles_prove_in_one_binary() -> Result<()> {
    let wallet = wallet()?;
    prove_verify_compress(&wallet, 1)?;

    // The aggregator's shape is its own, and it proves at the aggregator
    // rank over the wallet application's canonical compressed proof.
    type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
    assert_ne!(
        Shape::of::<Aggregator<HEADER_SIZE>>(),
        Shape::of::<Standard>()
    );
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Agg::circuit_poseidon(pasta);
    let mut rng = StdRng::seed_from_u64(2);
    let decompression = Decompression::new(wallet, &mut rng)?;
    let aggregator = ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize_with(pasta, decompression)?;
    prove_verify_compress(&aggregator, 3)?;

    // A wallet's compressed proof enters the aggregator: decompressed, it
    // verifies as a proof of the aggregator, fuses as a child of the
    // aggregator's own step, and the result compresses.
    let wallet = aggregator.context().wallet();
    let (leaf, _) = wallet.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(7))?;
    let compressed = wallet.compress(&leaf, &mut rng)?;
    let node = aggregator.decompress(&mut rng, &compressed)?;
    assert_eq!(node.data(), leaf.data());
    assert!(aggregator.verify_uncompressed(&node, &mut rng)?);
    let (parent, _) =
        aggregator.fuse(&mut rng, Hash2 { poseidon_params }, (), node.clone(), node)?;
    assert!(aggregator.verify_uncompressed(&parent, &mut rng)?);
    let compressed = aggregator.compress(&parent, &mut rng)?;
    assert!(aggregator.verify_compressed(&compressed)?);
    Ok(())
}

/// The aggregator's helper circuits fix the tags of the wallet registries
/// its decompression reads, so an aggregator over another wallet
/// application is another application: a proof it decompressed from that
/// wallet's proof does not verify under this one, uncompressed or
/// compressed.
#[test]
fn an_aggregator_over_another_wallet_is_another_application() -> Result<()> {
    type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Agg::circuit_poseidon(pasta);
    let mut rng = StdRng::seed_from_u64(5);
    let aggregator = |wallet, rng: &mut StdRng| {
        ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?
            .finalize_with(pasta, Decompression::new(wallet, rng)?)
    };
    let ours = aggregator(wallet()?, &mut rng)?;
    // The other wallet registers one step fewer.
    let other = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .finalize(pasta)?;
    let theirs = aggregator(other, &mut rng)?;

    let wallet = theirs.context().wallet();
    let (leaf, _) = wallet.seed(&mut rng, WitnessLeaf { poseidon_params }, Fp::from(7))?;
    let compressed = wallet.compress(&leaf, &mut rng)?;
    assert!(wallet.verify_compressed(&compressed)?);
    // Our wallet's verifier refuses the proof, and so does our aggregator,
    // before proving.
    let ours_wallet = ours.context().wallet();
    assert!(!matches!(
        ours_wallet.verify_compressed(&compressed),
        Ok(true)
    ));
    assert!(ours.decompress(&mut rng, &compressed).is_err());
    // The other aggregator decompresses it, into a proof of its own
    // application alone.
    let node = theirs.decompress(&mut rng, &compressed)?;
    assert!(theirs.verify_uncompressed(&node, &mut rng)?);
    assert!(!matches!(
        ours.verify_uncompressed(&node, &mut rng),
        Ok(true)
    ));
    let compressed = theirs.compress(&node, &mut rng)?;
    assert!(theirs.verify_compressed(&compressed)?);
    assert!(!matches!(ours.verify_compressed(&compressed), Ok(true)));
    Ok(())
}

/// A builder cannot replace either wallet registry the aggregator's context
/// supplies. Otherwise the verifier could certify a different source while
/// `context().wallet()` still names this wallet.
#[test]
fn an_aggregator_refuses_source_registry_overrides() -> Result<()> {
    use ragu_backend::ReferenceBackend;
    use ragu_pcd::profile::online::source::SourceRegistry;

    type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let other = Box::leak(Box::new(
        ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
            .register(WitnessLeaf { poseidon_params })?
            .finalize(pasta)?,
    ));
    let wrong_nested = Box::leak(Box::new(
        RegistryBuilder::<Fq, WalletRank>::new()
            .register_circuit(())?
            .finalize()?,
    ));
    let source_native =
        SourceRegistry::new::<WalletRank, ReferenceBackend>(other.native_registry());
    let source_nested = SourceRegistry::new::<WalletRank, ReferenceBackend>(wrong_nested);
    let mut rng = StdRng::seed_from_u64(0x894);
    for (native, nested) in [(Some(source_native), None), (None, Some(source_nested))] {
        let wallet = wallet()?;
        assert_ne!(
            wallet.native_registry().tag(),
            other.native_registry().tag()
        );
        assert_ne!(wallet.nested_registry().tag(), wrong_nested.tag());
        let result = ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
            .register(WitnessLeaf { poseidon_params })?
            .register(Hash2 { poseidon_params })?
            .with_source_registries(native, nested)
            .finalize_with(pasta, Decompression::new(wallet, &mut rng)?);
        match result {
            Err(Error::Initialization(reason)) => assert_eq!(
                reason.to_string(),
                "the builder and profile context both supply a source registry for the same field"
            ),
            Err(error) => panic!("unexpected initialization error: {error}"),
            Ok(_) => panic!("an aggregator accepted another wallet's source registry"),
        }
    }
    Ok(())
}

/// A zero bridge alpha is a valid wallet proof. Its AB bridge coefficient
/// must not force the decompression's affine point stage to hold infinity.
#[test]
fn a_zero_bridge_alpha_wallet_proof_decompresses() -> Result<()> {
    type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
    let pasta = ragu_pcd::pasta::baked_aggregator();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let wallet = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .finalize(pasta)?;
    let mut selected = FirstZero {
        first: true,
        rest: StdRng::seed_from_u64(8941),
    };
    let (leaf, _) = wallet.seed(&mut selected, WitnessLeaf { poseidon_params }, Fp::from(42))?;
    let mut rng = StdRng::seed_from_u64(894);
    assert!(wallet.verify_uncompressed(&leaf, &mut rng)?);
    let compressed = wallet.compress(&leaf, &mut rng)?;
    assert!(wallet.verify_compressed(&compressed)?);
    let aggregator = ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .finalize_with(pasta, Decompression::new(wallet, &mut rng)?)?;
    let decompressed = aggregator.decompress(&mut rng, &compressed)?;
    assert_eq!(decompressed.data(), leaf.data());
    assert!(aggregator.verify_uncompressed(&decompressed, &mut rng)?);
    let compressed = aggregator.compress(&decompressed, &mut rng)?;
    assert!(aggregator.verify_compressed(&compressed)?);
    Ok(())
}

/// A wallet compresses over the Standard tables alone: `baked()` carries
/// the generators past its table that the compression's runs commit at.
#[test]
fn a_wallet_compresses_over_the_standard_tables() -> Result<()> {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon_params = Pasta::circuit_poseidon(pasta);
    let wallet = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
        .register(WitnessLeaf { poseidon_params })?
        .register(Hash2 { poseidon_params })?
        .finalize(pasta)?;
    prove_verify_compress(&wallet, 4)
}
