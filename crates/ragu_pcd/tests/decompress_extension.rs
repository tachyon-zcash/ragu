//! The decompression circuits as the aggregator profile's extension: the
//! pinned layout is the schedules', the hooks register every chunk, the
//! statement and binding circuits and every stage at the aggregator rank
//! and refuse the production rank, and an application over the profile
//! builds at the aggregator rank, where every fuse circuit fits with the
//! extension's polynomials, and its bootstrap proof verifies with the
//! chunks run over the wallet application's canonical compressed proof. A
//! wallet proof decompresses into a proof of the aggregator carrying its
//! header; one relabelled on the way fails, and so does one whose two
//! sides were prepared from different compressed proofs.

use ragu_circuits::{
    polynomials::{AggregatorRank, ProductionRank, Rank},
    registry::RegistryBuilder,
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, allocator::Allocator};
use rand::{SeedableRng, rngs::StdRng};

use super::{native, native_counts, nested, nested_counts};
use crate::{
    Application, ApplicationBuilder,
    decompress::{
        prover::Decompressed,
        run::Sides,
        support::{HEADER_SIZE, Setup, TestR},
    },
    header::{Header, Suffix},
    profile::{Aggregator, Decompression, Profile, Profiled, Shape, Standard},
    step::{Encoded, Index, Step, internal::decompress::Decompress},
};

type P = Aggregator<HEADER_SIZE>;

/// The pinned layouts are the schedules' at the aggregator rank, for the
/// test header size and for the internal tests', and lay out as the
/// module says: transcript chunks first and digits chunks last, over six
/// native stages and five nested ones, with the statement and binding
/// circuits after the chunks.
#[test]
fn pinned_layout_is_the_schedules() {
    assert_eq!(
        P::native_circuits(HEADER_SIZE),
        native_counts::<Pasta, ProductionRank, AggregatorRank, HEADER_SIZE>().unwrap(),
        "the native pins for the test header size"
    );
    assert_eq!(
        P::NESTED_CIRCUITS,
        nested_counts::<Pasta, ProductionRank, AggregatorRank, HEADER_SIZE>().unwrap(),
        "the nested pins"
    );
    assert_eq!(
        Aggregator::<103>::native_circuits(103),
        native_counts::<Pasta, ProductionRank, AggregatorRank, 103>().unwrap(),
        "the native pins for the internal tests' header size"
    );
    assert_eq!(
        P::native_extension(),
        native::<Pasta, ProductionRank, AggregatorRank, HEADER_SIZE>().unwrap()
    );
    assert_eq!(
        P::nested_extension(),
        nested::<Pasta, ProductionRank, AggregatorRank, HEADER_SIZE>().unwrap()
    );
    assert_eq!(
        Aggregator::<103>::native_extension(),
        native::<Pasta, ProductionRank, AggregatorRank, 103>().unwrap()
    );
    assert_eq!(
        Aggregator::<103>::nested_extension(),
        nested::<Pasta, ProductionRank, AggregatorRank, 103>().unwrap()
    );

    let native = P::native_extension();
    let counts = P::native_circuits(HEADER_SIZE);
    let (chunks, transcript, digits) = (counts.chunks, counts.transcript, counts.digits);
    assert_eq!(native.circuits.len(), chunks + 2);
    assert_eq!(native.stages, 6);
    assert!(
        native.circuits[..transcript]
            .iter()
            .all(|c| c == &[0, 1, 2, 3, 4])
    );
    assert!(
        native.circuits[transcript..chunks - digits]
            .iter()
            .all(|c| c == &[0, 1, 2, 3])
    );
    assert!(
        native.circuits[chunks - digits..chunks]
            .iter()
            .all(|c| c == &[0, 1, 2, 3, 5])
    );
    assert_eq!(native.circuits[chunks], [0]);
    assert_eq!(native.circuits[chunks + 1], [0, 1, 2, 3]);
    assert_eq!(native.statement, Some(chunks as u32));
    let binding = native.binding.as_ref().expect("the native side binds");
    assert_eq!(binding.circuit, chunks as u32 + 1);
    assert_eq!(binding.stages, [0, 1, 2, 4]);
    assert_eq!(native.final_masks.len(), 4);
    assert_eq!(
        native.final_masks[0].len(),
        chunks - transcript - digits + 1
    );
    assert_eq!(native.final_masks[1].len(), transcript);
    assert_eq!(native.final_masks[2].len(), digits);
    assert_eq!(native.final_masks[3], [chunks as u32]);
    assert!(native.is_consistent());

    let nested = P::nested_extension();
    let counts = P::NESTED_CIRCUITS;
    let (chunks, digits) = (counts.chunks, counts.digits);
    assert_eq!(nested.circuits.len(), chunks + 1);
    assert_eq!(nested.stages, 5);
    assert!(
        nested.circuits[..chunks - digits]
            .iter()
            .all(|c| c == &[0, 1, 2, 3])
    );
    assert!(
        nested.circuits[chunks - digits..chunks]
            .iter()
            .all(|c| c == &[0, 1, 2, 3, 4])
    );
    assert_eq!(nested.circuits[chunks], [0, 1, 2, 3]);
    assert_eq!(nested.final_masks.len(), 2);
    assert_eq!(nested.final_masks[0].len(), chunks - digits + 1);
    assert_eq!(nested.final_masks[1].len(), digits);
    assert_eq!(nested.statement, None);
    let binding = nested.binding.as_ref().expect("the nested side binds");
    assert_eq!(binding.circuit, chunks as u32);
    assert_eq!(binding.stages, [5]);
    assert!(nested.is_consistent());
    P::check().unwrap();
}

/// Every chunk and bonding of both sides registers through the hooks at
/// the aggregator rank, one past the last fails, and the production rank
/// is refused.
#[test]
fn hooks_register_every_chunk_and_stage() {
    let params = crate::pasta::baked();
    let native = P::native_extension();
    let mut registry = RegistryBuilder::<Fp, AggregatorRank>::new();
    for circuit in 0..native.circuits.len() {
        registry = P::register_native_circuit::<Pasta, AggregatorRank, HEADER_SIZE>(
            circuit, registry, params,
        )
        .unwrap();
    }
    for bonding in 0..native.bondings() {
        registry = P::register_native_bonding::<Pasta, AggregatorRank, HEADER_SIZE>(
            bonding, registry, params,
        )
        .unwrap();
    }
    assert_eq!(registry.num_internal_circuits(), native.internal());
    assert!(matches!(
        P::register_native_bonding::<Pasta, AggregatorRank, HEADER_SIZE>(
            native.bondings(),
            registry,
            params
        ),
        Err(Error::Initialization(_))
    ));
    assert!(matches!(
        P::register_native_circuit::<Pasta, TestR, HEADER_SIZE>(0, RegistryBuilder::new(), params),
        Err(Error::Initialization(_))
    ));

    let nested = P::nested_extension();
    let mut registry = RegistryBuilder::<Fq, AggregatorRank>::new();
    for circuit in 0..nested.circuits.len() {
        registry =
            P::register_nested_circuit::<Pasta, AggregatorRank>(circuit, registry, params).unwrap();
    }
    for bonding in 0..nested.bondings() {
        registry =
            P::register_nested_bonding::<Pasta, AggregatorRank>(bonding, registry, params).unwrap();
    }
    assert_eq!(registry.num_internal_circuits(), nested.internal());
    assert!(matches!(
        P::register_nested_circuit::<Pasta, TestR>(0, RegistryBuilder::new(), params),
        Err(Error::Initialization(_))
    ));
}

/// The profile's shape is wider than the standard one, and an application
/// over it builds at the aggregator rank: every fuse circuit fits the
/// budget with the extension's polynomials, every chunk circuit registers
/// beside them, and the bootstrap proof, with the chunks run over the
/// wallet application's canonical compressed proof, verifies.
#[test]
fn the_fuse_fits_at_the_aggregator_rank() {
    let standard = Shape::of::<Standard>();
    let shape = Shape::of::<P>();
    assert_eq!(
        shape.native_rx,
        standard.native_rx + P::NATIVE_EXTENSION + shape.native_steps - standard.native_steps
    );
    // The walks fold more points at fewer steps per the profile's
    // endoscalings per step.
    assert!(shape.nested_points > standard.nested_points);
    assert!(shape.nested_steps < standard.nested_steps);

    let setup = Setup::new();
    let mut rng = StdRng::seed_from_u64(5);
    let decompression = Decompression::new(setup.app, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .finalize_with(crate::pasta::baked(), decompression)
        .unwrap();
    let bootstrap = app.bootstrap.clone().expect("finalized").carry::<()>(());
    assert!(app.verify(&bootstrap, &mut rng).unwrap());
}

/// A header carrying one field element.
struct Value;

impl Header<Fp> for Value {
    const SUFFIX: Suffix = Suffix::new(7);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// A seed step outputting its witness as a [`Value`] header.
struct Leaf;

impl<C: Cycle<CircuitField = Fp>> Step<C> for Leaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, Value, H>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::new(dr, allocator, witness.clone())?;
        Ok(((left, right, output), witness, D::unit()))
    }
}

/// A wallet application with a leaf step, for proofs with a header.
fn wallet() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap()
}

/// A wallet's compressed proof decompresses into a proof of the aggregator
/// carrying the wallet proof's header and data, which verifies; the same
/// decompression under another header fails, since the statement circuit's
/// claim holds the decompression step's output header to the decompressed
/// statement's.
#[test]
fn decompresses_a_wallet_proof() {
    let pasta = crate::pasta::baked();
    let mut rng = StdRng::seed_from_u64(9);
    let wallet = wallet();
    let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
    let compressed = wallet.compress(&leaf, &mut rng).unwrap();
    assert!(wallet.verify_compressed(&compressed).unwrap());

    let decompression = Decompression::new(wallet, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(pasta, decompression)
        .unwrap();
    let node = app.decompress(&mut rng, &compressed).unwrap();
    assert_eq!(*node.data(), Fp::from(42));
    assert!(app.verify(&node, &mut rng).unwrap());

    let decompressed = app.context().prepare(&compressed).unwrap();
    let (relabelled, ()) = app
        .fuse_with_source(
            &mut rng,
            Decompress::<Value>::new(),
            Fp::from(43),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&decompressed),
        )
        .unwrap();
    assert!(
        !matches!(app.verify(&relabelled, &mut rng), Ok(true)),
        "a relabelled decompression fails"
    );
}

/// A decompression whose circuit-field side was prepared from one
/// compression of a wallet proof and whose scalar-field side from another
/// fails: each side is consistent with itself, and every chunk of both
/// accepts, but the binding circuits' claims hold each side's view of
/// the other to that side's actual stages, which the two compressions'
/// challenges, scalars and messages do not share. Without the binding the
/// proof verifies, with each side verifying a compressed proof of its
/// own.
#[test]
fn sides_from_different_proofs_are_rejected() {
    let pasta = crate::pasta::baked();
    let mut rng = StdRng::seed_from_u64(23);
    let wallet = wallet();
    let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
    let first = wallet.compress(&leaf, &mut rng).unwrap();
    let second = wallet.compress(&leaf, &mut rng).unwrap();
    assert!(wallet.verify_compressed(&first).unwrap());
    assert!(wallet.verify_compressed(&second).unwrap());

    let decompression = Decompression::new(wallet, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(pasta, decompression)
        .unwrap();
    let first = app.context().prepare(&first).unwrap();
    let second = app.context().prepare(&second).unwrap();
    let mixed = Decompressed(Sides {
        native: first.0.native,
        nested: second.0.nested,
    });
    let (node, ()) = app
        .fuse_with_source(
            &mut rng,
            Decompress::<Value>::new(),
            Fp::from(42),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&mixed),
        )
        .unwrap();
    assert!(
        !matches!(app.verify(&node, &mut rng), Ok(true)),
        "a decompression of two proofs fails"
    );
    let compressed = app.compress(&node, &mut rng).unwrap();
    assert!(
        !matches!(app.verify_compressed(&compressed), Ok(true)),
        "and so does its compression"
    );
}

/// A step fusing two [`Value`] headers into their sum.
struct Join;

impl<C: Cycle<CircuitField = Fp>> Step<C> for Join {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Value;
    type Right = Value;
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Value, H>,
            Encoded<'dr, D, Value, H>,
            Encoded<'dr, D, Value, H>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let left_element = Element::alloc(dr, allocator, left)?;
        let right_element = Element::alloc(dr, allocator, right)?;
        let sum = left_element.add(dr, &right_element);
        let data = sum.value().map(|v| *v);
        Ok((
            (
                Encoded::from_gadget(left_element),
                Encoded::from_gadget(right_element),
                Encoded::from_gadget(sum),
            ),
            data,
            D::unit(),
        ))
    }
}

/// The points and scalars one curve's messages carry: the fold's two
/// commitments and two epsilons, p and q, the openings; the batch's f and
/// evaluations; the IPA's s, rounds and c.
fn messages_size<P: udon::curve::Affine>(
    messages: &crate::compress::Messages<P>,
) -> (usize, usize) {
    let points = 2 + 2 + 1 + 1 + 2 * messages.opening.rounds.len();
    let scalars = 2 + messages.reduction.openings.len() + messages.batch.evaluations.len() + 1;
    (points, scalars)
}

/// The points and scalars a compressed proof carries over the cycle.
fn compressed_size<C: Cycle>(proof: &crate::CompressedProof<C>) -> (usize, usize) {
    let instance = &proof.instance;
    let points = instance.native.len() + 2 + instance.nested.len() + 3;
    let scalars = instance.left_header.len() + instance.right_header.len() + 1 + 4 + 1 + 6 + 4 + 4;
    let native = messages_size(&proof.native);
    let nested = messages_size(&proof.nested);
    (points + native.0 + nested.0, scalars + native.1 + nested.1)
}

/// The coefficients an uncompressed proof stores: its sparse rx
/// polynomials' blocks, `registry_xy` and `p` on each side, and the two
/// accumulators per side taken as dense.
fn stored_coefficients<C: crate::profile::ProfiledCycle, R: Rank>(
    proof: &crate::Proof<C, R>,
) -> usize {
    use crate::internal::{native, nested};
    let mut stored = 0;
    for index in native::RxIndex::all::<C::Profile>() {
        stored += proof[index].iter_stored_coeffs().count();
    }
    for index in nested::RxIndex::all::<C::Profile>() {
        stored += proof[index].iter_stored_coeffs().count();
    }
    stored += proof.native_registry_xy_poly().iter_stored_coeffs().count();
    stored += proof.native_p_poly().iter_stored_coeffs().count();
    stored += proof.nested_registry_xy_poly().iter_stored_coeffs().count();
    stored += proof.nested_p_poly().iter_stored_coeffs().count();
    stored + 4 * R::num_coeffs()
}

/// Timings and sizes of both roles, printed; run alone on an idle machine
/// with `--ignored --nocapture`.
#[test]
#[ignore]
fn timings() {
    use std::time::Instant;

    let pasta = crate::pasta::baked();
    let mut rng = StdRng::seed_from_u64(21);
    macro_rules! timed {
        ($label:expr, $e:expr) => {{
            let start = Instant::now();
            let value = $e;
            std::println!("{:<40} {:>8.2} s", $label, start.elapsed().as_secs_f64());
            value
        }};
    }
    let report = |role: &str,
                  polynomials: usize,
                  rank: u32,
                  stored: usize,
                  (points, scalars): (usize, usize)| {
        std::println!(
            "{role}: {polynomials} polynomials of 2^{rank} coefficients ({:.1} MB dense, {:.1} MB stored); compressed proof {points} points + {scalars} scalars ({:.1} KB at 32 bytes each)",
            polynomials as f64 * (1u64 << rank) as f64 * 32.0 / 1e6,
            stored as f64 * 32.0 / 1e6,
            (points + scalars) as f64 * 32.0 / 1e3
        );
    };

    // The wallet.
    let wallet = timed!(
        "wallet finalize (registries + bootstrap)",
        ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(Join)
            .unwrap()
            .finalize(pasta)
            .unwrap()
    );
    let (leaf_a, _) = timed!(
        "wallet seed (one fuse)",
        wallet.seed(&mut rng, Leaf, Fp::from(1)).unwrap()
    );
    let (leaf_b, _) = wallet.seed(&mut rng, Leaf, Fp::from(2)).unwrap();
    let (node, _) = timed!(
        "wallet fuse (two children)",
        wallet.fuse(&mut rng, Join, (), leaf_a, leaf_b).unwrap()
    );
    assert!(timed!(
        "wallet verify (uncompressed)",
        wallet.verify(&node, &mut rng).unwrap()
    ));
    let compressed = timed!("wallet compress", wallet.compress(&node, &mut rng).unwrap());
    assert!(timed!(
        "wallet verify_compressed",
        wallet.verify_compressed(&compressed).unwrap()
    ));
    report(
        "wallet",
        Shape::of::<Standard>().polynomials(),
        ProductionRank::RANK,
        stored_coefficients(node.proof()),
        compressed_size(compressed.proof()),
    );

    // The aggregator.
    let decompression = timed!(
        "aggregator canonical decompression",
        Decompression::new(wallet, &mut rng).unwrap()
    );
    let aggregator = timed!(
        "aggregator finalize (registries + bootstrap)",
        ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(Join)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap()
    );
    let _ = timed!(
        "aggregator prepare (native chunk run)",
        aggregator.context().prepare(&compressed).unwrap()
    );
    let node_a = timed!(
        "aggregator decompress (prepare + fuse)",
        aggregator.decompress(&mut rng, &compressed).unwrap()
    );
    let node_b = aggregator.decompress(&mut rng, &compressed).unwrap();
    let parent = timed!(
        "aggregator fuse (two children)",
        aggregator
            .fuse(&mut rng, Join, (), node_a, node_b)
            .unwrap()
            .0
    );
    assert!(timed!(
        "aggregator verify (uncompressed)",
        aggregator.verify(&parent, &mut rng).unwrap()
    ));
    let compressed = timed!(
        "aggregator compress",
        aggregator.compress(&parent, &mut rng).unwrap()
    );
    assert!(timed!(
        "aggregator verify_compressed",
        aggregator.verify_compressed(&compressed).unwrap()
    ));
    report(
        "aggregator",
        Shape::of::<P>().polynomials(),
        AggregatorRank::RANK,
        stored_coefficients(parent.proof()),
        compressed_size(compressed.proof()),
    );
}
