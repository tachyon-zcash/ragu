//! The decompression circuits as the aggregator profile's extension: the
//! pinned layout is the schedules', the hooks register every chunk, the
//! statement and binding circuits and every stage at the aggregator rank
//! and refuse the wallet rank, and an application over the profile
//! builds at the aggregator rank, where every fuse circuit fits with the
//! extension's polynomials, and its bootstrap proof verifies with the
//! chunks run over the wallet application's canonical compressed proof. A
//! wallet proof decompresses into a proof of the aggregator carrying its
//! header; one relabelled on the way fails, and so do one whose two
//! sides were prepared from different compressed proofs and one of another
//! wallet application's registry.

use alloc::{string::ToString, vec::Vec};

use ragu_circuits::{
    polynomials::{AggregatorRank, Rank, WalletRank},
    registry::{CircuitIndex, RegistryBuilder},
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, GadgetExt, allocator::Allocator};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{native, native_counts, nested, nested_counts};
use crate::{
    Application, ApplicationBuilder, CompressedProof,
    decompress::{
        prover::{Decompressed, Sides},
        stages::num_runs,
        support::{HEADER_SIZE, Setup, TestR},
    },
    header::{Dummy, Header, Suffix},
    profile::{
        Aggregator, CircuitSlot, Decompression, MaskSlot, Profile, Profiled, Shape, Standard,
    },
    step::{Encoded, Index, Step, internal::decompress::Decompress},
};

type P = Aggregator<HEADER_SIZE>;

fn padding() -> [Vec<Fp>; 2] {
    core::array::from_fn(|_| alloc::vec![Fp::ONE])
}

/// The pinned layouts match the schedules at the aggregator rank at sampled
/// header widths and every width-band boundary, and lay out as the
/// module says: transcript chunks first and digits chunks last, over six
/// native stages and, on the nested side, a stage per run, the trailing
/// stage and the lifts, work and digits stages, with the statement and
/// binding circuits after the chunks.
#[test]
fn pinned_layout_is_the_schedules() {
    /// The internal tests' header size.
    const CENSUS: usize = crate::internal::tests::HEADER_SIZE;
    fn check_native_counts<const H: usize>() {
        assert_eq!(
            Aggregator::<H>::native_circuits(H),
            native_counts::<Pasta, WalletRank, AggregatorRank, H>().unwrap(),
            "native circuit counts at header size {H}"
        );
    }
    check_native_counts::<HEADER_SIZE>();
    check_native_counts::<CENSUS>();
    check_native_counts::<195>();
    // Every header size compiles its own copy of the schedule, which the
    // CI runners cannot afford in this test target, so the nightly tests
    // check the rest of the range and the boundaries between transcript
    // counts.
    #[cfg(ragu_pcd_nightly_tests)]
    {
        check_native_counts::<1>();
        check_native_counts::<2>();
        check_native_counts::<3>();
        check_native_counts::<9>();
        check_native_counts::<57>();
        check_native_counts::<58>();
        check_native_counts::<100>();
        check_native_counts::<153>();
        check_native_counts::<154>();
    }
    assert_eq!(
        P::NESTED_CIRCUITS,
        nested_counts::<Pasta, WalletRank, AggregatorRank, HEADER_SIZE>().unwrap(),
        "the nested pins"
    );
    assert_eq!(
        P::native_extension(),
        native::<Pasta, WalletRank, AggregatorRank, HEADER_SIZE>().unwrap()
    );
    assert_eq!(
        P::nested_extension(),
        nested::<Pasta, WalletRank, AggregatorRank, HEADER_SIZE>().unwrap()
    );
    assert_eq!(
        Aggregator::<CENSUS>::native_extension(),
        native::<Pasta, WalletRank, AggregatorRank, CENSUS>().unwrap()
    );
    assert_eq!(
        Aggregator::<CENSUS>::nested_extension(),
        nested::<Pasta, WalletRank, AggregatorRank, CENSUS>().unwrap()
    );

    let native = P::native_extension();
    let counts = P::native_circuits(HEADER_SIZE);
    let (chunk_circuits, transcript, digits) = (counts.circuits, counts.transcript, counts.digits);
    assert_eq!(native.circuits.len(), chunk_circuits + 2);
    assert_eq!(native.stages, 6);
    assert!(
        native.circuits[..transcript]
            .iter()
            .all(|c| c == &[0, 1, 2, 3, 4])
    );
    assert!(
        native.circuits[transcript..chunk_circuits - digits]
            .iter()
            .all(|c| c == &[0, 1, 2, 3])
    );
    assert!(
        native.circuits[chunk_circuits - digits..chunk_circuits]
            .iter()
            .all(|c| c == &[0, 1, 2, 3, 5])
    );
    assert_eq!(native.circuits[chunk_circuits], [0]);
    assert_eq!(native.circuits[chunk_circuits + 1], [0, 1, 2, 3]);
    assert_eq!(native.statement, Some(chunk_circuits as u32));
    let runs = num_runs::<WalletRank>() as u32;
    let binding = native.binding.as_ref().expect("the native side binds");
    assert_eq!(binding.circuit, chunk_circuits as u32 + 1);
    assert_eq!(
        binding.stages,
        (0..runs).chain([runs + 1, runs + 3]).collect::<Vec<_>>(),
        "the run stages, then the lifts and digits stages"
    );
    assert_eq!(native.final_masks.len(), 4);
    assert_eq!(
        native.final_masks[0].len(),
        chunk_circuits - transcript - digits + 1
    );
    assert_eq!(native.final_masks[1].len(), transcript);
    assert_eq!(native.final_masks[2].len(), digits);
    assert_eq!(native.final_masks[3], [chunk_circuits as u32]);
    assert!(native.is_consistent());

    let nested = P::nested_extension();
    let counts = P::NESTED_CIRCUITS;
    let (chunk_circuits, digits) = (counts.circuits, counts.digits);
    assert_eq!(nested.circuits.len(), chunk_circuits + 1);
    assert_eq!(nested.stages as u32, runs + 4);
    let common: Vec<u32> = (0..runs + 3).collect();
    let with_digits: Vec<u32> = (0..runs + 4).collect();
    assert!(
        nested.circuits[..chunk_circuits - digits]
            .iter()
            .all(|c| c == &common)
    );
    assert!(
        nested.circuits[chunk_circuits - digits..chunk_circuits]
            .iter()
            .all(|c| c == &with_digits)
    );
    assert_eq!(nested.circuits[chunk_circuits], common);
    assert_eq!(nested.final_masks.len(), 2);
    assert_eq!(nested.final_masks[0].len(), chunk_circuits - digits + 1);
    assert_eq!(nested.final_masks[1].len(), digits);
    assert_eq!(nested.statement, None);
    let binding = nested.binding.as_ref().expect("the nested side binds");
    assert_eq!(binding.circuit, chunk_circuits as u32);
    assert_eq!(binding.stages, [5]);
    assert!(nested.is_consistent());
    P::check().unwrap();
}

/// Every chunk and mask of both sides registers through the hooks at
/// the aggregator rank at the maximum profile width. One past the last
/// fails, and the wallet rank is refused.
#[test]
fn hooks_register_every_chunk_and_stage() {
    const H: usize = 195;
    type Wide = Aggregator<H>;

    let params = crate::pasta::baked_aggregator();
    let native = Wide::native_extension();
    let mut registry = RegistryBuilder::<Fp, AggregatorRank>::new();
    for circuit in 0..native.circuits.len() {
        registry = Wide::register_native_circuit::<Pasta, AggregatorRank, H>(
            circuit,
            CircuitSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    for mask in 0..native.masks() {
        registry = Wide::register_native_mask::<Pasta, AggregatorRank, H>(
            mask,
            MaskSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    assert_eq!(registry.num_internal_circuits(), native.internal());
    assert!(matches!(
        Wide::register_native_mask::<Pasta, AggregatorRank, H>(
            native.masks(),
            MaskSlot::new(registry),
            params
        ),
        Err(Error::Initialization(_))
    ));
    assert!(matches!(
        Wide::register_native_circuit::<Pasta, TestR, H>(
            0,
            CircuitSlot::new(RegistryBuilder::new()),
            params
        ),
        Err(Error::Initialization(_))
    ));

    let nested = Wide::nested_extension();
    let mut registry = RegistryBuilder::<Fq, AggregatorRank>::new();
    for circuit in 0..nested.circuits.len() {
        registry = Wide::register_nested_circuit::<Pasta, AggregatorRank>(
            circuit,
            CircuitSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    for mask in 0..nested.masks() {
        registry = Wide::register_nested_mask::<Pasta, AggregatorRank>(
            mask,
            MaskSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    assert_eq!(registry.num_internal_circuits(), nested.internal());
    assert!(matches!(
        Wide::register_nested_circuit::<Pasta, TestR>(
            0,
            CircuitSlot::new(RegistryBuilder::new()),
            params
        ),
        Err(Error::Initialization(_))
    ));
}

/// The profile's shape is wider than the standard one, and an application
/// over it builds at the aggregator rank: every fuse circuit fits the
/// budget with the extension's polynomials, every chunk circuit registers
/// beside them and none can stand in for an application circuit, and the
/// bootstrap proof, with the chunks run over the wallet application's
/// canonical compressed proof, verifies.
#[test]
fn the_fuse_fits_at_the_aggregator_rank() {
    let standard = Shape::of::<Standard>();
    let shape = Shape::of::<P>();
    // The extension's polynomials, the online batch's three stages and its
    // helper's, and the walk's.
    assert_eq!(
        shape.native_rx,
        standard.native_rx
            + P::NATIVE_EXTENSION
            + crate::profile::online::stages::RXS
            + shape.native_steps
            - standard.native_steps
    );
    // The walks fold more points at fewer steps per the profile's
    // endoscalings per step.
    assert!(shape.nested_points > standard.nested_points);
    assert!(shape.nested_steps < standard.nested_steps);

    let setup = Setup::new();
    let mut rng = StdRng::seed_from_u64(5);
    let decompression = Decompression::new(setup.app, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .finalize_with(crate::pasta::baked_aggregator(), decompression)
        .unwrap();
    crate::internal::tests::assert_only_steps_satisfy_application_instances(&app);
    let bootstrap = app.bootstrap.clone().expect("finalized").carry::<()>(());
    assert!(app.verify_uncompressed(&bootstrap, &mut rng).unwrap());
}

/// A header carrying one field element.
struct Value;

impl Header<Fp> for Value {
    const SUFFIX: Suffix = Suffix::new(7);
    type OnlinePolyCommit = (crate::header::Padding, crate::header::Padding);
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

/// A header of another type at [`Value`]'s suffix.
struct Other;

impl Header<Fp> for Other {
    const SUFFIX: Suffix = Suffix::new(7);
    type OnlinePolyCommit = (crate::header::Padding, crate::header::Padding);
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

/// A seed step outputting its witness as an [`Other`] header.
struct OtherLeaf;

impl<C: Cycle<CircuitField = Fp>> Step<C> for OtherLeaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Other;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, Other, H>,
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
        _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
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

/// A kind of online polynomial.
#[derive(Clone, Copy)]
struct Carried;

impl crate::header::OnlinePoly for Carried {}

#[derive(Clone, Copy)]
struct CarriedSecond;
impl crate::header::OnlinePoly for CarriedSecond {}

/// A header with two application polynomials.
struct Carrying;

impl Header<Fp> for Carrying {
    const SUFFIX: Suffix = Suffix::new(8);
    type OnlinePolyCommit = (Carried, CarriedSecond);
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

/// A seed step with two constant application polynomials.
struct CarryingLeaf;

impl<C: Cycle<CircuitField = Fp>> Step<C> for CarryingLeaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = (Fp, [Fp; 2]);
    const NUM_STAGED: usize = 2;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: crate::step::HeaderInput<'_, Fp, ()>,
        _: crate::step::HeaderInput<'_, Fp, ()>,
    ) -> Result<crate::step::Prepared<Fp, Carrying>> {
        Ok(crate::step::Prepared::new()
            .poly(Carried, [witness.1[0]])
            .poly(CarriedSecond, [witness.1[1]])
            .stage(witness.1))
    }
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Carrying;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        oracles: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, Carrying, H>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let zeta = oracles.zeta().clone();
        let first = oracles.output(Carried).open(dr, &zeta)?;
        let second = oracles.output(CarriedSecond).open(dr, &zeta)?;
        first.enforce_equal(dr, &oracles.staged()[0])?;
        second.enforce_equal(dr, &oracles.staged()[1])?;
        let data = witness.map(|(data, _)| data);
        let output = Encoded::new(dr, allocator, data.clone())?;
        Ok(((left, right, output), data, D::unit()))
    }
}

/// A wallet application with a leaf step, for proofs with a header.
fn wallet() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
    ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize(crate::pasta::baked_aggregator())
        .unwrap()
}

/// Every consumer of a decompression agrees on it, `accepts` or not: the
/// ordinary verifier, the compressed verifier on its compression, and the
/// ordinary verifier on a parent that folds its claims, its
/// rerandomization. The three compute the step binding's claim from the
/// proof alike, each on its own path.
fn every_consumer(
    app: &Application<'_, Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>,
    pcd: crate::Pcd<Profiled<Pasta, P>, AggregatorRank, Value>,
    accepts: bool,
    rng: &mut StdRng,
    case: &str,
) {
    assert!(
        matches!(app.verify_uncompressed(&pcd, &mut *rng), Ok(v) if v == accepts),
        "{case}: ordinary verifier"
    );
    let compressed = app.compress(&pcd, &mut *rng).unwrap();
    assert!(
        matches!(app.verify_compressed(&compressed), Ok(v) if v == accepts),
        "{case}: compressed verifier"
    );
    let parent = app.rerandomize(pcd, &mut *rng).unwrap();
    assert!(
        matches!(app.verify_uncompressed(&parent, &mut *rng), Ok(v) if v == accepts),
        "{case}: as a child"
    );
}

/// A wallet's compressed proof decompresses into a proof of the aggregator
/// carrying the wallet proof's header and data, which verifies; the same
/// decompression under another header fails, since the statement circuit's
/// claim holds the decompression step's output header to the decompressed
/// statement's. A decompression with a substituted output polynomial
/// fails the nested binding to the wallet proof's commitments.
#[test]
fn decompresses_a_wallet_proof() {
    let pasta = crate::pasta::baked_aggregator();
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
    every_consumer(&app, node.clone(), true, &mut rng, "the decompression");

    // The step commits the nested IPA's s(X) in its nested batch. The
    // proof carries the commitment for its verifier, which holds the
    // fuse's walk and the chunks' binding circuit to the same point: with
    // another commitment, a claim fails.
    let (proof, data) = node.clone().into_parts();
    let ipa = crate::decompress::online::slot::IPA;
    let mut other = proof.clone();
    other.nested_online_commitments[ipa] = -other.nested_online_commitments[ipa];
    assert!(
        matches!(
            app.verify_uncompressed(&other.carry::<Value>(data), &mut rng),
            Ok(false)
        ),
        "another batch commitment fails"
    );
    // The left opening's point exposes the staged digest. The
    // `hashes_1` and statement claims bind it to the step.
    assert_eq!(proof.step_binding.len(), 1);
    for i in 0..proof.step_binding.len() {
        let mut other = proof.clone();
        other.step_binding[i] += Fp::ONE;
        assert!(
            matches!(
                app.verify_uncompressed(&other.carry::<Value>(data), &mut rng),
                Ok(false)
            ),
            "another step binding value fails: {i}"
        );
    }

    let decompressed = app.context().prepare(&compressed).unwrap();
    let (relabelled, ()) = app
        .fuse_with_source(
            &mut rng,
            Decompress::<Value>::new(true),
            (Fp::from(43), padding(), decompressed.transcript_digest()),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&decompressed),
        )
        .unwrap();
    assert!(
        matches!(app.verify_uncompressed(&relabelled, &mut rng), Ok(false)),
        "a relabelled decompression fails"
    );

    // A prover who puts another polynomial in either output slot has
    // internally consistent PCS openings, but the commitment disagrees
    // with the one the chunks verified. Check all consuming paths.
    for slot in 0..2 {
        let mut wrong = padding();
        wrong[slot] = alloc::vec![Fp::from(2)];
        let (other_slot, ()) = app
            .fuse_with_source(
                &mut rng,
                Decompress::<Value>::new(true),
                (Fp::from(42), wrong, decompressed.transcript_digest()),
                app.bootstrap_pcd(),
                app.bootstrap_pcd(),
                Some(&decompressed),
            )
            .unwrap();
        every_consumer(
            &app,
            other_slot,
            false,
            &mut rng,
            "another output polynomial",
        );
    }

    // The transcript digest: the step stages the compression transcript's
    // last squeeze before its challenge, so both IPAs' round challenges,
    // and both challenge polynomials, are fixed before the point they are
    // opened at. A step that stages another value exposes a digest the
    // chunks' transcript does not squeeze, and its proof fails.
    let decompressed = app.context().prepare(&compressed).unwrap();
    let (other_digest, ()) = app
        .fuse_with_source(
            &mut rng,
            Decompress::<Value>::new(true),
            (
                Fp::from(42),
                padding(),
                decompressed.transcript_digest() + Fp::ONE,
            ),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&decompressed),
        )
        .unwrap();
    every_consumer(
        &app,
        other_digest,
        false,
        &mut rng,
        "a decompression that staged another digest",
    );

    // The nested curve's binding, from the prover's side: a step that
    // commits, in its nested batch, the challenge polynomial of other
    // round challenges opens that polynomial's own commitment, which
    // agrees with the proof, but the opening is not s(X)'s and the
    // commitment not the nested IPA's G'.
    let decompressed = app.context().prepare(&compressed).unwrap();
    let (other_ipa, ()) = crate::decompress::support::with_other_nested_ipa_polynomial(|| {
        app.fuse_with_source(
            &mut rng,
            Decompress::<Value>::new(true),
            (Fp::from(42), padding(), decompressed.transcript_digest()),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&decompressed),
        )
    })
    .unwrap();
    every_consumer(
        &app,
        other_ipa,
        false,
        &mut rng,
        "a decompression whose nested batch holds another polynomial",
    );
}

/// A compressed proof the wallet application's verifier rejects up front is
/// refused before any proving: `decompress` fails with the admission's own
/// rejection on a circuit id outside the registry's domain, an IPA opening
/// a round pair short of the rank and a recomputed nested stage that does
/// not commit as the instance claims.
#[test]
fn refuses_a_proof_the_wallet_rejects() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(17);
    let wallet = wallet();
    let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
    let (proof, data) = wallet.compress(&leaf, &mut rng).unwrap().into_parts();
    let decompression = Decompression::new(wallet, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(pasta, decompression)
        .unwrap();
    let wallet = app.context().wallet();

    let edits: [(&str, fn(&mut CompressedProof<Pasta>)); 3] = [
        ("an out-of-domain circuit id", |proof| {
            proof.instance.circuit_id = CircuitIndex::new(u32::MAX as usize);
        }),
        ("a round pair short of the rank", |proof| {
            proof.native.opening.rounds.pop();
        }),
        ("a stage that does not commit as claimed", |proof| {
            proof.instance.bridge_alpha += Fq::ONE;
        }),
    ];
    for (case, edit) in edits {
        let mut edited = proof.clone();
        edit(&mut edited);
        let Err(rejection) = wallet.admit_compressed(&edited) else {
            panic!("{case}: the wallet admits it");
        };
        let edited = edited.carry::<Value>(data);
        assert!(
            matches!(wallet.verify_compressed(&edited), Ok(false)),
            "{case}: the wallet's verifier rejects it"
        );
        let Err(error) = app.decompress(&mut rng, &edited) else {
            panic!("{case}: decompresses");
        };
        assert_eq!(error.to_string(), rejection.to_string(), "{case}");
    }
}

/// Two chunk circuits that load the same stages do not stand in for each
/// other: with the stages as they are, a proof whose polynomials for two
/// such circuits are swapped fails both verifiers, on either side.
#[test]
fn chunk_circuits_sharing_stages_are_not_interchangeable() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(31);
    let decompression = Decompression::new(wallet(), &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(pasta, decompression)
        .unwrap();
    let (leaf, _) = app.seed(&mut rng, Leaf, Fp::from(5)).unwrap();
    assert!(app.verify_uncompressed(&leaf, &mut rng).unwrap());

    let rejected = |pcd: crate::Pcd<Profiled<Pasta, P>, AggregatorRank, Value>,
                    rng: &mut StdRng,
                    case: &str| {
        assert!(
            matches!(app.verify_uncompressed(&pcd, &mut *rng), Ok(false)),
            "{case}: the decider"
        );
        let compressed = app
            .compress(&pcd, rng)
            .and_then(|compressed| app.verify_compressed(&compressed));
        assert!(
            matches!(compressed, Ok(false)),
            "{case}: the compressed verifier"
        );
    };
    // Two work-stage chunk circuits of the circuit-field side, after the
    // transcript ones.
    let first = P::native_circuits(HEADER_SIZE).transcript;
    let (mut proof, data) = leaf.clone().into_parts();
    proof.native_extension_circuit_rxs.swap(first, first + 1);
    rejected(
        proof.carry::<Value>(data),
        &mut rng,
        "circuit-field chunk circuits swapped",
    );
    // Two work-stage chunk circuits of the scalar-field side.
    let (mut proof, data) = leaf.into_parts();
    proof.nested_extension_circuit_rxs.swap(0, 1);
    rejected(
        proof.carry::<Value>(data),
        &mut rng,
        "scalar-field chunk circuits swapped",
    );
}

/// The decompression step cannot output the dummy header, whose suffix
/// would let a decompressed proof stand as the base case: the step's
/// uniform encoding holds the suffix wire away from it, so no proof of the
/// step with that header exists, whatever the chunks verified.
#[test]
fn a_decompression_cannot_output_the_dummy_suffix() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(37);
    let wallet = wallet();
    let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
    let compressed = wallet.compress(&leaf, &mut rng).unwrap();
    let decompression = Decompression::new(wallet, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(pasta, decompression)
        .unwrap();
    let decompressed = app.context().prepare(&compressed).unwrap();
    match app.fuse_with_source(
        &mut rng,
        Decompress::<Dummy>::new(true),
        ((), padding(), decompressed.transcript_digest()),
        app.bootstrap_pcd(),
        app.bootstrap_pcd(),
        Some(&decompressed),
    ) {
        Err(_) => {}
        Ok((forged, ())) => assert!(
            matches!(app.verify_uncompressed(&forged, &mut rng), Ok(false)),
            "a decompression under the dummy header fails"
        ),
    }
}

/// The chunk circuits use the generators at the aggregator rank, so a
/// wallet application over tables that stop short of it, the Standard
/// ones, is refused a decompression with an error rather than a panic.
#[test]
fn a_wallet_short_of_the_aggregator_rank_is_refused() {
    let wallet = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let decompression = Decompression::<Pasta, AggregatorRank, HEADER_SIZE, _>::new(
        wallet,
        &mut StdRng::seed_from_u64(40),
    );
    assert!(matches!(decompression, Err(Error::Initialization(_))));
}

/// The aggregator reads a decompressed statement with the wallet's own
/// header type: an application registering another type at a suffix the
/// wallet's steps output, or no header there, does not build; nor does one
/// over other parameters than its wallet application's, whose traces the
/// chunk circuits registered over its own would not match.
#[test]
fn the_aggregator_reads_statements_with_the_wallets_headers() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(41);
    let other_params = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(
            crate::pasta::baked(),
            Decompression::new(wallet(), &mut rng).unwrap(),
        );
    assert!(
        matches!(other_params, Err(Error::Initialization(_))),
        "other parameters than the wallet's"
    );
    let other = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(OtherLeaf)
        .unwrap()
        .finalize_with(pasta, Decompression::new(wallet(), &mut rng).unwrap());
    assert!(
        matches!(other, Err(Error::Initialization(_))),
        "another header type at the wallet's suffix"
    );
    let none = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(crate::profile::testing::UnitStep)
        .unwrap()
        .finalize_with(pasta, Decompression::new(wallet(), &mut rng).unwrap());
    assert!(
        matches!(none, Err(Error::Initialization(_))),
        "no header at the wallet's suffix"
    );
}

/// A prover cannot pass another wallet application's proof through the
/// decompression, whichever stage it writes that application's registry
/// in. The other application registers one more step, under our wallet's
/// registry tags: a collision no prover can produce, which the test
/// installs so that the two aggregators' own registries are the same and
/// only the wallet registry their batches certify tells them apart.
///
/// With the other registry's evaluations in the work stage alone, under
/// our aggregator's batches, the chunk that holds them to the query stage
/// is unsatisfied. With the batches over the other registry too, as the
/// aggregator built over that application proves them, every circuit of
/// our registries is satisfied and the terminal check is what fails: the
/// verifier evaluates the wallet registry it holds, uncompressed and
/// compressed.
#[test]
fn another_applications_registry_is_rejected_in_either_stage() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(47);
    let ours_wallet = wallet();
    let other_wallet = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
        .with_native_tag(ours_wallet.native_registry.tag())
        .with_nested_tag(ours_wallet.nested_registry.tag())
        .register(Leaf)
        .unwrap()
        .register(Join)
        .unwrap()
        .finalize(pasta)
        .unwrap();
    let (leaf, _) = other_wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
    let compressed = other_wallet.compress(&leaf, &mut rng).unwrap();
    assert!(other_wallet.verify_compressed(&compressed).unwrap());
    assert!(
        !matches!(ours_wallet.verify_compressed(&compressed), Ok(true)),
        "the proof is not one of our wallet application's"
    );

    let aggregator = |wallet, rng: &mut StdRng| {
        ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(Join)
            .unwrap()
            .finalize_with(pasta, Decompression::new(wallet, rng).unwrap())
            .unwrap()
    };
    let ours = aggregator(ours_wallet, &mut rng);
    let theirs = aggregator(other_wallet, &mut rng);
    assert_eq!(
        (ours.native_registry.tag(), ours.nested_registry.tag()),
        (theirs.native_registry.tag(), theirs.nested_registry.tag()),
        "the aggregators' own registries are the same"
    );
    assert!(
        ours.decompress(&mut rng, &compressed).is_err(),
        "our prover refuses the proof before proving"
    );

    // The work stage alone: the other application's evaluations, as its
    // own verifier computes them, under our aggregator's batches, which
    // open our wallet's registry.
    let prepared = theirs.context().prepare(&compressed).unwrap();
    let (forged, ()) = ours
        .fuse_with_source(
            &mut rng,
            Decompress::<Value>::new(true),
            (Fp::from(42), padding(), prepared.transcript_digest()),
            ours.bootstrap_pcd(),
            ours.bootstrap_pcd(),
            Some(&prepared),
        )
        .unwrap();
    assert!(
        matches!(ours.verify_uncompressed(&forged, &mut rng), Ok(false)),
        "evaluations of another registry than the batches' fail a chunk"
    );

    // Both stages: the other aggregator's decompression, whose batches
    // open the other application's registry, is a proof of the registries
    // the two aggregators share, and our verifier's terminal check
    // evaluates our wallet's registry.
    let node = theirs.decompress(&mut rng, &compressed).unwrap();
    assert!(theirs.verify_uncompressed(&node, &mut rng).unwrap());
    assert!(
        matches!(ours.verify_uncompressed(&node, &mut rng), Ok(false)),
        "batches over another registry fail the terminal check"
    );
    let compressed = theirs.compress(&node, &mut rng).unwrap();
    assert!(theirs.verify_compressed(&compressed).unwrap());
    assert!(
        matches!(ours.verify_compressed(&compressed), Ok(false)),
        "and its compression the compressed verifier's"
    );
}

/// A wallet step that drops the polynomial slots while preserving the data.
struct PadCarrying;

impl<C: Cycle<CircuitField = Fp>> Step<C> for PadCarrying {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Carrying;
    type Right = ();
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
        &self,
        dr: &mut D,
        _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Carrying, H>,
            Encoded<'dr, D, (), H>,
            Encoded<'dr, D, Value, H>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let value = Element::alloc(dr, allocator, left.clone())?;
        Ok((
            (
                Encoded::from_gadget(value.clone()),
                Encoded::new(dr, allocator, right)?,
                Encoded::from_gadget(value),
            ),
            left,
            D::unit(),
        ))
    }
}

/// An aggregator must register every header its wallet outputs, padding
/// or not. Registering both, it decompresses either output.
#[test]
fn decompression_accepts_a_padded_output_from_a_wallet_with_online_polynomials() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(42);
    let wallet = || {
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(CarryingLeaf)
            .unwrap()
            .register(PadCarrying)
            .unwrap()
            .finalize(pasta)
            .unwrap()
    };

    // The wallet outputs `Carrying` and `Value`; an aggregator that
    // registers `Value` alone is refused.
    let missing = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .finalize_with(pasta, Decompression::new(wallet(), &mut rng).unwrap());
    assert!(
        matches!(missing, Err(Error::Initialization(ref reason)) if reason.to_string().contains("registers no header")),
        "an unregistered header that carries online polynomials"
    );

    let wallet = wallet();
    let (carrying, _) = wallet
        .seed(&mut rng, CarryingLeaf, (Fp::from(42), [Fp::ONE; 2]))
        .unwrap();
    let carrying_proof = wallet.compress(&carrying, &mut rng).unwrap();
    let (padded, _) = wallet
        .fuse(
            &mut rng,
            PadCarrying,
            (),
            carrying,
            wallet.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let padded_proof = wallet.compress(&padded, &mut rng).unwrap();
    assert!(wallet.verify_compressed(&carrying_proof).unwrap());
    assert!(wallet.verify_compressed(&padded_proof).unwrap());
    // The carrying header declares a polynomial even when its commitment
    // happens to equal the padding commitment.
    assert_eq!(
        carrying_proof.online_commitments(),
        padded_proof.online_commitments(),
    );

    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(CarryingLeaf)
        .unwrap()
        .register(PadCarrying)
        .unwrap()
        .finalize_with(pasta, Decompression::new(wallet, &mut rng).unwrap())
        .unwrap();
    let carried = app
        .decompress_with_polynomials(&mut rng, &carrying_proof, padding())
        .unwrap();
    assert!(app.verify_uncompressed(&carried, &mut rng).unwrap());

    let decompressed = app.decompress(&mut rng, &padded_proof).unwrap();
    assert_eq!(*decompressed.data(), Fp::from(42));
    let parent = app.rerandomize(decompressed, &mut rng).unwrap();
    let compressed = app.compress(&parent, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
}

/// A profile whose decompression step pads its output slots refuses every
/// header that names an online polynomial, output or read: a decompressed
/// statement can land at any application suffix.
#[test]
fn a_padding_decompression_refuses_headers_with_online_polynomials() {
    use crate::profile::testing::{Decompressing, StatementContext};
    type Padded = Profiled<Pasta, Decompressing>;
    let params = crate::pasta::baked_aggregator();
    let refused = |result: Result<Application<'_, Padded, AggregatorRank, HEADER_SIZE>>| matches!(result, Err(Error::Initialization(ref reason)) if reason.to_string().contains("names an online polynomial"));

    let outputs = ApplicationBuilder::<Padded, AggregatorRank, HEADER_SIZE>::new()
        .register(CarryingLeaf)
        .unwrap()
        .finalize_with(params, StatementContext::default());
    assert!(refused(outputs), "a step that outputs `Carrying`");

    let reads = ApplicationBuilder::<Padded, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .register(PadCarrying)
        .unwrap()
        .finalize_with(params, StatementContext::default());
    assert!(refused(reads), "a step that reads `Carrying`");
}

#[test]
fn decompression_preserves_both_wallet_commitments_for_the_next_fuse() {
    let params = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(103);
    let wallet = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
        .register(CarryingLeaf)
        .unwrap()
        .finalize(params)
        .unwrap();
    let (leaf, ()) = wallet
        .seed(
            &mut rng,
            CarryingLeaf,
            (Fp::from(42), [Fp::from(5), Fp::from(7)]),
        )
        .unwrap();
    let polynomials = leaf.polynomials();
    let compressed = wallet.compress(&leaf, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(CarryingLeaf)
        .unwrap()
        .finalize_with(params, Decompression::new(wallet, &mut rng).unwrap())
        .unwrap();
    // Coefficients that do not commit to the wallet proof's commitments
    // are refused before any proving.
    for slot in 0..polynomials.len() {
        let mut wrong = polynomials.clone();
        wrong[slot][0] += Fp::ONE;
        assert!(
            matches!(
                app.decompress_with_polynomials(&mut rng, &compressed, wrong),
                Err(Error::InvalidWitness(ref reason))
                    if reason.to_string().contains("online commitments")
            ),
            "other coefficients in slot {slot}"
        );
    }
    let node = app
        .decompress_with_polynomials(&mut rng, &compressed, polynomials.clone())
        .unwrap();
    assert_eq!(node.data(), leaf.data());
    assert_eq!(node.commitments(), compressed.online_commitments());
    assert_eq!(node.polynomials(), polynomials);
    assert!(app.verify_uncompressed(&node, &mut rng).unwrap());

    // Rerandomize opens both child slots and copies them through the fuses.
    let parent = app.rerandomize(node, &mut rng).unwrap();
    let result = app.compress(&parent, &mut rng).unwrap();
    assert_eq!(result.online_commitments(), compressed.online_commitments());
    assert!(app.verify_compressed(&result).unwrap());
}

/// Decompressed wallet proofs recurse: two fuse under a step of the
/// aggregator's own, and the result fuses with a third, each level
/// verifying uncompressed and the last compressed too.
#[test]
fn decompressed_proofs_recurse() {
    let pasta = crate::pasta::baked_aggregator();
    let mut rng = StdRng::seed_from_u64(43);
    let wallet = wallet();
    let mut compressed = |value: u64| {
        let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(value)).unwrap();
        wallet.compress(&leaf, &mut rng).unwrap()
    };
    let (a, b, c) = (compressed(41), compressed(42), compressed(43));
    let decompression = Decompression::new(wallet, &mut rng).unwrap();
    let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .register(Leaf)
        .unwrap()
        .register(Join)
        .unwrap()
        .finalize_with(pasta, decompression)
        .unwrap();
    let a = app.decompress(&mut rng, &a).unwrap();
    let b = app.decompress(&mut rng, &b).unwrap();
    let c = app.decompress(&mut rng, &c).unwrap();
    let (ab, ()) = app.fuse(&mut rng, Join, (), a, b).unwrap();
    assert_eq!(*ab.data(), Fp::from(83));
    assert!(app.verify_uncompressed(&ab, &mut rng).unwrap());
    let (abc, ()) = app.fuse(&mut rng, Join, (), ab, c).unwrap();
    assert_eq!(*abc.data(), Fp::from(126));
    assert!(app.verify_uncompressed(&abc, &mut rng).unwrap());
    let compressed = app.compress(&abc, &mut rng).unwrap();
    assert!(app.verify_compressed(&compressed).unwrap());
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
    let pasta = crate::pasta::baked_aggregator();
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
            Decompress::<Value>::new(true),
            (Fp::from(42), padding(), mixed.transcript_digest()),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&mixed),
        )
        .unwrap();
    assert!(
        matches!(app.verify_uncompressed(&node, &mut rng), Ok(false)),
        "a decompression of two proofs fails"
    );
    let compressed = app.compress(&node, &mut rng).unwrap();
    assert!(
        matches!(app.verify_compressed(&compressed), Ok(false)),
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
        _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
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
    // The circuit id and the bridge alpha, the four accumulator values,
    // each child's x and y on both fields, and a(u) and b(u) on both.
    let _ = instance;
    let scalars = 1 + 1 + 4 + 4 + 4 + 4;
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

    let pasta = crate::pasta::baked_aggregator();
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
        ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
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
        wallet.verify_uncompressed(&node, &mut rng).unwrap()
    ));
    let compressed = timed!("wallet compress", wallet.compress(&node, &mut rng).unwrap());
    assert!(timed!(
        "wallet verify_compressed",
        wallet.verify_compressed(&compressed).unwrap()
    ));
    report(
        "wallet",
        Shape::of::<Standard>().polynomials(),
        WalletRank::RANK,
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
            .finalize_with(crate::pasta::baked_aggregator(), decompression)
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
        aggregator.verify_uncompressed(&parent, &mut rng).unwrap()
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
