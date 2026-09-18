//! Review O08: context and configuration splice attacks.
//!
//! Whole proofs are reused under a different application or header context,
//! while rank and generator tests isolate the two parameter-dependent
//! relations below the proof type. Each attack has an independently false
//! receiving relation; matching proof bytes or commitments are controls, not
//! acceptance oracles.

use alloc::{vec, vec::Vec};

use ragu_arithmetic::{Cycle, FixedGenerators, ff::Field, pasta_curves::EpAffine};
use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::polynomials::{ProductionRank, Rank, TestRank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pasta::{Fp, Fq, Pasta};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};
use rand::{SeedableRng, rngs::StdRng};

use super::{
    C, HEADER_SIZE, R,
    test_steps::{Leaf, Number, OrderedAdd},
};
use crate::{
    Application, ApplicationBuilder, Pcd,
    header::{Header, Suffix},
    internal::stage_wires::{StageReader, wire_degree},
    step::{Encoded, Index, Step},
    verify::VerificationChecks,
};

type App = Application<'static, C, R, HEADER_SIZE>;

const LEFT: Fp = Fp::from_raw([19, 0, 0, 0]);
const RIGHT: Fp = Fp::from_raw([43, 0, 0, 0]);
const FOREIGN_HEADER_VALUE: Fp = Fp::from_raw([71, 0, 0, 0]);
const RECEIVER_HEADER_VALUE: Fp = Fp::from_raw([89, 0, 0, 0]);

fn checks<H: Header<Fp>>(
    app: &App,
    pcd: &Pcd<C, R, H>,
    seed: u64,
    context: &str,
) -> Result<VerificationChecks> {
    let (accepted, checks) = app.verify_with_checks(pcd, StdRng::seed_from_u64(seed))?;
    let checks = checks.expect("well-formed splice metadata must reach the decider predicates");
    assert_eq!(accepted, checks.all(), "{context}: {checks:?}");
    Ok(checks)
}

/// The source application's index-two relation is symmetric addition.
struct ContextAdd;

impl Step<Pasta> for ContextAdd {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const SIZE: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, SIZE>,
            Encoded<'dr, D, Number, SIZE>,
            Encoded<'dr, D, Number, SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::<_, Number, SIZE>::new(dr, allocator, left)?;
        let right = Encoded::<_, Number, SIZE>::new(dr, allocator, right)?;
        let output = left.as_gadget().add(dr, right.as_gadget());
        let data = output.value().map(|value| *value);
        Ok(((left, right, Encoded::from_gadget(output)), data, D::unit()))
    }
}

fn source_application() -> Result<App> {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(super::test_steps::Add)?
        .register(ContextAdd)?
        .finalize(Pasta::baked())
}

fn receiver_application() -> Result<App> {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .register(super::test_steps::Add)?
        .register(OrderedAdd)?
        .finalize(Pasta::baked())
}

#[test]
fn whole_proof_is_rejected_by_a_false_receiving_application_relation() -> Result<()> {
    let source = source_application()?;
    let receiver = receiver_application()?;
    let equivalent_source = source_application()?;

    let mut rng = StdRng::seed_from_u64(0x8730_0801);
    let left = source.seed(&mut rng, Leaf, LEFT)?.0;
    let right = source.seed(&mut rng, Leaf, RIGHT)?.0;
    let source_parent = source.fuse(&mut rng, ContextAdd, (), left, right)?.0;
    let source_value = *source_parent.data();
    assert_eq!(source_value, LEFT + RIGHT);
    assert_ne!(source_value, LEFT + RIGHT + RIGHT);
    assert!(checks(&source, &source_parent, 0x8730_0802, "source proof")?.all());
    assert!(
        checks(
            &equivalent_source,
            &source_parent,
            0x8730_0802,
            "equivalent application context",
        )?
        .all()
    );

    // Retyping carries the exact same proof and public value. The receiving
    // relation at index two is left + 2*right, which is independently false.
    let spliced = source_parent.proof().clone().carry::<Number>(source_value);
    assert_eq!(spliced.proof().test_mismatch(source_parent.proof()), None);
    let rejected = checks(&receiver, &spliced, 0x8730_0802, "cross-application splice")?;
    assert!(!rejected.all());
    assert!(
        !rejected.native_registry,
        "receiver registry must reject: {rejected:?}"
    );
    assert!(
        rejected.commitments,
        "the unchanged caches remain valid: {rejected:?}"
    );
    assert!(
        rejected.transcript,
        "proof-only transcript bytes remain valid: {rejected:?}"
    );

    // The receiving context itself is usable for the intended relation.
    let mut receiver_rng = StdRng::seed_from_u64(0x8730_0803);
    let left = receiver.seed(&mut receiver_rng, Leaf, LEFT)?.0;
    let right = receiver.seed(&mut receiver_rng, Leaf, RIGHT)?.0;
    let receiver_parent = receiver
        .fuse(&mut receiver_rng, OrderedAdd, (), left, right)?
        .0;
    assert_eq!(*receiver_parent.data(), LEFT + RIGHT + RIGHT);
    assert!(checks(&receiver, &receiver_parent, 0x8730_0804, "receiver control")?.all());
    Ok(())
}

/// Same field encoding as `Number`, but a distinct application suffix.
struct AliasNumber;

impl Header<Fp> for AliasNumber {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// The receiving header has the same data type and element encoding as
/// `Number`, but its only registered leaf emits a different constant.
struct AliasLeaf;

impl Step<Pasta> for AliasLeaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = AliasNumber;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), SIZE>,
            Encoded<'dr, D, (), SIZE>,
            Encoded<'dr, D, AliasNumber, SIZE>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let value = witness.as_ref().map(|_| RECEIVER_HEADER_VALUE);
        let output = Encoded::new(dr, &mut Standard::new(), value)?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            witness.as_ref().map(|_| RECEIVER_HEADER_VALUE),
            D::unit(),
        ))
    }
}

#[test]
fn same_data_encoding_does_not_authorize_a_foreign_header_context() -> Result<()> {
    assert_ne!(Number::SUFFIX.get(), AliasNumber::SUFFIX.get());
    let source = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(Leaf)?
        .finalize(Pasta::baked())?;
    let receiver = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(AliasLeaf)?
        .finalize(Pasta::baked())?;

    let source_node = source
        .seed(
            &mut StdRng::seed_from_u64(0x8730_0810),
            Leaf,
            FOREIGN_HEADER_VALUE,
        )?
        .0;
    assert!(checks(&source, &source_node, 0x8730_0811, "source header")?.all());
    assert_ne!(FOREIGN_HEADER_VALUE, RECEIVER_HEADER_VALUE);

    // Only the Rust-level header type changes. The underlying proof and field
    // element remain byte-for-byte the source objects, while the receiving
    // step relation permits only RECEIVER_HEADER_VALUE.
    let spliced = source_node
        .proof()
        .clone()
        .carry::<AliasNumber>(FOREIGN_HEADER_VALUE);
    assert_eq!(spliced.proof().test_mismatch(source_node.proof()), None);
    let rejected = checks(&receiver, &spliced, 0x8730_0811, "header-context splice")?;
    assert!(!rejected.all());
    assert!(
        rejected.commitments,
        "unchanged proof caches must not decide: {rejected:?}"
    );
    assert!(
        rejected.transcript,
        "common element encoding must not decide: {rejected:?}"
    );
    assert!(
        !rejected.native_revdot || !rejected.native_registry,
        "a receiving semantic obligation must reject: {rejected:?}"
    );

    let honest_receiver = receiver
        .seed(&mut StdRng::seed_from_u64(0x8730_0812), AliasLeaf, ())?
        .0;
    assert_eq!(*honest_receiver.data(), RECEIVER_HEADER_VALUE);
    assert!(
        checks(
            &receiver,
            &honest_receiver,
            0x8730_0813,
            "honest alias header"
        )?
        .all()
    );
    Ok(())
}

/// A deliberately different generator configuration with the same concrete
/// curve type, suitable for isolating commitment-context reuse.
struct RotatedPallasGenerators {
    g: Vec<EpAffine>,
    h: EpAffine,
}

impl FixedGenerators<EpAffine> for RotatedPallasGenerators {
    fn g(&self) -> &[EpAffine] {
        &self.g
    }

    fn h(&self) -> &EpAffine {
        &self.h
    }
}

fn staged_pair<Rk: Rank>(first: Fq, second: Fq) -> sparse::Polynomial<Fq, Rk> {
    let mut coefficients = vec![Fq::ZERO; Rk::num_coeffs()];
    coefficients[wire_degree::<Rk>(0)] = first;
    coefficients[wire_degree::<Rk>(1)] = second;
    sparse::Polynomial::from_coeffs(coefficients)
}

#[test]
fn matching_commitment_bytes_do_not_authorize_rank_or_generator_splices() {
    let first = Fq::from(17);
    let second = Fq::from(29);
    let small = staged_pair::<TestRank>(first, second);
    let widened =
        sparse::Polynomial::<Fq, ProductionRank>::from_coeffs(small.iter_coeffs().collect());
    let receiver = staged_pair::<ProductionRank>(first, second);

    let small_reader = StageReader::<Fq, TestRank>::new(&small);
    assert_eq!(
        [small_reader.read(0), small_reader.read(1)],
        [first, second]
    );
    let widened_reader = StageReader::<Fq, ProductionRank>::new(&widened);
    assert_eq!(
        [widened_reader.read(0), widened_reader.read(1)],
        [Fq::ZERO; 2]
    );
    let receiver_reader = StageReader::<Fq, ProductionRank>::new(&receiver);
    assert_eq!(
        [receiver_reader.read(0), receiver_reader.read(1)],
        [first, second]
    );
    assert_ne!(wire_degree::<TestRank>(0), wire_degree::<ProductionRank>(0));
    assert_ne!(wire_degree::<TestRank>(1), wire_degree::<ProductionRank>(1));

    // Widening preserves every coefficient index, so it also preserves its
    // commitment under a common generator table. Nevertheless, it is false as
    // a ProductionRank staged pair because that rank reads different degrees.
    let generators = Pasta::nested_generators(Pasta::baked());
    let small_commitment = ReferenceBackend::sparse_commit_to_affine(&small, generators);
    let widened_commitment = ReferenceBackend::sparse_commit_to_affine(&widened, generators);
    let receiver_commitment = ReferenceBackend::sparse_commit_to_affine(&receiver, generators);
    assert_eq!(small_commitment, widened_commitment);
    assert_ne!(widened_commitment, receiver_commitment);

    // Conversely, the same valid receiver polynomial is a false cached
    // commitment relation after generator parameters are spliced.
    let mut rotated_g = generators.g().to_vec();
    rotated_g.rotate_left(1);
    let rotated = RotatedPallasGenerators {
        g: rotated_g,
        h: *generators.h(),
    };
    assert_ne!(rotated.g()[0], generators.g()[0]);
    let source_commitment = ReferenceBackend::sparse_commit_to_affine(&receiver, &rotated);
    let receiving_commitment = ReferenceBackend::sparse_commit_to_affine(&receiver, generators);
    assert_ne!(source_commitment, receiving_commitment);
}
