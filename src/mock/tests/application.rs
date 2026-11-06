use alloc::{boxed::Box, string::ToString as _, vec, vec::Vec};

use ragu_circuits::polynomials::{ProductionRank as TestRank, Rank};
use ragu_core::{
    Cycle as _, Error, FixedGenerators as _, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
    pasta::{Ep, EpAffine, Eq, Fp, Fq, PallasGenerators, Pasta, PastaParams, VestaGenerators},
};
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::{
    curve::{Affine as _, AffineAdapter, Projective as _},
    field::Field as _,
};

use super::super::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};

type ApplicationBuilder = crate::ApplicationBuilder<'static, Pasta, TestRank, 4>;
type Application = crate::Application<'static, Pasta, TestRank, 4>;
type Proof = crate::Proof<Pasta, TestRank>;

pub(super) fn test_params() -> &'static PastaParams {
    test_params_for::<TestRank>()
}

pub(super) fn test_params_for<R: Rank>() -> &'static PastaParams {
    let n = R::num_coeffs() as u64;
    let pallas =
        |i: u64| AffineAdapter::as_slice(&[(Ep::generator() * Fq::from(i)).to_affine()])[0];
    let vesta = |i: u64| AffineAdapter::as_slice(&[(Eq::generator() * Fp::from(i)).to_affine()])[0];
    let pallas = PallasGenerators::new(
        (1..=n).map(pallas).collect::<Vec<_>>().leak(),
        pallas(n + 1),
    );
    let vesta = VestaGenerators::new((1..=n).map(vesta).collect::<Vec<_>>().leak(), vesta(n + 1));
    Box::leak(Box::new(PastaParams::new(pallas, vesta)))
}

struct TestHeader;

#[derive(Clone, Debug)]
struct TestHeaderData {
    value: u64,
}

impl Header<Fp> for TestHeader {
    type Data = TestHeaderData;
    type Output = Kind![Fp; Element<'_, _>];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, data.map(|data| Fp::from(data.value)))
    }
}

struct SeedStep;

impl Step<Pasta> for SeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = u64;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        _right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        let output_data = witness.map(|witness| TestHeaderData { value: witness });
        let output = Encoded::new(dr, &mut (), output_data.clone())?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

struct MergeStep;

impl Step<Pasta> for MergeStep {
    type Aux<'source> = ();
    type Left = TestHeader;
    type Output = TestHeader;
    type Right = TestHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        let output_data = D::just(|| TestHeaderData {
            value: left.as_ref().take().value + right.as_ref().take().value,
        });
        let left = Encoded::<_, TestHeader, HEADER_SIZE>::new(dr, &mut (), left)?;
        let right = Encoded::<_, TestHeader, HEADER_SIZE>::new(dr, &mut (), right)?;
        let output = Encoded::<_, TestHeader, HEADER_SIZE>::new(dr, &mut (), output_data.clone())?;
        left.as_gadget()
            .add(dr, right.as_gadget())
            .enforce_equal(dr, output.as_gadget())?;
        Ok(((left, right, output), output_data, D::unit()))
    }
}

#[test]
fn serialized_proof_rejects_mismatched_header_data() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");

    let bytes = pcd.proof.to_bytes().expect("encode proof");
    let recovered_proof = Proof::from_bytes(&bytes).expect("recovered proof should deserialize");

    let bad_pcd = recovered_proof.carry::<TestHeader>(TestHeaderData { value: 999 });
    let valid = app
        .verify_uncompressed(&bad_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(
        !valid,
        "round-tripped proof must still reject mismatched header data"
    );
}

#[test]
fn tampered_serialized_proof_fails_to_deserialize() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");

    let mut bytes = pcd.proof.to_bytes().expect("encode proof");
    bytes[0] ^= 0xFFu8;
    assert!(
        Proof::from_bytes(&bytes).is_err(),
        "tampered proof bytes must be rejected before reaching verify"
    );
}

#[test]
fn rerandomize_preserves_validity() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");
    let original_proof = pcd.proof.clone();

    let rerand_pcd = app
        .rerandomize(pcd, &mut rng)
        .expect("rerandomize should succeed");
    let valid = app
        .verify_uncompressed(&rerand_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(valid, "rerandomized proof should still verify");
    assert_ne!(
        rerand_pcd.proof.to_bytes().expect("encode proof"),
        original_proof.to_bytes().expect("encode proof"),
        "rerandomization must change the proof"
    );
}

/// Distinct Header type that declares the same `SUFFIX` value as `TestHeader`.
struct ConflictingHeader;

impl Header<Fp> for ConflictingHeader {
    type Data = TestHeaderData;
    type Output = Kind![Fp; Element<'_, _>];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, data.map(|data| Fp::from(data.value)))
    }
}

/// Second seed step claiming `Index::new(0)` for the duplicate-index test.
struct DuplicateIndexStep;

impl Step<Pasta> for DuplicateIndexStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        SeedStep.witness::<D, HEADER_SIZE>(dr, oracles, D::just(|| 0), left, right)
    }
}

/// Seed step whose output is `ConflictingHeader` (which collides with
/// `TestHeader::SUFFIX`).
struct SuffixCollisionStep;

impl Step<Pasta> for SuffixCollisionStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = ConflictingHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        _right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        let output_data = D::just(|| TestHeaderData { value: 0 });
        let output = Encoded::new(dr, &mut (), output_data.clone())?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

#[test]
fn duplicate_index_rejects_registration() {
    let result = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register first step should succeed")
        .register(DuplicateIndexStep);
    assert!(result.is_err(), "duplicate INDEX must be rejected");
}

#[test]
fn non_sequential_index_rejects_registration() {
    let result = ApplicationBuilder::new().register(MergeStep);
    assert!(
        result.is_err(),
        "non-sequential INDEX (1 before 0) must be rejected"
    );
}

#[test]
fn duplicate_suffix_distinct_types_rejects_registration() {
    let result = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register first step should succeed")
        .register(SuffixCollisionStep);
    assert!(
        result.is_err(),
        "distinct Header types sharing a SUFFIX must be rejected"
    );
}

#[test]
fn same_suffix_same_type_succeeds_registration() {
    let result = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register SeedStep should succeed")
        .register(MergeStep);
    assert!(
        result.is_ok(),
        "reusing the same Header type across steps is allowed"
    );
}

#[test]
fn internal_step_index_rejects_registration() {
    struct InternalIndexStep;
    impl Step<Pasta> for InternalIndexStep {
        type Aux<'source> = ();
        type Left = ();
        type Output = TestHeader;
        type Right = ();
        type Witness<'source> = ();

        const INDEX: Index = Index::internal(0);

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
            &self,
            dr: &mut D,
            oracles: &mut Oracles<'_, 'dr, D>,
            _witness: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
            right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
        ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
            SeedStep.witness::<D, HEADER_SIZE>(dr, oracles, D::just(|| 0), left, right)
        }
    }

    let result = ApplicationBuilder::new().register(InternalIndexStep);
    assert!(
        result.is_err(),
        "application-defined steps must not use Index::Internal"
    );
}

/// Header carrying a Pallas commitment point.
struct PointHeader;

#[derive(Clone, Debug)]
struct PointHeaderData {
    commitment: Ep,
}

impl Header<Fp> for PointHeader {
    type Data = PointHeaderData;
    type Output = Kind![Fp; ragu_primitives::Point<'_, _, EpAffine>];

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        _allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        ragu_primitives::Point::alloc(dr, data.map(|data| data.commitment.to_affine()))
    }
}

/// Seed step whose output header carries the witness point.
struct PointSeedStep;

impl Step<Pasta> for PointSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = PointHeader;
    type Right = ();
    type Witness<'source> = Ep;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        _right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        let output_data = witness.map(|witness| PointHeaderData {
            commitment: witness,
        });
        let output = Encoded::new(dr, &mut (), output_data.clone())?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

/// Step consuming a [`PointHeader`] as its left input.
struct PointConsumeStep;

impl Step<Pasta> for PointConsumeStep {
    type Aux<'source> = ();
    type Left = PointHeader;
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        _right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        let output_data = D::just(|| TestHeaderData { value: 1 });
        let left = Encoded::new(dr, &mut (), left)?;
        let output = Encoded::new(dr, &mut (), output_data.clone())?;
        Ok((
            (left, Encoded::from_gadget(()), output),
            output_data,
            D::unit(),
        ))
    }
}

/// Application with [`PointSeedStep`] registered.
fn point_app() -> Application {
    ApplicationBuilder::new()
        .register(PointSeedStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize")
}

#[test]
fn header_with_point_round_trips() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = point_app();

    let (pcd, ()) = app
        .seed(&mut rng, PointSeedStep, Ep::generator())
        .expect("seed with a non-identity point");
    assert!(app.verify_uncompressed(&pcd, &mut rng).expect("verify"));
}

#[test]
fn identity_point_in_output_header_fails_fuse() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = point_app();

    assert!(
        matches!(
            app.seed(&mut rng, PointSeedStep, Ep::identity()),
            Err(Error::InvalidWitness(_))
        ),
        "identity point in output header must fail"
    );
}

#[test]
fn identity_point_in_input_header_fails_fuse() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(PointSeedStep)
        .expect("register")
        .register(PointConsumeStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize");

    let (left, ()) = app
        .seed(&mut rng, PointSeedStep, Ep::generator())
        .expect("seed");
    let bad_left = left.proof.carry::<PointHeader>(PointHeaderData {
        commitment: Ep::identity(),
    });
    let right = app.bootstrap_proof().clone().carry::<()>(());

    assert!(
        matches!(
            app.fuse(&mut rng, PointConsumeStep, (), bad_left, right),
            Err(Error::InvalidWitness(_))
        ),
        "identity point in input header must fail"
    );
}

#[test]
fn identity_point_in_carried_data_errors_verify() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = point_app();

    let (pcd, ()) = app
        .seed(&mut rng, PointSeedStep, Ep::generator())
        .expect("seed with a non-identity point");
    let bad_pcd = pcd.proof.carry::<PointHeader>(PointHeaderData {
        commitment: Ep::identity(),
    });

    // Errs rather than returning `Ok(false)`: re-encoding such a header
    // fails synthesis in real ragu, it does not merely mismatch.
    assert!(matches!(
        app.verify_uncompressed(&bad_pcd, &mut rng),
        Err(Error::InvalidWitness(_))
    ));
}

#[test]
fn verify_rejects_unregistered_output_header() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = point_app();
    let data = TestHeaderData { value: 42 };
    // Recompute both hashes for the forged header: merely swapping the carried
    // header on an honest proof would only exercise the existing hash check.
    let mut dr = ragu_primitives::Simulator::new();
    let encoded = Encoded::<_, TestHeader, 4>::new(
        &mut dr,
        &mut (),
        ragu_primitives::Simulator::<Fp>::just(|| data.clone()),
    )
    .expect("encode");
    let proof = Proof::new(
        Index::new(0),
        &mut dr,
        &encoded,
        b"forged-witness",
        app.bootstrap_proof().polynomials.clone(),
        app.bootstrap_proof().commitments,
        app.bootstrap_proof().setup_hash,
    )
    .expect("proof");
    assert!(
        !app.verify_uncompressed(&proof.carry::<TestHeader>(data), &mut rng)
            .expect("verify")
    );
}

#[test]
fn verify_rejects_header_registered_for_another_step() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(PointSeedStep)
        .expect("register point output")
        .register(PointConsumeStep)
        .expect("register scalar output")
        .finalize(test_params())
        .expect("finalize");
    let (point, ()) = app
        .seed(&mut rng, PointSeedStep, Ep::generator())
        .expect("seed");
    assert!(
        app.verify_uncompressed(&point, &mut rng)
            .expect("verify point output")
    );
    let (scalar, ()) = app
        .fuse(
            &mut rng,
            PointConsumeStep,
            (),
            point,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .expect("fuse");
    assert!(
        app.verify_uncompressed(&scalar, &mut rng)
            .expect("verify scalar output")
    );

    let data = TestHeaderData { value: 1 };
    let mut dr = ragu_primitives::Simulator::new();
    let encoded = Encoded::<_, TestHeader, 4>::new(
        &mut dr,
        &mut (),
        ragu_primitives::Simulator::<Fp>::just(|| data.clone()),
    )
    .expect("encode");
    let proof = Proof::new(
        Index::new(0),
        &mut dr,
        &encoded,
        b"forged-witness",
        app.bootstrap_proof().polynomials.clone(),
        app.bootstrap_proof().commitments,
        app.bootstrap_proof().setup_hash,
    )
    .expect("proof");
    assert!(
        !app.verify_uncompressed(&proof.carry::<TestHeader>(data), &mut rng)
            .expect("verify")
    );
}

#[test]
fn verify_rejects_input_only_header_as_output() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = point_app();
    // Unit is registered as an input to PointSeedStep, but not as its output.
    let mut dr = ragu_primitives::Simulator::<Fp>::new();
    let encoded = Encoded::<_, (), 4>::from_gadget(());
    let proof = Proof::new(
        Index::new(0),
        &mut dr,
        &encoded,
        b"forged-witness",
        app.bootstrap_proof().polynomials.clone(),
        app.bootstrap_proof().commitments,
        app.bootstrap_proof().setup_hash,
    )
    .expect("proof");
    assert!(
        !app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)
            .expect("verify")
    );
}

pub(super) struct Seed<const I: usize, const STAGED: usize = 1>(pub(super) Option<Vec<Fp>>);
impl<const I: usize, const STAGED: usize> Step<Pasta> for Seed<I, STAGED> {
    const INDEX: Index = Index::new(I);
    const NUM_STAGED: usize = STAGED;
    type Witness<'s> = Fp;
    type Aux<'s> = ();
    type Left = ();
    type Right = ();
    type Output = ValueHeader;
    fn staged<'s>(
        &self,
        root: &Fp,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        Ok(vec![*root; STAGED])
    }
    fn polynomials<'s>(
        &self,
        root: &Fp,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; 3]> {
        let mut polynomials = [
            vec![Fp::ONE],
            vec![-*root, Fp::ONE, Fp::ZERO],
            vec![Fp::ONE],
        ];
        if let Some(polynomial) = &self.0 {
            polynomials[2] = polynomial.clone();
        }
        Ok(polynomials)
    }
    fn witness<'dr, 's: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Witnessed<'dr, 's, Self, D, N>
    where
        Self: 'dr,
    {
        let y = oracles.query_at_zeta(dr, Slot::output(1))?;
        let expected = oracles.zeta().sub(dr, &oracles.staged()[0]);
        y.enforce_equal(dr, &expected)?;
        // A second opening of the same slot at a different point is supported.
        let root = oracles.staged()[0].clone();
        let at_root = oracles.query(dr, Slot::output(1), &root)?;
        let zero = Element::constant(dr, Fp::ZERO);
        at_root.enforce_equal(dr, &zero)?;
        let stamp = oracles.bridge_hash()[0].clone();
        let data = stamp.value().map(|v| *v);
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(stamp),
            ),
            data,
            D::unit(),
        ))
    }
}

pub(super) struct ValueHeader;
impl Header<Fp> for ValueHeader {
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    const SUFFIX: Suffix = Suffix::new(0);
    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

pub(super) type Witnessed<'dr, 'source, S, D, const N: usize> = Result<(
    (
        Encoded<'dr, D, <S as Step<Pasta>>::Left, N>,
        Encoded<'dr, D, <S as Step<Pasta>>::Right, N>,
        Encoded<'dr, D, <S as Step<Pasta>>::Output, N>,
    ),
    DriverValue<D, <<S as Step<Pasta>>::Output as Header<Fp>>::Data>,
    DriverValue<D, <S as Step<Pasta>>::Aux<'source>>,
)>;

pub(super) struct Merge(pub(super) bool);
impl Step<Pasta> for Merge {
    const INDEX: Index = Index::new(1);
    const NUM_STAGED: usize = 1;
    type Witness<'s> = Option<Fp>;
    type Aux<'s> = ();
    type Left = ValueHeader;
    type Right = ValueHeader;
    type Output = ValueHeader;
    fn staged<'s>(
        &self,
        _: &Option<Fp>,
        left: HeaderInput<'_, Fp, ValueHeader>,
        _: HeaderInput<'_, Fp, ValueHeader>,
    ) -> Result<Vec<Fp>> {
        Ok(vec![*left.data])
    }
    fn polynomials<'s>(
        &self,
        _: &Option<Fp>,
        left: HeaderInput<'_, Fp, ValueHeader>,
        right: HeaderInput<'_, Fp, ValueHeader>,
    ) -> Result<[Vec<Fp>; 3]> {
        let (l, r) = (&left.polynomials[1], &right.polynomials[1]);
        let mut product = vec![Fp::ZERO; l.len() + r.len() - 1];
        for (i, a) in l.iter().enumerate() {
            for (j, b) in r.iter().enumerate() {
                product[i + j] += *a * *b;
            }
        }
        if self.0 {
            product[0] += Fp::ONE;
        }
        Ok([vec![Fp::ONE], product, vec![Fp::ONE]])
    }
    fn witness<'dr, 's: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Option<Fp>>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Witnessed<'dr, 's, Self, D, N>
    where
        Self: 'dr,
    {
        let l = oracles.query_at_zeta(dr, Slot::left(1))?;
        let r = oracles.query_at_zeta(dr, Slot::right(1))?;
        let o = oracles.query_at_zeta(dr, Slot::output(1))?;
        l.mul(dr, &r)?.enforce_equal(dr, &o)?;
        // A separate witness can supply the returned input gadget while the
        // carried data feeds the staged output. The framework must bind both.
        let left = witness.map(|override_data| override_data.unwrap_or(*left.as_ref().take()));
        let stamp = oracles.staged()[0].clone();
        let data = stamp.value().map(|v| *v);
        Ok((
            (
                Encoded::new(dr, &mut (), left)?,
                Encoded::new(dr, &mut (), right)?,
                Encoded::from_gadget(stamp),
            ),
            data,
            D::unit(),
        ))
    }
}

#[test]
fn polynomial_flow_and_header_binding() -> Result<()> {
    let params = test_params();
    let app = ApplicationBuilder::new()
        .register(Seed::<0>(None))?
        .register(Merge(false))?
        .finalize(params)?;
    let mut rng = StdRng::seed_from_u64(0);
    let (left, ()) = app.seed(&mut rng, Seed::<0>(None), Fp::from(5u64))?;
    let (right, ()) = app.seed(&mut rng, Seed::<0>(None), Fp::from(7u64))?;
    assert_eq!(left.polynomials()[1].len(), 2);
    assert_eq!(app.commit(&left.polynomials()[1])?, left.commitments()[1]);
    let point = left.commitments()[1];
    let (x, y) = point.coordinates().expect("finite");
    let generators = Pasta::nested_generators(params).g();
    assert_eq!(
        app.bridge_hash(point)?,
        ragu_core::msm([x, y], [generators[3975], generators[8071]]).to_affine()
    );
    assert_eq!(
        *left.data(),
        app.bridge_hash(left.commitments()[1])?
            .coordinates()
            .expect("finite")
            .0
    );
    assert!(
        app.fuse(&mut rng, Merge(true), None, left.clone(), right.clone())
            .is_err()
    );
    let forged = left
        .proof()
        .clone()
        .carry::<ValueHeader>(*left.data() + Fp::ONE);
    assert!(!app.verify_uncompressed(&forged, &mut rng)?);
    assert!(
        app.fuse(
            &mut rng,
            Merge(false),
            Some(*left.data()),
            forged,
            right.clone()
        )
        .is_err()
    );
    let (merged, ()) = app.fuse(&mut rng, Merge(false), None, left, right.clone())?;
    assert!(app.verify_uncompressed(&merged, &mut rng)?);
    super::proof::check_codecs(&app, &merged, &right, &mut rng)?;
    // Correct header and polynomial data, but an index this app does not accept.
    let other = ApplicationBuilder::new()
        .register(Seed::<0>(None))?
        .register(Merge(false))?
        .register(Seed::<2>(None))?
        .finalize(test_params())?;
    let (foreign, ()) = other.seed(&mut rng, Seed::<2>(None), Fp::from(5u64))?;
    assert!(!app.verify_uncompressed(&foreign, &mut rng)?);
    assert!(
        app.fuse(&mut rng, Merge(false), None, foreign, right)
            .is_err()
    );
    let root = Fp::from(5u64);
    let (valid, ()) = app.seed(&mut rng, Seed::<0>(None), root)?;
    assert!(app.verify_uncompressed(&valid, &mut rng)?);
    let mut oversized = valid.polynomials()[2].clone();
    oversized.resize(TestRank::num_coeffs() + 1, Fp::ZERO);
    // Existing zero rejection, the trailing-zero capacity bug, and a nonzero
    // polynomial whose commitment cancels in the extra (non-bridge) slot.
    for (polynomial, expected) in [
        (vec![Fp::ZERO], "an online polynomial must not be zero"),
        (oversized, "polynomial exceeds rank capacity"),
        (
            vec![Fp::from(2), -Fp::ONE],
            "an online commitment must not be the identity",
        ),
    ] {
        let Err(Error::InvalidWitness(message)) =
            app.seed(&mut rng, Seed::<0>(Some(polynomial)), root)
        else {
            panic!("expected {expected}");
        };
        assert_eq!(message.to_string(), expected);
    }
    assert!(
        ApplicationBuilder::new()
            .register(Seed::<0, { 2 << (TestRank::RANK - 2) }>(None))
            .is_err()
    );
    Ok(())
}
