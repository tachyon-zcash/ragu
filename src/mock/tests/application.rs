use alloc::vec::Vec;

use ragu_circuits::polynomials::{TestRank, sparse};
use ragu_core::{
    Coeff, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
    pasta::{Ep, Eq, Fp, Fq},
};
use ragu_primitives::Element;
use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective;

use super::{assert_invalid_witness, test_params};
use crate::{
    Application, ApplicationBuilder, Header, Index, PROOF_SIZE_COMPRESSED, Pcd, Proof, Step,
    StepCtx, Suffix,
};

struct TestHeader;

#[derive(Clone, Debug)]
struct TestHeaderData {
    value: u64,
}

impl Header for TestHeader {
    type Data = TestHeaderData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (
            alloc::vec![Fp::from(data.value)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

struct SeedStep;

impl Step for SeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = u64;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(witness.map(|value| (TestHeaderData { value }, ())).cast())
    }
}

struct EvaluationHeader;

impl Header for EvaluationHeader {
    type Data = Fp;

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (alloc::vec![*data], Vec::new(), Vec::new(), Vec::new())
    }
}

struct PolynomialSeedStep;

impl Step for PolynomialSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = EvaluationHeader;
    type Right = ();
    type Witness<'source> = sparse::Polynomial<Fp, TestRank>;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let handle = ctx.witness_polynomial(witness)?;
        let x = Fp::from(2u64);
        let evaluation = ctx.evaluate(&handle, D::just(|| x))?;
        let x_gadget = Element::constant(ctx.dr, x);
        let y_gadget = Element::alloc(ctx.dr, &mut (), evaluation.clone())?;
        ctx.enforce_poly_query(&handle, x_gadget, y_gadget)?;
        Ok((evaluation, D::unit()))
    }
}

struct ConstrainedSeedStep;

impl Step for ConstrainedSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = Fp;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let value = Element::alloc(ctx.dr, &mut (), witness)?;
        value.enforce_zero(ctx.dr)?;
        Ok(D::just(|| (TestHeaderData { value: 0 }, ())).cast())
    }
}

struct GateCheckSeedStep;

impl Step for GateCheckSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        ctx.dr.mul(|| Ok((Coeff::One, Coeff::One, Coeff::Zero)))?;
        Ok(D::just(|| (TestHeaderData { value: 0 }, ())).cast())
    }
}

struct BadPolynomialQuerySeedStep;

impl Step for BadPolynomialQuerySeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = sparse::Polynomial<Fp, TestRank>;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let handle = ctx.witness_polynomial(witness)?;
        let x_gadget = Element::constant(ctx.dr, Fp::from(2u64));
        let incorrect_y = Element::constant(ctx.dr, Fp::from(22u64));
        ctx.enforce_poly_query(&handle, x_gadget, incorrect_y)?;
        Ok(D::just(|| (TestHeaderData { value: 0 }, ())).cast())
    }
}

struct MergeStep;

impl Step for MergeStep {
    type Aux<'source> = ();
    type Left = TestHeader;
    type Output = TestHeader;
    type Right = TestHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(D::just(|| {
            (
                TestHeaderData {
                    value: left.take().value + right.take().value,
                },
                (),
            )
        })
        .cast())
    }
}

#[test]
fn seed_then_verify() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");

    let valid = app.verify(&pcd, &mut rng).expect("verify should succeed");
    assert!(valid, "proof should verify against matching header data");
}

#[test]
fn seed_executes_polynomial_hooks() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(PolynomialSeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");
    let polynomial = sparse::Polynomial::<Fp, TestRank>::from_coeffs(alloc::vec![
        Fp::from(3u64),
        Fp::from(1u64),
        Fp::from(4u64),
    ]);

    let (pcd, ()) = app
        .seed(&mut rng, PolynomialSeedStep, polynomial)
        .expect("a valid polynomial opening should seed");

    assert_eq!(*pcd.data(), Fp::from(21u64));
    assert!(app.verify(&pcd, &mut rng).expect("verify should succeed"));
}

#[test]
fn application_execution_checks_constraints_and_polynomial_queries() {
    let mut rng = StdRng::seed_from_u64(0);
    let constrained_app = ApplicationBuilder::new()
        .register(ConstrainedSeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");
    constrained_app
        .seed(&mut rng, ConstrainedSeedStep, Fp::from(0u64))
        .expect("an allocated zero constrained to zero should succeed");
    let error = match constrained_app.seed(&mut rng, ConstrainedSeedStep, Fp::from(1u64)) {
        Ok(_) => panic!("an allocated one constrained to zero should fail"),
        Err(error) => error,
    };
    assert_invalid_witness(error, "constraint failed");

    let gate_app = ApplicationBuilder::new()
        .register(GateCheckSeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");
    let error = match gate_app.seed(&mut rng, GateCheckSeedStep, ()) {
        Ok(_) => panic!("a gate assigned (1, 1, 0) should fail"),
        Err(error) => error,
    };
    assert_invalid_witness(error, "gate check failed");

    let polynomial_app = ApplicationBuilder::new()
        .register(BadPolynomialQuerySeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");
    let polynomial = sparse::Polynomial::<Fp, TestRank>::from_coeffs(alloc::vec![
        Fp::from(3u64),
        Fp::from(1u64),
        Fp::from(4u64),
    ]);
    let error = match polynomial_app.seed(&mut rng, BadPolynomialQuerySeedStep, polynomial) {
        Ok(_) => panic!("an incorrect polynomial query through seed should fail"),
        Err(error) => error,
    };
    assert_invalid_witness(
        error,
        "poly-query rejected: the polynomial does not evaluate to the claimed value at the claimed point",
    );
}

#[test]
fn verify_rejects_wrong_data() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");
    let bad_pcd = pcd.proof.carry::<TestHeader>(TestHeaderData { value: 999 });

    let valid = app
        .verify(&bad_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(!valid, "proof should reject mismatched header data");
}

#[test]
fn fuse_then_verify() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .register(MergeStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd_a, ()) = app.seed(&mut rng, SeedStep, 10u64).expect("seed a");
    let (pcd_b, ()) = app.seed(&mut rng, SeedStep, 20u64).expect("seed b");

    let (merged_pcd, ()) = app
        .fuse(&mut rng, MergeStep, (), pcd_a, pcd_b)
        .expect("fuse should succeed");

    let valid = app
        .verify(&merged_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(valid, "merged proof should verify");
}

#[test]
fn fuse_rejects_wrong_sum() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize");

    let (pcd_a, ()) = app.seed(&mut rng, SeedStep, 10u64).expect("seed a");
    let (pcd_b, ()) = app.seed(&mut rng, SeedStep, 20u64).expect("seed b");

    let (merged_pcd, ()) = app
        .fuse(&mut rng, MergeStep, (), pcd_a, pcd_b)
        .expect("fuse");
    let bad_pcd = merged_pcd
        .proof
        .carry::<TestHeader>(TestHeaderData { value: 31 });

    let valid = app.verify(&bad_pcd, &mut rng).expect("verify");
    assert!(!valid, "fused proof must reject wrong header data");
}

#[test]
fn deep_fuse_chain() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize");

    let mut pcds = Vec::new();
    for val in 1u64..=4 {
        let (pcd, ()) = app.seed(&mut rng, SeedStep, val).expect("seed");
        pcds.push(pcd);
    }

    let pcd1 = pcds.remove(0);
    let pcd2 = pcds.remove(0);
    let (merged_left, ()) = app
        .fuse(&mut rng, MergeStep, (), pcd1, pcd2)
        .expect("fuse left");

    let pcd3 = pcds.remove(0);
    let pcd4 = pcds.remove(0);
    let (merged_right, ()) = app
        .fuse(&mut rng, MergeStep, (), pcd3, pcd4)
        .expect("fuse right");

    let (final_pcd, ()) = app
        .fuse(&mut rng, MergeStep, (), merged_left, merged_right)
        .expect("fuse final");

    assert!(
        app.verify(&final_pcd, &mut rng).expect("verify"),
        "depth-2 fuse tree must verify"
    );

    let bad_pcd = final_pcd
        .proof
        .carry::<TestHeader>(TestHeaderData { value: 11 });
    assert!(
        !app.verify(&bad_pcd, &mut rng).expect("verify"),
        "wrong total must fail"
    );
}

#[test]
fn different_merge_trees_same_header() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize");

    let (pa, ()) = app.seed(&mut rng, SeedStep, 1u64).expect("seed a");
    let (pb, ()) = app.seed(&mut rng, SeedStep, 2u64).expect("seed b");
    let (pc, ()) = app.seed(&mut rng, SeedStep, 3u64).expect("seed c");

    // Tree shape 1: fuse(fuse(a, b), c)
    let (ab, ()) = app
        .fuse(&mut rng, MergeStep, (), pa.clone(), pb.clone())
        .expect("fuse ab");
    let (left_leaning, ()) = app
        .fuse(&mut rng, MergeStep, (), ab, pc.clone())
        .expect("fuse (ab)c");

    // Tree shape 2: fuse(a, fuse(b, c))
    let (bc, ()) = app.fuse(&mut rng, MergeStep, (), pb, pc).expect("fuse bc");
    let (right_leaning, ()) = app
        .fuse(&mut rng, MergeStep, (), pa, bc)
        .expect("fuse a(bc)");

    assert!(app.verify(&left_leaning, &mut rng).expect("verify"));
    assert!(app.verify(&right_leaning, &mut rng).expect("verify"));
    assert_ne!(
        left_leaning.proof.serialize(),
        right_leaning.proof.serialize(),
        "different tree shapes must produce different proofs"
    );
}

/// Header value is `witness²`, aux is `vec![witness²]`.
struct AuxSeedStep;

impl Step for AuxSeedStep {
    type Aux<'source> = Vec<u64>;
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = u64;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(witness
            .map(|witness| {
                let squared = witness * witness;
                (TestHeaderData { value: squared }, alloc::vec![squared])
            })
            .cast())
    }
}

struct AuxMergeStep;

impl Step for AuxMergeStep {
    type Aux<'source> = Vec<u64>;
    type Left = TestHeader;
    type Output = TestHeader;
    type Right = TestHeader;
    type Witness<'source> = (Vec<u64>, Vec<u64>);

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(D::just(|| {
            let (left_aux, right_aux) = witness.take();
            let mut combined = left_aux;
            combined.extend(right_aux);
            (
                TestHeaderData {
                    value: left.take().value + right.take().value,
                },
                combined,
            )
        })
        .cast())
    }
}

#[test]
fn aux_data_flows_through_seed_and_fuse() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(AuxSeedStep)
        .expect("register")
        .register(AuxMergeStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize");

    let (pcd_a, aux_a) = app.seed(&mut rng, AuxSeedStep, 3u64).expect("seed a");
    assert_eq!(aux_a, alloc::vec![9]);

    let (pcd_b, aux_b) = app.seed(&mut rng, AuxSeedStep, 4u64).expect("seed b");
    assert_eq!(aux_b, alloc::vec![16]);

    let (merged_pcd, merged_aux) = app
        .fuse(&mut rng, AuxMergeStep, (aux_a, aux_b), pcd_a, pcd_b)
        .expect("fuse");

    assert_eq!(merged_aux, alloc::vec![9, 16]);
    let reconstructed_value: u64 = merged_aux.iter().sum();
    assert_eq!(reconstructed_value, 25);
    let valid = app.verify(&merged_pcd, &mut rng).expect("verify");
    assert!(valid, "fused proof must verify");
}

#[test]
fn serialized_proof_still_verifies() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");
    let saved_data = pcd.data.clone();

    let bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    let recovered_proof = Proof::try_from(&bytes).expect("recovered proof should deserialize");

    let recovered_pcd = recovered_proof.carry::<TestHeader>(saved_data);
    let valid = app
        .verify(&recovered_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(valid, "round-tripped proof should still verify");
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

    let bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    let recovered_proof = Proof::try_from(&bytes).expect("recovered proof should deserialize");

    let bad_pcd = recovered_proof.carry::<TestHeader>(TestHeaderData { value: 999 });
    let valid = app
        .verify(&bad_pcd, &mut rng)
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

    let mut bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    bytes[0] ^= 0xFFu8;
    assert!(
        Proof::try_from(&bytes).is_err(),
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
        .verify(&rerand_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(valid, "rerandomized proof should still verify");
    assert_ne!(
        rerand_pcd.proof.serialize(),
        original_proof.serialize(),
        "rerandomization must change the proof"
    );
}

/// Distinct Header type that declares the same `SUFFIX` value as `TestHeader`.
struct ConflictingHeader;

impl Header for ConflictingHeader {
    type Data = TestHeaderData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (
            alloc::vec![Fp::from(data.value)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Second seed step claiming `Index::new(0)` for the duplicate-index test.
struct DuplicateIndexStep;

impl Step for DuplicateIndexStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(D::just(|| (TestHeaderData { value: 0 }, ())).cast())
    }
}

/// Seed step whose output is `ConflictingHeader` (which collides with
/// `TestHeader::SUFFIX`).
struct SuffixCollisionStep;

impl Step for SuffixCollisionStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = ConflictingHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(D::just(|| (TestHeaderData { value: 0 }, ())).cast())
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
    impl Step for InternalIndexStep {
        type Aux<'source> = ();
        type Left = ();
        type Output = TestHeader;
        type Right = ();
        type Witness<'source> = ();

        const INDEX: Index = Index::internal(0);

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _ctx: &mut StepCtx<'_, 'dr, D>,
            _witness: DriverValue<D, Self::Witness<'source>>,
            _left: DriverValue<D, <Self::Left as Header>::Data>,
            _right: DriverValue<D, <Self::Right as Header>::Data>,
        ) -> Result<(
            DriverValue<D, <Self::Output as Header>::Data>,
            DriverValue<D, Self::Aux<'source>>,
        )>
        where
            Self: 'dr,
        {
            Ok(D::just(|| (TestHeaderData { value: 0 }, ())).cast())
        }
    }

    let result = ApplicationBuilder::new().register(InternalIndexStep);
    assert!(
        result.is_err(),
        "application-defined steps must not use Index::Internal"
    );
}

#[test]
fn verify_rejects_unregistered_step_index() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let encoded = TestHeader::encode(&TestHeaderData { value: 42 });
    let forged_proof = Proof::new(
        TestHeader::SUFFIX,
        Index::new(999),
        &encoded,
        b"unused-witness",
    )
    .expect("header without points hashes without error");
    let forged_pcd: Pcd<TestHeader> =
        forged_proof.carry::<TestHeader>(TestHeaderData { value: 42 });

    let valid = app
        .verify(&forged_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(
        !valid,
        "proof whose step_index is outside the registered range must fail verify"
    );
}

#[test]
fn verify_rejects_swapped_header_type() {
    struct SwappedHeader;
    impl Header for SwappedHeader {
        type Data = TestHeaderData;

        const SUFFIX: Suffix = Suffix::new(99);

        fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
            (
                alloc::vec![Fp::from(data.value)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        }
    }

    let mut rng = StdRng::seed_from_u64(0);
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize(test_params())
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng, SeedStep, 42u64)
        .expect("seed should succeed");

    let swapped_pcd: Pcd<SwappedHeader> = pcd
        .proof
        .carry::<SwappedHeader>(TestHeaderData { value: 42 });

    let valid = app
        .verify(&swapped_pcd, &mut rng)
        .expect("verify should succeed");
    assert!(
        !valid,
        "proof bound to a different Header SUFFIX must fail verify"
    );
}

/// Header carrying a Vesta commitment point.
struct PointHeader;

#[derive(Clone, Debug)]
struct PointHeaderData {
    commitment: Eq,
}

impl Header for PointHeader {
    type Data = PointHeaderData;

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            alloc::vec![data.commitment],
        )
    }
}

/// Seed step whose output header carries the witness point.
struct PointSeedStep;

impl Step for PointSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = PointHeader;
    type Right = ();
    type Witness<'source> = Eq;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(witness
            .map(|commitment| (PointHeaderData { commitment }, ()))
            .cast())
    }
}

/// Step consuming a [`PointHeader`] as its left input.
struct PointConsumeStep;

impl Step for PointConsumeStep {
    type Aux<'source> = ();
    type Left = PointHeader;
    type Output = TestHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(1);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header>::Data>,
        _right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> Result<(
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        Ok(D::just(|| (TestHeaderData { value: 1 }, ())).cast())
    }
}

/// Application with [`PointSeedStep`] registered.
fn point_app() -> Application<'static> {
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
        .seed(&mut rng, PointSeedStep, Eq::generator())
        .expect("seed with a non-identity point");
    assert!(app.verify(&pcd, &mut rng).expect("verify"));
}

#[test]
fn identity_point_in_output_header_fails_fuse() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = point_app();

    assert!(
        matches!(
            app.seed(&mut rng, PointSeedStep, Eq::identity()),
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

    let bad_left = Proof::bootstrap().carry::<PointHeader>(PointHeaderData {
        commitment: Eq::identity(),
    });
    let right = Proof::bootstrap().carry::<()>(());

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
        .seed(&mut rng, PointSeedStep, Eq::generator())
        .expect("seed with a non-identity point");
    let bad_pcd = pcd.proof.carry::<PointHeader>(PointHeaderData {
        commitment: Eq::identity(),
    });

    // Errs rather than returning `Ok(false)`: re-encoding such a header
    // fails synthesis in real ragu, it does not merely mismatch.
    assert!(matches!(
        app.verify(&bad_pcd, &mut rng),
        Err(Error::InvalidWitness(_))
    ));
}
