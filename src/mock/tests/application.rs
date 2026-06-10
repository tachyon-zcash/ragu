use alloc::vec::Vec;

use rand::thread_rng as rng;

use crate::{
    application::*,
    ctx::StepCtx,
    error::Result,
    header::{Header, Suffix},
    proof::{PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::{Index, Step},
};

struct TestHeader;

#[derive(Clone, Debug)]
struct TestHeaderData {
    value: u64,
}

impl Header for TestHeader {
    type Data = TestHeaderData;

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let bytes = data.value.to_le_bytes();
        bytes.to_vec()
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

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((TestHeaderData { value: witness }, ()))
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

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        _witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            TestHeaderData {
                value: left.value + right.value,
            },
            (),
        ))
    }
}

#[test]
fn seed_then_verify() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
        .expect("seed should succeed");

    let valid = app.verify(&pcd, rng()).expect("verify should succeed");
    assert!(valid, "proof should verify against matching header data");
}

#[test]
fn verify_rejects_wrong_data() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
        .expect("seed should succeed");
    let bad_pcd = pcd.proof.carry::<TestHeader>(TestHeaderData { value: 999 });

    let valid = app.verify(&bad_pcd, rng()).expect("verify should succeed");
    assert!(!valid, "proof should reject mismatched header data");
}

#[test]
fn fuse_then_verify() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .register(MergeStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd_a, ()) = app.seed(&mut rng(), SeedStep, 10u64).expect("seed a");
    let (pcd_b, ()) = app.seed(&mut rng(), SeedStep, 20u64).expect("seed b");

    let (merged_pcd, ()) = app
        .fuse(&mut rng(), MergeStep, (), pcd_a, pcd_b)
        .expect("fuse should succeed");

    let valid = app
        .verify(&merged_pcd, rng())
        .expect("verify should succeed");
    assert!(valid, "merged proof should verify");
}

#[test]
fn fuse_rejects_wrong_sum() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd_a, ()) = app.seed(&mut rng(), SeedStep, 10u64).expect("seed a");
    let (pcd_b, ()) = app.seed(&mut rng(), SeedStep, 20u64).expect("seed b");

    let (merged_pcd, ()) = app
        .fuse(&mut rng(), MergeStep, (), pcd_a, pcd_b)
        .expect("fuse");
    let bad_pcd = merged_pcd
        .proof
        .carry::<TestHeader>(TestHeaderData { value: 31 });

    let valid = app.verify(&bad_pcd, rng()).expect("verify");
    assert!(!valid, "fused proof must reject wrong header data");
}

#[test]
fn deep_fuse_chain() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let mut pcds = Vec::new();
    for val in 1u64..=4 {
        let (pcd, ()) = app.seed(&mut rng(), SeedStep, val).expect("seed");
        pcds.push(pcd);
    }

    let pcd1 = pcds.remove(0);
    let pcd2 = pcds.remove(0);
    let (merged_left, ()) = app
        .fuse(&mut rng(), MergeStep, (), pcd1, pcd2)
        .expect("fuse left");

    let pcd3 = pcds.remove(0);
    let pcd4 = pcds.remove(0);
    let (merged_right, ()) = app
        .fuse(&mut rng(), MergeStep, (), pcd3, pcd4)
        .expect("fuse right");

    let (final_pcd, ()) = app
        .fuse(&mut rng(), MergeStep, (), merged_left, merged_right)
        .expect("fuse final");

    assert!(
        app.verify(&final_pcd, rng()).expect("verify"),
        "depth-2 fuse tree must verify"
    );

    let bad_pcd = final_pcd
        .proof
        .carry::<TestHeader>(TestHeaderData { value: 11 });
    assert!(
        !app.verify(&bad_pcd, rng()).expect("verify"),
        "wrong total must fail"
    );
}

#[test]
fn different_merge_trees_same_header() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register")
        .register(MergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pa, ()) = app.seed(&mut rng(), SeedStep, 1u64).expect("seed a");
    let (pb, ()) = app.seed(&mut rng(), SeedStep, 2u64).expect("seed b");
    let (pc, ()) = app.seed(&mut rng(), SeedStep, 3u64).expect("seed c");

    // Tree shape 1: fuse(fuse(a, b), c)
    let (ab, ()) = app
        .fuse(&mut rng(), MergeStep, (), pa.clone(), pb.clone())
        .expect("fuse ab");
    let (left_leaning, ()) = app
        .fuse(&mut rng(), MergeStep, (), ab, pc.clone())
        .expect("fuse (ab)c");

    // Tree shape 2: fuse(a, fuse(b, c))
    let (bc, ()) = app
        .fuse(&mut rng(), MergeStep, (), pb, pc)
        .expect("fuse bc");
    let (right_leaning, ()) = app
        .fuse(&mut rng(), MergeStep, (), pa, bc)
        .expect("fuse a(bc)");

    assert!(app.verify(&left_leaning, rng()).expect("verify"));
    assert!(app.verify(&right_leaning, rng()).expect("verify"));
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

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let squared = witness * witness;
        Ok((TestHeaderData { value: squared }, alloc::vec![squared]))
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

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        witness: Self::Witness<'source>,
        left: <Self::Left as Header>::Data,
        right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let (left_aux, right_aux) = witness;
        let mut combined = left_aux;
        combined.extend(right_aux);
        Ok((
            TestHeaderData {
                value: left.value + right.value,
            },
            combined,
        ))
    }
}

#[test]
fn aux_data_flows_through_seed_and_fuse() {
    let app = ApplicationBuilder::new()
        .register(AuxSeedStep)
        .expect("register")
        .register(AuxMergeStep)
        .expect("register")
        .finalize()
        .expect("finalize");

    let (pcd_a, aux_a) = app.seed(&mut rng(), AuxSeedStep, 3u64).expect("seed a");
    assert_eq!(aux_a, alloc::vec![9]);

    let (pcd_b, aux_b) = app.seed(&mut rng(), AuxSeedStep, 4u64).expect("seed b");
    assert_eq!(aux_b, alloc::vec![16]);

    let (merged_pcd, merged_aux) = app
        .fuse(&mut rng(), AuxMergeStep, (aux_a, aux_b), pcd_a, pcd_b)
        .expect("fuse");

    assert_eq!(merged_aux, alloc::vec![9, 16]);
    let reconstructed_value: u64 = merged_aux.iter().sum();
    assert_eq!(reconstructed_value, 25);
    let valid = app.verify(&merged_pcd, rng()).expect("verify");
    assert!(valid, "fused proof must verify");
}

#[test]
fn serialized_proof_still_verifies() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
        .expect("seed should succeed");
    let saved_data = pcd.data.clone();

    let bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    let recovered_proof = Proof::try_from(&bytes).expect("recovered proof should deserialize");

    let recovered_pcd = recovered_proof.carry::<TestHeader>(saved_data);
    let valid = app
        .verify(&recovered_pcd, rng())
        .expect("verify should succeed");
    assert!(valid, "round-tripped proof should still verify");
}

#[test]
fn serialized_proof_rejects_mismatched_header_data() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
        .expect("seed should succeed");

    let bytes: [u8; PROOF_SIZE_COMPRESSED] = pcd.proof.into();
    let recovered_proof = Proof::try_from(&bytes).expect("recovered proof should deserialize");

    let bad_pcd = recovered_proof.carry::<TestHeader>(TestHeaderData { value: 999 });
    let valid = app.verify(&bad_pcd, rng()).expect("verify should succeed");
    assert!(
        !valid,
        "round-tripped proof must still reject mismatched header data"
    );
}

#[test]
fn tampered_serialized_proof_fails_to_deserialize() {
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
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
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
        .expect("seed should succeed");
    let original_proof = pcd.proof.clone();

    let rerand_pcd = app
        .rerandomize(pcd, &mut rng())
        .expect("rerandomize should succeed");
    let valid = app
        .verify(&rerand_pcd, rng())
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

    fn encode(data: &Self::Data) -> Vec<u8> {
        data.value.to_le_bytes().to_vec()
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

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        _witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((TestHeaderData { value: 0 }, ()))
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

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        _witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((TestHeaderData { value: 0 }, ()))
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

        fn witness<'source>(
            &self,
            _ctx: &mut StepCtx<'_>,
            _witness: Self::Witness<'source>,
            _left: <Self::Left as Header>::Data,
            _right: <Self::Right as Header>::Data,
        ) -> Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
            Ok((TestHeaderData { value: 0 }, ()))
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
    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let encoded = TestHeader::encode(&TestHeaderData { value: 42 });
    let forged_proof = Proof::new(
        TestHeader::SUFFIX,
        Index::new(999),
        &encoded,
        b"unused-witness",
    );
    let forged_pcd: Pcd<TestHeader> =
        forged_proof.carry::<TestHeader>(TestHeaderData { value: 42 });

    let valid = app
        .verify(&forged_pcd, rng())
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

        fn encode(data: &Self::Data) -> Vec<u8> {
            data.value.to_le_bytes().to_vec()
        }
    }

    let app = ApplicationBuilder::new()
        .register(SeedStep)
        .expect("register should succeed")
        .finalize()
        .expect("finalize should succeed");

    let (pcd, ()) = app
        .seed(&mut rng(), SeedStep, 42u64)
        .expect("seed should succeed");

    let swapped_pcd: Pcd<SwappedHeader> = pcd
        .proof
        .carry::<SwappedHeader>(TestHeaderData { value: 42 });

    let valid = app
        .verify(&swapped_pcd, rng())
        .expect("verify should succeed");
    assert!(
        !valid,
        "proof bound to a different Header SUFFIX must fail verify"
    );
}
