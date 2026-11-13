use ragu_circuits::polynomials::{ProductionRank as TestRank, Rank};
use ragu_core::{
    Cycle as _, FixedGenerators as _, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
    pasta::{Fp, PallasGenerators, Pasta, PastaParams, VestaGenerators},
};
use ragu_primitives::{Element, allocator::Allocator};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::AffineAdapter;

use super::{
    super::{
        CompressedProof,
        header::{Header, Padding, Suffix},
        step::{Encoded, Index, Oracles, Step},
    },
    application::{
        Merge, ValueHeader as PolynomialHeader, Witnessed, test_builder_for, test_params,
        test_params_for,
    },
};

type Application = crate::Application<'static, Pasta, TestRank, 4>;
type Pcd<H> = crate::Pcd<Pasta, TestRank, H>;
type Proof = crate::Proof<Pasta, TestRank>;

/// Header carrying one field element, as an application header would.
struct ValueHeader;

impl Header<Fp> for ValueHeader {
    type OnlinePolyCommit = (Padding, Padding);
    type Data = u64;
    type Output = Kind![Fp; Element<'_, _>];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, data.map(Fp::from))
    }
}

/// Seed step producing a [`ValueHeader`].
struct ValueSeedStep;

impl Step<Pasta> for ValueSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = ValueHeader;
    type Right = ();
    type Witness<'source> = u64;

    const INDEX: Index = Index::new(0);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        _right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Witnessed<'dr, 'source, Self, D, HEADER_SIZE> {
        let output = Encoded::new(dr, &mut (), witness.clone())?;
        Ok((
            (Encoded::from_gadget(()), Encoded::from_gadget(()), output),
            witness,
            D::unit(),
        ))
    }
}

/// Application with [`ValueSeedStep`] registered.
fn value_app() -> Application {
    test_builder_for::<TestRank>()
        .register(ValueSeedStep)
        .expect("register")
        .finalize(test_params())
        .expect("finalize")
}

#[test]
fn round_trip() {
    let mut rng = StdRng::seed_from_u64(0);
    let app = value_app();
    let (pcd, ()) = app.seed(&mut rng, ValueSeedStep, 7u64).expect("seed");

    let bytes = pcd.proof().to_bytes().expect("encode proof");
    let recovered = Proof::from_bytes(&bytes).expect("round trip should succeed");
    assert_eq!(
        pcd.proof().to_bytes().expect("encode proof"),
        recovered.to_bytes().expect("encode proof")
    );
}

#[test]
fn differential_verification_accepts_and_rejects() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(3);
    let app = value_app();
    let (pcd, ()) = app.seed(&mut rng, ValueSeedStep, 7)?;
    assert!(app.verify_differential(&pcd, &mut rng)?);
    let mismatched = pcd.proof().clone().carry::<ValueHeader>(8);
    assert!(!app.verify_differential(&mismatched, &mut rng)?);
    Ok(())
}

pub(super) fn check_codecs(
    app: &Application,
    merged: &Pcd<PolynomialHeader>,
    right: &Pcd<PolynomialHeader>,
    rng: &mut StdRng,
) -> Result<()> {
    let bytes = merged.proof().to_bytes().expect("encode proof");
    assert_eq!(bytes.len(), Proof::encoded_len::<4>());
    let decoded = Proof::from_bytes(&bytes)
        .expect("decode proof")
        .carry::<PolynomialHeader>(*merged.data());
    assert_eq!(decoded.polynomials(), merged.polynomials());
    assert!(app.verify_uncompressed(&decoded, &mut *rng)?);
    let (resumed, ()) = app.fuse(rng, Merge(false), None, decoded, right.clone())?;
    assert!(app.verify_uncompressed(&resumed, &mut *rng)?);
    let mut corrupt = bytes;
    corrupt[CompressedProof::<Pasta>::encoded_len::<TestRank, 4>()] ^= 2; // Alter a coefficient, not its commitment.
    let corrupt = Proof::from_bytes(&corrupt)
        .expect("decode representation")
        .carry::<PolynomialHeader>(*merged.data());
    assert!(!app.verify_uncompressed(&corrupt, &mut *rng)?);
    assert!(
        app.fuse(rng, Merge(false), None, corrupt, right.clone())
            .is_err()
    );
    let compressed = app.compress(&resumed, rng)?;
    assert_eq!(compressed.online_commitments(), resumed.commitments());
    assert_eq!(
        compressed.proof().online_commitments(),
        resumed.commitments()
    );
    let bytes = compressed
        .proof()
        .to_bytes()
        .expect("encode compressed proof");
    let decoded = CompressedProof::<Pasta>::from_bytes(&bytes)
        .expect("decode compressed proof")
        .carry::<PolynomialHeader>(*compressed.data());
    assert!(app.verify_compressed(&decoded)?);
    assert_eq!(decoded.online_commitments(), resumed.commitments());
    assert_eq!(decoded.proof().online_commitments(), resumed.commitments());
    let ordinary = resumed.proof().to_bytes().expect("encode ordinary proof");
    assert!(matches!(
        CompressedProof::<Pasta>::from_bytes(&ordinary[..bytes.len()]),
        Err(crate::wire::Error::Invalid {
            reason: "proof payload kind mismatch",
            ..
        })
    ));
    Ok(())
}

#[test]
fn compressed_proofs_reject_other_setup_and_rank() -> Result<()> {
    type LargerRank = ragu_circuits::polynomials::R<14>;
    let params = test_params_for::<LargerRank>();
    let app = test_builder_for::<TestRank>()
        .register(ValueSeedStep)?
        .finalize(params)?;
    let mut rng = StdRng::seed_from_u64(1);
    let (pcd, ()) = app.seed(&mut rng, ValueSeedStep, 7)?;
    let compressed = app.compress(&pcd, &mut rng)?;
    let decoded = CompressedProof::<Pasta>::from_bytes(
        &compressed.proof().to_bytes().expect("encode compressed"),
    )
    .expect("decode compressed")
    .carry::<ValueHeader>(7);
    assert!(app.verify_compressed(&decoded)?);
    let host = Pasta::host_generators(params);
    let nested = Pasta::nested_generators(params);
    let mut host_g = host.g().to_vec();
    host_g[0] = -host_g[0];
    let other_params = PastaParams::new(
        PallasGenerators::new(
            AffineAdapter::as_slice(nested.g()),
            AffineAdapter::as_slice(&[*nested.h()])[0],
        ),
        VestaGenerators::new(
            AffineAdapter::as_slice(&host_g).to_vec().leak(),
            AffineAdapter::as_slice(&[*host.h()])[0],
        ),
    );
    let other = test_builder_for::<TestRank>()
        .register(ValueSeedStep)?
        .finalize(&other_params)?;
    assert!(!other.verify_compressed(&decoded)?);
    let wide = test_builder_for::<LargerRank>()
        .register(ValueSeedStep)?
        .finalize(params)?;
    let (pcd, ()) = wide.seed(&mut rng, ValueSeedStep, 7)?;
    let mut bytes = wide
        .compress(&pcd, &mut rng)?
        .proof()
        .to_bytes()
        .expect("encode wide proof");
    bytes[16..20].copy_from_slice(&TestRank::RANK.to_le_bytes());
    assert!(matches!(
        CompressedProof::<Pasta>::from_bytes(&bytes),
        Err(crate::wire::Error::Invalid {
            reason: "mock proof binding mismatch",
            ..
        })
    ));
    Ok(())
}
