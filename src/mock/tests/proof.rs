use ragu_circuits::polynomials::ProductionRank as TestRank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{Element, allocator::Allocator};
use rand::{SeedableRng as _, rngs::StdRng};

use super::{
    super::{
        ApplicationBuilder, CompressedProof,
        header::{Header, Suffix},
        step::{Encoded, Index, Oracles, Step},
    },
    application::{Merge, ValueHeader as PolynomialHeader, Witnessed, test_params},
};

type Application = crate::Application<'static, Pasta, TestRank, 4>;
type Pcd<H> = crate::Pcd<Pasta, TestRank, H>;
type Proof = crate::Proof<Pasta, TestRank>;

/// Header carrying one field element, as an application header would.
struct ValueHeader;

impl Header<Fp> for ValueHeader {
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
        _oracles: &mut Oracles<'_, 'dr, D>,
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
    ApplicationBuilder::new()
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
    assert!(app.compress(&corrupt, rng).is_err());
    assert!(
        app.fuse(rng, Merge(false), None, corrupt, right.clone())
            .is_err()
    );
    let compressed = app.compress(merged, rng)?;
    let bytes = compressed
        .proof()
        .to_bytes()
        .expect("encode compressed proof");
    assert_eq!(
        bytes.len(),
        CompressedProof::<Pasta>::encoded_len::<TestRank, 4>()
    );
    let decoded = CompressedProof::<Pasta>::from_bytes(&bytes)
        .expect("decode compressed proof")
        .carry::<PolynomialHeader>(*compressed.data());
    assert!(app.verify_compressed(&decoded)?);
    let forged = decoded
        .proof()
        .clone()
        .carry::<PolynomialHeader>(*decoded.data() + Fp::from(1));
    assert!(!app.verify_compressed(&forged)?);
    Ok(())
}
