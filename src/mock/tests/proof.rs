use ragu_circuits::polynomials::{ProductionRank as TestRank, Rank};
use ragu_core::{
    Cycle as _, Error, FixedGenerators as _, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
    pasta::{Fp, PallasGenerators, Pasta, PastaParams, VestaGenerators},
};
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator};
use rand::{SeedableRng as _, rngs::StdRng};
use udon::{curve::AffineAdapter, field::Field as _};

use super::{
    super::{
        ApplicationBuilder, CompressedProof,
        header::{Header, Suffix},
        step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
    },
    application::{
        Merge, ValueHeader as PolynomialHeader, Witnessed, test_params, test_params_for,
    },
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
    let decoded = transport(merged);
    assert_eq!(decoded.polynomials(), merged.polynomials());
    assert!(app.verify_uncompressed(&decoded, &mut *rng)?);
    let right = transport(&app.rerandomize(right.clone(), rng)?);
    let (resumed, ()) = app.fuse(rng, Merge(false), None, decoded, right.clone())?;
    assert!(app.verify_uncompressed(&resumed, &mut *rng)?);
    let resumed = transport(&resumed);
    let expected_lift_polynomials = resumed.polynomials();
    let expected_lift_data = *resumed.data() + Fp::ONE;
    let bootstrap = crate::Proof::<Pasta, TestRank>::from_bytes(
        &app.bootstrap_proof().to_bytes().expect("encode bootstrap"),
    )
    .expect("decode bootstrap")
    .carry::<()>(());
    let (lifted, ()) = app.fuse(rng, Lift, (), resumed, bootstrap)?;
    assert_eq!(lifted.polynomials(), expected_lift_polynomials);
    assert_eq!(*lifted.data(), expected_lift_data);
    let (unmerged, ()) = app.fuse(rng, Unmerge, (), transport(&lifted), right.clone())?;
    assert_eq!(unmerged.polynomials(), merged.polynomials());
    assert_eq!(*unmerged.data(), expected_lift_data - *right.data());
    let unmerged = transport(&unmerged);
    assert!(app.verify_uncompressed(&unmerged, &mut *rng)?);
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
    let compressed = app.compress(&unmerged, rng)?;
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
    assert!(
        CompressedProof::<Pasta>::from_bytes(
            &unmerged.proof().to_bytes().expect("encode proof")[..bytes.len()]
        )
        .is_err()
    );
    let mut wrong_kind = bytes.clone();
    wrong_kind[10..12].copy_from_slice(&1u16.to_le_bytes());
    assert!(CompressedProof::<Pasta>::from_bytes(&wrong_kind).is_err());
    for offset in [8, 12, 14] {
        let mut unsupported = bytes.clone();
        unsupported[offset] ^= 0xff;
        assert!(CompressedProof::<Pasta>::from_bytes(&unsupported).is_err());
        let mut unsupported = unmerged.proof().to_bytes().expect("encode proof");
        unsupported[offset] ^= 0xff;
        assert!(Proof::from_bytes(&unsupported).is_err());
    }
    let forged = decoded
        .proof()
        .clone()
        .carry::<PolynomialHeader>(*decoded.data() + Fp::from(1));
    assert!(!app.verify_compressed(&forged)?);
    Ok(())
}

pub(super) fn transport(pcd: &Pcd<PolynomialHeader>) -> Pcd<PolynomialHeader> {
    let decoded = Proof::from_bytes(&pcd.proof().to_bytes().expect("encode proof"))
        .expect("decode proof")
        .carry::<PolynomialHeader>(*pcd.data());
    assert_eq!(decoded.polynomials(), pcd.polynomials());
    assert_eq!(decoded.commitments(), pcd.commitments());
    assert_eq!(decoded.data(), pcd.data());
    decoded
}

pub(super) struct Lift;

impl Step<Pasta> for Lift {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = PolynomialHeader;
    type Right = ();
    type Output = PolynomialHeader;

    fn polynomials<'source>(
        &self,
        _: &(),
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; 3]> {
        Ok(left.polynomials.clone())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
    ) -> Witnessed<'dr, 'source, Self, D, N> {
        for i in 0..3 {
            let l = oracles.query_at_zeta(dr, Slot::left(i))?;
            let o = oracles.query_at_zeta(dr, Slot::output(i))?;
            l.enforce_equal(dr, &o)?;
        }
        let data = left.as_ref().map(|value| *value + Fp::ONE);
        let left = Encoded::<_, PolynomialHeader, N>::new(dr, &mut (), left)?;
        let output = Encoded::<_, PolynomialHeader, N>::new(dr, &mut (), data.clone())?;
        let one = Element::constant(dr, Fp::ONE);
        left.as_gadget()
            .add(dr, &one)
            .enforce_equal(dr, output.as_gadget())?;
        Ok(((left, Encoded::from_gadget(()), output), data, D::unit()))
    }
}

pub(super) struct Unmerge;

impl Step<Pasta> for Unmerge {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = PolynomialHeader;
    type Right = PolynomialHeader;
    type Output = PolynomialHeader;

    fn polynomials<'source>(
        &self,
        _: &(),
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> Result<[Vec<Fp>; 3]> {
        let mut polynomials = core::array::from_fn(|_| Vec::new());
        for (i, quotient) in polynomials.iter_mut().enumerate() {
            let (l, r) = (&left.polynomials[i], &right.polynomials[i]);
            if l.len() < 2 || r.len() != 2 || r[1] != Fp::ONE {
                return Err(Error::InvalidWitness(
                    "expected monic linear divisor".into(),
                ));
            }
            quotient.resize(l.len() - 1, Fp::ZERO);
            let root = -r[0];
            let mut acc = Fp::ZERO;
            for j in (1..l.len()).rev() {
                acc = l[j] + root * acc;
                quotient[j - 1] = acc;
            }
            if l[0] + root * acc != Fp::ZERO {
                return Err(Error::InvalidWitness(
                    "polynomial division has a remainder".into(),
                ));
            }
        }
        Ok(polynomials)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Witnessed<'dr, 'source, Self, D, N> {
        for i in 0..3 {
            let l = oracles.query_at_zeta(dr, Slot::left(i))?;
            let r = oracles.query_at_zeta(dr, Slot::right(i))?;
            let o = oracles.query_at_zeta(dr, Slot::output(i))?;
            o.mul(dr, &r)?.enforce_equal(dr, &l)?;
        }
        let data = D::just(|| *left.as_ref().take() - *right.as_ref().take());
        let left = Encoded::<_, PolynomialHeader, N>::new(dr, &mut (), left)?;
        let right = Encoded::<_, PolynomialHeader, N>::new(dr, &mut (), right)?;
        let output = Encoded::<_, PolynomialHeader, N>::new(dr, &mut (), data.clone())?;
        output
            .as_gadget()
            .add(dr, right.as_gadget())
            .enforce_equal(dr, left.as_gadget())?;
        Ok(((left, right, output), data, D::unit()))
    }
}

#[test]
fn compressed_proofs_reject_other_setups() -> Result<()> {
    let params = test_params();
    let app = ApplicationBuilder::<Pasta, TestRank, 4>::new()
        .register(ValueSeedStep)?
        .finalize(params)?;
    let mut rng = StdRng::seed_from_u64(1);
    let (pcd, ()) = app.seed(&mut rng, ValueSeedStep, 7)?;
    let compressed = app.compress(&pcd, &mut rng)?;
    let decoded = CompressedProof::<Pasta>::from_bytes(
        &compressed.proof().to_bytes().expect("encode compressed"),
    )
    .expect("decode compressed")
    .carry::<ValueHeader>(*pcd.data());
    assert!(app.verify_uncompressed(&pcd, &mut rng)?);
    assert!(app.verify_compressed(&decoded)?);
    for change_host in [true, false] {
        let host = Pasta::host_generators(params);
        let nested = Pasta::nested_generators(params);
        let mut host_g = host.g().to_vec();
        let mut nested_g = nested.g().to_vec();
        if change_host {
            host_g[0] = -host_g[0];
        } else {
            nested_g[0] = -nested_g[0];
        }
        let other_params = PastaParams::new(
            PallasGenerators::new(
                AffineAdapter::as_slice(&nested_g).to_vec().leak(),
                AffineAdapter::as_slice(&[*nested.h()])[0],
            ),
            VestaGenerators::new(
                AffineAdapter::as_slice(&host_g).to_vec().leak(),
                AffineAdapter::as_slice(&[*host.h()])[0],
            ),
        );
        let other = ApplicationBuilder::<Pasta, TestRank, 4>::new()
            .register(ValueSeedStep)?
            .finalize(&other_params)?;
        assert!(!other.verify_uncompressed(&pcd, &mut rng)?);
        assert!(other.compress(&pcd, &mut rng).is_err());
        assert!(!other.verify_compressed(&decoded)?);
    }
    Ok(())
}

struct WideSeed;

impl Step<Pasta> for WideSeed {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = u64;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ValueHeader;

    fn polynomials<'source>(
        &self,
        _: &u64,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; 3]> {
        let mut wide = vec![Fp::ZERO; TestRank::num_coeffs() + 1];
        wide[0] = Fp::ONE;
        wide[TestRank::num_coeffs()] = Fp::ONE;
        Ok([wide, vec![Fp::ONE], vec![Fp::ONE]])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, u64>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Witnessed<'dr, 'source, Self, D, N> {
        ValueSeedStep.witness::<D, N>(dr, oracles, witness, left, right)
    }
}

#[test]
fn compressed_dimensions_cannot_be_relabelled() -> Result<()> {
    type LargerRank = ragu_circuits::polynomials::R<14>;
    let params = test_params_for::<LargerRank>();
    let wide = ApplicationBuilder::<Pasta, LargerRank, 4>::new()
        .register(WideSeed)?
        .finalize(params)?;
    let narrow = ApplicationBuilder::<Pasta, TestRank, 4>::new()
        .register(ValueSeedStep)?
        .finalize(params)?;
    let mut rng = StdRng::seed_from_u64(2);
    let (pcd, ()) = wide.seed(&mut rng, WideSeed, 9)?;
    assert!(pcd.polynomials()[0].len() > TestRank::num_coeffs());
    let compressed = wide.compress(&pcd, &mut rng)?;
    let bytes = compressed.proof().to_bytes().expect("encode wide proof");
    assert_eq!(&bytes[..8], b"RAGUPCD\0");
    let decoded = CompressedProof::<Pasta>::from_bytes(&bytes)
        .expect("decode wide proof")
        .carry::<ValueHeader>(9);
    assert!(wide.verify_compressed(&decoded)?);
    assert!(!narrow.verify_compressed(&decoded)?);
    let mut rank_edit = bytes.clone();
    rank_edit[16..20].copy_from_slice(&TestRank::RANK.to_le_bytes());
    assert!(matches!(
        CompressedProof::<Pasta>::from_bytes(&rank_edit),
        Err(crate::wire::Error::Invalid {
            reason: "mock proof binding mismatch",
            ..
        })
    ));
    let mut header_edit = bytes;
    header_edit[20..28].copy_from_slice(&5u64.to_le_bytes());
    assert!(matches!(
        CompressedProof::<Pasta>::from_bytes(&header_edit),
        Err(crate::wire::Error::Invalid {
            reason: "mock proof binding mismatch",
            ..
        })
    ));
    Ok(())
}

#[test]
fn in_memory_operations_do_not_require_wire_bounds() -> Result<()> {
    const LARGE_HEADER: usize = crate::wire::MAX_HEADER_SIZE + 1;
    let app = ApplicationBuilder::<Pasta, TestRank, LARGE_HEADER>::new()
        .register(ValueSeedStep)?
        .finalize(test_params())?;
    let mut rng = StdRng::seed_from_u64(3);
    let bootstrap = app.bootstrap_proof().clone().carry::<()>(());
    assert!(bootstrap.proof().to_bytes().is_err());
    let rerandomized = app.rerandomize(bootstrap, &mut rng)?;
    assert!(app.verify_uncompressed(&rerandomized, &mut rng)?);
    let (seeded, ()) = app.seed(&mut rng, ValueSeedStep, 7)?;
    assert!(app.verify_uncompressed(&seeded, &mut rng)?);
    assert!(seeded.proof().to_bytes().is_err());
    Ok(())
}
use alloc::{vec, vec::Vec};
