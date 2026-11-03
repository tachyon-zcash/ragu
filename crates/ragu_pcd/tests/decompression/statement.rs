//! The statement circuit holds the decompression step's output header to the
//! header its extension verified, and every other step's to the unit header.
//!
//! [`Decompressing`] stands in for a profile with decompression circuits: its
//! one native extension circuit exposes a header its prover context holds, as
//! a decompression extension exposes the output header of the compressed
//! proof it verified. The binding is the statement claim's (see
//! [`statement_ky`]): a proof of the decompression step whose output header is
//! not the header exposed has a false claim, and so does a proof of any other
//! step whose statement circuit exposes anything but the unit header.
//!
//! [`statement_ky`]: crate::internal::native::stages::preamble::ProofInputs::statement_ky

use alloc::vec::Vec;

use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{Element, allocator::Standard as Allocator};
use rand::{SeedableRng, rngs::StdRng};

use crate::{
    Application, ApplicationBuilder, Pcd, RegistryTags,
    header::Header,
    internal::ky,
    profile::{
        Profiled,
        testing::{Decompressing, StatementContext},
    },
    proof::recursive_propagation_tests::support::Value,
    step::{Encoded, Index, Step, internal::decompress::Decompress},
};

const HEADER_SIZE: usize = 4;
const MANIFEST: &[u8] = &[0x26; 32];
type C = Profiled<Pasta, Decompressing>;
type Rk = R<14>;
type App = Application<'static, C, Rk, HEADER_SIZE>;

/// Passes a value through: the step a decompressed statement feeds.
struct Consume;

impl Step<C> for Consume {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Value;
    type Right = ();
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Value, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Value, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Allocator::new();
        let left = Element::alloc(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let data = left.value().map(|value| *value);
        Ok((
            (
                Encoded::from_gadget(left.clone()),
                right,
                Encoded::from_gadget(left),
            ),
            data,
            D::unit(),
        ))
    }
}

fn application() -> Result<App> {
    ApplicationBuilder::<C, Rk, HEADER_SIZE>::new()
        .register(Consume)?
        .with_registry_tags(RegistryTags::from_beacon(&[0x42; 32], MANIFEST), MANIFEST)?
        .finalize_with(
            crate::pasta::baked_aggregator(),
            StatementContext::default(),
        )
}

/// The padded output header of a [`Value`] proof: what a decompression
/// extension would expose after verifying a compressed proof of `value`.
fn statement(value: Fp) -> Vec<Fp> {
    ky::output_header::<C, Value, HEADER_SIZE>(value).expect("a value encodes")
}

/// Both verifiers' verdicts on `pcd`.
fn check_both<H: Header<Fp>>(
    app: &App,
    pcd: &Pcd<C, Rk, H>,
    expected: bool,
    rng: &mut StdRng,
    case: &str,
) -> Result<()> {
    assert_eq!(
        app.verify_uncompressed(pcd, &mut *rng)?,
        expected,
        "{case}: ordinary verifier"
    );
    let compressed = app.compress(pcd, rng)?;
    assert_eq!(
        app.verify_compressed(&compressed)?,
        expected,
        "{case}: compressed verifier"
    );
    Ok(())
}

/// A decompression whose output header is the header its statement circuit
/// exposed verifies, compresses, and feeds a parent and a rerandomization
/// whose statement circuits expose the unit header.
#[test]
fn a_decompression_exposing_its_output_header_verifies() -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x908_dec0);
    let value = Fp::from(7);

    app.context().expose(Some(statement(value)));
    let (decompressed, ()) = app.fuse(
        &mut rng,
        Decompress::<Value>::new(),
        value,
        app.bootstrap_pcd(),
        app.bootstrap_pcd(),
    )?;
    assert_eq!(*decompressed.data(), value);
    check_both(&app, &decompressed, true, &mut rng, "decompression")?;

    // Every other step's statement circuit exposes the unit header, as the
    // bootstrap's did under the default context.
    app.context().expose(None);
    let (parent, ()) = app.fuse(
        &mut rng,
        Consume,
        (),
        decompressed.clone(),
        app.bootstrap_pcd(),
    )?;
    assert_eq!(*parent.data(), value);
    check_both(&app, &parent, true, &mut rng, "parent")?;
    let rerandomized = app.rerandomize(decompressed, &mut rng)?;
    check_both(&app, &rerandomized, true, &mut rng, "rerandomization")
}

/// A decompression whose output header is not the header its statement
/// circuit exposed is rejected, whether the circuit exposed another value's
/// header or the unit header, and so is a parent over it.
#[test]
fn a_decompression_exposing_another_statement_is_rejected() -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x908_dec1);

    app.context().expose(Some(statement(Fp::from(7))));
    let (relabelled, ()) = app.fuse(
        &mut rng,
        Decompress::<Value>::new(),
        Fp::from(8),
        app.bootstrap_pcd(),
        app.bootstrap_pcd(),
    )?;
    assert_eq!(*relabelled.data(), Fp::from(8));
    check_both(&app, &relabelled, false, &mut rng, "relabelled statement")?;

    app.context().expose(None);
    let (unverified, ()) = app.fuse(
        &mut rng,
        Decompress::<Value>::new(),
        Fp::from(7),
        app.bootstrap_pcd(),
        app.bootstrap_pcd(),
    )?;
    check_both(&app, &unverified, false, &mut rng, "unit statement")?;

    let (parent, ()) = app.fuse(&mut rng, Consume, (), relabelled, app.bootstrap_pcd())?;
    check_both(
        &app,
        &parent,
        false,
        &mut rng,
        "parent of a relabelled statement",
    )
}

/// A proof of any step but the decompression step whose statement circuit
/// exposes a header other than the unit header is rejected: the header a
/// decompression verified binds only the decompression step's output.
#[test]
fn an_ordinary_step_exposing_a_statement_is_rejected() -> Result<()> {
    let app = application()?;
    let mut rng = StdRng::seed_from_u64(0x908_dec2);
    let value = Fp::from(7);

    app.context().expose(Some(statement(value)));
    let (decompressed, ()) = app.fuse(
        &mut rng,
        Decompress::<Value>::new(),
        value,
        app.bootstrap_pcd(),
        app.bootstrap_pcd(),
    )?;
    check_both(&app, &decompressed, true, &mut rng, "decompression")?;

    // Still exposing the decompressed header: the parent and the
    // rerandomization must expose the unit header instead.
    let (parent, ()) = app.fuse(
        &mut rng,
        Consume,
        (),
        decompressed.clone(),
        app.bootstrap_pcd(),
    )?;
    check_both(
        &app,
        &parent,
        false,
        &mut rng,
        "parent exposing a statement",
    )?;
    let rerandomized = app.rerandomize(decompressed, &mut rng)?;
    check_both(
        &app,
        &rerandomized,
        false,
        &mut rng,
        "rerandomization exposing a statement",
    )
}
