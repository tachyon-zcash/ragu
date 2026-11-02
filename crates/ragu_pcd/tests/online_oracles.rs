//! The online polynomial oracles, end to end: an application whose header
//! carries an accumulator polynomial seeds, extends, merges and queries it,
//! every proof verifies under both verifiers, rerandomization keeps the
//! polynomial, and a step that misstates its polynomial or its claim cannot
//! produce a proof.
//!
//! This suite is ignored in the platform matrix and runs in the dedicated
//! Linux PR job with `--test online_oracles -- --include-ignored`.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{
    Application, ApplicationBuilder, Pcd,
    header::{HEADER_POLYNOMIALS, Header},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_primitives::{Element, GadgetExt, allocator::Standard};
use ragu_testing::pcd::accumulator::{
    Accumulator, ExtendAccumulator, MergeAccumulators, ProveMember, ProveNonMember, SEED_SIZE,
    SeedAccumulator, multiply, multiply_linear, vanishing,
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

type C = Pasta;
type R = ProductionRank;
const HEADER_SIZE: usize = 4;
type App = Application<'static, C, R, HEADER_SIZE>;

fn app() -> App {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(SeedAccumulator)
        .and_then(|b| b.register(ExtendAccumulator))
        .and_then(|b| b.register(MergeAccumulators))
        .and_then(|b| b.register(ProveMember))
        .and_then(|b| b.register(ProveNonMember))
        .and_then(|b| b.register(UnitSeed))
        .expect("the application must build")
        .finalize(ragu_pcd::pasta::baked())
        .expect("the application must build")
}

fn roots(from: u64) -> Vec<Fp> {
    (from..from + SEED_SIZE as u64).map(Fp::from).collect()
}

/// `pcd` verifies under both verifiers and carries `expected`'s
/// accumulator polynomial in its first slot, or the constant one in both
/// slots when it carries no accumulator.
fn check<H: Header<Fp>>(app: &App, pcd: &Pcd<C, R, H>, expected: Option<&[Fp]>, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    assert!(app.verify_differential(pcd, &mut rng).unwrap());
    let one = vec![Fp::ONE];
    match expected {
        Some(expected) => assert_eq!(pcd.polynomials(), [expected.to_vec(), one]),
        None => assert_eq!(pcd.polynomials(), [one.clone(), one]),
    }
}

/// A tree of accumulator steps over the oracles: the seeds commit
/// polynomials from their witnesses, the extension and merge from their
/// inputs' polynomials, the membership steps open an input polynomial at a
/// witnessed point; every proof verifies and carries the right polynomial,
/// and rerandomization preserves it.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn accumulators_prove_verify_and_rerandomize() -> Result<()> {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xacc);

    let (a, ()) = app.seed(&mut rng, SeedAccumulator, roots(1))?;
    let set_a = vanishing(&roots(1));
    check(&app, &a, Some(&set_a), 1);
    assert_eq!(*a.data(), Fp::from(SEED_SIZE as u64));

    let (a, ()) = app.fuse(
        &mut rng,
        ExtendAccumulator,
        Fp::from(10),
        a,
        app_unit(&app)?,
    )?;
    let set_a = multiply_linear(&set_a, Fp::from(10));
    check(&app, &a, Some(&set_a), 2);
    assert_eq!(*a.data(), Fp::from(SEED_SIZE as u64 + 1));

    let (b, ()) = app.seed(&mut rng, SeedAccumulator, roots(20))?;
    let set_b = vanishing(&roots(20));
    let (ab, ()) = app.fuse(&mut rng, MergeAccumulators, (), a.clone(), b)?;
    let set_ab = multiply(&set_a, &set_b);
    check(&app, &ab, Some(&set_ab), 3);
    assert_eq!(*ab.data(), Fp::from(2 * SEED_SIZE as u64 + 1));

    // Membership and non-membership open the polynomial away from zeta.
    let (member, ()) = app.fuse(
        &mut rng,
        ProveMember,
        Fp::from(21),
        ab.clone(),
        app_unit(&app)?,
    )?;
    check(&app, &member, None, 4);
    let (non_member, ()) = app.fuse(
        &mut rng,
        ProveNonMember,
        Fp::from(99),
        ab.clone(),
        app_unit(&app)?,
    )?;
    check(&app, &non_member, None, 5);

    // Rerandomization keeps the polynomial, and proves it did.
    let rerandomized = app.rerandomize(ab, &mut rng)?;
    check(&app, &rerandomized, Some(&set_ab), 6);
    let (again, ()) = app.fuse(
        &mut rng,
        ProveMember,
        Fp::from(1),
        rerandomized,
        app_unit(&app)?,
    )?;
    check(&app, &again, None, 7);
    Ok(())
}

/// A unit-header proof to fill a step's right input.
fn app_unit(app: &App) -> Result<Pcd<C, R, ()>> {
    let mut rng = StdRng::seed_from_u64(0x0);
    Ok(app.seed(&mut rng, UnitSeed, ())?.0)
}

/// A seed with no polynomials, registered after the accumulator steps. Its
/// circuit pins the convention for the unit header it consumes and
/// produces: every slot holds the constant one, which it opens at zeta.
struct UnitSeed;

impl Step<C> for UnitSeed {
    const INDEX: Index = Index::new(5);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        for slot in Slot::all() {
            let value = oracles.query_at_zeta(dr, slot)?;
            value.enforce_equal(dr, &Element::one())?;
        }
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
            ),
            D::unit(),
            D::unit(),
        ))
    }
}

/// A step over the accumulator whose first phase misbehaves one way or
/// another, registered beside [`SeedAccumulator`] in an application of its
/// own so the failure is the step's.
struct Faulty<const FAULT: u8>;

/// Returns the zero polynomial, whose commitment the walk cannot take.
const ZERO: u8 = 1;
/// Returns the input polynomial unchanged while the circuit claims the
/// extension: the claim fails at witness generation, since the oracle's
/// value is the committed polynomial's.
const STALE: u8 = 2;

impl<const FAULT: u8> Step<C> for Faulty<FAULT> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = Accumulator;
    type Right = ();
    type Output = Accumulator;

    fn polynomials<'source>(
        &self,
        _: &Fp,
        left: HeaderInput<'_, Fp, Accumulator>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        let first = match FAULT {
            ZERO => vec![Fp::ZERO; 4],
            _ => left.polynomials[0].clone(),
        };
        Ok([first, vec![Fp::ONE]])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        root: DriverValue<D, Fp>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Accumulator, HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Accumulator, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left: Encoded<'dr, D, Accumulator, HS> = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let root = Element::alloc(dr, allocator, root)?;
        let zeta = oracles.zeta().clone();
        let input = oracles.query_at_zeta(dr, Slot::left(0))?;
        let output = oracles.query_at_zeta(dr, Slot::output(0))?;
        let factor = zeta.sub(dr, &root);
        let expected = input.mul(dr, &factor)?;
        output.enforce_equal(dr, &expected)?;
        let count = left.as_gadget().add(dr, &Element::one());
        let data = count.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(count)), data, D::unit()))
    }
}

fn faulty_app<const FAULT: u8>() -> App {
    ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(SeedAccumulator)
        .and_then(|b| b.register(Faulty::<FAULT>))
        .and_then(|b| b.register(UnitAt2))
        .expect("the application must build")
        .finalize(ragu_pcd::pasta::baked())
        .expect("the application must build")
}

/// [`UnitSeed`] at the index the faulty applications have free.
struct UnitAt2;

impl Step<C> for UnitAt2 {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, ()>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        UnitSeed.witness::<D, HS>(dr, oracles, witness, left, right)
    }
}

/// A proof attempt is refused when proving fails outright, or when it
/// yields a proof neither verifier accepts: a constraint the witness does
/// not satisfy is recorded into the trace and caught by the verifiers,
/// while an inversion of zero fails at witness generation.
fn refused<H: Header<Fp>>(app: &App, attempt: Result<Pcd<C, R, H>>, what: &str) {
    match attempt {
        Err(_) => {}
        Ok(pcd) => {
            let mut rng = StdRng::seed_from_u64(0xdead);
            assert!(
                !app.verify_differential(&pcd, &mut rng).unwrap(),
                "{what}: the verifiers accepted a false claim"
            );
        }
    }
}

/// A step whose first phase returns a zero polynomial cannot prove; and
/// one whose committed polynomial is not the one its circuit claims yields
/// a proof the verifiers reject, because the oracle answers for the
/// committed polynomial and the circuit's relation then fails.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn a_misstated_polynomial_cannot_prove() -> Result<()> {
    fn attempt<const FAULT: u8>() -> (App, Result<Pcd<C, R, Accumulator>>) {
        let app = faulty_app::<FAULT>();
        let mut rng = StdRng::seed_from_u64(0xbad);
        let (a, ()) = app.seed(&mut rng, SeedAccumulator, roots(1)).unwrap();
        let (unit, ()) = app.seed(&mut rng, UnitAt2, ()).unwrap();
        let attempt = app
            .fuse(&mut rng, Faulty::<FAULT>, Fp::from(10), a, unit)
            .map(|(pcd, ())| pcd);
        (app, attempt)
    }
    assert!(matches!(attempt::<ZERO>().1, Err(Error::InvalidWitness(_))));
    let (app, stale) = attempt::<STALE>();
    refused(&app, stale, "stale polynomial");
    Ok(())
}

/// A membership claim about an element the accumulator does not hold, or a
/// non-membership claim about one it does, is refused.
#[test]
#[ignore = "proves at production rank; run in the PR job"]
fn a_false_membership_claim_cannot_prove() -> Result<()> {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xfa15e);
    let (a, ()) = app.seed(&mut rng, SeedAccumulator, roots(1))?;
    let member = app
        .fuse(
            &mut rng,
            ProveMember,
            Fp::from(99),
            a.clone(),
            app_unit(&app)?,
        )
        .map(|(pcd, ())| pcd);
    refused(&app, member, "a non-member claimed as a member");
    let non_member = app
        .fuse(&mut rng, ProveNonMember, Fp::from(2), a, app_unit(&app)?)
        .map(|(pcd, ())| pcd);
    refused(&app, non_member, "a member claimed as a non-member");
    Ok(())
}
