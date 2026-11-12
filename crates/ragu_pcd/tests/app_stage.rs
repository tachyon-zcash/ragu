//! The application stage must bind exactly a step's staged values, fixed
//! before the step's challenge, when a prover bypasses the API.

use alloc::{vec, vec::Vec};

use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    polynomials::{ProductionRank, Rank},
    staging,
};
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{Element, GadgetExt, allocator::Allocator};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::{
    Application, ApplicationBuilder, Pcd,
    header::{Header, Padding, Suffix},
    internal::native::RxIndex,
    step::{Encoded, HeaderInput, Index, Oracles, Step},
};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;
/// The stage holds `x` and `x²`.
const STAGE: usize = 2;
type App = Application<'static, Pasta, R, HEADER_SIZE>;
type Builder = ApplicationBuilder<'static, Pasta, R, HEADER_SIZE>;

/// Stages nothing.
struct Unit;
impl Step<Pasta> for Unit {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        _: &mut D,
        _: &mut Oracles<'_, 'dr, D>,
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

struct Number;
impl Header<Fp> for Number {
    const SUFFIX: Suffix = Suffix::new(0);
    type OnlinePolyCommit = (Padding, Padding);
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

/// Stages `x` and `state = x²` and carries `n = x² + state`, so the stage
/// commitment binds the square the carried number was built from. A
/// `Square(false)` stages the wrong count.
struct Square(bool);
impl Step<Pasta> for Square {
    const INDEX: Index = Index::new(1);
    const NUM_STAGED: usize = STAGE;
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Number;

    fn staged<'source>(
        &self,
        x: &Fp,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        Ok(if self.0 {
            vec![*x, x.square()]
        } else {
            vec![*x]
        })
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Number, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let [x, state] = oracles.staged() else {
            return Err(Error::InvalidWitness("two staged values".into()));
        };
        let square = x.square(dr)?;
        state.enforce_equal(dr, &square)?;
        let n = state.add(dr, &square);
        let value = n.value().map(|value| *value);
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(n),
            ),
            value,
            D::unit(),
        ))
    }
}

/// Propagates the number of an already-verified child.
struct Carry;
impl Step<Pasta> for Carry {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, HS>,
            Encoded<'dr, D, Number, HS>,
            Encoded<'dr, D, Number, HS>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let value = left.clone();
        let left = Encoded::new(dr, &mut (), left)?;
        let right = Encoded::new(dr, &mut (), right)?;
        Ok(((left.clone(), right, left), value, D::unit()))
    }
}

/// Stages `N` values, each constrained to zero.
struct Zeros<const N: usize>;
impl<const N: usize> Step<Pasta> for Zeros<N> {
    const INDEX: Index = Index::new(3);
    const NUM_STAGED: usize = N;
    type Witness<'source> = [Fp; N];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn staged<'source>(
        &self,
        values: &[Fp; N],
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<Vec<Fp>> {
        Ok(values.to_vec())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, [Fp; N]>,
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
        let zero = Element::zero(dr);
        for value in oracles.staged() {
            value.enforce_equal(dr, &zero)?;
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

fn builder() -> Builder {
    Builder::new()
        .register(Unit)
        .unwrap()
        .register(Square(true))
        .unwrap()
        // Selecting a backend must keep the queued circuits and their stage.
        .with_backend::<ReferenceBackend>()
        .register(Carry)
        .unwrap()
}

fn app() -> App {
    builder().finalize(crate::pasta::baked()).unwrap()
}

/// A later step can enlarge the stage after the steps that use less of it
/// have been registered.
fn app_with_stage<const N: usize>() -> App {
    builder()
        .register(Zeros::<N>)
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap()
}

/// An honest proof over a nonzero stage: `x = 3`, `state = 9`, `n = 18`.
fn honest(app: &App, rng: &mut StdRng) -> Pcd<Pasta, R, Number> {
    app.seed(rng, Square(true), Fp::from(3)).unwrap().0
}

fn check<H: Header<Fp>>(app: &App, pcd: &Pcd<Pasta, R, H>, rng: &mut StdRng, expected: bool) {
    assert_eq!(
        app.verify_differential(pcd, &mut *rng).unwrap(),
        expected,
        "verification"
    );
}

/// Rebuilds every ancestor and checks both child positions at each level.
/// The same path checks honest controls, so rejecting every parent cannot
/// pass.
fn check_through_recursion(
    app: &App,
    pcd: Pcd<Pasta, R, Number>,
    honest: &Pcd<Pasta, R, Number>,
    rng: &mut StdRng,
    expected: bool,
) {
    check(app, &pcd, rng, expected);
    let rerandomized = app.rerandomize(pcd.clone(), rng);
    if expected {
        check(app, &rerandomized.unwrap(), rng, expected);
    }

    for (left, right) in [(pcd.clone(), honest.clone()), (honest.clone(), pcd)] {
        let Ok((parent, ())) = app.fuse(rng, Carry, (), left, right) else {
            assert!(!expected, "an honest fuse must succeed");
            continue;
        };
        check(app, &parent, rng, expected);
    }
}

/// Adds `delta` to the `a` wire of `gate` in the given application
/// polynomial and recommits it, as a prover bypassing the API would.
fn edit<H: Header<Fp>>(
    app: &App,
    pcd: Pcd<Pasta, R, H>,
    component: RxIndex,
    gate: usize,
    delta: Fp,
) -> Pcd<Pasta, R, H> {
    let (mut proof, data) = pcd.into_parts();
    let edit = staging::stage_rx::<_, R>(Fp::ZERO, gate, 1, &[delta]).unwrap();
    let (rx, commitment) = match component {
        RxIndex::Application => (
            &mut proof.native_application_rx,
            &mut proof.native_application_commitment,
        ),
        RxIndex::ApplicationStage => (
            &mut proof.native_application_stage_rx,
            &mut proof.native_application_stage_commitment,
        ),
        other => panic!("not an application polynomial: {other:?}"),
    };
    rx.add_assign(&edit);
    *commitment = crate::proof::Cached(ReferenceBackend::sparse_commit_to_affine(
        rx,
        Pasta::host_generators(app.params),
    ));
    proof.carry::<H>(data)
}

#[test]
fn steps_with_a_stage_verify_through_recursion() {
    let app = app();
    assert_eq!(app.stage_size, STAGE);
    let mut rng = StdRng::seed_from_u64(73001);
    let honest = honest(&app, &mut rng);
    assert_eq!(*honest.data(), Fp::from(18));
    check_through_recursion(&app, honest.clone(), &honest, &mut rng, true);

    // Steps that stage nothing share the proof layout.
    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    check(&app, &unit, &mut rng, true);
    let rerandomized = app.rerandomize(unit, &mut rng).unwrap();
    check(&app, &rerandomized, &mut rng, true);
}

#[test]
fn steps_verify_with_a_large_odd_stage() {
    let app = app_with_stage::<257>();
    assert_eq!(app.stage_size, 257);
    let mut rng = StdRng::seed_from_u64(73002);
    let honest = honest(&app, &mut rng);
    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    check(&app, &unit, &mut rng, true);
    let (staged, ()) = app.seed(&mut rng, Zeros::<257>, [Fp::ZERO; 257]).unwrap();
    check(&app, &staged, &mut rng, true);
    // The staged values are the step's own constrained wires: a violating
    // value past the first reserved gate still fails the step's circuit.
    let (violating, ()) = app
        .seed(&mut rng, Zeros::<257>, {
            let mut values = [Fp::ZERO; 257];
            values[256] = Fp::ONE;
            values
        })
        .unwrap();
    check(&app, &violating, &mut rng, false);
    let (carried, ()) = app
        .fuse(&mut rng, Carry, (), honest.clone(), honest.clone())
        .unwrap();
    check_through_recursion(&app, carried, &honest, &mut rng, true);
}

/// An honest proof's stage polynomial holds exactly the step's staged
/// values in the stage's block and nothing else.
#[test]
fn the_stage_holds_exactly_the_staged_values() {
    let app = app_with_stage::<5>();
    let mut rng = StdRng::seed_from_u64(73003);
    let honest = honest(&app, &mut rng);
    let stage = &honest.proof()[RxIndex::ApplicationStage];
    // The SYSTEM gate carries the prover's blinding; read it back from where
    // an otherwise empty stage places it.
    let probe = staging::stage_rx::<_, R>(Fp::ONE, 1, app.stage_size, &[]).unwrap();
    let blinding = probe.iter_coeffs().position(|c| c == Fp::ONE).unwrap();
    let alpha = stage.iter_coeffs().nth(blinding).unwrap();
    let expected =
        staging::stage_rx::<_, R>(alpha, 1, app.stage_size, &[Fp::from(3), Fp::from(9)]).unwrap();
    assert_eq!(
        stage.iter_coeffs().collect::<Vec<_>>(),
        expected.iter_coeffs().collect::<Vec<_>>()
    );
}

/// Every proof's stage is held to its block and its step's own polynomial
/// out of it, and its commitment is the one the step's own transcript
/// absorbed before $\zeta$, so a proof cannot be restaged afterwards.
#[test]
fn the_stage_commitment_binds_exactly_the_staged_values() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(73004);
    let honest = honest(&app, &mut rng);
    let delta = Fp::from(5);
    let inside = 1;
    let outside = R::n() - 1;

    // Moving a staged value breaks the step's binding constraint, and the
    // stage commitment the step's transcript absorbed.
    let moved = edit(
        &app,
        honest.clone(),
        RxIndex::ApplicationStage,
        inside,
        delta,
    );
    check_through_recursion(&app, moved, &honest, &mut rng, false);

    // The stage mask rejects stage values outside the block, and the final
    // mask rejects the step's own values inside it.
    let spilled = edit(
        &app,
        honest.clone(),
        RxIndex::ApplicationStage,
        outside,
        delta,
    );
    check_through_recursion(&app, spilled, &honest, &mut rng, false);
    let overlapped = edit(&app, honest.clone(), RxIndex::Application, inside, delta);
    check_through_recursion(&app, overlapped, &honest, &mut rng, false);

    // A step that stages nothing has no wire that reads the block, but its
    // stage commitment is still the one its transcript absorbed: a prover
    // who swaps in another stage after $\zeta$ is rejected, so the parent
    // always folds the stage the step's challenge was drawn over.
    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    for (component, gate) in [
        (RxIndex::ApplicationStage, inside),
        (RxIndex::ApplicationStage, outside),
        (RxIndex::Application, inside),
    ] {
        let edited = edit(&app, unit.clone(), component, gate, delta);
        check(&app, &edited, &mut rng, false);
    }
}

#[test]
fn a_step_must_stage_exactly_its_declared_count() {
    let app = Builder::new()
        .register(Unit)
        .unwrap()
        .register(Square(false))
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(73005);
    assert!(matches!(
        app.seed(&mut rng, Square(false), Fp::from(3)),
        Err(Error::InvalidWitness(_))
    ));
}

#[test]
fn oversized_stages_are_rejected_at_registration() {
    assert!(Builder::new().register(Zeros::<{ 1 << 20 }>).is_err());
}
