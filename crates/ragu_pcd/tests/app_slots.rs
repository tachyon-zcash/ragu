//! Fixed bundles and their shared stage must hold when a prover bypasses the API.

use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    CircuitExt,
    polynomials::{ProductionRank, Rank, sparse},
    registry::CircuitIndex,
    staging,
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    shared::Shared,
};
use rand::{SeedableRng, rngs::StdRng};
use udon::field::Field;

use crate::{
    APPLICATION_SLOTS, Application, ApplicationBuilder, Pcd,
    header::{Header, Suffix},
    internal::{native::RxIndex, tests::SharedInputs},
    step::{Encoded, Index, Step, internal::adapter::Adapter},
};

#[path = "app_slots_pcs.rs"]
mod pcs;

type R = ProductionRank;
const HEADER_SIZE: usize = 4;
/// The shared stage holds `x` and `state`.
const STAGE: usize = 2;
type App = Application<'static, Pasta, R, HEADER_SIZE>;
type Builder = ApplicationBuilder<'static, Pasta, R, HEADER_SIZE>;

struct Unit;
impl Step<Pasta> for Unit {
    const INDEX: Index = Index::new(0);
    type Shared = ();
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        (),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
            ),
            (),
            D::unit(),
            D::unit(),
        ))
    }
}

struct Number;
impl Header<Fp> for Number {
    const SUFFIX: Suffix = Suffix::new(0);
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

/// The complete bundle establishes that the carried number is `2x²`: `Square`
/// enforces `n = x² + state` and `Finish` enforces `state = x²`, over the
/// shared stage's `x` and `state`. Neither fragment establishes it alone.
struct Square;
struct Finish;

#[derive(Gadget, Shared)]
struct Connection<'dr, D: Driver<'dr>> {
    x: Element<'dr, D>,
    state: Element<'dr, D>,
}

macro_rules! fragment {
    ($name:ty, $index:expr, |$dr:ident, $n:ident, $x:ident, $state:ident| $body:block) => {
        impl Step<Pasta> for $name {
            const INDEX: Index = Index::new($index);
            type Shared = Kind![Fp; Connection<'_, _>];
            type Witness<'source> = (Fp, Fp);
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = Number;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                $dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
                _: DriverValue<D, ()>,
                _: DriverValue<D, ()>,
            ) -> Result<(
                (
                    Encoded<'dr, D, (), HS>,
                    Encoded<'dr, D, (), HS>,
                    Encoded<'dr, D, Number, HS>,
                ),
                Bound<'dr, D, Self::Shared>,
                DriverValue<D, Fp>,
                DriverValue<D, ()>,
            )> {
                let (x, n) = witness.cast();
                let $n = Element::alloc($dr, &mut (), n)?;
                let $x = Element::alloc($dr, &mut (), x)?;
                let $state = $body;
                let value = $n.value().map(|value| *value);
                Ok((
                    (
                        Encoded::from_gadget(()),
                        Encoded::from_gadget(()),
                        Encoded::from_gadget($n),
                    ),
                    Connection {
                        x: $x,
                        state: $state,
                    },
                    value,
                    D::unit(),
                ))
            }
        }
    };
}

fragment!(Square, 1, |dr, n, x, state| {
    let square = x.square(dr)?;
    n.sub(dr, &square)
});
fragment!(Finish, 2, |dr, n, x, state| { x.square(dr)? });

/// Propagates the invariant of an already-verified child.
struct Carry;
impl Step<Pasta> for Carry {
    const INDEX: Index = Index::new(3);
    type Shared = ();
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Number;
    type Right = Number;
    type Output = Number;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
        left: DriverValue<D, Fp>,
        right: DriverValue<D, Fp>,
    ) -> Result<(
        (
            Encoded<'dr, D, Number, HS>,
            Encoded<'dr, D, Number, HS>,
            Encoded<'dr, D, Number, HS>,
        ),
        (),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )> {
        let value = left.clone();
        let left = Encoded::new(dr, &mut (), left)?;
        let right = Encoded::new(dr, &mut (), right)?;
        Ok(((left.clone(), right, left), (), value, D::unit()))
    }
}

fn app() -> App {
    app_with_shared::<STAGE>()
}

fn builder() -> Builder {
    Builder::new().register(Unit).unwrap()
}

/// A later bundle can increase the internal shared capacity after the
/// original fragments and standalone steps have been registered.
fn app_with_shared<const SIZE: usize>() -> App {
    let builder = builder()
        .register_bundle((Square, Finish))
        .unwrap()
        // Selecting a backend must keep the queued circuits and their shared
        // input requirements.
        .with_backend::<ReferenceBackend>()
        .register(Carry)
        .unwrap();
    let builder = if SIZE > STAGE {
        builder
            .register_bundle((SharedInputs::<4, SIZE>, SharedInputs::<5, SIZE>))
            .unwrap()
    } else {
        builder
    };
    builder.finalize(crate::pasta::baked()).unwrap()
}

/// The original bundle's two shared inputs, regardless of the requirements
/// of any later bundle.
fn shared(x: Fp, state: Fp) -> alloc::vec::Vec<Fp> {
    alloc::vec![x, state]
}

/// An honest proof over a nonzero shared stage: `x = 3`, `state = 9`,
/// `n = 18`.
fn honest(app: &App, rng: &mut StdRng) -> Pcd<Pasta, R, Number> {
    app.seed_bundle(
        rng,
        (Square, Finish),
        ((Fp::from(3), Fp::from(18)), (Fp::from(3), Fp::from(18))),
    )
    .unwrap()
    .0
}

fn check<H: Header<Fp>, const HS: usize>(
    app: &Application<'_, Pasta, R, HS>,
    pcd: &Pcd<Pasta, R, H>,
    rng: &mut StdRng,
    expected: bool,
) {
    assert_eq!(
        app.verify(pcd, &mut *rng).unwrap(),
        expected,
        "uncompressed"
    );
    let compressed = app.compress(pcd, rng).unwrap();
    assert_eq!(
        app.verify_compressed(&compressed).unwrap(),
        expected,
        "compressed"
    );
}

/// Rebuild every ancestor and check both child positions at each level. The
/// same path checks honest controls, so rejecting every parent cannot pass.
fn check_through_recursion<const HS: usize>(
    app: &Application<'_, Pasta, R, HS>,
    pcd: Pcd<Pasta, R, Number>,
    honest: &Pcd<Pasta, R, Number>,
    rng: &mut StdRng,
    expected: bool,
) {
    check(app, &pcd, rng, expected);
    let rerandomized = app.rerandomize(pcd.clone(), rng).unwrap();
    check(app, &rerandomized, rng, expected);

    for (left, right) in [(pcd.clone(), honest.clone()), (honest.clone(), pcd)] {
        let (parent, ()) = app.fuse(rng, Carry, (), left, right).unwrap();
        check(app, &parent, rng, expected);
        for (left, right) in [(parent.clone(), honest.clone()), (honest.clone(), parent)] {
            let (grandparent, ()) = app.fuse(rng, Carry, (), left, right).unwrap();
            check(app, &grandparent, rng, expected);
        }
    }
}

/// Bypass the prover's bundle policy without changing the registered circuit
/// wiring. A malicious prover can choose these IDs and trace values too.
/// Building from scratch recomputes every commitment and transcript; the
/// fixed bundle constants in the original registry must reject the claim.
fn forge_bundle<'source, S, T>(
    app: &mut App,
    rng: &mut StdRng,
    steps: (S, T),
    shared: &[Fp],
    witnesses: (S::Witness<'source>, T::Witness<'source>),
) -> Pcd<Pasta, R, Number>
where
    S: Step<Pasta, Left = (), Right = (), Output = Number>,
    T: Step<Pasta, Left = (), Right = (), Output = Number, Shared = S::Shared>,
{
    let required = <Square as Step<Pasta>>::INDEX
        .bundle(&app.application_bundles)
        .unwrap();
    let claimed =
        [S::INDEX, T::INDEX].map(|index| index.circuit_index(app.num_application_steps).unwrap());
    assert_ne!(claimed, required, "the attack must change the bundle");

    let original = app.application_bundles.clone();
    for bundle in &mut app.application_bundles {
        if *bundle == required {
            *bundle = claimed;
        }
    }
    let result = if crate::internal::native::is_split_bundle(claimed) {
        app.seed_bundle(rng, steps, witnesses)
    } else {
        // The public API refuses shared values for repeated IDs. A malicious
        // prover can instead put them directly into each fragment's own
        // polynomial at the original shared wires, bypassing both lane masks.
        // Only the registered bundle IDs then distinguish these locally
        // satisfying traces from a legitimate standalone step.
        app.seed(
            rng,
            PrivateStage {
                step: steps.0,
                shared: shared.to_vec(),
            },
            witnesses.0,
        )
    };
    app.application_bundles = original;

    let (pcd, _) = result.unwrap();
    assert_eq!(pcd.proof().circuit_ids(), claimed);
    if !crate::internal::native::is_split_bundle(claimed) {
        // Check that this is a targeted bypass attempt: each repeated
        // fragment's circuit equation holds with its real bundle's public
        // IDs, and fails only when the forged repeated IDs replace them.
        let y = Fp::from(7);
        let z = Fp::from(11);
        let (mut proof, data) = pcd.clone().into_parts();
        proof.circuit_ids = required;
        let real_bundle = proof.carry::<Number>(data);
        let expected =
            crate::internal::ky::native_ky::<Pasta, R, Number, HEADER_SIZE>(&real_bundle, y)
                .unwrap()
                .application;
        let forged = crate::internal::ky::native_ky::<Pasta, R, Number, HEADER_SIZE>(&pcd, y)
            .unwrap()
            .application;
        for (slot, id) in claimed.into_iter().enumerate() {
            let mut a = pcd.proof()[RxIndex::Application(slot as u32)].clone();
            a.add_assign(&pcd.proof()[RxIndex::ApplicationStage]);
            let mut b = a.clone();
            b.dilate(z);
            b.add_assign(&app.native_registry.circuit_y(id, y));
            b.add_assign(&R::tz(z));
            let actual = <ReferenceBackend as ragu_backend::Backend>::sparse_revdot(&a, &b);
            assert_eq!(actual, expected, "fragment {slot} is locally valid");
            assert_ne!(actual, forged, "fragment {slot} binds the registered IDs");
        }
    }
    pcd
}

/// A dishonest fragment with its shared values moved into its own trace.
/// Its floor plan matches the real fragment, but it claims repeated IDs so
/// that the lane masks are disabled. The registry's bundle constants must
/// still reject it.
struct PrivateStage<S> {
    step: S,
    shared: alloc::vec::Vec<Fp>,
}

impl<S: Step<Pasta>> Step<Pasta> for PrivateStage<S> {
    const INDEX: Index = S::INDEX;
    type Shared = ();
    type Witness<'source> = S::Witness<'source>;
    type Aux<'source> = S::Aux<'source>;
    type Left = S::Left;
    type Right = S::Right;
    type Output = S::Output;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        (),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let mut shared = alloc::vec::Vec::with_capacity(self.shared.len());
        for i in 0..2 * staging::stage_gates(self.shared.len()) {
            let value = D::just(|| self.shared.get(i).copied().unwrap_or(Fp::ZERO));
            let element = Element::alloc(dr, allocator, value)?;
            if i < self.shared.len() {
                shared.push(element.wire().clone());
            }
        }
        let (headers, gadget, output, aux) =
            self.step.witness::<_, HS>(dr, witness, left, right)?;
        crate::step::internal::adapter::bind_shared(dr, &gadget, &shared)?;
        Ok((headers, (), output, aux))
    }
}

/// The commitment of each application slot's polynomial.
fn slot_commitments<H: Header<Fp>>(
    pcd: &Pcd<Pasta, R, H>,
) -> [<Pasta as Cycle>::HostCurve; APPLICATION_SLOTS] {
    core::array::from_fn(|slot| {
        pcd.proof()
            .native_rx_commitment(RxIndex::Application(slot as u32))
    })
}

#[test]
fn complete_and_repeated_bundles_verify() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(89501);
    let pcd = honest(&app, &mut rng);
    let bundle = <Square as Step<Pasta>>::INDEX
        .bundle(&app.application_bundles)
        .unwrap();
    assert_eq!(pcd.proof().circuit_ids(), bundle);
    assert_eq!(*pcd.data(), Fp::from(18));
    check_through_recursion(&app, pcd.clone(), &pcd, &mut rng, true);

    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    assert_eq!(
        unit.proof().circuit_ids(),
        [<Unit as Step<Pasta>>::INDEX
            .circuit_index(app.num_application_steps)
            .unwrap(); APPLICATION_SLOTS]
    );
    check(&app, &unit, &mut rng, true);
}

/// A step registered on its own is traced and committed once; the same
/// polynomial fills every slot, and each slot's claim holds on its own.
#[test]
fn standalone_steps_repeat_one_claim() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(89508);
    let honest = honest(&app, &mut rng);
    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    let (carried, ()) = app
        .fuse(&mut rng, Carry, (), honest.clone(), honest.clone())
        .unwrap();
    for [a, b] in [slot_commitments(&unit), slot_commitments(&carried)] {
        assert_eq!(a, b);
    }
    check(&app, &unit, &mut rng, true);
    check_through_recursion(&app, carried, &honest, &mut rng, true);

    // A bundle's fragments are distinct circuits with distinct traces.
    let [a, b] = slot_commitments(&honest);
    assert_ne!(a, b);
}

#[test]
fn application_api_refuses_standalone_steps_supplied_as_a_bundle() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(89521);
    assert!(
        app.seed_bundle(&mut rng, (Unit, Unit), ((), ())).is_err(),
        "register(Unit) does not register the pair (Unit, Unit) for bundle proving"
    );
}

/// A valid step that counts actual witness evaluation, including for empty
/// shared connections. Registration's unknown-witness pass does not count.
struct CountedStep<const INDEX: usize>;

impl<const INDEX: usize> Step<Pasta> for CountedStep<INDEX> {
    const INDEX: Index = Index::new(INDEX);
    type Shared = ();
    type Witness<'source> = &'source core::sync::atomic::AtomicUsize;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ();

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, ()>,
        right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
        ),
        (),
        DriverValue<D, ()>,
        DriverValue<D, ()>,
    )> {
        D::try_just(|| {
            witness
                .take()
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        })?;
        Unit.witness::<D, HS>(dr, D::unit(), left, right)
    }
}

#[test]
fn application_api_checks_registration_before_evaluating_any_witness() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    let app = Builder::new()
        .register(CountedStep::<0>)
        .unwrap()
        .register_bundle((CountedStep::<1>, CountedStep::<2>))
        .unwrap()
        .register(CountedStep::<3>)
        .unwrap()
        .register_bundle((CountedStep::<4>, CountedStep::<5>))
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(89522);
    let calls = AtomicUsize::new(0);

    macro_rules! refused {
        ($case:literal, $call:expr) => {
            assert!($call.is_err(), "{} must return an error", $case);
            assert_eq!(
                calls.load(Ordering::Relaxed),
                0,
                "{} must fail before either witness runs",
                $case,
            );
        };
    }

    refused!(
        "first bundle step alone",
        app.seed(&mut rng, CountedStep::<1>, &calls)
    );
    refused!(
        "second bundle step alone",
        app.seed(&mut rng, CountedStep::<2>, &calls)
    );
    refused!(
        "standalone step twice",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<0>, CountedStep::<0>),
            (&calls, &calls)
        )
    );
    refused!(
        "two standalone steps",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<0>, CountedStep::<3>),
            (&calls, &calls)
        )
    );
    refused!(
        "repeated bundle step",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<1>, CountedStep::<1>),
            (&calls, &calls)
        )
    );
    refused!(
        "reversed bundle",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<2>, CountedStep::<1>),
            (&calls, &calls)
        )
    );
    refused!(
        "steps from different bundles",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<1>, CountedStep::<5>),
            (&calls, &calls)
        )
    );
    refused!(
        "unregistered standalone step",
        app.seed(&mut rng, CountedStep::<6>, &calls)
    );
    refused!(
        "unregistered first bundle step",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<6>, CountedStep::<2>),
            (&calls, &calls)
        )
    );
    refused!(
        "unregistered second bundle step",
        app.seed_bundle(
            &mut rng,
            (CountedStep::<1>, CountedStep::<6>),
            (&calls, &calls)
        )
    );

    let (standalone, ()) = app.seed(&mut rng, CountedStep::<0>, &calls).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    check(&app, &standalone, &mut rng, true);
    let (bundle, ()) = app
        .seed_bundle(
            &mut rng,
            (CountedStep::<1>, CountedStep::<2>),
            (&calls, &calls),
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 3);
    check(&app, &bundle, &mut rng, true);
}

#[test]
fn standalone_steps_verify_with_a_large_odd_shared_stage() {
    let app = app_with_shared::<257>();
    let mut rng = StdRng::seed_from_u64(89511);
    let honest = honest(&app, &mut rng);
    check(&app, &honest, &mut rng, true);
    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    check(&app, &unit, &mut rng, true);
    let (carried, ()) = app
        .fuse(&mut rng, Carry, (), honest.clone(), honest.clone())
        .unwrap();
    // Covers standalone/bundle children in both positions, repeated
    // standalone ancestors, rerandomization, and both verifier paths.
    check_through_recursion(&app, carried, &honest, &mut rng, true);
}

#[test]
fn both_verifiers_reject_circuit_id_edits_in_every_slot() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(89507);
    let pcd = honest(&app, &mut rng);
    check(&app, &pcd, &mut rng, true);
    let compressed = app.compress(&pcd, &mut rng).unwrap();

    for slot in 0..APPLICATION_SLOTS {
        for id in [
            <Unit as Step<Pasta>>::INDEX
                .circuit_index(app.num_application_steps)
                .unwrap(),
            CircuitIndex::from_u32(u32::MAX),
        ] {
            let (mut proof, data) = pcd.clone().into_parts();
            proof.circuit_ids[slot] = id;
            assert!(
                !app.verify(&proof.carry::<Number>(data), &mut rng).unwrap(),
                "uncompressed slot {slot}, circuit {id:?}",
            );

            let (mut proof, data) = compressed.clone().into_parts();
            proof.instance.circuit_ids[slot] = id;
            assert!(
                !app.verify_compressed(&proof.carry::<Number>(data)).unwrap(),
                "compressed slot {slot}, circuit {id:?}",
            );
        }
    }
}

#[test]
fn missing_extra_reordered_and_repeated_fragments_are_refused() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(89502);
    let witness = (Fp::ZERO, Fp::ZERO);

    // The public entry points require a complete bundle; the internal
    // prover also refuses a fragment supplied without its second trace.
    assert!(
        app.fuse_with_slots(
            &mut rng,
            Square,
            witness,
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            alloc::vec![],
        )
        .is_err(),
        "a fragment cannot be proved alone"
    );

    // A step registered on its own takes no additional prepared slots,
    // including an explicit copy of its own trace.
    let (unit, _, ()) = app.prepare_step(&mut rng, Unit, (), (), ()).unwrap();
    for count in [APPLICATION_SLOTS - 1, APPLICATION_SLOTS] {
        assert!(
            app.fuse_with_slots(
                &mut rng,
                Unit,
                (),
                app.bootstrap_pcd(),
                app.bootstrap_pcd(),
                alloc::vec![unit.clone(); count],
            )
            .is_err(),
            "{count} standalone slots",
        );
    }

    // Repeated, reordered and disagreeing fragments.
    assert!(
        app.seed_bundle(&mut rng, (Square, Square), (witness, witness))
            .is_err()
    );
    assert!(
        app.seed_bundle(&mut rng, (Finish, Finish), (witness, witness))
            .is_err()
    );
    assert!(
        app.seed_bundle(&mut rng, (Finish, Square), (witness, witness))
            .is_err()
    );
    assert!(
        app.seed_bundle(&mut rng, (Square, Finish), (witness, (Fp::ZERO, Fp::ONE)))
            .is_err(),
        "headers must agree"
    );
}

/// Oversized schemas are refused before allocating their gadget or circuits.
#[test]
fn oversized_shared_inputs_are_rejected_before_circuit_construction() {
    const NO_CIRCUIT_ROOM: usize = (1 << (R::RANK - 1)) - 2;
    assert!(
        builder()
            .register_bundle((
                SharedInputs::<1, NO_CIRCUIT_ROOM>,
                SharedInputs::<2, NO_CIRCUIT_ROOM>
            ))
            .is_err()
    );
    assert!(
        builder()
            .register_bundle((
                SharedInputs::<1, { usize::MAX }>,
                SharedInputs::<2, { usize::MAX }>
            ))
            .is_err()
    );
}

#[test]
fn odd_shared_gadgets_are_inferred_and_bound() {
    let app = builder()
        .register_bundle((SharedInputs::<1, 3>, SharedInputs::<2, 3>))
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(89512);
    for (shared, expected) in [
        ([Fp::ZERO; 3], true),
        ([Fp::ZERO, Fp::ZERO, Fp::ONE], false),
    ] {
        let (pcd, ()) = app
            .seed_bundle(
                &mut rng,
                (SharedInputs::<1, 3>, SharedInputs::<2, 3>),
                (shared, shared),
            )
            .unwrap();
        check(&app, &pcd, &mut rng, expected);
    }
}

#[test]
fn empty_shared_gadgets_can_bundle_without_connections() {
    let app = builder()
        .register_bundle((SharedInputs::<1, 0>, SharedInputs::<2, 0>))
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap();
    let mut rng = StdRng::seed_from_u64(89514);
    let (pcd, ()) = app
        .seed_bundle(
            &mut rng,
            (SharedInputs::<1, 0>, SharedInputs::<2, 0>),
            ([], []),
        )
        .unwrap();
    check(&app, &pcd, &mut rng, true);
    let pcd = app.rerandomize(pcd, &mut rng).unwrap();
    check(&app, &pcd, &mut rng, true);
}

#[test]
fn bundle_shared_connections_must_agree() {
    // A later bundle changes internal capacity, not this bundle's schema.
    let app = app_with_shared::<3>();
    let mut rng = StdRng::seed_from_u64(89509);
    for witnesses in [
        ((Fp::from(3), Fp::from(18)), (Fp::from(4), Fp::from(18))),
        ((Fp::from(3), Fp::from(19)), (Fp::from(3), Fp::from(19))),
    ] {
        assert!(
            app.seed_bundle(&mut rng, (Square, Finish), witnesses)
                .is_err(),
            "each returned field must agree"
        );
    }
    let pcd = honest(&app, &mut rng);
    check(&app, &pcd, &mut rng, true);
}

#[derive(Clone, Copy, Debug)]
enum Preparation {
    Sequential,
    Reverse,
    Parallel,
}

/// Prepare the actual adapter traces in different orders, then feed those
/// same traces to the ordinary assembly and fuse pipeline. The circuit IDs
/// remain in their registered order even when preparation is reversed.
fn prepare<'source, S, T, const HS: usize>(
    app: &Application<'_, Pasta, R, HS>,
    rng: &mut StdRng,
    order: Preparation,
    steps: (S, T),
    witnesses: (S::Witness<'source>, T::Witness<'source>),
    left: &Pcd<Pasta, R, S::Left>,
    right: &Pcd<Pasta, R, S::Right>,
) -> (
    (crate::fuse::Slot<Pasta, R>, Fp, S::Aux<'source>),
    crate::fuse::Slot<Pasta, R>,
)
where
    S: Step<Pasta, Output = Number>,
    T: Step<Pasta, Left = S::Left, Right = S::Right, Output = Number, Shared = S::Shared>,
{
    let bundle = S::INDEX.bundle(&app.application_bundles).unwrap();
    let size = app.shared_size;
    let first_data = (left.data().clone(), right.data().clone());
    let second_data = first_data.clone();
    let first = move || {
        Adapter::<Pasta, S, R, HS>::new(steps.0, bundle, size)
            .unwrap()
            .trace((first_data.0, first_data.1, witnesses.0))
            .unwrap()
    };
    let second = move || {
        Adapter::<Pasta, T, R, HS>::new(steps.1, bundle, size)
            .unwrap()
            .trace((second_data.0, second_data.1, witnesses.1))
            .unwrap()
    };
    let (first, second) = match order {
        Preparation::Sequential => (first(), second()),
        Preparation::Reverse => {
            let second = second();
            (first(), second)
        }
        Preparation::Parallel => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .unwrap();
            let started = std::sync::Barrier::new(2);
            pool.install(|| {
                rayon::join(
                    || {
                        started.wait();
                        first()
                    },
                    || {
                        started.wait();
                        second()
                    },
                )
            })
        }
    };
    (
        app.assemble_step::<_, S>(rng, first).unwrap(),
        app.assemble_step::<_, T>(rng, second).unwrap().0,
    )
}

#[test]
fn sequential_reverse_and_parallel_preparation_bind_the_same_connections() {
    let app = app_with_shared::<3>();
    let mut rng = StdRng::seed_from_u64(89513);
    let honest = honest(&app, &mut rng);
    for order in [
        Preparation::Sequential,
        Preparation::Reverse,
        Preparation::Parallel,
    ] {
        let good = (Fp::from(3), Fp::from(18));
        let (first, second) = prepare(
            &app,
            &mut rng,
            order,
            (Square, Finish),
            (good, good),
            &app.bootstrap_pcd(),
            &app.bootstrap_pcd(),
        );
        assert_eq!(first.0.shared, [Fp::from(3), Fp::from(9)]);
        assert_eq!(first.0.shared, second.shared, "{order:?}");
        let (pcd, ()) = app
            .fuse_prepared::<_, Square>(
                &mut rng,
                first,
                app.bootstrap_pcd().into_parts().0,
                app.bootstrap_pcd().into_parts().0,
                alloc::vec![second],
            )
            .unwrap();
        assert_eq!(*pcd.data(), Fp::from(18));
        check_through_recursion(&app, pcd, &honest, &mut rng, true);

        // Each false statement changes just one connection field, leaving
        // the other equal. Both individual fragment computations are valid.
        for (field, witnesses) in [
            (0, ((Fp::ONE, Fp::ONE), (Fp::ZERO, Fp::ONE))),
            (
                1,
                ((Fp::from(3), Fp::from(19)), (Fp::from(3), Fp::from(19))),
            ),
        ] {
            let (first, second) = prepare(
                &app,
                &mut rng,
                order,
                (Square, Finish),
                witnesses,
                &app.bootstrap_pcd(),
                &app.bootstrap_pcd(),
            );
            assert_ne!(first.0.shared[field], second.shared[field]);
            assert_eq!(first.0.shared[1 - field], second.shared[1 - field]);
            assert!(
                app.fuse_prepared::<_, Square>(
                    &mut rng,
                    first.clone(),
                    app.bootstrap_pcd().into_parts().0,
                    app.bootstrap_pcd().into_parts().0,
                    alloc::vec![second.clone()],
                )
                .is_err(),
                "{order:?}, field {field}"
            );

            // Forge only host metadata. The actual gadget wires still
            // disagree: circuit bindings must reject the rebuilt proof.
            let mut second = second;
            second.shared.clone_from(&first.0.shared);
            let (forged, ()) = app
                .fuse_prepared::<_, Square>(
                    &mut rng,
                    first,
                    app.bootstrap_pcd().into_parts().0,
                    app.bootstrap_pcd().into_parts().0,
                    alloc::vec![second],
                )
                .unwrap();
            assert_eq!(*forged.data(), witnesses.0.1);
            check_through_recursion(&app, forged, &honest, &mut rng, false);
        }
    }
}

#[test]
fn bundle_registration_requires_distinct_sequential_fragments() {
    for (case, result) in [
        ("reordered", builder().register_bundle((Finish, Square))),
        ("repeated", builder().register_bundle((Square, Square))),
    ] {
        assert!(result.is_err(), "{case}");
    }
}

/// The lane checks are what make the shared stage shared. Moving a value
/// from the stage into a fragment's own polynomial, at the stage's wire,
/// satisfies every circuit claim: the fragment reads the sum of the two
/// polynomials either way. Only the application final mask's bonding claim
/// notices, and it must, or each fragment could carry its own `x`.
fn lane_moves_are_rejected_through_recursion(app: &App, rng: &mut StdRng) {
    let honest = honest(app, rng);
    let left = app.bootstrap_pcd();
    let right = app.bootstrap_pcd();

    // Where the stage lays `x`: the coefficient the stage polynomial puts
    // its first value at.
    let laid =
        staging::stage_rx::<Fp, R>(Fp::ZERO, 1, app.shared_size, &shared(Fp::from(5), Fp::ZERO))
            .unwrap();
    let x = laid
        .iter_coeffs()
        .position(|coeff| coeff == Fp::from(5))
        .unwrap();
    let monomial = |delta: Fp| {
        let mut coeffs = alloc::vec![Fp::ZERO; x + 1];
        coeffs[x] = delta;
        sparse::Polynomial::<Fp, R>::from_coeffs(coeffs)
    };

    // `Square` sees `x = 1`, so `n = 1`; `Finish` sees `x = 0`, so
    // `state = 0`. Each trace is valid for what it sees, and the shared
    // header `n = 1` is `2x²` for neither view.
    let stage = shared(Fp::ONE, Fp::ZERO);
    let (mut finish, _, ()) = app
        .prepare_step(rng, Finish, (Fp::ZERO, Fp::ONE), (), ())
        .unwrap();
    assert!(
        app.fuse_with_slots(
            rng,
            Square,
            (Fp::ONE, Fp::ONE),
            left.clone(),
            right.clone(),
            alloc::vec![finish.clone()],
        )
        .is_err(),
        "the public API must reject a slot traced against another stage"
    );

    // Bypass the API: claim the step's stage, and carry `x`'s difference in
    // the slot's own lane. The proof is then built afresh, so every
    // commitment and transcript is consistent with the edited polynomial.
    finish.shared = stage.clone();
    finish.rx.add_assign(&monomial(-Fp::ONE));
    let (forged, ()) = app
        .fuse_with_slots(
            rng,
            Square,
            (Fp::ONE, Fp::ONE),
            left,
            right,
            alloc::vec![finish],
        )
        .unwrap();
    assert_eq!(*forged.data(), Fp::ONE);
    check_through_recursion(app, forged, &honest, rng, false);
}

#[test]
fn fragments_disagreeing_on_the_shared_stage_are_rejected_through_recursion() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(89505);
    lane_moves_are_rejected_through_recursion(&app, &mut rng);
}

/// An odd-sized stage ends in a padding wire no fragment reads; the honest
/// path and the lane checks must hold across it as well.
#[test]
fn odd_sized_shared_stages_verify_and_keep_their_lanes() {
    let app = app_with_shared::<{ STAGE + 1 }>();
    let mut rng = StdRng::seed_from_u64(89510);
    let pcd = honest(&app, &mut rng);
    assert_eq!(*pcd.data(), Fp::from(18));
    check_through_recursion(&app, pcd.clone(), &pcd, &mut rng, true);
    let (unit, ()) = app.seed(&mut rng, Unit, ()).unwrap();
    check(&app, &unit, &mut rng, true);
    lane_moves_are_rejected_through_recursion(&app, &mut rng);
}

#[test]
fn every_fragment_is_required_through_recursion() {
    let mut app = app();
    let mut rng = StdRng::seed_from_u64(89504);
    let honest = honest(&app, &mut rng);
    check(&app, &honest, &mut rng, true);

    // Remove each predicate in turn. The remaining predicate is locally
    // valid over the shared stage, but allows an output other than `2x²`.
    let zeros = shared(Fp::ZERO, Fp::ZERO);
    let without_square = forge_bundle(
        &mut app,
        &mut rng,
        (Finish, Finish),
        &zeros,
        ((Fp::ZERO, Fp::ONE), (Fp::ZERO, Fp::ONE)),
    );
    let two_one = shared(Fp::from(2), Fp::ONE);
    let without_finish = forge_bundle(
        &mut app,
        &mut rng,
        (Square, Square),
        &two_one,
        ((Fp::from(2), Fp::from(5)), (Fp::from(2), Fp::from(5))),
    );
    // Also retain the minimal omitted-predicate counterexample: `n = 1`
    // satisfies both square traces over `(1, 0)`, but the full invariant is 2.
    let one_zero = shared(Fp::ONE, Fp::ZERO);
    let minimal = forge_bundle(
        &mut app,
        &mut rng,
        (Square, Square),
        &one_zero,
        ((Fp::ONE, Fp::ONE), (Fp::ONE, Fp::ONE)),
    );
    assert_eq!(*minimal.data(), Fp::ONE);

    for (forged, invariant) in [
        (without_square, Fp::ZERO),
        (without_finish, Fp::from(8)),
        (minimal, Fp::from(2)),
    ] {
        assert_ne!(*forged.data(), invariant);
        check_through_recursion(&app, forged, &honest, &mut rng, false);
    }
}

#[test]
fn every_unregistered_order_is_rejected_through_recursion() {
    let mut app = app();
    let mut rng = StdRng::seed_from_u64(89506);
    let honest = honest(&app, &mut rng);

    // The swapped order contains both valid fragments and a true output
    // statement. The rejection must enforce the registered order itself.
    let stage = shared(Fp::from(3), Fp::from(9));
    let forged = forge_bundle(
        &mut app,
        &mut rng,
        (Finish, Square),
        &stage,
        ((Fp::from(3), Fp::from(18)), (Fp::from(3), Fp::from(18))),
    );
    check_through_recursion(&app, forged, &honest, &mut rng, false);
}
