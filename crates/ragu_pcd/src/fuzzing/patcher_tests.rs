//! Capture classification and relational checks on internal circuits.
//!
//! Base-case classification follows the current children's output headers,
//! independently of the capture entry point and the children's own history.

#[path = "patcher_relations_tests.rs"]
mod relations;

#[path = "patcher_contract_tests.rs"]
mod contracts;

#[path = "patcher_endoscalar_tests.rs"]
mod endoscalar;

#[path = "patcher_transcript_tests.rs"]
mod transcript;

#[path = "patcher_jacobian_tests.rs"]
mod jacobian;

use core::marker::PhantomData;

use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
};
use ragu_pasta::{Fp, Pasta};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
};
use ragu_testing::patcher::{capture_with_stage_values, constraints_hold, playback, repair};
use rand::{SeedableRng, rngs::StdRng};

use super::*;
use crate::{
    ApplicationBuilder,
    header::{Header, NUM_INTERNAL_SUFFIXES, Suffix},
    step::{Encoded, Index},
};

type R = ragu_circuits::polynomials::ProductionRank;

/// A nontrivial header even at zero data, using the largest legal suffix.
struct ApplicationHeader;

impl<F: Field> Header<F> for ApplicationHeader {
    const SUFFIX: Suffix = Suffix::new(usize::MAX - NUM_INTERNAL_SUFFIXES as usize);
    type Data = F;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// Only the header types matter here; each output carries the supplied data.
struct HeaderStep<L, R, O, const ID: usize>(PhantomData<(L, R, O)>);

impl<L, R, O, const ID: usize> HeaderStep<L, R, O, ID> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C: Cycle, L, R, O, const ID: usize> Step<C> for HeaderStep<L, R, O, ID>
where
    L: Header<C::CircuitField>,
    R: Header<C::CircuitField>,
    O: Header<C::CircuitField>,
    O::Data: Sync,
{
    const INDEX: Index = Index::new(ID);
    type Witness<'source> = O::Data;
    type Aux<'source> = ();
    type Left = L;
    type Right = R;
    type Output = O;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, L::Data>,
        right: DriverValue<D, R::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, L, HEADER_SIZE>,
            Encoded<'dr, D, R, HEADER_SIZE>,
            Encoded<'dr, D, O, HEADER_SIZE>,
        ),
        DriverValue<D, O::Data>,
        DriverValue<D, ()>,
    )> {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let output = Encoded::new(dr, allocator, witness.as_ref().map(Clone::clone))?;
        Ok(((left, right, output), witness, D::unit()))
    }
}

type Trivial = HeaderStep<(), (), (), 0>;
type Leaf = HeaderStep<(), (), ApplicationHeader, 1>;
type Left = HeaderStep<ApplicationHeader, (), ApplicationHeader, 2>;
type Right = HeaderStep<(), ApplicationHeader, ApplicationHeader, 3>;
type Both = HeaderStep<ApplicationHeader, ApplicationHeader, ApplicationHeader, 4>;
type ToTrivial = HeaderStep<ApplicationHeader, ApplicationHeader, (), 5>;

struct BaseCaseChecker {
    case: &'static str,
    base_case: bool,
    visited: [bool; 2],
}

impl BaseCaseChecker {
    fn new(case: &'static str, base_case: bool) -> Self {
        Self {
            case,
            base_case,
            visited: [false; 2],
        }
    }

    fn check<'w, F: Field, Cir: Circuit<F>>(
        &self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[F],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
        c_position: usize,
    ) -> Result<()> {
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        let rec = &cap.recorder;
        let context = format!("{}: {}", self.case, spec.name);
        assert!(constraints_hold(&rec.events, &rec.values), "{context}");
        assert!(
            playback(circuit, make_witness()?, rec.values.clone())?,
            "{context}"
        );

        let instance_outputs: Vec<_> = spec
            .outputs
            .iter()
            .filter_map(|output| match output {
                OutputRef::Instance(i) => Some(*i),
                OutputRef::Stage(_) => None,
            })
            .collect();
        assert_eq!(
            instance_outputs,
            if self.base_case {
                Vec::new()
            } else {
                alloc::vec![c_position]
            },
            "{context}: c is an output exactly outside the base case",
        );

        // Keep every other public/stage value fixed, including the staged
        // collapsed claims. Only internal advice can accompany the changed c.
        let c = cap.instance[c_position];
        let fixed: Vec<_> = cap
            .instance
            .iter()
            .chain(&cap.stage_wires)
            .copied()
            .filter(|&wire| wire != c)
            .collect();
        let mut changed = rec.values.clone();
        let changed_c = changed[c] + F::ONE;
        changed[c] = changed_c;
        let mut pins = fixed.clone();
        pins.push(c);
        repair(&rec.events, &mut changed, &pins);
        assert_eq!(
            changed[c], changed_c,
            "{context}: repair must preserve the changed c"
        );
        for wire in fixed {
            assert_eq!(
                changed[wire], rec.values[wire],
                "{context}: wire {wire} is frozen"
            );
        }

        let accepted = constraints_hold(&rec.events, &changed);
        assert_eq!(
            playback(circuit, make_witness()?, changed)?,
            accepted,
            "{context}: recorded and live constraints agree",
        );
        assert_eq!(
            accepted, self.base_case,
            "{context}: c is free exactly in the base case"
        );
        Ok(())
    }

    fn assert_complete(self) {
        assert_eq!(
            self.visited, [true; 2],
            "{}: both collapse circuits were checked",
            self.case
        );
    }
}

impl<C: Cycle> InternalCircuitVisitor<C> for BaseCaseChecker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == "outer_collapse" {
            assert!(!core::mem::replace(&mut self.visited[0], true));
            self.check(
                spec,
                circuit,
                stage_values,
                make_witness,
                unified_slot_positions("c")[0],
            )?;
        }
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == "nested_collapse" {
            assert!(!core::mem::replace(&mut self.visited[1], true));
            // The nested instance starts with c_n, then v_n, x, y and u.
            self.check(spec, circuit, stage_values, make_witness, 0)?;
        }
        Ok(())
    }
}

#[test]
fn base_case_capture_follows_child_output_headers() -> Result<()> {
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(Trivial::new())?
        .register(Leaf::new())?
        .register(Left::new())?
        .register(Right::new())?
        .register(Both::new())?
        .register(ToTrivial::new())?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0xba5e_ca5e);

    // Only bootstrap consumes Dummy headers and leaves the child claims free.
    let mut checker = BaseCaseChecker::new("bootstrap, dummy children", true);
    capture_internal_circuits_bootstrap(&app, &mut rng, &mut checker)?;
    checker.assert_complete();

    // Seeds consume the bootstrap proof's ordinary unit output. Both output
    // types must enforce the child claims despite the children's base case.
    let mut checker = BaseCaseChecker::new("seeded, trivial output", false);
    capture_internal_circuits_seeded(&app, &mut rng, Trivial::new(), (), &mut checker)?;
    checker.assert_complete();
    let mut checker = BaseCaseChecker::new("seeded, application output", false);
    capture_internal_circuits_seeded(&app, &mut rng, Leaf::new(), Fp::ZERO, &mut checker)?;
    checker.assert_complete();

    // The same bootstrap proofs through the generic entry point.
    let mut checker = BaseCaseChecker::new("generic, bootstrap children", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Trivial::new(),
        (),
        app.bootstrap_pcd(),
        app.bootstrap_pcd(),
        &mut checker,
    )?;
    checker.assert_complete();

    // Application-produced unit headers also take the recursive branch,
    // regardless of their own input headers.
    let (left, _) = app.seed(&mut rng, Leaf::new(), Fp::ZERO)?;
    let (right, _) = app.seed(&mut rng, Leaf::new(), Fp::from(29))?;
    let (trivial, _) = app.fuse(&mut rng, ToTrivial::new(), (), left.clone(), right.clone())?;

    let mut checker = BaseCaseChecker::new("generic, trivial/trivial, trivial output", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Trivial::new(),
        (),
        trivial.clone(),
        trivial.clone(),
        &mut checker,
    )?;
    checker.assert_complete();
    let mut checker = BaseCaseChecker::new("generic, trivial/trivial, application output", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Leaf::new(),
        Fp::ZERO,
        trivial.clone(),
        trivial.clone(),
        &mut checker,
    )?;
    checker.assert_complete();

    let mut checker = BaseCaseChecker::new("generic, application/trivial", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Left::new(),
        Fp::ZERO,
        left.clone(),
        trivial.clone(),
        &mut checker,
    )?;
    checker.assert_complete();
    let mut checker = BaseCaseChecker::new("generic, trivial/application", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Right::new(),
        Fp::ZERO,
        trivial,
        right.clone(),
        &mut checker,
    )?;
    checker.assert_complete();
    let mut checker = BaseCaseChecker::new("generic, application/application", false);
    capture_internal_circuits(
        &app,
        &mut rng,
        Both::new(),
        Fp::ZERO,
        left,
        right,
        &mut checker,
    )?;
    checker.assert_complete();
    Ok(())
}
