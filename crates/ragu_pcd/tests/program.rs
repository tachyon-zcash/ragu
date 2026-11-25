//! Tests of [`program`](super): a small program run three ways, the rules
//! its log holds, and its steps as circuits over one memory stage.
//!
//! The program has four steps. Step 0 takes two advised values, a seed and
//! a base point, and stores the seed's square. Steps 1 and 2 are the two
//! pages of a Horner walk over fixed coefficients at the square, from the
//! seed. Step 3 stores the base point's double and the sum of the walk's
//! result and the square.

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use ragu_circuits::{
    CircuitExt, WithAux,
    polynomials::WalletRank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder, StageExt},
};
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Kind},
    maybe::{Always, Empty, Maybe},
    pasta::{Ep, EpAffine, Fp, Fq},
};
use ragu_primitives::{Element, Simulator};
use ragu_testing::registry::TestRegistryBuilder;
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective},
    field::Field,
};

use super::{
    Cell, Definition, ElementCell, Layout, Loaded, Log, Memory, MemoryStage, PointCell, Program,
    Report, Shape, Values, run,
};
use crate::internal::{
    paging::{self, ElementHorner},
    tests::assert_stage_values,
};

type R = WalletRank;
type Sim = Simulator<Fp>;
type Executor = Emulator<Wireless<Always<()>, Fp>>;
type Counter = Emulator<Wireless<Empty, Fp>>;

/// The walk's coefficients and its capacity: two pages, of three and two.
const COEFFICIENTS: [u64; 5] = [3, 1, 4, 1, 5];
const CAPACITY: usize = 3;

/// The program's memory.
struct Toy;

/// The cells of [`Toy`], by what they hold.
struct Cells {
    /// Advised in step 0.
    seed: ElementCell,
    /// Stored in step 0.
    square: ElementCell,
    /// The walk's interstitials, stored in steps 1 and 2.
    walk: Vec<ElementCell>,
    /// Stored in step 3.
    total: ElementCell,
    /// Advised in step 0.
    base: PointCell,
    /// Stored in step 3.
    double: PointCell,
}

fn layout() -> (Cells, Layout<Toy>) {
    let mut layout = Layout::new();
    let points = layout.points(2);
    let cells = Cells {
        seed: layout.element(),
        square: layout.element(),
        walk: layout.elements(paging::num_pages(CAPACITY, COEFFICIENTS.len())),
        total: layout.element(),
        base: points[0],
        double: points[1],
    };
    (cells, layout)
}

impl Shape for Toy {
    const NAME: &'static str = "toy";

    fn points() -> usize {
        layout().1.num_points()
    }

    fn elements() -> usize {
        layout().1.num_elements()
    }
}

/// What the prover supplies.
#[derive(Clone, Copy)]
struct Advice {
    seed: Fp,
    base: EpAffine,
}

struct Inputs<'a, 'dr, D: Driver<'dr, F = Fp>> {
    advice: DriverValue<D, Advice>,
    memory: Memory<'a, 'dr, D, EpAffine, Toy>,
}

impl Program<Fp> for Toy {
    type Inputs<'a, 'dr, D: Driver<'dr, F = Fp>>
        = Inputs<'a, 'dr, D>
    where
        'dr: 'a,
        D: 'a;

    fn steps(&self) -> usize {
        4
    }

    fn step<'a, 'dr: 'a, D: Driver<'dr, F = Fp> + 'a>(
        &self,
        step: usize,
        dr: &mut D,
        inputs: &Inputs<'a, 'dr, D>,
    ) -> Result<()> {
        let (cells, _) = layout();
        let memory = &inputs.memory;
        match step {
            0 => {
                let seed = memory.advise_element(
                    dr,
                    cells.seed,
                    inputs.advice.as_ref().map(|a| a.seed),
                )?;
                memory.advise_point(dr, cells.base, inputs.advice.as_ref().map(|a| a.base))?;
                let square = seed.mul(dr, &seed)?;
                memory.store_element(dr, cells.square, &square)
            }
            1 | 2 => {
                let page = step - 1;
                let point = memory.load_element(dr, cells.square)?;
                let start = match page.checked_sub(1) {
                    Some(before) => memory.load_element(dr, cells.walk[before])?,
                    None => memory.load_element(dr, cells.seed)?,
                };
                let coefficients: Vec<Element<'dr, D>> =
                    paging::range(CAPACITY, page, COEFFICIENTS.len())
                        .map(|index| Element::constant(dr, Fp::from(COEFFICIENTS[index])))
                        .collect();
                let end = paging::fold(dr, &ElementHorner::new(&point), start, &coefficients)?;
                memory.store_element(dr, cells.walk[page], &end)
            }
            3 => {
                let base = memory.load_point(dr, cells.base)?;
                let double = base.double(dr)?;
                memory.store_point(dr, cells.double, &double)?;
                let result = memory.load_element(dr, *cells.walk.last().unwrap())?;
                let square = memory.load_element(dr, cells.square)?;
                let total = result.add(dr, &square);
                memory.store_element(dr, cells.total, &total)
            }
            _ => unreachable!("the program has four steps"),
        }
    }
}

fn advice(seed: u64) -> Advice {
    let mut rng = StdRng::seed_from_u64(seed);
    Advice {
        seed: Fp::random(|bytes| rng.fill_bytes(bytes)),
        base: (Ep::generator() * Fq::random(|bytes| rng.fill_bytes(bytes))).to_affine(),
    }
}

fn placeholder() -> EpAffine {
    Ep::generator().to_affine()
}

fn blank() -> Values<EpAffine> {
    Values::blank::<Toy>(placeholder())
}

/// The prover's run: the memory's values and the run's report.
fn trace(advice: Advice) -> (Values<EpAffine>, Report) {
    let values = RefCell::new(blank());
    let log = Log::new();
    {
        let mut dr = Executor::execute();
        let inputs = Inputs {
            advice: Executor::just(|| advice),
            memory: Memory::tracing(&values, &log),
        };
        run(&Toy, &mut dr, &inputs, &log).unwrap();
    }
    (values.into_inner(), log.finish().unwrap())
}

/// Whether step `step`'s constraints hold over `values`, and the gates the
/// step took.
fn step_holds(step: usize, advice: Advice, values: &Values<EpAffine>) -> (bool, usize) {
    let mut gates = 0;
    let result = Simulator::simulate((), |dr: &mut Sim, _| {
        let loaded = Loaded::alloc(dr, Sim::just(|| values))?;
        let inputs = Inputs {
            advice: Sim::just(|| advice),
            memory: Memory::loaded(&loaded),
        };
        let before = dr.num_gates();
        let result = Toy.step(step, dr, &inputs);
        gates = dr.num_gates() - before;
        result
    });
    (result.is_ok(), gates)
}

/// The steps whose constraints fail over `values`.
fn failing(advice: Advice, values: &Values<EpAffine>) -> Vec<usize> {
    (0..Toy.steps())
        .filter(|&step| !step_holds(step, advice, values).0)
        .collect()
}

/// The run fills every cell with the value the program defines for it.
#[test]
fn a_run_fills_the_memory() {
    let advice = advice(1);
    let (cells, _) = layout();
    let (values, _) = trace(advice);

    let square = advice.seed.square();
    let horner = |inputs: &[u64], start: Fp| {
        inputs
            .iter()
            .fold(start, |state, &c| state * square + Fp::from(c))
    };
    let first = horner(&COEFFICIENTS[..CAPACITY], advice.seed);
    let second = horner(&COEFFICIENTS[CAPACITY..], first);

    assert_eq!(values.elements[cells.seed.index()], advice.seed);
    assert_eq!(values.elements[cells.square.index()], square);
    assert_eq!(values.elements[cells.walk[0].index()], first);
    assert_eq!(values.elements[cells.walk[1].index()], second);
    assert_eq!(values.elements[cells.total.index()], second + square);
    assert_eq!(values.points[cells.base.index()], advice.base);
    assert_eq!(
        values.points[cells.double.index()],
        advice.base.to_projective().double().to_affine()
    );
}

/// Every step's circuit holds over the values the run filled.
#[test]
fn every_step_holds_over_the_traced_values() {
    let advice = advice(2);
    let (values, _) = trace(advice);
    assert_eq!(failing(advice, &values), Vec::<usize>::new());
}

/// The report names each cell's definition and its loads.
#[test]
fn the_report_names_definitions_and_loads() {
    let (cells, _) = layout();
    let (_, report) = trace(advice(3));

    let usage = |cell: Cell| {
        let usage = report.usage(cell);
        (usage.step, usage.how, usage.loads.clone())
    };
    assert_eq!(
        usage(Cell::Element(cells.seed)),
        (0, Definition::Advised, vec![1])
    );
    assert_eq!(
        usage(Cell::Element(cells.square)),
        (0, Definition::Stored, vec![1, 2, 3])
    );
    assert_eq!(
        usage(Cell::Element(cells.walk[0])),
        (1, Definition::Stored, vec![2])
    );
    assert_eq!(
        usage(Cell::Element(cells.walk[1])),
        (2, Definition::Stored, vec![3])
    );
    assert_eq!(
        usage(Cell::Element(cells.total)),
        (3, Definition::Stored, vec![])
    );
    assert_eq!(
        usage(Cell::Point(cells.base)),
        (0, Definition::Advised, vec![3])
    );
    assert_eq!(
        usage(Cell::Point(cells.double)),
        (3, Definition::Stored, vec![])
    );

    // The free values are the two advised cells, and the cells no step
    // loads are the program's two results.
    assert_eq!(
        report.advised(),
        vec![Cell::Point(cells.base), Cell::Element(cells.seed)]
    );
    assert_eq!(
        report.unread(),
        vec![Cell::Point(cells.double), Cell::Element(cells.total)]
    );
    assert_eq!(
        report.defined_by(0),
        vec![
            Cell::Point(cells.base),
            Cell::Element(cells.seed),
            Cell::Element(cells.square)
        ]
    );
    assert_eq!(report.defined_by(1), vec![Cell::Element(cells.walk[0])]);
}

/// A checking run on a driver without a witness gives the same report:
/// the program's structure does not depend on its values.
#[test]
fn a_run_without_a_witness_gives_the_same_report() {
    let (_, traced) = trace(advice(4));
    let log = Log::new();
    {
        let mut dr = Counter::counter();
        let inputs = Inputs {
            advice: no_value::<Advice>(),
            memory: Memory::checking(&log, placeholder()),
        };
        run(&Toy, &mut dr, &inputs, &log).unwrap();
    }
    assert_eq!(log.finish().unwrap(), traced);
}

/// A wrong value in a cell fails the step that stored it and every step
/// that loads it, and no other step. A wrong advised value fails the steps
/// that use it: the steps that load it, and the step that advises it when
/// that step computes with it, as step 0 squares the seed.
#[test]
fn a_wrong_cell_fails_its_definition_and_its_loads() {
    let advice = advice(5);
    let (cells, _) = layout();
    let (honest, report) = trace(advice);
    let other = (Ep::generator() * Fq::from(77)).to_affine();
    for usage in &report.cells {
        let mut values = honest.clone();
        match usage.cell {
            Cell::Element(cell) => values.elements[cell.index()] += Fp::ONE,
            Cell::Point(cell) => values.points[cell.index()] = other,
        }
        let mut expected = usage.loads.clone();
        if usage.how == Definition::Stored || usage.cell == Cell::Element(cells.seed) {
            expected.push(usage.step);
        }
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(failing(advice, &values), expected, "{:?}", usage.cell);
    }
}

/// A load costs no gate, and the step that advises a point holds it to the
/// curve.
#[test]
fn a_load_is_free_and_an_advised_point_is_held_to_the_curve() {
    let advice = advice(6);
    let (values, _) = trace(advice);
    let (cells, _) = layout();
    let gates = |f: &dyn Fn(&mut Sim, &Memory<'_, 'static, Sim, EpAffine, Toy>) -> Result<()>| {
        let mut gates = 0;
        Simulator::simulate((), |dr: &mut Sim, _| {
            let loaded = Loaded::alloc(dr, Sim::just(|| &values))?;
            let memory = Memory::loaded(&loaded);
            let before = dr.num_gates();
            f(dr, &memory)?;
            gates = dr.num_gates() - before;
            Ok(())
        })
        .unwrap();
        gates
    };
    assert_eq!(
        gates(&|dr, memory| memory.load_element(dr, cells.square).map(|_| ())),
        0
    );
    assert_eq!(
        gates(&|dr, memory| memory.load_point(dr, cells.base).map(|_| ())),
        0
    );
    assert_eq!(
        gates(&|dr, memory| {
            let value = Sim::just(|| advice.seed);
            memory.advise_element(dr, cells.seed, value).map(|_| ())
        }),
        0
    );
    assert!(
        gates(&|dr, memory| {
            let value = Sim::just(|| advice.base);
            memory.advise_point(dr, cells.base, value).map(|_| ())
        }) > 0
    );
}

/// Runs `body` as the only step of a traced run and returns its error.
fn refused(
    body: impl FnOnce(&mut Counter, &Memory<'_, 'static, Counter, EpAffine, Toy>) -> Result<()>,
) -> bool {
    let log = Log::new();
    let memory = Memory::checking(&log, placeholder());
    log.begin(0);
    body(&mut Counter::counter(), &memory).is_err()
}

fn no_value<T: Send>() -> DriverValue<Counter, T> {
    Counter::just(|| unreachable!("the driver has no witness"))
}

/// The log refuses a second definition of a cell, whichever way each
/// defines it.
#[test]
fn a_second_definition_is_refused() {
    let (cells, _) = layout();
    assert!(refused(|dr, memory| {
        let value = memory.advise_element(dr, cells.seed, no_value::<Fp>())?;
        memory.store_element(dr, cells.square, &value)?;
        memory.store_element(dr, cells.square, &value)
    }));
    assert!(refused(|dr, memory| {
        memory.advise_element(dr, cells.seed, no_value::<Fp>())?;
        memory
            .advise_element(dr, cells.seed, no_value::<Fp>())
            .map(|_| ())
    }));
    assert!(refused(|dr, memory| {
        let point = memory.advise_point(dr, cells.base, no_value::<EpAffine>())?;
        memory.store_point(dr, cells.base, &point)
    }));
    // One definition each is accepted.
    assert!(!refused(|dr, memory| {
        let value = memory.advise_element(dr, cells.seed, no_value::<Fp>())?;
        memory.store_element(dr, cells.square, &value)?;
        let point = memory.advise_point(dr, cells.base, no_value::<EpAffine>())?;
        memory.store_point(dr, cells.double, &point)
    }));
}

/// The log refuses a load before the cell's definition.
#[test]
fn a_load_before_the_definition_is_refused() {
    let (cells, _) = layout();
    assert!(refused(|dr, memory| memory
        .load_element(dr, cells.square)
        .map(|_| ())));
    assert!(refused(|dr, memory| memory
        .load_point(dr, cells.base)
        .map(|_| ())));
    assert!(!refused(|dr, memory| {
        memory.advise_element(dr, cells.seed, no_value::<Fp>())?;
        memory.load_element(dr, cells.seed).map(|_| ())
    }));
}

/// A run that leaves a cell without a definition does not finish.
#[test]
fn a_cell_without_a_definition_is_refused() {
    let log = Log::new();
    {
        let mut dr = Counter::counter();
        let inputs = Inputs {
            advice: no_value::<Advice>(),
            memory: Memory::checking(&log, placeholder()),
        };
        // Every step but the last, which defines two cells.
        for step in 0..3 {
            log.begin(step);
            Toy.step(step, &mut dr, &inputs).unwrap();
        }
    }
    assert!(log.finish().is_err());
}

/// An access outside a step is refused: the log has no step to record.
#[test]
fn an_access_outside_a_step_is_refused() {
    let (cells, _) = layout();
    let log = Log::new();
    let memory: Memory<'_, '_, Counter, EpAffine, Toy> = Memory::checking(&log, placeholder());
    assert!(
        memory
            .advise_element(&mut Counter::counter(), cells.seed, no_value::<Fp>())
            .is_err()
    );
}

#[test]
#[should_panic(expected = "a run goes through the steps in order")]
fn the_steps_of_a_run_are_in_order() {
    let log = Log::new();
    log.begin(2);
    log.begin(1);
}

/// Another memory, to take a cell from.
struct Other;

impl Shape for Other {
    const NAME: &'static str = "other";

    fn points() -> usize {
        0
    }

    fn elements() -> usize {
        1
    }
}

#[test]
#[should_panic(expected = "used on the memory \"toy\"")]
fn a_cell_of_another_memory_is_refused() {
    let mut other = Layout::<Other>::new();
    assert_ne!(other.point(), other.point());
    let cell = other.element();
    let log = Log::new();
    let memory: Memory<'_, '_, Counter, EpAffine, Toy> = Memory::checking(&log, placeholder());
    log.begin(0);
    let _ = memory.load_element(&mut Counter::counter(), cell);
}

#[test]
#[should_panic(expected = "is recorded once")]
fn a_memory_is_traced_once() {
    let log = Log::new();
    let _first: Memory<'_, '_, Counter, EpAffine, Toy> = Memory::checking(&log, placeholder());
    let _second: Memory<'_, '_, Counter, EpAffine, Toy> = Memory::checking(&log, placeholder());
}

/// The layout numbers each kind's cells from zero in order, and the stage
/// holds two wires per point and one per element.
#[test]
fn the_stage_holds_the_layouts_cells() {
    let (cells, layout) = layout();
    assert_eq!((layout.num_points(), layout.num_elements()), (2, 5));
    assert_eq!(
        [
            cells.seed,
            cells.square,
            cells.walk[0],
            cells.walk[1],
            cells.total
        ]
        .map(|c| c.index()),
        [0, 1, 2, 3, 4]
    );
    assert_eq!([cells.base, cells.double].map(|c| c.index()), [0, 1]);
    assert_eq!(
        <MemoryStage<Toy, EpAffine, ()> as ragu_circuits::staging::Stage<Fp, R>>::values(),
        2 * 2 + 5
    );
    assert_stage_values::<Fp, R, _>(&MemoryStage::<Toy, EpAffine, ()>::default());
}

/// Step `index` of the program as a circuit over the memory stage.
#[derive(Clone)]
struct StepCircuit {
    index: usize,
}

type ToyStage = MemoryStage<Toy, EpAffine, ()>;

impl MultiStageCircuit<Fp, R> for StepCircuit {
    type Last = ToyStage;
    type Instance<'source> = ();
    type Witness<'source> = (Advice, &'source Values<EpAffine>);
    type Output = Kind![Fp; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let (memory, dr) = dr.add_stage::<ToyStage>()?;
        let dr = dr.finish();
        let loaded = memory.unenforced(dr, witness.as_ref().map(|w| w.1))?;
        let inputs = Inputs {
            advice: witness.as_ref().map(|w| w.0),
            memory: Memory::loaded(&loaded),
        };
        Toy.step(self.index, dr, &inputs)?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// Whether the claim of step `index` holds: its trace with the memory
/// stage's polynomial for `committed`, against the step's wiring
/// polynomial. The step's trace is built over `witnessed`.
fn claim_holds(
    index: usize,
    advice: Advice,
    witnessed: &Values<EpAffine>,
    committed: &Values<EpAffine>,
) -> bool {
    let circuit = StepCircuit { index };
    let mut builder = TestRegistryBuilder::new();
    let handle = builder
        .register_circuit(MultiStage::new(circuit.clone()))
        .unwrap();
    let mask = builder.register_mask(<ToyStage as StageExt<Fp, R>>::stage_mask().unwrap());
    let final_mask = builder.register_mask(<ToyStage as StageExt<Fp, R>>::final_mask().unwrap());
    let registry = builder.finalize().unwrap();

    let staged = MultiStage::new(circuit);
    let trace = staged.trace((advice, witnessed)).unwrap().into_output();
    let rx = registry.assemble(&trace, handle, Fp::ZERO).unwrap();
    let memory = <ToyStage as StageExt<Fp, R>>::rx(Fp::ZERO, committed).unwrap();

    let y = Fp::from(0x70726f67u64);
    // The stage polynomial and the step's trace are each well formed.
    assert_eq!(memory.revdot(&registry.y(mask, y)), Fp::ZERO);
    assert_eq!(rx.revdot(&registry.y(final_mask, y)), Fp::ZERO);

    let mut sum = rx;
    sum.add_assign(&memory);
    sum.revdot(&registry.y(handle, y)) == staged.ky((), y).unwrap()
}

/// The steps as circuits share the memory through its stage polynomial:
/// every step's claim holds over the committed values the run filled, and
/// a committed stage with one wrong cell fails the claims of the step that
/// stored the cell and of the steps that load it, whatever the steps'
/// provers witnessed.
#[test]
fn the_step_circuits_share_the_memory_stage() {
    let advice = advice(7);
    let (honest, report) = trace(advice);
    for step in 0..Toy.steps() {
        assert!(claim_holds(step, advice, &honest, &honest), "step {step}");
    }

    let (cells, _) = layout();
    for cell in [Cell::Element(cells.square), Cell::Element(cells.walk[0])] {
        let usage = report.usage(cell);
        let mut committed = honest.clone();
        let Cell::Element(element) = cell else {
            unreachable!()
        };
        committed.elements[element.index()] += Fp::ONE;
        let mut expected = usage.loads.clone();
        expected.push(usage.step);
        expected.sort_unstable();
        expected.dedup();
        for witnessed in [&honest, &committed] {
            let failing: Vec<usize> = (0..Toy.steps())
                .filter(|&step| !claim_holds(step, advice, witnessed, &committed))
                .collect();
            assert_eq!(failing, expected, "{cell:?}");
        }
    }
}
