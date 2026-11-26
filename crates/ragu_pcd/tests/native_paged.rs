//! Tests of the native program of a paged profile: which step defines each
//! cell of its memory and which values the prover supplies.

use alloc::vec::Vec;

use ragu_circuits::polynomials::WalletRank;
use ragu_core::{
    Cycle,
    drivers::emulator::{Emulator, Wireless},
    maybe::Empty,
    pasta::Pasta,
};
use ragu_primitives::Element;
use udon::curve::Affine as _;

use super::{Batch, Challenges, Inputs, Sizes, Step, cells, every_stage, schedule};
use crate::{
    internal::program::{self, Cell, Definition, Log, Memory, Report},
    profile::{Profiled, testing::Grouped},
};

type C = Profiled<Pasta, Grouped>;
type Counter = Emulator<Wireless<Empty, <Pasta as Cycle>::CircuitField>>;
const HEADER_SIZE: usize = 4;

/// The report of a run of the program that records its accesses on a
/// driver without a witness.
fn report() -> Report {
    let log = Log::new();
    {
        let dr = &mut Counter::counter();
        let stages = every_stage::<_, C, WalletRank, HEADER_SIZE>(dr, &Empty).unwrap();
        let challenges = Challenges::from_each(|_| Element::alloc(dr, &mut (), Empty)).unwrap();
        let inputs = Inputs {
            stages: &stages,
            memory: Memory::checking(&log, <Pasta as Cycle>::NestedCurve::generator()),
            challenges: Some(&challenges),
            online_fold: Empty,
        };
        program::run(
            &Batch::<C, WalletRank, HEADER_SIZE>::new(),
            dr,
            &inputs,
            &log,
        )
        .unwrap();
    }
    log.finish().unwrap()
}

/// Every cell of the memory has one definition, in the step that computes
/// it; the first step defines the challenges, and the one cell no step
/// loads is $v$, which the export circuit provides as the instance's.
#[test]
fn every_cell_is_defined_by_the_step_that_computes_it() {
    let report = report();
    let schedule = schedule::<Grouped>();
    let sizes = Sizes::of::<Grouped>();
    let cells = cells::<Grouped>();
    let position = |step: Step| schedule.iter().position(|&s| s == step).unwrap();
    let defined = |cell, step: Step| {
        let usage = report.usage(Cell::Element(cell));
        assert_eq!(usage.step, position(step), "{cell:?}");
        assert_eq!(usage.how, Definition::Stored, "{cell:?}");
    };

    assert_eq!(schedule[0], Step::Challenges);
    for &cell in cells.challenges.each() {
        defined(cell, Step::Challenges);
        assert!(!report.usage(Cell::Element(cell)).loads.is_empty());
    }
    assert_eq!(cells.masks.len(), sizes.masks);
    for &cell in &cells.masks {
        defined(cell, Step::Masks);
    }
    for (page, &[a, b]) in cells.fold.iter().enumerate() {
        defined(a, Step::Fold { page });
        defined(b, Step::Fold { page });
    }
    assert!(cells.quotients.len() > 1, "the test profile's f has pages");
    for (page, &cell) in cells.quotients.iter().enumerate() {
        defined(cell, Step::Quotients { page });
    }
    for (page, &cell) in cells.evaluations.iter().enumerate() {
        defined(cell, Step::Evaluations { page });
    }

    // The profile has no online batch: no cell is the prover's to supply.
    assert!(cells.online_fold.is_empty());
    assert!(report.advised().is_empty());

    let unread: Vec<Cell> = report.unread();
    assert_eq!(
        unread,
        Vec::from([Cell::Element(*cells.evaluations.last().unwrap())])
    );
}

/// A step circuit has no unified instance: the challenge step fails in it.
#[test]
fn the_challenges_are_stored_where_the_instance_is() {
    let log = Log::new();
    let dr = &mut Counter::counter();
    let stages = every_stage::<_, C, WalletRank, HEADER_SIZE>(dr, &Empty).unwrap();
    let inputs = Inputs {
        stages: &stages,
        memory: Memory::checking(&log, <Pasta as Cycle>::NestedCurve::generator()),
        challenges: None,
        online_fold: Empty,
    };
    log.begin(0);
    assert!(super::compute_v::challenges(dr, &inputs).is_err());
}
