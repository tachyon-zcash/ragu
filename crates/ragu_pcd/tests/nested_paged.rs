//! Tests of the nested program of a paged profile: what each cell of its
//! memory holds, which step defines it and which values the prover
//! supplies.

use alloc::vec::Vec;

use ragu_circuits::polynomials::WalletRank;
use ragu_core::{
    Cycle,
    drivers::emulator::{Emulator, Wireless},
    maybe::Empty,
    pasta::Pasta,
};
use udon::curve::Affine as _;

use super::{Fuse, Inputs, Sizes, Step, cells, every_stage, schedule};
use crate::{
    internal::program::{self, Cell, Definition, Log, Memory, Report},
    profile::{Profile, testing::Grouped},
};

type Host = <Pasta as Cycle>::HostCurve;
type Counter = Emulator<Wireless<Empty, <Pasta as Cycle>::ScalarField>>;

/// The report of a run of the program of profile `P` that records its
/// accesses on a driver without a witness.
fn report<P: Profile>() -> Report {
    let log = Log::new();
    {
        let dr = &mut Counter::counter();
        let stages = every_stage::<_, Host, WalletRank, P>(dr, &Empty).unwrap();
        let inputs = Inputs {
            stages: &stages,
            memory: Memory::checking(&log, Host::generator()),
            online_fold: Empty,
        };
        program::run(&Fuse::<Host, WalletRank, P>::new(), dr, &inputs, &log).unwrap();
    }
    log.finish().unwrap()
}

/// Every cell of the memory has one definition, in the step the cell's
/// documentation names, and a later step loads it or one of the two
/// instance circuits does.
#[test]
fn every_cell_is_defined_by_the_step_that_computes_it() {
    let report = report::<Grouped>();
    let schedule = schedule::<Grouped>();
    let sizes = Sizes::of::<Grouped>();
    let cells = cells::<Grouped>();
    let position = |step: Step| schedule.iter().position(|&s| s == step).unwrap();
    let defined = |cell: Cell, step: Step| {
        let usage = report.usage(cell);
        assert_eq!(usage.step, position(step), "{cell:?}");
        assert_eq!(usage.how, Definition::Stored, "{cell:?}");
    };

    for (child, child_cells) in cells.children.iter().enumerate() {
        let step = Step::Child { child };
        for &cell in &child_cells.nested {
            defined(Cell::Element(cell), step);
        }
        defined(Cell::Element(child_cells.unified), step);
        defined(Cell::Element(child_cells.compute_v), step);
        assert!(child_cells.online_helper.is_none() && child_cells.binding.is_none());
    }

    let errors = Step::Errors {
        page: sizes.error_pages() - 1,
    };
    defined(Cell::Element(cells.c), errors);
    defined(Cell::Point(cells.registry_wy), errors);
    defined(Cell::Point(cells.native_inner_error), errors);
    defined(Cell::Point(cells.native_outer_error), errors);

    assert_eq!(cells.masks.len(), sizes.masks);
    for &cell in &cells.masks {
        defined(Cell::Element(cell), Step::Masks);
    }
    defined(Cell::Point(cells.native_query), Step::Masks);
    defined(Cell::Point(cells.registry_xy), Step::Masks);

    for (page, &[a, b]) in cells.fold.iter().enumerate() {
        defined(Cell::Element(a), Step::Fold { page });
        defined(Cell::Element(b), Step::Fold { page });
    }
    for (page, &cell) in cells.quotients.iter().enumerate() {
        defined(Cell::Element(cell), Step::Quotients { page });
    }
    for (page, &cell) in cells.evaluations.iter().enumerate() {
        defined(Cell::Element(cell), Step::Evaluations { page });
    }
    defined(
        Cell::Point(cells.native_eval),
        Step::Evaluations { page: 0 },
    );

    // The profile has no online batch: no cell is the prover's to supply.
    assert!(cells.online_fold.is_empty());
    assert!(report.advised().is_empty());

    // The cells no step loads are the ones the instance circuit reads: the
    // folded c_n, v_n and the commitments the unified instance exports
    // from the stages that circuit does not load.
    let mut unread = report.unread();
    unread.sort();
    let mut expected: Vec<Cell> = Vec::from([
        Cell::Element(cells.c),
        Cell::Element(*cells.evaluations.last().unwrap()),
        Cell::Point(cells.native_inner_error),
        Cell::Point(cells.native_outer_error),
        Cell::Point(cells.native_query),
        Cell::Point(cells.native_eval),
    ]);
    expected.sort();
    assert_eq!(unread, expected);
}

/// The walk's steps load the two commitments they hold inputs to from the
/// cells of the steps that load the commitments' stages.
#[test]
fn a_walk_step_reads_the_copies_other_branches_stored() {
    let report = report::<Grouped>();
    let schedule = schedule::<Grouped>();
    let cells = cells::<Grouped>();
    let walk: Vec<usize> = schedule
        .iter()
        .enumerate()
        .filter(|(_, step)| matches!(step, Step::Walk { .. }))
        .map(|(position, _)| position)
        .collect();
    assert!(walk.len() > 1);
    for cell in [cells.registry_wy, cells.registry_xy] {
        assert_eq!(report.usage(Cell::Point(cell)).loads, walk);
    }
}
