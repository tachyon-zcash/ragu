use alloc::{string::ToString, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use ragu_core::{
    Coeff,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{
    Element,
    allocator::Standard,
    vec::{ConstLen, FixedVec},
};
use rand::Rng;

use super::{
    pager::*,
    record::*,
    replay::{Body, Step},
    *,
};
use crate::{
    Blind, Circuit, CircuitExt, WiringObject, WithAux, floor_planner, into_wiring_object,
    polynomials::sparse,
    staging::{MultiStage, StageBuilder, StageExt},
    wiring::monomials::{Monomial, Monomials},
};

/// A rank with the room for a carry stage of [`WIDE`] values and a page's
/// gates beside it.
type R = crate::polynomials::R<13>;

/// The values the carry stage of a test circuit holds unless a test says
/// otherwise: more than any of them carries.
const WIDE: usize = 512;

/// A circuit without stages as a pageable circuit, over a carry stage of
/// `CARRY` values.
struct Flat<C, const CARRY: usize = WIDE>(C);

impl<C: Circuit<Fp>, const CARRY: usize> MultiStageCircuit<Fp, R> for Flat<C, CARRY> {
    type Last = ();
    type Instance<'source> = C::Instance<'source>;
    type Witness<'source> = C::Witness<'source>;
    type Output = C::Output;
    type Aux<'source> = C::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        self.0.instance(dr, instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        self.0.witness(builder.finish(), witness)
    }
}

impl<C: Circuit<Fp>, const CARRY: usize> Pageable<Fp, R> for Flat<C, CARRY> {
    type Carry = ConstLen<CARRY>;
}

/// `circuit`, which has no stages, as a pageable circuit over a carry
/// stage of [`WIDE`] values.
fn flat<C: Circuit<Fp>>(circuit: C) -> MultiStage<Fp, R, Flat<C>> {
    MultiStage::new(Flat(circuit))
}

/// `circuit` in as few pages of `page_gates` gates of its own as it cuts
/// into.
fn fitted<S: Pageable<Fp, R>>(
    circuit: MultiStage<Fp, R, S>,
    page_gates: usize,
) -> Result<Pages<Fp, R, S>> {
    let stages = Stages::of::<Fp, R, S>();
    let circuit = Arc::new(circuit);
    let own = size(&*circuit)?.0 - stages.own_start();
    let limit = (stages.carry_gates().end).saturating_add(page_gates);
    let fewest = own.div_ceil(page_gates).max(1);
    let mut last = None;
    for pages in fewest..fewest + 16 {
        match Pages::cut_within(circuit.clone(), pages, limit) {
            Err(Error::GateBoundExceeded { .. }) => last = Some(pages),
            paged => return paged,
        }
    }
    refuse(format!("the circuit does not cut into {last:?} pages"))
}

/// `LEN` squarings of the witness, each `STRIDE`-th followed by adding
/// the witness back and some by adding the value two squarings ago: a
/// narrow cut, one wire every page names, and constraints over two
/// pages' wires.
struct Chain<const LEN: usize, const STRIDE: usize>;

impl<const LEN: usize, const STRIDE: usize> Chain<LEN, STRIDE> {
    fn run(witness: Fp) -> Fp {
        let mut acc = witness;
        let mut history = alloc::vec![witness];
        for step in 0..LEN {
            acc = acc.square();
            if step % STRIDE == 0 {
                acc += witness;
            }
            if step % (2 * STRIDE) == 1 {
                acc += history[history.len() - 2];
            }
            history.push(acc);
        }
        acc
    }
}

impl<const LEN: usize, const STRIDE: usize> Circuit<Fp> for Chain<LEN, STRIDE> {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let first = Element::alloc(dr, &mut Standard::new(), witness)?;
        let mut acc = first.clone();
        let mut history = alloc::vec![first.clone()];
        for step in 0..LEN {
            acc = acc.square(dr)?;
            if step % STRIDE == 0 {
                acc = acc.add(dr, &first);
            }
            if step % (2 * STRIDE) == 1 {
                acc = acc.add(dr, &history[history.len() - 2]);
            }
            history.push(acc.clone());
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

struct TwoOutputs;

impl Circuit<Fp> for TwoOutputs {
    type Instance<'source> = (Fp, Fp);
    type Witness<'source> = (Fp, Fp);
    type Output = Kind![Fp; (Element<'_, _>, Element<'_, _>)];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let allocator = &mut Standard::new();
        let first = Element::alloc(dr, allocator, instance.as_ref().map(|values| values.0))?;
        let second = Element::alloc(dr, allocator, instance.as_ref().map(|values| values.1))?;
        Ok((first, second))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let allocator = &mut Standard::new();
        let first = Element::alloc(dr, allocator, witness.as_ref().map(|values| values.0))?;
        let second = Element::alloc(dr, allocator, witness.as_ref().map(|values| values.1))?;
        Ok(WithAux::new((first, second), D::unit()))
    }
}

/// The gates of its own a circuit without stages allocates.
fn own_gates<C: Circuit<Fp>>(circuit: &C) -> Result<usize> {
    Ok(size(circuit)?.0 - 1)
}

#[test]
fn one_page_carries_nothing() -> Result<()> {
    let paged = fitted(flat(Chain::<40, 5>), 1 << 20)?;
    let report = paged.report();
    assert_eq!(report.pages.len(), 1);
    assert_eq!(report.carried_wires, 0);
    assert_eq!(report.slots, 0);
    assert_eq!(report.cross_constraints, 0);
    assert!(report.cuts.is_empty());
    assert_eq!(report.num_gates, 1 + report.pages[0].gates);
    Ok(())
}

#[test]
fn a_chain_carries_its_cut_and_its_long_lived_wire() -> Result<()> {
    let whole = fitted(flat(Chain::<40, 5>), 1 << 20)?;
    let paged = fitted(flat(Chain::<40, 5>), 8)?;
    let (whole, paged) = (whole.report(), paged.report());
    assert_eq!(paged.num_gates, whole.num_gates);
    assert_eq!(paged.num_constraints, whole.num_constraints);
    assert_eq!(paged.pages.len(), (whole.num_gates - 1).div_ceil(8));
    // A boundary is crossed by the running value, by the values just
    // before it and by the witness, which every later page names.
    assert!(paged.cuts.iter().all(|&cut| (1..=4).contains(&cut)));
    assert!(paged.carried_wires >= paged.pages.len() - 1);
    assert!(paged.carried_wires <= 4 * paged.pages.len());
    Ok(())
}

/// Whether the revdot claim of one page holds, on its own polynomial
/// plus `loaded`, the carry stage's and those of the stages it loads,
/// for random challenges.
fn page_claim_holds<C: Circuit<Fp>>(
    page: C,
    witness: C::Witness<'_>,
    instance: C::Instance<'_>,
    loaded: &sparse::Polynomial<Fp, R>,
) -> Result<bool> {
    let mut rng = rand::rng();
    let trace = page.trace(witness)?.into_output();
    let y = Fp::random(|bytes| rng.fill_bytes(bytes));
    let z = Fp::random(|bytes| rng.fill_bytes(bytes));
    let expected = page.ky(instance, y)?;
    let object = into_wiring_object::<_, _, R>(page)?;
    let plan = floor_planner::floor_plan(object.segment_records());
    let mut a = trace.assemble::<R>(&plan, Blind::<Fp>::random(&mut rng))?;
    a.add_assign(loaded);
    let mut b = a.clone();
    b.dilate(z);
    b.add_assign(&object.sy(y, &plan));
    b.add_assign(&R::tz(z));
    Ok(expected == a.revdot(&b))
}

/// Pages `Chain<LEN, STRIDE>` over a carry stage of `CARRY` values, in
/// pages of twenty-two gates of its own, and tells which pages' claims
/// hold, with the carry stage's values passed through `tamper`.
fn claims<const LEN: usize, const STRIDE: usize, const CARRY: usize>(
    tamper: impl Fn(&mut Vec<Fp>),
) -> Result<(Pages<Fp, R, Flat<Chain<LEN, STRIDE>, CARRY>>, Vec<bool>)> {
    let witness = Fp::from(3u64);
    let instance = Chain::<LEN, STRIDE>::run(witness);
    let paged = fitted(MultiStage::new(Flat::<_, CARRY>(Chain::<LEN, STRIDE>)), 22)?;
    let pages = paged.num_pages();
    let captured = paged.capture(witness)?;
    let mut values = captured.carry.clone();
    tamper(&mut values);
    let carry = paged.carry_rx(Blind::<Fp>::random(&mut rand::rng()), &values)?;

    let mut holds = Vec::new();
    for index in 0..pages - 1 {
        holds.push(page_claim_holds(
            paged.page(index),
            &captured.pages[index][..],
            (),
            &carry,
        )?);
    }
    holds.push(page_claim_holds(paged.last(), witness, instance, &carry)?);
    Ok((paged, holds))
}

#[test]
fn every_page_of_a_paged_circuit_satisfies_its_claim() -> Result<()> {
    let (paged, holds) = claims::<100, 3, 32>(|_| {})?;
    assert!(paged.num_pages() >= 4, "the chain takes several pages");
    assert!(paged.report().slots > 0, "the chain carries values");
    assert!(holds.iter().all(|&hold| hold), "{holds:?}");
    check::check(&paged)?;
    Ok(())
}

#[test]
fn the_pages_constraints_are_the_circuits() -> Result<()> {
    // Whatever the cut.
    for page_gates in [1, 2, 3, 5, 8, 13, 28, 1 << 20] {
        fitted(flat(Chain::<100, 3>), page_gates)?.check()?;
        fitted(MultiStage::new(Seeded::<90>), page_gates)?.check()?;
    }
    // In polynomials of fifty-seven gates, over a carry stage of
    // sixty-four values, in as many pages as that takes and in more.
    for pages in 5..9 {
        let circuit = MultiStage::new(Flat::<_, 64>(Chain::<100, 3>));
        let cut = Pages::cut_within(circuit, pages, 57)?;
        let (layout, report) = (cut.layout(), cut.report());
        assert_eq!(layout.carry, 1..33);
        assert_eq!(layout.window(), 33..57);
        assert!(report.slots <= 64);
        for held in &report.pages {
            assert!(held.gates <= layout.room());
        }
        check::check(&cut)?;
    }
    Ok(())
}

#[test]
fn pages_without_the_room_are_refused() {
    assert!(matches!(
        Pages::cut_within(MultiStage::new(Flat::<_, 64>(Chain::<100, 3>)), 2, 57),
        Err(Error::GateBoundExceeded { .. })
    ));
}

/// `paged` with the pager's draft of it passed through `tamper`, and its
/// pages compiled from the draft it leaves.
fn tampered<S: Pageable<Fp, R>>(
    paged: &Pages<Fp, R, S>,
    tamper: impl FnOnce(&mut Draft<Fp>),
) -> Pages<Fp, R, S> {
    let (mut draft, report, recording) = drafted(paged);
    tamper(&mut draft);
    draft.compile(&recording);
    Pages::over(paged.circuit.clone(), Arc::new(draft.finish()), report)
}

/// The pager's draft of `paged`, before it is compiled, with its report
/// and the walk it was made from.
fn drafted<S: Pageable<Fp, R>>(
    paged: &Pages<Fp, R, S>,
) -> (Draft<Fp>, PagingReport, Recording<Fp>) {
    Pages::<Fp, R, S>::drafted(&paged.circuit, paged.num_pages(), paged.plan.limit)
        .expect("the circuit cuts as it did")
}

#[test]
fn a_plan_that_miscarries_is_caught() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    let draft = drafted(&paged).0;
    let (&constraint, _) = draft.links.iter().next().expect("the chain carries");

    // A slot read at the wrong scale.
    let wrong = tampered(&paged, |plan| {
        plan.links.get_mut(&constraint).unwrap()[0].scale += Fp::ONE;
    });
    assert!(refused(
        &wrong,
        "a carry slot lacks its defining constraint"
    ));

    // A slot the constraint no longer reads: the term is dropped.
    let wrong = tampered(&paged, |plan| {
        plan.links.remove(&constraint);
    });
    assert!(refused(
        &wrong,
        "a carry slot lacks its defining constraint"
    ));

    // A slot no page holds to its wires.
    let wrong = tampered(&paged, |plan| {
        for links in plan.links.values_mut() {
            for link in links.iter_mut().filter(|link| link.slot == 0) {
                link.defines = false;
            }
        }
    });
    assert!(refused(
        &wrong,
        "a carry slot lacks its defining constraint"
    ));

    // A constraint homed on a page that lacks its wires.
    let wrong = tampered(&paged, |plan| {
        let moved = plan.homes.iter().position(|&home| home == 2).unwrap();
        plan.homes[moved] = 0;
    });
    assert!(refused(&wrong, "constraints are not the circuit's"));
    Ok(())
}

#[test]
fn a_missing_carry_definition_cannot_hide_behind_a_zero_constraint() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    let (mut draft, report, recording) = drafted(&paged);
    let (&constraint, links) = draft
        .links
        .iter()
        .find(|(_, links)| links.iter().any(|link| link.defines))
        .expect("the chain has a defined carry slot");
    let exporter = links.iter().find(|link| link.defines).unwrap().exporter as usize;

    draft
        .links
        .get_mut(&constraint)
        .unwrap()
        .iter_mut()
        .find(|link| link.defines)
        .unwrap()
        .defines = false;
    draft.compile(&recording);
    // The old value-based check included one zero for each slot definition.
    // A planner could replace a missing definition with 0 = 0 and pass it.
    draft.programs[exporter].enforce_zero(Vec::new());
    let wrong = Pages::over(paged.circuit.clone(), Arc::new(draft.finish()), report);
    assert!(matches!(
        check::check(&wrong),
        Err(Error::Initialization(message)) if message.to_string().contains("a carry slot lacks its defining constraint")
    ));
    Ok(())
}

#[test]
fn the_public_output_keeps_its_order() -> Result<()> {
    let paged = fitted(flat(TwoOutputs), 8)?;
    check::check(&paged)?;
    let mut plan = (*paged.plan).clone();
    assert_eq!(plan.programs.len(), 1);
    assert_eq!(plan.programs[0].outputs.len(), 2);
    plan.programs[0].outputs.swap(0, 1);
    let wrong = Pages::over(paged.circuit.clone(), Arc::new(plan), paged.report.clone());
    assert!(matches!(
        check::check(&wrong),
        Err(Error::Initialization(message)) if message.to_string().contains("public output")
    ));
    Ok(())
}

#[test]
fn a_circuit_of_one_page_is_its_last_page() -> Result<()> {
    let (paged, holds) = claims::<8, 3, 2>(|_| {})?;
    assert_eq!(paged.num_pages(), 1);
    assert_eq!(paged.report().slots, 0);
    assert_eq!(holds, [true]);
    Ok(())
}

#[test]
fn a_wrong_carried_value_fails_a_page() -> Result<()> {
    let slots = claims::<100, 3, 32>(|_| {})?.0.report().slots;
    for slot in 0..slots {
        let (_, holds) = claims::<100, 3, 32>(|values| values[slot] += Fp::ONE)?;
        // The page that holds the slot to its wires no longer does, and
        // neither does a page that reads it.
        assert!(
            holds.iter().filter(|&&hold| !hold).count() >= 2,
            "slot {slot}: {holds:?}"
        );
    }
    Ok(())
}

#[test]
fn a_carry_stage_too_small_is_refused() -> Result<()> {
    // The chain carries more values than two.
    assert!(matches!(
        fitted(MultiStage::new(Flat::<_, 2>(Chain::<100, 3>)), 22),
        Err(Error::Initialization(message))
            if message.to_string().contains("more than the 2 their carry")
    ));
    Ok(())
}

/// `paged` with its plan passed through `tamper` and left as that leaves
/// it: its pages are not compiled again.
fn misplaced<S: Pageable<Fp, R>>(
    paged: &Pages<Fp, R, S>,
    tamper: impl FnOnce(&mut Plan<Fp>),
) -> Pages<Fp, R, S> {
    let mut plan = (*paged.plan).clone();
    tamper(&mut plan);
    Pages::over(paged.circuit.clone(), Arc::new(plan), paged.report.clone())
}

/// Whether the check refuses `paged` for `what`.
fn refused<S: Pageable<Fp, R>>(paged: &Pages<Fp, R, S>, what: &str) -> bool {
    matches!(
        check::check(paged),
        Err(Error::Initialization(message)) if message.to_string().contains(what)
    )
}

#[test]
fn a_plan_that_misplaces_a_gate_is_caught() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    let last = paged.num_pages() - 1;
    assert!(last >= 2, "the chain takes several pages");
    assert!(!paged.layout().carry.is_empty(), "the chain carries values");

    // A gate on two pages, in place of one of the second's.
    let wrong = misplaced(&paged, |plan| plan.held[1][0] = plan.held[0][0]);
    assert!(refused(&wrong, "duplicates a gate"));

    // Two gates of a page at each other's place: the page's constraints
    // are then over other gates than the circuit's.
    let wrong = misplaced(&paged, |plan| plan.held[0].swap(0, 1));
    assert!(check::check(&wrong).is_err());

    // A gate that is not the circuit's.
    let wrong = misplaced(&paged, |plan| plan.held[0][0] = u32::MAX);
    assert!(refused(&wrong, "holds a gate outside the circuit"));

    // A gate no page holds: the last page gives up its last.
    let wrong = misplaced(&paged, |plan| {
        plan.held[last].pop();
        *plan.programs[last].own_mut() -= 1;
    });
    assert!(refused(&wrong, "does not cover the circuit"));

    // A page that allocates other gates than it holds.
    let wrong = misplaced(&paged, |plan| *plan.programs[0].own_mut() += 1);
    assert!(refused(&wrong, "allocates other gates than it holds"));

    // A page with more gates than a polynomial holds.
    let limit = paged.layout().carry.end;
    let wrong = misplaced(&paged, |plan| plan.limit = limit);
    assert!(refused(&wrong, "more gates than a polynomial has"));
    Ok(())
}

/// A run of squarings that takes one more once it is told to: a circuit
/// that does not emit the same gates on every walk.
struct Fickle(Arc<AtomicBool>);

impl Circuit<Fp> for Fickle {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let mut acc = Element::alloc(dr, &mut Standard::new(), witness)?;
        for _ in 0..20 + usize::from(self.0.load(Ordering::Relaxed)) {
            acc = acc.square(dr)?;
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_circuit_that_walks_otherwise_than_it_was_cut_is_refused() -> Result<()> {
    let longer = Arc::new(AtomicBool::new(false));
    let paged = fitted(flat(Fickle(longer.clone())), 8)?;
    assert!(paged.num_pages() > 1, "the squarings take several pages");
    check::check(&paged)?;
    let witness = Fp::from(3u64);
    paged.capture(witness)?;

    // The circuit now allocates a gate its plan does not have. Its pages
    // are given no values, and the check no longer passes them.
    longer.store(true, Ordering::Relaxed);
    assert!(matches!(
        paged.capture(witness),
        Err(Error::Initialization(message)) if message.to_string().contains("diverged from its plan")
    ));
    assert!(refused(&paged, "does not cover the circuit"));
    Ok(())
}

#[test]
fn a_plan_out_of_shape_is_caught() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    assert!(paged.report().slots > 2, "the chain carries several values");

    // A plan says nothing of the circuit's stages, of its carry stage's
    // gates or of where a gate is placed, so none of them can be other
    // than the circuit's: the pages are laid over what its type states.
    let stages = Stages::of::<Fp, R, Flat<Chain<100, 3>>>();
    assert_eq!(paged.layout().own_start, stages.own_start());
    assert_eq!(paged.layout().carry, stages.carry_gates());

    // A slot another constraint defines, read at another scale: the
    // pages' constraints are no longer the circuit's.
    let draft = drafted(&paged).0;
    let (constraint, link) = draft
        .links
        .iter()
        .find_map(|(&constraint, links)| {
            let link = links.iter().position(|link| !link.defines)?;
            Some((constraint, link))
        })
        .expect("a slot is read by more than the constraint that defines it");
    let wrong = tampered(&paged, |plan| {
        plan.links.get_mut(&constraint).unwrap()[link].scale += Fp::ONE;
    });
    assert!(refused(&wrong, "constraints are not the circuit's"));

    // The check's other refusals guard what a page cannot do, whatever its
    // plan: a page before the last has no public output, so it writes no
    // output gate and ends on its `ONE` constraint, and the circuit's own
    // walk always ends on one.
    Ok(())
}

/// The wiring polynomial of `circuit`, written out of its recording.
///
/// A recording counts the gates and the constraints in the order the
/// circuit emits them. A wiring polynomial holds them by segment: what the
/// circuit emits outside any routine, then each routine's own, in the
/// order the walk meets the calls. A segment's constraints are the
/// coefficients of the powers of `Y` from its last down, and a gate's
/// wires are the wiring layout's powers of `X` at the gate's place.
fn recorded<C: Circuit<Fp>>(circuit: &C) -> Result<Monomials<Fp>> {
    let n = R::n();
    let recording = Recording::<Fp>::whole_of(circuit)?;
    let count = recording.constraints.len();

    // The segment of each gate and of each constraint: the innermost call
    // that emits it, or none.
    fn segments(
        calls: &[Invocation],
        gates: &mut [usize],
        constraints: &mut [usize],
        next: &mut usize,
    ) {
        for call in calls {
            let segment = *next;
            *next += 1;
            gates[call.gates.clone()].fill(segment);
            constraints[call.constraints.clone()].fill(segment);
            segments(&call.invocations, gates, constraints, next);
        }
    }
    let mut gates = vec![0; recording.num_gates];
    let mut constraints = vec![0; count];
    let mut segments_len = 1;
    segments(
        &recording.invocations,
        &mut gates,
        &mut constraints,
        &mut segments_len,
    );
    // The place of each: a segment's gates from its first on, and its
    // constraints down from its last, in the order it emits them.
    let place = |of: &[usize], down: bool| -> Vec<usize> {
        let mut sizes = vec![0; segments_len];
        for &segment in of {
            sizes[segment] += 1;
        }
        let starts: Vec<usize> = sizes
            .iter()
            .scan(0, |start, size| {
                let first = *start;
                *start += size;
                Some(first)
            })
            .collect();
        let mut emitted = vec![0; segments_len];
        of.iter()
            .map(|&segment| {
                emitted[segment] += 1;
                if down {
                    starts[segment] + sizes[segment] - emitted[segment]
                } else {
                    starts[segment] + emitted[segment] - 1
                }
            })
            .collect()
    };
    let (gates, constraints) = (place(&gates, false), place(&constraints, true));

    let mut monomials = Vec::new();
    for (index, (_, terms)) in recording.constraints.iter().enumerate() {
        for &(wire, coeff) in terms {
            let gate = gates[(wire / 4) as usize];
            let x = match wire % 4 {
                0 => 2 * n + gate,
                1 => 2 * n - 1 - gate,
                2 => 4 * n - 1 - gate,
                _ => gate,
            };
            monomials.push(Monomial {
                y: constraints[index],
                x,
                coeff,
            });
        }
    }
    monomials.sort_unstable_by_key(|monomial| (monomial.y, monomial.x));
    Ok(Monomials::new(monomials))
}

/// The wiring polynomial `circuit` is registered with, as the registry
/// hashes it into its tag.
fn registered<C: Circuit<Fp>>(circuit: C) -> Result<Monomials<Fp>> {
    let object = into_wiring_object::<_, _, R>(circuit)?;
    let plan = floor_planner::floor_plan(object.segment_records());
    Ok(object.monomials(&plan))
}

/// Holds each page's recording to the page's registered polynomial.
fn pages_are_recorded<S: Pageable<Fp, R>>(paged: &Pages<Fp, R, S>) -> Result<()> {
    for page in 0..paged.num_pages() - 1 {
        assert_eq!(
            recorded(&paged.page(page))?,
            registered(paged.page(page))?,
            "page {page}"
        );
    }
    assert_eq!(recorded(&paged.last())?, registered(paged.last())?);
    Ok(())
}

#[test]
fn a_recording_is_the_registered_polynomial() -> Result<()> {
    // The check compares recordings, and what is registered is a wiring
    // polynomial: the two are the same polynomial. Of circuits small
    // enough for one polynomial, with a stage and without.
    assert_eq!(recorded(&Chain::<20, 3>)?, registered(Chain::<20, 3>)?);
    assert_eq!(recorded(&TwoOutputs)?, registered(TwoOutputs)?);
    let small = || MultiStage::<Fp, R, _>::new(Seeded::<20>);
    assert_eq!(recorded(&small())?, registered(small())?);

    // Of circuits that call routines, one within another.
    assert_eq!(recorded(&Called::<5>)?, registered(Called::<5>)?);
    assert_eq!(recorded(&Wrapped::<3>)?, registered(Wrapped::<3>)?);

    // And of every page, which is what a registry holds of a paged
    // circuit: a page calls the routines it holds, so its polynomial has
    // their segments as the circuit's would.
    pages_are_recorded(&fitted(flat(Chain::<100, 3>), 8)?)?;
    pages_are_recorded(&fitted(flat(TwoOutputs), 1)?)?;
    pages_are_recorded(&fitted(MultiStage::new(Seeded::<90>), 8)?)?;
    for page_gates in [8, 20, 31] {
        pages_are_recorded(&fitted(flat(Called::<5>), page_gates)?)?;
        pages_are_recorded(&fitted(flat(Wrapped::<5>), page_gates)?)?;
    }
    Ok(())
}

#[test]
fn a_digest_tells_two_cuts_apart() -> Result<()> {
    let digest = |page_gates: usize| -> Result<[u8; 32]> {
        fitted(flat(Chain::<100, 3>), page_gates)?.digest()
    };
    // The same cut gives the same digest, and a cut a gate later another.
    assert_eq!(digest(8)?, digest(8)?);
    assert_ne!(digest(8)?, digest(9)?);

    // Where the search places the cuts, and in more pages.
    let placed = |pages: usize| -> Result<[u8; 32]> {
        Pages::cut_within(MultiStage::new(Flat::<_, 64>(Chain::<100, 3>)), pages, 57)?.digest()
    };
    assert_eq!(placed(6)?, placed(6)?);
    assert_ne!(placed(6)?, placed(7)?);
    Ok(())
}

/// Four values every page reads.
#[derive(Default)]
struct Seeds;

impl Stage<Fp, R> for Seeds {
    type Parent = ();
    type Witness<'source> = [Fp; 4];
    type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

    fn values() -> usize {
        4
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, [Fp; 4]>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), witness.as_ref().map(|seeds| seeds[i]))
        })
    }
}

/// `LEN` squarings, each followed by adding one of the stage's values:
/// a circuit over a stage that every page reads.
struct Seeded<const LEN: usize>;

impl<const LEN: usize> Seeded<LEN> {
    fn run(seeds: [Fp; 4]) -> Fp {
        (0..LEN).fold(seeds[0], |acc, step| acc.square() + seeds[step % 4])
    }
}

impl<const LEN: usize> Pageable<Fp, R> for Seeded<LEN> {
    type Carry = ConstLen<256>;
}

impl<const LEN: usize> MultiStageCircuit<Fp, R> for Seeded<LEN> {
    type Last = Seeds;
    type Instance<'source> = Fp;
    type Witness<'source> = [Fp; 4];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, [Fp; 4]>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (seeds, builder) = builder.add_stage::<Seeds>()?;
        let dr = builder.finish();
        let seeds = seeds.unenforced(dr, witness)?;
        let mut acc = seeds[0].clone();
        for step in 0..LEN {
            acc = acc.square(dr)?;
            acc = acc.add(dr, &seeds[step % 4]);
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_staged_circuit_pages_after_its_stage() -> Result<()> {
    let seeds = [3u64, 5, 7, 11].map(Fp::from);
    let instance = Seeded::<90>::run(seeds);
    let stages = Stages::of::<Fp, R, Seeded<90>>();
    assert_eq!(
        stages.own_start(),
        3,
        "the SYSTEM gate and the stage's two gates"
    );
    assert_eq!(stages.carry_gates(), 3..131, "its values after the stage");
    let paged = Pages::cut_within(MultiStage::new(Seeded::<90>), 5, 155)?;
    let pages = paged.num_pages();
    // The stage's wires are every page's: none is carried, and every
    // page names them.
    assert!(paged.report().pages.iter().all(|page| page.stage_wires > 0));
    assert!(paged.report().slots <= 2 * (pages - 1));
    assert_eq!(paged.layout().window(), 131..155);

    let captured = paged.capture(seeds)?;
    let mut rng = rand::rng();
    let carry = paged.carry_rx(Blind::<Fp>::random(&mut rng), &captured.carry)?;
    let stage = <Seeds as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), seeds)?;
    let mut loaded = carry.clone();
    loaded.add_assign(&stage);

    for index in 0..pages - 1 {
        assert!(page_claim_holds(
            paged.page(index),
            &captured.pages[index][..],
            (),
            &loaded
        )?);
        // A page reads the stage: without it, its claim fails.
        assert!(!page_claim_holds(
            paged.page(index),
            &captured.pages[index][..],
            (),
            &carry
        )?);
    }
    assert!(page_claim_holds(paged.last(), seeds, instance, &loaded)?);
    assert!(!page_claim_holds(paged.last(), seeds, instance, &carry)?);
    Ok(())
}

/// `LEN` squares of sums of the witness, all allocated first, then a
/// product that takes them one by one: a batch computed long before it
/// is used, as a batch of inverses is.
struct Batch<const LEN: usize>;

impl<const LEN: usize> Batch<LEN> {
    fn run(witness: Fp) -> Fp {
        let mut sum = witness;
        (0..LEN).fold(witness, |acc, _| {
            sum += witness;
            acc * sum.square()
        })
    }
}

impl<const LEN: usize> Circuit<Fp> for Batch<LEN> {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let first = Element::alloc(dr, &mut Standard::new(), witness)?;
        let mut sum = first.clone();
        let mut squares = Vec::new();
        for _ in 0..LEN {
            sum = sum.add(dr, &first);
            squares.push(sum.square(dr)?);
        }
        let mut acc = first;
        for square in &squares {
            acc = acc.mul(dr, square)?;
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_gate_is_placed_with_the_first_gate_it_feeds() -> Result<()> {
    // In the order the circuit allocates its gates, a cut between the
    // squares and the product carries every square past it, more than
    // a carry stage beside the pages holds. Each square is placed with
    // the product that takes it, and a cut carries the running product
    // and the witness.
    let witness = Fp::from(3u64);
    let paged = Pages::cut_within(MultiStage::new(Flat::<_, 16>(Batch::<40>)), 4, 34)?;
    assert!(paged.report().slots <= 3 * 3, "{:?}", paged.report().cuts);
    check::check(&paged)?;

    let captured = paged.capture(witness)?;
    let carry = paged.carry_rx(Blind::<Fp>::random(&mut rand::rng()), &captured.carry)?;
    for index in 0..3 {
        assert!(page_claim_holds(
            paged.page(index),
            &captured.pages[index][..],
            (),
            &carry
        )?);
    }
    let instance = Batch::<40>::run(witness);
    assert!(page_claim_holds(paged.last(), witness, instance, &carry)?);
    Ok(())
}

/// A cut that fits with every gate where the circuit allocates it is taken,
/// though another order carries less: no other order is looked for.
#[test]
fn a_cut_that_fits_as_allocated_is_taken() -> Result<()> {
    // The same circuit and the same room, over a carry stage that holds
    // every square a cut between the squares and the product carries.
    let limit = Stages::of::<Fp, R, Flat<Batch<40>>>().carry_gates().end + 25;
    let paged = Pages::cut_within(flat(Batch::<40>), 4, limit)?;
    check::check(&paged)?;
    assert!(paged.plan.held.iter().flatten().is_sorted());
    assert!(paged.report().slots > 3 * 3, "{:?}", paged.report().cuts);
    Ok(())
}

/// A plan is held to the stages its circuit was cut over: one that lays a
/// stage elsewhere names the same wires in its constraints, but a page
/// would read them at gates the stage's polynomial does not hold them at.
/// Four values, at the first gates after the SYSTEM gate.
#[derive(Default)]
struct Left;

impl Stage<Fp, R> for Left {
    type Parent = ();
    type Witness<'source> = [Fp; 4];
    type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

    fn values() -> usize {
        4
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, [Fp; 4]>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
        })
    }
}

/// Four more values, which a circuit reserves after [`Left`]'s.
#[derive(Default)]
struct Right;

impl Stage<Fp, R> for Right {
    type Parent = Left;
    type Witness<'source> = [Fp; 4];
    type OutputKind = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<4>>];

    fn values() -> usize {
        4
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, [Fp; 4]>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| {
            Element::alloc(dr, &mut (), witness.as_ref().map(|values| values[i]))
        })
    }
}

const LEFT: [u64; 4] = [3, 5, 7, 11];
/// Holds each value of [`Left`] to the value of [`Right`] at its place:
/// a circuit with no gates of its own, over two stages.
struct Tie;

impl MultiStageCircuit<Fp, R> for Tie {
    type Last = Right;
    type Instance<'source> = ();
    type Witness<'source> = ([Fp; 4], [Fp; 4]);
    type Output = ();
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, ()>> {
        Ok(())
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, ([Fp; 4], [Fp; 4])>,
    ) -> Result<WithAux<Bound<'dr, D, ()>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (left, builder) = builder.add_stage::<Left>()?;
        let (right, builder) = builder.add_stage::<Right>()?;
        let dr = builder.finish();
        let left = left.unenforced(dr, witness.as_ref().map(|w| w.0))?;
        let right = right.unenforced(dr, witness.as_ref().map(|w| w.1))?;
        for place in 0..4 {
            dr.enforce_zero(|lc| lc.add(left[place].wire()).sub(right[place].wire()))?;
        }
        Ok(WithAux::new((), D::unit()))
    }
}

impl Pageable<Fp, R> for Tie {
    type Carry = ConstLen<4>;
}

#[test]
fn a_circuit_without_gates_pages_too() -> Result<()> {
    let stages = Stages::of::<Fp, R, Tie>();
    let paged = Pages::cut_within(MultiStage::new(Tie), 2, stages.carry_gates().end + 8)?;
    assert_eq!(paged.num_pages(), 2);
    assert_eq!(paged.report().slots, 0);
    assert_eq!(paged.report().num_gates, stages.own_start());
    check::check(&paged)?;

    // Each page's claim, on both stages and the carry stage, which holds
    // nothing: every page loads both stages, so nothing is carried, and
    // the constraints are the first page's.
    let holds = |right: [u64; 4]| -> Result<[bool; 2]> {
        let mut rng = rand::rng();
        let witness = (LEFT.map(Fp::from), right.map(Fp::from));
        let captured = paged.capture(witness)?;
        let mut loaded = paged.carry_rx(Blind::<Fp>::random(&mut rng), &captured.carry)?;
        loaded.add_assign(&<Left as StageExt<Fp, R>>::rx(
            Blind::<Fp>::random(&mut rng),
            witness.0,
        )?);
        loaded.add_assign(&<Right as StageExt<Fp, R>>::rx(
            Blind::<Fp>::random(&mut rng),
            witness.1,
        )?);
        Ok([
            page_claim_holds(paged.page(0), &captured.pages[0][..], (), &loaded)?,
            page_claim_holds(paged.last(), witness, (), &loaded)?,
        ])
    };
    assert_eq!(holds(LEFT)?, [true, true]);
    assert_eq!(holds([3, 5, 7, 12])?, [false, true]);
    Ok(())
}

#[test]
fn the_masks_are_the_carry_stages() -> Result<()> {
    let stages = Stages::of::<Fp, R, Seeded<90>>();
    let paged = Pages::cut_within(MultiStage::new(Seeded::<90>), 5, 155)?;
    let layout = paged.layout();
    // The carry stage follows the circuit's stage, and every page's own
    // gates follow it.
    assert_eq!(layout.carry, stages.carry_gates());
    assert_eq!(layout.window(), layout.carry.end..155);
    let _: &dyn WiringObject<Fp, R> = &paged.carry_mask()?.into_inner();
    let _: &dyn WiringObject<Fp, R> = &paged.page_mask()?.into_inner();
    Ok(())
}

/// `BLOCKS` blocks of seven gates after the first: a block takes one value
/// and gives one, and holds two between its gates.
struct Blocks<const BLOCKS: usize>;

impl<const BLOCKS: usize> Circuit<Fp> for Blocks<BLOCKS> {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let mut acc = Element::alloc(dr, &mut Standard::new(), witness)?;
        for _ in 0..BLOCKS {
            let mut earlier = acc.clone();
            let mut later = acc.square(dr)?;
            for _ in 0..5 {
                let next = earlier.mul(dr, &later)?;
                earlier = core::mem::replace(&mut later, next);
            }
            acc = earlier.mul(dr, &later)?;
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_cut_falls_between_blocks() -> Result<()> {
    // Seven times as many gates as there are places a cut is looked for
    // at, so one place for every seven gates, in blocks of seven: a cut
    // between two blocks carries the one value that passes from block to
    // block, and a cut within a block the two it holds. Every cut is
    // found between two blocks, though the blocks start a gate past the
    // sevens.
    let circuit = Blocks::<1024>;
    assert_eq!(own_gates(&circuit)?, 7 * GRID + 1);
    let paged = Pages::cut_within(flat(circuit), 20, 647)?;
    check::check(&paged)?;
    let report = paged.report();
    assert!(report.pages.iter().filter(|page| page.gates > 0).count() > 1);
    assert!(
        report.cuts.iter().all(|&carried| carried <= 1),
        "{:?}",
        report.cuts
    );
    Ok(())
}

/// Six squarings, as a routine.
#[derive(Clone)]
struct Squarings;

impl Routine<Fp> for Squarings {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        (0..6).try_fold(input, |acc, _| acc.square(dr))
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        _: &mut D,
        _: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// `CALLS` calls of [`Squarings`], each on the square of the one before:
/// a chain that carries one value wherever it is cut.
struct Called<const CALLS: usize>;

impl<const CALLS: usize> Circuit<Fp> for Called<CALLS> {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let mut acc = Element::alloc(dr, &mut Standard::new(), witness)?;
        for _ in 0..CALLS {
            acc = dr.routine(Squarings, acc)?.square(dr)?;
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_routine_is_not_cut() -> Result<()> {
    // A cut carries as much within a call as between two, and a page has
    // room left past the last call it holds whole: every call's gates are
    // on one page all the same.
    let recording = Recording::of(&flat(Called::<30>))?;
    let routines: Vec<_> = recording.routines().cloned().collect();
    assert_eq!(routines.len(), 30);
    let paged = Pages::cut_within(flat(Called::<30>), 3, 354)?;
    check::check(&paged)?;
    let draft = drafted(&paged).0;
    for routine in routines {
        assert_eq!(routine.len(), 6);
        let pages: Vec<usize> = routine
            .map(|gate| draft.place(gate).expect("a gate of the circuit's own").0)
            .collect();
        assert!(pages.iter().all(|&page| page == pages[0]), "{pages:?}");
    }
    Ok(())
}

/// The check holds the pages to the routines the circuit calls, whatever
/// chose the cuts: a plan that parts a routine's gates is refused though
/// its pages' constraints are the circuit's.
#[test]
fn a_plan_that_splits_a_routine_is_caught() -> Result<()> {
    let paged = Pages::cut_within(flat(Called::<30>), 3, 354)?;
    check::check(&paged)?;
    let recording = Recording::of(&flat(Called::<30>))?;
    let routine = recording.routines().next().cloned().expect("a routine");
    // The routine's last gate and the gate the page allocates before the
    // routine's first, which is not the routine's, at each other's place.
    let draft = drafted(&paged).0;
    let (page, last) = draft.place(routine.end - 1).expect("a gate");
    let (_, before) = draft.place(routine.start).expect("a gate");
    let first = draft.layout.carry.end;
    let (last, before) = (last - first, before - first - 1);
    let other = draft.held[page][before] as usize;
    assert!(!routine.contains(&other));
    let wrong = tampered(&paged, |plan| {
        let own_start = plan.layout.own_start;
        plan.held[page].swap(last, before);
        plan.places
            .swap(routine.end - 1 - own_start, other - own_start);
    });
    assert!(refused(&wrong, "split a routine the circuit calls"));
    Ok(())
}

/// A routine that calls another: a square of its own, [`Squarings`] on it,
/// and a product of what that gives. Its second output is what
/// [`Squarings`] gave plus its own input and one, so it passes an input
/// through and holds a constant.
#[derive(Clone)]
struct Wrapping;

impl Routine<Fp> for Wrapping {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = [PhantomData<Kind![Fp; Element<'_, _>]>; 2];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let square = input.square(dr)?;
        let inner = dr.routine(Squarings, square)?;
        let product = inner.mul(dr, &input)?;
        let passed = inner.add(dr, &input).add(dr, &Element::one());
        Ok([product, passed])
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        _: &mut D,
        _: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// `CALLS` calls of [`Wrapping`], each on the product of what the one
/// before gave.
struct Wrapped<const CALLS: usize>;

impl<const CALLS: usize> Circuit<Fp> for Wrapped<CALLS> {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let mut acc = Element::alloc(dr, &mut Standard::new(), witness)?;
        for _ in 0..CALLS {
            let [product, passed] = dr.routine(Wrapping, acc)?;
            acc = product.mul(dr, &passed)?;
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_recording_keeps_the_calls() -> Result<()> {
    let recording = Recording::of(&flat(Wrapped::<5>))?;
    assert_eq!(recording.invocations.len(), 5);
    assert_eq!(recording.routines().count(), 5);
    // Every name the walk gives is a virtual wire that holds one wire.
    let renamed = |names: &Range<usize>| {
        names
            .clone()
            .all(|name| matches!(recording.virtuals[name][..], [(_, coeff)] if coeff == Fp::ONE))
    };
    let mut names = 0;
    for (call, routine) in recording.invocations.iter().zip(recording.routines()) {
        assert_eq!(&call.gates, routine);
        // Its own square and product, and the six squarings within.
        assert_eq!(call.gates.len(), 8);
        assert_eq!((call.inputs.len(), call.outputs.len()), (1, 2));
        assert_eq!(call.inputs.end, call.internal.start);
        assert_eq!(call.internal.end, call.outputs.start);
        assert!(renamed(&call.inputs) && renamed(&call.outputs));

        let [inner] = &call.invocations[..] else {
            panic!("one call within");
        };
        assert_eq!(inner.gates, call.gates.start + 1..call.gates.end - 1);
        assert_eq!((inner.inputs.len(), inner.outputs.len()), (1, 1));
        assert!(inner.invocations.is_empty());
        assert!(renamed(&inner.inputs) && renamed(&inner.outputs));
        // What is within the inner call is within the outer one.
        let within = |inner: &Range<usize>, outer: &Range<usize>| {
            outer.start <= inner.start && inner.end <= outer.end
        };
        assert!(within(&inner.constraints, &call.constraints));
        assert!(within(
            &(inner.inputs.start..inner.outputs.end),
            &call.internal
        ));

        // What the call emits names its own gates, its own names and
        // `ONE`, and nothing else of the circuit.
        let own = |wire: u32| {
            if wire & VIRTUAL != 0 {
                (call.inputs.start..call.outputs.start).contains(&((wire ^ VIRTUAL) as usize))
            } else {
                wire == ONE || call.gates.contains(&((wire / 4) as usize))
            }
        };
        for (_, terms) in &recording.raw[call.constraints.clone()] {
            assert!(terms.iter().all(|&(wire, _)| own(wire)), "{terms:?}");
        }
        for terms in &recording.virtuals[call.internal.clone()] {
            assert!(terms.iter().all(|&(wire, _)| own(wire)), "{terms:?}");
        }
        names += call.inputs.len() + call.outputs.len();
        names += inner.inputs.len() + inner.outputs.len();
    }
    // The names are not virtual wires the circuit made.
    assert_eq!(recording.adds + names, recording.virtuals.len());
    // Followed back to the gates' wires, the recording is what it was: the
    // pages of the circuit are still the circuit's.
    let paged = fitted(flat(Wrapped::<5>), 20)?;
    assert!(paged.num_pages() > 1);
    check::check(&paged)?;
    Ok(())
}

/// The compiled plan of `paged`, tampered with as it is: what a page runs.
fn compiled<S: Pageable<Fp, R>>(
    paged: &Pages<Fp, R, S>,
    tamper: impl FnOnce(&mut Plan<Fp>),
) -> Pages<Fp, R, S> {
    misplaced(paged, tamper)
}

#[test]
fn a_program_that_names_a_wire_it_does_not_hold_is_refused() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    let one = Coeff::Arbitrary(Fp::ONE);
    let refusal = "names a wire it does not hold";

    // A virtual wire the page never makes.
    let wrong = compiled(&paged, |plan| {
        plan.programs[0]
            .constraint(0)
            .push((VIRTUAL | 0x00ff_ffff, one));
    });
    assert!(refused(&wrong, refusal));

    // A virtual wire made after the one that names it.
    let wrong = compiled(&paged, |plan| {
        let made = plan.programs[1].virtuals;
        plan.programs[1]
            .first_add()
            .push((VIRTUAL | (made - 1), one));
    });
    assert!(refused(&wrong, refusal));

    // A gate past the page's own.
    let first = paged.layout().carry.end;
    let wrong = compiled(&paged, |plan| {
        let past = (first + plan.programs[0].gates()) as u32;
        plan.programs[0].constraint(0).push((4 * past, one));
    });
    assert!(refused(&wrong, refusal));

    // A wire of the SYSTEM gate other than `ONE`.
    let wrong = compiled(&paged, |plan| {
        plan.programs[0].constraint(0).push((0, one));
    });
    assert!(refused(&wrong, refusal));
    Ok(())
}

#[test]
fn a_dropped_constraint_is_caught() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    let page = paged.num_pages() / 2;
    let constraints = paged.plan.programs[page].constraints();
    assert!(constraints > 2, "a page in the middle enforces constraints");

    // Without any one of its constraints the page is refused: for the
    // constraints of the circuit, as a missing one of the circuit's, and
    // for a slot's definition, as a slot without one.
    let mut missing = 0;
    for dropped in 0..constraints {
        let wrong = compiled(&paged, |plan| {
            plan.programs[page].drop_constraint(dropped);
        });
        assert!(check::check(&wrong).is_err(), "constraint {dropped}");
        missing += usize::from(refused(&wrong, "constraints are not the circuit's"));
    }
    assert!(missing > 0, "a constraint of the circuit's was dropped");

    // The same with another of the page's constraints in its place, or an
    // empty one, which keeps the count.
    for dropped in 0..constraints {
        let other = (dropped + 1) % constraints;
        let wrong = compiled(&paged, |plan| {
            let filler = plan.programs[page].constraint(other).clone();
            *plan.programs[page].constraint(dropped) = filler;
        });
        assert!(check::check(&wrong).is_err(), "constraint {dropped}");
        let wrong = compiled(&paged, |plan| {
            plan.programs[page].constraint(dropped).clear();
        });
        assert!(check::check(&wrong).is_err(), "constraint {dropped}");
    }
    Ok(())
}

#[test]
fn a_slot_no_page_writes_cannot_be_read() -> Result<()> {
    // A carry stage of three values takes two gates: the last wire of the
    // second is padding, and the chain writes one slot of the three.
    let paged = fitted(MultiStage::new(Flat::<_, 3>(Chain::<40, 50>)), 24)?;
    check::check(&paged)?;
    let carry = paged.layout().carry.clone();
    assert_eq!((carry.len(), paged.plan.slots.len()), (2, 1));
    let last = paged.num_pages() - 1;
    let one = Coeff::Arbitrary(Fp::ONE);

    // The second and third slots, which no page writes, and the padding
    // wire: a constraint that reads one is none of the circuit's.
    for wire in [
        4 * carry.start as u32 + 3,
        4 * (carry.start as u32 + 1),
        4 * (carry.start as u32 + 1) + 3,
    ] {
        for page in [0, last] {
            let wrong = compiled(&paged, |plan| {
                plan.programs[page].constraint(0).push((wire, one));
            });
            assert!(
                refused(&wrong, "constraints are not the circuit's"),
                "wire {wire} on page {page}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_slot_is_written_by_the_page_that_holds_its_wires() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    let carry = paged.layout().carry.clone();
    let slot = |wire: u32| wire & VIRTUAL == 0 && carry.contains(&((wire / 4) as usize));
    // The first page reads no slot, so a constraint of its own that names
    // one writes it. One over gates' wires alone is as well formed on the
    // next page, which holds no fewer gates.
    let mut first = paged.plan.programs[0].clone();
    let definition = (0..first.constraints())
        .position(|index| {
            let terms = first.constraint(index);
            terms.iter().any(|&(wire, _)| slot(wire))
                && terms.iter().all(|&(wire, _)| wire & VIRTUAL == 0)
        })
        .expect("the first page writes a slot over its gates' wires");
    assert!(paged.plan.programs[0].gates() <= paged.plan.programs[1].gates());

    // The same constraint on the next page is over that page's gates: the
    // slot is left without the page that holds its wires.
    let wrong = compiled(&paged, |plan| {
        let moved = plan.programs[0].drop_constraint(definition);
        plan.programs[1].enforce_zero(moved);
    });
    assert!(refused(
        &wrong,
        "a carry slot lacks its defining constraint"
    ));
    Ok(())
}

#[test]
fn pages_planned_for_another_circuit_are_refused() -> Result<()> {
    let paged = fitted(flat(Chain::<100, 3>), 8)?;
    check::check(&paged)?;
    // The same plan over a circuit it was not cut from.
    let other = Pages::planned(flat(Chain::<100, 5>), &paged.plan());
    assert!(other.check().is_err());
    Ok(())
}

#[test]
fn a_carry_stage_takes_no_more_values_than_it_holds() -> Result<()> {
    let paged = fitted(MultiStage::new(Flat::<_, 3>(Chain::<40, 50>)), 24)?;
    let mut rng = rand::rng();
    assert!(
        paged
            .carry_rx(Blind::<Fp>::random(&mut rng), &[Fp::ONE; 3])
            .is_ok()
    );
    assert!(
        paged
            .carry_rx(Blind::<Fp>::random(&mut rng), &[Fp::ONE; 4])
            .is_err()
    );
    Ok(())
}

/// Returns a value of [`Left`] and does nothing else with the stage.
struct Returned;

impl Pageable<Fp, R> for Returned {
    type Carry = ConstLen<2>;
}

impl MultiStageCircuit<Fp, R> for Returned {
    type Last = Left;
    type Instance<'source> = Fp;
    type Witness<'source> = [Fp; 4];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, [Fp; 4]>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (left, builder) = builder.add_stage::<Left>()?;
        let dr = builder.finish();
        let left = left.unenforced(dr, witness)?;
        Ok(WithAux::new(left[2].clone(), D::unit()))
    }
}

/// A stage's wire that a circuit only returns is read of the stage: the
/// public output binds it, though no constraint of the body names it.
#[test]
fn a_returned_stage_wire_is_read() -> Result<()> {
    let stages = Stages::of::<Fp, R, Returned>();
    let read = reads(&MultiStage::<Fp, R, _>::new(Returned), &stages, 1)?;
    assert_eq!(read, [[1]]);
    // A circuit that names the stage's wires in its body reads them there.
    let stages = Stages::of::<Fp, R, Tie>();
    let read = reads(&MultiStage::<Fp, R, _>::new(Tie), &stages, 1)?;
    assert_eq!(read, [[4, 4]]);
    Ok(())
}

/// Consecutive gates linked by their a-wires, with extra reads and an
/// optional public output from a d-wire.
#[derive(Clone, Copy)]
struct Linked {
    gates: usize,
    extra: &'static [(usize, usize)],
    output: Option<usize>,
}

impl Circuit<Fp> for Linked {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(Element::zero(dr))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let mut wires = Vec::new();
        let mut output = Element::zero(dr);
        for i in 0..self.gates {
            let (a, _, _, extra) = dr.gate(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
            let d = dr.assign_extra(extra, || Ok(Coeff::Zero))?;
            if self.output == Some(i) {
                output = Element::promote(d, D::just(|| Fp::ZERO));
            }
            wires.push(a);
        }
        for (i, j) in (0..self.gates - 1)
            .map(|i| (i, i + 1))
            .chain(self.extra.iter().copied())
        {
            dr.enforce_zero(|lc| lc.add(&wires[i]).sub(&wires[j]))?;
        }
        Ok(WithAux::new(output, D::unit()))
    }
}

/// Nine gates: the fifth takes the sum of the first four's $a$ wires, and
/// the sixth and the seventh each take another wire of the fifth.
struct Summed;

impl Circuit<Fp> for Summed {
    type Instance<'source> = ();
    type Witness<'source> = ();
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(Element::zero(dr))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let mut gates = Vec::new();
        for _ in 0..9 {
            let (a, b, c, extra) = dr.gate(|| Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero)))?;
            dr.assign_extra(extra, || Ok(Coeff::Zero))?;
            gates.push((a, b, c));
        }
        dr.enforce_zero(|lc| {
            gates[..4]
                .iter()
                .fold(lc, |lc, (a, _, _)| lc.add(a))
                .sub(&gates[4].0)
        })?;
        dr.enforce_zero(|lc| lc.add(&gates[4].1).sub(&gates[5].0))?;
        dr.enforce_zero(|lc| lc.add(&gates[4].2).sub(&gates[6].0))?;
        Ok(WithAux::new(Element::zero(dr), D::unit()))
    }
}

/// A slot holds a linear combination, so a cut is weighed by the
/// combinations the constraints past it name of the gates before it, not by
/// the wires: a sum of four wires that one constraint takes is one value to
/// carry, and two wires that two constraints take are two.
#[test]
fn a_cut_is_weighed_by_the_combinations_it_carries() -> Result<()> {
    // The carry stage holds one value, in one gate, and a page has room
    // for five gates of the nine: the cut falls after the fourth, which
    // carries the sum, or after the fifth, which carries its two wires.
    let paged = Pages::cut_within(MultiStage::new(Flat::<_, 1>(Summed)), 2, 7)?.check()?;
    assert_eq!(paged.pages().layout().starts, [1, 5]);
    assert_eq!(paged.pages().report().slots, 1);
    assert_eq!(paged.pages().report().carried_wires, 4);
    Ok(())
}

/// The check tells a circuit that ends its public output with a constant
/// zero from one that ends it with a wire, which the output's type does
/// not: both of these return one element.
#[test]
fn the_check_tells_an_output_that_ends_in_a_zero() -> Result<()> {
    let ends_in_zero = |output| -> Result<bool> {
        let circuit = Linked {
            gates: 6,
            extra: &[],
            output,
        };
        let checked = Pages::cut_within(MultiStage::new(Flat::<_, 4>(circuit)), 3, 5)?.check()?;
        Ok(checked.ends_in_zero())
    };
    assert!(ends_in_zero(None)?);
    // A wire of the last page, and one an earlier page carries to it.
    assert!(!ends_in_zero(Some(5))?);
    assert!(!ends_in_zero(Some(0))?);
    // Two wires, neither a zero.
    let two = Pages::cut_within(flat(TwoOutputs), 1, 1 << 12)?.check()?;
    assert!(!two.ends_in_zero());
    Ok(())
}

/// The public output is the last page's, so a cut that leaves the output's
/// gate on an earlier page carries it. The cost of a cut counts that, and
/// the cut keeps the gate on the last page, as a cut there carries less,
/// however much the carry stage holds.
#[test]
fn a_cut_counts_the_outputs_export() -> Result<()> {
    let room = GRID + 2;
    let circuit = Linked {
        gates: 2 * GRID,
        extra: &[],
        output: Some(room - 1),
    };
    // Both carry stages take one gate. Every cut carries the link across
    // it, and a cut past the output's gate carries the output too.
    let limit = 2 + room;
    let roomy = Pages::cut_within(MultiStage::new(Flat::<_, 2>(circuit)), 2, limit)?.check()?;
    assert_eq!(roomy.pages().report().slots, 1);
    assert_eq!(roomy.pages().layout().starts, [1, room]);
    let tight = Pages::cut_within(MultiStage::new(Flat::<_, 1>(circuit)), 2, limit)?.check()?;
    assert_eq!(tight.pages().report().slots, 1);
    assert_eq!(tight.pages().layout().starts, [1, room]);
    Ok(())
}

/// Each routine segment of `circuit`: its gates, its constraints and its
/// fingerprint, in order.
fn routine_segments<C: Circuit<Fp>>(
    circuit: &C,
) -> Result<Vec<(usize, usize, crate::metrics::DeepFingerprint)>> {
    Ok(crate::metrics::eval(circuit)?
        .segments
        .iter()
        .filter_map(|segment| match segment.identity() {
            crate::metrics::RoutineIdentity::Routine(fingerprint) => {
                Some((segment.num_gates(), segment.num_constraints(), *fingerprint))
            }
            crate::metrics::RoutineIdentity::Root => None,
        })
        .collect())
}

/// Holds `paged` to its circuit, which holds its pages' routines to the
/// circuit's, and each page's claim, with what one walk of the circuit
/// `captured` for its pages and `stages`, the polynomials of the
/// circuit's stages. `last` tells whether the last page's claim holds on
/// what it is given to load.
fn pages_hold<S: Pageable<Fp, R>>(
    paged: &Pages<Fp, R, S>,
    captured: &Captured<Fp>,
    last: impl Fn(&sparse::Polynomial<Fp, R>) -> Result<bool>,
    stages: Option<&sparse::Polynomial<Fp, R>>,
) -> Result<()> {
    check::check(paged)?;
    let pages = paged.num_pages();

    let mut loaded = paged.carry_rx(Blind::<Fp>::random(&mut rand::rng()), &captured.carry)?;
    if let Some(stages) = stages {
        loaded.add_assign(stages);
    }
    for page in 0..pages - 1 {
        assert!(
            page_claim_holds(paged.page(page), &captured.pages[page][..], (), &loaded)?,
            "page {page}"
        );
    }
    assert!(last(&loaded)?);
    Ok(())
}

#[test]
fn a_page_calls_the_routines_it_holds() -> Result<()> {
    let witness = Fp::from(3u64);
    let squared = |times: usize, value: Fp| (0..times).fold(value, |acc, _| acc.square());
    for page_gates in [8, 20, 31, 1 << 20] {
        // A routine after another, each on what the one before gave.
        let paged = fitted(flat(Called::<12>), page_gates)?;
        assert_eq!(routine_segments(&*paged.circuit)?.len(), 12);
        let instance = (0..12).fold(witness, |acc, _| squared(7, acc));
        pages_hold(
            &paged,
            &paged.capture(witness)?,
            |loaded| page_claim_holds(paged.last(), witness, instance, loaded),
            None,
        )?;

        // A routine that calls another, passes an input through to its
        // output and adds a constant to it.
        let paged = fitted(flat(Wrapped::<6>), page_gates)?;
        assert_eq!(routine_segments(&*paged.circuit)?.len(), 12);
        let instance = (0..6).fold(witness, |acc, _| {
            let inner = squared(7, acc);
            (inner * acc) * (inner + acc + Fp::ONE)
        });
        pages_hold(
            &paged,
            &paged.capture(witness)?,
            |loaded| page_claim_holds(paged.last(), witness, instance, loaded),
            None,
        )?;
    }
    Ok(())
}

/// A routine without gates: it holds the third wire it takes to the sum
/// of the first two, and gives that sum, which is of its inputs alone.
#[derive(Clone)]
struct Balance;

impl Routine<Fp> for Balance {
    type Input = [PhantomData<Kind![Fp; Element<'_, _>]>; 3];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let [a, b, sum] = input;
        let both = a.add(dr, &b);
        both.sub(dr, &sum).enforce_zero(dr)?;
        Ok(both)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp, Wire = ()>>(
        &self,
        _: &mut D,
        _: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// The square of the witness, `LEN` squarings of it, and [`Balance`] on
/// the first square, the last and a gate that holds their sum: a routine
/// whose inputs are the two ends of the circuit. The circuit then
/// multiplies what the routine gives.
struct Far<const LEN: usize>;

impl<const LEN: usize> Far<LEN> {
    fn run(witness: Fp) -> Fp {
        let first = witness.square();
        let last = (0..LEN).fold(first, |acc, _| acc.square());
        (first + last) * last
    }
}

impl<const LEN: usize> Circuit<Fp> for Far<LEN> {
    type Instance<'source> = Fp;
    type Witness<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let allocator = &mut Standard::new();
        let first = Element::alloc(dr, allocator, witness)?.square(dr)?;
        let mut last = first.clone();
        for _ in 0..LEN {
            last = last.square(dr)?;
        }
        let sum = D::just(|| *first.value().take() + *last.value().take());
        let sum = Element::alloc(dr, allocator, sum)?;
        let both = dr.routine(Balance, [first, last.clone(), sum])?;
        Ok(WithAux::new(both.mul(dr, &last)?, D::unit()))
    }
}

#[test]
fn a_routine_takes_another_pages_wires_through_the_carry_stage() -> Result<()> {
    let witness = Fp::from(3u64);
    for page_gates in [8, 13, 21] {
        let paged = fitted(flat(Far::<40>), page_gates)?;
        assert!(paged.num_pages() > 2);
        // The routine has no gate: the page the walk is on calls it, and
        // reads the first square, which the first page holds, off a slot.
        let [(gates, constraints, _)] = routine_segments(&*paged.circuit)?[..] else {
            panic!("one routine");
        };
        assert_eq!((gates, constraints), (0, 1));
        assert!(paged.report().slots > 0);
        pages_hold(
            &paged,
            &paged.capture(witness)?,
            |loaded| page_claim_holds(paged.last(), witness, Far::<40>::run(witness), loaded),
            None,
        )?;
    }
    Ok(())
}

/// `CALLS` calls of [`Wrapping`], each on a value of the stage: a routine
/// whose input is a stage's wire, which it also passes through.
struct SeededCalls<const CALLS: usize>;

impl<const CALLS: usize> SeededCalls<CALLS> {
    fn run(seeds: [Fp; 4]) -> Fp {
        (0..CALLS).fold(seeds[0], |acc, call| {
            let seed = seeds[call % 4];
            let inner = (0..7).fold(seed, |acc, _| acc.square());
            acc * (inner * seed) + (inner + seed + Fp::ONE)
        })
    }
}

impl<const CALLS: usize> Pageable<Fp, R> for SeededCalls<CALLS> {
    type Carry = ConstLen<256>;
}

impl<const CALLS: usize> MultiStageCircuit<Fp, R> for SeededCalls<CALLS> {
    type Last = Seeds;
    type Instance<'source> = Fp;
    type Witness<'source> = [Fp; 4];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, [Fp; 4]>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (seeds, builder) = builder.add_stage::<Seeds>()?;
        let dr = builder.finish();
        let seeds = seeds.unenforced(dr, witness)?;
        let mut acc = seeds[0].clone();
        for call in 0..CALLS {
            let [product, passed] = dr.routine(Wrapping, seeds[call % 4].clone())?;
            acc = acc.mul(dr, &product)?.add(dr, &passed);
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

#[test]
fn a_routine_takes_a_stages_wires() -> Result<()> {
    let seeds = [3u64, 5, 7, 11].map(Fp::from);
    let stage = <Seeds as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rand::rng()), seeds)?;
    for page_gates in [9, 20, 40] {
        let paged = fitted(MultiStage::new(SeededCalls::<9>), page_gates)?;
        assert!(paged.num_pages() > 1);
        pages_hold(
            &paged,
            &paged.capture(seeds)?,
            |loaded| page_claim_holds(paged.last(), seeds, SeededCalls::<9>::run(seeds), loaded),
            Some(&stage),
        )?;
    }
    Ok(())
}

/// The first routine the first page of `plan` calls.
fn first_routine(plan: &mut Plan<Fp>) -> &mut Arc<Body<Fp>> {
    plan.programs[0]
        .steps
        .iter_mut()
        .find_map(|step| match step {
            Step::Routine(body, _) => Some(body),
            _ => None,
        })
        .expect("the first page calls a routine")
}

/// The check holds the pages to the routines the circuit calls, and not
/// only to its constraints: a page that calls a routine with two of its
/// constraints in each other's place enforces what the circuit does, and
/// is refused.
#[test]
fn a_page_that_calls_another_routine_is_caught() -> Result<()> {
    let paged = fitted(flat(Called::<5>), 20)?;
    check::check(&paged)?;
    let wrong = compiled(&paged, |plan| {
        let call = first_routine(plan);
        *call = Arc::new(call.changed(|steps| {
            let enforced: Vec<usize> = (0..steps.len())
                .filter(|&step| matches!(steps[step], Step::EnforceZero(_)))
                .collect();
            steps.swap(enforced[0], enforced[1]);
        }));
    });
    assert!(refused(&wrong, "a routine more times than"));
    Ok(())
}

/// The check of the relation reaches into the routines a page calls: a
/// routine that does not enforce one of its constraints is refused for the
/// constraint, before the routines are compared.
#[test]
fn a_constraint_dropped_within_a_routine_is_caught() -> Result<()> {
    let paged = fitted(flat(Called::<5>), 20)?;
    check::check(&paged)?;
    let wrong = compiled(&paged, |plan| {
        let call = first_routine(plan);
        *call = Arc::new(call.changed(|steps| {
            let enforced = steps
                .iter()
                .position(|step| matches!(step, Step::EnforceZero(_)))
                .expect("the routine enforces a constraint");
            steps.remove(enforced);
        }));
    });
    assert!(refused(&wrong, "constraints are not the circuit's"));
    Ok(())
}
