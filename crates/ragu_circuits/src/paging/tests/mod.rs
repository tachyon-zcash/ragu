use alloc::{string::ToString, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use ragu_core::{
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

use super::{plan::*, record::*, *};
use crate::{
    Blind, Circuit, CircuitExt, WiringObject, WithAux, floor_planner, into_wiring_object,
    polynomials::{TestRank, sparse},
    staging::{self, MultiStage, StageBuilder, StageExt},
    wiring::monomials::{Monomial, Monomials},
};

type R = TestRank;

/// The gates a polynomial of the test rank holds before its blind gate.
fn limit() -> usize {
    R::blind_gate()
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
    let paged = Paged::fitted(Chain::<40, 5>, &Stages::whole(1), 1 << 20)?;
    let report = paged.report();
    assert_eq!(report.pages.len(), 1);
    assert_eq!(report.carried_wires, 0);
    assert_eq!(report.slots, 0);
    assert_eq!(report.cross_constraints, 0);
    assert!(report.cuts.is_empty());
    assert_eq!(report.num_gates, 1 + report.pages[0].gates);
    assert!(paged.layout().carry.is_empty());
    Ok(())
}

#[test]
fn a_chain_carries_its_cut_and_its_long_lived_wire() -> Result<()> {
    let whole = Paged::fitted(Chain::<40, 5>, &Stages::whole(1), 1 << 20)?;
    let paged = Paged::fitted(Chain::<40, 5>, &Stages::whole(1), 8)?;
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

/// Pages `Chain<LEN, STRIDE>` at the test rank, before a carry stage of
/// `carry_gates` gates, and tells which pages' claims hold, with the
/// carry stage's values passed through `tamper`.
fn claims<const LEN: usize, const STRIDE: usize>(
    carry_gates: usize,
    tamper: impl Fn(&mut Vec<Fp>),
) -> Result<(Paged<Fp, Chain<LEN, STRIDE>>, Vec<bool>)> {
    let witness = Fp::from(3u64);
    let instance = Chain::<LEN, STRIDE>::run(witness);
    let own = own_gates(&Chain::<LEN, STRIDE>)?;
    let stages = Stages::whole(1).pages(own.div_ceil(limit() - carry_gates - 1));
    let layout = Layout::fill(&stages, own, limit(), carry_gates)?;
    let paged = Paged::new(Chain::<LEN, STRIDE>, &stages, layout)?;
    let pages = paged.num_pages();

    let mut traces = Vec::new();
    for index in 0..pages - 1 {
        traces.push(Some(
            paged
                .page(index)
                .trace(&paged.capture(witness)?[index])?
                .into_output(),
        ));
    }
    traces.push(Some(paged.last().trace(witness)?.into_output()));
    let mut values = paged.carry_values(&traces)?;
    tamper(&mut values);
    let carry = paged.layout().carry.clone();
    let carry = staging::stage_rx::<Fp, R>(
        Blind::<Fp>::random(&mut rand::rng()),
        carry.start,
        2 * carry.len(),
        &values,
    )?;

    let mut holds = Vec::new();
    for index in 0..pages - 1 {
        holds.push(page_claim_holds(
            paged.page(index),
            &paged.capture(witness)?[index][..],
            (),
            &carry,
        )?);
    }
    holds.push(page_claim_holds(paged.last(), witness, instance, &carry)?);
    Ok((paged, holds))
}

#[test]
fn every_page_of_a_paged_circuit_satisfies_its_claim() -> Result<()> {
    let (paged, holds) = claims::<100, 3>(8, |_| {})?;
    assert!(paged.num_pages() >= 4, "the chain takes several pages");
    assert!(paged.report().slots > 0, "the chain carries values");
    assert!(holds.iter().all(|&hold| hold), "{holds:?}");
    paged.check()
}

#[test]
fn the_pages_constraints_are_the_circuits() -> Result<()> {
    // Whatever the cut.
    for page_gates in [1, 2, 3, 5, 8, 13, 28, 1 << 20] {
        Paged::fitted(Chain::<100, 3>, &Stages::whole(1), page_gates)?.check()?;
        Paged::fitted(
            MultiStage::<Fp, R, _>::new(Seeded::<90>),
            &Stages::of::<Fp, R, Seeded<90>>(),
            page_gates,
        )?
        .check()?;
    }
    // In polynomials of the test rank, in as many pages as that takes
    // and in more.
    for pages in 5..9 {
        let cut = Paged::cut(Chain::<100, 3>, &Stages::whole(1).pages(pages), limit())?;
        let (layout, report) = (cut.layout(), cut.report());
        assert_eq!(layout.carry.end, limit());
        assert!(2 * layout.carry.len() >= report.slots);
        for (page, held) in report.pages.iter().enumerate() {
            assert!(held.gates <= layout.room(page));
        }
        cut.check()?;
    }
    Ok(())
}

#[test]
fn pages_without_the_room_are_refused() {
    assert!(matches!(
        Paged::cut(Chain::<100, 3>, &Stages::whole(1).pages(2), limit()),
        Err(Error::GateBoundExceeded { .. })
    ));
}

/// `paged` with its plan passed through `tamper`, and its pages
/// compiled from the plan it leaves.
fn tampered<C: Circuit<Fp>>(
    paged: &Paged<Fp, C>,
    tamper: impl FnOnce(&mut Plan<Fp>),
) -> Paged<Fp, C> {
    let mut plan = (*paged.plan).clone();
    tamper(&mut plan);
    plan.compile(&Recording::of(&*paged.circuit).expect("the circuit walks"));
    Paged {
        circuit: paged.circuit.clone(),
        plan: Arc::new(plan),
        report: paged.report.clone(),
        stages: paged.stages.clone(),
    }
}

#[test]
fn a_plan_that_miscarries_is_caught() -> Result<()> {
    let paged = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 8)?;
    paged.check()?;
    let (&constraint, _) = paged.plan.links.iter().next().expect("the chain carries");

    // A slot read at the wrong scale.
    let wrong = tampered(&paged, |plan| {
        plan.links.get_mut(&constraint).unwrap()[0].scale += Fp::ONE;
    });
    assert!(wrong.check().is_err());

    // A slot the constraint no longer reads: the term is dropped.
    let wrong = tampered(&paged, |plan| {
        plan.links.remove(&constraint);
    });
    assert!(wrong.check().is_err());

    // A slot no page holds to its wires.
    let wrong = tampered(&paged, |plan| {
        for links in plan.links.values_mut() {
            for link in links.iter_mut().filter(|link| link.slot == 0) {
                link.defines = false;
            }
        }
    });
    assert!(wrong.check().is_err());

    // A constraint homed on a page that lacks its wires.
    let wrong = tampered(&paged, |plan| {
        let moved = plan.homes.iter().position(|&home| home == 2).unwrap();
        plan.homes[moved] = 0;
    });
    assert!(wrong.check().is_err());
    Ok(())
}

#[test]
fn a_missing_carry_definition_cannot_hide_behind_a_zero_constraint() -> Result<()> {
    let paged = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 8)?;
    paged.check()?;
    let (&constraint, links) = paged
        .plan
        .links
        .iter()
        .find(|(_, links)| links.iter().any(|link| link.defines))
        .expect("the chain has a defined carry slot");
    let exporter = links.iter().find(|link| link.defines).unwrap().exporter as usize;

    let mut plan = (*paged.plan).clone();
    plan.links
        .get_mut(&constraint)
        .unwrap()
        .iter_mut()
        .find(|link| link.defines)
        .unwrap()
        .defines = false;
    plan.compile(&Recording::of(&*paged.circuit)?);
    // The old value-based check included one zero for each slot definition.
    // A planner could replace a missing definition with 0 = 0 and pass it.
    plan.programs[exporter].constraints.push(Vec::new());
    let wrong = Paged {
        circuit: paged.circuit.clone(),
        plan: Arc::new(plan),
        report: paged.report.clone(),
        stages: paged.stages.clone(),
    };
    assert!(matches!(
        wrong.check(),
        Err(Error::Initialization(message)) if message.to_string().contains("a carry slot lacks its defining constraint")
    ));
    Ok(())
}

#[test]
fn the_public_output_keeps_its_order() -> Result<()> {
    let paged = Paged::fitted(TwoOutputs, &Stages::whole(1), 8)?;
    paged.check()?;
    let mut plan = (*paged.plan).clone();
    assert_eq!(plan.programs.len(), 1);
    assert_eq!(plan.programs[0].outputs.len(), 2);
    plan.programs[0].outputs.swap(0, 1);
    let wrong = Paged {
        circuit: paged.circuit.clone(),
        plan: Arc::new(plan),
        report: paged.report.clone(),
        stages: paged.stages.clone(),
    };
    assert!(matches!(
        wrong.check(),
        Err(Error::Initialization(message)) if message.to_string().contains("public output")
    ));
    Ok(())
}

#[test]
fn a_circuit_of_one_page_is_its_last_page() -> Result<()> {
    let (paged, holds) = claims::<8, 3>(1, |_| {})?;
    assert_eq!(paged.num_pages(), 1);
    assert_eq!(paged.report().slots, 0);
    assert_eq!(holds, [true]);
    Ok(())
}

#[test]
fn a_wrong_carried_value_fails_a_page() -> Result<()> {
    let slots = claims::<100, 3>(8, |_| {})?.0.report().slots;
    for slot in 0..slots {
        let (_, holds) = claims::<100, 3>(8, |values| values[slot] += Fp::ONE)?;
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
    let own = own_gates(&Chain::<100, 3>)?;
    let stages = Stages::whole(1).pages(own.div_ceil(limit() - 2));
    let layout = Layout::fill(&stages, own, limit(), 1)?;
    assert!(matches!(
        Paged::new(Chain::<100, 3>, &stages, layout),
        Err(Error::Initialization(_))
    ));
    Ok(())
}

/// `paged` with its plan passed through `tamper` and left as that leaves
/// it: its pages are not compiled again.
fn misplaced<C: Circuit<Fp>>(
    paged: &Paged<Fp, C>,
    tamper: impl FnOnce(&mut Plan<Fp>),
) -> Paged<Fp, C> {
    let mut plan = (*paged.plan).clone();
    tamper(&mut plan);
    Paged {
        circuit: paged.circuit.clone(),
        plan: Arc::new(plan),
        report: paged.report.clone(),
        stages: paged.stages.clone(),
    }
}

/// Whether the check refuses `paged` for `what`.
fn refused<C: Circuit<Fp>>(paged: &Paged<Fp, C>, what: &str) -> bool {
    matches!(
        paged.check(),
        Err(Error::Initialization(message)) if message.to_string().contains(what)
    )
}

#[test]
fn a_plan_that_misplaces_a_gate_is_caught() -> Result<()> {
    let paged = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 8)?;
    paged.check()?;
    let last = paged.num_pages() - 1;
    assert!(last >= 2, "the chain takes several pages");
    assert!(!paged.layout().carry.is_empty(), "the chain carries values");

    // A gate on two pages, in place of one of the second's.
    let wrong = misplaced(&paged, |plan| plan.held[1][0] = plan.held[0][0]);
    assert!(refused(&wrong, "duplicates or misplaces a gate"));

    // Two gates of a page at each other's place.
    let wrong = misplaced(&paged, |plan| plan.held[0].swap(0, 1));
    assert!(refused(&wrong, "duplicates or misplaces a gate"));

    // A gate that is not the circuit's.
    let wrong = misplaced(&paged, |plan| plan.held[0][0] = plan.num_gates as u32);
    assert!(refused(&wrong, "holds a gate outside the circuit"));

    // A gate no page holds: the last page gives up its last.
    let wrong = misplaced(&paged, |plan| {
        plan.held[last].pop();
        plan.programs[last].own.end -= 1;
    });
    assert!(refused(&wrong, "omit a gate of the circuit"));

    // A page that starts where the page before it has not ended.
    let wrong = misplaced(&paged, |plan| plan.layout.starts[1] += 1);
    assert!(refused(&wrong, "inconsistent gate layout"));

    // A page that allocates other gates than its layout gives it.
    let wrong = misplaced(&paged, |plan| plan.programs[0].gates += 1);
    assert!(refused(&wrong, "allocates other gates than its layout"));
    let wrong = misplaced(&paged, |plan| plan.programs[0].own.start += 1);
    assert!(refused(&wrong, "allocates other gates than its layout"));

    // The carry stage over a page's own gates.
    let wrong = misplaced(&paged, |plan| plan.layout.carry.start -= 1);
    assert!(refused(&wrong, "overlaps the carry stage"));

    // A page's own gates over those of a stage it loads.
    let staged = Paged::fitted(
        MultiStage::<Fp, R, _>::new(Seeded::<90>),
        &Stages::of::<Fp, R, Seeded<90>>(),
        8,
    )?;
    staged.check()?;
    let wrong = misplaced(&staged, |plan| plan.layout.firsts[0] -= 1);
    assert!(refused(&wrong, "inconsistent gate layout"));
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
    let paged = Paged::fitted(Fickle(longer.clone()), &Stages::whole(1), 8)?;
    assert!(paged.num_pages() > 1, "the squarings take several pages");
    paged.check()?;
    let witness = Fp::from(3u64);
    paged.capture(witness)?;

    // The circuit now allocates a gate its plan does not have. Its pages
    // are given no values, and the check no longer passes them.
    longer.store(true, Ordering::Relaxed);
    assert!(matches!(
        paged.capture(witness),
        Err(Error::Initialization(message)) if message.to_string().contains("diverged from its plan")
    ));
    assert!(paged.check().is_err());
    Ok(())
}

#[test]
fn a_plan_out_of_shape_is_caught() -> Result<()> {
    let paged = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 8)?;
    paged.check()?;
    assert!(paged.report().slots > 2, "the chain carries several values");

    // Fewer places than the circuit has gates.
    let wrong = misplaced(&paged, |plan| {
        plan.places.pop();
    });
    assert!(refused(&wrong, "does not cover the circuit"));

    // A carry stage that ends before it starts.
    let wrong = misplaced(&paged, |plan| {
        plan.layout.carry.start = plan.layout.carry.end + 1;
    });
    assert!(refused(&wrong, "inverted gate range"));

    // A page whose gates run past the last index.
    let wrong = misplaced(&paged, |plan| plan.layout.firsts[0] = usize::MAX);
    assert!(refused(&wrong, "gate range overflows"));

    // Stages that take more gates than the circuit has, as if the cut had
    // been asked for them.
    let mut wrong = misplaced(&paged, |plan| plan.stages.spans.push(1..1_000_000));
    wrong.stages = wrong.plan.stages.clone();
    assert!(refused(&wrong, "fewer gates than its stages"));

    // A carry stage of one gate, which holds two of the values.
    let wrong = misplaced(&paged, |plan| {
        plan.layout.carry.start = plan.layout.carry.end - 1;
    });
    assert!(refused(&wrong, "more than the 2 their carry"));

    // A slot another constraint defines, read at another scale: the
    // pages' constraints are no longer the circuit's.
    let (constraint, link) = paged
        .plan
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

/// The wiring polynomial of `circuit`, which calls no routine, written
/// out of its recording: of `count` constraints, the one emitted at
/// `index` is the coefficient of `Y^(count - 1 - index)`, and a gate's
/// wires are the wiring layout's powers of `X`.
fn recorded<C: Circuit<Fp>>(circuit: &C) -> Result<Monomials<Fp>> {
    let n = R::n();
    let (_, constraints) = Recording::<Fp>::all_of(circuit)?;
    let count = constraints.len();
    let mut monomials = Vec::new();
    for (index, terms) in constraints.iter().enumerate() {
        for &(wire, coeff) in terms {
            let gate = (wire / 4) as usize;
            let x = match wire % 4 {
                0 => 2 * n + gate,
                1 => 2 * n - 1 - gate,
                2 => 4 * n - 1 - gate,
                _ => gate,
            };
            monomials.push(Monomial {
                y: count - 1 - index,
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
fn pages_are_recorded<C: Circuit<Fp>>(paged: &Paged<Fp, C>) -> Result<()> {
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

    // And of every page, which is what a registry holds of a paged
    // circuit: a page replays a routine's gates flat, so the pages of a
    // circuit that calls routines are among them.
    pages_are_recorded(&Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 8)?)?;
    pages_are_recorded(&Paged::fitted(TwoOutputs, &Stages::whole(1), 1)?)?;
    pages_are_recorded(&Paged::fitted(
        MultiStage::<Fp, R, _>::new(Seeded::<90>),
        &Stages::of::<Fp, R, Seeded<90>>(),
        8,
    )?)?;
    pages_are_recorded(&Paged::fitted(Called::<5>, &Stages::whole(1), 8)?)
}

#[test]
fn a_digest_tells_two_cuts_apart() -> Result<()> {
    let digest = |page_gates: usize| -> Result<[u8; 32]> {
        Paged::fitted(Chain::<100, 3>, &Stages::whole(1), page_gates)?.digest::<R>()
    };
    // The same cut gives the same digest, and a cut a gate later another.
    assert_eq!(digest(8)?, digest(8)?);
    assert_ne!(digest(8)?, digest(9)?);

    // Where the search places the cuts, and in more pages.
    let placed = |pages: usize| -> Result<[u8; 32]> {
        Paged::cut(Chain::<100, 3>, &Stages::whole(1).pages(pages), limit())?.digest::<R>()
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
fn a_staged_circuit_pages_beside_its_stage() -> Result<()> {
    let seeds = [3u64, 5, 7, 11].map(Fp::from);
    let instance = Seeded::<90>::run(seeds);
    let stages = Stages::of::<Fp, R, Seeded<90>>();
    assert_eq!(
        stages.own_start(),
        3,
        "the SYSTEM gate and the stage's two gates"
    );
    let paged = Paged::cut(
        MultiStage::<Fp, R, _>::new(Seeded::<90>),
        &stages.pages(5),
        limit(),
    )?;
    let pages = paged.num_pages();
    // The stage's wires are every page's: none is carried, and every
    // page names them.
    assert!(paged.report().pages.iter().all(|page| page.stage_wires > 0));
    assert!(paged.report().slots <= 2 * (pages - 1));
    assert!(paged.layout().firsts.iter().all(|&first| first == 3));

    let mut traces = Vec::new();
    for index in 0..pages - 1 {
        traces.push(Some(
            paged
                .page(index)
                .trace(&paged.capture(seeds)?[index])?
                .into_output(),
        ));
    }
    traces.push(Some(paged.last().trace(seeds)?.into_output()));
    let mut rng = rand::rng();
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces)?;
    let stage = <Seeds as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), seeds)?;
    let mut loaded = carry.clone();
    loaded.add_assign(&stage);

    for index in 0..pages - 1 {
        assert!(page_claim_holds(
            paged.page(index),
            &paged.capture(seeds)?[index][..],
            (),
            &loaded
        )?);
        // A page reads the stage: without it, its claim fails.
        assert!(!page_claim_holds(
            paged.page(index),
            &paged.capture(seeds)?[index][..],
            (),
            &carry
        )?);
    }
    assert!(page_claim_holds(paged.last(), seeds, instance, &loaded)?);
    assert!(!page_claim_holds(paged.last(), seeds, instance, &carry)?);
    Ok(())
}

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
    let paged = Paged::cut(Batch::<40>, &Stages::whole(1).pages(4), limit())?;
    assert!(paged.report().slots <= 3 * 3, "{:?}", paged.report().cuts);
    paged.check()?;

    let mut traces = Vec::new();
    for index in 0..3 {
        traces.push(Some(
            paged
                .page(index)
                .trace(&paged.capture(witness)?[index])?
                .into_output(),
        ));
    }
    traces.push(Some(paged.last().trace(witness)?.into_output()));
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rand::rng()), &traces)?;
    for index in 0..3 {
        assert!(page_claim_holds(
            paged.page(index),
            &paged.capture(witness)?[index][..],
            (),
            &carry
        )?);
    }
    let instance = Batch::<40>::run(witness);
    assert!(page_claim_holds(paged.last(), witness, instance, &carry)?);
    Ok(())
}

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

#[test]
fn a_circuit_without_gates_pages_too() -> Result<()> {
    let stages = Stages::of::<Fp, R, Tie>().pages(2);
    let paged = Paged::cut(MultiStage::<Fp, R, _>::new(Tie), &stages, limit())?;
    assert_eq!(paged.num_pages(), 2);
    assert_eq!(paged.report().slots, 0);
    assert_eq!(paged.report().num_gates, stages.own_start());
    paged.check()?;

    // Each page's claim, on both stages and the carry stage, which holds
    // nothing: every page loads both stages, so nothing is carried, and
    // the constraints are the first page's.
    let holds = |right: [u64; 4]| -> Result<[bool; 2]> {
        let mut rng = rand::rng();
        let witness = (LEFT.map(Fp::from), right.map(Fp::from));
        let mut loaded = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &[])?;
        loaded.add_assign(&<Left as StageExt<Fp, R>>::rx(
            Blind::<Fp>::random(&mut rng),
            witness.0,
        )?);
        loaded.add_assign(&<Right as StageExt<Fp, R>>::rx(
            Blind::<Fp>::random(&mut rng),
            witness.1,
        )?);
        Ok([
            page_claim_holds(paged.page(0), &paged.capture(witness)?[0][..], (), &loaded)?,
            page_claim_holds(paged.last(), witness, (), &loaded)?,
        ])
    };
    assert_eq!(holds(LEFT)?, [true, true]);
    assert_eq!(holds([3, 5, 7, 12])?, [false, true]);
    Ok(())
}

/// A plan is held to the stages its circuit was cut over: one that lays
/// the stages the other way round names the same wires in its
/// constraints, but a page would read each stage's at the gates of the
/// other's polynomial.
#[test]
fn a_plan_over_other_stages_is_refused() -> Result<()> {
    let stages = Stages::of::<Fp, R, Tie>().pages(2);
    let paged = Paged::cut(MultiStage::<Fp, R, _>::new(Tie), &stages, limit())?;
    paged.check()?;
    let spans = &paged.plan.stages.spans;
    assert_eq!(spans[0].len(), spans[1].len(), "the stages are as large");
    let wrong = tampered(&paged, |plan| plan.stages.spans.swap(0, 1));
    assert!(refused(
        &wrong,
        "other stages than the circuit was cut over"
    ));
    Ok(())
}

/// Pages that each load every stage, as the aggregator's do, share one
/// window: past every stage, up to the carry stage. One mask over it holds
/// them all, the last page's included.
#[test]
fn pages_that_load_every_stage_share_a_window() -> Result<()> {
    let paged = Paged::fitted(
        MultiStage::<Fp, R, _>::new(Seeded::<90>),
        &Stages::of::<Fp, R, Seeded<90>>(),
        8,
    )?;
    paged.check()?;
    let layout = paged.layout();
    let stages = paged.stages();
    assert!(paged.num_pages() > 2, "the circuit takes pages");
    let window = layout.window(0);
    let stages_end = stages.spans.iter().map(|span| span.end).max().unwrap_or(1);
    assert!(window.start >= stages_end, "the window is past every stage");
    assert_eq!(
        window.end, layout.carry.start,
        "the window ends at the carry stage"
    );
    let _: &dyn WiringObject<Fp, R> = &paged.carry_mask::<R>()?.into_inner();
    for page in 0..paged.num_pages() {
        assert_eq!(layout.window(page), window, "page {page} shares the window");
        let _: &dyn WiringObject<Fp, R> = &paged.own_mask::<R>(page)?.into_inner();
    }
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
    let paged = Paged::cut(circuit, &Stages::whole(1).pages(20), 400)?;
    paged.check()?;
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
    let routines = Recording::of(&Called::<30>)?.routines;
    assert_eq!(routines.len(), 30);
    let paged = Paged::cut(Called::<30>, &Stages::whole(1).pages(3), 100)?;
    paged.check()?;
    for routine in routines {
        assert_eq!(routine.len(), 6);
        let pages: Vec<usize> = routine
            .map(|gate| {
                paged
                    .plan
                    .place(gate)
                    .expect("a gate of the circuit's own")
                    .0
            })
            .collect();
        assert!(pages.iter().all(|&page| page == pages[0]), "{pages:?}");
    }
    Ok(())
}
