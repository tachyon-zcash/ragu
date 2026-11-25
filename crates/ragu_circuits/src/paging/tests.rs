use alloc::vec::Vec;

use ragu_core::{
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::Fp,
};
use ragu_primitives::{
    Element,
    allocator::Standard,
    vec::{ConstLen, FixedVec},
};
use rand::Rng;

use super::{plan::*, *};
use crate::{
    Blind, Circuit, CircuitExt, WiringObject, WithAux, floor_planner, into_wiring_object,
    polynomials::{TestRank, sparse},
    staging::{self, MultiStage, StageBuilder, StageExt},
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
    let mut values = paged.carry_values::<R>(&traces, &[])?;
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
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &[])?;
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

/// Four more values, which a circuit reserves after [`Left`]'s but
/// whose polynomial holds them at the same gates: a branch beside it.
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

    fn skip_gates() -> usize {
        1
    }
}

/// `LEN` squarings, each followed by adding a value of [`Left`] in the
/// first half and of [`Right`] in the second, and every seventh by one
/// of the other stage's: a circuit over two stages that share gates.
struct Branched<const LEN: usize>;

impl<const LEN: usize> Branched<LEN> {
    fn run(left: [Fp; 4], right: [Fp; 4]) -> Fp {
        (0..LEN).fold(left[0], |acc, step| {
            let (near, far) = if step < LEN / 2 {
                (left, right)
            } else {
                (right, left)
            };
            let acc = acc.square() + near[step % 4];
            if step % 7 == 3 {
                acc + far[step % 4]
            } else {
                acc
            }
        })
    }
}

impl<const LEN: usize> MultiStageCircuit<Fp, R> for Branched<LEN> {
    type Last = Right;
    type Instance<'source> = Fp;
    type Witness<'source> = ([Fp; 4], [Fp; 4]);
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
        witness: DriverValue<D, ([Fp; 4], [Fp; 4])>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
    where
        Self: 'dr,
    {
        let (left, builder) = builder.add_stage::<Left>()?;
        let (right, builder) = builder.add_stage::<Right>()?;
        let dr = builder.finish();
        let left = left.unenforced(dr, witness.as_ref().map(|w| w.0))?;
        let right = right.unenforced(dr, witness.as_ref().map(|w| w.1))?;
        let mut acc = left[0].clone();
        for step in 0..LEN {
            let (near, far) = if step < LEN / 2 {
                (&left, &right)
            } else {
                (&right, &left)
            };
            acc = acc.square(dr)?;
            acc = acc.add(dr, &near[step % 4]);
            if step % 7 == 3 {
                acc = acc.add(dr, &far[step % 4]);
            }
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

const LEFT: [u64; 4] = [3, 5, 7, 11];
const RIGHT: [u64; 4] = [13, 17, 19, 23];

/// `Branched<60>` in the pages `loads` tells the stages of, with the
/// two stages' polynomials and the carry stage's.
#[allow(clippy::type_complexity)]
fn branched(
    loads: Vec<Vec<usize>>,
) -> Result<(
    Paged<Fp, MultiStage<Fp, R, Branched<60>>>,
    [sparse::Polynomial<Fp, R>; 2],
    sparse::Polynomial<Fp, R>,
)> {
    let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
    let stages = Stages::of::<Fp, R, Branched<60>>();
    // The stages share their gates, and the circuit counts them end to
    // end.
    assert_eq!(stages.spans, [1..3, 1..3]);
    assert_eq!(stages.own_start(), 5);
    let paged = Paged::cut(
        MultiStage::<Fp, R, _>::new(Branched::<60>),
        &stages.loading(loads),
        limit(),
    )?;
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
    let mut rng = rand::rng();
    let rxs = [
        <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
        <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
    ];
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &[&rxs[0], &rxs[1]])?;
    Ok((paged, rxs, carry))
}

/// Whether each page's claim holds on the carry stage's polynomial and
/// those of the stages `loads` gives it.
fn branched_claims(
    paged: &Paged<Fp, MultiStage<Fp, R, Branched<60>>>,
    rxs: &[sparse::Polynomial<Fp, R>; 2],
    carry: &sparse::Polynomial<Fp, R>,
    loads: impl Fn(usize) -> Vec<usize>,
) -> Result<Vec<bool>> {
    let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
    let instance = Branched::<60>::run(witness.0, witness.1);
    let pages = paged.num_pages();
    let mut holds = Vec::new();
    for index in 0..pages {
        let mut loaded = carry.clone();
        for stage in loads(index) {
            loaded.add_assign(&rxs[stage]);
        }
        holds.push(if index + 1 < pages {
            page_claim_holds(
                paged.page(index),
                &paged.capture(witness)?[index][..],
                (),
                &loaded,
            )?
        } else {
            page_claim_holds(paged.last(), witness, instance, &loaded)?
        });
    }
    Ok(holds)
}

#[test]
fn a_circuit_pages_over_stages_that_share_gates() -> Result<()> {
    let loads = alloc::vec![vec![0], vec![0], vec![1], vec![1]];
    let (paged, rxs, carry) = branched(loads.clone())?;
    assert_eq!(paged.num_pages(), 4);
    assert_eq!(paged.layout().firsts, [3; 4], "a page holds one stage");
    // Each half names the other's stage, which its pages do not load:
    // those values are carried.
    assert!(paged.report().slots > 3);
    paged.check()?;

    // With the stage it loads, a page's claim holds; with the other,
    // which holds other values at the same gates, it fails.
    let holds = branched_claims(&paged, &rxs, &carry, |page| loads[page].clone())?;
    assert_eq!(holds, [true; 4]);
    let holds = branched_claims(&paged, &rxs, &carry, |page| vec![1 - loads[page][0]])?;
    assert_eq!(holds, [false; 4]);
    Ok(())
}

#[test]
fn a_page_that_loads_less_has_more_room() -> Result<()> {
    // The second page loads neither stage and the last one only the
    // first: every value they read of a stage is carried.
    let loads = alloc::vec![vec![0], vec![], vec![1], vec![0]];
    let (paged, rxs, carry) = branched(loads.clone())?;
    let layout = paged.layout();
    // A page's own gates start past the stages it loads, and the last
    // page's past the circuit's last stage, whatever it loads.
    assert_eq!(layout.firsts, [3, 1, 3, 3]);
    assert_eq!(layout.room(1), layout.room(0) + 2);
    let gates: Vec<usize> = paged.report().pages.iter().map(|page| page.gates).collect();
    assert_eq!(gates.iter().sum::<usize>(), 60);
    paged.check()?;

    let holds = branched_claims(&paged, &rxs, &carry, |page| loads[page].clone())?;
    assert_eq!(holds, [true; 4]);
    // The page that loads no stage reads none: either stage beside it
    // moves the gates its own polynomial is at.
    let holds = branched_claims(&paged, &rxs, &carry, |page| {
        if page == 1 {
            vec![0]
        } else {
            loads[page].clone()
        }
    })?;
    assert_eq!(holds, [true, false, true, true]);
    Ok(())
}

#[test]
fn the_cuts_follow_what_the_pages_load() -> Result<()> {
    // The circuit's first half reads the first stage for the most part
    // and its second half the second, and each reads every value of
    // the other stage at some point: whichever pages load which, the
    // eight values of the two are carried, once each, beside what
    // crosses a cut.
    for loads in [
        alloc::vec![vec![0], vec![0], vec![1], vec![1]],
        alloc::vec![vec![1], vec![1], vec![0], vec![0]],
    ] {
        let (paged, ..) = branched(loads)?;
        paged.check()?;
        let report = paged.report();
        assert!(
            (8..=8 + 2 * report.cuts.len()).contains(&report.slots),
            "{report:?}"
        );
    }

    // Where every page loads everything, a cut is placed where few
    // wires are named across it: no worse than cutting evenly.
    let even = Paged::fitted(Chain::<100, 3>, &Stages::whole(1), 21)?;
    let placed = Paged::cut(
        Chain::<100, 3>,
        &Stages::whole(1).pages(even.num_pages()),
        limit(),
    )?;
    assert!(placed.report().slots <= even.report().slots);
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
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rand::rng()), &traces, &[])?;
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

#[test]
fn stages_that_share_gates_cannot_be_loaded_together() {
    let cut = |loads| {
        Paged::cut(
            MultiStage::<Fp, R, _>::new(Branched::<60>),
            &Stages::of::<Fp, R, Branched<60>>().loading(loads),
            limit(),
        )
    };
    assert!(matches!(
        cut(alloc::vec![vec![0, 1], vec![0], vec![1], vec![1]]),
        Err(Error::Initialization(_))
    ));
    // Nor can a stage the circuit reads be loaded by no page.
    assert!(matches!(
        cut(alloc::vec![vec![0], vec![0], vec![0], vec![0]]),
        Err(Error::Initialization(_))
    ));
}

/// Holds each value of [`Left`] to the value of [`Right`] at its place:
/// a circuit with no gates of its own, over two stages that share
/// gates.
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
    let stages = Stages::of::<Fp, R, Tie>().loading(alloc::vec![vec![0], vec![1]]);
    let paged = Paged::cut(MultiStage::<Fp, R, _>::new(Tie), &stages, limit())?;
    assert_eq!(paged.num_pages(), 2);
    assert_eq!(paged.report().slots, 4);
    assert_eq!(paged.report().num_gates, stages.own_start());
    paged.check()?;

    // Each page's claim, on the stage it loads and the carry stage,
    // which holds the first stage's values for the second's page.
    let holds = |right: [u64; 4]| -> Result<[bool; 2]> {
        let mut rng = rand::rng();
        let witness = (LEFT.map(Fp::from), right.map(Fp::from));
        let left = <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?;
        let right = <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?;
        // No page has gates: the carry stage is read off the stage.
        let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &[], &[&left])?;
        let loaded = |stage: &sparse::Polynomial<Fp, R>| {
            let mut loaded = carry.clone();
            loaded.add_assign(stage);
            loaded
        };
        Ok([
            page_claim_holds(
                paged.page(0),
                &paged.capture(witness)?[0][..],
                (),
                &loaded(&left),
            )?,
            page_claim_holds(paged.last(), witness, (), &loaded(&right))?,
        ])
    };
    assert_eq!(holds(LEFT)?, [true, true]);
    assert_eq!(holds([3, 5, 7, 12])?, [true, false]);
    Ok(())
}

#[test]
fn idle_pages_hold_stages_for_pages_that_load_none() -> Result<()> {
    // The first two pages hold no gates: each loads a stage and holds
    // slots to its values for the last two, which load neither and so
    // start at the first gate.
    let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
    let stages = Stages::of::<Fp, R, Branched<40>>()
        .loading(alloc::vec![vec![0], vec![1], vec![], vec![]])
        .idling(alloc::vec![0, 1])
        .unsealed();
    let paged = Paged::cut(
        MultiStage::<Fp, R, _>::new(Branched::<40>),
        &stages,
        limit(),
    )?;
    assert_eq!(paged.layout().firsts, [3, 3, 1, 1]);
    let gates: Vec<usize> = paged.report().pages.iter().map(|page| page.gates).collect();
    assert_eq!(gates[..2], [0, 0]);
    assert_eq!(gates.iter().sum::<usize>(), 40);
    paged.check()?;

    let mut rng = rand::rng();
    let traces = [
        None,
        None,
        Some(
            paged
                .page(2)
                .trace(&paged.capture(witness)?[2])?
                .into_output(),
        ),
        Some(paged.last().trace(witness)?.into_output()),
    ];
    let rxs = [
        <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
        <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
    ];
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &[&rxs[0], &rxs[1]])?;

    // An idle page's claim is on the stage it loads and the carry
    // stage: with the other stage, it fails.
    for page in 0..2 {
        for (stage, holds) in [(page, true), (1 - page, false)] {
            let mut loaded = carry.clone();
            loaded.add_assign(&rxs[stage]);
            assert_eq!(
                page_claim_holds(
                    paged.page(page),
                    &paged.capture(witness)?[page][..],
                    (),
                    &loaded
                )?,
                holds
            );
        }
    }

    // The other pages' claims are on the carry stage alone.
    let instance = Branched::<40>::run(witness.0, witness.1);
    assert!(page_claim_holds(
        paged.page(2),
        &paged.capture(witness)?[2][..],
        (),
        &carry
    )?);
    assert!(page_claim_holds(paged.last(), witness, instance, &carry)?);
    Ok(())
}

/// [`Branched`], with each value of [`Left`] held equal to the value of
/// [`Right`] at the same place: a circuit that holds one stage to
/// another that shares its gates.
struct Tied<const LEN: usize>;

impl<const LEN: usize> MultiStageCircuit<Fp, R> for Tied<LEN> {
    type Last = Right;
    type Instance<'source> = Fp;
    type Witness<'source> = ([Fp; 4], [Fp; 4]);
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
        witness: DriverValue<D, ([Fp; 4], [Fp; 4])>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>>
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
        let mut acc = left[0].clone();
        for step in 0..LEN {
            let (near, far) = if step < LEN / 2 {
                (&left, &right)
            } else {
                (&right, &left)
            };
            acc = acc.square(dr)?;
            acc = acc.add(dr, &near[step % 4]);
            if step % 7 == 3 {
                acc = acc.add(dr, &far[step % 4]);
            }
        }
        Ok(WithAux::new(acc, D::unit()))
    }
}

/// Whether each page's claim holds, for `Tied<40>` in two groups of two
/// pages apart and two more pages, with `right` in the second stage.
fn tied_claims(
    paged: &Paged<Fp, MultiStage<Fp, R, Tied<40>>>,
    right: [u64; 4],
) -> Result<Vec<bool>> {
    let mut rng = rand::rng();
    let witness = (LEFT.map(Fp::from), right.map(Fp::from));
    let instance = Branched::<40>::run(witness.0, witness.1);
    let rxs = [
        <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
        <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
    ];
    let stages = [&rxs[0], &rxs[1]];
    let traces = [
        None,
        None,
        None,
        None,
        Some(
            paged
                .page(4)
                .trace(&paged.capture(witness)?[4])?
                .into_output(),
        ),
        Some(paged.last().trace(witness)?.into_output()),
    ];
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &stages)?;
    let apart = [
        paged.apart_rx::<R>(0, Blind::<Fp>::random(&mut rng), &stages)?,
        paged.apart_rx::<R>(1, Blind::<Fp>::random(&mut rng), &stages)?,
    ];
    // A page's claim is on the stage it loads and its carry stage.
    let mut holds = Vec::new();
    for page in 0..6 {
        let mut loaded = if page < 4 {
            apart[page / 2].clone()
        } else {
            carry.clone()
        };
        loaded.add_assign(&rxs[page % 2]);
        holds.push(if page < 5 {
            page_claim_holds(
                paged.page(page),
                &paged.capture(witness)?[page][..],
                (),
                &loaded,
            )?
        } else {
            page_claim_holds(paged.last(), witness, instance, &loaded)?
        });
    }
    Ok(holds)
}

#[test]
fn pages_apart_hold_what_ties_two_stages() -> Result<()> {
    // Two groups of two pages apart, a page for each stage, then two
    // pages for the circuit's gates.
    let stages = Stages::of::<Fp, R, Tied<40>>()
        .loading(alloc::vec![
            vec![0],
            vec![1],
            vec![0],
            vec![1],
            vec![0],
            vec![1]
        ])
        .apart(alloc::vec![2, 2]);
    let tied = || MultiStage::<Fp, R, _>::new(Tied::<40>);

    // The first group's carry stage has the room for every tie: the
    // second holds none, and neither do the other pages.
    let paged = Paged::cut(tied(), &stages, limit())?;
    assert_eq!(paged.report().apart, [4, 0]);
    let gates: Vec<usize> = paged.report().pages.iter().map(|page| page.gates).collect();
    assert_eq!(gates[..4], [0; 4]);
    assert_eq!(gates.iter().sum::<usize>(), 40);
    let layout = paged.layout();
    assert_eq!(layout.apart[0], (0..2, limit() - 2..limit()));
    assert_eq!(layout.apart[1], (2..4, limit()..limit()));
    assert_eq!(layout.window(0), 3..limit() - 2);
    assert_eq!(layout.window(1), layout.window(0));
    for group in 0..2 {
        let _: &dyn WiringObject<Fp, R> = &paged.apart_mask::<R>(group)?.into_inner();
    }
    paged.check()?;
    assert_eq!(tied_claims(&paged, LEFT)?, [true; 6]);
    // A second stage that is not the first fails the claim of the
    // page that holds the ties, and of the pages that read it.
    let holds = tied_claims(&paged, [3, 5, 7, 12])?;
    assert_eq!(holds[..4], [true, false, true, true]);

    // With a carry stage of one gate each, the groups hold two ties
    // each; with less, the other pages carry what is left.
    let own = paged.report().num_gates - stages.own_start();
    let spread = |first: usize, second: usize| -> Result<_> {
        let mut layout = Layout::fill(&stages, own, limit(), 8)?;
        layout.apart[0].1 = limit() - first..limit();
        layout.apart[1].1 = limit() - second..limit();
        let paged = Paged::new(tied(), &stages, layout)?;
        paged.check()?;
        assert_eq!(tied_claims(&paged, LEFT)?, [true; 6]);
        Ok(paged.report().apart.clone())
    };
    assert_eq!(spread(1, 1)?, [2, 2]);
    assert_eq!(spread(1, 0)?, [2, 0]);
    assert_eq!(spread(0, 0)?, [0, 0]);
    Ok(())
}

#[test]
fn pages_that_share_a_carry_stage_keep_theirs_off_the_others() -> Result<()> {
    // Each stage is loaded by one page, then read by a page that loads
    // none; a last page loads the second, and the circuit takes them
    // all. With each pair of pages
    // sharing a carry stage, what the second of a pair reads of the
    // first, and of the stage the first loads, is carried there.
    let witness = (LEFT.map(Fp::from), RIGHT.map(Fp::from));
    let instance = Branched::<96>::run(witness.0, witness.1);
    let stages = Stages::of::<Fp, R, Branched<96>>().loading(alloc::vec![
        vec![0],
        vec![],
        vec![1],
        vec![],
        vec![1]
    ]);
    let branched = || MultiStage::<Fp, R, _>::new(Branched::<96>);
    let plain = Paged::cut(branched(), &stages, limit())?;
    let stages = stages.sharing(alloc::vec![0..2, 2..4]);
    let paged = Paged::cut(branched(), &stages, limit())?;
    paged.check()?;
    assert_eq!(paged.num_local(), 2);
    let report = paged.report();
    assert!(report.local.iter().all(|&slots| slots > 0), "{report:?}");
    assert!(report.slots < plain.report().slots, "{report:?}");
    // A shared carry stage is right before the circuit's, and its
    // pages' own gates end where it starts.
    let layout = paged.layout();
    for (group, (pages, gates)) in layout.local.iter().enumerate() {
        assert_eq!(gates.end, layout.carry.start);
        for page in pages.clone() {
            assert_eq!(layout.window(page).end, gates.start);
        }
        let _: &dyn WiringObject<Fp, R> = &paged.local_mask::<R>(group)?.into_inner();
    }
    assert_eq!(layout.window(4).end, layout.carry.start);

    let mut rng = rand::rng();
    let mut traces = Vec::new();
    for index in 0..4 {
        traces.push(Some(
            paged
                .page(index)
                .trace(&paged.capture(witness)?[index])?
                .into_output(),
        ));
    }
    traces.push(Some(paged.last().trace(witness)?.into_output()));
    let rxs = [
        <Left as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.0)?,
        <Right as StageExt<Fp, R>>::rx(Blind::<Fp>::random(&mut rng), witness.1)?,
    ];
    let stage_rxs = [&rxs[0], &rxs[1]];
    let carry = paged.carry_rx::<R>(Blind::<Fp>::random(&mut rng), &traces, &stage_rxs)?;
    let local = [
        paged.local_rx::<R>(0, Blind::<Fp>::random(&mut rng), &traces, &stage_rxs)?,
        paged.local_rx::<R>(1, Blind::<Fp>::random(&mut rng), &traces, &stage_rxs)?,
    ];
    // A page's claim is on the circuit's carry stage, the one it
    // shares, and the stages it loads: with the other pair's, it
    // fails.
    let holds = |page: usize, shared: Option<usize>| -> Result<bool> {
        let mut loaded = carry.clone();
        if let Some(group) = shared {
            loaded.add_assign(&local[group]);
        }
        for &stage in &stages.loads[page] {
            loaded.add_assign(&rxs[stage]);
        }
        if page < 4 {
            page_claim_holds(
                paged.page(page),
                &paged.capture(witness)?[page][..],
                (),
                &loaded,
            )
        } else {
            page_claim_holds(paged.last(), witness, instance, &loaded)
        }
    };
    for page in 0..4 {
        assert!(holds(page, Some(page / 2))?, "page {page}");
        assert!(!holds(page, Some(1 - page / 2))?, "page {page}");
    }
    assert!(holds(4, None)?);
    Ok(())
}

#[test]
fn the_masks_cover_the_layout() -> Result<()> {
    let (paged, ..) = branched(alloc::vec![vec![0], vec![], vec![1], vec![0]])?;
    let layout = paged.layout();
    assert_eq!(layout.carry.end, limit());
    let _: &dyn WiringObject<Fp, R> = &paged.carry_mask::<R>()?.into_inner();
    for page in 0..4 {
        let _: &dyn WiringObject<Fp, R> = &paged.own_mask::<R>(page)?.into_inner();
        assert_eq!(layout.window(page), layout.firsts[page]..layout.carry.start);
    }
    Ok(())
}
