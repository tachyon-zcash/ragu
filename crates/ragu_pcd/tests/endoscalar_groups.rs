//! Tests of the grouped endoscaling walk (see
//! [`paging`](crate::internal::paging#groups)): its witness against the
//! walk in one stage, its steps' claims over each step's own group, the
//! check that holds a group to the links, and what a step reserves as the
//! walk grows.

use alloc::{vec, vec::Vec};

use ragu_circuits::{
    CircuitExt, WithAux,
    polynomials::{Rank, WalletRank},
    staging::{MultiStage, MultiStageCircuit, Stage, StageBuilder, StageExt},
    testing::synthesis_counts,
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Ep, EpAffine, Fp, Fq},
};
use ragu_primitives::{
    Uendo, lift_endoscalar,
    vec::{ConstLen, Len},
};
use ragu_testing::registry::TestRegistryBuilder;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective},
    field::Field,
};

use super::{
    EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, LinksStage, NoGap, NumStepsLen,
    PointsStage, PointsWitness, WalkWitness, grouping,
};
use crate::internal::{paging, tests::assert_stage_values};

type R = WalletRank;
/// The endoscalings per step and the steps per group these tests use.
type E = ConstLen<4>;
type Q = ConstLen<3>;

type Witness<const N: usize> = WalkWitness<EpAffine, ConstLen<N>, E, Q>;
type Step<const N: usize> = EndoscalingStep<EpAffine, R, ConstLen<N>, E, NoGap, Q>;
type Group<const N: usize> = PointsStage<EpAffine, ConstLen<N>, E, NoGap, Q>;
type Links<const N: usize> = LinksStage<EpAffine, ConstLen<N>, E, NoGap, Q>;

fn random_point(rng: &mut StdRng) -> EpAffine {
    (Ep::generator() * Fq::random(|bytes| rng.fill_bytes(bytes))).to_affine()
}

/// A random endoscalar and `N` random points.
fn walk<const N: usize>(seed: u64) -> (Uendo, Vec<EpAffine>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let endoscalar = Uendo::random(|| rng.random());
    let points = (0..N).map(|_| random_point(&mut rng)).collect();
    (endoscalar, points)
}

/// The grouped witness holds the values of the walk in one stage: each
/// group's entry is the state before it, its inputs are the walk's in
/// order, its interstitials are the walk's, and the links are the entries
/// and the result.
fn witness_matches_the_whole_walk<const N: usize>() {
    let (endoscalar, points) = walk::<N>(N as u64);
    let grouped = Witness::<N>::new(endoscalar, &points);
    let whole = PointsWitness::<EpAffine, ConstLen<N>, E>::new(endoscalar, &points);
    let grouping = grouping::<ConstLen<N>, E, Q>();

    assert_eq!(grouped.groups.len(), grouping.groups());
    assert_eq!(grouped.links.len(), grouping.groups() + 1);
    let mut entry = whole.initial;
    let mut step = 0;
    for (index, group) in grouped.groups.iter().enumerate() {
        assert_eq!(group.initial, entry, "N {N}, group {index}");
        assert_eq!(grouped.links[index], entry);
        let inputs = grouping.inputs_of(index);
        for (local, input) in inputs.clone().enumerate() {
            assert_eq!(group.inputs[local], whole.inputs[input]);
        }
        for local in 0..grouping.pages_of(index) {
            assert_eq!(group.interstitials[local], whole.interstitials[step]);
            entry = whole.interstitials[step];
            step += 1;
        }
    }
    assert_eq!(step, NumStepsLen::<ConstLen<N>, E>::len());
    assert_eq!(*grouped.links.last().unwrap(), entry);
    assert_eq!(grouped.result(), entry);

    // The result is the scaled sum of the points.
    let scalar: Fq = lift_endoscalar(endoscalar);
    let mut expected = points[0].to_projective();
    for point in &points[1..] {
        expected = expected * scalar + point.to_projective();
    }
    assert_eq!(grouped.result(), expected.to_affine());
}

#[test]
fn the_witness_holds_the_whole_walks_values() {
    // One point; one step; one full group; a short last group; a last
    // group of one step; whole groups.
    witness_matches_the_whole_walk::<1>();
    witness_matches_the_whole_walk::<2>();
    witness_matches_the_whole_walk::<5>();
    witness_matches_the_whole_walk::<13>();
    witness_matches_the_whole_walk::<14>();
    witness_matches_the_whole_walk::<27>();
    witness_matches_the_whole_walk::<37>();
}

/// The stages hold what they declare, and a group's stage does not grow
/// with the walk. A walk in one stage has no links.
#[test]
fn stage_values_match_wire_counts() {
    assert_stage_values::<Fp, R, _>(&Group::<27>::default());
    assert_stage_values::<Fp, R, _>(&Links::<27>::default());
    assert_stage_values::<Fp, R, _>(&Links::<1>::default());
    assert_eq!(<Group<27> as Stage<Fp, R>>::values(), 2 * (1 + 12 + 3));
    assert_eq!(
        <Group<27> as Stage<Fp, R>>::values(),
        <Group<403> as Stage<Fp, R>>::values()
    );
    assert_eq!(<Links<27> as Stage<Fp, R>>::values(), 2 * (3 + 1));
    assert_eq!(
        <LinksStage<EpAffine, ConstLen<27>, E> as Stage<Fp, R>>::values(),
        0
    );
}

/// The circuit that holds group `group` to the links, as a walk's owner
/// would write it, with nothing else in it.
#[derive(Clone)]
struct LinkCheck<const N: usize> {
    group: usize,
}

impl<const N: usize> MultiStageCircuit<Fp, R> for LinkCheck<N> {
    type Last = Links<N>;
    type Instance<'source> = ();
    type Witness<'source> = &'source Witness<N>;
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
        let dr = dr.skip_stage::<EndoscalarStage>()?;
        let dr = dr.skip_stage::<NoGap>()?;
        let (points, dr) = dr.add_stage::<Group<N>>()?;
        let (links, dr) = dr.add_stage::<Links<N>>()?;
        let dr = dr.finish();
        let points = points.unenforced(dr, witness.as_ref().map(|w| &w.groups[self.group]))?;
        let links = links.unenforced(dr, witness.as_ref().map(|w| &w.links))?;
        let exit = grouping::<ConstLen<N>, E, Q>().pages_of(self.group) - 1;
        paging::link(
            dr,
            &links.states,
            self.group,
            &points.initial,
            &points.interstitials[exit],
        )?;
        Ok(WithAux::new((), D::unit()))
    }
}

/// Whether the claim of step `step` holds: its trace, built over
/// `witnessed`, with the endoscalar stage and the points stage polynomial
/// of group `group` of `committed`.
fn step_holds<const N: usize>(
    step: usize,
    group: usize,
    endoscalar: Uendo,
    witnessed: &Witness<N>,
    committed: &Witness<N>,
) -> bool {
    let circuit = Step::<N>::new(step);
    let own = circuit.group();
    let mut builder = TestRegistryBuilder::new();
    let handle = builder
        .register_circuit(MultiStage::new(circuit.clone()))
        .unwrap();
    let group_mask = builder.register_mask(<Group<N> as StageExt<Fp, R>>::stage_mask().unwrap());
    let final_mask = builder.register_mask(<Group<N> as StageExt<Fp, R>>::final_mask().unwrap());
    let registry = builder.finalize().unwrap();

    let staged = MultiStage::new(circuit);
    let trace = staged
        .trace(EndoscalingStepWitness {
            endoscalar,
            points: &witnessed.groups[own],
        })
        .unwrap()
        .into_output();
    let rx = registry.assemble(&trace, handle, Fp::ZERO).unwrap();
    let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(Fp::ZERO, endoscalar).unwrap();

    let y = Fp::from(0x67726f7570u64);
    // The step's trace and every group's polynomial are well formed: the
    // groups share one mask.
    assert_eq!(rx.revdot(&registry.y(final_mask, y)), Fp::ZERO);
    let mut group_rx = None;
    for (index, witness) in committed.groups.iter().enumerate() {
        let rx = <Group<N> as StageExt<Fp, R>>::rx(Fp::ZERO, witness).unwrap();
        assert_eq!(rx.revdot(&registry.y(group_mask, y)), Fp::ZERO);
        if index == group {
            group_rx = Some(rx);
        }
    }

    let mut sum = rx;
    sum.add_assign(&endoscalar_rx);
    sum.add_assign(&group_rx.expect("a group of the walk"));
    sum.revdot(&registry.y(handle, y)) == staged.ky((), y).unwrap()
}

/// Whether the claim of the link check of group `group` holds over the
/// group's polynomial and the links stage of `committed`.
fn link_holds<const N: usize>(
    group: usize,
    witnessed: &Witness<N>,
    committed: &Witness<N>,
) -> bool {
    let circuit = LinkCheck::<N> { group };
    let mut builder = TestRegistryBuilder::new();
    let handle = builder
        .register_circuit(MultiStage::new(circuit.clone()))
        .unwrap();
    let links_mask = builder.register_mask(<Links<N> as StageExt<Fp, R>>::stage_mask().unwrap());
    let final_mask = builder.register_mask(<Links<N> as StageExt<Fp, R>>::final_mask().unwrap());
    let registry = builder.finalize().unwrap();

    let staged = MultiStage::new(circuit);
    let trace = staged.trace(witnessed).unwrap().into_output();
    let rx = registry.assemble(&trace, handle, Fp::ZERO).unwrap();
    let group_rx = <Group<N> as StageExt<Fp, R>>::rx(Fp::ZERO, &committed.groups[group]).unwrap();
    let links_rx = <Links<N> as StageExt<Fp, R>>::rx(Fp::ZERO, &committed.links).unwrap();

    let y = Fp::from(0x6c696e6b73u64);
    assert_eq!(links_rx.revdot(&registry.y(links_mask, y)), Fp::ZERO);
    assert_eq!(rx.revdot(&registry.y(final_mask, y)), Fp::ZERO);

    let mut sum = rx;
    sum.add_assign(&group_rx);
    sum.add_assign(&links_rx);
    sum.revdot(&registry.y(handle, y)) == staged.ky((), y).unwrap()
}

/// The steps whose claims fail, each over its own group, then the groups
/// whose link checks fail.
fn failing<const N: usize>(
    endoscalar: Uendo,
    witnessed: &Witness<N>,
    committed: &Witness<N>,
) -> (Vec<usize>, Vec<usize>) {
    let steps = (0..NumStepsLen::<ConstLen<N>, E>::len())
        .filter(|&step| {
            let group = Step::<N>::new(step).group();
            !step_holds(step, group, endoscalar, witnessed, committed)
        })
        .collect();
    let groups = (0..committed.groups.len())
        .filter(|&group| !link_holds(group, witnessed, committed))
        .collect();
    (steps, groups)
}

/// Every step's claim holds over its own group's polynomial and fails over
/// another group's, and every group's link check holds.
#[test]
fn a_steps_claim_takes_its_own_groups_stage() {
    // 26 inputs: seven steps in groups of three, three and one.
    const N: usize = 27;
    let (endoscalar, points) = walk::<N>(1);
    let witness = Witness::<N>::new(endoscalar, &points);
    assert_eq!(witness.groups.len(), 3);
    assert_eq!(failing(endoscalar, &witness, &witness), (vec![], vec![]));
    for step in 0..7 {
        let own = Step::<N>::new(step).group();
        assert_eq!(own, step / 3);
        for group in (0..3).filter(|&group| group != own) {
            assert!(
                !step_holds(step, group, endoscalar, &witness, &witness),
                "step {step} over group {group}"
            );
        }
    }
}

/// A wrong committed value fails the claims of the circuits that read it,
/// and no other, whatever their provers witnessed.
#[test]
fn a_wrong_value_fails_the_circuits_that_read_it() {
    const N: usize = 27;
    let (endoscalar, points) = walk::<N>(2);
    let honest = Witness::<N>::new(endoscalar, &points);
    let other = (Ep::generator() * Fq::from(99)).to_affine();
    let check = |name: &str, change: &dyn Fn(&mut Witness<N>), steps: &[usize], links: &[usize]| {
        let mut committed = honest.clone();
        change(&mut committed);
        for witnessed in [&honest, &committed] {
            assert_eq!(
                failing(endoscalar, witnessed, &committed),
                (steps.to_vec(), links.to_vec()),
                "{name}"
            );
        }
    };

    // A link: the checks of the groups on both sides of it.
    check("link 0", &|w| w.links[0] = other, &[], &[0]);
    check("link 1", &|w| w.links[1] = other, &[], &[0, 1]);
    check("link 2", &|w| w.links[2] = other, &[], &[1, 2]);
    check("result", &|w| w.links[3] = other, &[], &[2]);
    // A group's entry: its first step and its check.
    check("entry", &|w| w.groups[0].initial = other, &[0], &[0]);
    check("entry", &|w| w.groups[1].initial = other, &[3], &[1]);
    // A group's exit: its last step and its check.
    check(
        "exit",
        &|w| w.groups[1].interstitials[2] = other,
        &[5],
        &[1],
    );
    check(
        "exit",
        &|w| w.groups[2].interstitials[0] = other,
        &[6],
        &[2],
    );
    // A state between two steps of a group: those two steps.
    check(
        "inner",
        &|w| w.groups[1].interstitials[0] = other,
        &[3, 4],
        &[],
    );
    check(
        "inner",
        &|w| w.groups[0].interstitials[1] = other,
        &[1, 2],
        &[],
    );
    // An input: its step.
    check("input", &|w| w.groups[1].inputs[5] = other, &[4], &[]);
    check("input", &|w| w.groups[2].inputs[1] = other, &[6], &[]);
    // The slots nothing reads: the short last group's unused inputs and
    // interstitials.
    check("padding", &|w| w.groups[2].inputs[2] = other, &[], &[]);
    check(
        "padding",
        &|w| w.groups[2].interstitials[1] = other,
        &[],
        &[],
    );
    check(
        "padding",
        &|w| w.groups[2].interstitials[2] = other,
        &[],
        &[],
    );
}

/// A walk of one point has one step in one group, which holds the group's
/// entry to its exit, and the check holds both to the links.
#[test]
fn a_walk_of_one_point_holds_it_to_the_result() {
    const N: usize = 1;
    let (endoscalar, points) = walk::<N>(3);
    let honest = Witness::<N>::new(endoscalar, &points);
    assert_eq!(honest.result(), points[0]);
    assert_eq!(honest.links.clone().into_inner(), [points[0], points[0]]);
    assert_eq!(failing(endoscalar, &honest, &honest), (vec![], vec![]));
    let mut wrong = honest.clone();
    wrong.links[1] = (Ep::generator() * Fq::from(5)).to_affine();
    assert_eq!(failing(endoscalar, &wrong, &wrong), (vec![], vec![0]));
}

fn gates<F: Field>(circuit: &impl ragu_circuits::Circuit<F>) -> usize {
    synthesis_counts(circuit).unwrap().num_gates
}

/// A full grouped step takes the same gates whatever the walk's length.
/// The step of a walk in one stage grows by every point and every step.
#[test]
fn a_steps_gates_do_not_grow_with_the_walk() {
    fn grouped<const N: usize>() -> usize {
        gates(&MultiStage::new(Step::<N>::new(0)))
    }
    assert_eq!(grouped::<27>(), grouped::<103>());
    assert_eq!(grouped::<27>(), grouped::<803>());

    fn whole<const N: usize>() -> usize {
        gates(&MultiStage::new(EndoscalingStep::<
            EpAffine,
            R,
            ConstLen<N>,
            E,
        >::new(0)))
    }
    let grown = (103 - 27)
        + (NumStepsLen::<ConstLen<103>, E>::len() - NumStepsLen::<ConstLen<27>, E>::len());
    assert_eq!(whole::<103>() - whole::<27>(), grown);
}

/// A walk of the size the aggregator profile needs at the wallet rank,
/// about 800 points, fits four endoscalings in a grouped step at
/// thirty-two steps a group, and a fifth does not fit. The step of the
/// same walk in one stage takes more gates than the rank has.
#[test]
fn four_endoscalings_fit_a_grouped_step_of_a_long_walk() {
    const N: usize = 802;
    type Wide = ConstLen<32>;
    let step = EndoscalingStep::<EpAffine, R, ConstLen<N>, E, NoGap, Wide>::new(0);
    let full = gates(&MultiStage::new(step));

    // One application, from the two step sizes of a short walk.
    let short = |index| {
        gates(&MultiStage::new(EndoscalingStep::<
            EpAffine,
            R,
            ConstLen<6>,
            E,
        >::new(index)))
    };
    let application = (short(0) - short(1)) / 3;
    assert_eq!(short(0) - short(1), 3 * application);

    let budget = R::blind_gate();
    assert!(
        full <= budget,
        "a grouped step takes {full} gates of {budget}"
    );
    assert!(
        full + application > budget,
        "a fifth endoscaling of {application} gates would fit beside {full} of {budget}"
    );
    std::println!(
        "grouped step over {N} points: {full} gates of {budget}, {application} an endoscaling"
    );

    let whole = gates(&MultiStage::new(EndoscalingStep::<
        EpAffine,
        R,
        ConstLen<N>,
        E,
    >::new(0)));
    assert!(
        whole > budget,
        "the step in one stage takes {whole} gates of {budget}"
    );
}
