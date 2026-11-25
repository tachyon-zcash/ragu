//! Tests of [`paging`](super): the page arithmetic, the native
//! interstitials, the page runner over both units with honest and wrong
//! stage values, and the capacity of the two endoscaling walks.
//!
//! The runner tests use a walk whose values are plain vectors of gadgets on
//! a [`Simulator`], which checks every constraint as it is emitted: a page
//! over wrong values returns an error.

use alloc::{vec, vec::Vec};

use ragu_circuits::{Circuit, polynomials::Rank, staging::MultiStage, testing::synthesis_counts};
use ragu_core::{
    Result,
    drivers::Driver,
    pasta::{Ep, EpAffine, EqAffine, Fp, Fq, Pasta},
};
use ragu_primitives::{
    Element, HoistedEndoscalar, Point, Simulator, Uendo, lift_endoscalar, vec::Len,
};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective},
    field::Field,
};

use super::{ElementHorner, PointHorner, Unit, Walk, interstitials, num_pages, page, range};
use crate::{
    internal::{
        endoscalar,
        native::{self, circuits::endoscaling_step, stages::points},
        nested,
    },
    profile::{Profile, Standard},
};

type Sim = Simulator<Fp>;

/// A walk whose values are vectors: what a page would read from stages.
struct VecWalk<U: Unit<'static, Sim>> {
    unit: U,
    capacity: usize,
    initial: U::State,
    inputs: Vec<U::Input>,
    interstitials: Vec<U::State>,
}

impl<U: Unit<'static, Sim>> Walk<'static, Sim> for VecWalk<U> {
    type Unit = U;

    fn unit(&self) -> &U {
        &self.unit
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    fn initial(&self) -> &U::State {
        &self.initial
    }

    fn input(&self, index: usize) -> &U::Input {
        &self.inputs[index]
    }

    fn interstitial(&self, page: usize) -> &U::State {
        &self.interstitials[page]
    }
}

fn element(dr: &mut Sim, value: Fp) -> Element<'static, Sim> {
    Element::alloc(dr, &mut (), Sim::just(|| value)).unwrap()
}

fn random_fp(rng: &mut StdRng) -> Fp {
    Fp::random(|bytes| rng.fill_bytes(bytes))
}

fn random_point(rng: &mut StdRng) -> EpAffine {
    (Ep::generator() * Fq::random(|bytes| rng.fill_bytes(bytes))).to_affine()
}

/// The values of an element walk: the point, the initial state, the inputs
/// and the interstitials at `capacity`.
#[derive(Clone)]
struct ElementValues {
    capacity: usize,
    point: Fp,
    initial: Fp,
    inputs: Vec<Fp>,
    interstitials: Vec<Fp>,
}

impl ElementValues {
    /// An honest walk over `len` random inputs.
    fn honest(rng: &mut StdRng, capacity: usize, len: usize) -> Self {
        let point = random_fp(rng);
        let initial = random_fp(rng);
        let inputs: Vec<Fp> = (0..len).map(|_| random_fp(rng)).collect();
        let interstitials = interstitials(capacity, initial, &inputs, |state, input| {
            *state = *state * point + input
        });
        ElementValues {
            capacity,
            point,
            initial,
            inputs,
            interstitials,
        }
    }

    /// Runs page `index` over these values. Returns whether the page's
    /// constraints hold, and the gates the page itself took.
    fn run(&self, index: usize) -> (bool, usize) {
        let mut gates = 0;
        let result = Simulator::simulate((), |dr, _| {
            let point = element(dr, self.point);
            let walk = VecWalk {
                unit: ElementHorner::new(&point),
                capacity: self.capacity,
                initial: element(dr, self.initial),
                inputs: self.inputs.iter().map(|&v| element(dr, v)).collect(),
                interstitials: self.interstitials.iter().map(|&v| element(dr, v)).collect(),
            };
            let before = dr.num_gates();
            let result = page(dr, &walk, index);
            gates = dr.num_gates() - before;
            result
        });
        (result.is_ok(), gates)
    }

    /// The pages whose constraints hold, as one flag per page.
    fn pages(&self) -> Vec<bool> {
        (0..num_pages(self.capacity, self.inputs.len()))
            .map(|index| self.run(index).0)
            .collect()
    }
}

/// The values of a point walk, as [`ElementValues`].
#[derive(Clone)]
struct PointValues {
    capacity: usize,
    endoscalar: Uendo,
    initial: EpAffine,
    inputs: Vec<EpAffine>,
    interstitials: Vec<EpAffine>,
}

impl PointValues {
    fn honest(rng: &mut StdRng, capacity: usize, len: usize) -> Self {
        let endoscalar = Uendo::random(|| rng.random());
        let scalar: Fq = lift_endoscalar(endoscalar);
        let initial = random_point(rng);
        let inputs: Vec<EpAffine> = (0..len).map(|_| random_point(rng)).collect();
        let interstitials = interstitials(
            capacity,
            initial.to_projective(),
            &inputs,
            |state, input: &EpAffine| *state = *state * scalar + input.to_projective(),
        )
        .into_iter()
        .map(|state| state.to_affine())
        .collect();
        PointValues {
            capacity,
            endoscalar,
            initial,
            inputs,
            interstitials,
        }
    }

    fn run(&self, index: usize) -> (bool, usize) {
        let mut gates = 0;
        let result = Simulator::simulate((), |dr: &mut Sim, _| {
            let point = |dr: &mut Sim, value: EpAffine| Point::alloc(dr, Sim::just(|| value));
            let endoscalar = HoistedEndoscalar::alloc(dr, Sim::just(|| self.endoscalar))?;
            let walk = VecWalk {
                unit: PointHorner::<_, EpAffine>::new(&endoscalar),
                capacity: self.capacity,
                initial: point(dr, self.initial)?,
                inputs: self
                    .inputs
                    .iter()
                    .map(|&value| point(dr, value))
                    .collect::<Result<_>>()?,
                interstitials: self
                    .interstitials
                    .iter()
                    .map(|&value| point(dr, value))
                    .collect::<Result<_>>()?,
            };
            let before = dr.num_gates();
            let result = page(dr, &walk, index);
            gates = dr.num_gates() - before;
            result
        });
        (result.is_ok(), gates)
    }

    fn pages(&self) -> Vec<bool> {
        (0..num_pages(self.capacity, self.inputs.len()))
            .map(|index| self.run(index).0)
            .collect()
    }
}

/// Every page but the listed ones holds.
fn all_but(pages: usize, failing: &[usize]) -> Vec<bool> {
    (0..pages).map(|index| !failing.contains(&index)).collect()
}

/// The pages' ranges are adjacent, cover the inputs, hold the capacity each
/// but the last, and are empty past the walk.
#[test]
fn pages_partition_the_inputs() {
    for capacity in 1..=9 {
        for len in 0..=60 {
            let pages = num_pages(capacity, len);
            assert_eq!(pages, len.div_ceil(capacity).max(1), "{capacity} {len}");
            let mut next = 0;
            for index in 0..pages {
                let range = range(capacity, index, len);
                assert_eq!(range.start, next, "pages are adjacent");
                assert!(range.len() <= capacity);
                if index + 1 < pages {
                    assert_eq!(range.len(), capacity, "only the last page is short");
                } else if len > 0 {
                    assert!(!range.is_empty(), "the last page of a walk has an input");
                }
                next = range.end;
            }
            assert_eq!(next, len, "the pages cover every input");
            assert!(range(capacity, pages, len).is_empty());
            assert!(range(capacity, pages + 7, len).is_empty());
        }
    }
    assert_eq!(num_pages(4, 0), 1, "a walk with no inputs has one page");
    assert!(range(4, 0, 0).is_empty());
    assert!(range(usize::MAX, usize::MAX, 3).is_empty(), "no overflow");
}

/// The endoscaling steps are the pages of a walk over the points after the
/// first.
#[test]
fn the_endoscaling_steps_are_the_pages() {
    for endoscalings in 1..=6 {
        for points in 1..=40 {
            assert_eq!(
                endoscalar::num_steps(endoscalings, points),
                num_pages(endoscalings, points - 1)
            );
        }
    }
}

#[test]
#[should_panic(expected = "a page applies its unit at least once")]
fn a_capacity_of_zero_is_refused() {
    num_pages(0, 5);
}

/// The native helper leaves the state after each page: every state is the
/// whole walk's fold over the inputs up to its page's end.
#[test]
fn interstitials_are_the_states_after_each_page() {
    let apply = |state: &mut u64, input: &u64| *state = state.wrapping_mul(31).wrapping_add(*input);
    for capacity in 1..=7 {
        for len in 0..=30 {
            let inputs: Vec<u64> = (0..len as u64).map(|i| 1000 + 17 * i).collect();
            let states = interstitials(capacity, 5u64, &inputs, apply);
            assert_eq!(states.len(), num_pages(capacity, len));
            for (index, state) in states.iter().enumerate() {
                let end = range(capacity, index, len).end;
                let mut expected = 5u64;
                inputs[..end]
                    .iter()
                    .for_each(|input| apply(&mut expected, input));
                assert_eq!(
                    *state, expected,
                    "capacity {capacity}, len {len}, page {index}"
                );
            }
        }
    }
    assert_eq!(interstitials(3, 9u64, &[], apply), vec![9]);
}

/// Every page of an honest element walk holds, and the last interstitial
/// is the polynomial's value by Horner's rule.
#[test]
fn element_pages_chain_to_the_evaluation() {
    let mut rng = StdRng::seed_from_u64(0x7061_6765);
    for (capacity, len) in [(1, 1), (1, 5), (3, 7), (4, 8), (4, 9), (5, 3), (16, 40)] {
        let values = ElementValues::honest(&mut rng, capacity, len);
        assert!(
            values.pages().iter().all(|&holds| holds),
            "{capacity} {len}"
        );
        let mut expected = values.initial;
        for input in &values.inputs {
            expected = expected * values.point + input;
        }
        assert_eq!(*values.interstitials.last().unwrap(), expected);
    }
}

/// An application of the element unit takes one gate, a page nothing else.
#[test]
fn an_element_application_takes_one_gate() {
    let mut rng = StdRng::seed_from_u64(1);
    let values = ElementValues::honest(&mut rng, 4, 10);
    assert_eq!(values.run(0), (true, 4));
    assert_eq!(values.run(1), (true, 4));
    assert_eq!(values.run(2), (true, 2));
    let empty = ElementValues::honest(&mut rng, 4, 0);
    assert_eq!(empty.run(0), (true, 0));
}

/// A wrong interstitial fails the page that holds its result to it and the
/// page that starts from it, and no other.
#[test]
fn a_wrong_interstitial_fails_the_two_pages_that_touch_it() {
    let mut rng = StdRng::seed_from_u64(2);
    let honest = ElementValues::honest(&mut rng, 3, 11);
    let pages = honest.interstitials.len();
    assert_eq!(pages, 4);
    for wrong in 0..pages {
        let mut values = honest.clone();
        values.interstitials[wrong] += Fp::ONE;
        let failing: Vec<usize> = [wrong, wrong + 1]
            .into_iter()
            .filter(|&index| index < pages)
            .collect();
        assert_eq!(
            values.pages(),
            all_but(pages, &failing),
            "interstitial {wrong}"
        );
    }
}

/// A wrong input fails the page it belongs to, and no other.
#[test]
fn a_wrong_input_fails_its_page() {
    let mut rng = StdRng::seed_from_u64(3);
    let honest = ElementValues::honest(&mut rng, 3, 11);
    for wrong in 0..honest.inputs.len() {
        let mut values = honest.clone();
        values.inputs[wrong] += Fp::ONE;
        assert_eq!(values.pages(), all_but(4, &[wrong / 3]), "input {wrong}");
    }
}

/// A wrong initial state or a wrong point fails every page that uses it:
/// the first page, and every page with an application.
#[test]
fn a_wrong_initial_state_or_point_fails_the_pages_that_use_it() {
    let mut rng = StdRng::seed_from_u64(4);
    let honest = ElementValues::honest(&mut rng, 3, 11);
    let mut values = honest.clone();
    values.initial += Fp::ONE;
    assert_eq!(values.pages(), all_but(4, &[0]));
    let mut values = honest.clone();
    values.point += Fp::ONE;
    assert_eq!(values.pages(), all_but(4, &[0, 1, 2, 3]));
}

/// Two interstitials in each other's place fail the pages around them: the
/// pages are held to an order.
#[test]
fn swapped_interstitials_fail() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut values = ElementValues::honest(&mut rng, 3, 11);
    values.interstitials.swap(0, 2);
    assert_eq!(values.pages(), all_but(4, &[0, 1, 2, 3]));
}

/// A walk with no inputs has one page, which holds the initial state to
/// its interstitial.
#[test]
fn the_empty_walk_holds_the_initial_state() {
    let mut rng = StdRng::seed_from_u64(6);
    let mut values = ElementValues::honest(&mut rng, 4, 0);
    assert_eq!(values.interstitials, vec![values.initial]);
    assert_eq!(values.pages(), vec![true]);
    values.interstitials[0] += Fp::ONE;
    assert_eq!(values.pages(), vec![false]);
}

#[test]
#[should_panic(expected = "is not a page of the walk")]
fn a_page_past_the_walk_is_refused() {
    let mut rng = StdRng::seed_from_u64(7);
    let mut values = ElementValues::honest(&mut rng, 3, 6);
    // A value to index, so that only the page check can panic.
    values.interstitials.push(Fp::ZERO);
    values.run(2);
}

/// What a page asked a walk for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asked {
    Initial,
    Input(usize),
    Interstitial(usize),
}

/// A walk that records what a page asks it for.
struct Recording<'a> {
    walk: VecWalk<ElementHorner<'a, 'static, Sim>>,
    asked: core::cell::RefCell<Vec<Asked>>,
}

impl<'a> Walk<'static, Sim> for Recording<'a> {
    type Unit = ElementHorner<'a, 'static, Sim>;

    fn unit(&self) -> &Self::Unit {
        self.walk.unit()
    }

    fn capacity(&self) -> usize {
        self.walk.capacity()
    }

    fn num_inputs(&self) -> usize {
        self.walk.num_inputs()
    }

    fn initial(&self) -> &Element<'static, Sim> {
        self.asked.borrow_mut().push(Asked::Initial);
        self.walk.initial()
    }

    fn input(&self, index: usize) -> &Element<'static, Sim> {
        self.asked.borrow_mut().push(Asked::Input(index));
        self.walk.input(index)
    }

    fn interstitial(&self, page: usize) -> &Element<'static, Sim> {
        self.asked.borrow_mut().push(Asked::Interstitial(page));
        self.walk.interstitial(page)
    }
}

/// A page asks the walk for its own inputs, the interstitial before it or
/// the initial state, and its own interstitial, and for nothing else: a
/// page circuit needs only these values among the stages it loads.
#[test]
fn a_page_reads_only_its_own_values() {
    let mut rng = StdRng::seed_from_u64(11);
    let values = ElementValues::honest(&mut rng, 3, 11);
    for index in 0..4 {
        let mut asked = Vec::new();
        Simulator::simulate((), |dr: &mut Sim, _| {
            let point = element(dr, values.point);
            let walk = Recording {
                walk: VecWalk {
                    unit: ElementHorner::new(&point),
                    capacity: values.capacity,
                    initial: element(dr, values.initial),
                    inputs: values.inputs.iter().map(|&v| element(dr, v)).collect(),
                    interstitials: values
                        .interstitials
                        .iter()
                        .map(|&v| element(dr, v))
                        .collect(),
                },
                asked: Default::default(),
            };
            page(dr, &walk, index)?;
            asked = walk.asked.into_inner();
            Ok(())
        })
        .unwrap();
        let mut expected = vec![match index.checked_sub(1) {
            Some(before) => Asked::Interstitial(before),
            None => Asked::Initial,
        }];
        expected.extend(range(3, index, 11).map(Asked::Input));
        expected.push(Asked::Interstitial(index));
        assert_eq!(asked, expected, "page {index}");
    }
}

/// Every page of an honest point walk holds: the unit in the circuit agrees
/// with the scaling the prover fills the interstitials by, and the last
/// interstitial is the scaled sum of the points.
#[test]
fn point_pages_chain_to_the_scaled_sum() {
    let mut rng = StdRng::seed_from_u64(8);
    for (capacity, len) in [(1, 2), (2, 5), (4, 4), (4, 6)] {
        let values = PointValues::honest(&mut rng, capacity, len);
        assert!(
            values.pages().iter().all(|&holds| holds),
            "{capacity} {len}"
        );
        let scalar: Fq = lift_endoscalar(values.endoscalar);
        let mut expected = values.initial.to_projective();
        for input in &values.inputs {
            expected = expected * scalar + input.to_projective();
        }
        assert_eq!(*values.interstitials.last().unwrap(), expected.to_affine());
    }
}

/// Wrong points fail the pages that read them, as wrong elements do.
#[test]
fn wrong_points_fail_the_pages_that_read_them() {
    let mut rng = StdRng::seed_from_u64(9);
    let honest = PointValues::honest(&mut rng, 2, 5);
    let other = random_point(&mut rng);

    let mut values = honest.clone();
    values.interstitials[1] = other;
    assert_eq!(values.pages(), all_but(3, &[1, 2]));

    let mut values = honest.clone();
    values.inputs[2] = other;
    assert_eq!(values.pages(), all_but(3, &[1]));

    let mut values = honest.clone();
    values.initial = other;
    assert_eq!(values.pages(), all_but(3, &[0]));

    // Another endoscalar moves every state.
    let mut values = honest.clone();
    values.endoscalar = Uendo::from(u128::from(values.endoscalar != Uendo::from(1u128)));
    assert_eq!(values.pages(), all_but(3, &[0, 1, 2]));

    // A one-point walk holds its initial point to the output.
    let mut values = PointValues::honest(&mut rng, 4, 0);
    assert_eq!(values.pages(), vec![true]);
    values.interstitials[0] = other;
    assert_eq!(values.pages(), vec![false]);
}

/// Every application of the point unit takes the same gates, and a page
/// takes one bank beside them, whatever its length.
#[test]
fn a_point_page_takes_one_bank_and_equal_applications() {
    let mut rng = StdRng::seed_from_u64(10);
    let mut gates = |len: usize| {
        let (holds, gates) = PointValues::honest(&mut rng, 8, len).run(0);
        assert!(holds);
        gates
    };
    let (empty, one, two, five) = (gates(0), gates(1), gates(2), gates(5));
    let application = one - empty;
    assert_eq!(empty, 1, "the bank's check");
    assert_eq!(two, empty + 2 * application);
    assert_eq!(five, empty + 5 * application);
}

/// Holds a walk's capacity to the largest count that fits: a full page of
/// `full` gates fits `budget`, and one more application of `application`
/// gates does not.
pub(crate) fn assert_capacity(walk: &str, full: usize, application: usize, budget: usize) {
    assert!(
        full <= budget,
        "{walk}: a full page takes {full} gates of {budget}; lower the capacity"
    );
    assert!(
        full + application > budget,
        "{walk}: a full page takes {full} gates of {budget} and an application \
         {application}; raise the capacity"
    );
}

fn gates<F: Field>(circuit: &impl Circuit<F>) -> usize {
    synthesis_counts(circuit).unwrap().num_gates
}

/// The standard profile's two endoscaling walks fill their pages: the
/// endoscalings per step are the most a step fits at the wallet rank
/// beside the stages it loads.
#[test]
fn the_endoscaling_walks_fill_their_pages() {
    type R = ragu_circuits::polynomials::WalletRank;
    let budget = R::blind_gate();

    // The native walk: a full first step, and a last step short of it.
    let capacity = Standard::NATIVE_ENDOSCALINGS_PER_STEP;
    let len = points::NumInputs::<Standard>::len();
    let pages = num_pages(capacity, len);
    assert_eq!(pages, native::NumSteps::<Standard>::len());
    let short = range(capacity, pages - 1, len).len();
    assert!(short < capacity, "the last step measures an application");
    let full = gates(&endoscaling_step::Circuit::<Pasta, R>::new(0));
    let last = gates(&endoscaling_step::Circuit::<Pasta, R>::new(pages - 1));
    let application = (full - last) / (capacity - short);
    assert_eq!(full - last, application * (capacity - short));
    assert_capacity("native endoscaling", full, application, budget);

    // The nested walk, likewise.
    let capacity = Standard::NESTED_ENDOSCALINGS_PER_STEP;
    let len = nested::NumPoints::<Standard>::len() - 1;
    let pages = num_pages(capacity, len);
    assert_eq!(pages, nested::NumSteps::<Standard>::len());
    let short = range(capacity, pages - 1, len).len();
    assert!(short < capacity, "the last step measures an application");
    let step =
        |index| MultiStage::new(nested::EndoscalingStep::<EqAffine, R, Standard>::new(index));
    let full = gates(&step(0));
    let last = gates(&step(pages - 1));
    let application = (full - last) / (capacity - short);
    assert_eq!(full - last, application * (capacity - short));
    assert_capacity("nested endoscaling", full, application, budget);
}
