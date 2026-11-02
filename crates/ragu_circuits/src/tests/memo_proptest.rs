//! Property tests for memoized $s(x, y)$ evaluation over random routine
//! trees whose constraints reference internal wires, input wires, nested
//! routine outputs and `ONE`.

use alloc::{boxed::Box, vec, vec::Vec};

use proptest::prelude::*;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression},
    gadgets::{Bound, Kind},
    pasta::Fp,
    routines::{Prediction, Routine},
};
use ragu_primitives::{Element, allocator::Standard};
use rand::Rng;
use udon::field::Field;

use crate::{
    Circuit, WithAux, floor_planner, into_wiring_object,
    polynomials::TestRank,
    registry::{CircuitIndex, RegistryBuilder},
    wiring::MemoCache,
};

const MAX_OPS: usize = 5;
const MAX_DEPTH: u32 = 3;
const MAX_TREE_SIZE: u32 = 10;

/// One step of a routine body. Indices select from the pool of elements
/// available so far (input first), modulo the pool size.
#[derive(Clone, Debug)]
enum Op {
    /// `pool.push(pool[i]^2)`: one gate, two constraints on the operand.
    Square(usize),
    /// `pool.push(pool[i] * pool[j])`.
    Mul(usize, usize),
    /// `pool.push(pool[i] + pool[j])`: no gate, a mixed linear form.
    Add(usize, usize),
    /// `enforce(pool[i] - pool[j] = 0)`.
    Equal(usize, usize),
    /// `enforce(pool[i] - ONE = 0)`: references the `ONE` wire.
    IsOne(usize),
    /// Nested routine call with `pool[i]` as input; output joins the pool.
    Call(Box<Tree>, usize),
}

#[derive(Clone, Debug)]
struct Tree {
    ops: Vec<Op>,
}

fn arb_tree() -> impl Strategy<Value = Tree> {
    let leaf_op = prop_oneof![
        (0..8usize).prop_map(Op::Square),
        (0..8usize, 0..8usize).prop_map(|(i, j)| Op::Mul(i, j)),
        (0..8usize, 0..8usize).prop_map(|(i, j)| Op::Add(i, j)),
        (0..8usize, 0..8usize).prop_map(|(i, j)| Op::Equal(i, j)),
        (0..8usize).prop_map(Op::IsOne),
    ];
    let leaf = proptest::collection::vec(leaf_op.clone(), 0..=MAX_OPS).prop_map(|ops| Tree { ops });
    leaf.prop_recursive(MAX_DEPTH, MAX_TREE_SIZE, 2, move |inner| {
        let op = prop_oneof![
            leaf_op.clone(),
            (inner, 0..8usize).prop_map(|(t, i)| Op::Call(Box::new(t), i)),
        ];
        proptest::collection::vec(op, 0..=MAX_OPS).prop_map(|ops| Tree { ops })
    })
}

fn run_tree<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    tree: &Tree,
    input: Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let mut pool = vec![input];
    for op in &tree.ops {
        let pick = |i: usize| pool[i % pool.len()].clone();
        match op {
            Op::Square(i) => {
                let v = pick(*i).square(dr)?;
                pool.push(v);
            }
            Op::Mul(i, j) => {
                let v = pick(*i).mul(dr, &pick(*j))?;
                pool.push(v);
            }
            Op::Add(i, j) => {
                let v = pick(*i).add(dr, &pick(*j));
                pool.push(v);
            }
            Op::Equal(i, j) => {
                let (a, b) = (pick(*i), pick(*j));
                dr.enforce_zero(|lc| lc.add(a.wire()).sub(b.wire()))?;
            }
            Op::IsOne(i) => {
                let a = pick(*i);
                dr.enforce_zero(|lc| lc.add(a.wire()).sub(&D::ONE))?;
            }
            Op::Call(subtree, i) => {
                let v = dr.routine(TreeRoutine(subtree.as_ref().clone()), pick(*i))?;
                pool.push(v);
            }
        }
    }
    Ok(pool.pop().expect("pool is never empty"))
}

#[derive(Clone)]
struct TreeRoutine(Tree);

impl Routine<Fp> for TreeRoutine {
    type Input = Kind![Fp; Element<'_, _>];
    type Output = Kind![Fp; Element<'_, _>];
    type Aux<'dr> = ();

    fn execute<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        input: Bound<'dr, D, Self::Input>,
        _aux: DriverValue<D, Self::Aux<'dr>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        run_tree(dr, &self.0, input)
    }

    fn predict<'dr, D: Driver<'dr, F = Fp>>(
        &self,
        _dr: &mut D,
        _input: &Bound<'dr, D, Self::Input>,
    ) -> Result<Prediction<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'dr>>>> {
        Ok(Prediction::Unknown(D::unit()))
    }
}

/// Calls each tree as a top-level routine in order, chaining outputs.
struct TreeCircuit {
    /// Gates emitted before the first routine, to shift placements.
    prefix_squares: usize,
    trees: Vec<Tree>,
}

impl Circuit<Fp> for TreeCircuit {
    type Instance<'source> = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    type Witness<'source> = Fp;
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, &mut Standard::new(), instance)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>> {
        let mut a = Element::alloc(dr, &mut Standard::new(), witness)?;
        for _ in 0..self.prefix_squares {
            a = a.square(dr)?;
        }
        for tree in &self.trees {
            a = dr.routine(TreeRoutine(tree.clone()), a)?;
        }
        Ok(WithAux::new(a, D::unit()))
    }
}

fn random() -> Fp {
    Fp::random(|bytes| rand::rng().fill_bytes(bytes))
}

proptest! {
    /// Recording and replaying every top-level routine (fresh cache, so each
    /// is recorded once and replayed in place) reproduces the plain
    /// evaluation, and the plain evaluators agree with each other.
    #[test]
    fn replay_matches_plain_evaluation(trees in proptest::collection::vec(arb_tree(), 1..=3)) {
        let circuit = TreeCircuit { prefix_squares: 0, trees };
        let obj = into_wiring_object::<Fp, _, TestRank>(circuit)
            .map_err(|_| TestCaseError::reject("tree exceeds the test rank"))?;
        super::consistency_checks(&*obj);

        let plan = floor_planner::floor_plan(obj.segment_records());
        for (x, y) in [(random(), random()), (Fp::ZERO, random()), (random(), Fp::ZERO)] {
            let mut cache = MemoCache::new();
            prop_assert_eq!(obj.sxy_with_cache(x, y, &plan, &mut cache), obj.sxy(x, y, &plan));
            let mut cache = MemoCache::new();
            let memoized = obj.sx_with_cache(x, &plan, &mut cache);
            prop_assert!(memoized.iter_coeffs().eq(obj.sx(x, &plan).iter_coeffs()));
            let mut cache = MemoCache::new();
            let memoized = obj.sy_with_cache(y, &plan, &mut cache);
            prop_assert!(memoized.iter_coeffs().eq(obj.sy(y, &plan).iter_coeffs()));
        }
    }

    /// Replaying recordings taken in one circuit inside another circuit —
    /// same routines at different offsets, with different inputs, in a
    /// different order — reproduces the plain registry evaluation.
    #[test]
    fn shared_cache_across_circuits(
        trees in proptest::collection::vec(arb_tree(), 1..=3),
        prefix in 0..3usize,
    ) {
        let mut reversed = trees.clone();
        reversed.reverse();
        let circuits = [
            TreeCircuit { prefix_squares: 0, trees: trees.clone() },
            TreeCircuit { prefix_squares: prefix, trees: reversed },
            TreeCircuit { prefix_squares: prefix + 1, trees },
        ];

        let mut builder = RegistryBuilder::<Fp, TestRank>::new();
        for circuit in circuits {
            builder = builder
                .register_circuit(circuit)
                .map_err(|_| TestCaseError::reject("tree exceeds the test rank"))?;
        }
        let registry = builder.finalize().expect("registry");

        let (w, x, y) = (random(), random(), random());
        let w_in_domain = CircuitIndex::new(1).omega_j::<Fp>();
        for (w, x, y) in [(w, x, y), (w_in_domain, x, y), (w, Fp::ZERO, y), (w, x, Fp::ZERO)] {
            prop_assert_eq!(registry.wxy(w, x, y), registry.wxy_combined(w, x, y));
            prop_assert_eq!(registry.wx(w, x).eval(y), registry.wxy(w, x, y));
            prop_assert_eq!(registry.wy(w, y).eval(x), registry.wxy(w, x, y));
        }
    }
}
