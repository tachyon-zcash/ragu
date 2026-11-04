//! A circuit's public wiring, recorded once as a linear arithmetic program.
//!
//! Virtual wires remain shared nodes rather than expanded sparse matrix rows.
//! Evaluating X runs the program forwards; evaluating Y distributes constraint
//! weights backwards. Neither operation executes circuit or routine code.

use alloc::{vec, vec::Vec};
use ragu_core::{
    Coeff, Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::Bound,
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use crate::{
    DriverScope,
    floor_planner::ConstraintSegment,
    polynomials::{Rank, sparse},
    raw::RawCircuit,
};

#[derive(Clone)]
struct Expression<F: Field> {
    terms: Vec<(usize, Coeff<F>)>,
    gain: Coeff<F>,
}

impl<F: Field> Expression<F> {
    fn new() -> Self {
        Self {
            terms: Vec::new(),
            gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<usize, F> for Expression<F> {
    fn add_term(mut self, wire: &usize, coeff: Coeff<F>) -> Self {
        let coeff = coeff * self.gain;
        if !coeff.is_zero() {
            self.terms.push((*wire, coeff));
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// Temporary circuit recording. Expressions are normalized before retention.
struct Recording<F: Field, R: Rank> {
    nodes: Vec<Expression<F>>,
    constraints: Vec<(usize, Expression<F>)>,
    gates: usize,
    _rank: core::marker::PhantomData<R>,
}

/// Immutable wiring shared by all evaluations of a registered circuit.
/// Terms and ranges are contiguous; repeated nontrivial coefficients are
/// interned instead of storing a field-sized enum in every term.
pub(crate) struct Compiled<F: Field, R: Rank> {
    terms: Vec<(usize, usize)>,
    constants: Vec<F>,
    nodes: Vec<core::ops::Range<usize>>,
    constraints: Vec<(usize, core::ops::Range<usize>)>,
    gates: usize,
    _rank: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> Recording<F, R> {
    fn finish(self) -> Compiled<F, R> {
        let base = R::num_coeffs();
        // Mark nodes reachable from constraints, then count references only
        // within that live graph. Dead expressions need no evaluation.
        let mut live = vec![false; self.nodes.len()];
        for (_, row) in &self.constraints {
            for &(wire, _) in &row.terms {
                if wire >= base {
                    live[wire - base] = true;
                }
            }
        }
        for (i, node) in self.nodes.iter().enumerate().rev() {
            if live[i] {
                for &(wire, _) in &node.terms {
                    if wire >= base {
                        live[wire - base] = true;
                    }
                }
            }
        }
        let mut uses = vec![0usize; live.len()];
        for node in self
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| live[*i])
            .map(|(_, n)| n)
            .chain(self.constraints.iter().map(|(_, row)| row))
        {
            for &(wire, _) in &node.terms {
                if wire >= base {
                    uses[wire - base] += 1;
                }
            }
        }
        // Inline a node only when it has one use. This removes temporary
        // virtual wires and folds their fixed coefficients without expanding
        // shared expressions or increasing the graph's total term count.
        fn inline<F: Field>(
            row: Expression<F>,
            nodes: &mut [Option<Expression<F>>],
            uses: &[usize],
            base: usize,
        ) -> Expression<F> {
            let mut terms = Vec::new();
            for (wire, coefficient) in row.terms {
                if wire >= base && uses[wire - base] == 1 {
                    let child = nodes[wire - base]
                        .take()
                        .expect("a single-use node is consumed once");
                    for (wire, inner) in child.terms {
                        let coefficient = coefficient * inner;
                        if !coefficient.is_zero() {
                            terms.push((wire, coefficient));
                        }
                    }
                } else {
                    terms.push((wire, coefficient));
                }
            }
            Expression {
                terms,
                gain: Coeff::One,
            }
        }
        let mut normalized = Vec::with_capacity(self.nodes.len());
        for (i, node) in self.nodes.into_iter().enumerate() {
            if live[i] {
                let row = inline(node, &mut normalized, &uses, base);
                normalized.push(Some(row));
            } else {
                normalized.push(None);
            }
        }
        let mut rows = Vec::with_capacity(self.constraints.len());
        for (y, row) in self.constraints {
            rows.push((y, inline(row, &mut normalized, &uses, base)));
        }
        rows.sort_unstable_by_key(|(y, _)| *y);
        let mut program = Compiled {
            terms: Vec::new(),
            constants: Vec::new(),
            nodes: Vec::new(),
            constraints: Vec::new(),
            gates: self.gates,
            _rank: core::marker::PhantomData,
        };
        let mut pool = alloc::collections::BTreeMap::<Vec<u8>, usize>::new();
        let mut remap = vec![usize::MAX; normalized.len()];
        // Allocated wire IDs become indices in four compact gate buffers;
        // virtual IDs follow those buffers, with dead/inlined nodes removed.
        let map_wire = |wire: usize, remap: &[usize]| -> usize {
            if wire >= base {
                let mapped = remap[wire - base];
                assert_ne!(
                    mapped,
                    usize::MAX,
                    "retained nodes refer only to retained predecessors"
                );
                4 * self.gates + mapped
            } else if wire < R::n() {
                wire
            } else if wire < 2 * R::n() {
                self.gates + wire - (2 * R::n() - self.gates)
            } else if wire < 3 * R::n() {
                2 * self.gates + wire - 2 * R::n()
            } else {
                3 * self.gates + wire - (4 * R::n() - self.gates)
            }
        };
        for (i, row) in normalized.into_iter().enumerate() {
            if let Some(row) = row {
                let row = program.store(row, &mut pool, |wire| map_wire(wire, &remap));
                remap[i] = program.nodes.len();
                program.nodes.push(row);
            }
        }
        for (y, row) in rows {
            let row = program.store(row, &mut pool, |wire| map_wire(wire, &remap));
            program.constraints.push((y, row));
        }
        program
    }
}

impl<F: Field, R: Rank> Compiled<F, R> {
    fn store(
        &mut self,
        row: Expression<F>,
        pool: &mut alloc::collections::BTreeMap<Vec<u8>, usize>,
        map: impl Fn(usize) -> usize,
    ) -> core::ops::Range<usize> {
        let start = self.terms.len();
        for (wire, coefficient) in row.terms {
            let code = match coefficient {
                Coeff::One => 0,
                Coeff::NegativeOne => 1,
                Coeff::Two => 2,
                _ => {
                    let coefficient = coefficient.value();
                    if coefficient == F::ZERO {
                        continue;
                    }
                    if coefficient == F::ONE {
                        0
                    } else if coefficient == -F::ONE {
                        1
                    } else if coefficient == F::ONE.double() {
                        2
                    } else {
                        *pool
                            .entry(coefficient.to_bytes().as_ref().to_vec())
                            .or_insert_with(|| {
                                let code = self.constants.len() + 3;
                                self.constants.push(coefficient);
                                code
                            })
                    }
                }
            };
            self.terms.push((map(wire), code));
        }
        start..self.terms.len()
    }

    fn eval(&self, row: core::ops::Range<usize>, values: &[F]) -> F {
        let mut value = F::ZERO;
        let mut products = None;
        for &(wire, code) in &self.terms[row] {
            match code {
                0 => value += values[wire],
                1 => value -= values[wire],
                2 => value += values[wire].double(),
                _ => F::mul_accumulate(
                    products.get_or_insert_with(Default::default),
                    &values[wire],
                    &self.constants[code - 3],
                ),
            }
        }
        if let Some(products) = products {
            value += F::reduce(products);
        }
        value
    }

    fn distribute(&self, row: core::ops::Range<usize>, value: F, values: &mut [F]) {
        for &(wire, code) in &self.terms[row] {
            match code {
                0 => values[wire] += value,
                1 => values[wire] -= value,
                2 => values[wire] += value.double(),
                _ => values[wire] += value * self.constants[code - 3],
            }
        }
    }

    fn at_x(&self, x: F, powers: Option<&[F]>) -> Vec<F> {
        let mut values = vec![F::ZERO; 4 * self.gates + self.nodes.len()];
        for (block, start) in [
            0,
            2 * R::n() - self.gates,
            2 * R::n(),
            R::num_coeffs() - self.gates,
        ]
        .into_iter()
        .enumerate()
        {
            let block_values = &mut values[block * self.gates..(block + 1) * self.gates];
            if let Some(powers) = powers {
                block_values.copy_from_slice(&powers[start..start + self.gates]);
            } else {
                let mut power = x.pow_u64(start as u64);
                for value in block_values {
                    *value = power;
                    power *= x;
                }
            }
        }
        for (i, row) in self.nodes.iter().enumerate() {
            values[4 * self.gates + i] = self.eval(row.clone(), &values);
        }
        values
    }

    pub(crate) fn sx(&self, x: F) -> sparse::Polynomial<F, R> {
        self.sx_with_powers(x, None)
    }

    pub(crate) fn sx_with_powers(&self, x: F, powers: Option<&[F]>) -> sparse::Polynomial<F, R> {
        let values = self.at_x(x, powers);
        let len = self.constraints.last().map_or(0, |(y, _)| y + 1);
        let mut result = vec![F::ZERO; len];
        for (y, row) in &self.constraints {
            result[*y] = self.eval(row.clone(), &values);
        }
        sparse::Polynomial::from_coeffs(result)
    }

    pub(crate) fn sxy(&self, x: F, y: F) -> F {
        self.sxy_with_powers(x, y, None)
    }

    pub(crate) fn sxy_with_powers(&self, x: F, y: F, powers: Option<&[F]>) -> F {
        let values = self.at_x(x, powers);
        let mut degree = self.constraints.last().map_or(0, |(y, _)| *y);
        let mut result = F::ZERO;
        for (power, row) in self.constraints.iter().rev() {
            let gap = degree - power;
            if gap == 1 {
                result *= y;
            } else if gap > 1 {
                result *= y.pow_u64(gap as u64);
            }
            result += self.eval(row.clone(), &values);
            degree = *power;
        }
        if degree > 0 {
            result *= y.pow_u64(degree as u64);
        }
        result
    }

    pub(crate) fn sy(&self, y: F) -> sparse::Polynomial<F, R> {
        self.sy_with_powers(y, None)
    }

    pub(crate) fn sy_with_powers(&self, y: F, powers: Option<&[F]>) -> sparse::Polynomial<F, R> {
        let mut values = vec![F::ZERO; 4 * self.gates + self.nodes.len()];
        let mut degree = 0;
        let mut power = F::ONE;
        for (position, row) in &self.constraints {
            if let Some(powers) = powers {
                power = powers[*position];
            } else {
                let gap = position - degree;
                if gap == 1 {
                    power *= y;
                } else if gap > 1 {
                    power *= y.pow_u64(gap as u64);
                }
            }
            self.distribute(row.clone(), power, &mut values);
            degree = *position;
        }
        for (i, row) in self.nodes.iter().enumerate().rev() {
            self.distribute(row.clone(), values[4 * self.gates + i], &mut values);
        }
        values.truncate(4 * self.gates);
        let mut c = values.split_off(3 * self.gates);
        c.reverse();
        let a = values.split_off(2 * self.gates);
        let mut b = values.split_off(self.gates);
        b.reverse();
        let mut view = sparse::View::wiring();
        view.a = a;
        view.b = b;
        view.c = c;
        view.d = values;
        view.build()
    }
}

struct Scope {
    gates: usize,
    constraints: usize,
    start: usize,
    end: usize,
}

struct Recorder<'a, F: Field, R: Rank> {
    compiled: Recording<F, R>,
    scope: Scope,
    floor_plan: &'a [ConstraintSegment],
    routine: usize,
}

impl<F: Field, R: Rank> DriverScope<Scope> for Recorder<'_, F, R> {
    fn scope(&mut self) -> &mut Scope {
        &mut self.scope
    }
}

impl<F: Field, R: Rank> DriverTypes for Recorder<'_, F, R> {
    type MaybeKind = Empty;
    type LCadd = Expression<F>;
    type LCenforce = Expression<F>;
    type ImplField = F;
    type ImplWire = usize;
    type Extra = usize;

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(usize, usize, usize, usize)> {
        let i = self.scope.gates;
        if i >= R::n() {
            return Err(Error::GateBoundExceeded { limit: R::n() });
        }
        self.scope.gates += 1;
        self.compiled.gates = self.compiled.gates.max(i + 1);
        Ok((
            2 * R::n() + i,
            2 * R::n() - 1 - i,
            R::num_coeffs() - 1 - i,
            i,
        ))
    }

    fn assign_extra(&mut self, i: usize, _: impl Fn() -> Result<Coeff<F>>) -> Result<usize> {
        Ok(i)
    }
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Recorder<'_, F, R> {
    type F = F;
    type Wire = usize;
    const ONE: usize = 0;

    fn add(&mut self, lc: impl Fn(Expression<F>) -> Expression<F>) -> usize {
        let wire = R::num_coeffs() + self.compiled.nodes.len();
        self.compiled.nodes.push(lc(Expression::new()));
        wire
    }

    fn enforce_zero(&mut self, lc: impl Fn(Expression<F>) -> Expression<F>) -> Result<()> {
        let q = self.scope.constraints;
        if q >= R::num_coeffs() - 1 {
            return Err(Error::ConstraintBoundExceeded {
                limit: R::num_coeffs() - 1,
            });
        }
        assert!(q < self.scope.end, "constraint count must match floor plan");
        // Constraints are reversed within each routine's floor-plan segment.
        let y = self.scope.end - 1 - (q - self.scope.start);
        self.compiled.constraints.push((y, lc(Expression::new())));
        self.scope.constraints += 1;
        Ok(())
    }

    fn routine<Ro: Routine<F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.routine += 1;
        let seg = &self.floor_plan[self.routine];
        self.with_scope(
            Scope {
                gates: seg.gate_start,
                constraints: seg.constraint_start,
                start: seg.constraint_start,
                end: seg.constraint_start + seg.num_constraints,
            },
            |this| {
                let aux = Emulator::predict(&routine, &input)?.into_aux();
                let result = routine.execute(this, input, aux)?;
                assert_eq!(this.scope.gates, seg.gate_start + seg.num_gates);
                assert_eq!(
                    this.scope.constraints,
                    seg.constraint_start + seg.num_constraints
                );
                Ok(result)
            },
        )
    }
}

pub(crate) fn compile<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    floor_plan: &[ConstraintSegment],
) -> Result<Compiled<F, R>> {
    let mut recorder = Recorder {
        compiled: Recording {
            nodes: Vec::new(),
            constraints: Vec::new(),
            gates: 0,
            _rank: core::marker::PhantomData,
        },
        scope: Scope {
            gates: 0,
            constraints: 0,
            start: 0,
            end: floor_plan[0].num_constraints,
        },
        floor_plan,
        routine: 0,
    };
    crate::raw::orchestrate(&mut recorder, circuit, Empty)?;
    assert_eq!(recorder.routine + 1, floor_plan.len());
    assert_eq!(recorder.scope.gates, floor_plan[0].num_gates);
    assert_eq!(recorder.scope.constraints, floor_plan[0].num_constraints);
    Ok(recorder.compiled.finish())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Circuit, metrics, raw::CircuitAdapterRef};
    use ragu_core::pasta::Fp;

    pub(crate) fn assert_matches_interpreted<C: Circuit<Fp>, R: Rank>(circuit: &C) {
        let metrics = metrics::eval(circuit).unwrap();
        let plan = crate::floor_planner::floor_plan(&metrics.segments);
        let raw = CircuitAdapterRef(circuit);
        let compiled = compile::<_, _, R>(&raw, &plan).unwrap();
        for x in [Fp::ZERO, Fp::ONE, Fp::from(13)] {
            let sx = super::super::sx::eval::<_, _, R>(&raw, x, &plan).unwrap();
            assert!(sx.iter_coeffs().eq(compiled.sx(x).iter_coeffs()));
            for y in [Fp::ZERO, Fp::ONE, Fp::from(29)] {
                let sy = super::super::sy::eval::<_, _, R>(&raw, y, &plan).unwrap();
                assert!(sy.iter_coeffs().eq(compiled.sy(y).iter_coeffs()));
                assert_eq!(
                    super::super::sxy::eval::<_, _, R>(&raw, x, y, &plan).unwrap(),
                    compiled.sxy(x, y)
                );
            }
        }
    }

    #[test]
    fn full_rank_and_linear_circuits_match_interpreted_wiring() {
        for times in [0, 1, 10, 30] {
            assert_matches_interpreted::<_, crate::polynomials::TestRank>(
                &crate::tests::SquareCircuit { times },
            );
        }
    }

    #[test]
    fn shared_expressions_and_gains_evaluate_in_both_directions() {
        use crate::{WithAux, raw::RawCircuit};
        struct Shared;
        impl RawCircuit<Fp> for Shared {
            type Witness<'a> = ();
            type Output = ();
            type Aux<'a> = ();
            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
                &self,
                dr: &mut D,
                _: ragu_core::drivers::DriverValue<D, ()>,
            ) -> Result<WithAux<(), ragu_core::drivers::DriverValue<D, ()>>> {
                let (a, b, c, extra) = dr.gate(|| unreachable!())?;
                let d = dr.assign_extra(extra, || unreachable!())?;
                let shared = dr.add(|lc| {
                    lc.add(&a)
                        .gain(Coeff::Arbitrary(Fp::from(7)))
                        .sub(&b)
                        .add(&d)
                });
                let outer = dr.add(|lc| lc.add(&shared).gain(Coeff::Two).add(&shared).sub(&c));
                dr.enforce_zero(|lc| lc.add(&outer).sub(&shared).gain(Coeff::Zero).add(&a))?;
                dr.enforce_zero(|lc| lc.add(&shared).gain(Coeff::NegativeOne).add(&d))?;
                Ok(WithAux::new((), D::unit()))
            }
        }
        let metrics = crate::metrics::eval_raw(&Shared).unwrap();
        let plan = crate::floor_planner::floor_plan(&metrics.segments);
        let compiled = compile::<_, _, crate::polynomials::TestRank>(&Shared, &plan).unwrap();
        for x in [Fp::ZERO, Fp::ONE, Fp::from(11)] {
            let expected =
                super::super::sx::eval::<_, _, crate::polynomials::TestRank>(&Shared, x, &plan)
                    .unwrap();
            assert!(expected.iter_coeffs().eq(compiled.sx(x).iter_coeffs()));
            for y in [Fp::ZERO, Fp::ONE, Fp::from(17)] {
                let expected =
                    super::super::sy::eval::<_, _, crate::polynomials::TestRank>(&Shared, y, &plan)
                        .unwrap();
                assert!(expected.iter_coeffs().eq(compiled.sy(y).iter_coeffs()));
                assert_eq!(compiled.sxy(x, y), expected.eval(x));
            }
        }
    }
}
