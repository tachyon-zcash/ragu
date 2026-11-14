//! The wiring polynomial $s(X, Y)$ as an explicit sparse matrix.
//!
//! [`sx`](super::sx), [`sy`](super::sy) and [`sxy`](super::sxy) evaluate the
//! wiring polynomial by interpreting the circuit, which repeats the whole
//! synthesis for every evaluation point. A circuit's constraints do not
//! depend on the point, so this module interprets the circuit once, with
//! wires standing for the monomials $X^i$ themselves rather than for their
//! values, and keeps the result: for every constraint $q$, the terms
//! $u \cdot X^i$ whose sum is the coefficient of $Y^q$.
//!
//! A [`Matrix`] then evaluates any restriction with one pass over its terms.
//! It holds the same polynomial as the interpreting evaluators, so its
//! restrictions are equal to theirs as polynomials.
//!
//! The driver follows [`sx`](super::sx): constraints are stored in emission
//! order within each floor-plan segment and reversed at the end, and a
//! routine jumps to its segment's gate and constraint offsets.

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

/// A wire of the extracting driver: a monomial $X^i$ or a linear combination
/// of monomials recorded earlier.
#[derive(Clone, Copy)]
pub(crate) enum Symbol {
    /// The monomial $X^i$.
    Monomial(u32),
    /// The combination with this index in the driver's table.
    Combination(u32),
}

/// A linear combination under construction: its terms as written, expanded
/// by the driver once the expression is complete.
pub(crate) struct Terms<F: Field> {
    terms: Vec<(Symbol, F)>,
    gain: Coeff<F>,
}

impl<F: Field> Default for Terms<F> {
    fn default() -> Self {
        Self {
            terms: Vec::new(),
            gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<Symbol, F> for Terms<F> {
    fn add_term(mut self, wire: &Symbol, coeff: Coeff<F>) -> Self {
        let coeff = coeff * self.gain;
        if !coeff.is_zero() {
            self.terms.push((*wire, coeff.value()));
        }
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}

/// Per-routine state saved and restored across routine boundaries.
struct Scope {
    /// Absolute index of the next gate.
    gates: usize,
    /// Absolute index of the next constraint.
    constraints: usize,
}

/// A [`Driver`] that records every constraint as a combination of monomials.
struct Extractor<'fp, F: Field, R: Rank> {
    /// The terms of each constraint, by absolute constraint index.
    rows: Vec<Vec<(u32, F)>>,
    /// The combinations [`Driver::add`] has produced.
    combinations: Vec<Vec<(u32, F)>>,
    scope: Scope,
    floor_plan: &'fp [ConstraintSegment],
    current_routine: usize,
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> Extractor<'_, F, R> {
    /// Expands `terms` into monomials, merging repeated ones and dropping
    /// those that cancel.
    fn expand(&self, terms: Vec<(Symbol, F)>) -> Vec<(u32, F)> {
        let mut expanded = Vec::with_capacity(terms.len());
        for (symbol, coeff) in terms {
            match symbol {
                Symbol::Monomial(degree) => expanded.push((degree, coeff)),
                Symbol::Combination(index) => expanded.extend(
                    self.combinations[index as usize]
                        .iter()
                        .map(|(degree, inner)| (*degree, *inner * coeff)),
                ),
            }
        }
        expanded.sort_unstable_by_key(|(degree, _)| *degree);
        let mut merged: Vec<(u32, F)> = Vec::with_capacity(expanded.len());
        for (degree, coeff) in expanded {
            match merged.last_mut() {
                Some((last, sum)) if *last == degree => *sum += coeff,
                _ => merged.push((degree, coeff)),
            }
        }
        merged.retain(|(_, coeff)| !coeff.is_zero());
        merged
    }
}

impl<F: Field, R: Rank> DriverScope<Scope> for Extractor<'_, F, R> {
    fn scope(&mut self) -> &mut Scope {
        &mut self.scope
    }
}

impl<F: Field, R: Rank> DriverTypes for Extractor<'_, F, R> {
    type MaybeKind = Empty;
    type LCadd = Terms<F>;
    type LCenforce = Terms<F>;
    type ImplField = F;
    type ImplWire = Symbol;
    type Extra = u32;

    /// Consumes a gate, returning the monomials of its $a$, $b$ and $c$
    /// wires and the gate index, from which
    /// [`assign_extra`](DriverTypes::assign_extra) derives the $d$ wire.
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Symbol, Symbol, Symbol, u32)> {
        let index = self.scope.gates;
        if index == R::n() {
            return Err(Error::GateBoundExceeded { limit: R::n() });
        }
        self.scope.gates += 1;

        let n = R::n();
        Ok((
            Symbol::Monomial((2 * n + index) as u32),
            Symbol::Monomial((2 * n - 1 - index) as u32),
            Symbol::Monomial((4 * n - 1 - index) as u32),
            index as u32,
        ))
    }

    fn assign_extra(&mut self, gate: u32, _: impl Fn() -> Result<Coeff<F>>) -> Result<Symbol> {
        Ok(Symbol::Monomial(gate))
    }
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Extractor<'_, F, R> {
    type F = F;
    type Wire = Symbol;

    /// The `ONE` wire is the $d$ wire of gate zero, at $X^0$.
    const ONE: Self::Wire = Symbol::Monomial(0);

    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        let combination = self.expand(lc(Terms::default()).terms);
        self.combinations.push(combination);
        Symbol::Combination((self.combinations.len() - 1) as u32)
    }

    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        let q = self.scope.constraints;
        if q >= R::num_coeffs() - 1 {
            return Err(Error::ConstraintBoundExceeded {
                limit: R::num_coeffs() - 1,
            });
        }
        self.scope.constraints += 1;

        self.rows[q] = self.expand(lc(Terms::default()).terms);

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let seg = &self.floor_plan[self.current_routine];
        let init_scope = Scope {
            gates: seg.gate_start,
            constraints: seg.constraint_start,
        };

        self.with_scope(init_scope, |this| {
            let aux = Emulator::predict(&routine, &input)?.into_aux();
            let result = routine.execute(this, input, aux)?;

            assert_eq!(
                this.scope.gates,
                seg.gate_start + seg.num_gates,
                "routine gate count must match floor plan"
            );
            assert_eq!(
                this.scope.constraints,
                seg.constraint_start + seg.num_constraints,
                "routine constraint count must match floor plan"
            );

            Ok(result)
        })
    }
}

/// The wiring polynomial of one circuit: for each constraint $q$, in order,
/// the terms $u \cdot X^i$ of the coefficient of $Y^q$, sorted by degree.
pub struct Matrix<F> {
    /// `starts[q]..starts[q + 1]` are constraint `q`'s terms.
    starts: Vec<u32>,
    degrees: Vec<u32>,
    values: Vec<F>,
}

impl<F: Field> Matrix<F> {
    /// Interprets `circuit` once and records its constraints.
    pub(crate) fn extract<RC: RawCircuit<F>, R: Rank>(
        circuit: &RC,
        floor_plan: &[ConstraintSegment],
    ) -> Result<Self> {
        let mut extractor = Extractor::<F, R> {
            rows: vec![Vec::new(); R::num_coeffs()],
            combinations: Vec::new(),
            scope: Scope {
                gates: 0,
                constraints: 0,
            },
            floor_plan,
            current_routine: 0,
            _marker: core::marker::PhantomData,
        };

        crate::raw::orchestrate(&mut extractor, circuit, Empty)?;

        assert_eq!(
            extractor.current_routine + 1,
            extractor.floor_plan.len(),
            "floor plan routine count must match constraint emission"
        );
        assert_eq!(
            extractor.scope.gates, extractor.floor_plan[0].num_gates,
            "root gate count must match floor plan"
        );
        assert_eq!(
            extractor.scope.constraints, extractor.floor_plan[0].num_constraints,
            "root constraint count must match floor plan"
        );

        // Canonical constraint order within each segment, as in `sx`.
        for seg in extractor.floor_plan {
            extractor.rows[seg.constraint_start..seg.constraint_start + seg.num_constraints]
                .reverse();
        }

        // Trailing constraints with no terms are not stored.
        let used = extractor
            .rows
            .iter()
            .rposition(|row| !row.is_empty())
            .map_or(0, |last| last + 1);
        let mut starts = Vec::with_capacity(used + 1);
        let mut degrees = Vec::new();
        let mut values = Vec::new();
        starts.push(0);
        for row in &extractor.rows[..used] {
            for (degree, value) in row {
                degrees.push(*degree);
                values.push(*value);
            }
            starts.push(degrees.len() as u32);
        }
        Ok(Self {
            starts,
            degrees,
            values,
        })
    }

    /// The matrix of a polynomial in the product $XY$ alone, from its
    /// coefficients by power of $XY$: `coefficients` yields the coefficient
    /// of $(XY)^k$ at position $k$.
    pub(crate) fn diagonal(coefficients: impl Iterator<Item = F>) -> Self {
        let mut starts = vec![0];
        let mut degrees = Vec::new();
        let mut values = Vec::new();
        for (k, value) in coefficients.enumerate() {
            if value != F::ZERO {
                degrees.push(k as u32);
                values.push(value);
            }
            starts.push(degrees.len() as u32);
        }
        Self {
            starts,
            degrees,
            values,
        }
    }

    /// The number of stored terms.
    pub fn len(&self) -> usize {
        self.degrees.len()
    }

    /// Whether the polynomial is zero.
    pub fn is_empty(&self) -> bool {
        self.degrees.is_empty()
    }

    /// Every term $u \cdot X^i Y^q$ as `(q, i, u)`, by constraint.
    pub fn terms(&self) -> impl Iterator<Item = (u32, u32, &F)> {
        self.starts.windows(2).zip(0u32..).flat_map(|(bounds, q)| {
            let range = bounds[0] as usize..bounds[1] as usize;
            self.degrees[range.clone()]
                .iter()
                .zip(&self.values[range])
                .map(move |(degree, value)| (q, *degree, value))
        })
    }

    /// Removes the `ONE` wire's constraint, the term $X^0 Y^0$ with
    /// coefficient one that every circuit's matrix begins with.
    pub(crate) fn without_one(mut self) -> Self {
        assert!(
            self.starts.len() > 1
                && self.starts[1] == 1
                && self.degrees[0] == 0
                && self.values[0] == F::ONE,
            "the first constraint is the ONE wire's"
        );
        self.degrees.remove(0);
        self.values.remove(0);
        for start in &mut self.starts[1..] {
            *start -= 1;
        }
        self
    }

    fn rows(&self) -> impl Iterator<Item = (&[u32], &[F])> {
        self.starts.windows(2).map(|bounds| {
            let range = bounds[0] as usize..bounds[1] as usize;
            (&self.degrees[range.clone()], &self.values[range])
        })
    }

    /// Computes $s(X, y)$.
    pub(crate) fn sy<R: Rank>(&self, y: F) -> sparse::Polynomial<F, R> {
        let mut coeffs = vec![F::ZERO; R::num_coeffs()];
        let mut power = F::ONE;
        for (degrees, values) in self.rows() {
            for (degree, value) in degrees.iter().zip(values) {
                coeffs[*degree as usize] += *value * power;
            }
            power *= y;
        }
        sparse::Polynomial::from_coeffs(coeffs)
    }

    /// Computes $s(x, Y)$.
    pub(crate) fn sx<R: Rank>(&self, x: F) -> sparse::Polynomial<F, R> {
        let powers = powers::<F, R>(x);
        let mut coeffs = vec![F::ZERO; R::num_coeffs()];
        for (coeff, (degrees, values)) in coeffs.iter_mut().zip(self.rows()) {
            let mut sum = F::Accumulator::default();
            for (degree, value) in degrees.iter().zip(values) {
                F::mul_accumulate(&mut sum, value, &powers[*degree as usize]);
            }
            *coeff = F::reduce(sum);
        }
        sparse::Polynomial::from_coeffs(coeffs)
    }

    /// Computes $s(x, y)$.
    pub(crate) fn sxy<R: Rank>(&self, x: F, y: F) -> F {
        let powers = powers::<F, R>(x);
        let mut total = F::ZERO;
        // Horner in `y` over the constraints, highest first.
        let rows: Vec<_> = self.rows().collect();
        for (degrees, values) in rows.into_iter().rev() {
            let mut sum = F::Accumulator::default();
            for (degree, value) in degrees.iter().zip(values) {
                F::mul_accumulate(&mut sum, value, &powers[*degree as usize]);
            }
            total = total * y + F::reduce(sum);
        }
        total
    }
}

/// The powers $x^0, \ldots, x^{4n - 1}$.
fn powers<F: Field, R: Rank>(x: F) -> Vec<F> {
    let mut powers = Vec::with_capacity(R::num_coeffs());
    let mut power = F::ONE;
    for _ in 0..R::num_coeffs() {
        powers.push(power);
        power *= x;
    }
    powers
}
