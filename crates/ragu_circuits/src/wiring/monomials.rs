//! The wiring polynomial $s(X, Y)$ itself, as its nonzero monomials.
//!
//! This module provides [`eval`], which runs constraint emission with a
//! [`Driver`] whose wires are linear forms in the wire monomials of $X$ and
//! returns every nonzero coefficient of $s(X, Y)$ in a canonical order. Where
//! [`sx`], [`sy`] and [`sxy`] evaluate the polynomial at a point, this module
//! writes it down. The registry hashes the result to derive its
//! [tag](crate::registry::Tag).
//!
//! # Design
//!
//! The wires of gate $i$ are the monomials $X^{2n+i}$, $X^{2n-1-i}$,
//! $X^{4n-1-i}$ and $X^i$ (see [`sparse::View`]). [`Driver::add`] combines
//! wires into a linear form, and [`Driver::enforce_zero`] records a form as the
//! coefficient of $Y^q$, where $q$ is the constraint's absolute index under the
//! floor plan: the same assignment [`sx`] and [`sy`] make, with the first
//! constraint emitted in a segment taking the segment's highest power.
//!
//! Every form is kept canonical (terms sorted by degree, duplicates merged,
//! zeros dropped), so the output is a function of the polynomial alone. Two
//! circuits with the same wiring polynomial yield the same [`Monomials`]
//! whatever the shape of the `add` and `enforce_zero` calls that emitted them,
//! and distinct polynomials yield distinct ones.
//!
//! [`Driver`]: ragu_core::drivers::Driver
//! [`Driver::add`]: ragu_core::drivers::Driver::add
//! [`Driver::enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [`sparse::View`]: crate::polynomials::sparse::View
//! [`sx`]: super::sx
//! [`sy`]: super::sy
//! [`sxy`]: super::sxy

use alloc::{rc::Rc, vec::Vec};

use ragu_core::{
    Coeff, Error, Result,
    drivers::{Driver, DriverTypes, LinearExpression, emulator::Emulator},
    gadgets::Bound,
    maybe::Empty,
    routines::Routine,
};
use udon::field::Field;

use crate::{DriverScope, floor_planner::ConstraintSegment, polynomials::Rank, raw::RawCircuit};

/// A nonzero coefficient of $s(X, Y)$: `coeff` times $X^x Y^y$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Monomial<F> {
    /// The power of $Y$: the constraint's absolute index.
    pub y: usize,
    /// The power of $X$: the wire's degree in the wiring layout.
    pub x: usize,
    /// The coefficient, which is never zero.
    pub coeff: F,
}

/// The nonzero monomials of a wiring polynomial, in increasing $(y, x)$ order.
///
/// This is the polynomial written out: the sequence determines $s(X, Y)$ and
/// $s(X, Y)$ determines the sequence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Monomials<F>(Vec<Monomial<F>>);

impl<F: Field> Monomials<F> {
    /// Wraps monomials that are already in increasing $(y, x)$ order with
    /// nonzero coefficients.
    pub(crate) fn new(monomials: Vec<Monomial<F>>) -> Self {
        debug_assert!(
            monomials
                .windows(2)
                .all(|pair| (pair[0].y, pair[0].x) < (pair[1].y, pair[1].x)),
            "monomials must be strictly increasing in (y, x)"
        );
        debug_assert!(
            monomials.iter().all(|m| !m.coeff.is_zero()),
            "monomials must have nonzero coefficients"
        );
        Self(monomials)
    }

    /// The monomials, in increasing $(y, x)$ order.
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &Monomial<F>> {
        self.0.iter()
    }

    /// Absorbs the polynomial into a BLAKE2b state: the number of monomials,
    /// then each monomial's $y$ and $x$ as little-endian `u64` and its
    /// coefficient in canonical bytes.
    ///
    /// Every item is fixed-width or length-prefixed, so distinct polynomials
    /// absorb distinct byte strings and the encoding is self-delimiting.
    pub(crate) fn hash_into(&self, state: &mut blake2b_simd::State) {
        state.update(&(self.0.len() as u64).to_le_bytes());
        for m in &self.0 {
            state.update(&(m.y as u64).to_le_bytes());
            state.update(&(m.x as u64).to_le_bytes());
            state.update(m.coeff.to_bytes().as_ref());
        }
    }

    /// Removes the `ONE` constraint, the monomial $X^0 Y^0$ with coefficient
    /// one, turning a circuit wiring polynomial into a bonding polynomial.
    ///
    /// # Panics
    ///
    /// Panics if the constant term is anything but that monomial, which cannot
    /// happen for a polynomial [`eval`] produced: [`orchestrate`] emits the
    /// `ONE` constraint last, so it occupies $Y^0$ alone.
    ///
    /// [`orchestrate`]: crate::raw::orchestrate
    pub(crate) fn strip_one(&mut self) {
        let one = self.0.first().expect("the ONE constraint is present");
        assert_eq!(
            (one.y, one.x, one.coeff),
            (0, 0, F::ONE),
            "the constant term must be the ONE constraint"
        );
        self.0.remove(0);
        assert!(
            self.0.first().is_none_or(|m| m.y > 0),
            "the ONE constraint occupies Y^0 alone"
        );
    }

    /// Evaluates the polynomial at $(x, y)$.
    #[cfg(test)]
    pub(crate) fn eval(&self, x: F, y: F) -> F {
        self.0
            .iter()
            .map(|m| m.coeff * x.pow_u64(m.x as u64) * y.pow_u64(m.y as u64))
            .fold(F::ZERO, |acc, term| acc + term)
    }
}

/// A wire: a linear form in the wire monomials of $X$.
#[derive(Clone)]
enum Wire<F> {
    /// A gate wire, the monomial $X^{\text{degree}}$.
    Monomial(usize),
    /// A virtual wire from [`Driver::add`]: a canonical linear form.
    ///
    /// [`Driver::add`]: ragu_core::drivers::Driver::add
    Form(Rc<[(usize, F)]>),
}

/// Scales `value` by a coefficient, sparing the multiplication for the unit
/// coefficients.
fn scale<F: Field>(value: F, coeff: Coeff<F>) -> F {
    match coeff {
        Coeff::One => value,
        Coeff::NegativeOne => -value,
        coeff => value * coeff.value(),
    }
}

/// Sorts a form's terms by degree, merges duplicates and drops zeros.
fn canonical<F: Field>(mut terms: Vec<(usize, F)>) -> Vec<(usize, F)> {
    terms.sort_unstable_by_key(|&(x, _)| x);
    let mut form: Vec<(usize, F)> = Vec::with_capacity(terms.len());
    for (x, coeff) in terms {
        match form.last_mut() {
            Some((last, sum)) if *last == x => *sum += coeff,
            _ => form.push((x, coeff)),
        }
    }
    form.retain(|(_, coeff)| !coeff.is_zero());
    form
}

/// Collects the terms of a linear combination, expanding virtual wires into
/// their monomials.
struct Terms<F: Field> {
    terms: Vec<(usize, F)>,
    gain: Coeff<F>,
}

impl<F: Field> Terms<F> {
    fn new() -> Self {
        Self {
            terms: Vec::new(),
            gain: Coeff::One,
        }
    }

    /// The collected terms as a canonical form.
    fn canonical(self) -> Vec<(usize, F)> {
        canonical(self.terms)
    }
}

impl<F: Field> LinearExpression<Wire<F>, F> for Terms<F> {
    fn add_term(mut self, wire: &Wire<F>, coeff: Coeff<F>) -> Self {
        let coeff = coeff * self.gain;
        if coeff.is_zero() {
            return self;
        }
        match wire {
            Wire::Monomial(x) => self.terms.push((*x, coeff.value())),
            Wire::Form(form) => self
                .terms
                .extend(form.iter().map(|&(x, value)| (x, scale(value, coeff)))),
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
    /// The power of $Y$ the next constraint takes: a segment's constraints
    /// take decreasing powers from its last index down to its first.
    y: usize,
}

impl Scope {
    fn new(gates: usize, constraints: usize, num_constraints: usize) -> Self {
        Self {
            gates,
            constraints,
            // Never read when the segment has no constraints.
            y: (constraints + num_constraints).saturating_sub(1),
        }
    }
}

/// A [`Driver`] that writes down $s(X, Y)$.
///
/// Gate wires are monomials in $X$, linear combinations are canonical forms in
/// those monomials, and each constraint contributes its form at the power of
/// $Y$ the floor plan assigns it.
///
/// [`Driver`]: ragu_core::drivers::Driver
struct Evaluator<'fp, F, R> {
    /// Per-routine scoped state.
    scope: Scope,

    /// Every nonzero coefficient recorded so far, in emission order.
    monomials: Vec<Monomial<F>>,

    /// Floor plan mapping DFS segment index to absolute offsets.
    floor_plan: &'fp [ConstraintSegment],

    /// Global monotonic DFS counter for routine entries.
    current_routine: usize,

    /// Marker for the rank type parameter.
    _marker: core::marker::PhantomData<R>,
}

impl<F: Field, R: Rank> DriverScope<Scope> for Evaluator<'_, F, R> {
    fn scope(&mut self) -> &mut Scope {
        &mut self.scope
    }
}

impl<F: Field, R: Rank> DriverTypes for Evaluator<'_, F, R> {
    type MaybeKind = Empty;
    type LCadd = Terms<F>;
    type LCenforce = Terms<F>;
    type ImplField = F;
    type ImplWire = Wire<F>;
    type Extra = usize;

    /// Consumes a gate, returning its $(a, b, c)$ monomials and its index as
    /// [`Extra`](DriverTypes::Extra), from which [`assign_extra`] forms the
    /// $d$ monomial.
    ///
    /// # Errors
    ///
    /// Returns [`Error::GateBoundExceeded`] if the gate count reaches
    /// [`Rank::n()`].
    ///
    /// [`assign_extra`]: DriverTypes::assign_extra
    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(Wire<F>, Wire<F>, Wire<F>, usize)> {
        let i = self.scope.gates;
        let n = R::n();
        if i == n {
            return Err(Error::GateBoundExceeded { limit: n });
        }
        self.scope.gates += 1;

        Ok((
            Wire::Monomial(2 * n + i),
            Wire::Monomial(2 * n - 1 - i),
            Wire::Monomial(4 * n - 1 - i),
            i,
        ))
    }

    fn assign_extra(&mut self, i: usize, _: impl Fn() -> Result<Coeff<F>>) -> Result<Wire<F>> {
        Ok(Wire::Monomial(i))
    }
}

impl<'dr, F: Field, R: Rank> Driver<'dr> for Evaluator<'_, F, R> {
    type F = F;
    type Wire = Wire<F>;

    /// The $d$ wire of the SYSTEM gate, $X^0$.
    const ONE: Self::Wire = Wire::Monomial(0);

    /// Combines wires into a canonical linear form.
    fn add(&mut self, lc: impl Fn(Self::LCadd) -> Self::LCadd) -> Self::Wire {
        Wire::Form(Rc::from(lc(Terms::new()).canonical()))
    }

    /// Records the constraint's form as the coefficient of $Y^q$ for the
    /// constraint's absolute index $q$.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConstraintBoundExceeded`] if the constraint count
    /// reaches `Rank::num_coeffs() - 1` (the last slot is reserved for the
    /// registry tag constraint).
    fn enforce_zero(&mut self, lc: impl Fn(Self::LCenforce) -> Self::LCenforce) -> Result<()> {
        if self.scope.constraints >= R::num_coeffs() - 1 {
            return Err(Error::ConstraintBoundExceeded {
                limit: R::num_coeffs() - 1,
            });
        }
        self.scope.constraints += 1;
        let y = self.scope.y;
        self.scope.y = y.saturating_sub(1);

        let form = lc(Terms::new()).canonical();
        self.monomials
            .extend(form.into_iter().map(|(x, coeff)| Monomial { y, x, coeff }));

        Ok(())
    }

    fn routine<Ro: Routine<Self::F> + 'dr>(
        &mut self,
        routine: Ro,
        input: Bound<'dr, Self, Ro::Input>,
    ) -> Result<Bound<'dr, Self, Ro::Output>> {
        self.current_routine += 1;
        let seg = &self.floor_plan[self.current_routine];

        // Jump to this routine's absolute position in the polynomial; see
        // "Polynomial Encoding and Scope Jumps" in the `wiring` module doc.
        let init_scope = Scope::new(seg.gate_start, seg.constraint_start, seg.num_constraints);

        self.with_scope(init_scope, |this| {
            let aux = Emulator::predict(&routine, &input)?.into_aux();
            let result = routine.execute(this, input, aux)?;

            // Verify this routine consumed exactly the expected constraints.
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

/// Writes down the wiring polynomial $s(X, Y)$ as its nonzero monomials.
///
/// See the [module documentation][`self`] for the layout.
///
/// # Arguments
///
/// - `circuit`: The circuit whose wiring polynomial to write down.
/// - `floor_plan`: Per-segment absolute offsets, computed by
///   [`floor_plan()`](crate::floor_planner::floor_plan).
pub fn eval<F: Field, RC: RawCircuit<F>, R: Rank>(
    circuit: &RC,
    floor_plan: &[ConstraintSegment],
) -> Result<Monomials<F>> {
    let root = &floor_plan[0];
    let mut evaluator = Evaluator::<F, R> {
        scope: Scope::new(0, 0, root.num_constraints),
        monomials: Vec::new(),
        floor_plan,
        current_routine: 0,
        _marker: core::marker::PhantomData,
    };

    crate::raw::orchestrate(&mut evaluator, circuit, Empty)?;

    // Verify all floor plan segments were consumed and counts match.
    assert_eq!(
        evaluator.current_routine + 1,
        evaluator.floor_plan.len(),
        "floor plan routine count must match constraint emission"
    );
    assert_eq!(
        evaluator.scope.gates, evaluator.floor_plan[0].num_gates,
        "root gate count must match floor plan"
    );
    assert_eq!(
        evaluator.scope.constraints, evaluator.floor_plan[0].num_constraints,
        "root constraint count must match floor plan"
    );

    // Segments occupy disjoint ranges of Y-powers and each form is canonical,
    // so every (y, x) occurs once; ordering them is all that remains.
    let mut monomials = evaluator.monomials;
    monomials.sort_unstable_by_key(|m| (m.y, m.x));
    Ok(Monomials::new(monomials))
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::Fp;
    use rand::Rng;
    use udon::field::Field;

    use super::Monomials;
    use crate::{
        WiringObject, floor_planner, into_wiring_object,
        polynomials::{Rank, TestRank},
        tests::SquareCircuit,
    };

    fn object(times: usize) -> alloc::boxed::Box<dyn WiringObject<Fp, TestRank>> {
        into_wiring_object::<_, _, TestRank>(SquareCircuit { times }).unwrap()
    }

    fn monomials(obj: &dyn WiringObject<Fp, TestRank>) -> Monomials<Fp> {
        obj.monomials(&floor_planner::floor_plan(obj.segment_records()))
    }

    #[test]
    fn agrees_with_the_evaluators() {
        for times in [0, 1, 2, 5, 10] {
            let obj = object(times);
            let plan = floor_planner::floor_plan(obj.segment_records());
            let monomials = obj.monomials(&plan);
            for _ in 0..4 {
                let x = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
                let y = Fp::random(|bytes| rand::rng().fill_bytes(bytes));
                assert_eq!(monomials.eval(x, y), obj.sxy(x, y, &plan));
                assert_eq!(monomials.eval(x, y), obj.sx(x, &plan).eval(y));
                assert_eq!(monomials.eval(x, y), obj.sy(y, &plan).eval(x));
            }
            // Every monomial lies within the polynomial's degree bounds.
            assert!(monomials.iter().all(|m| m.x < 4 * TestRank::n()));
            assert!(monomials.iter().all(|m| m.y < TestRank::num_coeffs() - 1));
        }
    }

    #[test]
    fn is_a_function_of_the_polynomial() {
        for (i, j) in [(0, 0), (3, 3), (0, 1), (2, 5)] {
            let (a, b) = (monomials(&*object(i)), monomials(&*object(j)));
            assert_eq!(a == b, i == j, "SquareCircuit {i} vs {j}");
        }
    }

    #[test]
    fn starts_with_the_one_constraint() {
        let mut monomials = monomials(&*object(3));
        let first = *monomials.iter().next().unwrap();
        assert_eq!((first.y, first.x, first.coeff), (0, 0, Fp::ONE));
        let before = monomials.iter().len();
        monomials.strip_one();
        assert_eq!(monomials.iter().len(), before - 1);
        assert!(monomials.iter().all(|m| m.y > 0));
    }

    #[test]
    fn hash_is_self_delimiting() {
        let digest = |m: &Monomials<Fp>| {
            let mut state = blake2b_simd::Params::new().to_state();
            m.hash_into(&mut state);
            state.finalize()
        };
        let a = monomials(&*object(2));
        let b = monomials(&*object(3));
        assert_ne!(digest(&a), digest(&b));
        // Absorbing two polynomials in either order distinguishes the orders.
        let both = |first: &Monomials<Fp>, second: &Monomials<Fp>| {
            let mut state = blake2b_simd::Params::new().to_state();
            first.hash_into(&mut state);
            second.hash_into(&mut state);
            state.finalize()
        };
        assert_ne!(both(&a, &b), both(&b, &a));
    }
}
