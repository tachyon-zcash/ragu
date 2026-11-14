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
    ///
    /// # Panics
    ///
    /// Panics if a power $X^x Y^y$ repeats or is out of order, or if a
    /// coefficient is zero: the sequence would no longer be a function of the
    /// polynomial, which the registry tag relies on.
    pub(crate) fn new(monomials: Vec<Monomial<F>>) -> Self {
        assert!(
            monomials
                .windows(2)
                .all(|pair| (pair[0].y, pair[0].x) < (pair[1].y, pair[1].x)),
            "monomials must be strictly increasing in (y, x)"
        );
        assert!(
            monomials.iter().all(|m| !m.coeff.is_zero()),
            "monomials must have nonzero coefficients"
        );
        Self(monomials)
    }

    /// The polynomial whose every term is a power of $XY$: the coefficient
    /// of $(XY)^k$ is the `k`-th of `coeffs`.
    pub(crate) fn diagonal(coeffs: impl Iterator<Item = F>) -> Self {
        Self::new(
            coeffs
                .enumerate()
                .filter(|(_, coeff)| !coeff.is_zero())
                .map(|(k, coeff)| Monomial { y: k, x: k, coeff })
                .collect(),
        )
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

/// A [`Driver`] that writes down the monomials of $s(X, Y)$.
///
/// Gate wires are monomials in $X$, linear combinations are canonical forms in
/// those monomials, and each constraint contributes its form as the
/// coefficient of the power of $Y$ the floor plan assigns it.
///
/// [`Driver`]: ragu_core::drivers::Driver
struct Evaluator<'fp, F, R> {
    /// Per-routine scoped state.
    scope: Scope,

    /// The monomials written so far, in emission order.
    monomials: Vec<Monomial<F>>,

    /// Floor plan mapping DFS segment index to absolute offsets.
    floor_plan: &'fp [ConstraintSegment],

    /// Global monotonic DFS counter for routine entries.
    current_routine: usize,

    /// Marker for the field and rank type parameters.
    _marker: core::marker::PhantomData<(F, R)>,
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

        self.monomials.extend(
            lc(Terms::new())
                .canonical()
                .into_iter()
                .map(|(x, coeff)| Monomial { y, x, coeff }),
        );

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
    // Routines are covered by `crate::tests::consistency_checks`, which
    // compares the written polynomial with `sxy`, `sx` and `sy` for every test
    // circuit, including the random routine trees of `tests::segment_order`.

    use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
    use core::marker::PhantomData;

    use ragu_core::{
        Coeff, Error, Result,
        drivers::{Driver, DriverTypes, LinearExpression},
        pasta::Fp,
    };
    use rand::Rng;
    use udon::field::Field;

    use super::{Evaluator, Monomial, Monomials, Scope, Terms, Wire, canonical, scale};
    use crate::{
        WiringObject, floor_planner, into_wiring_object,
        polynomials::{Rank, TestRank},
        raw::CircuitAdapter,
        tests::SquareCircuit,
    };

    impl<F: Field> Monomials<F> {
        /// The monomials, in increasing $(y, x)$ order.
        pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &Monomial<F>> {
            self.0.iter()
        }

        /// Evaluates the polynomial at $(x, y)$.
        pub(crate) fn eval(&self, x: F, y: F) -> F {
            self.0
                .iter()
                .map(|m| m.coeff * x.pow_u64(m.x as u64) * y.pow_u64(m.y as u64))
                .fold(F::ZERO, |acc, term| acc + term)
        }
    }

    type Ev = Evaluator<'static, Fp, TestRank>;

    fn term(y: usize, x: usize, coeff: Fp) -> Monomial<Fp> {
        Monomial { y, x, coeff }
    }

    fn object(times: usize) -> Box<dyn WiringObject<Fp, TestRank>> {
        into_wiring_object::<_, _, TestRank>(SquareCircuit { times }).unwrap()
    }

    /// The wiring polynomial of `SquareCircuit { times }`, written down.
    fn monomials(times: usize) -> Monomials<Fp> {
        let obj = object(times);
        obj.monomials(&floor_planner::floor_plan(obj.segment_records()))
    }

    /// An evaluator over one segment of `num_constraints` constraints.
    fn evaluator(num_constraints: usize) -> Ev {
        Evaluator {
            scope: Scope::new(0, 0, num_constraints),
            monomials: Vec::new(),
            floor_plan: &[],
            current_routine: 0,
            _marker: PhantomData,
        }
    }

    /// Runs `body` on an evaluator over one segment of `num_constraints`
    /// constraints and writes down what it emitted.
    fn emit(num_constraints: usize, body: impl FnOnce(&mut Ev) -> Result<()>) -> Monomials<Fp> {
        let mut evaluator = evaluator(num_constraints);
        body(&mut evaluator).unwrap();
        let mut monomials = evaluator.monomials;
        monomials.sort_unstable_by_key(|m| (m.y, m.x));
        Monomials::new(monomials)
    }

    fn zero_gate() -> Result<(Coeff<Fp>, Coeff<Fp>, Coeff<Fp>)> {
        Ok((Coeff::Zero, Coeff::Zero, Coeff::Zero))
    }

    /// Allocates a gate, returning its $a$, $b$ and $c$ wires.
    fn gate(evaluator: &mut Ev) -> (Wire<Fp>, Wire<Fp>, Wire<Fp>) {
        let (a, b, c, _) = DriverTypes::gate(evaluator, zero_gate).unwrap();
        (a, b, c)
    }

    fn degree(wire: &Wire<Fp>) -> usize {
        match wire {
            Wire::Monomial(degree) => *degree,
            Wire::Form(_) => panic!("a gate wire is a monomial"),
        }
    }

    fn digest(polynomials: &[&Monomials<Fp>]) -> blake2b_simd::Hash {
        let mut state = blake2b_simd::Params::new().to_state();
        for polynomial in polynomials {
            polynomial.hash_into(&mut state);
        }
        state.finalize()
    }

    #[test]
    fn new_accepts_increasing_nonzero_monomials() {
        assert_eq!(Monomials::<Fp>::new(vec![]).iter().len(), 0);
        let written = Monomials::new(vec![
            term(0, 5, Fp::ONE),
            term(1, 2, Fp::ONE),
            term(1, 3, -Fp::ONE),
        ]);
        assert_eq!(written.iter().len(), 3);
    }

    #[test]
    #[should_panic(expected = "strictly increasing in (y, x)")]
    fn new_rejects_a_repeated_power() {
        let _ = Monomials::new(vec![term(1, 2, Fp::ONE), term(1, 2, Fp::ONE)]);
    }

    #[test]
    #[should_panic(expected = "strictly increasing in (y, x)")]
    fn new_rejects_monomials_out_of_order() {
        let _ = Monomials::new(vec![term(2, 0, Fp::ONE), term(1, 9, Fp::ONE)]);
    }

    #[test]
    #[should_panic(expected = "nonzero coefficients")]
    fn new_rejects_a_zero_coefficient() {
        let _ = Monomials::new(vec![term(0, 0, Fp::ZERO)]);
    }

    #[test]
    fn diagonal_is_the_diagonal_polynomial() {
        let coeffs = [Fp::ZERO, Fp::ONE, Fp::ZERO, -Fp::ONE];
        assert_eq!(
            Monomials::diagonal(coeffs.into_iter()),
            Monomials::new(vec![term(1, 1, Fp::ONE), term(3, 3, -Fp::ONE)])
        );
        assert_eq!(
            Monomials::diagonal(core::iter::empty::<Fp>()),
            Monomials::default()
        );
        assert_eq!(
            Monomials::diagonal([Fp::ZERO; 4].into_iter()),
            Monomials::default()
        );
    }

    #[test]
    fn hash_absorbs_the_documented_encoding() {
        let written = Monomials::new(vec![term(0, 0, Fp::ONE), term(2, 7, -Fp::from(3))]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        for (y, x, coeff) in [(0u64, 0u64, Fp::ONE), (2, 7, -Fp::from(3))] {
            bytes.extend_from_slice(&y.to_le_bytes());
            bytes.extend_from_slice(&x.to_le_bytes());
            bytes.extend_from_slice(coeff.to_bytes().as_ref());
        }
        assert_eq!(
            digest(&[&written]),
            blake2b_simd::Params::new().hash(&bytes)
        );
    }

    #[test]
    fn hash_binds_every_power_and_coefficient() {
        let single = |y, x, coeff| Monomials::new(vec![term(y, x, coeff)]);
        let base = digest(&[&single(1, 2, Fp::ONE)]);
        assert_ne!(base, digest(&[&single(2, 1, Fp::ONE)]), "powers swapped");
        assert_ne!(base, digest(&[&single(1, 3, Fp::ONE)]), "power of X");
        assert_ne!(base, digest(&[&single(0, 2, Fp::ONE)]), "power of Y");
        assert_ne!(base, digest(&[&single(1, 2, Fp::from(2))]), "coefficient");
    }

    #[test]
    fn hash_is_self_delimiting() {
        let (a, b) = (monomials(2), monomials(3));
        assert_ne!(digest(&[&a]), digest(&[&b]));
        // Absorbing two polynomials in either order distinguishes the orders.
        assert_ne!(digest(&[&a, &b]), digest(&[&b, &a]));
        // Moving a monomial across the boundary between two polynomials moves
        // their counts, so where one polynomial ends is bound too.
        let (first, second) = (term(1, 1, Fp::ONE), term(2, 2, Fp::ONE));
        let together = Monomials::new(vec![first, second]);
        let (left, right) = (Monomials::new(vec![first]), Monomials::new(vec![second]));
        assert_ne!(
            digest(&[&together, &Monomials::default()]),
            digest(&[&left, &right])
        );
        // Even the zero polynomial absorbs its count.
        assert_ne!(digest(&[&Monomials::default()]), digest(&[]));
    }

    #[test]
    fn starts_with_the_one_constraint() {
        let mut monomials = monomials(3);
        let first = *monomials.iter().next().unwrap();
        assert_eq!((first.y, first.x, first.coeff), (0, 0, Fp::ONE));
        let before = monomials.iter().len();
        monomials.strip_one();
        assert_eq!(monomials.iter().len(), before - 1);
        assert!(monomials.iter().all(|m| m.y > 0));
    }

    #[test]
    #[should_panic(expected = "the ONE constraint is present")]
    fn strip_one_rejects_the_zero_polynomial() {
        Monomials::<Fp>::default().strip_one();
    }

    #[test]
    #[should_panic(expected = "must be the ONE constraint")]
    fn strip_one_rejects_another_constant_term() {
        Monomials::new(vec![term(0, 0, Fp::from(2))]).strip_one();
    }

    #[test]
    #[should_panic(expected = "occupies Y^0 alone")]
    fn strip_one_rejects_a_shared_row() {
        Monomials::new(vec![term(0, 0, Fp::ONE), term(0, 3, Fp::ONE)]).strip_one();
    }

    #[test]
    fn scale_multiplies_by_every_coefficient() {
        let value = Fp::from(11);
        for coeff in [
            Coeff::Zero,
            Coeff::One,
            Coeff::Two,
            Coeff::NegativeOne,
            Coeff::Arbitrary(Fp::from(5)),
            Coeff::NegativeArbitrary(Fp::from(5)),
        ] {
            let expected = value * coeff.value();
            assert_eq!(scale(value, coeff), expected);
        }
    }

    #[test]
    fn canonical_sorts_merges_and_drops_zeros() {
        let form = canonical(vec![
            (5, Fp::ONE),
            (2, Fp::from(3)),
            (5, Fp::from(2)),
            (7, Fp::ONE),
            (7, -Fp::ONE),
            (4, Fp::ZERO),
        ]);
        assert_eq!(form, vec![(2, Fp::from(3)), (5, Fp::from(3))]);
        assert_eq!(canonical::<Fp>(vec![]), vec![]);
    }

    #[test]
    fn terms_apply_the_gain_and_expand_virtual_wires() {
        let virtual_wire = Wire::Form(Rc::from(vec![(1, Fp::from(2)), (6, -Fp::ONE)]));
        let terms = Terms::new()
            .add_term(&Wire::Monomial(3), Coeff::Two)
            .add_term(&Wire::Monomial(9), Coeff::Zero)
            .gain(Coeff::Arbitrary(Fp::from(5)))
            .add_term(&Wire::Monomial(4), Coeff::One)
            .add_term(&virtual_wire, Coeff::NegativeOne)
            .gain(Coeff::Zero)
            .add_term(&Wire::Monomial(8), Coeff::One);
        assert_eq!(
            terms.canonical(),
            vec![
                (1, -Fp::from(10)),
                (3, Fp::from(2)),
                (4, Fp::from(5)),
                (6, Fp::from(5)),
            ]
        );
    }

    #[test]
    fn gates_take_their_wiring_powers() {
        let n = TestRank::n();
        let mut evaluator = evaluator(0);
        for i in 0..n {
            let (a, b, c, extra) = DriverTypes::gate(&mut evaluator, zero_gate).unwrap();
            let d = evaluator.assign_extra(extra, || Ok(Coeff::Zero)).unwrap();
            assert_eq!(
                [&a, &b, &c, &d].map(degree),
                [2 * n + i, 2 * n - 1 - i, 4 * n - 1 - i, i],
                "gate {i}"
            );
        }
        // ONE is the SYSTEM gate's d wire.
        assert_eq!(degree(&<Ev as Driver<'static>>::ONE), 0);
        assert!(matches!(
            DriverTypes::gate(&mut evaluator, zero_gate),
            Err(Error::GateBoundExceeded { limit }) if limit == n
        ));
    }

    #[test]
    fn constraints_take_decreasing_powers_in_their_segment() {
        let n = TestRank::n();
        let written = emit(3, |evaluator| {
            let (a, b, c) = gate(evaluator);
            evaluator.enforce_zero(|lc| lc.add(&a))?;
            evaluator.enforce_zero(|lc| lc.add(&b))?;
            evaluator.enforce_zero(|lc| lc.add(&c))
        });
        // The first constraint emitted takes the segment's highest power.
        assert_eq!(
            written,
            Monomials::new(vec![
                term(0, 4 * n - 1, Fp::ONE),
                term(1, 2 * n - 1, Fp::ONE),
                term(2, 2 * n, Fp::ONE),
            ])
        );
    }

    #[test]
    fn constraint_bound_reserves_the_tag_slot() {
        let limit = TestRank::num_coeffs() - 1;
        let one = <Ev as Driver<'static>>::ONE;
        let mut evaluator = evaluator(limit);
        for _ in 0..limit {
            evaluator.enforce_zero(|lc| lc.add(&one)).unwrap();
        }
        assert!(matches!(
            evaluator.enforce_zero(|lc| lc.add(&one)),
            Err(Error::ConstraintBoundExceeded { limit: reported }) if reported == limit
        ));
        // No constraint reaches the power of Y the tag takes.
        assert!(evaluator.monomials.iter().all(|m| m.y < limit));
    }

    #[test]
    fn is_a_function_of_the_polynomial_not_of_its_emission() {
        let direct = emit(2, |evaluator| {
            let (a, b, c) = gate(evaluator);
            evaluator.enforce_zero(|lc| lc.add(&a).add(&a).add(&b))?;
            evaluator.enforce_zero(|lc| lc.add(&c))
        });
        let reshaped = emit(2, |evaluator| {
            let (a, b, c) = gate(evaluator);
            // A virtual wire, terms in another order, a doubled coefficient
            // for a repeated wire, a pair that cancels and a negated gain.
            let sum = evaluator.add(|lc| lc.add(&b).add_term(&a, Coeff::Two));
            evaluator.enforce_zero(|lc| lc.add(&sum).add(&c).sub(&c))?;
            evaluator.enforce_zero(|lc| lc.gain(Coeff::NegativeOne).sub(&c))
        });
        assert_eq!(direct, reshaped);
        // A constraint whose terms cancel contributes nothing.
        let cancelled = emit(1, |evaluator| {
            let (a, _, _) = gate(evaluator);
            evaluator.enforce_zero(|lc| lc.add(&a).sub(&a))
        });
        assert_eq!(cancelled, Monomials::default());
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
            assert_eq!(
                monomials(i) == monomials(j),
                i == j,
                "SquareCircuit {i} vs {j}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "root gate count must match floor plan")]
    fn rejects_another_circuits_floor_plan() {
        let plan = floor_planner::floor_plan(object(5).segment_records());
        let _ = super::eval::<Fp, _, TestRank>(&CircuitAdapter(SquareCircuit { times: 2 }), &plan);
    }
}
