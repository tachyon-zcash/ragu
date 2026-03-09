use ff::Field;

use super::Coeff;

/// Linear expressions represent accumulated linear combinations of wires. They
/// provide an efficient interface for adding or subtracting terms, allowing
/// drivers to optimize arithmetic depending on the coefficient, wire type and
/// context.
///
/// In Ragu, linear expressions cannot be directly scaled, since scaling
/// arbitrary combinations can be inefficient in some contexts. Instead, each
/// expression maintains a "gain" factor (initialized to $1$), and every term
/// added is multiplied by the _current_ gain. The gain can be updated at any
/// time, affecting only subsequent terms. This is equivalent to scale-and-add
/// techniques, though it can be more awkward or unfamiliar. See also the
/// [book].
///
/// [book]: https://tachyon.z.cash/ragu/guide/drivers/linear.html
pub trait LinearExpression<W: Clone, F: Field>: Sized {
    /// This adds a term to the linear expression, described by a wire and an
    /// associated coefficient. Terms being added are always scaled by the
    /// current gain.
    fn add_term(self, wire: &W, coeff: Coeff<F>) -> Self;

    /// Scale the current gain by some amount.
    fn gain(self, coeff: Coeff<F>) -> Self;

    /// Extends the linear expression using an iterator of terms.
    fn extend(mut self, with: impl IntoIterator<Item = (W, Coeff<F>)>) -> Self {
        for (wire, coeff) in with {
            self = self.add_term(&wire, coeff);
        }
        self
    }

    /// Adds a wire to the linear expression with a coefficient of $1$.
    fn add(self, wire: &W) -> Self {
        self.add_term(wire, Coeff::One)
    }

    /// Subtracts a wire from the linear expression by adding with a coefficient of $-1$.
    fn sub(self, wire: &W) -> Self {
        self.add_term(wire, Coeff::NegativeOne)
    }
}

/// This is a trivial implementation for drivers that do not need to do anything
/// with a linear expression.
impl<W: Clone, F: Field> LinearExpression<W, F> for () {
    fn add_term(self, _: &W, _: Coeff<F>) -> Self {
        self
    }

    fn gain(self, _: Coeff<F>) -> Self {
        self
    }
}

/// A straightforward linear expression that directly computes the sum.
pub struct DirectSum<F: Field> {
    /// The current value of the linear combination.
    value: F,

    /// The current gain of the linear combination.
    current_gain: Coeff<F>,
}

impl<F: Field> DirectSum<F> {
    /// Returns the current value of the linear combination.
    pub fn value(&self) -> F {
        self.value
    }

    /// Returns the current gain of the linear combination.
    #[cfg(test)]
    pub(crate) fn current_gain(&self) -> Coeff<F> {
        self.current_gain
    }
}

impl<F: Field> Default for DirectSum<F> {
    fn default() -> Self {
        Self {
            value: F::ZERO,
            current_gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<F, F> for DirectSum<F> {
    fn add_term(mut self, wire: &F, coeff: Coeff<F>) -> Self {
        match coeff * self.current_gain {
            Coeff::Zero => {}
            Coeff::One => self.value += *wire,
            Coeff::Two => self.value += wire.double(),
            Coeff::NegativeOne => self.value -= *wire,
            Coeff::Arbitrary(coeff) => self.value += *wire * coeff,
            Coeff::NegativeArbitrary(coeff) => self.value -= *wire * coeff,
        }

        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.current_gain = self.current_gain * coeff;
        self
    }
}

#[test]
fn test_linexp_direct() {
    use alloc::vec;
    use ragu_pasta::Fp;

    let acc = DirectSum::default()
        .add_term(&Fp::from(2), Coeff::Arbitrary(Fp::from(3))) // acc = 0 + 2 * 3 = 6
        .add_term(&Fp::from(4), Coeff::Arbitrary(Fp::from(5))) // acc = 6 + 4 * 5 = 26
        .add(&Fp::from(3)) // acc = 26 + 3 * 1 = 29
        .sub(&Fp::from(10)) // acc = 29 + 10 * -1 = 19
        .extend(vec![
            (Fp::from(3), Coeff::Arbitrary(Fp::from(4))),
            (Fp::from(10), Coeff::Arbitrary(-Fp::from(3))),
        ]); // acc = 19 + (3 * 4) + (10 * -3) = 19 + 12 - 30 = 1
    assert_eq!(acc.value(), Fp::ONE);
}

#[test]
#[allow(clippy::unit_cmp)]
fn test_linexp_trivial() {
    use alloc::vec;
    use ragu_pasta::Fp;

    assert_eq!(
        (),
        ().extend(vec![
            (Fp::from(3), Coeff::Arbitrary(Fp::from(4))),
            (Fp::from(10), Coeff::Arbitrary(-Fp::from(3))),
        ])
    );
}

#[test]
fn direct_sum_gain_factor() {
    use ragu_pasta::Fp;

    let acc = DirectSum::<Fp>::default()
        .add(&Fp::from(5))
        .gain(Coeff::Arbitrary(Fp::from(2)))
        .add(&Fp::from(3))
        .gain(Coeff::NegativeOne)
        .add(&Fp::from(4));

    assert_eq!(acc.value(), Fp::from(3));
}

#[test]
fn direct_sum_all_coeff_arms() {
    use ragu_pasta::Fp;

    let wire = Fp::from(10);
    let acc = DirectSum::<Fp>::default()
        // Zero: no-op
        .add_term(&wire, Coeff::Zero)
        // One: +10
        .add_term(&wire, Coeff::One)
        // Two: +20
        .add_term(&wire, Coeff::Two)
        // NegativeOne: -10
        .add_term(&wire, Coeff::NegativeOne)
        // Arbitrary(3): +30
        .add_term(&wire, Coeff::Arbitrary(Fp::from(3)))
        // NegativeArbitrary(2): -20
        .add_term(&wire, Coeff::NegativeArbitrary(Fp::from(2)));

    // 0 + 10 + 20 - 10 + 30 - 20 = 30
    assert_eq!(acc.value(), Fp::from(30));
}

#[test]
fn direct_sum_gain_interactions() {
    use alloc::vec;
    use ragu_pasta::Fp;

    // gain(Zero) annihilates subsequent terms
    let acc = DirectSum::<Fp>::default()
        .add(&Fp::from(5))
        .gain(Coeff::Zero)
        .add(&Fp::from(100));
    assert_eq!(acc.value(), Fp::from(5));

    // gain(NegativeOne) flips signs
    let acc = DirectSum::<Fp>::default()
        .add(&Fp::from(10))
        .gain(Coeff::NegativeOne)
        .add(&Fp::from(3));
    assert_eq!(acc.value(), Fp::from(7));

    // Chained gain changes
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Arbitrary(Fp::from(2)))
        .add(&Fp::from(5)) // 2*5 = 10
        .gain(Coeff::Arbitrary(Fp::from(3)))
        .add(&Fp::from(1)); // (2*3)*1 = 6 => total 16
    assert_eq!(acc.value(), Fp::from(16));

    // extend with empty iterator
    let acc = DirectSum::<Fp>::default().add(&Fp::from(7)).extend(vec![]);
    assert_eq!(acc.value(), Fp::from(7));
}

#[test]
fn direct_sum_default_state() {
    use ragu_pasta::Fp;

    let ds = DirectSum::<Fp>::default();
    assert_eq!(ds.value(), Fp::ZERO);
    assert_eq!(ds.current_gain().value(), Fp::ONE);
}

#[test]
fn direct_sum_all_coeff_arms_with_nontrivial_gain() {
    use ragu_pasta::Fp;

    let wire = Fp::from(7);
    let gain_val = Fp::from(3);

    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Arbitrary(gain_val))
        .add_term(&wire, Coeff::Zero) // 7 * 0 * 3 = 0
        .add_term(&wire, Coeff::One) // 7 * 1 * 3 = 21
        .add_term(&wire, Coeff::Two) // 7 * 2 * 3 = 42
        .add_term(&wire, Coeff::NegativeOne) // 7 * (-1) * 3 = -21
        .add_term(&wire, Coeff::Arbitrary(Fp::from(5))) // 7 * 5 * 3 = 105
        .add_term(&wire, Coeff::NegativeArbitrary(Fp::from(2))); // 7 * (-2) * 3 = -42

    // 0 + 21 + 42 - 21 + 105 - 42 = 105
    assert_eq!(acc.value(), Fp::from(105));
}

#[test]
fn direct_sum_gain_two_and_negative_arbitrary() {
    use ragu_pasta::Fp;

    // gain(Two): each add is doubled
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Two)
        .add(&Fp::from(5)) // 5 * 2 = 10
        .add(&Fp::from(3)); // 3 * 2 = 6 => total 16
    assert_eq!(acc.value(), Fp::from(16));

    // gain(NegativeArbitrary(4)): each add scaled by -4
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::NegativeArbitrary(Fp::from(4)))
        .add(&Fp::from(3)) // 3 * (-4) = -12
        .add(&Fp::from(2)); // 2 * (-4) = -8 => total -20
    assert_eq!(acc.value(), -Fp::from(20));
}

#[test]
fn direct_sum_sub_with_nontrivial_gain() {
    use ragu_pasta::Fp;

    // gain(NegativeOne), then sub (which uses NegativeOne coeff).
    // NegativeOne * NegativeOne = One, so sub becomes addition.
    let acc = DirectSum::<Fp>::default()
        .add(&Fp::from(10)) // 10
        .gain(Coeff::NegativeOne)
        .sub(&Fp::from(3)); // coeff = -1, gain = -1 => net +3 => 13
    assert_eq!(acc.value(), Fp::from(13));
}

#[test]
fn direct_sum_extend_with_nontrivial_gain() {
    use alloc::vec;
    use ragu_pasta::Fp;

    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Arbitrary(Fp::from(5)))
        .extend(vec![
            (Fp::from(2), Coeff::One),                    // 2 * 1 * 5 = 10
            (Fp::from(3), Coeff::Arbitrary(Fp::from(4))), // 3 * 4 * 5 = 60
            (Fp::from(1), Coeff::NegativeOne),            // 1 * (-1) * 5 = -5
        ]);

    // 10 + 60 - 5 = 65
    assert_eq!(acc.value(), Fp::from(65));
}

#[test]
fn direct_sum_zero_wire() {
    use ragu_pasta::Fp;

    let zero = Fp::ZERO;
    let acc = DirectSum::<Fp>::default()
        .add_term(&zero, Coeff::One)
        .add_term(&zero, Coeff::Two)
        .add_term(&zero, Coeff::NegativeOne)
        .add_term(&zero, Coeff::Arbitrary(Fp::from(999)))
        .add_term(&zero, Coeff::NegativeArbitrary(Fp::from(999)));
    assert_eq!(acc.value(), Fp::ZERO);
}

#[test]
fn trivial_impl_all_methods() {
    use ragu_pasta::Fp;

    let wire = Fp::from(42);
    <() as LinearExpression<Fp, Fp>>::add_term((), &wire, Coeff::Arbitrary(Fp::from(5)));
    <() as LinearExpression<Fp, Fp>>::gain((), Coeff::Arbitrary(Fp::from(3)));
    <() as LinearExpression<Fp, Fp>>::add((), &wire);
    <() as LinearExpression<Fp, Fp>>::sub((), &wire);
}

#[test]
fn direct_sum_coeff_zero_with_every_gain_variant() {
    use ragu_pasta::Fp;

    let wire = Fp::from(42);

    for gain in [
        Coeff::Zero,
        Coeff::One,
        Coeff::Two,
        Coeff::NegativeOne,
        Coeff::Arbitrary(Fp::from(7)),
        Coeff::NegativeArbitrary(Fp::from(7)),
    ] {
        let acc = DirectSum::<Fp>::default()
            .gain(gain)
            .add_term(&wire, Coeff::Zero);
        assert_eq!(
            acc.value(),
            Fp::ZERO,
            "Coeff::Zero should be no-op with gain {gain:?}"
        );
    }
}

#[test]
fn direct_sum_arbitrary_zero_vs_coeff_zero() {
    use ragu_pasta::Fp;

    let wire = Fp::from(10);

    // Coeff::Zero hits the no-op arm directly.
    let a = DirectSum::<Fp>::default().add_term(&wire, Coeff::Zero);

    // Arbitrary(ZERO) survives multiplication and hits `wire * F::ZERO`.
    let b = DirectSum::<Fp>::default().add_term(&wire, Coeff::Arbitrary(Fp::ZERO));

    // NegativeArbitrary(ZERO) hits `wire * F::ZERO` via the negative arm.
    let c = DirectSum::<Fp>::default().add_term(&wire, Coeff::NegativeArbitrary(Fp::ZERO));

    assert_eq!(a.value(), Fp::ZERO);
    assert_eq!(b.value(), Fp::ZERO);
    assert_eq!(c.value(), Fp::ZERO);
}

#[test]
fn direct_sum_gain_zero_is_irrecoverable() {
    use ragu_pasta::Fp;

    let wire = Fp::from(100);

    // Once gain is Zero, no subsequent gain call can restore it.
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Zero)
        .gain(Coeff::One)
        .add(&wire);
    assert_eq!(acc.value(), Fp::ZERO);

    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Zero)
        .gain(Coeff::Arbitrary(Fp::from(999)))
        .add(&wire);
    assert_eq!(acc.value(), Fp::ZERO);

    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Zero)
        .gain(Coeff::NegativeOne)
        .add(&wire);
    assert_eq!(acc.value(), Fp::ZERO);

    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Zero)
        .gain(Coeff::Two)
        .add(&wire);
    assert_eq!(acc.value(), Fp::ZERO);
}

#[test]
fn direct_sum_gain_zero_affects_sub_and_extend() {
    use alloc::vec;
    use ragu_pasta::Fp;

    let wire = Fp::from(50);

    // sub after gain(Zero)
    let acc = DirectSum::<Fp>::default()
        .add(&Fp::from(10))
        .gain(Coeff::Zero)
        .sub(&wire);
    assert_eq!(acc.value(), Fp::from(10));

    // extend after gain(Zero)
    let acc = DirectSum::<Fp>::default()
        .add(&Fp::from(10))
        .gain(Coeff::Zero)
        .extend(vec![
            (Fp::from(100), Coeff::One),
            (Fp::from(200), Coeff::Arbitrary(Fp::from(5))),
        ]);
    assert_eq!(acc.value(), Fp::from(10));
}

#[test]
fn direct_sum_extend_mixed_zero_coefficients() {
    use alloc::vec;
    use ragu_pasta::Fp;

    // With default gain (One): zeros interleaved with live terms.
    let acc = DirectSum::<Fp>::default().extend(vec![
        (Fp::from(10), Coeff::Zero),
        (Fp::from(5), Coeff::One), // +5
        (Fp::from(99), Coeff::Zero),
        (Fp::from(3), Coeff::Two), // +6
        (Fp::from(77), Coeff::Zero),
    ]);
    assert_eq!(acc.value(), Fp::from(11));

    // With non-trivial gain: zeros still produce nothing.
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Arbitrary(Fp::from(10)))
        .extend(vec![
            (Fp::from(7), Coeff::Zero),
            (Fp::from(2), Coeff::One), // 2 * 1 * 10 = 20
            (Fp::from(99), Coeff::Zero),
        ]);
    assert_eq!(acc.value(), Fp::from(20));
}

#[test]
fn direct_sum_gain_arbitrary_zero_vs_gain_zero() {
    use ragu_pasta::Fp;

    let wire = Fp::from(100);

    // gain(Arbitrary(ZERO)) stores gain as Arbitrary(0), not Zero.
    // Subsequent multiplications go through Arbitrary arms but still produce zero.
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Arbitrary(Fp::ZERO))
        .add(&wire)
        .add_term(&wire, Coeff::Two)
        .sub(&wire);
    assert_eq!(acc.value(), Fp::ZERO);

    // gain(NegativeArbitrary(ZERO)) similarly absorbs.
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::NegativeArbitrary(Fp::ZERO))
        .add(&wire)
        .add_term(&wire, Coeff::Arbitrary(Fp::from(5)))
        .sub(&wire);
    assert_eq!(acc.value(), Fp::ZERO);

    // Irrecoverable: further gain changes can't restore non-zero.
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Arbitrary(Fp::ZERO))
        .gain(Coeff::Arbitrary(Fp::from(999)))
        .add(&wire);
    assert_eq!(acc.value(), Fp::ZERO);
}

#[test]
fn direct_sum_all_coeff_arms_with_gain_two() {
    use ragu_pasta::Fp;

    let wire = Fp::from(10);
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::Two)
        // Zero * Two = Zero → no-op
        .add_term(&wire, Coeff::Zero)
        // One * Two = Arbitrary(2) → 10 * 2 = 20
        .add_term(&wire, Coeff::One)
        // Two * Two = Arbitrary(4) → 10 * 4 = 40
        .add_term(&wire, Coeff::Two)
        // NegativeOne * Two = Arbitrary(-2) → 10 * (-2) = -20
        .add_term(&wire, Coeff::NegativeOne)
        // Arbitrary(3) * Two = Arbitrary(6) → 10 * 6 = 60
        .add_term(&wire, Coeff::Arbitrary(Fp::from(3)))
        // NegativeArbitrary(2) * Two = Arbitrary(-4) → 10 * (-4) = -40
        .add_term(&wire, Coeff::NegativeArbitrary(Fp::from(2)));

    // 0 + 20 + 40 - 20 + 60 - 40 = 60
    assert_eq!(acc.value(), Fp::from(60));
}

#[test]
fn direct_sum_all_coeff_arms_with_gain_negative_one() {
    use ragu_pasta::Fp;

    let wire = Fp::from(10);
    let acc = DirectSum::<Fp>::default()
        .gain(Coeff::NegativeOne)
        // Zero * NegativeOne = Zero → no-op
        .add_term(&wire, Coeff::Zero)
        // One * NegativeOne = NegativeOne → -10
        .add_term(&wire, Coeff::One)
        // Two * NegativeOne = Arbitrary(-2) → 10 * (-2) = -20
        .add_term(&wire, Coeff::Two)
        // NegativeOne * NegativeOne = One → +10
        .add_term(&wire, Coeff::NegativeOne)
        // Arbitrary(3) * NegativeOne = NegativeArbitrary(3) → -(10 * 3) = -30
        .add_term(&wire, Coeff::Arbitrary(Fp::from(3)))
        // NegativeArbitrary(2) * NegativeOne = Arbitrary(2) → 10 * 2 = 20
        .add_term(&wire, Coeff::NegativeArbitrary(Fp::from(2)));

    // 0 - 10 - 20 + 10 - 30 + 20 = -30
    assert_eq!(acc.value(), -Fp::from(30));
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use ragu_pasta::Fp;

    fn arb_fe() -> impl Strategy<Value = Fp> {
        (0u64..1000).prop_map(Fp::from)
    }

    fn arb_coeff() -> impl Strategy<Value = Coeff<Fp>> {
        prop_oneof![
            Just(Coeff::Zero),
            Just(Coeff::One),
            Just(Coeff::Two),
            Just(Coeff::NegativeOne),
            arb_fe().prop_map(Coeff::Arbitrary),
            arb_fe().prop_map(Coeff::NegativeArbitrary),
        ]
    }

    #[derive(Debug, Clone)]
    enum Op {
        AddTerm(Fp, Coeff<Fp>),
        Gain(Coeff<Fp>),
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (arb_fe(), arb_coeff()).prop_map(|(w, c)| Op::AddTerm(w, c)),
            arb_coeff().prop_map(Op::Gain),
        ]
    }

    proptest! {
        #[test]
        fn proptest_direct_sum_matches_manual(ops in proptest::collection::vec(arb_op(), 0..30)) {
            let mut ds = DirectSum::<Fp>::default();
            let mut manual_value = Fp::ZERO;
            let mut manual_gain = Fp::ONE;

            for op in ops {
                match op {
                    Op::AddTerm(wire, coeff) => {
                        ds = ds.add_term(&wire, coeff);
                        manual_value += wire * coeff.value() * manual_gain;
                    }
                    Op::Gain(coeff) => {
                        ds = ds.gain(coeff);
                        manual_gain *= coeff.value();
                    }
                }
            }

            assert_eq!(ds.value(),manual_value);
        }
    }
}
