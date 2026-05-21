//! Algebraic-identity fuzz target.
//!
//! Generates random `Fp` pairs `(a, b)` and a Boolean `bv`, allocates them
//! as gadgets through `Simulator`, and asserts that a fixed list of
//! algebraic identities hold for every input. Any failure means a gadget
//! has broken the algebraic contract it claims to implement.
//!
//! This is property-based testing in fuzz-target form: the identities are
//! checked exhaustively over the input space `Vec<Op>`-style harnesses
//! can't easily probe, because they require running both sides of an
//! equation under the *same* witness and comparing the resulting wire
//! values. The Simulator does this naturally — it stores the assigned
//! `Fp` value on every wire, so `Element::value().take()` retrieves the
//! exact witness value the gadget produced.
//!
//! # Identities (Element)
//!
//! - additive commutativity: `a + b == b + a`
//! - additive identity:      `a + 0 == a`
//! - additive inverse:       `a + (-a) == 0`
//! - multiplicative commutativity: `a * b == b * a`
//! - multiplicative identity: `a * 1 == a`
//! - multiplicative annihilator: `a * 0 == 0`
//! - subtract self:          `a - a == 0`
//! - double negation:        `-(-a) == a`
//! - double == add self:     `Element::double(a) == a + a`
//! - square == mul self:     `Element::square(a) == a * a`
//! - distributivity:         `a * (b + 1) == a * b + a`
//! - div_nonzero round-trip: `(a / b) * b == a` (when `b != 0`)
//! - scale identities:       `scale(a, 1) == a`, `scale(a, 0) == 0`,
//!                           `scale(a, 2) == double(a)`
//! - alloc_square:           `let (r, s) = alloc_square(a*a); r*r == s`
//! - add_coeff identities:   `add_coeff(b, 1) == add(b)`,
//!                           `add_coeff(b, 0) == self`
//! - is_equal:               `is_equal(a, a) == true`,
//!                           `is_equal(a, b) == (a_val == b_val)`
//! - sum:                    `sum([]) == 0`, `sum([a]) == a`,
//!                           `sum([a, b]) == a + b`
//! - fold:                   `fold([&a], &s) == a` (single-element identity),
//!                           `fold([&a, &b], &one) == a + b`,
//!                           `fold([&a, &b], &s) == a*s + b`
//! - multiadd:               `multiadd([&a], &[1]) == a`,
//!                           `multiadd([&a, &b], &[1, 1]) == a + b`,
//!                           `multiadd([&a], &[w]) == scale(a, w)`
//! - from_repr round-trip:   `Fp::from_repr(a.to_repr()) == Some(a)`
//!                           (pure field-arithmetic check, not a gadget;
//!                           sanity-guards canonical serialization)
//! - invert:                 `a * invert(a) == 1` (when `a != 0`)
//! - is_zero:                `is_zero(0) == true`,
//!                           `is_zero(a) == (a_val == 0)`
//!
//! # Identities (Boolean)
//!
//! - double not:             `!!bv == bv`
//! - self and:               `bv & bv == bv`
//! - not on constants:       `not(alloc(true)) == false`,
//!                           `not(alloc(false)) == true`
//! - and identity:           `and(bv, alloc(true)) == bv`
//! - and annihilator:        `and(bv, alloc(false)) == false`
//! - and correctness:        `and(bv, bv2).value() == (bv_val && bv2_val)`
//! - and commutativity:      `and(bv, bv2) == and(bv2, bv)`
//! - element() conversion:   `bv.element().value() == (if bv then 1 else 0)`
//!
//! # Identities (ConditionalSelect)
//!
//! Ragu's convention (`Boolean::conditional_select(&self, dr, a, b)`) is
//! `result = a + cond * (b - a)` — so `cond=false → a`, `cond=true → b`.
//!
//! - false select:           `cond_select(false, a, b) == a`
//! - true select:            `cond_select(true, a, b) == b`
//! - branches equal:         `cond_select(c, x, x) == x` (any `c`)
//!
//! If any assertion fails, libFuzzer records a crash with the input
//! that triggered it.

#![no_main]

use arbitrary::Arbitrary;
use ff::{Field, PrimeField};
use libfuzzer_sys::fuzz_target;
use pasta_curves::Fp;
use ragu_arithmetic::Coeff;
use ragu_core::maybe::Maybe;
use ragu_primitives::{Boolean, Element, Simulator, allocator::Standard};

#[derive(Arbitrary, Debug)]
struct Input {
    /// 32 raw bytes parsed as canonical Fp via from_repr.
    a_bytes: [u8; 32],
    /// 32 raw bytes parsed as canonical Fp via from_repr.
    b_bytes: [u8; 32],
    /// First Boolean witness for the Boolean-side identities.
    bv: bool,
    /// Second Boolean witness, used for and commutativity / correctness
    /// identities that need two distinct booleans.
    bv2: bool,
}

/// Parse 32 bytes as a canonical Fp, falling back to a low-entropy
/// u64-derived value if the bytes don't form a valid field element.
/// This way every input is usable, including ones from libFuzzer's
/// random byte mutation.
fn parse_fp(bytes: [u8; 32]) -> Fp {
    Option::<Fp>::from(Fp::from_repr(bytes)).unwrap_or_else(|| {
        Fp::from(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    })
}

fuzz_target!(|input: Input| {
    // DEBUG_INPUT=1 prints the parsed Arbitrary input and exits — useful for
    // triaging crash artifacts. See README.md "DEBUG_INPUT env var" section.
    if std::env::var("DEBUG_INPUT").is_ok() {
        eprintln!("{:#?}", input);
        return;
    }
    let a_val = parse_fp(input.a_bytes);
    let b_val = parse_fp(input.b_bytes);
    let bv_val = input.bv;
    let bv2_val = input.bv2;

    // from_repr round-trip: pure field-arithmetic check. Doesn't exercise
    // any gadget; just guards that the canonical byte representation is a
    // true bijection, which the rest of the suite assumes.
    {
        let bytes = a_val.to_repr();
        let recovered: Option<Fp> = Fp::from_repr(bytes).into();
        assert_eq!(
            recovered,
            Some(a_val),
            "from_repr(to_repr(a)) != Some(a): a={:?}",
            a_val,
        );
    }

    let witness_data = (a_val, b_val, bv_val, bv2_val);

    let _ = Simulator::<Fp>::simulate(witness_data, |dr, witness| {
        let allocator = &mut Standard::new();

        let a = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.0))?;
        let b = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.1))?;
        let bv = Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.2))?;
        let bv2 = Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w.3))?;
        let zero = Element::constant(dr, Fp::ZERO);
        let one = Element::constant(dr, Fp::ONE);

        // ------------------------------------------------------------------
        // Element identities
        // ------------------------------------------------------------------

        // additive commutativity
        let lhs = a.add(dr, &b);
        let rhs = b.add(dr, &a);
        assert_eq!(
            *lhs.value().take(),
            *rhs.value().take(),
            "add commutativity failed: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // additive identity
        let lhs = a.add(dr, &zero);
        assert_eq!(
            *lhs.value().take(),
            a_val,
            "additive identity failed: a={:?}",
            a_val,
        );

        // additive inverse
        let neg_a = a.negate(dr);
        let sum = a.add(dr, &neg_a);
        assert_eq!(
            *sum.value().take(),
            Fp::ZERO,
            "additive inverse failed: a={:?}",
            a_val,
        );

        // multiplicative commutativity
        let lhs = a.mul(dr, &b)?;
        let rhs = b.mul(dr, &a)?;
        assert_eq!(
            *lhs.value().take(),
            *rhs.value().take(),
            "mul commutativity failed: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // multiplicative identity
        let lhs = a.mul(dr, &one)?;
        assert_eq!(
            *lhs.value().take(),
            a_val,
            "multiplicative identity failed: a={:?}",
            a_val,
        );

        // multiplicative annihilator
        let lhs = a.mul(dr, &zero)?;
        assert_eq!(
            *lhs.value().take(),
            Fp::ZERO,
            "multiplicative annihilator failed: a={:?}",
            a_val,
        );

        // subtract self
        let diff = a.sub(dr, &a);
        assert_eq!(
            *diff.value().take(),
            Fp::ZERO,
            "subtract self failed: a={:?}",
            a_val,
        );

        // double negation
        let neg_a = a.negate(dr);
        let neg_neg_a = neg_a.negate(dr);
        assert_eq!(
            *neg_neg_a.value().take(),
            a_val,
            "double negation failed: a={:?}",
            a_val,
        );

        // double == add self
        let doubled = a.double(dr);
        let added = a.add(dr, &a);
        assert_eq!(
            *doubled.value().take(),
            *added.value().take(),
            "double != add self: a={:?}",
            a_val,
        );

        // square == mul self
        let squared = a.square(dr)?;
        let mul_self = a.mul(dr, &a)?;
        assert_eq!(
            *squared.value().take(),
            *mul_self.value().take(),
            "square != mul self: a={:?}",
            a_val,
        );

        // distributivity: a * (b + 1) == a * b + a
        let b_plus_one = b.add(dr, &one);
        let lhs = a.mul(dr, &b_plus_one)?;
        let ab = a.mul(dr, &b)?;
        let rhs = ab.add(dr, &a);
        assert_eq!(
            *lhs.value().take(),
            *rhs.value().take(),
            "distributivity failed: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // div_nonzero round-trip: (a / b) * b == a, when b != 0
        if b_val != Fp::ZERO {
            let a_over_b = a.div_nonzero(dr, &b)?;
            let recovered = a_over_b.mul(dr, &b)?;
            assert_eq!(
                *recovered.value().take(),
                a_val,
                "div_nonzero round-trip failed: (a / b) * b != a, a={:?} b={:?}",
                a_val,
                b_val,
            );
        }

        // scale by 1 is the identity
        let scaled_one = a.scale(dr, Coeff::Arbitrary(Fp::ONE));
        assert_eq!(
            *scaled_one.value().take(),
            a_val,
            "scale(a, 1) != a: a={:?}",
            a_val,
        );

        // scale by 0 is the annihilator
        let scaled_zero_coeff = a.scale(dr, Coeff::Arbitrary(Fp::ZERO));
        assert_eq!(
            *scaled_zero_coeff.value().take(),
            Fp::ZERO,
            "scale(a, 0) != 0: a={:?}",
            a_val,
        );

        // scale by 2 == double
        let scaled_two = a.scale(dr, Coeff::Arbitrary(Fp::from(2)));
        let doubled_check = a.double(dr);
        assert_eq!(
            *scaled_two.value().take(),
            *doubled_check.value().take(),
            "scale(a, 2) != double(a): a={:?}",
            a_val,
        );

        // alloc_square: pre-square a so we know a*a is a QR; the gadget
        // should return (root, sq) with root*root == sq.
        let a_squared_val = a_val.square();
        if let Ok((root, sq)) = Element::alloc_square(
            dr,
            witness.as_ref().map(|_| a_squared_val),
        ) {
            let root_squared = root.mul(dr, &root)?;
            assert_eq!(
                *root_squared.value().take(),
                *sq.value().take(),
                "alloc_square: root^2 != sq, a={:?}",
                a_val,
            );
        }

        // add_coeff(b, 1) == add(b)
        let ac_one = a.add_coeff(dr, &b, Coeff::Arbitrary(Fp::ONE));
        let plain_add = a.add(dr, &b);
        assert_eq!(
            *ac_one.value().take(),
            *plain_add.value().take(),
            "add_coeff(b, 1) != add(b): a={:?} b={:?}",
            a_val,
            b_val,
        );

        // add_coeff(b, 0) == a
        let ac_zero = a.add_coeff(dr, &b, Coeff::Arbitrary(Fp::ZERO));
        assert_eq!(
            *ac_zero.value().take(),
            a_val,
            "add_coeff(b, 0) != a: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // is_equal: self vs self → true
        let eq_self = a.is_equal(dr, allocator, &a)?;
        assert!(
            eq_self.value().take(),
            "is_equal(a, a) != true: a={:?}",
            a_val,
        );

        // is_equal: a vs b → (a_val == b_val)
        let eq_other = a.is_equal(dr, allocator, &b)?;
        assert_eq!(
            eq_other.value().take(),
            a_val == b_val,
            "is_equal(a, b) != (a == b): a={:?} b={:?}",
            a_val,
            b_val,
        );

        // sum([]) == 0
        let empty_iter: Vec<&Element<'_, _>> = Vec::new();
        let sum_empty = Element::sum(dr, empty_iter);
        assert_eq!(
            *sum_empty.value().take(),
            Fp::ZERO,
            "sum([]) != 0",
        );

        // sum([a]) == a
        let sum_single = Element::sum(dr, [&a]);
        assert_eq!(
            *sum_single.value().take(),
            a_val,
            "sum([a]) != a: a={:?}",
            a_val,
        );

        // sum([a, b]) == a + b
        let sum_pair = Element::sum(dr, [&a, &b]);
        assert_eq!(
            *sum_pair.value().take(),
            a_val + b_val,
            "sum([a, b]) != a + b: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // fold([&a], &s) == a (single-element fold returns the element)
        let fold_single = Element::fold(dr, [&a], &b)?;
        assert_eq!(
            *fold_single.value().take(),
            a_val,
            "fold([a], s) != a: a={:?}",
            a_val,
        );

        // fold([&a, &b], &one) == a*1 + b == a + b
        let fold_with_one = Element::fold(dr, [&a, &b], &one)?;
        assert_eq!(
            *fold_with_one.value().take(),
            a_val + b_val,
            "fold([a, b], 1) != a + b: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // fold([&a, &b], &s) == a*s + b (general formula). Use a itself
        // as the scale factor for an interesting test value.
        let fold_general = Element::fold(dr, [&a, &b], &a)?;
        assert_eq!(
            *fold_general.value().take(),
            a_val * a_val + b_val,
            "fold([a, b], a) != a*a + b: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // multiadd([&a], &[1]) == a
        let ma_single_one = ragu_primitives::multiadd(dr, &[a.clone()], &[Fp::ONE]);
        assert_eq!(
            *ma_single_one.value().take(),
            a_val,
            "multiadd([a], [1]) != a: a={:?}",
            a_val,
        );

        // multiadd([&a], &[w]) == scale(a, w) — use b_val as the coefficient
        let ma_single_scaled = ragu_primitives::multiadd(dr, &[a.clone()], &[b_val]);
        let scale_check = a.scale(dr, Coeff::Arbitrary(b_val));
        assert_eq!(
            *ma_single_scaled.value().take(),
            *scale_check.value().take(),
            "multiadd([a], [b]) != scale(a, b): a={:?} b={:?}",
            a_val,
            b_val,
        );

        // multiadd([&a, &b], &[1, 1]) == a + b
        let ma_pair = ragu_primitives::multiadd(dr, &[a.clone(), b.clone()], &[Fp::ONE, Fp::ONE]);
        assert_eq!(
            *ma_pair.value().take(),
            a_val + b_val,
            "multiadd([a, b], [1, 1]) != a + b: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // invert: a * invert(a) == 1, when a != 0
        if a_val != Fp::ZERO {
            let a_inv = a.invert(dr)?;
            let product = a.mul(dr, &a_inv)?;
            assert_eq!(
                *product.value().take(),
                Fp::ONE,
                "a * invert(a) != 1: a={:?}",
                a_val,
            );
        }

        // is_zero: is_zero(0) == true
        let zero_is_zero = zero.is_zero(dr, allocator)?;
        assert!(
            zero_is_zero.value().take(),
            "is_zero(0) != true",
        );

        // is_zero: is_zero(a) == (a == 0)
        let a_is_zero = a.is_zero(dr, allocator)?;
        assert_eq!(
            a_is_zero.value().take(),
            a_val == Fp::ZERO,
            "is_zero(a) != (a == 0): a={:?}",
            a_val,
        );

        // ------------------------------------------------------------------
        // Boolean identities
        // ------------------------------------------------------------------

        // double not
        let not_bv = bv.not(dr);
        let not_not_bv = not_bv.not(dr);
        assert_eq!(
            not_not_bv.value().take(),
            bv_val,
            "boolean double-not failed: bv={}",
            bv_val,
        );

        // self and
        let bv_and_bv = bv.and(dr, &bv)?;
        assert_eq!(
            bv_and_bv.value().take(),
            bv_val,
            "boolean self-and failed: bv={}",
            bv_val,
        );

        // not on constants
        let true_const = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| true))?;
        let false_const = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| false))?;
        let not_true = true_const.not(dr);
        let not_false = false_const.not(dr);
        assert!(
            !not_true.value().take(),
            "not(true) != false",
        );
        assert!(
            not_false.value().take(),
            "not(false) != true",
        );

        // and identity: and(bv, true) == bv
        let and_true = bv.and(dr, &true_const)?;
        assert_eq!(
            and_true.value().take(),
            bv_val,
            "and(bv, true) != bv: bv={}",
            bv_val,
        );

        // and annihilator: and(bv, false) == false
        let and_false = bv.and(dr, &false_const)?;
        assert!(
            !and_false.value().take(),
            "and(bv, false) != false: bv={}",
            bv_val,
        );

        // and correctness against native: and(bv, bv2).value() == (bv && bv2)
        let and_correctness = bv.and(dr, &bv2)?;
        assert_eq!(
            and_correctness.value().take(),
            bv_val && bv2_val,
            "and(bv, bv2) != bv && bv2: bv={} bv2={}",
            bv_val,
            bv2_val,
        );

        // and commutativity: and(bv, bv2) == and(bv2, bv)
        let and_swapped = bv2.and(dr, &bv)?;
        assert_eq!(
            and_correctness.value().take(),
            and_swapped.value().take(),
            "and not commutative: bv={} bv2={}",
            bv_val,
            bv2_val,
        );

        // element() conversion: bv.element().value() == (if bv then 1 else 0)
        let bv_as_elem = bv.element();
        assert_eq!(
            *bv_as_elem.value().take(),
            if bv_val { Fp::ONE } else { Fp::ZERO },
            "bv.element() != (if bv then 1 else 0): bv={}",
            bv_val,
        );

        // ------------------------------------------------------------------
        // ConditionalSelect identities
        // ------------------------------------------------------------------

        let true_cond = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| true))?;
        let false_cond = Boolean::alloc(dr, allocator, witness.as_ref().map(|_| false))?;

        // conditional_select formula: a + cond * (b - a)
        //   cond = false → a; cond = true → b.

        // false select returns the first arg
        let selected_false = false_cond.conditional_select(dr, &a, &b)?;
        assert_eq!(
            *selected_false.value().take(),
            a_val,
            "false-cond conditional_select failed: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // true select returns the second arg
        let selected_true = true_cond.conditional_select(dr, &a, &b)?;
        assert_eq!(
            *selected_true.value().take(),
            b_val,
            "true-cond conditional_select failed: a={:?} b={:?}",
            a_val,
            b_val,
        );

        // Equal branches: cond_select(c, x, x) == x regardless of c
        let bv_select_same = bv.conditional_select(dr, &a, &a)?;
        assert_eq!(
            *bv_select_same.value().take(),
            a_val,
            "cond_select(bv, a, a) != a: bv={} a={:?}",
            bv_val,
            a_val,
        );

        Ok(())
    });
});
