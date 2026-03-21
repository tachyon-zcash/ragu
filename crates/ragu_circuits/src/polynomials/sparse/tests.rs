use alloc::vec::Vec;
use ff::Field;
use proptest::prelude::*;
use ragu_pasta::Fp;

use crate::polynomials::{Rank, TestRank};

use super::Polynomial;
use super::view::{Backward, Forward, View};

type R = TestRank;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn arb_fe() -> impl Strategy<Value = Fp> {
    any::<u64>().prop_map(Fp::from)
}

fn arb_nonzero_fe() -> impl Strategy<Value = Fp> {
    arb_fe().prop_filter("nonzero", |f| bool::from(!f.is_zero()))
}

/// Wire vector with random length 0..=n, all entries random.
fn arb_wire_vec() -> impl Strategy<Value = Vec<Fp>> {
    proptest::collection::vec(arb_fe(), 0..=R::n())
}

/// Wire vector that mimics the alloc optimization pattern: mostly zeros with
/// scattered non-zero entries at random positions.
fn arb_sparse_wire_vec() -> impl Strategy<Value = Vec<Fp>> {
    // Pick a length, then for each position randomly decide zero or non-zero.
    (0..=R::n()).prop_flat_map(|len| {
        proptest::collection::vec(
            prop_oneof![
                8 => Just(Fp::ZERO),
                2 => any::<u64>().prop_map(Fp::from),
            ],
            len,
        )
    })
}

/// Build a polynomial via forward view with random wire vectors.
fn arb_forward_poly() -> impl Strategy<Value = Polynomial<Fp, R>> {
    (
        arb_wire_vec(),
        arb_wire_vec(),
        arb_wire_vec(),
        arb_wire_vec(),
    )
        .prop_map(|(a, b, c, d)| {
            let mut view = View::<Fp, R, Forward>::new();
            view.a = a;
            view.b = b;
            view.c = c;
            view.d = d;
            view.build()
        })
}

/// Build a polynomial via backward view with random wire vectors.
fn arb_backward_poly() -> impl Strategy<Value = Polynomial<Fp, R>> {
    (
        arb_wire_vec(),
        arb_wire_vec(),
        arb_wire_vec(),
        arb_wire_vec(),
    )
        .prop_map(|(a, b, c, d)| {
            let mut view = View::<Fp, R, Backward>::new();
            view.a = a;
            view.b = b;
            view.c = c;
            view.d = d;
            view.build()
        })
}

/// Build a polynomial via forward view with sparse (mostly-zero) wire vectors,
/// mimicking the alloc optimization pattern.
fn arb_sparse_forward_poly() -> impl Strategy<Value = Polynomial<Fp, R>> {
    (
        arb_sparse_wire_vec(),
        arb_sparse_wire_vec(),
        arb_sparse_wire_vec(),
        arb_sparse_wire_vec(),
    )
        .prop_map(|(a, b, c, d)| {
            let mut view = View::<Fp, R, Forward>::new();
            view.a = a;
            view.b = b;
            view.c = c;
            view.d = d;
            view.build()
        })
}

/// Build a polynomial from a mostly-zero dense coefficient vector.
fn arb_sparse_from_coeffs_poly() -> impl Strategy<Value = Polynomial<Fp, R>> {
    proptest::collection::vec(
        prop_oneof![
            8 => Just(Fp::ZERO),
            2 => any::<u64>().prop_map(Fp::from),
        ],
        R::num_coeffs(),
    )
    .prop_map(Polynomial::<Fp, R>::from_coeffs)
}

/// Any polynomial: randomly picks between different construction paths and
/// sparsity patterns.
fn arb_any_poly() -> impl Strategy<Value = Polynomial<Fp, R>> {
    prop_oneof![
        2 => arb_forward_poly(),
        2 => arb_backward_poly(),
        3 => arb_sparse_forward_poly(),
        2 => arb_sparse_from_coeffs_poly(),
        1 => Just(Polynomial::<Fp, R>::new()),
    ]
}

fn arb_dense_coeffs() -> impl Strategy<Value = Vec<Fp>> {
    prop_oneof![
        1 => proptest::collection::vec(arb_fe(), 0..=R::num_coeffs()),
        1 => proptest::collection::vec(
            prop_oneof![
                8 => Just(Fp::ZERO),
                2 => any::<u64>().prop_map(Fp::from),
            ],
            0..=R::num_coeffs(),
        ),
    ]
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    // -----------------------------------------------------------------------
    // from_coeffs roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn from_coeffs_roundtrip(coeffs in arb_dense_coeffs()) {
        let poly = Polynomial::<Fp, R>::from_coeffs(coeffs.clone());
        let mut expected = coeffs;
        expected.resize(R::num_coeffs(), Fp::ZERO);
        prop_assert_eq!(poly.to_dense(), expected);
    }

    // -----------------------------------------------------------------------
    // View degree mapping
    // -----------------------------------------------------------------------

    #[test]
    fn forward_view_degree_mapping(
        a in arb_wire_vec(),
        b in arb_wire_vec(),
        c in arb_wire_vec(),
        d in arb_wire_vec(),
    ) {
        let n = R::n();
        let mut view = View::<Fp, R, Forward>::new();
        view.a = a.clone();
        view.b = b.clone();
        view.c = c.clone();
        view.d = d.clone();
        let poly = view.build();
        let dense = poly.to_dense();

        // c[i] -> degree i
        for (i, val) in c.iter().enumerate() {
            prop_assert_eq!(dense[i], *val);
        }
        // b[i] -> degree 2*n - 1 - i
        for (i, val) in b.iter().enumerate() {
            prop_assert_eq!(dense[2 * n - 1 - i], *val);
        }
        // a[i] -> degree 2*n + i
        for (i, val) in a.iter().enumerate() {
            prop_assert_eq!(dense[2 * n + i], *val);
        }
        // d[i] -> degree 4*n - 1 - i
        for (i, val) in d.iter().enumerate() {
            prop_assert_eq!(dense[4 * n - 1 - i], *val);
        }
    }

    #[test]
    fn forward_view_sparse_mapping(
        a in arb_sparse_wire_vec(),
        b in arb_sparse_wire_vec(),
        c in arb_sparse_wire_vec(),
        d in arb_sparse_wire_vec(),
    ) {
        let n = R::n();
        let mut view = View::<Fp, R, Forward>::new();
        view.a = a.clone();
        view.b = b.clone();
        view.c = c.clone();
        view.d = d.clone();
        let poly = view.build();
        let dense = poly.to_dense();

        for (i, val) in c.iter().enumerate() {
            prop_assert_eq!(dense[i], *val);
        }
        for (i, val) in b.iter().enumerate() {
            prop_assert_eq!(dense[2 * n - 1 - i], *val);
        }
        for (i, val) in a.iter().enumerate() {
            prop_assert_eq!(dense[2 * n + i], *val);
        }
        for (i, val) in d.iter().enumerate() {
            prop_assert_eq!(dense[4 * n - 1 - i], *val);
        }
    }

    #[test]
    fn backward_is_reversal_of_forward(
        a in arb_wire_vec(),
        b in arb_wire_vec(),
        c in arb_wire_vec(),
        d in arb_wire_vec(),
    ) {
        let mut fwd_view = View::<Fp, R, Forward>::new();
        fwd_view.a = a.clone();
        fwd_view.b = b.clone();
        fwd_view.c = c.clone();
        fwd_view.d = d.clone();
        let fwd = fwd_view.build();

        let mut bwd_view = View::<Fp, R, Backward>::new();
        bwd_view.a = a;
        bwd_view.b = b;
        bwd_view.c = c;
        bwd_view.d = d;
        let bwd = bwd_view.build();

        let fwd_dense = fwd.to_dense();
        let bwd_dense = bwd.to_dense();

        let mut bwd_reversed = bwd_dense;
        bwd_reversed.reverse();
        prop_assert_eq!(fwd_dense, bwd_reversed);
    }

    // -----------------------------------------------------------------------
    // eval consistency
    // -----------------------------------------------------------------------

    #[test]
    fn eval_matches_dense(poly in arb_any_poly(), x in arb_fe()) {
        let dense = poly.to_dense();
        let expected = ragu_arithmetic::eval(&dense, x);
        prop_assert_eq!(poly.eval(x), expected);
    }

    // -----------------------------------------------------------------------
    // dilate consistency
    // -----------------------------------------------------------------------

    #[test]
    fn dilate_correct(poly in arb_any_poly(), x in arb_fe(), z in arb_fe()) {
        let original_eval = poly.eval(x * z);
        let mut dilated = poly.clone();
        dilated.dilate(z);
        prop_assert_eq!(dilated.eval(x), original_eval);
    }

    // -----------------------------------------------------------------------
    // revdot consistency
    // -----------------------------------------------------------------------

    #[test]
    fn revdot_matches_dense(a in arb_any_poly(), b in arb_any_poly()) {
        let a_dense = a.to_dense();
        let b_dense = b.to_dense();
        let expected = ragu_arithmetic::dot(a_dense.iter(), b_dense.iter().rev());
        prop_assert_eq!(a.revdot(&b), expected);
    }

    #[test]
    fn revdot_forward_against_backward(
        a in arb_forward_poly(),
        b in arb_backward_poly(),
    ) {
        let a_dense = a.to_dense();
        let b_dense = b.to_dense();
        let expected = ragu_arithmetic::dot(a_dense.iter(), b_dense.iter().rev());
        prop_assert_eq!(a.revdot(&b), expected);
    }

    // -----------------------------------------------------------------------
    // Arithmetic operations
    // -----------------------------------------------------------------------

    #[test]
    fn add_assign_correct(a in arb_any_poly(), b in arb_any_poly(), x in arb_fe()) {
        let expected = a.eval(x) + b.eval(x);
        let mut sum = a;
        sum.add_assign(&b);
        prop_assert_eq!(sum.eval(x), expected);
    }

    #[test]
    fn add_assign_dense_check(a in arb_any_poly(), b in arb_any_poly()) {
        let a_dense = a.to_dense();
        let b_dense = b.to_dense();
        let mut sum = a;
        sum.add_assign(&b);
        let sum_dense = sum.to_dense();
        for i in 0..R::num_coeffs() {
            prop_assert_eq!(sum_dense[i], a_dense[i] + b_dense[i]);
        }
    }

    #[test]
    fn sub_assign_correct(a in arb_any_poly(), b in arb_any_poly(), x in arb_fe()) {
        let expected = a.eval(x) - b.eval(x);
        let mut diff = a;
        diff.sub_assign(&b);
        prop_assert_eq!(diff.eval(x), expected);
    }

    #[test]
    fn add_commutative(a in arb_any_poly(), b in arb_any_poly()) {
        let mut ab = a.clone();
        ab.add_assign(&b);
        let mut ba = b.clone();
        ba.add_assign(&a);
        prop_assert_eq!(ab.to_dense(), ba.to_dense());
    }

    #[test]
    fn add_sub_inverse(a in arb_any_poly(), b in arb_any_poly()) {
        let mut result = a.clone();
        result.add_assign(&b);
        result.sub_assign(&b);
        prop_assert_eq!(result.to_dense(), a.to_dense());
    }

    #[test]
    fn scale_correct(poly in arb_any_poly(), c in arb_fe(), x in arb_fe()) {
        let expected = c * poly.eval(x);
        let mut scaled = poly;
        scaled.scale(c);
        prop_assert_eq!(scaled.eval(x), expected);
    }

    #[test]
    fn negate_correct(poly in arb_any_poly(), x in arb_fe()) {
        let expected = -poly.eval(x);
        let mut negated = poly;
        negated.negate();
        prop_assert_eq!(negated.eval(x), expected);
    }

    #[test]
    fn negate_double_identity(poly in arb_any_poly()) {
        let mut result = poly.clone();
        result.negate();
        result.negate();
        prop_assert_eq!(result.to_dense(), poly.to_dense());
    }

    #[test]
    fn scale_zero_is_zero(poly in arb_any_poly()) {
        let mut result = poly;
        result.scale(Fp::ZERO);
        for c in result.to_dense() {
            prop_assert_eq!(c, Fp::ZERO);
        }
    }

    #[test]
    fn scale_one_is_identity(poly in arb_any_poly()) {
        let original = poly.to_dense();
        let mut result = poly;
        result.scale(Fp::ONE);
        prop_assert_eq!(result.to_dense(), original);
    }

    // -----------------------------------------------------------------------
    // fold
    // -----------------------------------------------------------------------

    #[test]
    fn fold_correct(
        p1 in arb_any_poly(),
        p2 in arb_any_poly(),
        p3 in arb_any_poly(),
        alpha in arb_nonzero_fe(),
        x in arb_fe(),
    ) {
        // fold([p1, p2, p3], alpha) = alpha^2 * p1 + alpha * p2 + p3
        let folded = Polynomial::<Fp, R>::fold([&p1, &p2, &p3], alpha);
        let expected = alpha * alpha * p1.eval(x) + alpha * p2.eval(x) + p3.eval(x);
        prop_assert_eq!(folded.eval(x), expected);
    }

    #[test]
    fn fold_single(poly in arb_any_poly(), alpha in arb_fe(), x in arb_fe()) {
        let folded = Polynomial::<Fp, R>::fold([&poly], alpha);
        prop_assert_eq!(folded.eval(x), poly.eval(x));
    }

    // -----------------------------------------------------------------------
    // PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn eq_across_construction_paths(coeffs in arb_dense_coeffs()) {
        let from_coeffs = Polynomial::<Fp, R>::from_coeffs(coeffs.clone());
        let mut padded = coeffs;
        padded.resize(R::num_coeffs(), Fp::ZERO);
        let from_full = Polynomial::<Fp, R>::from_coeffs(padded);
        prop_assert_eq!(from_coeffs, from_full);
    }

    #[test]
    fn eq_reflexive(poly in arb_any_poly()) {
        prop_assert_eq!(&poly, &poly);
    }

    // -----------------------------------------------------------------------
    // Ring FFT roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn ring_fft_roundtrip(
        p0 in arb_any_poly(),
        p1 in arb_any_poly(),
        p2 in arb_any_poly(),
        p3 in arb_any_poly(),
    ) {
        let domain = ragu_arithmetic::Domain::<Fp>::new(2); // size 4
        let mut polys = alloc::vec![p0, p1, p2, p3];
        let originals: Vec<_> = polys.clone();

        domain.ring_fft::<Polynomial<Fp, R>>(&mut polys);
        domain.ring_ifft::<Polynomial<Fp, R>>(&mut polys);

        for (orig, result) in originals.iter().zip(polys.iter()) {
            prop_assert_eq!(orig.to_dense(), result.to_dense());
        }
    }

    // -----------------------------------------------------------------------
    // Commitment consistency
    // -----------------------------------------------------------------------

    #[test]
    fn commit_matches_dense(poly in arb_any_poly(), blind in arb_fe()) {
        use ragu_arithmetic::Cycle;
        use ragu_pasta::Pasta;

        let pasta = Pasta::baked();
        let generators = Pasta::host_generators(pasta);

        let sparse_commit = poly.commit_to_affine(generators, blind);

        let dense_poly =
            crate::polynomials::unstructured::Polynomial::<Fp, R>::from_coeffs(poly.to_dense());
        let dense_commit = dense_poly.commit_to_affine(generators, blind);

        prop_assert_eq!(sparse_commit, dense_commit);
    }

    // -----------------------------------------------------------------------
    // Zero pruning after arithmetic
    // -----------------------------------------------------------------------

    #[test]
    fn sub_self_is_empty(poly in arb_any_poly()) {
        let mut result = poly.clone();
        result.sub_assign(&poly);
        prop_assert!(result.is_empty(), "sub_assign(self) should yield empty polynomial");
        prop_assert_eq!(result.num_nonzero(), 0);
    }

    #[test]
    fn add_negation_is_empty(poly in arb_any_poly()) {
        let mut negated = poly.clone();
        negated.negate();
        let mut result = poly;
        result.add_assign(&negated);
        prop_assert!(result.is_empty(), "add_assign(-self) should yield empty polynomial");
    }
}

// ---------------------------------------------------------------------------
// Deterministic edge cases
// ---------------------------------------------------------------------------

#[test]
fn zero_polynomial_operations() {
    let zero = Polynomial::<Fp, R>::new();
    assert!(zero.is_empty());
    assert_eq!(zero.num_nonzero(), 0);
    assert_eq!(zero.eval(Fp::from(42u64)), Fp::ZERO);
    assert_eq!(zero.revdot(&zero), Fp::ZERO);

    let mut p = zero.clone();
    p.scale(Fp::from(5u64));
    assert!(p.is_empty());
    p.negate();
    assert!(p.is_empty());

    // add zero to zero
    let mut p = zero.clone();
    p.add_assign(&zero);
    assert!(p.is_empty());
}

#[test]
fn single_coefficient_at_degree_boundaries() {
    let val = Fp::from(7u64);
    let x = Fp::from(3u64);

    for degree in [
        0,
        1,
        R::n() - 1,
        R::n(),
        2 * R::n() - 1,
        2 * R::n(),
        3 * R::n(),
        R::num_coeffs() - 1,
    ] {
        let mut coeffs = alloc::vec![Fp::ZERO; R::num_coeffs()];
        coeffs[degree] = val;
        let poly = Polynomial::<Fp, R>::from_coeffs(coeffs);
        assert_eq!(
            poly.eval(x),
            val * x.pow_vartime([u64::try_from(degree).unwrap()]),
            "degree {degree}"
        );
        assert_eq!(poly.num_nonzero(), 1, "degree {degree}");
    }
}

#[test]
fn only_a_wire_data() {
    let mut view = View::<Fp, R, Forward>::new();
    for _ in 0..R::n() {
        view.a.push(Fp::random(&mut rand::rng()));
    }
    let poly = view.build();

    // a[i] -> degree 2*n+i, so non-zero block at [2*n, 3*n).
    assert_eq!(poly.blocks().len(), 1);
    assert_eq!(poly.blocks()[0].0, 2 * R::n());
    assert_eq!(poly.blocks()[0].1.len(), R::n());
}

#[test]
fn only_d_wire_data() {
    let mut view = View::<Fp, R, Forward>::new();
    for _ in 0..R::n() {
        view.d.push(Fp::random(&mut rand::rng()));
    }
    let poly = view.build();

    // d[i] -> degree 4*n-1-i, so block at [3*n, 4*n).
    assert_eq!(poly.blocks().len(), 1);
    assert_eq!(poly.blocks()[0].0, 3 * R::n());
    assert_eq!(poly.blocks()[0].1.len(), R::n());
}

#[test]
fn alloc_optimization_pattern() {
    // Simulate the alloc optimization: most gates are mul (a,b,c,0),
    // a few are alloc (a,0,0,d).
    let n = R::n();
    let mut view = View::<Fp, R, Forward>::new();
    for i in 0..n {
        if i % 10 == 0 {
            // Alloc gate: a is non-zero, b=c=0, d is non-zero.
            view.a.push(Fp::random(&mut rand::rng()));
            view.b.push(Fp::ZERO);
            view.c.push(Fp::ZERO);
            view.d.push(Fp::random(&mut rand::rng()));
        } else {
            // Mul gate: a,b,c non-zero, d=0.
            let a = Fp::random(&mut rand::rng());
            let b = Fp::random(&mut rand::rng());
            view.a.push(a);
            view.b.push(b);
            view.c.push(a * b);
            view.d.push(Fp::ZERO);
        }
    }
    let poly = view.build();

    // Verify eval consistency.
    let dense = poly.to_dense();
    let x = Fp::random(&mut rand::rng());
    assert_eq!(poly.eval(x), ragu_arithmetic::eval(&dense, x));

    // The d-wire region should be sparse (few non-zero entries).
    // d[i] -> degree 4*n-1-i, so d occupies degrees [3*n, 4*n).
    // Only n/10 entries are non-zero.
    let d_region = &dense[3 * n..4 * n];
    let d_nonzero = d_region.iter().filter(|x| bool::from(!x.is_zero())).count();
    let expected_allocs = (0..n).filter(|i| i % 10 == 0).count();
    assert_eq!(d_nonzero, expected_allocs);
}
