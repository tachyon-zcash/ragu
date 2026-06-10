use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;

use crate::{
    ctx::StepCtx,
    hooks::{FrameworkHooks, PolyQueryClaim},
    polynomial::{Commitment, Polynomial},
    relations::{enforce_poly_concat, enforce_poly_product, enforce_poly_splice},
};

/// Distinct nonzero values, so any reordering or substitution is detectable.
fn values(n: u32) -> Vec<Fp> {
    (0..n)
        .map(|i| Fp::from(u64::from(i) + 1) * Fp::from(7u64))
        .collect()
}

/// The poly-query opening claims a relation recorded, read without consuming the
/// `hooks` (so a test can inspect them after the call).
fn recorded_claims(hooks: &FrameworkHooks) -> Vec<PolyQueryClaim> {
    hooks.clone().into_outputs()
}

/// The opening claims a relation is expected to emit for `operands`: one
/// `(commitment, z, eval(z))` per operand at the shared challenge `z` derived
/// from the operand commitments in order -- exactly the shape every relation
/// here produces. Pass the operands in the order the relation opens them.
fn expected_opening_claims(operands: &[&Polynomial]) -> Vec<PolyQueryClaim> {
    let coms: Vec<Commitment> = operands.iter().map(|poly| poly.commit()).collect();
    let mut hooks = FrameworkHooks::new();
    let mut ctx = StepCtx::new(&mut hooks);
    let z = ctx.derive_challenge(&coms).unwrap();
    operands
        .iter()
        .zip(&coms)
        .map(|(p, &com)| (com, z, p.eval(z)))
        .collect()
}

#[test]
fn product_accepts_the_product() {
    let a = Polynomial::from_roots(&[Fp::from(1u64), Fp::from(2u64)]);
    let b = Polynomial::from_roots(&[Fp::from(3u64)]);
    // product = a · b is prover-supplied; the relation confirms it against the
    // three committed polynomials without ever multiplying.
    let product = a.multiply(&b);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_product(&mut ctx, &a, &b, &product).unwrap();
    }
    // It opened exactly the three operands at the shared challenge.
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&a, &b, &product]),
    );
}

#[test]
fn product_rejects_a_result_that_is_not_the_product() {
    let a = Polynomial::from_roots(&[Fp::from(1u64), Fp::from(2u64)]);
    let b = Polynomial::from_roots(&[Fp::from(3u64)]);
    // A polynomial that is not a · b.
    let result = Polynomial::from_roots(&[Fp::from(4u64), Fp::from(5u64)]);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        assert!(enforce_poly_product(&mut ctx, &a, &b, &result).is_err());
    }
    // Rejection is at the identity check, before any opening is recorded.
    assert!(recorded_claims(&hooks).is_empty());
}

#[test]
fn concat_accepts_the_concatenation() {
    let v = values(6);
    let head = Polynomial::from_coeffs(&v[..2]);
    let tail = Polynomial::from_coeffs(&v[2..]);
    // result = head ++ tail is prover-supplied; the shift offset = 2 is a witness
    // the relation confirms against the three committed sequences.
    let result = Polynomial::from_coeffs(&v);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_concat(&mut ctx, &head, &tail, 2, &result).unwrap();
    }
    // It opened exactly the three operands at the shared challenge.
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&head, &tail, &result]),
    );
}

#[test]
fn concat_rejects_a_result_that_is_not_the_concatenation() {
    let v = values(6);
    let head = Polynomial::from_coeffs(&v[..2]);
    let tail = Polynomial::from_coeffs(&v[2..]);
    // A polynomial that is not head ++ tail.
    let mut bad = v.clone();
    bad.swap(0, 5);
    let result = Polynomial::from_coeffs(&bad);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        assert!(enforce_poly_concat(&mut ctx, &head, &tail, 2, &result).is_err());
    }
    // Rejection is at the identity check, before any opening is recorded.
    assert!(recorded_claims(&hooks).is_empty());
}

#[test]
fn concat_rejects_a_wrong_offset() {
    // Only offset = len(head) = 2 satisfies the shifted-sum identity: the genuine
    // offset opens the three operands, and wrong offsets are rejected with nothing
    // recorded.
    let v = values(6);
    let head = Polynomial::from_coeffs(&v[..2]);
    let tail = Polynomial::from_coeffs(&v[2..]);
    let result = Polynomial::from_coeffs(&v);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_concat(&mut ctx, &head, &tail, 2, &result).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&head, &tail, &result]),
    );

    for bad_offset in [3_usize, 1] {
        let mut hooks = FrameworkHooks::new();
        {
            let mut ctx = StepCtx::new(&mut hooks);
            assert!(enforce_poly_concat(&mut ctx, &head, &tail, bad_offset, &result).is_err());
        }
        assert!(recorded_claims(&hooks).is_empty());
    }
}

#[test]
fn splice_accepts_the_splice() {
    // combined = left ++ [mid] ++ right with left = v[..2], mid = v[2],
    // right = v[3..]; the spliced scalar lands at degree offset = len(left) = 2.
    let v = values(6);
    let left = Polynomial::from_coeffs(&v[..2]);
    let right = Polynomial::from_coeffs(&v[3..]);
    let mid = v[2];
    let combined = Polynomial::from_coeffs(&v);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_splice(&mut ctx, &left, mid, &right, 2, &combined).unwrap();
    }
    // It opened exactly the three committed operands -- and no claim for `mid`.
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&left, &right, &combined]),
    );
}

#[test]
fn splice_rejects_a_result_that_is_not_the_splice() {
    let v = values(6);
    let left = Polynomial::from_coeffs(&v[..2]);
    let right = Polynomial::from_coeffs(&v[3..]);
    let mid = v[2];
    // A polynomial that is not left ++ [mid] ++ right.
    let mut bad = v.clone();
    bad.swap(0, 5);
    let combined = Polynomial::from_coeffs(&bad);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        assert!(enforce_poly_splice(&mut ctx, &left, mid, &right, 2, &combined).is_err());
    }
    // Rejection is at the identity check, before any opening is recorded.
    assert!(recorded_claims(&hooks).is_empty());
}

#[test]
fn splice_rejects_a_wrong_offset() {
    // Only offset = len(left) = 2 satisfies the spliced-sum identity when `mid` is
    // held fixed: the genuine offset opens the three committed operands, and wrong
    // offsets are rejected with nothing recorded.
    let v = values(6);
    let left = Polynomial::from_coeffs(&v[..2]);
    let right = Polynomial::from_coeffs(&v[3..]);
    let mid = v[2];
    let combined = Polynomial::from_coeffs(&v);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_splice(&mut ctx, &left, mid, &right, 2, &combined).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&left, &right, &combined]),
    );

    for bad_offset in [3_usize, 1] {
        let mut hooks = FrameworkHooks::new();
        {
            let mut ctx = StepCtx::new(&mut hooks);
            assert!(
                enforce_poly_splice(&mut ctx, &left, mid, &right, bad_offset, &combined).is_err()
            );
        }
        assert!(recorded_claims(&hooks).is_empty());
    }
}

#[test]
fn splice_with_a_free_mid_proves_an_arbitrary_result() {
    // CHARACTERIZATION (not a soundness guarantee): this demonstrates WHY the
    // splice's `mid` MUST be bound before the challenge. The identity is linear in
    // `mid`, so for a `combined` that is NOT the splice of `left`/`right`, a prover
    // free to choose `mid` after seeing the challenge can solve for the unique
    // `mid` that satisfies the point-wise check, and the relation accepts. The
    // recorded openings are then indistinguishable from honest openings of the
    // committed operands -- the forgery is invisible at the claim level, so only
    // binding `mid` upstream (before the challenge) prevents it.
    let v = values(6);
    let left = Polynomial::from_coeffs(&v[..2]);
    let right = Polynomial::from_coeffs(&v[3..]);
    let offset = 2usize;
    // An arbitrary value unrelated to any splice of left/right.
    let not_combined = Polynomial::from_coeffs(&values(9)[3..]);

    // Reproduce the relation's challenge (a pure hash of the three commitments in
    // the order the relation uses) to solve for a forging `mid`.
    let z = {
        let mut hooks = FrameworkHooks::new();
        let mut ctx = StepCtx::new(&mut hooks);
        ctx.derive_challenge(&[left.commit(), right.commit(), not_combined.commit()])
            .unwrap()
    };
    let zo = z.pow_vartime([offset as u64]);
    let zo_inv = Option::<Fp>::from(zo.invert()).expect("challenge is nonzero");
    // mid = (combined(z) - left(z) - z^(offset+1)·right(z)) · z^{-offset}.
    let forged_mid = (not_combined.eval(z) - left.eval(z) - zo * z * right.eval(z)) * zo_inv;

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_splice(&mut ctx, &left, forged_mid, &right, offset, &not_combined).unwrap();
    }
    // Accepted -- and the openings look exactly like honest openings of the
    // committed operands.
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&left, &right, &not_combined]),
    );
}

#[test]
fn product_accepts_any_factorization() {
    // CHARACTERIZATION (not a soundness guarantee): the relation pins `product =
    // multiplicand · multiplier` but says nothing about WHICH factors those are.
    // Two distinct factorizations of the same committed product both pass, each
    // recording the openings of its own factors -- so a statement that relies on
    // the factors must bind their commitments (the module-level binding
    // obligation).
    let (r1, r2, r3) = (Fp::from(1u64), Fp::from(2u64), Fp::from(3u64));
    let product = Polynomial::from_roots(&[r1, r2, r3]); // (x-1)(x-2)(x-3)

    // Grouping A: (x-1)(x-2) · (x-3).
    let a1 = Polynomial::from_roots(&[r1, r2]);
    let b1 = Polynomial::from_roots(&[r3]);
    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_product(&mut ctx, &a1, &b1, &product).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&a1, &b1, &product]),
    );

    // Grouping B: (x-1) · (x-2)(x-3) -- a different opening set for the same
    // committed product.
    let a2 = Polynomial::from_roots(&[r1]);
    let b2 = Polynomial::from_roots(&[r2, r3]);
    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_product(&mut ctx, &a2, &b2, &product).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&a2, &b2, &product]),
    );
}

#[test]
fn product_accepts_a_trailing_zero_padded_result() {
    // CHARACTERIZATION: the binding target is the commitment *point*, and `commit`
    // ignores trailing-zero coefficients (zero · generator = identity). A
    // polynomial and its trailing-zero padding share a commitment (so compare
    // equal) and are interchangeable in the relation -- the obligation is
    // commitment-identity, not the literal coefficient vector.
    let a = Polynomial::from_roots(&[Fp::from(1u64), Fp::from(2u64)]);
    let b = Polynomial::from_roots(&[Fp::from(3u64)]);
    let product = a.multiply(&b);

    let mut padded = product.coefficients().to_vec();
    padded.push(Fp::ZERO);
    padded.push(Fp::ZERO);
    let product_padded = Polynomial::from_coeffs(&padded);

    assert_eq!(product, product_padded);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_product(&mut ctx, &a, &b, &product_padded).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&a, &b, &product_padded]),
    );
}

#[test]
fn concat_accepts_overlapping_head_and_tail() {
    // CHARACTERIZATION (not a soundness guarantee): the relation enforces only the
    // shifted-sum identity `result = head + X^offset·tail`, NOT `deg(head) <
    // offset`. With head reaching degree >= offset, head and tail overlap
    // additively; a `result` matching that sum still passes (and records honest
    // openings) even though it is not a clean concatenation. This is why callers
    // owe `deg(head) < offset`.
    let v = values(5);
    let head = Polynomial::from_coeffs(&v[..3]); // degree 2, reaches the offset
    let tail = Polynomial::from_coeffs(&v[3..]); // [t0, t1]
    let offset = 2usize;
    // head + X^2·tail overlaps at index 2: [h0, h1, h2 + t0, t1].
    let result = Polynomial::from_coeffs(&[v[0], v[1], v[2] + v[3], v[4]]);

    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_concat(&mut ctx, &head, &tail, offset, &result).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&head, &tail, &result]),
    );
}

#[test]
fn concat_accepts_a_zero_padded_offset() {
    // CHARACTERIZATION (not a soundness guarantee): `offset` is not pinned to
    // `len(head)`. The same `head`/`tail` form a valid relation at the tight
    // offset = len(head) = 2 AND at offset = 3 (a zero gap between them), with
    // different `result`s, both accepted. A statement that reads `result` against
    // a fixed absolute layout must therefore pin `offset`.
    let v = values(4);
    let head = Polynomial::from_coeffs(&v[..2]); // [h0, h1], len 2
    let tail = Polynomial::from_coeffs(&v[2..]); // [t0, t1]

    // Tight: head ++ tail = [h0, h1, t0, t1] at offset 2.
    let tight = Polynomial::from_coeffs(&v);
    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_concat(&mut ctx, &head, &tail, 2, &tight).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&head, &tail, &tight]),
    );

    // Zero-padded: head ++ [0] ++ tail = [h0, h1, 0, t0, t1] at offset 3.
    let padded = Polynomial::from_coeffs(&[v[0], v[1], Fp::ZERO, v[2], v[3]]);
    let mut hooks = FrameworkHooks::new();
    {
        let mut ctx = StepCtx::new(&mut hooks);
        enforce_poly_concat(&mut ctx, &head, &tail, 3, &padded).unwrap();
    }
    assert_eq!(
        recorded_claims(&hooks),
        expected_opening_claims(&[&head, &tail, &padded]),
    );
}
