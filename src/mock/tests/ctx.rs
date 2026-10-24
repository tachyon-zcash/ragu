use alloc::vec;

use ragu_circuits::polynomials::{TestRank, sparse};
use ragu_core::{
    Cycle,
    drivers::Driver,
    maybe::Maybe as _,
    pasta::{EpAffine, Fp, Pasta},
};
use ragu_primitives::{Element, Point, Simulator, poseidon::Sponge};
use udon::{curve::Affine as _, field::Field};

use super::{super::hooks::FrameworkHooks, assert_invalid_witness, test_params};
use crate::StepCtx;

/// Independent sponge computation used to check the public challenge hook.
fn expected_challenge(inputs: &[Fp]) -> Fp {
    let mut dr = Simulator::<Fp>::new();
    let mut sponge = Sponge::new(&mut dr, Pasta::circuit_poseidon(test_params()));
    let domain = Element::constant(
        &mut dr,
        Fp::from_u128(u64::from_le_bytes(*b"raguchal") as u128),
    );
    sponge
        .absorb(&mut dr, &domain)
        .expect("domain absorption should succeed");
    for input in inputs {
        let input = Element::constant(&mut dr, *input);
        sponge
            .absorb(&mut dr, &input)
            .expect("input absorption should succeed");
    }
    *sponge
        .squeeze(&mut dr)
        .expect("challenge squeeze should succeed")
        .value()
        .take()
}

#[test]
fn derive_challenge_absorbs_real_gadgets() {
    let mut dr = Simulator::<Fp>::new();
    let mut hooks = FrameworkHooks::new(test_params());
    let mut ctx = StepCtx::new(&mut dr, &mut hooks);

    let scalar = Element::constant(ctx.dr, Fp::from(7u64));
    let scalar_challenge = ctx
        .derive_challenge(&scalar)
        .expect("a field element gadget should be accepted");
    assert_eq!(
        *scalar_challenge.value().take(),
        expected_challenge(&[Fp::from(7u64)])
    );

    let point = Point::<'_, _, EpAffine>::constant(ctx.dr, EpAffine::generator())
        .expect("the generator should be a valid point gadget");
    let (x, y) = point
        .value()
        .take()
        .coordinates()
        .expect("the generator is not the identity");
    let point_challenge = ctx
        .derive_challenge(&point)
        .expect("a point gadget should be accepted");
    assert_eq!(*point_challenge.value().take(), expected_challenge(&[x, y]));
}

#[test]
fn poly_query_checks_the_committed_polynomial() {
    let mut dr = Simulator::<Fp>::new();
    let mut hooks = FrameworkHooks::new(test_params());
    let mut ctx = StepCtx::new(&mut dr, &mut hooks);

    // 3 + x + 4x², named below by the commitment returned from witnessing it.
    let polynomial = sparse::Polynomial::<Fp, TestRank>::from_coeffs(vec![
        Fp::from(3u64),
        Fp::ONE,
        Fp::from(4u64),
    ]);
    let expected_commitment = polynomial.commit_to_affine(Pasta::host_generators(test_params()));
    let commitment_bytes = expected_commitment.to_bytes();
    let commitment_bytes: &[u8] = commitment_bytes.as_ref();
    let limb = |bytes: &[u8]| {
        Fp::from_u128(u128::from_le_bytes(
            bytes
                .try_into()
                .expect("a commitment limb contains 16 bytes"),
        ))
    };
    let expected_limbs = [limb(&commitment_bytes[..16]), limb(&commitment_bytes[16..])];

    let handle = ctx
        .witness_polynomial(Simulator::<Fp>::just(|| polynomial.clone()))
        .expect("witnessing a nonzero commitment should succeed");
    assert_eq!(handle.value().take(), expected_limbs);
    let commitment_challenge = ctx
        .derive_challenge(&handle)
        .expect("a polynomial commitment handle should be accepted");
    assert_eq!(
        *commitment_challenge.value().take(),
        expected_challenge(&expected_limbs)
    );

    let x = Fp::from(2u64);
    let y = Fp::from(21u64);
    let evaluation = ctx
        .evaluate(&handle, Simulator::<Fp>::just(|| x))
        .expect("the witnessed commitment should be evaluable");
    assert_eq!(evaluation.take(), y);

    let x_gadget = Element::constant(ctx.dr, x);
    let y_gadget = Element::constant(ctx.dr, y);
    ctx.enforce_poly_query(&handle, x_gadget, y_gadget)
        .expect("the correct opening should be accepted");

    let x_gadget = Element::constant(ctx.dr, x);
    let wrong_y = Element::constant(ctx.dr, y + Fp::ONE);
    let error = ctx
        .enforce_poly_query(&handle, x_gadget, wrong_y)
        .expect_err("an incorrect opening must be rejected");
    assert_invalid_witness(
        error,
        "poly-query rejected: the polynomial does not evaluate to the claimed value at the claimed point",
    );

    assert_eq!(
        hooks.into_outputs().take(),
        vec![(expected_commitment.to_projective(), x, y)],
        "only the valid opening should be recorded"
    );
}

#[test]
fn identity_polynomial_commitment_is_accepted() {
    let mut dr = Simulator::<Fp>::new();
    let mut hooks = FrameworkHooks::new(test_params());
    let mut ctx = StepCtx::new(&mut dr, &mut hooks);
    let zero_polynomial = sparse::Polynomial::<Fp, TestRank>::new();

    let handle = ctx
        .witness_polynomial(Simulator::<Fp>::just(|| zero_polynomial))
        .expect("the zero polynomial's identity commitment should be witnessed");
    let challenge = ctx
        .derive_challenge(&handle)
        .expect("an identity commitment handle should be challenge input");
    let identity_limbs = handle.value().take();
    assert_eq!(
        *challenge.value().take(),
        expected_challenge(&identity_limbs),
        "the identity commitment handle should contribute its compressed encoding"
    );

    let x = Fp::from(19u64);
    let evaluation = ctx
        .evaluate(&handle, Simulator::<Fp>::just(|| x))
        .expect("the zero polynomial should be evaluable");
    assert_eq!(evaluation.take(), Fp::ZERO, "zero evaluates independently to zero");

    let x_gadget = Element::constant(ctx.dr, x);
    let zero_gadget = Element::constant(ctx.dr, Fp::ZERO);
    ctx.enforce_poly_query(&handle, x_gadget, zero_gadget)
        .expect("a zero opening for the identity commitment should be accepted");
}

#[test]
fn real_point_identity_constant_is_rejected() {
    let mut dr = Simulator::<Fp>::new();
    let error = match Point::<'_, _, EpAffine>::constant(&mut dr, EpAffine::identity()) {
        Ok(_) => panic!("a real point constant at identity must be rejected"),
        Err(error) => error,
    };
    assert_invalid_witness(error, "point at infinity cannot be witnessed");
}

#[test]
fn real_point_identity_allocation_is_rejected() {
    let mut dr = Simulator::<Fp>::new();
    let error = match Point::<'_, _, EpAffine>::alloc(
        &mut dr,
        Simulator::<Fp>::just(|| EpAffine::identity()),
    ) {
        Ok(_) => panic!("a real point allocation at identity must be rejected"),
        Err(error) => error,
    };
    assert_invalid_witness(error, "point at infinity cannot be witnessed");
}
