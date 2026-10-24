use alloc::vec;

use ragu_circuits::polynomials::{TestRank, sparse};
use ragu_core::{
    Cycle, Error, Result,
    drivers::Driver,
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::{EpAffine, Fp, Pasta},
};
use ragu_primitives::{Element, Point, Simulator, io::{Buffer, Write}, poseidon::Sponge};
use udon::{curve::Affine as _, field::Field};

use super::{super::hooks::FrameworkHooks, assert_invalid_witness, test_params};
use crate::StepCtx;

#[derive(Gadget, Write)]
struct Pair<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    first: Element<'dr, D>,
    #[ragu(gadget)]
    second: Element<'dr, D>,
}

#[derive(Gadget)]
struct RejectingWrite<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    element: Element<'dr, D>,
}

impl Write<Fp> for Kind![Fp; @RejectingWrite<'_, _>] {
    fn write_gadget<'dr, D: Driver<'dr, F = Fp>, B: Buffer<'dr, D>>(
        _: &Bound<'dr, D, Self>,
        _: &mut D,
        _: &mut B,
    ) -> Result<()> {
        Err(Error::InvalidWitness("test write rejected".into()))
    }
}

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

    let scalar_value = Fp::from(7u64);
    let scalar = Element::alloc(
        ctx.dr,
        &mut (),
        Simulator::<Fp>::just(|| scalar_value),
    )
    .expect("the scalar input should be allocated");
    let gates_before = ctx.dr.num_gates();
    let constraints_before = ctx.dr.num_constraints();
    let scalar_challenge = ctx
        .derive_challenge(&scalar)
        .expect("a field element gadget should be accepted");
    assert!(
        ctx.dr.num_gates() > gates_before + 1,
        "challenge derivation should synthesize the sponge on the caller driver"
    );
    assert!(
        ctx.dr.num_constraints() > constraints_before,
        "challenge derivation should emit caller-driver constraints"
    );
    assert_eq!(
        *scalar_challenge.value().take(),
        expected_challenge(&[scalar_value])
    );

    let point = Point::<'_, _, EpAffine>::alloc(
        ctx.dr,
        Simulator::<Fp>::just(EpAffine::generator),
    )
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
fn derive_challenge_accepts_composite_and_empty_inputs() {
    let mut dr = Simulator::<Fp>::new();
    let mut hooks = FrameworkHooks::new(test_params());
    let mut ctx = StepCtx::new(&mut dr, &mut hooks);
    let first_value = Fp::from(3u64);
    let second_value = Fp::from(11u64);
    let first = Element::alloc(
        ctx.dr,
        &mut (),
        Simulator::<Fp>::just(|| first_value),
    )
    .expect("the first composite input should be allocated");
    let second = Element::alloc(
        ctx.dr,
        &mut (),
        Simulator::<Fp>::just(|| second_value),
    )
    .expect("the second composite input should be allocated");
    let pair = Pair {
        first: first.clone(),
        second: second.clone(),
    };
    let pair_challenge = ctx
        .derive_challenge(&pair)
        .expect("a writable composite should be accepted");
    assert_eq!(
        *pair_challenge.value().take(),
        expected_challenge(&[first_value, second_value])
    );

    let reversed = Pair {
        first: second,
        second: first,
    };
    let reversed_challenge = ctx
        .derive_challenge(&reversed)
        .expect("a reversed writable composite should be accepted");
    assert_eq!(
        *reversed_challenge.value().take(),
        expected_challenge(&[second_value, first_value])
    );
    assert_ne!(
        *pair_challenge.value().take(),
        *reversed_challenge.value().take(),
        "reversing distinct absorbed inputs should change the challenge"
    );

    let empty_challenge = ctx
        .derive_challenge(&())
        .expect("empty input should still derive a domain-separated challenge");
    assert_eq!(
        *empty_challenge.value().take(),
        expected_challenge(&[]),
        "empty input should absorb the domain tag and squeeze once"
    );
}

#[test]
fn derive_challenge_propagates_write_errors() {
    let mut dr = Simulator::<Fp>::new();
    let mut hooks = FrameworkHooks::new(test_params());
    let mut ctx = StepCtx::new(&mut dr, &mut hooks);
    let input = RejectingWrite {
        element: Element::constant(ctx.dr, Fp::ZERO),
    };

    let error = match ctx.derive_challenge(&input) {
        Ok(_) => panic!("a rejected gadget write should fail challenge derivation"),
        Err(error) => error,
    };
    assert_invalid_witness(error, "test write rejected");
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
