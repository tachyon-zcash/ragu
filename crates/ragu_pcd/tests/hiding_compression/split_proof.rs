//! The final revdot split identity and the query-point layout, over committed
//! inputs on either curve. The private prefix must eventually prove where the
//! advised transcript challenges and folded terms came from.

use alloc::vec::Vec;
use core::array;

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::{Always, Empty, Maybe, MaybeKind},
};
use ragu_primitives::Element;
use rand::CryptoRng;
use udon::{curve::Affine, field::Field};

use super::{
    Bases, CLAIMS, DERIVED, TestR, Transcript,
    batch_proof::{BatchPublic, Opening},
    circuit_proof::{CircuitProof, Recorder},
};
use ragu_circuits::polynomials::Rank;

pub(super) const AUX: usize = 7;
pub(super) const PUBLIC_AUX: [usize; 5] = [0, 1, 2, 5, 6];
const REDUCTION_QUERIES: usize = DERIVED + 3;

pub(super) fn auxiliaries<F: Field>(
    r: F,
    z: F,
    openings: &[F],
    (rho, terms): (F, [(F, F); 3]),
) -> [F; AUX] {
    // Derived::ALL is A, Dilated, B, Inner, Outer.
    let [(a, b), (inner, w_i), (outer, w_o)] = terms;
    assert_eq!((inner, outer), (openings[3], openings[4]));
    [
        r,
        z,
        rho,
        a - openings[0],
        b - openings[1] - openings[2],
        w_i,
        w_o,
    ]
}

fn synthesize<'dr, F: Field, M: MaybeKind>(
    dr: &mut Recorder<F, M>,
    values: DriverValue<Recorder<F, M>, Vec<F>>,
) -> Result<()> {
    let mut bound = Vec::with_capacity(AUX + 2 * REDUCTION_QUERIES);
    for i in 0..AUX + 2 * REDUCTION_QUERIES {
        let element = Element::alloc(dr, &mut (), values.as_ref().map(|values| values[i]))?;
        dr.bind(element.wire())?;
        bound.push(element);
    }
    let [r, z, rho, a_public, b_public, w_i, w_o] = &bound[..AUX] else {
        unreachable!();
    };
    let point = |i: usize| &bound[AUX + 2 * i];
    let value = |i: usize| &bound[AUX + 2 * i + 1];
    // Derived openings at r, except for the dilated one at rz.
    for i in [0, 2, 3, 4, DERIVED + 1] {
        dr.enforce_equal(r.wire(), point(i).wire())?;
    }
    let rz = r.mul(dr, z)?;
    dr.enforce_equal(rz.wire(), point(1).wire())?;
    let inverse_r = point(DERIVED);
    let one = r.mul(dr, inverse_r)?;
    dr.enforce_equal(one.wire(), &<Recorder<F, M> as Driver>::ONE)?;
    let zero = Element::constant(dr, F::ZERO);
    dr.enforce_equal(zero.wire(), point(DERIVED + 2).wire())?;

    let a = value(0).add(dr, a_public);
    let b = value(1).add(dr, value(2)).add(dr, b_public);
    let ab = a.mul(dr, &b)?;
    let inner = value(3).mul(dr, w_i)?;
    let outer = value(4).mul(dr, w_o)?;
    let outer_weighted = rho.mul(dr, &outer)?;
    let errors = inner.add(dr, &outer_weighted);
    let errors = rho.mul(dr, &errors)?;
    let combined = ab.add(dr, &errors);

    let mut r_to_n = r.clone();
    for _ in 0..TestR::RANK {
        r_to_n = r_to_n.mul(dr, &r_to_n)?;
    }
    let r_to_n_minus_1 = r_to_n.mul(dr, inverse_r)?;
    let p = r_to_n_minus_1.mul(dr, value(DERIVED))?;
    let q = r_to_n.mul(dr, value(DERIVED + 1))?;
    let split = p.add(dr, &q);
    dr.enforce_equal(combined.wire(), split.wire())?;
    Ok(())
}

pub(super) fn prove<C: Affine>(
    bases: Bases<C>,
    transcript: Transcript,
    aux: &[Opening<C::Scalar>; AUX],
    queries: &[(Opening<C::Scalar>, Opening<C::Scalar>); CLAIMS],
    rng: &mut impl CryptoRng,
) -> CircuitProof<C> {
    let bound: Vec<_> = aux
        .iter()
        .copied()
        .chain(
            queries[..REDUCTION_QUERIES]
                .iter()
                .flat_map(|&(x, y)| [x, y]),
        )
        .collect();
    let mut recorder = Recorder::<C::Scalar, Always<()>>::new();
    let values = Recorder::<C::Scalar, Always<()>>::just(|| {
        bound.iter().map(|opening| opening.value).collect()
    });
    synthesize(&mut recorder, values).unwrap();
    recorder.prove(bases, domain(transcript), &bound, rng)
}

pub(super) fn verify<C: Affine>(
    bases: Bases<C>,
    transcript: Transcript,
    public: &BatchPublic<C>,
    proof: &CircuitProof<C>,
) -> bool {
    let mut shape = Recorder::<C::Scalar, Empty>::new();
    synthesize(&mut shape, Empty).unwrap();
    let bound: [_; AUX + 2 * REDUCTION_QUERIES] = array::from_fn(|i| {
        if i < AUX {
            public.split[i]
        } else {
            let (x, y) = public.queries[(i - AUX) / 2];
            if (i - AUX) % 2 == 0 { x } else { y }
        }
    });
    proof.verify(&shape, bases, domain(transcript), &bound)
}

fn domain(mut transcript: Transcript) -> Transcript {
    transcript.bytes(b"private revdot split identity");
    transcript
}
