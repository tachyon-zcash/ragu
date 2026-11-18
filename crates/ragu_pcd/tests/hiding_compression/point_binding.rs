//! Bind a private point gadget to its public ElGamal ciphertext.

use ragu_core::{
    Coeff, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Boolean, Element, GadgetExt, NonzeroBank, Point};
use udon::{
    curve::{EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{Bases, HiddenPoint};

pub(super) fn enforce_opening<'dr, D: Driver<'dr, F = C::Base>, C: Affine>(
    dr: &mut D,
    point: &Point<'dr, D, C>,
    blind: DriverValue<D, C::Scalar>,
    ciphertext: HiddenPoint<C>,
    bases: Bases<C>,
) -> Result<()> {
    let witness = blind.map(|scalar| scalar.to_le_bits());
    NonzeroBank::scope(dr, |dr, bank| {
        let first_start = Point::constant(dr, bases.g0)?;
        let second_offset_point = Point::constant(dr, bases.g1)?;
        let second_start = point.add_incomplete(dr, &second_offset_point, bank)?;
        let mut first = first_start;
        let mut second = second_start;
        let mut first_offset = bases.g0.to_projective();
        let mut second_offset = bases.g1.to_projective();
        let mut j = bases.j.to_projective();
        let mut h = bases.h.to_projective();

        for i in 0..C::Scalar::ZERO.to_le_bits().as_ref().len() {
            let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|bits| bits.as_ref()[i]))?;
            let j_next = j.double();
            let h_next = h.double();
            let first_step = select(dr, &bit, j.to_affine(), j_next.to_affine())?;
            let second_step = select(dr, &bit, h.to_affine(), h_next.to_affine())?;
            first = first.add_incomplete(dr, &first_step, bank)?;
            second = second.add_incomplete(dr, &second_step, bank)?;
            first_offset = first_offset + j;
            second_offset = second_offset + h;
            j = j_next;
            h = h_next;
        }

        // Every selected point contributes its base power in addition to
        // the bit's contribution. Shift the public points by those sums.
        let first_expected = (ciphertext.first.to_projective() + first_offset).to_affine();
        let second_expected = (ciphertext.second.to_projective() + second_offset).to_affine();
        let first_expected = Point::constant(dr, first_expected)?;
        first.enforce_conservative_equal(dr, &first_expected)?;
        let second_expected = Point::constant(dr, second_expected)?;
        second.enforce_conservative_equal(dr, &second_expected)
    })
}

fn select<'dr, D: Driver<'dr, F = C::Base>, C: Affine>(
    dr: &mut D,
    bit: &Boolean<'dr, D>,
    zero: C,
    one: C,
) -> Result<Point<'dr, D, C>> {
    let point = Point::alloc(dr, bit.value().map(|bit| if bit { one } else { zero }))?;
    let (x0, y0) = zero.coordinates().expect("nonidentity base");
    let (x1, y1) = one.coordinates().expect("nonidentity base");
    let mut coordinates = alloc::vec::Vec::with_capacity(2);
    point.write(dr, &mut coordinates)?;
    for (coordinate, (lo, hi)) in coordinates.iter().zip([(x0, x1), (y0, y1)]) {
        let selected = bit.element().scale(dr, Coeff::Arbitrary(hi - lo));
        let lo = Element::constant(dr, lo);
        let selected = selected.add(dr, &lo);
        dr.enforce_equal(coordinate.wire(), selected.wire())?;
    }
    Ok(point)
}
