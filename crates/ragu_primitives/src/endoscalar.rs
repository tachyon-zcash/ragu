//! Implements logic for endoscaling, as introduced in
//! [Halo](https://eprint.iacr.org/2019/1021).
//!
//! An endoscalar is the catchy name for a small binary string that is used to
//! perform elliptic curve scalar multiplication on curves that have an
//! efficient endomorphism attached. By producing endoscalars as challenges and
//! applying an appropriate algorithm, points on an elliptic curve can be
//! multiplied by equally "random" challenge scalars more efficiently within a
//! circuit than an arbitrary scalar.
//!
//! This module provides an implementation of the scaling operation for curves
//! which support the endomorphism, and an implementation of the algorithm for
//! recovering the effective scalar that an endoscalar maps to for a particular
//! prime field.

use ff::{Field, PrimeField, WithSmallOrderMulGroup};
use ragu_arithmetic::{Coeff, CurveAffine, Uendo};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, LinearExpression, emulator::Emulator},
    gadgets::Gadget,
    maybe::Maybe,
};

use alloc::vec::Vec;

use crate::{
    Boolean, Element, Point,
    promotion::Demoted,
    vec::{CollectFixed, ConstLen, FixedVec},
};

/// Represents a challenge used to scale elliptic curve points.
#[derive(Gadget)]
pub struct Endoscalar<'dr, D: Driver<'dr>> {
    /// The bits of this endoscalar in little-endian order.
    #[ragu(gadget)]
    bits: FixedVec<Demoted<'dr, D, Boolean<'dr, D>>, ConstLen<{ Uendo::BITS as usize }>>,

    /// The represented endoscalar witness value in compact representation.
    #[ragu(value)]
    value: DriverValue<D, Uendo>,
}

impl<'dr, D: Driver<'dr>> Endoscalar<'dr, D> {
    /// Allocate an endoscalar with the provided `Uendo` value.
    pub fn alloc(dr: &mut D, value: DriverValue<D, Uendo>) -> Result<Self> {
        // Convert the provided Uendo into a little-endian representation of its
        // bits.
        let bits = (0..Uendo::BITS as usize)
            .map(|i| {
                let bit = Boolean::alloc(
                    dr,
                    value
                        .view()
                        .map(|v| (*v >> i) & Uendo::from(1u64) == Uendo::from(1u64)),
                )?;
                Demoted::new(&bit)
            })
            .try_collect_fixed()?;

        Ok(Endoscalar { bits, value })
    }

    /// Returns an iterator over the bits in this endoscalar, little endian order.
    pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
        let mut bits = self.value.view().map(|v| {
            (0..(Uendo::BITS as usize))
                .map(move |i| (*v >> i) & Uendo::from(1u64) == Uendo::from(1u64))
        });

        self.bits.iter().map(move |demoted_bit| {
            demoted_bit.promote(bits.view_mut().map(|bits| bits.next().unwrap()))
        })
    }

    /// Extracts an endoscalar from a random element in the field.
    pub fn extract(dr: &mut D, elem: Element<'dr, D>) -> Result<Self>
    where
        D::F: WithSmallOrderMulGroup<3>,
    {
        let mut bits = Vec::with_capacity(Uendo::BITS as usize);
        let mut value = D::just(|| Uendo::from(0u64));
        let mut constant = D::F::ZERO;

        let mut coeff_0 = D::F::ZERO;
        let mut coeff_1 = D::F::ZERO;
        let coeff_2 = D::F::MULTIPLICATIVE_GENERATOR;
        let coeff_3 = D::F::ONE - D::F::MULTIPLICATIVE_GENERATOR;

        for i in 0..(Uendo::BITS as usize) {
            let (sqrt, bit) = D::with(|| {
                let value = *elem.value().take() + constant;

                if let Some(sqrt) = value.sqrt().into_option() {
                    Ok((sqrt, true))
                } else {
                    let sqrt = (value * D::F::MULTIPLICATIVE_GENERATOR)
                        .sqrt()
                        .into_option()
                        .expect("should produce a square if the other didn't");
                    Ok((sqrt, false))
                }
            })?
            .cast();

            value.view_mut().map(|v| {
                if *bit.snag() {
                    *v |= Uendo::from(1u64) << i
                }
            });

            let bit = Boolean::alloc(dr, bit)?;
            let (_, square) = Element::alloc_square(dr, sqrt)?;
            let vb = elem.mul(dr, &bit.element())?;

            // Enforce that the square is equal to
            //     (elem + i) if bit == 1
            //     (elem + i) * MULTIPLICATIVE_GENERATOR) if bit == 0
            // This is done by enforcing the linear constraint:
            //
            //     square = bit * (elem + i)
            //            + (1 - bit) * ((elem + i) * MULTIPLICATIVE_GENERATOR)
            //
            //            = i * MULTIPLICATIVE_GENERATOR
            //            + bit * (i * (1 - MULTIPLICATIVE_GENERATOR))
            //            + elem * MULTIPLICATIVE_GENERATOR
            //            + vb * (1 - MULTIPLICATIVE_GENERATOR)
            dr.enforce_zero(|lc| {
                lc.add_term(&D::ONE, coeff_0.into())
                    .add_term(bit.wire(), coeff_1.into())
                    .add_term(elem.wire(), coeff_2.into())
                    .add_term(vb.wire(), coeff_3.into())
                    .sub(square.wire())
            })?;

            bits.push(Demoted::new(&bit)?);
            constant += D::F::ONE;
            coeff_0 += coeff_2;
            coeff_1 += coeff_3;
        }

        Ok(Endoscalar {
            bits: FixedVec::try_from(bits)?,
            value,
        })
    }

    /// Scale a point by the endoscalar.
    pub fn group_scale<C: CurveAffine<Base = D::F>>(
        &self,
        dr: &mut D,
        p: &Point<'dr, D, C>,
    ) -> Result<Point<'dr, D, C>> {
        let mut acc = p.endo(dr).add_incomplete(dr, p, None)?.double(dr)?;
        let mut bits = self.bits();

        // Uendo::BITS is guaranteed to be even (enforced in ragu_arithmetic).
        for _ in 0..(Uendo::BITS as usize / 2) {
            let negate_bit = bits.next().unwrap();
            let endo_bit = bits.next().unwrap();

            let q = p
                .conditional_negate(dr, &negate_bit)?
                .conditional_endo(dr, &endo_bit)?;
            acc = acc.double_and_add_incomplete(dr, &q)?;
        }

        Ok(acc)
    }

    /// Lifts this endoscalar to a field element (scales $1$ by the endoscalar).
    pub fn lift(&self, dr: &mut D) -> Result<Element<'dr, D>>
    where
        D::F: WithSmallOrderMulGroup<3>,
    {
        let mut constant_term = (D::F::ZETA + D::F::ONE).double();
        let coeffs = [
            -D::F::from(2),
            D::F::ZETA - D::F::ONE,
            (D::F::ONE - D::F::ZETA).double(),
        ];

        let mut acc = Element::zero(dr);
        let mut bits = self.bits();

        // Uendo::BITS is guaranteed to be even (enforced in ragu_arithmetic).
        for _ in 0..(Uendo::BITS as usize / 2) {
            let n = bits.next().unwrap();
            let e = bits.next().unwrap();
            let ne = n.and(dr, &e)?;

            acc = acc.double(dr);
            constant_term = constant_term.double();
            constant_term += D::F::ONE;

            let n = n.element().scale(dr, Coeff::Arbitrary(coeffs[0]));
            let e = e.element().scale(dr, Coeff::Arbitrary(coeffs[1]));
            let ne = ne.element().scale(dr, Coeff::Arbitrary(coeffs[2]));

            acc = acc.add(dr, &n);
            acc = acc.add(dr, &e);
            acc = acc.add(dr, &ne);
        }

        let tmp = Element::constant(dr, constant_term);
        acc = acc.add(dr, &tmp);

        Ok(acc)
    }
}

/// Lifts an endoscalar to a field element (computes the effective scalar).
///
/// This implements [Algorithm 2, \[BGH19\]](https://eprint.iacr.org/2019/1021)
/// and is the native counterpart to [`Endoscalar::lift`].
pub fn lift_endoscalar<F: WithSmallOrderMulGroup<3>>(endo: Uendo) -> F {
    let mut acc = (F::ZETA + F::ONE).double();
    for i in 0..(Uendo::BITS as usize / 2) {
        let bits = endo >> (i << 1);
        let mut tmp = F::ONE;
        if bits & Uendo::from(0b01u64) != Uendo::from(0u64) {
            tmp = -tmp;
        }
        if bits & Uendo::from(0b10u64) != Uendo::from(0u64) {
            tmp *= F::ZETA;
        }
        acc = acc.double() + tmp;
    }
    acc
}

/// Extracts an endoscalar from a random field element.
///
/// Given a random output of a secure algebraic hash function, this extracts
/// `k` bits of "randomness" from the value by checking whether `value + i`
/// is a quadratic residue for each bit position `i`.
pub fn extract_endoscalar<F: PrimeField + WithSmallOrderMulGroup<3>>(value: F) -> Uendo {
    Emulator::emulate_wireless(value, |dr, witness| {
        let elem = Element::alloc(dr, witness)?;
        let endo = Endoscalar::extract(dr, elem)?;
        Ok(*endo.value.snag())
    })
    .expect("wireless emulation should not fail")
}

#[cfg(test)]
mod tests {
    use super::{Element, Endoscalar, Maybe, Point};
    use ff::{Field, PrimeField, WithSmallOrderMulGroup};
    use group::{Group, prime::PrimeCurveAffine};
    use ragu_arithmetic::{CurveAffine, CurveExt, Uendo};
    use ragu_core::Result;
    use ragu_pasta::{EpAffine, Fp};
    use rand::RngExt;

    use crate::Simulator;

    pub struct EndoscalarTest {
        pub value: Uendo,
    }

    impl EndoscalarTest {
        /// Implements [Algorithm 1, \[BGH19\]](https://eprint.iacr.org/2019/1021).
        pub fn scale<C: CurveAffine>(&self, p: &C) -> C {
            let p = p.to_curve();
            let mut acc = (p.endo() + p).double();
            for bits in (0..(Uendo::BITS as usize / 2)).map(|i| self.value >> (i << 1)) {
                let mut s = p;
                if bits & Uendo::from(0b01u64) != Uendo::from(0u64) {
                    s = -s;
                }
                if bits & Uendo::from(0b10u64) != Uendo::from(0u64) {
                    s = s.endo();
                }

                acc = (acc + s) + acc;
            }
            acc.into()
        }

        /// Implements [Algorithm 2, \[BGH19\]](https://eprint.iacr.org/2019/1021).
        pub fn lift<F: WithSmallOrderMulGroup<3>>(&self) -> F {
            super::lift_endoscalar(self.value)
        }
    }

    pub fn extract<F: PrimeField + WithSmallOrderMulGroup<3>>(value: F) -> EndoscalarTest {
        EndoscalarTest {
            value: super::extract_endoscalar(value),
        }
    }

    #[test]
    #[allow(clippy::useless_conversion)]
    fn test_endoscaling_consistency() {
        use group::prime::PrimeCurveAffine;
        use ragu_pasta::{EpAffine, Fq};

        let p = EpAffine::generator();
        let e = EndoscalarTest {
            value: Uendo::from(206786806484900909362154774549736492353u128),
        };
        let scaled = e.scale(&p);
        let expected: EpAffine = (p * e.lift::<Fq>()).into();

        assert_eq!(scaled, expected);
    }

    #[test]
    fn test_extract() -> Result<()> {
        let p = EpAffine::generator();
        let r = Fp::random(&mut rand::rng());
        let extracted = extract(r).value;

        Simulator::<Fp>::simulate((r, extracted, p), |dr, witness| {
            let (r, extracted, p) = witness.cast();
            let p = Point::alloc(dr, p)?;
            let r = Element::alloc(dr, r)?;
            let my_extracted = Endoscalar::extract(dr, r)?;
            let allocated = Endoscalar::alloc(dr, extracted)?;

            assert_eq!(my_extracted.value.snag(), allocated.value.snag());

            let a = my_extracted.group_scale(dr, &p)?;
            let b = allocated.group_scale(dr, &p)?;
            assert_eq!(a.value().take(), b.value().take());

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_endoscaling() -> Result<()> {
        let p = EpAffine::generator();
        let r: Uendo = rand::rng().random();
        let expected = EndoscalarTest { value: r }.scale(&p);

        Simulator::simulate((p, r), |dr, witness| {
            let (p, r) = witness.cast();
            let p = Point::alloc(dr, p.clone())?;
            let r = Endoscalar::alloc(dr, r.clone())?;

            dr.reset();
            assert_eq!(r.group_scale(dr, &p)?.value().take(), expected);
            assert_eq!(
                dr.num_multiplications(),
                7 * (1 + (Uendo::BITS as usize / 2))
            );

            Ok(())
        })?;

        Ok(())
    }

    #[test]
    fn test_endoscalar_lift() -> Result<()> {
        let r: Uendo = rand::rng().random();
        let expected: Fp = EndoscalarTest { value: r }.lift();

        Simulator::<Fp>::simulate(r, |dr, witness| {
            let r = Endoscalar::alloc(dr, witness)?;
            let s = r.lift(dr)?;

            assert_eq!(*s.value().take(), expected);

            Ok(())
        })?;

        Ok(())
    }
}
