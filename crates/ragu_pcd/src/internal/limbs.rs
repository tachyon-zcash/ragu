//! The limbs of a step's own last online commitment, $O_1$, and their
//! digest $H(O_1)$.
//!
//! $O_1$ is a host-curve point whose coordinates lie in the nested field, so
//! the native application circuit cannot read them. Each coordinate $c$ is
//! split into two limbs, $c = c_{lo} + 2^{128} c_{hi}$ with
//! $c_{lo} < 2^{128}$ and $c_{hi} < 2^{\mathtt{CAPACITY} - 128}$: integers
//! small enough to be the same value in both fields of the cycle. Since
//! $c_{lo} + 2^{128} c_{hi} < 2^{\mathtt{CAPACITY}}$, which is below the
//! nested field's modulus, the split is unique.
//!
//! The nested challenge stage holds the four limbs $(x_{lo}, x_{hi}, y_{lo},
//! y_{hi})$ after $\beta$ (see [`challenges`]), and the nested `collapse`
//! circuit holds them linearly to the coordinates of the $O_1$ in the
//! nested preamble. The challenge stage is committed unblinded, so the four
//! limbs contribute the fixed combination
//!
//! $$H(O_1) = \sum_{i < 4} \ell_i \cdot G_{\mathrm{idx}(i)}$$
//!
//! of nested-curve generators to its commitment. The last two
//! `bind_challenges` circuits recompute that point natively from the
//! limbs' bits (see [`bind_challenges`]) and pin it to the unified
//! instance, whose value the application circuit reads as its bridge hash.
//! The parent's `bind_beta` adds it into the challenge stage commitment it
//! walks, which ties the native limbs to the nested ones and so to $O_1$.
//!
//! A coordinate at or above $2^{\mathtt{CAPACITY}}$ has no such split, and a
//! step whose $O_1$ has one cannot prove. Over the Pasta fields a coordinate
//! lands there with probability about $2^{-129}$.
//!
//! [`challenges`]: super::nested::stages::challenges
//! [`bind_challenges`]: super::native::circuits::bind_challenges

use ragu_circuits::polynomials::Rank;
use ragu_core::{Error, FixedGenerators, Result};
use udon::{
    curve::{Affine, Projective as _},
    field::Field,
};

use crate::{internal::native::stages::eval::generator_index, profile::ProfiledCycle};

/// The number of limbs: two per coordinate.
pub const NUM: usize = 4;

/// The bits of a low limb.
pub const LO_BITS: usize = 128;

/// The bits of a high limb over a coordinate field `F`: the remainder of
/// its capacity, so that the two limbs fit below the modulus.
pub const fn hi_bits<F: Field>() -> usize {
    F::CAPACITY as usize - LO_BITS
}

/// The limbs of `point`, $(x_{lo}, x_{hi}, y_{lo}, y_{hi})$, as integers.
///
/// # Errors
///
/// Fails if `point` is the identity, or if a coordinate is at or above
/// $2^{\mathtt{CAPACITY}}$ and so has no split.
pub fn integers<P: Affine>(point: P) -> Result<[u128; NUM]> {
    let (x, y) = point
        .coordinates()
        .ok_or_else(|| Error::InvalidWitness("the identity has no limbs".into()))?;
    let split = |coordinate: P::Base| -> Result<[u128; 2]> {
        let bits = coordinate.to_le_bits();
        let bits = bits.as_ref();
        let pack = |range: core::ops::Range<usize>| {
            bits[range]
                .iter()
                .rev()
                .fold(0u128, |acc, &bit| (acc << 1) | u128::from(bit))
        };
        let hi_end = LO_BITS + hi_bits::<P::Base>();
        if bits[hi_end..].iter().any(|&bit| bit) {
            return Err(Error::InvalidWitness(
                "a coordinate at or above 2^CAPACITY has no limbs".into(),
            ));
        }
        Ok([pack(0..LO_BITS), pack(LO_BITS..hi_end)])
    };
    let [x_lo, x_hi] = split(x)?;
    let [y_lo, y_hi] = split(y)?;
    Ok([x_lo, x_hi, y_lo, y_hi])
}

/// The limbs of `point` as elements of `F`.
///
/// # Errors
///
/// See [`integers`].
pub fn limbs<P: Affine, F: Field>(point: P) -> Result<[F; NUM]> {
    Ok(integers(point)?.map(F::from_u128))
}

/// The nested-curve generator index the challenge stage commits limb `i`
/// with.
pub fn limb_generator_index<C: ProfiledCycle, R: Rank>(i: usize) -> usize {
    generator_index::<C, R>(super::nested::stages::challenges::LIMBS_INDEX + i)
}

/// $\sum_{i \in \mathtt{range}} \ell_i \cdot G_{\mathrm{idx}(i)}$, over the
/// limbs of `point`.
///
/// # Errors
///
/// See [`integers`].
pub fn partial_digest<C: ProfiledCycle, R: Rank>(
    generators: &impl FixedGenerators<C::NestedCurve>,
    point: C::HostCurve,
    range: core::ops::Range<usize>,
) -> Result<C::NestedCurve> {
    let limbs = limbs::<_, C::ScalarField>(point)?;
    let generators = generators.g();
    let sum = range.fold(
        <C::NestedCurve as Affine>::Projective::identity(),
        |acc, i| acc + generators[limb_generator_index::<C, R>(i)] * limbs[i],
    );
    Ok(sum.into())
}

/// $H(O_1)$ for `point`: the challenge stage's limb terms, which a step's
/// application circuit reads as its bridge hash.
///
/// # Errors
///
/// See [`integers`].
pub fn digest<C: ProfiledCycle, R: Rank>(
    generators: &impl FixedGenerators<C::NestedCurve>,
    point: C::HostCurve,
) -> Result<C::NestedCurve> {
    partial_digest::<C, R>(generators, point, 0..NUM)
}

#[cfg(test)]
mod tests {
    use ragu_core::pasta::{EqAffine, Fp, Fq};
    use udon::curve::Affine as _;

    use super::*;

    /// The limbs recompose to the coordinates in the nested field, and are
    /// the same integers in the native one.
    #[test]
    fn limbs_recompose_to_the_coordinates() {
        let point = (EqAffine::generator().to_projective() * Fp::from(0x1234_5678u64)).into();
        let (x, y) = EqAffine::coordinates(&point).unwrap();
        let shift = Fq::from_u128(1 << 64) * Fq::from_u128(1 << 64);
        let nested = limbs::<EqAffine, Fq>(point).unwrap();
        assert_eq!(nested[0] + shift * nested[1], x);
        assert_eq!(nested[2] + shift * nested[3], y);
        let native = limbs::<EqAffine, Fp>(point).unwrap();
        let integers = integers(point).unwrap();
        for i in 0..NUM {
            assert_eq!(native[i], Fp::from_u128(integers[i]));
        }
        assert!(integers[1] < 1 << hi_bits::<Fq>());
        assert!(integers[3] < 1 << hi_bits::<Fq>());
    }
}
