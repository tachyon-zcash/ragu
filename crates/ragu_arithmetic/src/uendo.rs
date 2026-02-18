//! This module defines a 136-bit unsigned integer type used in Ragu's protocols
//! primarily for endoscalars. The actual width that will be used in practice
//! could vary between 128 bits and 160 bits in practice, depending on the
//! tightness of security bounds and performance limitations. This type offers a
//! way to adjust this amount later without changing the API.

use core::{
    cmp::{Eq, PartialEq},
    fmt::{self, Debug},
    ops::{BitAnd, BitOr, BitOrAssign, Shl, ShlAssign, Shr},
};
use rand::RngExt;

const BITS: usize = 136;
const LIMBS: usize = BITS.div_ceil(64);
const NORMALIZATION_MASK: u64 = u64::MAX >> (64 - (BITS % 64));

const _ASSERT_CORRECT_BITS_VALUE: () = {
    if !BITS.is_multiple_of(2) {
        // This integer type is used for endoscalars, which are assumed to have
        // an even bit length for simplicity.
        panic!("BITS must be even");
    }

    if BITS < 130 || BITS > 160 {
        // This integer type is used for endoscalars, which are assumed to have
        // a bit length between 130 and 160 (inclusive).
        panic!("BITS must be between 130 and 160");
    }
};

/// Integer type used as a random challenge in Ragu's protocols.
#[derive(Copy, Clone, Default)]
pub struct Uendo {
    // LSB-first ordering: limbs[0] is least significant
    limbs: [u64; LIMBS],
}

impl rand::distr::Distribution<Uendo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Uendo {
        let mut limbs = [0; LIMBS];
        for limb in &mut limbs {
            *limb = rng.random();
        }
        Uendo { limbs }.normalized()
    }
}

impl Uendo {
    /// The size of this integer type in bits
    pub const BITS: u32 = BITS as u32;

    /// The value $0$
    pub const ZERO: Self = Self { limbs: [0; LIMBS] };

    /// The value $1$
    pub const ONE: Self = {
        let mut limbs = [0; LIMBS];
        limbs[0] = 1;
        Self { limbs }
    };

    /// Creates a new value from a `u64`.
    const fn from_u64(value: u64) -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = value;
        Self { limbs }
    }

    /// Creates a new value from a `u128`.
    const fn from_u128(value: u128) -> Self {
        let mut limbs = [0; LIMBS];
        limbs[0] = value as u64;
        limbs[1] = (value >> 64) as u64;
        Self { limbs }
    }

    /// Ensures the most significant bits are properly masked.
    fn normalize(&mut self) {
        self.limbs[LIMBS - 1] &= NORMALIZATION_MASK;
    }

    /// Returns a normalized copy of this value.
    fn normalized(mut self) -> Self {
        self.normalize();
        self
    }
}

impl From<u64> for Uendo {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u128> for Uendo {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl PartialEq for Uendo {
    fn eq(&self, other: &Self) -> bool {
        self.limbs == other.limbs
    }
}

impl Eq for Uendo {}

impl BitAnd for Uendo {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mut result = Self::ZERO;
        for i in 0..LIMBS {
            result.limbs[i] = self.limbs[i] & rhs.limbs[i];
        }
        result
    }
}

impl BitOr for Uendo {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        let mut result = Self::ZERO;
        for i in 0..LIMBS {
            result.limbs[i] = self.limbs[i] | rhs.limbs[i];
        }
        result
    }
}

impl BitOrAssign for Uendo {
    fn bitor_assign(&mut self, rhs: Self) {
        for i in 0..LIMBS {
            self.limbs[i] |= rhs.limbs[i];
        }
    }
}

impl Shl<usize> for Uendo {
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        if rhs >= BITS {
            return Self::ZERO;
        }

        let limb_shift = rhs / 64;
        let bit_shift = rhs % 64;

        let mut result = Self::ZERO;

        for target_index in limb_shift..LIMBS {
            let source_index = target_index - limb_shift;
            result.limbs[target_index] = self.limbs[source_index] << bit_shift;

            if bit_shift > 0 && source_index > 0 {
                result.limbs[target_index] |= self.limbs[source_index - 1] >> (64 - bit_shift);
            }
        }

        result.normalized()
    }
}

impl ShlAssign<usize> for Uendo {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs;
    }
}

impl Shr<usize> for Uendo {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        if rhs >= BITS {
            return Self::ZERO;
        }

        let limb_shift = rhs / 64;
        let bit_shift = rhs % 64;

        let mut result = Self::ZERO;

        for target_index in 0..(LIMBS - limb_shift) {
            let source_index = target_index + limb_shift;
            result.limbs[target_index] = self.limbs[source_index] >> bit_shift;

            if bit_shift > 0 && source_index + 1 < LIMBS {
                result.limbs[target_index] |= self.limbs[source_index + 1] << (64 - bit_shift);
            }
        }

        result
    }
}

impl Debug for Uendo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uendo(0x")?;
        for i in (0..LIMBS).rev() {
            write!(f, "{:016x}", self.limbs[i])?;
        }
        write!(f, ")")?;

        Ok(())
    }
}
