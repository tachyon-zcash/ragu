//! # `ragu_arithmetic`
//!
//! This crate contains arithmetic traits and utilities that are common in the
//! Ragu project.
//!
//! ## Cycles of Elliptic Curves
//!
//! Ragu is parameterized by a cycle of elliptic curves defined over large prime
//! fields. Curves like these, particularly cycles of Koblitz curves, are used
//! in [Zcash](https://z.cash/) because they are useful for building recursive
//! SNARKs. The concrete parameters are defined by an implementation of the
//! [`Cycle`] trait. As long as such an implementation satisfies the requisite
//! API contracts and passes any applicable (static) assertions, it is supported
//! by Ragu.
//!
//! Currently, the only implementation of the [`Cycle`] trait is provided by the
//! [`ragu_pasta`](https://crates.io/crates/ragu_pasta) crate, which provides
//! support for the [Pasta
//! curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/).
//! In fact, many of the common traits used throughout Ragu are actually defined
//! in the [`pasta_curves`] crate, which provides the actual implementations of
//! the Pasta curves and fields, and we
//! [currently](https://github.com/ebfull/ragu/issues/1) rely on those traits in
//! this crate for compatibility and interoperability reasons.
//!
//! ## FFTs
//!
//! Ragu targets the Pasta curves because they are designed to support efficient
//! multi-point evaluation and interpolation of polynomials through the use of
//! (radix-2) [Fast Fourier
//! Transforms](https://en.wikipedia.org/wiki/Fast_Fourier_transform) (FFTs).
//! Ragu itself attempts to minimize the usage of FFTs, but they are still
//! convenient in some cases and necessary for some applications and SNARK
//! protocols.
//!
//! We currently require curves to have the high 2-adicity property needed to
//! support these evaluation domains, essentially limiting users to the Pasta
//! curves. However, this is not an inherent requirement of the cryptography and
//! future versions of Ragu may support cycles such as the one formed by
//! [sec**p**256k1](https://en.bitcoin.it/wiki/Secp256k1)/sec**q**256k1, which
//! do not have this high 2-adicity property but are used in many
//! cryptocurrencies.
//!
//! ## Endomorphisms
//!
//! Koblitz curves are of the form $y^2 = x^3 + b$ and their base and scalar
//! fields have size $p \equiv 1 \pmod{3}$ and thus implement
//! [`WithSmallOrderMulGroup<3>`]. This means they support an efficient
//! endomorphism that can be used to accelerate scalar multiplication, and this
//! is leveraged extensively in Ragu.
//!
//! The Pasta curves have this form, and so does the secp256k1/secq256k1 cycle.
//!
//! ## Algebraic Hashes
//!
//! Due to their superior performance in arithmetic circuits, so-called
//! arithmetic hash functions are used in Ragu. In particular, Ragu leans
//! heavily on [Poseidon](https://eprint.iacr.org/2019/458). Implementations of
//! [`Cycle`] provide parameters for the Poseidon permutation over the requisite
//! fields by implementing the [`PoseidonPermutation`] trait.

#![no_std]
#![allow(non_snake_case)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc(html_favicon_url = "https://seanbowe.com/ragu_assets/icons/v1_favicon32.png")]
#![doc(html_logo_url = "https://seanbowe.com/ragu_assets/icons/v1_rustdoc128.png")]

use ff::{Field, WithSmallOrderMulGroup};
pub use pasta_curves::arithmetic::{Coordinates, CurveAffine, CurveExt};

extern crate alloc;

/// Converts a 256-bit integer literal into the little endian `[u64; 4]`
/// representation that e.g. [`Fp::from_raw`](pasta_curves::Fp::from_raw) or
/// [`Fp::pow`](pasta_curves::Fp::pow) need as input. This makes constants
/// slightly more readable, but is not intended for use in other contexts.
pub use ragu_macros::repr256;

mod coeff;
mod domain;
mod fft;
mod uendo;
mod util;

pub use coeff::Coeff;
pub use domain::Domain;
pub use fft::{Ring, bitreverse};
pub use util::{dot, eval, factor, factor_iter, geosum, mul};

// TODO(ebfull): Use this if we need to increase the bit size of endoscalars.
// pub use uendo::Uendo;
pub use u128 as Uendo;

/// Represents a "cycle" of elliptic curves where the scalar field of one curve
/// is the base field of the other, and vice-versa.
///
/// Implementations of this trait provide the types, their relationships, and
/// the ability to conveniently access common parameters.
pub trait Cycle: Send + Sync + 'static {
    /// The field that circuit developers will primarily work with, and the
    /// scalar field of the [`HostCurve`](Cycle::HostCurve).
    type CircuitField: WithSmallOrderMulGroup<3>;

    /// The scalar field of the [`NestedCurve`](Cycle::NestedCurve).
    type ScalarField: WithSmallOrderMulGroup<3>;

    /// The nested curve that applications typically use for asymmetric keys,
    /// signatures, and other cryptographic primitives. (This is the Pallas
    /// curve in Zcash.)
    type NestedCurve: CurveAffine<ScalarExt = Self::ScalarField, Base = Self::CircuitField>;

    /// The host curve that the proof system uses mainly to construct proofs for
    /// circuits over the [`CircuitField`](Cycle::CircuitField). (This is the
    /// ideal curve to use for committing to large vector or polynomial
    /// commitments and reasoning about them inside of PCD.)
    type HostCurve: CurveAffine<ScalarExt = Self::CircuitField, Base = Self::ScalarField>;

    /// Fixed generators for the [`NestedCurve`](Cycle::NestedCurve).
    type NestedGenerators: FixedGenerators<Self::NestedCurve>;

    /// Fixed generators for the [`HostCurve`](Cycle::HostCurve).
    type HostGenerators: FixedGenerators<Self::HostCurve>;

    /// Initialized fixed generators for the
    /// [`NestedCurve`](Cycle::NestedCurve).
    fn nested_generators(&self) -> &Self::NestedGenerators;

    /// Initialized fixed generators for the [`HostCurve`](Cycle::HostCurve).
    fn host_generators(&self) -> &Self::HostGenerators;

    /// Poseidon permutation parameters for the
    /// [`CircuitField`](Cycle::CircuitField).
    type CircuitPoseidon: PoseidonPermutation<Self::CircuitField>;

    /// Poseidon permutation parameters for the
    /// [`ScalarField`](Cycle::ScalarField).
    type ScalarPoseidon: PoseidonPermutation<Self::ScalarField>;

    /// Initialized Poseidon parameter constants for the
    /// [`CircuitField`](Cycle::CircuitField).
    fn circuit_poseidon(&self) -> &Self::CircuitPoseidon;

    /// Initialized Poseidon parameter constants for the
    /// [`ScalarField`](Cycle::ScalarField).
    fn scalar_poseidon(&self) -> &Self::ScalarPoseidon;
}

/// Contains various fixed generators for elliptic curves, all of which have
/// unknown discrete logarithm relationships with each other.
pub trait FixedGenerators<C: CurveAffine>: Send + Sync + 'static {
    /// The main generators used to commit to vectors (like the coefficients of
    /// polynomials).
    fn g(&self) -> &[C];

    /// Generator used as a blinding factor or randomization.
    fn h(&self) -> &C;

    /// Compute a commitment to a single value.
    fn short_commit(&self, value: C::ScalarExt, blind: C::ScalarExt) -> C {
        // TODO(ebfull): This returns a C, but the most efficient method would
        // be to return a `C::Curve` and let the caller perform batch inversion
        // if possible.
        (self.g()[0] * value + *self.h() * blind).into()
    }
}

/// Specification for a [Poseidon](https://eprint.iacr.org/2019/458) permutation over a field $\mathbb{F}$.
pub trait PoseidonPermutation<F: Field>: Send + Sync + 'static {
    /// The size of the state.
    const T: usize;

    /// The rate, which caps the number of elements that can be squeezed or
    /// absorbed before a permutation is applied. This must be smaller than `T`.
    const RATE: usize;

    /// Number of full rounds where the sbox is applied to every element of the
    /// state. This must be even, since exactly half of these rounds are applied
    /// at the start and then half at the end of the permutation.
    const FULL_ROUNDS: usize;

    /// Number of partial rounds where the sbox is applied only to the first
    /// element of the state.
    const PARTIAL_ROUNDS: usize;

    /// $\alpha$ parameter for the [sbox](https://en.wikipedia.org/wiki/S-box),
    /// representing the map $x \to x^\alpha$ which must be a permutation in the
    /// field.
    const ALPHA: isize;

    /// Returns an iterator over the constants for each round of the
    /// permutation, added to each element of the state (before the application
    /// of the sbox).
    fn round_constants(&self) -> impl Iterator<Item = &[F]>;

    /// Returns an iterator over the rows of the [MDS
    /// matrix](https://en.wikipedia.org/wiki/MDS_matrix) for this permutation.
    fn mds_matrix(&self) -> impl ExactSizeIterator<Item = &[F]>;
}
