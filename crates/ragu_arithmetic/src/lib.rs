//! # `ragu_arithmetic`
//!
//! Common arithmetic traits and utilities for the Ragu project.
//!
//! This crate provides:
//!
//! - [`Cycle`]: A trait describing a cycle of elliptic curves where the scalar
//!   field of one curve is the base field of the other. Currently only the
//!   [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/)
//!   are supported (via [`ragu_pasta`](https://crates.io/crates/ragu_pasta)).
//!   We [currently](https://github.com/tachyon-zcash/ragu/issues/1) rely on
//!   traits from [`pasta_curves`] for compatibility.
//!
//! - [`FixedGenerators`] and [`PoseidonPermutation`]: Companion traits that
//!   [`Cycle`] implementations use to supply commitment generators and
//!   [Poseidon](https://eprint.iacr.org/2019/458) hash parameters.
//!
//! - [`Domain`]: Radix-2 evaluation domains for FFTs. Requires fields with
//!   high 2-adicity (i.e., the Pasta curves).
//!
//! - [`Coeff`]: An optimized field-element wrapper that tracks common special
//!   values (zero, one, negation) to avoid unnecessary multiplications.
//!
//! - Polynomial utilities: [`eval`], [`dot`], [`factor`], [`mul`] (multiscalar
//!   multiplication), [`geosum`], and [`poly_with_roots`].
//!
//! Supported curves implement [`WithSmallOrderMulGroup<3>`], enabling an
//! efficient endomorphism for accelerated scalar multiplication.

#![no_std]
#![allow(non_snake_case)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_arithmetic` requires the `alloc` feature to be enabled.");
extern crate alloc;

mod coeff;
mod domain;
mod fft;
mod multicore;
mod uendo;
mod util;

use ff::{Field, FromUniformBytes, WithSmallOrderMulGroup};

pub use coeff::Coeff;
pub use domain::Domain;
pub use fft::{Ring, bitreverse};
pub use pasta_curves::arithmetic::{Coordinates, CurveAffine, CurveExt};
pub use util::{
    batch_to_affine, dot, eval, factor, factor_iter, geosum, low_u64, mul, poly_with_roots,
};

/// Converts a 256-bit integer literal into the little endian `[u64; 4]`
/// representation that e.g. [`Fp::from_raw`](pasta_curves::Fp::from_raw) or
/// [`Fp::pow`](pasta_curves::Fp::pow) need as input. This makes constants
/// slightly more readable, but is not intended for use in other contexts.
pub use ragu_macros::repr256;

/// TODO(ebfull): Use this if we need to increase the bit size of endoscalars.
///
/// The `uendo` module is a speculative implementation. We may need a
/// flexible-width challenge space larger than 128 bits due to birthday bound /
/// adversary advantage concerns. `Uendo` is a drop-in replacement for `u128`
/// that's generic over bit length, in case the security proof demands something
/// like 134-bit challenges. This may end up being removed if 128 bits suffices.
pub use u128 as Uendo;

/// Represents a "cycle" of elliptic curves where the scalar field of one curve
/// is the base field of the other, and vice-versa.
///
/// Implementations of this trait provide the types, their relationships, and
/// the ability to conveniently access common parameters.
///
/// The trait is designed as a zero-sized marker type, with runtime parameters
/// (generators, Poseidon constants) stored in the associated
/// [`Params`](Cycle::Params) type as necessary.
pub trait Cycle: Copy + Clone + Default + Send + Sync + 'static {
    /// The field that circuit developers will primarily work with, and the
    /// scalar field of the [`HostCurve`](Cycle::HostCurve).
    type CircuitField: WithSmallOrderMulGroup<3> + FromUniformBytes<64>;

    /// The scalar field of the [`NestedCurve`](Cycle::NestedCurve).
    type ScalarField: WithSmallOrderMulGroup<3> + FromUniformBytes<64>;

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

    /// Poseidon permutation parameters for the
    /// [`CircuitField`](Cycle::CircuitField).
    type CircuitPoseidon: PoseidonPermutation<Self::CircuitField>;

    /// Poseidon permutation parameters for the
    /// [`ScalarField`](Cycle::ScalarField).
    type ScalarPoseidon: PoseidonPermutation<Self::ScalarField>;

    /// Runtime parameters holding generators and Poseidon constants.
    type Params: Send + Sync + 'static;

    /// Returns the fixed generators for the
    /// [`NestedCurve`](Cycle::NestedCurve).
    fn nested_generators(params: &Self::Params) -> &Self::NestedGenerators;

    /// Returns the fixed generators for the [`HostCurve`](Cycle::HostCurve).
    fn host_generators(params: &Self::Params) -> &Self::HostGenerators;

    /// Returns the Poseidon parameter constants for the
    /// [`CircuitField`](Cycle::CircuitField).
    fn circuit_poseidon(params: &Self::Params) -> &Self::CircuitPoseidon;

    /// Returns the Poseidon parameter constants for the
    /// [`ScalarField`](Cycle::ScalarField).
    fn scalar_poseidon(params: &Self::Params) -> &Self::ScalarPoseidon;

    /// Generate the runtime parameters for this cycle.
    fn generate() -> Self::Params;
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
        (self.g()[0] * value + *self.h() * blind).into()
    }
}

/// Specification for a [Poseidon](https://eprint.iacr.org/2019/458) permutation over a field $\mathbb{F}$.
pub trait PoseidonPermutation<F: Field>: Send + Sync + 'static {
    /// The size of the state.
    const T: usize;

    /// The rate, which caps the number of elements that can be squeezed or
    /// absorbed before a permutation is applied. Must be smaller than `T`;
    /// violations may cause panics or incorrect behavior at runtime.
    const RATE: usize;

    /// Number of full rounds where the sbox is applied to every element of the
    /// state. Must be even (half at the start, half at the end); violations
    /// may cause panics or incorrect behavior at runtime.
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
