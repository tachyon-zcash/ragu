//! # `ragu_core`
//!
//! This crate contains the fundamental traits and types for writing protocols
//! and arithmetic circuits for the Ragu project. This API is re-exported (as
//! necessary) in other crates and so this crate is only intended to be used
//! internally by Ragu.
//!
//! This crate reexports Udon's cycle and Poseidon traits and exposes its Pasta
//! types through [`pasta`]. Ragu-specific generator derivation and loading
//! live in `ragu_pcd::pasta`.
//!
//! ## Cycles of Elliptic Curves
//!
//! Ragu is parameterized by a cycle of elliptic curves defined over large prime
//! fields, described by an implementation of the [`Cycle`] trait. The only
//! implementation is the [Pasta cycle](pasta), whose fields and curves — and
//! the vocabulary generic code names: fields, curves, evaluation domains,
//! polynomial utilities — are `udon`'s.
//!
//! ## Algebraic Hashes
//!
//! Ragu leans on [Poseidon](https://eprint.iacr.org/2019/458); a [`Cycle`]
//! provides the permutation's parameters over each field through
//! [`PoseidonPermutation`].

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_core` requires the `alloc` feature to be enabled.");
extern crate alloc;

pub mod convert;
pub mod drivers;
mod errors;
mod execution;
pub mod gadgets;
pub mod maybe;
pub mod routines;

pub use drivers::Coeff;
pub use errors::{Error, Result};
pub use execution::{fft, ifft, msm};
pub use udon::{
    cycle::{Cycle, FixedGenerators},
    poseidon::PoseidonPermutation,
};

/// Udon's Pasta cycle, fields, curves, and Poseidon instances.
pub mod pasta {
    use udon::curve::Affine;
    pub use udon::{
        cycle::{PallasGenerators, Pasta, PastaParams, VestaGenerators},
        poseidon::{PoseidonFp, PoseidonFq},
    };

    use crate::Cycle;

    /// The Pallas base field: the Pasta cycle's circuit field.
    pub type Fp = <Pasta as Cycle>::CircuitField;

    /// The Pallas scalar field: the Pasta cycle's scalar field.
    pub type Fq = <Pasta as Cycle>::ScalarField;

    /// Pallas in projective coordinates.
    pub type Ep = <EpAffine as Affine>::Projective;

    /// Pallas in affine coordinates, including identity: the Pasta cycle's
    /// nested curve.
    pub type EpAffine = <Pasta as Cycle>::NestedCurve;

    /// Vesta in projective coordinates.
    pub type Eq = <EqAffine as Affine>::Projective;

    /// Vesta in affine coordinates, including identity: the Pasta cycle's host
    /// curve.
    pub type EqAffine = <Pasta as Cycle>::HostCurve;
}
