//! A downstream consumer that depends only on `ragu`, compiled for bare metal
//! by backend CI.
//!
//! It checks that the root crate builds without `std`, and that the derive
//! macros resolve the `ragu_core`, `ragu_primitives` and `udon` paths they
//! emit through `ragu` alone.

#![no_std]

use ragu::{
    drivers::Driver,
    gadgets::{Gadget, Kind},
    pcd::pasta::PastaParams,
    primitives::{Element, comparison::GadgetEquals, consistent::Consistent, io::Write},
};

/// Obtains the parameters through the public API without requiring `std`.
pub fn parameters() -> &'static PastaParams {
    ragu::pcd::pasta::baked()
}

/// A gadget whose derives name `ragu_core`, `ragu_primitives` and `udon`.
#[derive(Gadget, Write, Consistent, GadgetEquals)]
pub struct Pair<'dr, D: Driver<'dr>> {
    /// The first element.
    #[ragu(gadget)]
    pub a: Element<'dr, D>,
    /// The second element.
    #[ragu(gadget)]
    pub b: Element<'dr, D>,
}

/// The kind of [`Pair`], through the `Kind!` macro.
pub type PairKind<F> = Kind![F; Pair<'_, _>];
