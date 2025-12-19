//! # `ragu_primitives`
//!
//! This crate contains low level gadgets and algorithms for the Ragu project.
//! This API is re-exported (as necessary) in other crates and so this crate is
//! only intended to be used internally by Ragu.

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;
extern crate self as ragu_primitives;

mod boolean;
mod element;
mod endoscalar;
mod foreign;
pub mod io;
mod lazy;
mod point;
pub mod poseidon;
pub mod promotion;
mod simulator;
mod util;
pub mod vec;

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};

use io::{Buffer, Write};
use promotion::Demoted;

pub use boolean::{Boolean, multipack};
pub use element::{Element, multiadd};
pub use endoscalar::Endoscalar;
pub use lazy::Lazy;
pub use point::Point;
pub use simulator::Simulator;

/// Primitive extension trait for all gadgets.
pub trait GadgetExt<'dr, D: Driver<'dr>>: Gadget<'dr, D> {
    /// Write this gadget into a buffer, assuming the gadget's
    /// [`Kind`](Gadget::Kind) implements [`Write`].
    fn write<B: Buffer<'dr, D>>(&self, dr: &mut D, buf: &mut B) -> Result<()>
    where
        Self::Kind: Write<D::F>,
    {
        <Self::Kind as Write<D::F>>::write_gadget(self, dr, buf)
    }

    /// Demote this gadget by stripping its witness data.
    fn demote(&self) -> Result<Demoted<'dr, D, Self>> {
        Demoted::new(self)
    }
}

impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> GadgetExt<'dr, D> for G {}
