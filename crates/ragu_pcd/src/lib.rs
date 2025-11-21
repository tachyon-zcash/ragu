//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;

use core::marker::PhantomData;

mod step;

/// Builder for an [`Application`](crate::Application) for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R, [(); HEADER_SIZE], &'params ())>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>
    ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    /// Create an empty [`ApplicationBuilder`] for proof-carrying data.
    pub fn new() -> Self {
        ApplicationBuilder {
            _marker: PhantomData,
        }
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    pub fn finalize(self, _params: &C) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        Ok(Application {
            _marker: PhantomData,
        })
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R, [(); HEADER_SIZE], &'params ())>,
}
