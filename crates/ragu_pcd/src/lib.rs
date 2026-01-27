//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

extern crate alloc;

mod circuits;
mod components;
mod fuse;
pub mod header;
mod proof;
pub mod step;
mod verify;

#[cfg(any(test, feature = "unstable-test-fixtures"))]
#[doc(hidden)]
pub mod test_fixtures;

#[cfg(test)]
mod tests;

use arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{Registry, RegistryBuilder},
};
use ragu_core::{Error, Result};
use rand::Rng;

use alloc::collections::BTreeMap;
use core::{any::TypeId, cell::OnceCell, marker::PhantomData};

use header::Header;
pub use proof::{Pcd, Proof};
use step::{Step, internal::adapter::Adapter};

/// Builder for an [`Application`] for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Suffix, TypeId>,
    _marker: PhantomData<[(); HEADER_SIZE]>,
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
            native_registry: RegistryBuilder::new(),
            nested_registry: RegistryBuilder::new(),
            num_application_steps: 0,
            header_map: BTreeMap::new(),
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) should be the next sequential
    /// index that has not been inserted yet.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        S::INDEX.assert_index(self.num_application_steps)?;

        self.prevent_duplicate_suffixes::<S::Output>()?;
        self.prevent_duplicate_suffixes::<S::Left>()?;
        self.prevent_duplicate_suffixes::<S::Right>()?;

        self.native_registry =
            self.native_registry
                .register_circuit(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;
        self.num_application_steps += 1;

        Ok(self)
    }

    /// Register `count` trivial circuits to simulate application steps
    /// registration.
    ///
    /// This is useful for testing internal circuit behavior with a non-zero
    /// number of application steps, without needing real [`Step`]
    /// implementations.
    #[cfg(test)]
    pub(crate) fn register_dummy_circuits(mut self, count: usize) -> Result<Self> {
        for _ in 0..count {
            self.native_registry = self.native_registry.register_circuit(())?;
            self.num_application_steps += 1;
        }
        Ok(self)
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    pub fn finalize(
        mut self,
        params: &'params C::Params,
    ) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        // First, insert all of the internal steps.
        {
            self.native_registry =
                self.native_registry
                    .register_circuit(Adapter::<C, _, R, HEADER_SIZE>::new(
                        step::internal::rerandomize::Rerandomize::<()>::new(),
                    ))?;

            self.native_registry =
                self.native_registry
                    .register_circuit(Adapter::<C, _, R, HEADER_SIZE>::new(
                        step::internal::trivial::Trivial::new(),
                    ))?;
        }

        // Then, insert all of the internal circuits used for recursion plumbing.
        {
            let (total_circuits, log2_circuits) =
                circuits::native::total_circuit_counts(self.num_application_steps);

            self.native_registry = circuits::native::register_all::<C, R, HEADER_SIZE>(
                self.native_registry,
                params,
                log2_circuits,
                self.num_application_steps,
            )?;

            assert_eq!(
                self.native_registry.log2_circuits(),
                log2_circuits,
                "log2_circuits mismatch"
            );
            assert_eq!(
                self.native_registry.num_circuits(),
                total_circuits,
                "final circuit count mismatch"
            );
        }

        // Register nested internal circuits (no application steps, no headers).
        self.nested_registry = circuits::nested::register_all::<C, R>(self.nested_registry)?;

        Ok(Application {
            native_registry: self.native_registry.finalize(C::circuit_poseidon(params))?,
            nested_registry: self.nested_registry.finalize(C::scalar_poseidon(params))?,
            params,
            num_application_steps: self.num_application_steps,
            seeded_trivial: OnceCell::new(),
            _marker: PhantomData,
        })
    }

    fn prevent_duplicate_suffixes<H: Header<C::CircuitField>>(&mut self) -> Result<()> {
        match self.header_map.get(&H::SUFFIX) {
            Some(ty) => {
                if *ty != TypeId::of::<H>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same suffix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(H::SUFFIX, TypeId::of::<H>());
            }
        }

        Ok(())
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    native_registry: Registry<'params, C::CircuitField, R>,
    nested_registry: Registry<'params, C::ScalarField, R>,
    params: &'params C::Params,
    num_application_steps: usize,
    /// Cached seeded trivial proof for rerandomization.
    seeded_trivial: OnceCell<Proof<C, R>>,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Seed a new computation by running a step with trivial inputs.
    ///
    /// This is the entry point for creating leaf nodes in a PCD tree.
    /// Internally creates minimal trivial proofs with `()` headers and fuses
    /// them with the provided step to produce a valid proof.
    pub fn seed<'source, RNG: Rng, S: Step<C, Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        self.fuse(rng, step, witness, self.trivial_pcd(), self.trivial_pcd())
    }

    /// Returns a seeded trivial proof for use in rerandomization.
    ///
    /// A seeded trivial is a trivial proof that has been through `seed()`
    /// (folded with itself). This gives it valid proof structure, avoiding
    /// base case detection issues.
    ///
    /// The proof is lazily created on first use and cached. *Importantly*,
    /// note that this may return the same proof on subsequent calls, and
    /// is not random.
    fn seeded_trivial_pcd<'source, RNG: Rng>(&self, rng: &mut RNG) -> Pcd<'source, C, R, ()> {
        let proof = self.seeded_trivial.get_or_init(|| {
            self.seed(rng, step::internal::trivial::Trivial::new(), ())
                .expect("seeded trivial seed should not fail")
                .0
        });
        proof.clone().carry(())
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a seeded trivial proof
    /// using an internal rerandomization step, such that the resulting proof
    /// is valid for the same [`Header`] but reveals nothing else about the
    /// original proof. As a result, [`Application::verify`] should produce the
    /// same result on the provided `pcd` as it would the output of this method.
    pub fn rerandomize<'source, RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<'source, C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<'source, C, R, H>> {
        let data = pcd.data.clone();

        // Seed a trivial proof for rerandomization.
        // TODO: this is a temporary hack that allows the base case logic to be simple
        let seeded_trivial = self.seeded_trivial_pcd(rng);
        let rerandomized_proof = self.fuse(
            rng,
            step::internal::rerandomize::Rerandomize::new(),
            (),
            pcd,
            seeded_trivial,
        )?;

        Ok(rerandomized_proof.0.carry(data))
    }
}
