//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{Mesh, MeshBuilder},
    polynomials::Rank,
    staging::Staged,
};
use ragu_core::{Error, Result};
use rand::Rng;

use alloc::collections::BTreeMap;
use core::{any::TypeId, marker::PhantomData};

use header::Header;
use internal_circuits::dummy;
pub use proof::{Pcd, Proof};
use step::{Step, adapter::Adapter};

pub mod header;
mod internal_circuits;
mod merge;
mod proof;
mod stages;
pub mod step;
mod verify;

/// Builder for an [`Application`] for proof-carrying data.
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: MeshBuilder<'params, C::CircuitField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Prefix, TypeId>,
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
            circuit_mesh: MeshBuilder::new(),
            num_application_steps: 0,
            header_map: BTreeMap::new(),
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) should be the next sequential
    /// index that has not been inserted yet.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        if S::INDEX
            .circuit_index(None)
            .expect("step index should be application-defined")
            != self.num_application_steps
        {
            return Err(Error::Initialization(
                "steps must be registered in sequential order".into(),
            ));
        }

        self.prevent_duplicate_prefixes::<S::Output>()?;
        self.prevent_duplicate_prefixes::<S::Left>()?;
        self.prevent_duplicate_prefixes::<S::Right>()?;

        self.circuit_mesh = self
            .circuit_mesh
            .register_circuit(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;
        self.num_application_steps += 1;

        Ok(self)
    }

    fn prevent_duplicate_prefixes<H: Header<C::CircuitField>>(&mut self) -> Result<()> {
        match self.header_map.get(&H::PREFIX) {
            Some(ty) => {
                if *ty != TypeId::of::<H>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same prefix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(H::PREFIX, TypeId::of::<H>());
            }
        }

        Ok(())
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    pub fn finalize(
        mut self,
        params: &'params C,
    ) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        // First, insert all of the internal steps.
        self.circuit_mesh =
            self.circuit_mesh
                .register_circuit(Adapter::<C, _, R, HEADER_SIZE>::new(
                    step::rerandomize::Rerandomize::<()>::new(),
                ))?;

        // Then, insert all of the "internal circuits" used for recursion plumbing.
        self.circuit_mesh = self.circuit_mesh.register_circuit(dummy::Circuit)?;

        self.circuit_mesh = self.circuit_mesh.register_circuit(Staged::new(
            crate::internal_circuits::c::Circuit::<C, R>::new(params.circuit_poseidon()),
        ))?;

        Ok(Application {
            circuit_mesh: self.circuit_mesh.finalize(params.circuit_poseidon())?,
            params,
            num_application_steps: self.num_application_steps,
            _marker: PhantomData,
        })
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: Mesh<'params, C::CircuitField, R>,
    params: &'params C,
    num_application_steps: usize,
    _marker: PhantomData<[(); HEADER_SIZE]>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    /// This may or may not be identical to any previously constructed (trivial)
    /// proof, and so is not guaranteed to be freshly randomized.
    pub fn trivial(&self) -> Proof<C, R> {
        proof::trivial::<C, R, HEADER_SIZE>(self.num_application_steps, &self.circuit_mesh)
    }

    /// Creates a random trivial proof for the empty [`Header`] implementation
    /// `()`. This takes more time to generate because it cannot be cached
    /// within the [`Application`].
    fn random<'source, RNG: Rng>(&self, _rng: &mut RNG) -> Pcd<'source, C, R, ()> {
        self.trivial().carry(())
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a random proof instance using
    /// an internal rerandomization step, such that the resulting proof is valid
    /// for the same [`Header`] but reveals nothing else about the original
    /// proof. As a result, [`Application::verify`] should produce the same
    /// result on the provided `pcd` as it would the output of this method.
    pub fn rerandomize<'source, RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<'source, C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<'source, C, R, H>> {
        let random_proof = self.random(rng);
        let data = pcd.data.clone();
        let rerandomized_proof = self.merge(
            rng,
            step::rerandomize::Rerandomize::new(),
            (),
            pcd,
            random_proof,
        )?;

        Ok(rerandomized_proof.0.carry(data))
    }

    /// Merge two PCD into one using a provided [`Step`].
    ///
    /// ## Parameters
    ///
    /// * `rng`: a random number generator used to sample randomness during
    ///   proof generation. The fact that this method takes a random number
    ///   generator is not an indication that the resulting proof-carrying data
    ///   is zero-knowledge; that must be ensured by performing
    ///   [`Application::rerandomize`] at a later point.
    /// * `step`: the [`Step`] instance that has been registered in this
    ///   [`Application`].
    /// * `witness`: the witness data for the [`Step`]
    /// * `left`: the left PCD to merge in this step; must correspond to the
    ///   [`Step::Left`] header.
    /// * `right`: the right PCD to merge in this step; must correspond to the
    ///   [`Step::Right`] header.
    pub fn merge<'source, RNG: Rng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, R, S::Left>,
        right: Pcd<'source, C, R, S::Right>,
    ) -> Result<(Proof<C, R>, S::Aux<'source>)> {
        merge::merge::<C, R, RNG, S, HEADER_SIZE>(
            self.num_application_steps,
            &self.circuit_mesh,
            self.params,
            rng,
            step,
            witness,
            left,
            right,
        )
    }

    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        rng: RNG,
    ) -> Result<bool> {
        verify::verify::<C, R, RNG, H, HEADER_SIZE>(&self.circuit_mesh, pcd, rng)
    }
}
