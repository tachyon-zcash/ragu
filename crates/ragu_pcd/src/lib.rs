//! # `ragu_pcd`

#![cfg_attr(not(test), no_std)]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1_favicon32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1_rustdoc128.png")]

extern crate alloc;

use arithmetic::Cycle;
use ragu_circuits::{
    Circuit,
    mesh::{Mesh, MeshBuilder},
    polynomials::Rank,
};
use ragu_core::{
    Error, Result,
    drivers::emulator::Emulator,
    maybe::{Always, Maybe, MaybeKind},
};
use rand::Rng;

use alloc::collections::BTreeMap;
use core::{any::TypeId, marker::PhantomData};

pub use header::Header;
pub use proof::{Pcd, Proof};
pub use step::Step;
use step::{Adapter, rerandomize::Rerandomize};

mod header;
mod proof;
mod step;

/// Builder for a proof-carrying data application.
///
/// ## Generic Parameters
///
/// * The [`R: Rank`](Rank) parameter defines the size of the polynomials used
///   in the construction.
/// * The [`C: Cycle`](Cycle) parameter defines the cycle of elliptic curves
///   used.
/// * The `HEADER_SIZE` parameter defines the _size_ of the headers in terms of
///   the number of elements in the public inputs reserved for each header,
///   including its discriminant (prefix).
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    circuit_mesh: MeshBuilder<'params, C::CircuitField, R>,
    next_step_index: usize,
    header_map: BTreeMap<header::Prefix, TypeId>,
    _marker: PhantomData<C>,
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
    /// Create a new [`ApplicationBuilder`] for proof-carrying data.
    pub fn new() -> Self {
        let tmp = ApplicationBuilder {
            circuit_mesh: MeshBuilder::new(),
            next_step_index: 0,
            header_map: BTreeMap::new(),
            _marker: PhantomData,
        };
        let tmp = tmp
            .register(step::rerandomize::Rerandomize::<()>::new())
            .expect("internal step");

        tmp
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) should be the next sequential
    /// index that has not been inserted yet.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        if S::INDEX.map() != self.next_step_index {
            return Err(Error::Initialization(
                "steps must be registered in sequential order".into(),
            ));
        }

        match self
            .header_map
            .get(&<S::Output as Header<C::CircuitField>>::PREFIX)
        {
            Some(ty) => {
                if *ty != TypeId::of::<S::Output>() {
                    return Err(Error::Initialization(
                        "two different Header implementations using the same prefix".into(),
                    ));
                }
            }
            None => {
                self.header_map.insert(
                    <S::Output as Header<C::CircuitField>>::PREFIX,
                    TypeId::of::<S::Output>(),
                );
            }
        }

        self.circuit_mesh = self
            .circuit_mesh
            .register_circuit(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;
        self.next_step_index += 1;

        Ok(self)
    }

    /// Finalize.
    pub fn finalize(self, params: &C) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        Ok(Application {
            _circuit_mesh: self.circuit_mesh.finalize(params.circuit_poseidon())?,
            _marker: PhantomData,
        })
    }
}

/// The recursion context that is used to create and verify proof-carrying data.
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    _circuit_mesh: Mesh<'params, C::CircuitField, R>,
    _marker: PhantomData<(C, R, [(); HEADER_SIZE])>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Creates a trivial proof for the empty [`Header`] implementation `()`.
    /// This may or may not be identical to any previously constructed (trivial)
    /// proof, and so is not guaranteed to be freshly randomized.
    pub fn trivial(&self) -> Proof<C> {
        Proof {
            _marker: PhantomData,
        }
    }

    /// Creates a random trivial proof for the empty [`Header`] implementation
    /// `()`. This takes more time to generate because it cannot be cached
    /// within the [`Application`].
    fn random<'source, RNG: Rng>(&self, _rng: &mut RNG) -> Pcd<'source, C, ()> {
        self.trivial().carry(())
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
    fn merge<'source, RNG: Rng, S: Step<C>>(
        &self,
        _rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<'source, C, S::Left>,
        right: Pcd<'source, C, S::Right>,
    ) -> Result<(Proof<C>, S::Aux<'source>)> {
        // TODO(ebfull): This should construct the actual witness rather than emulate.
        let mut dr = Emulator::extractor();
        let witness = Always::maybe_just(|| (left.data, right.data, witness));
        let (_, aux) = Adapter::<C, S, R, HEADER_SIZE>::new(step).witness(&mut dr, witness)?;

        Ok((
            Proof {
                _marker: PhantomData,
            },
            aux.take(),
        ))
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
        pcd: Pcd<'source, C, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<'source, C, H>> {
        let random_proof = self.random(rng);
        let data = pcd.data.clone();
        let rerandomized_proof = self.merge(rng, Rerandomize::new(), (), pcd, random_proof)?;

        Ok(rerandomized_proof.0.carry(data))
    }

    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<H: Header<C::CircuitField>>(&self, _pcd: &Pcd<'_, C, H>) -> Result<bool> {
        Ok(true)
    }
}
