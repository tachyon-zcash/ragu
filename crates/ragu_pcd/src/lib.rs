//! Proof-carrying data framework for Ragu.
//!
//! This crate provides the top-level API for building PCD applications:
//!
//! - [`ApplicationBuilder`] / [`Application`] — configure, build, then
//!   [`seed`](Application::seed), [`fuse`](Application::fuse),
//!   [`rerandomize`](Application::rerandomize), and
//!   [`verify`](Application::verify) proofs.
//! - [`step::Step`] — the trait that defines computation nodes (transitions).
//! - [`header::Header`] — the trait that defines succinct state representations.
//! - [`Proof`] / [`Pcd`] — the proof and proof-carrying-data structures.

#![no_std]
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("`ragu_pcd` requires the `alloc` feature to be enabled.");
extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

mod backend;
#[cfg(test)]
#[path = "../tests/backend_equivalence/mod.rs"]
mod backend_equivalence;
mod fuse;
// The fuzzing surface. Gates itself behind `unstable-fuzzing` with an inner
// `#![cfg]` and hides itself from the docs, so no feature attribute appears
// here.
pub mod fuzzing;
pub mod header;
mod internal;
mod proof;
pub mod step;
mod verify;

use alloc::collections::BTreeMap;
use core::{any::TypeId, cell::OnceCell, marker::PhantomData};

use header::Header;
pub use proof::{Pcd, Proof};
use ragu_arithmetic::{
    Cycle,
    rand::{CryptoRng, SeedableRng, rngs::StdRng},
};
use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::Rank,
    registry::{Registry, RegistryBuilder},
};
use ragu_core::{Error, Result};
use step::{Step, internal::adapter::Adapter};

/// Domain separation tag for Ragu PCD protocol.
// FIXME: choose a permanent domain separation tag before release.
pub(crate) const RAGU_TAG: &[u8] = b"FIXME";

pub use backend::SelectableBackend;

/// Builder for an [`Application`] for proof-carrying data.
pub struct ApplicationBuilder<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    B: SelectableBackend = ReferenceBackend,
> {
    native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    num_application_steps: usize,
    header_map: BTreeMap<header::Suffix, TypeId>,
    _marker: PhantomData<([(); HEADER_SIZE], B)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE, B>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    ApplicationBuilder<'params, C, R, HEADER_SIZE, B>
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

    /// Selects a Ragu-owned computational backend.
    ///
    /// The selected backend is used for proving and native witness
    /// computation; [`Application::verify`] consults the kernels of its
    /// [`SelectableBackend::Verifier`], which the selection fixes (for
    /// example `AcceleratedProver` accelerates proving only). Applications may
    /// select a Ragu implementation but cannot provide one.
    pub fn with_backend<SelectedBackend: SelectableBackend>(
        self,
    ) -> ApplicationBuilder<'params, C, R, HEADER_SIZE, SelectedBackend> {
        ApplicationBuilder {
            native_registry: self.native_registry,
            nested_registry: self.nested_registry,
            num_application_steps: self.num_application_steps,
            header_map: self.header_map,
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) must be the next sequential
    /// index that has not been inserted yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the step's index is not the next sequential index,
    /// or if any of the step's header suffixes conflict with an
    /// already-registered header type.
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        const {
            assert!(
                <S::Left as Header<C::CircuitField>>::SUFFIX.get()
                    != <header::Dummy as Header<C::CircuitField>>::SUFFIX.get()
                    && <S::Right as Header<C::CircuitField>>::SUFFIX.get()
                        != <header::Dummy as Header<C::CircuitField>>::SUFFIX.get(),
                "a Step cannot declare the Dummy header: only the internal Bootstrap step may, \
                 and its fuse is the base case"
            );
        }

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
    ///
    /// This also bootstraps the recursion: it fuses two synthesized dummies
    /// through an internal step — the only fuse treated as the base case — to
    /// produce the bootstrap proof that [`seed`](Application::seed) consumes as
    /// a child. This costs one fuse, once per application.
    ///
    /// # Errors
    ///
    /// Returns an error if internal circuit registration, registry
    /// finalization, or the bootstrap fuse fails.
    pub fn finalize(
        mut self,
        params: &'params C::Params,
    ) -> Result<Application<'params, C, R, HEADER_SIZE, B>> {
        // Build the native registry:
        // 1. Application circuits (already registered)
        // 2. Internal circuits and masks
        // 3. Internal steps
        let (total_circuits, log2_circuits) =
            internal::native::total_circuit_counts(self.num_application_steps);

        // First, register internal circuits and masks
        self.native_registry = internal::native::register_all::<C, R, HEADER_SIZE>(
            self.native_registry,
            params,
            log2_circuits,
        )?;

        // Then, register internal steps. `Bootstrap` is registered directly
        // because it is the one step allowed to declare `Dummy` inputs;
        // every other internal step goes through `register_internal_step`,
        // which rejects them.
        self = self.register_internal_step(step::internal::rerandomize::Rerandomize::<()>::new())?;
        self.native_registry =
            self.native_registry
                .register_internal_step(Adapter::<C, _, R, HEADER_SIZE>::new(
                    step::internal::bootstrap::Bootstrap::new(),
                ))?;

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

        // Register nested internal circuits (no application steps, no headers).
        self.nested_registry = internal::nested::register_all::<C, R>(self.nested_registry)?;

        let mut app = Application {
            native_registry: self.native_registry.finalize()?,
            nested_registry: self.nested_registry.finalize()?,
            params,
            num_application_steps: self.num_application_steps,
            bootstrap: None,
            seeded_trivial: OnceCell::new(),
            _marker: PhantomData,
        };

        // Bootstrap the recursion once, up front, so that `seed` never pays
        // for it lazily. The proof carries no secrets — it attests nothing and
        // is consumed as a public child by every seed — so a fixed seed is
        // fine. Its bytes are stable for a given `rand` version but must not
        // be relied on across versions (`StdRng` is not portable), so never
        // pin them.
        let mut rng = StdRng::seed_from_u64(0);
        let (pcd, ()) = app.fuse(
            &mut rng,
            step::internal::bootstrap::Bootstrap::new(),
            (),
            app.dummy_pcd(),
            app.dummy_pcd(),
        )?;
        app.bootstrap = Some(pcd.into_parts().0);

        Ok(app)
    }

    /// Registers an internal [`Step`] other than the bootstrap step.
    ///
    /// Internal steps do not go through `prevent_duplicate_suffixes`, so this
    /// is where the invariant that only
    /// [`Bootstrap`](step::internal::bootstrap::Bootstrap) declares
    /// [`Dummy`](header::Dummy) inputs is enforced: an internal step
    /// with `Dummy` inputs would take the base case, and if it also carried
    /// a data-bearing output it would let a prover attest arbitrary data without
    /// verifying its children. The check is evaluated at compile time for each
    /// step registered here.
    ///
    /// It covers *declared* (constant) suffixes only. An internal step whose
    /// input suffix is a witness wire — today only `Rerandomize`, via uniform
    /// encoding — must instead constrain that wire away from `Dummy`
    /// itself; see `ProofInputs::is_dummy_input`.
    fn register_internal_step<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        const {
            assert!(
                <S::Left as Header<C::CircuitField>>::SUFFIX.get()
                    != header::Suffix::internal(2).get()
                    && <S::Right as Header<C::CircuitField>>::SUFFIX.get()
                        != header::Suffix::internal(2).get(),
                "only the internal Bootstrap step may declare Dummy inputs"
            );
        }

        self.native_registry =
            self.native_registry
                .register_internal_step(Adapter::<C, S, R, HEADER_SIZE>::new(step))?;

        Ok(self)
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
pub struct Application<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    B: SelectableBackend = ReferenceBackend,
> {
    native_registry: Registry<'params, C::CircuitField, R>,
    nested_registry: Registry<'params, C::ScalarField, R>,
    params: &'params C::Params,
    num_application_steps: usize,
    /// The proof that bootstraps the recursion: a genuine, verifying
    /// `Pcd<()>` consumed as a child by every [`seed`](Self::seed).
    ///
    /// Always `Some` once [`ApplicationBuilder::finalize`] returns. It is `None`
    /// only while `finalize` is building it, since doing so runs
    /// [`fuse`](Self::fuse) on the otherwise complete `Application`.
    bootstrap: Option<Proof<C, R>>,
    /// A valid `Pcd<()>` used as the right child during rerandomization.
    /// Lazily derived from the bootstrap proof and then reused.
    seeded_trivial: OnceCell<Proof<C, R>>,
    _marker: PhantomData<([(); HEADER_SIZE], B)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    /// Seed a new computation by running a [`Step`] declaring `()` for both of
    /// its inputs.
    ///
    /// This is the entry point for creating leaf nodes in a PCD tree. The step
    /// is fused against the bootstrap proof built by
    /// [`ApplicationBuilder::finalize`] as both children, so this is an
    /// ordinary fuse whose child claims are enforced, not a base case.
    pub fn seed<'source, RNG: CryptoRng, S: Step<C, Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        self.fuse(
            rng,
            step,
            witness,
            self.bootstrap_pcd(),
            self.bootstrap_pcd(),
        )
    }

    /// Returns the `Pcd<()>` that bootstraps the recursion.
    ///
    /// [`ApplicationBuilder::finalize`] builds it once: two synthesized
    /// [`dummy_pcd`](Self::dummy_pcd) dummies — which cannot verify on
    /// their own — are fused through the internal
    /// [`Bootstrap`](step::internal::bootstrap::Bootstrap) step, the only step
    /// declaring [`Dummy`](header::Dummy) inputs and hence the only
    /// fuse treated as the base case. The result verifies, so
    /// [`seed`](Self::seed) consumes it as an ordinary child.
    ///
    /// The proof attests nothing: `Bootstrap` ignores its children entirely and
    /// outputs the data-less unit header. It is a public constant of the
    /// application, and every call returns a clone of the same proof.
    fn bootstrap_pcd(&self) -> Pcd<C, R, ()> {
        self.bootstrap
            .as_ref()
            .expect("finalize always sets the bootstrap proof")
            .clone()
            .carry(())
    }

    /// Returns the cached valid `Pcd<()>` used as the neutral right child of
    /// rerandomization.
    ///
    /// The proof is lazily created by folding the bootstrap proof with itself
    /// through the unit instantiation of the rerandomization step. Subsequent
    /// calls reuse the same proof.
    fn seeded_trivial_pcd<RNG: CryptoRng>(&self, rng: &mut RNG) -> Pcd<C, R, ()> {
        self.seeded_trivial
            .get_or_init(|| {
                self.fuse(
                    rng,
                    step::internal::rerandomize::Rerandomize::new(),
                    (),
                    self.bootstrap_pcd(),
                    self.bootstrap_pcd(),
                )
                .expect("seeded trivial fuse should not fail")
                .0
                .into_parts()
                .0
            })
            .clone()
            .carry(())
    }

    /// Rerandomize proof-carrying data.
    ///
    /// This will internally fold the [`Pcd`] with a cached seeded `Pcd<()>`
    /// using an internal rerandomization step, producing a
    /// fresh proof that is valid for the same [`Header`] and carries the same
    /// data. [`Application::verify`] produces the same result on the provided
    /// `pcd` as it would on the output of this method.
    ///
    /// The intent is that the output be unlinkable to the input. Today that is
    /// not achieved at all: the output embeds the input's commitments and stage
    /// polynomials in the clear (as its left-child data), and its folded
    /// accumulator is a deterministic function of the input proof, cached
    /// seeded proof, and public challenges. Achieving witness-hiding of the
    /// accumulator needs a fold-level randomizer; unlinkability of an
    /// uncompressed proof additionally needs the child data hidden (compression,
    /// or a second randomized pass). Both are future work, tracked separately.
    pub fn rerandomize<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<C, R, H>> {
        let seeded_trivial = self.seeded_trivial_pcd(rng);

        // The Rerandomize step's witness() returns the left input's data as
        // output data, preserving it through rerandomization. Its right child
        // is the valid, cached seeded unit proof.
        self.fuse(
            rng,
            step::internal::rerandomize::Rerandomize::new(),
            (),
            pcd,
            seeded_trivial,
        )
        .map(|(pcd, ())| pcd)
    }

    /// Returns a reference to the native [`Registry`].
    pub fn native_registry(&self) -> &Registry<'_, C::CircuitField, R> {
        &self.native_registry
    }
}
