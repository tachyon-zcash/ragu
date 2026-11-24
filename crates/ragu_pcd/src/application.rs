//! The application: [`ApplicationBuilder`] registers the steps and finalizes
//! into the [`Application`] in which proofs are made and checked.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{any::TypeId, marker::PhantomData};

use ragu_acceleration::AcceleratedBackend;
use ragu_circuits::{
    polynomials::Rank,
    registry::{Registry, RegistryBuilder},
    staging,
};
use ragu_core::{Cycle, Error, FixedGenerators, PreparedMsm, Result};
use rand::{CryptoRng, SeedableRng, rngs::StdRng};

use crate::{
    Pcd, Proof, SelectableBackend,
    backend::committer::Committer,
    header::Header,
    profile::{Profile, ProfiledCycle},
    step::{Step, internal::adapter::Adapter},
};

/// A step circuit's registration, held until every step's
/// [`NUM_STAGED`](Step::NUM_STAGED) is known, so that every step circuit
/// reserves the same application stage.
type ApplicationRegistration<'params, C, R> = Box<
    dyn FnOnce(
            RegistryBuilder<'params, <C as Cycle>::CircuitField, R>,
            usize,
        ) -> Result<RegistryBuilder<'params, <C as Cycle>::CircuitField, R>>
        + Send
        + Sync
        + 'params,
>;

/// Builder for an [`Application`] for proof-carrying data.
///
/// Independent work uses [`AcceleratedBackend`] by default. Select another
/// backend explicitly with [`Self::with_backend`].
pub struct ApplicationBuilder<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    B: SelectableBackend = AcceleratedBackend,
> {
    pub(crate) native_registry: RegistryBuilder<'params, C::CircuitField, R>,
    pub(crate) nested_registry: RegistryBuilder<'params, C::ScalarField, R>,
    pub(crate) native_source:
        Option<crate::profile::online::SourceRegistry<'params, C::CircuitField>>,
    pub(crate) nested_source:
        Option<crate::profile::online::SourceRegistry<'params, C::ScalarField>>,
    pub(crate) num_application_steps: usize,
    /// The step circuits, registered by [`finalize`](Self::finalize) once
    /// the stage size is known.
    pub(crate) application_circuits: Vec<ApplicationRegistration<'params, C, R>>,
    /// The application stage's size: the largest registered
    /// [`NUM_STAGED`](Step::NUM_STAGED).
    pub(crate) stage_size: usize,
    pub(crate) header_map: BTreeMap<crate::header::Suffix, TypeId>,
    /// A bootstrap proof supplied with [`with_bootstrap`](Self::with_bootstrap),
    /// which finalization installs instead of building one. Boxed to keep
    /// the builder small across by-value `register` calls.
    pub(crate) bootstrap: Option<Box<Proof<C, R>>>,
    /// The header type each registered step outputs, by suffix, and
    /// whether its proofs carry an online polynomial, in a slot its
    /// [`OnlinePolyCommit`](Header::OnlinePolyCommit) does not leave to
    /// padding: what a profile's context is checked against (see
    /// [`Profile::check_context`]).
    pub(crate) output_headers: BTreeMap<crate::header::Suffix, (TypeId, bool)>,
    /// Whether [`Self::finalize`] prepares tables of the commitment
    /// generators (see [`Self::with_commitment_tables`]).
    commitment_tables: bool,
    pub(crate) _marker: PhantomData<([(); HEADER_SIZE], B)>,
}

impl<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend> Default
    for ApplicationBuilder<'_, C, R, HEADER_SIZE, B>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    ApplicationBuilder<'params, C, R, HEADER_SIZE, B>
{
    /// Create an empty [`ApplicationBuilder`] for proof-carrying data.
    pub fn new() -> Self {
        ApplicationBuilder {
            native_source: None,
            nested_source: None,
            native_registry: RegistryBuilder::new(),
            nested_registry: RegistryBuilder::new(),
            num_application_steps: 0,
            application_circuits: Vec::new(),
            stage_size: 0,
            header_map: BTreeMap::new(),
            bootstrap: None,
            output_headers: BTreeMap::new(),
            commitment_tables: false,
            _marker: PhantomData,
        }
    }

    /// Prepares tables of the commitment generators at [`Self::finalize`],
    /// for the selected backend's prover.
    ///
    /// A backend that supports them, as the accelerated backends do, then
    /// commits to polynomials with fewer point additions, which makes every
    /// proof faster. The proofs themselves are unchanged. The tables are
    /// prepared once and held for the application's life: on each curve, 16
    /// points of 96 bytes for every coefficient of the rank, about 12.6 MB at
    /// 8192 coefficients. An application that proves repeatedly recovers the
    /// preparation within a few proofs; one that proves once, or only
    /// verifies, should leave them out. Other backends ignore the request.
    pub fn with_commitment_tables(mut self) -> Self {
        self.commitment_tables = true;
        self
    }

    /// Supplies source registries for meshes whose profile context supplies
    /// none. Finalization rejects two sources for the same field.
    ///
    /// A source can have a different rank from the enclosing application;
    /// finalization checks that its restrictions fit without truncation.
    /// The application's setup must identify these sources too.
    pub fn with_source_registries(
        mut self,
        native: Option<crate::profile::online::SourceRegistry<'params, C::CircuitField>>,
        nested: Option<crate::profile::online::SourceRegistry<'params, C::ScalarField>>,
    ) -> Self {
        self.native_source = native;
        self.nested_source = nested;
        self
    }

    /// Installs `tag` as the native registry's tag instead of the one
    /// [`finalize`](Self::finalize) derives from the registered circuits.
    ///
    /// A test seam for adversarial tests, which use it to model another setup
    /// over the same circuits or a tag collision between different ones; see
    /// [`RegistryBuilder::with_tag`].
    #[cfg(test)]
    pub(crate) fn with_native_tag(mut self, tag: C::CircuitField) -> Self {
        self.native_registry = self.native_registry.with_tag(tag);
        self
    }

    /// Installs `tag` as the nested registry's tag; see
    /// [`with_native_tag`](Self::with_native_tag).
    #[cfg(test)]
    pub(crate) fn with_nested_tag(mut self, tag: C::ScalarField) -> Self {
        self.nested_registry = self.nested_registry.with_tag(tag);
        self
    }

    /// Supplies the proof that bootstraps the recursion instead of building
    /// it: one that [`Application::bootstrap_proof`] returned for an
    /// application of the same configuration, stored by the caller, for
    /// instance with [`Proof::to_bytes`]. Finalization installs it instead of
    /// running the bootstrap fuse.
    ///
    /// In the standard profile, [`Application::rerandomize`] uses this proof
    /// as a public right child. A wallet-specific bootstrap proof can link
    /// rerandomized outputs, including after compression. To avoid a
    /// wallet-specific tag, applications can distribute one verified proof
    /// per compatible configuration and have wallets match its bytes or
    /// digest against a value pinned in shared configuration. The caller
    /// is responsible for this check.
    ///
    /// **TODO** Define how compatible wallets provision, pin and verify a
    /// shared bootstrap proof across platforms and releases.
    ///
    /// The proof is checked for this profile's shape and for being a proof of
    /// the bootstrap step, not for validity. No supplied proof can make
    /// anything verify that otherwise would not. Every
    /// [`seed`](Application::seed) enforces its children's claims, and
    /// those claims hold a proof of the bootstrap step to the unit header
    /// and padding polynomial slots, whatever its own application claim,
    /// which no one enforces. But a supplied proof that does not verify
    /// makes every proof built on it fail verification.
    /// Verify it separately through [`Application::compress`] and
    /// [`Application::verify_compressed`] before producing proofs.
    /// Key a stored proof by everything that fixes it (see
    /// [`Application::bootstrap_proof`]) so that a changed application never
    /// loads a stale one.
    ///
    /// # Errors
    ///
    /// Returns an initialization error if the proof does not have this
    /// profile's shape or is not a proof of the bootstrap step.
    pub fn with_bootstrap(mut self, proof: Proof<C, R>) -> Result<Self> {
        let bootstrap = crate::step::InternalStepIndex::Bootstrap.circuit_index::<C::Profile>()?;
        if !proof.well_formed() || proof.circuit_id() != bootstrap {
            return Err(Error::Initialization(
                "the supplied proof is not a bootstrap proof of this profile's shape".into(),
            ));
        }
        self.bootstrap = Some(Box::new(proof));
        Ok(self)
    }

    /// Selects a Ragu-owned computational backend.
    ///
    /// The selected backend is used for proving and native witness
    /// computation; [`Application::verify_compressed`] consults the kernels
    /// of its [`SelectableBackend::Verifier`], which the selection fixes (for
    /// example `AcceleratedProver` accelerates proving only). Applications may
    /// select a Ragu implementation but cannot provide one.
    pub fn with_backend<SelectedBackend: SelectableBackend>(
        self,
    ) -> ApplicationBuilder<'params, C, R, HEADER_SIZE, SelectedBackend> {
        ApplicationBuilder {
            native_registry: self.native_registry,
            nested_registry: self.nested_registry,
            native_source: self.native_source,
            nested_source: self.nested_source,
            num_application_steps: self.num_application_steps,
            application_circuits: self.application_circuits,
            stage_size: self.stage_size,
            header_map: self.header_map,
            bootstrap: self.bootstrap,
            output_headers: self.output_headers,
            commitment_tables: self.commitment_tables,
            _marker: PhantomData,
        }
    }

    /// Register a new application-defined [`Step`] in this context. The
    /// provided [`Step`]'s [`INDEX`](Step::INDEX) must be the next sequential
    /// index that has not been inserted yet.
    ///
    /// The step's [`NUM_STAGED`](Step::NUM_STAGED) sizes the proof's
    /// application stage: every proof carries one stage of the largest
    /// registered size, so the step circuits are constructed by
    /// [`Self::finalize`] once every step is known.
    ///
    /// # Cost
    ///
    /// Every step circuit, including the internal steps, reserves
    /// `ceil(n / 2)` gates for the stage, where `n` is the application's
    /// largest `NUM_STAGED`, and a step adds one equality constraint per
    /// value it stages. An application whose steps stage nothing reserves
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the step's index is not the next sequential index,
    /// if a non-unit header uses a reserved internal suffix, if any of the
    /// step's header suffixes conflict with an already-registered header type,
    /// or if the stage does not fit the rank's gates. Circuit construction
    /// errors are returned by [`Self::finalize`].
    pub fn register<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        const {
            assert!(
                <S::Left as Header<C::CircuitField>>::SUFFIX.get()
                    != <crate::header::Dummy as Header<C::CircuitField>>::SUFFIX.get()
                    && <S::Right as Header<C::CircuitField>>::SUFFIX.get()
                        != <crate::header::Dummy as Header<C::CircuitField>>::SUFFIX.get(),
                "a Step cannot declare the Dummy header: only the internal Bootstrap step may, \
                 and its fuse is the base case"
            );
        }

        S::INDEX.assert_index(self.num_application_steps)?;

        Self::require_unique_kinds::<S::Output>()?;
        Self::require_unique_kinds::<S::Left>()?;
        Self::require_unique_kinds::<S::Right>()?;
        self.prevent_duplicate_suffixes::<S::Output>()?;
        self.prevent_duplicate_suffixes::<S::Left>()?;
        self.prevent_duplicate_suffixes::<S::Right>()?;
        self.output_headers.insert(
            <S::Output as Header<C::CircuitField>>::SUFFIX,
            (
                TypeId::of::<S::Output>(),
                !<<S::Output as Header<C::CircuitField>>::OnlinePolyCommit as crate::header::OnlinePolyCommit>::is_padding(),
            ),
        );

        let stage_size = self.stage_size.max(S::NUM_STAGED);
        // Leave room after the SYSTEM gate and the stage, before the blind
        // gate.
        if 1usize
            .checked_add(staging::stage_gates(stage_size))
            .is_none_or(|end| end >= R::blind_gate())
        {
            return Err(Error::Initialization(
                "the application stage does not fit the rank's gates".into(),
            ));
        }
        self.stage_size = stage_size;
        self.application_circuits
            .push(Box::new(move |registry, stage_size| {
                registry.register_circuit(Adapter::<C, S, R, HEADER_SIZE>::with_stage(
                    step, stage_size,
                )?)
            }));
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
            self.application_circuits
                .push(Box::new(|registry, _| registry.register_circuit(())));
            self.num_application_steps += 1;
        }
        Ok(self)
    }

    /// Perform finalization and optimization steps to produce the
    /// [`Application`].
    ///
    /// This derives each registry's [`Tag`](ragu_circuits::registry::Tag)
    /// from the circuits it holds: the application's steps, and the profile's
    /// internal circuits.
    ///
    /// This also bootstraps the recursion: it fuses two synthesized dummies
    /// through an internal step — the only fuse treated as the base case — to
    /// produce the bootstrap proof that [`seed`](Application::seed) consumes as
    /// a child. This costs one fuse, once per application, unless the proof
    /// was supplied with [`with_bootstrap`](Self::with_bootstrap).
    ///
    /// # Errors
    ///
    /// Returns an error if internal circuit registration, registry
    /// finalization, or the bootstrap fuse fails.
    pub fn finalize(
        self,
        params: &'params C::Params,
    ) -> Result<Application<'params, C, R, HEADER_SIZE, B>>
    where
        <C::Profile as Profile>::Context<'params, C::Base, R, B>: Default,
    {
        self.finalize_with(params, Default::default())
    }

    /// Like [`finalize`](Self::finalize), with the profile's prover
    /// context: what its prover holds across proofs beyond the proof under
    /// construction (see [`Profile::Context`]).
    /// An `Aggregator` application takes a `Decompression` of the wallet
    /// application it aggregates.
    ///
    /// # Errors
    ///
    /// As [`finalize`](Self::finalize).
    pub fn finalize_with(
        mut self,
        params: &'params C::Params,
        mut context: <C::Profile as Profile>::Context<'params, C::Base, R, B>,
    ) -> Result<Application<'params, C, R, HEADER_SIZE, B>> {
        C::Profile::check()?;
        C::Profile::check_context(&mut context, params, &self.header_map)?;

        // The decompression step, which a profile with a statement circuit
        // registers below, stages a value: the application stage, which
        // every step circuit reserves, holds it.
        let decompresses = crate::profile::native_extension::<C::Profile>()
            .statement
            .is_some();
        if decompresses {
            type Decompress = crate::step::internal::decompress::Decompress<()>;
            let stage_size = self.stage_size.max(<Decompress as Step<C>>::NUM_STAGED);
            if 1usize
                .checked_add(staging::stage_gates(stage_size))
                .is_none_or(|end| end >= R::blind_gate())
            {
                return Err(Error::Initialization(
                    "the application stage does not fit the rank's gates".into(),
                ));
            }
            self.stage_size = stage_size;
        }
        C::Profile::NATIVE_ONLINE.check_circuit_points::<C::CircuitField>()?;
        C::Profile::NESTED_ONLINE.check_circuit_points::<C::ScalarField>()?;
        // The sources the meshes certify: one per field, supplied by the
        // builder or the profile's context. Context sources borrow it and
        // are read off it again after setup (see `Application::native_source`).
        // Setup fixes their tags in the helper circuits here.
        let ((native_tag, native_domain), (nested_tag, nested_domain)) = {
            let (profile_native, profile_nested) =
                C::Profile::source_registries::<C::Base, R, B>(&context);
            if (self.native_source.is_some() && profile_native.is_some())
                || (self.nested_source.is_some() && profile_nested.is_some())
            {
                return Err(Error::Initialization(
                    "the builder and profile context both supply a source registry for the same field"
                        .into(),
                ));
            }
            let native_source = self.native_source.clone().or(profile_native);
            let nested_source = self.nested_source.clone().or(profile_nested);
            for (declared, present) in [
                (C::Profile::NATIVE_MESH.is_some(), native_source.is_some()),
                (C::Profile::NESTED_MESH.is_some(), nested_source.is_some()),
            ] {
                if declared != present {
                    return Err(Error::Initialization(
                        "source registries do not match the profile meshes".into(),
                    ));
                }
            }
            if let Some(source) = &native_source {
                source.check_rank::<R>()?;
            }
            if let Some(source) = &nested_source {
                source.check_rank::<R>()?;
            }
            // The bootstrap proof commits the mesh's restrictions at its
            // all-one challenges, the nested ones at their lift.
            if let (Some(mesh), Some(source)) = (C::Profile::NATIVE_MESH, &native_source) {
                mesh.check_source::<_, R>(
                    C::Profile::NATIVE_ONLINE,
                    source,
                    <C::CircuitField as udon::field::Field>::ONE,
                )?;
            }
            if let (Some(mesh), Some(source)) = (C::Profile::NESTED_MESH, &nested_source) {
                mesh.check_source::<_, R>(
                    C::Profile::NESTED_ONLINE,
                    source,
                    crate::internal::nested::challenge::<C>(
                        <C::CircuitField as udon::field::Field>::ONE,
                    )?,
                )?;
            }
            (
                native_source
                    .as_ref()
                    .map(|source| (source.tag(), source.domain_log2()))
                    .unzip(),
                nested_source
                    .as_ref()
                    .map(|source| (source.tag(), source.domain_log2()))
                    .unzip(),
            )
        };

        // Build the native registry:
        // 1. Application circuits (with the final stage size)
        // 2. Internal circuits and masks
        // 3. Internal steps
        let (total_circuits, log2_circuits) =
            crate::internal::native::total_circuit_counts::<C::Profile>(self.num_application_steps);

        for register in core::mem::take(&mut self.application_circuits) {
            self.native_registry = register(self.native_registry, self.stage_size)?;
        }

        // Then, register internal circuits and masks.
        self.native_registry = crate::internal::native::register_all::<C, R, HEADER_SIZE>(
            self.native_registry,
            params,
            log2_circuits,
            self.stage_size,
            native_tag,
            native_domain,
        )?;

        // Then, register internal steps. `Bootstrap` is registered directly
        // because it is the one step allowed to declare `Dummy` inputs;
        // every other internal step goes through `register_internal_step`,
        // which rejects them.
        self = self
            .register_internal_step(crate::step::internal::rerandomize::Rerandomize::<()>::new())?;
        self.native_registry =
            self.native_registry.register_internal_step(
                Adapter::<C, _, R, HEADER_SIZE>::with_stage(
                    crate::step::internal::bootstrap::Bootstrap::new(),
                    self.stage_size,
                )?,
            )?;
        // The decompression step, for a profile whose extension verifies a
        // compressed proof: the one step whose output header is that
        // proof's statement (see `step::internal::decompress`).
        if decompresses {
            self = self.register_internal_step(
                crate::step::internal::decompress::Decompress::<()>::with_excluded_suffixes(
                    crate::profile::ProverContext::excluded_decompression_suffixes(&context),
                    C::Profile::DECOMPRESS_ONLINE_POLYNOMIALS,
                ),
            )?;
        }

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
        self.nested_registry = crate::internal::nested::register_all::<C, R>(
            self.nested_registry,
            params,
            nested_tag,
            nested_domain,
        )?;

        // TODO: In terms of how it currently works, `finalize` builds the
        // registries and derives the tags on every wallet startup. We'll
        // eventually refactor toward the app pinning the two registry
        // tags as constants (rederived and checked by a CI test) and
        // shipping them in the wallet binary as a trusted build artifact,
        // which the wallet loads at startup instead of hashing. This just
        // felt like a good interstitial step towards that.
        let native_registry = self.native_registry.finalize()?;
        let nested_registry = self.nested_registry.finalize()?;
        let host_generators = C::host_generators(params);
        let nested_generators = C::nested_generators(params);
        type Verifier<B> = <B as SelectableBackend>::Verifier;
        let native_ipa_generators = <Verifier<B> as ragu_backend::Backend>::prepare_msm(
            &host_generators.g()[..R::num_coeffs()],
        )
        .map(Arc::new);
        let nested_ipa_generators = <Verifier<B> as ragu_backend::Backend>::prepare_msm(
            &nested_generators.g()[..R::num_coeffs()],
        )
        .map(Arc::new);

        let mut app = Application {
            native_source: self.native_source,
            nested_source: self.nested_source,
            native_registry,
            nested_registry,
            params,
            num_application_steps: self.num_application_steps,
            output_headers: self.output_headers,
            stage_size: self.stage_size,
            bootstrap: self.bootstrap.map(|proof| *proof),
            host_committer: Committer::new::<R>(
                host_generators,
                self.commitment_tables,
                native_ipa_generators.as_ref(),
            ),
            nested_committer: Committer::new::<R>(
                nested_generators,
                self.commitment_tables,
                nested_ipa_generators.as_ref(),
            ),
            native_ipa_generators,
            nested_ipa_generators,
            context,
            _marker: PhantomData,
        };

        // Bootstrap the recursion once, up front, so that `seed` never pays
        // for it lazily, unless the application was given the proof. The proof
        // carries no secrets — it attests nothing and is consumed as a public
        // child by every seed — so a fixed seed is fine. The same build and
        // application configuration reproduce the proof, but `StdRng` may
        // vary across versions or platforms. A deployment needing common
        // bytes across compatible builds should share a stored proof rather
        // than assume regeneration matches.
        if app.bootstrap.is_none() {
            let mut rng = StdRng::seed_from_u64(0);
            let (pcd, ()) = app.fuse(
                &mut rng,
                crate::step::internal::bootstrap::Bootstrap::new(),
                (),
                app.dummy_pcd(),
                app.dummy_pcd(),
            )?;
            app.bootstrap = Some(pcd.into_parts().0);
        }

        Ok(app)
    }

    /// Registers an internal [`Step`] other than the bootstrap step.
    ///
    /// Internal steps do not go through `prevent_duplicate_suffixes`, so this
    /// is where the invariant that only
    /// [`Bootstrap`](crate::step::internal::bootstrap::Bootstrap) declares
    /// [`Dummy`](crate::header::Dummy) inputs is enforced: an internal step
    /// with `Dummy` inputs would take the base case, and if it also carried
    /// a data-bearing output it would let a prover attest arbitrary data without
    /// verifying its children. The check is evaluated at compile time for each
    /// step registered here.
    ///
    /// It covers *declared* (constant) suffixes only. An internal step whose
    /// input suffix is a witness wire — today only `Rerandomize`, via uniform
    /// encoding — must instead constrain that wire away from `Dummy`
    /// itself, and from zero; see `ProofInputs::is_dummy_input` and
    /// [`Encoded::new_uniform`](crate::step::Encoded::new_uniform).
    ///
    /// No explicit allowed-suffix set is needed: application steps encode
    /// suffixes as constants, [`Encoded::new_uniform`](crate::step::Encoded::new_uniform)
    /// excludes `Dummy` and zero, rerandomization preserves the input header,
    /// internal circuits end in a zero suffix that no application header can use, and
    /// only `Bootstrap` declares `Dummy` inputs. An internal step with a
    /// witnessed suffix must preserve these restrictions.
    fn register_internal_step<S: Step<C> + 'params>(mut self, step: S) -> Result<Self> {
        const {
            assert!(
                <S::Left as Header<C::CircuitField>>::SUFFIX.get()
                    != crate::header::Suffix::internal(2).get()
                    && <S::Right as Header<C::CircuitField>>::SUFFIX.get()
                        != crate::header::Suffix::internal(2).get(),
                "only the internal Bootstrap step may declare Dummy inputs"
            );
        }

        self.native_registry =
            self.native_registry.register_internal_step(
                Adapter::<C, S, R, HEADER_SIZE>::with_stage(step, self.stage_size)?,
            )?;

        Ok(self)
    }

    /// Rejects a header whose
    /// [`OnlinePolyCommit`](Header::OnlinePolyCommit) keeps the same kind
    /// in two slots: no step could name that kind.
    fn require_unique_kinds<H: Header<C::CircuitField>>() -> Result<()> {
        if <H::OnlinePolyCommit as crate::header::OnlinePolyCommit>::has_unique_kinds() {
            Ok(())
        } else {
            Err(Error::Initialization(
                "a Header cannot keep the same online polynomial kind in two slots".into(),
            ))
        }
    }

    fn prevent_duplicate_suffixes<H: Header<C::CircuitField>>(&mut self) -> Result<()> {
        if H::SUFFIX.get() < crate::header::NUM_INTERNAL_SUFFIXES as u64
            && TypeId::of::<H>() != TypeId::of::<()>()
        {
            return Err(Error::Initialization(
                "only the unit Header () may use a reserved internal suffix".into(),
            ));
        }

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
    C: ProfiledCycle,
    R: Rank,
    const HEADER_SIZE: usize,
    B: SelectableBackend = AcceleratedBackend,
> {
    pub(crate) native_registry: Registry<'params, C::CircuitField, R>,
    pub(crate) nested_registry: Registry<'params, C::ScalarField, R>,
    pub(crate) native_source:
        Option<crate::profile::online::SourceRegistry<'params, C::CircuitField>>,
    pub(crate) nested_source:
        Option<crate::profile::online::SourceRegistry<'params, C::ScalarField>>,
    pub(crate) params: &'params C::Params,
    pub(crate) num_application_steps: usize,
    /// The header type each registered step outputs, by suffix, and
    /// whether its proofs carry an online polynomial.
    pub(crate) output_headers: BTreeMap<crate::header::Suffix, (TypeId, bool)>,
    /// The application stage's size, in values.
    pub(crate) stage_size: usize,
    /// The profile's prover context: what its prover holds across proofs
    /// (see [`Profile::Context`]).
    pub(crate) context: <C::Profile as Profile>::Context<'params, C::Base, R, B>,
    /// The proof that bootstraps the recursion: a genuine, verifying
    /// `Pcd<()>` consumed as a child by every [`seed`](Self::seed).
    ///
    /// Always `Some` once [`ApplicationBuilder::finalize`] returns, which
    /// installs the proof given to [`ApplicationBuilder::with_bootstrap`] or
    /// builds it. It is `None` only while `finalize` is building it, since
    /// doing so runs [`fuse`](Self::fuse) on the otherwise complete
    /// `Application`.
    pub(crate) bootstrap: Option<Proof<C, R>>,
    /// Fixed IPA bases prepared once during application startup.
    pub(crate) native_ipa_generators: Option<Arc<PreparedMsm<C::HostCurve>>>,
    pub(crate) nested_ipa_generators: Option<Arc<PreparedMsm<C::NestedCurve>>>,
    host_committer: Committer<'params, C::HostCurve, C::HostGenerators, B>,
    nested_committer: Committer<'params, C::NestedCurve, C::NestedGenerators, B>,
    pub(crate) _marker: PhantomData<([(); HEADER_SIZE], B)>,
}

impl<'params, C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize, B: SelectableBackend>
    Application<'params, C, R, HEADER_SIZE, B>
{
    /// The profile's prover context, as given to
    /// [`finalize_with`](ApplicationBuilder::finalize_with): for an
    /// aggregator application, the `Decompression`
    /// holding the wallet application it aggregates.
    pub fn context(&self) -> &<C::Profile as Profile>::Context<'params, C::Base, R, B> {
        &self.context
    }

    /// The header type each registered step outputs, by suffix, and
    /// whether its proofs carry an online polynomial: the headers the
    /// application's statements carry.
    pub(crate) fn output_headers(&self) -> &BTreeMap<crate::header::Suffix, (TypeId, bool)> {
        &self.output_headers
    }

    /// Seed a new computation by running a [`Step`] declaring `()` for both of
    /// its inputs.
    ///
    /// This is the entry point for creating leaf nodes in a PCD tree. The step
    /// is fused against the bootstrap proof that
    /// [`ApplicationBuilder::finalize`] built or installed as both children, so
    /// this is an ordinary fuse whose child claims are enforced, not a base
    /// case.
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

    /// Returns the proof that bootstraps the recursion.
    ///
    /// [`ApplicationBuilder::finalize`] builds it once, unless it was given one
    /// with [`ApplicationBuilder::with_bootstrap`]: two synthesized dummy
    /// proofs, which cannot verify on their own, are fused through the
    /// internal bootstrap step, the only step whose inputs are dummies and
    /// hence the only fuse treated as the base case. The result verifies, so
    /// [`seed`](Self::seed) consumes it as an ordinary child. It attests
    /// nothing, and its own witness is empty: the bootstrap step skips its
    /// children's claims and outputs the data-less unit header.
    ///
    /// The default proof depends on the application's configuration: its
    /// registries and public parameters, its profile, rank and header size,
    /// the circuits of the Ragu version in use, the `StdRng` implementation,
    /// and for a profile with an extension the prover context at finalization.
    /// Store it with [`Proof::to_bytes`] and supply it to later applications
    /// of the same configuration with [`ApplicationBuilder::with_bootstrap`],
    /// so their finalization skips the bootstrap fuse.
    ///
    /// Like every uncompressed proof, this one is not zero-knowledge: for a
    /// profile with an extension it holds the extension's polynomials,
    /// computed over the prover context at finalization. Store or ship it
    /// only if that context holds nothing confidential. The built-in
    /// profiles' bootstrap proofs reveal nothing: the standard profile has
    /// no extension, and the aggregator's computes over the wallet
    /// application's bootstrap proof, which attests nothing.
    pub fn bootstrap_proof(&self) -> &Proof<C, R> {
        self.bootstrap
            .as_ref()
            .expect("finalize always sets the bootstrap proof")
    }

    /// The bootstrap proof as the `Pcd<()>` that [`seed`](Self::seed) and
    /// rerandomization consume; see [`bootstrap_proof`](Self::bootstrap_proof).
    pub(crate) fn bootstrap_pcd(&self) -> Pcd<C, R, ()> {
        self.bootstrap_proof().clone().carry(())
    }

    /// Rerandomize a proof while preserving its certified data and online
    /// polynomials. With a valid bootstrap proof,
    /// `Application::verify_uncompressed` gives the same result for `pcd`
    /// and for any returned proof.
    ///
    /// # Public application data
    ///
    /// The encoded header comes from [`Header::Data`] and is separate from
    /// the proof's online polynomial slots. A full rerandomized proof exposes
    /// the input's online polynomial coefficients through [`Pcd::polynomials`].
    /// [`compress`](Self::compress) publishes their unchanged deterministic
    /// commitments through [`CompressedPcd::online_commitments`](crate::CompressedPcd::online_commitments). A recipient
    /// can compare them with commitments to candidate polynomials or from
    /// the original proof.
    ///
    /// See [Publishing Proofs][publication].
    ///
    /// [publication]: https://tachyon.z.cash/ragu/guide/writing_circuits.html#publishing-proofs
    ///
    /// # Hiding scope
    ///
    /// For the standard profile, fix the application, setup and bootstrap
    /// proof. The goal is for fresh rerandomizations of valid inputs with the
    /// same encoded header and online polynomials to be indistinguishable,
    /// even to the party who selected the inputs. Joint hiding of the output
    /// fields remains unproved. Other profiles carry additional proof state.
    ///
    /// # How
    ///
    /// The input is fused twice through the internal rerandomization step,
    /// each time with the application's bootstrap proof as the right child.
    /// A fuse stores what it reads of its children as stage values, so one
    /// pass would show the input's commitments in the clear. After the
    /// second pass the output holds the first pass's commitments, which are
    /// fresh, and values computed from the first pass's polynomials. The
    /// construction uses free coefficients (see [`Blind`](ragu_circuits::Blind))
    /// and the randomizers each fuse folds and batches to mask those values.
    /// The internal `fuse::randomizer` module describes the masking argument.
    ///
    /// # Bootstrap linkability
    ///
    /// The default bootstrap is generated with a fixed seed, so the same build
    /// and application configuration reproduce the proof. `StdRng` may vary
    /// across versions or platforms, and [`ApplicationBuilder::with_bootstrap`]
    /// can install a different valid proof. The full uncompressed output's
    /// bridge preamble contains the right child's commitments. The compressed
    /// instance retains that child's native and nested `x` and `y` challenges.
    /// A wallet-specific bootstrap can therefore link outputs in either form,
    /// and a version-specific bootstrap can identify a cohort. See
    /// [`ApplicationBuilder::with_bootstrap`] for the shared-proof guidance
    /// and the open provisioning TODO.
    ///
    /// # What the caller must ensure
    ///
    /// - `pcd` verifies. For a proof that does not, this returns an error
    ///   or yields a proof that also fails verification. A receiver accepts a
    ///   proof as described in the [crate documentation](crate) before it
    ///   rerandomizes it.
    /// - The application's bootstrap proof verifies. The one that
    ///   [`ApplicationBuilder::finalize`] builds does. One supplied with
    ///   [`ApplicationBuilder::with_bootstrap`] is not checked for validity,
    ///   and if it does not verify, this returns an error or yields a proof
    ///   that also fails verification.
    /// - `rng` is a cryptographically secure source that the producer of
    ///   `pcd` cannot predict.
    pub fn rerandomize<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<Pcd<C, R, H>> {
        // The step returns the left input's data as its output's, so the
        // header and its data pass through both fuses unchanged.
        let (once, ()) = self.fuse(
            rng,
            crate::step::internal::rerandomize::Rerandomize::new(),
            (),
            pcd,
            self.bootstrap_pcd(),
        )?;
        self.fuse(
            rng,
            crate::step::internal::rerandomize::Rerandomize::new(),
            (),
            once,
            self.bootstrap_pcd(),
        )
        .map(|(pcd, ())| pcd)
    }

    /// Computes $H^{bridge}(P)$ from the zero-alpha stage polynomial the
    /// honest prover constructs for `point`. When `point` is the step's own last
    /// online commitment, this is the honest prover's value of
    /// [`Oracles::bridge_hash`](crate::step::Oracles::bridge_hash). An application
    /// that hashes a polynomial commitment, for instance into an anchor it
    /// also recomputes outside the circuit, calls this.
    ///
    /// It is the commitment of the stage holding `point`'s coordinates
    /// alone, so it depends on the rank and the nested generators; binding
    /// rests on the commitment's.
    ///
    /// An accepted bridge digest binds the point but need not use this
    /// canonical zero-alpha encoding or be fixed before the step's challenge.
    /// Anchor applications must compare natively recomputed advancement
    /// against canonical-chain anchors.
    ///
    /// # Errors
    ///
    /// Fails if `point` is the identity, which the stage cannot hold.
    pub fn bridge_hash(&self, point: C::HostCurve) -> Result<C::NestedCurve> {
        crate::bridge_hash::digest::<B, _, _, R, _>(point, C::nested_generators(self.params))
    }

    /// The commitment of an online polynomial with coefficients `coeffs`, in
    /// ascending degree. When [`Step::prepare`] prepares these coefficients,
    /// Ragu stores exactly this commitment in the output proof's slot.
    /// An application that recomputes a commitment outside the circuit, for
    /// instance to recompute a [`bridge_hash`](Self::bridge_hash), calls this.
    ///
    /// # Errors
    ///
    /// Fails if the polynomial has more coefficients than the rank holds.
    pub fn commit(&self, coeffs: &[C::CircuitField]) -> Result<C::HostCurve> {
        if coeffs.len() > R::num_coeffs() {
            return Err(Error::InvalidWitness(
                "a polynomial has more coefficients than the rank holds".into(),
            ));
        }
        let poly =
            ragu_circuits::polynomials::sparse::Polynomial::<_, R>::from_coeffs(coeffs.to_vec());
        Ok(self.host().commit(&poly))
    }

    /// What the prover commits to host-curve polynomials with.
    pub(crate) fn host(&self) -> &Committer<'params, C::HostCurve, C::HostGenerators, B> {
        &self.host_committer
    }

    /// What the prover commits to nested-curve polynomials with.
    pub(crate) fn nested(&self) -> &Committer<'params, C::NestedCurve, C::NestedGenerators, B> {
        &self.nested_committer
    }

    /// The native source registry the profile's mesh certifies: the builder's
    /// or the profile context's, whichever supplied it at setup (see
    /// [`Profile::source_registries`]).
    pub(crate) fn native_source(
        &self,
    ) -> Option<crate::profile::online::SourceRegistry<'_, C::CircuitField>> {
        self.native_source
            .clone()
            .or_else(|| C::Profile::source_registries::<C::Base, R, B>(&self.context).0)
    }

    /// The nested source registry, as [`native_source`](Self::native_source).
    pub(crate) fn nested_source(
        &self,
    ) -> Option<crate::profile::online::SourceRegistry<'_, C::ScalarField>> {
        self.nested_source
            .clone()
            .or_else(|| C::Profile::source_registries::<C::Base, R, B>(&self.context).1)
    }

    /// Returns a reference to the nested [`Registry`].
    pub fn nested_registry(&self) -> &Registry<'_, C::ScalarField, R> {
        &self.nested_registry
    }

    /// Returns a reference to the native [`Registry`].
    pub fn native_registry(&self) -> &Registry<'_, C::CircuitField, R> {
        &self.native_registry
    }
}
