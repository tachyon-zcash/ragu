//! Proof profiles.
//!
//! A profile is the set of internal circuits a proof carries beyond the
//! fuse's own, with the points an endoscaling step folds, and so the shape
//! of the proof: how many polynomials it holds and how long the two
//! endoscaling walks over them run. Every proof an
//! application makes has its profile's shape, and a proof is verified against
//! the registry it was made for, so the profile is fixed per application.
//!
//! Two profiles are foreseen. Wallets prove in [`Standard`]: the fuse alone,
//! compressed to a few kilobytes and sent over the network. Aggregators prove
//! in `Aggregator`: the fuse plus the circuits that verify a standard
//! compressed proof in circuit. A wallet's proof then enters an aggregator's
//! fuse as witness data rather than as a child, so the two shapes never have
//! to agree, and only the aggregator's proofs carry the extra polynomials.
//! The aggregator's circuits verify proofs of the standard profile, so the
//! aggregator depends on it. The standard profile knows nothing of the
//! aggregator but where its compression commits the transcript's runs: at
//! the generators the runs' stages take at the aggregator rank, which the
//! Standard tables carry (`pasta::STAGE_REACH`), so the run layout is part
//! of the standard profile's wire format (see `compress::runs`).
//!
//! A cycle names its profile through [`ProfiledCycle`], so every generic item
//! in this crate reaches the shape through the cycle it already carries, and
//! a wallet proof and an aggregator proof over the same curves are different
//! types. `Pasta` proves in the standard profile; [`Profiled`] puts a cycle
//! under any other profile, keeping its curves, generators and Poseidon
//! instances. The native and nested internal modules size their walks, index
//! lists and value containers from the profile's [`Shape`], so one binary
//! holds every profile's layout. The standard profile's layout is also the
//! internal modules' constant one, pinned to its shape at compile time.
//!
//! A profile declares what it adds as an [`Extension`] per side, circuits
//! with the stages they load, registers them through its hooks, and fills
//! their polynomials for every proof through its prover hooks, over the
//! [`Context`](Profile::Context) the application holds. The internal
//! modules place the circuits after the fuse's endoscaling steps and the
//! masks after the fuse's masks, fold a circuit's claim as a step's,
//! and the proof carries the polynomials. An extension may name a
//! statement circuit, whose claim binds an internal step's output header
//! to what the extension verified, and a binding circuit, whose claim
//! binds its side's view of the other side's stages to their commitments.
//! A profile may prove a circuit of its extension in pages, as it may the
//! fuse's ([`paging::ExtensionPages`]): the extension declares each page as
//! a circuit, and a registry build asks the profile for the pages once,
//! cut and held to the unpaged circuit, and registers each at its circuit.
//! `Aggregator` declares the decompression circuits, at the rank with
//! the room for them.
//!
//! Profile authors must review and test agreement between their
//! declarations, registered stages and masks, and the intended circuit relation.
//!
//! The verifier fixes its profile, registries and public parameters at setup.
//! Each registry's tag is derived from the circuits it holds, so profiles that
//! register different circuits have different tags.

pub mod online;
pub mod paging;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    any::{TypeId, type_name},
    fmt,
    marker::PhantomData,
    ops::Range,
};

use ragu_circuits::{
    Circuit, WithAux,
    paging::Planned,
    polynomials::{Rank, sparse},
    registry::{Registry, RegistryBuilder},
    staging::{MultiStage, MultiStageCircuit, Stage, StageExt},
};
// Without `baked` the module docs are its only use.
#[cfg_attr(not(feature = "baked"), allow(unused_imports))]
use ragu_core::pasta::Pasta;
use ragu_core::{
    Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
};
use ragu_primitives::{Element, WithSuffix};
use rand::CryptoRng;
use udon::field::Field;

pub use crate::decompress::{
    aggregator::{Aggregator, Counts},
    prover::{Decompressed, Decompression},
};
use crate::{
    SelectableBackend,
    header::Suffix,
    internal::{endoscalar, native, nested},
    ipa::IpaCycle,
};

/// What a profile pins for one of the fuse's internal circuits, as an
/// unpaged circuit: the pages it is cut into and the values its carry
/// stage holds.
///
/// Each page loads every stage the circuit reserves, then the carry stage,
/// through which the pages pass values to one another. Both numbers size
/// the proof and its polynomials, and the circuits a profile pages work on
/// every polynomial of a proof, the pages' among them, so a profile states
/// them and no circuit is cut otherwise: a circuit that takes more pages,
/// or carries more values, is refused where it is registered. Where the
/// cuts fall is not pinned: the pager chooses that. What a circuit takes is
/// found by a census pass, which cuts it: the `paging` census, with the
/// crate's `test-utils` feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageCount {
    pages: usize,
    /// The values the carry stage holds.
    carry: usize,
}

impl PageCount {
    /// The circuit whole.
    pub const WHOLE: Self = PageCount::new(1);

    /// `pages` pages, over a carry stage that holds nothing yet
    /// ([`carrying`](Self::carrying)).
    ///
    /// # Panics
    ///
    /// Panics if `pages` is zero: a circuit takes a page. In a profile's
    /// constant, that is a compile error.
    pub const fn new(pages: usize) -> Self {
        assert!(pages >= 1, "a circuit takes at least one page");
        PageCount { pages, carry: 0 }
    }

    /// The same pages, over a carry stage of `values` values.
    ///
    /// # Panics
    ///
    /// Panics if the circuit is whole and `values` is not zero: a circuit
    /// in one page has no carry stage.
    pub const fn carrying(mut self, values: usize) -> Self {
        assert!(
            self.pages > 1 || values == 0,
            "a circuit in one page has no carry stage"
        );
        self.carry = values;
        self
    }

    /// The pages.
    pub const fn num_pages(&self) -> usize {
        self.pages
    }

    /// The values the carry stage holds.
    pub const fn carry(&self) -> usize {
        self.carry
    }
}

/// The [`PageCount`] a profile pins for each of the fuse's internal
/// circuits.
///
/// A circuit with more than one page is cut into that many circuits, which
/// pass values to one another through a carry stage of the size its count
/// states (see [`ragu_circuits::paging`]). Every page loads every stage its
/// circuit reserves. The profile says how many pages; the pager chooses
/// where the cuts fall: where the fewest values pass from page to page,
/// among the places that leave every page room past the stages. The pages
/// before the last are registered as circuits of the profile's extension
/// and the carry stage as one of its stages, after what the profile
/// declares; the last page takes the circuit's own slot. The counts are
/// declared because they size the proof; the registration fails if the
/// pages do not have the room.
///
/// A walk's steps all have one count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageCounts {
    /// The native `hashes_1` circuit's.
    pub hashes_1: PageCount,
    /// The native `hashes_2` circuit's.
    pub hashes_2: PageCount,
    /// The native `collapse` circuit's.
    pub collapse: PageCount,
    /// The native `compute_v` circuit's.
    pub compute_v: PageCount,
    /// Each native `bind_challenges` circuit's.
    pub bind_challenges: PageCount,
    /// The native `bind_beta` circuit's.
    pub bind_beta: PageCount,
    /// The native `bind_endoscalar` circuit's.
    pub bind_endoscalar: PageCount,
    /// The nested `collapse` circuit's.
    pub nested_collapse: PageCount,
    /// The nested `compute_v` circuit's.
    pub nested_compute_v: PageCount,
    /// Each step's of the native walk.
    pub endoscaling_step: PageCount,
    /// Each step's of the nested walk.
    pub nested_endoscaling_step: PageCount,
}

impl PageCounts {
    /// Every circuit whole.
    pub const WHOLE: Self = PageCounts::uniform(PageCount::WHOLE);

    /// Every circuit cut as `cut` says, with the walks' steps whole.
    pub const fn uniform(cut: PageCount) -> Self {
        PageCounts {
            hashes_1: cut,
            hashes_2: cut,
            collapse: cut,
            compute_v: cut,
            bind_challenges: cut,
            bind_beta: cut,
            bind_endoscalar: cut,
            nested_collapse: cut,
            nested_compute_v: cut,
            endoscaling_step: PageCount::WHOLE,
            nested_endoscaling_step: PageCount::WHOLE,
        }
    }
}

/// The internal circuits a proof carries beyond the fuse's own: an
/// [`Extension`] on each side of the cycle, and the rx polynomials it adds
/// as constants, which size the proof's shape at compile time.
///
/// The constants must equal the extensions' [`rx`](Extension::rx) counts,
/// and each extension must be well formed
/// ([`is_consistent`](Extension::is_consistent)); [`check`](Self::check)
/// says so and the registration asserts it. The hooks must register what
/// the declaration says: circuit `k` loading exactly the stages
/// [`Extension::circuits`] lists for it, then each stage's mask, then each
/// final mask as the final mask of its circuits' last stage. Each hook
/// fills the slot it is given, a [`CircuitSlot`] or a [`MaskSlot`],
/// which takes one entry of its kind and nothing else, and the circuit
/// slot ends the circuit's public output with a zero, as the fuse's
/// circuits end theirs (see [`CircuitSlot::register`]). Stage loading and
/// stage/final-mask agreement with the declaration are not checked
/// automatically; a profile must pin this agreement in its tests.
///
/// The extension declarations must return the same layout for a given profile
/// type. Use distinct profile types for distinct layouts; the prover context
/// supplies witness data within that fixed layout.
///
/// The registered circuits must enforce the intended relation: a statement
/// circuit must expose the statement it verified, and a binding circuit must
/// recompute the declared commitments from the values its extension actually
/// uses. These circuit semantics are part of the verifier's trusted setup.
/// Prover hooks and the polynomials they return are untrusted witnesses.
///
/// A statement circuit exposes the inner proof's padded output header,
/// suffix included, and the suffix is what selects which of the
/// application's header types a decompressed statement is taken as. The
/// application must register, at every suffix a decompressed header can
/// carry, a header type with the inner application's encoding and meaning.
/// Nothing checks that agreement; it is part of the verifier's trusted setup.
///
/// A profile is part of an application's setup, and each of its registries
/// derives its [`Tag`](ragu_circuits::registry::Tag) from the circuits it
/// holds. Two profiles whose registries hold different circuits therefore
/// have different tags, and the verifiers tell their proofs apart by them;
/// two whose registries hold the same circuits are the same proof system.
pub trait Profile: Copy + Default + Eq + fmt::Debug + Send + Sync + 'static {
    /// The profile's name, which identifies it in diagnostics. It is not bound
    /// into the registry tags: profiles are told apart by the circuits they
    /// register. It must be distinct across the profiles over a cycle:
    /// [`check`](Self::check) refuses an empty name, and a built-in profile's
    /// name on any other profile.
    const NAME: &'static str;

    /// Whether this is one of the crate's own profiles, which carry the
    /// built-in names [`check`](Self::check) refuses on any other profile.
    /// [`BuiltIn`] has no public constructor and names the type it was made
    /// for, which `check` compares with the profile's own: a profile that
    /// copies a built-in profile's token carries that profile's type, and
    /// is still refused the built-in names.
    #[doc(hidden)]
    const BUILT_IN: Option<BuiltIn> = None;

    /// The native rx polynomials the profile adds: its native extension's.
    const NATIVE_EXTENSION: usize;
    /// The nested rx polynomials the profile adds: its nested extension's.
    const NESTED_EXTENSION: usize;

    /// Native online polynomial and opening declarations. The application
    /// slots are separate from this layout.
    ///
    /// Commitments follow their declared initial or auxiliary phases.
    const NATIVE_ONLINE: online::Layout = online::Layout::EMPTY;

    /// Nested online polynomial and opening declarations, independent of
    /// the native layout.
    ///
    /// Commitments follow their declared initial or auxiliary phases.
    const NESTED_ONLINE: online::Layout = online::Layout::EMPTY;

    /// A setup-fixed native source-registry mesh over declared online slots.
    /// Both inherited obligations are carried by every ordinary step.
    const NATIVE_MESH: Option<online::mesh::Mesh> = None;

    /// Nested counterpart of [`Self::NATIVE_MESH`].
    const NESTED_MESH: Option<online::mesh::Mesh> = None;

    /// Native online inputs the batch helper holds to the source
    /// registry's domain: each names a wire of the input stage whose value
    /// must be one of the points the source registry interpolates its
    /// circuits over. A restriction opened at such an input is then one
    /// circuit's wiring polynomial, not a combination of several. Needs
    /// [`Self::NATIVE_MESH`], whose source fixes the domain.
    const NATIVE_DOMAIN_INPUTS: &'static [usize] = &[];

    /// Nested counterpart of [`Self::NATIVE_DOMAIN_INPUTS`].
    const NESTED_DOMAIN_INPUTS: &'static [usize] = &[];

    /// Native extension circuits that reserve the online input and query
    /// stages before their own stages, indexed in `native_extension`.
    /// A consumer's first own stage must have `online::stages::QueryStage`
    /// as its parent. Circuits with no own stage end at that query stage.
    const NATIVE_ONLINE_CONSUMERS: &'static [u32] = &[];

    /// Nested counterpart of [`Self::NATIVE_ONLINE_CONSUMERS`].
    const NESTED_ONLINE_CONSUMERS: &'static [u32] = &[];

    /// The endoscalings a native endoscaling step performs: what fits a
    /// step beside the stages it reserves at the profile's rank. The walk
    /// over the nested batch takes a step per so many points, so more per
    /// step is fewer steps and fewer polynomials, and the other side's walk
    /// shortens with them. The standard profile's is the wallet rank's.
    /// Both endoscaling counts must be nonzero, and their product must
    /// exceed four times the polynomials a native step takes times those a
    /// nested step takes (one each, and one more for each page and for the
    /// carry stage of a paged step), so the mutually dependent walk sizes
    /// can converge. [`check`](Self::check) refuses a profile that does not
    /// meet this. A product only just past that bound converges slowly:
    /// the shape's solver gives up after 256 passes and panics
    /// ([`Shape::solve`]).
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = native::ENDOSCALINGS_PER_STEP;
    /// The endoscalings a nested endoscaling step performs, likewise.
    const NESTED_ENDOSCALINGS_PER_STEP: usize = nested::ENDOSCALINGS_PER_STEP;

    /// The pages the profile cuts each of the fuse's internal circuits
    /// into (see [`PageCounts`]). The default leaves every circuit whole.
    const PAGE_COUNTS: PageCounts = PageCounts::WHOLE;

    /// What the profile's prover holds across proofs beyond the proof
    /// under construction: the extension's witness source, which an
    /// application takes at
    /// [`finalize_with`](crate::ApplicationBuilder::finalize_with). Nothing
    /// for a profile without an extension.
    type Context<'params, Base, R, B>: ProverContext
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    /// Checks the prover context an application takes at
    /// [`finalize_with`](crate::ApplicationBuilder::finalize_with) against
    /// the application: `params` are the parameters it finalizes over and
    /// `headers` maps each suffix it registers to the header type
    /// registered at it. The default accepts any context.
    ///
    /// # Errors
    ///
    /// Fails if the context does not fit the application.
    fn check_context<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        params: &Base::Params,
        headers: &BTreeMap<Suffix, TypeId>,
    ) -> Result<()>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, params, headers);
        Ok(())
    }

    /// The source registries the profile's meshes certify, the native then
    /// the nested, for a profile whose prover context holds them. A builder
    /// may supply a source only for a field this hook leaves empty
    /// ([`with_source_registries`](crate::ApplicationBuilder::with_source_registries)).
    /// Setup fixes the sources' tags in the helper circuits. This hook is
    /// also called during proving and verification, so it must return the
    /// same `Some` or `None` choices and the same registries throughout the
    /// application's lifetime, including when the context contains interior
    /// mutable state.
    ///
    /// The default holds none.
    fn source_registries<'a, 'params: 'a, Base, R, B>(
        context: &'a Self::Context<'params, Base, R, B>,
    ) -> (
        Option<online::SourceRegistry<'a, Base::CircuitField>>,
        Option<online::SourceRegistry<'a, Base::ScalarField>>,
    )
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = context;
        (None, None)
    }

    /// The circuits and stages the profile adds on the native side.
    ///
    /// The challenge binders load a native extension's stages, and at the
    /// wallet rank their largest variant fills the
    /// gate budget with the census header: an extension stage costing more
    /// needs a smaller header or a cheaper binder. The internal census tests
    /// pin that count.
    fn native_extension() -> Extension {
        Extension::EMPTY
    }

    /// The circuits and stages the profile adds on the nested side.
    fn nested_extension() -> Extension {
        Extension::EMPTY
    }

    /// Registers circuit `circuit` of the native extension into `slot`, an
    /// internal circuit over the base cycle the profile extends (see
    /// [`ProfiledCycle::Base`]): the extension's circuits verify proofs in
    /// the standard profile over the same curves.
    ///
    /// # Errors
    ///
    /// The default declares no circuit and fails.
    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (circuit, slot, params);
        Err(Error::Initialization(
            "the profile's native extension has no circuits".into(),
        ))
    }

    /// Registers mask `mask` of the native extension, a stage mask or a
    /// final mask in [`Extension::masks`] order, into `slot`.
    ///
    /// # Errors
    ///
    /// The default declares no mask and fails.
    fn register_native_mask<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        mask: usize,
        slot: MaskSlot<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (mask, slot, params);
        Err(Error::Initialization(
            "the profile's native extension has no masks".into(),
        ))
    }

    /// The nested counterpart of
    /// [`register_native_circuit`](Self::register_native_circuit).
    ///
    /// # Errors
    ///
    /// The default declares no circuit and fails.
    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (circuit, slot, params);
        Err(Error::Initialization(
            "the profile's nested extension has no circuits".into(),
        ))
    }

    /// The nested counterpart of
    /// [`register_native_mask`](Self::register_native_mask).
    ///
    /// # Errors
    ///
    /// The default declares no mask and fails.
    fn register_nested_mask<'params, Base, R: Rank>(
        mask: usize,
        slot: MaskSlot<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (mask, slot, params);
        Err(Error::Initialization(
            "the profile's nested extension has no masks".into(),
        ))
    }

    /// The native extension's circuits that the profile proves in pages
    /// (see [`ragu_circuits::paging`]): each cut into the pages the profile
    /// pins for it and held to the unpaged circuit
    /// ([`paging::ExtensionPages`]). A registry build asks for them once,
    /// before it registers a circuit, and then registers each page at the
    /// extension circuit the profile declares for it, in place of
    /// [`register_native_circuit`](Self::register_native_circuit). The
    /// extension declares each page as a circuit that loads the unpaged
    /// circuit's stages and then its carry stage, and the carry stage's
    /// final mask over the pages.
    ///
    /// # Errors
    ///
    /// Fails if a circuit does not cut into the pages pinned, or if its
    /// pages are not the unpaged circuit's. The default pages nothing.
    fn native_extension_pages<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        params: &'params Base::Params,
    ) -> Result<Vec<paging::ExtensionPages<'params, Base::CircuitField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = params;
        Ok(Vec::new())
    }

    /// The nested counterpart of
    /// [`native_extension_pages`](Self::native_extension_pages).
    ///
    /// # Errors
    ///
    /// As [`native_extension_pages`](Self::native_extension_pages).
    fn nested_extension_pages<'params, Base, R: Rank>(
        params: &'params Base::Params,
    ) -> Result<Vec<paging::ExtensionPages<'params, Base::ScalarField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = params;
        Ok(Vec::new())
    }

    /// The native extension's polynomials for one proof: each circuit's,
    /// assembled against `registry` at the circuit's index in the layout,
    /// then each stage's, with an alpha from `rng`, over `source`, the proof
    /// the step decompresses, or over the context's canonical proof without.
    /// `online_openings` is the point and value at which the step opened
    /// each online slot, the left input's, the right input's, then its
    /// own output's, for an extension whose statement circuit exposes
    /// some.
    ///
    /// # Errors
    ///
    /// The default fills an empty extension and fails for any other.
    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
        online_openings: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, source, online_openings, registry, rng);
        if Self::native_extension().is_empty() {
            Ok(ExtensionRxs::default())
        } else {
            Err(Error::Initialization(NO_NATIVE_EXTENSION_PROVER.into()))
        }
    }

    /// The nested counterpart of
    /// [`native_extension_rxs`](Self::native_extension_rxs), with
    /// `output_commitments` the commitments of the step's own output
    /// slots, for an extension whose binding circuit exposes one (see
    /// [`Binding::online`]).
    ///
    /// # Errors
    ///
    /// The default fills an empty extension and fails for any other.
    fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
        output_commitments: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, source, output_commitments, registry, rng);
        if Self::nested_extension().is_empty() {
            Ok(ExtensionRxs::default())
        } else {
            Err(Error::Initialization(NO_NESTED_EXTENSION_PROVER.into()))
        }
    }

    /// Supplies this step's native online inputs before any fuse challenge,
    /// for the proof its extension runs over in this step: `source`'s, the
    /// proof the step decompresses, or the context's canonical proof without.
    ///
    /// The returned values are committed once in `online::stages::InputStage`.
    /// Consumers must use those stage wires for data that defines a random test.
    ///
    /// # Errors
    ///
    /// The default supplies only inherited mesh coordinates. Other input
    /// slots require this hook to supply the full input vector.
    fn native_online_inputs<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
    ) -> Result<Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, source);
        online::defaults::inputs::<Self, online::stages::Native, _>()
    }

    /// Supplies native online polynomials at one commitment deadline, for
    /// the proof the profile's extension runs over in this step, as
    /// [`native_online_inputs`](Self::native_online_inputs) does: `source`'s,
    /// or the context's canonical proof without.
    ///
    /// Return only the slots declared for `phase` that are not owned by the
    /// source mesh, in declaration order. The protocol prepares mesh slots.
    /// `inputs` are the immutable pre-w values; `challenges` contains only
    /// challenges sampled before this phase. Prover hooks supply witnesses;
    /// the transcript and registered consumers enforce the relation.
    ///
    /// # Errors
    ///
    /// The default handles empty phases and rejects a phase needing polynomials.
    fn native_online_polynomials<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
        phase: online::Phase,
        inputs: &[Base::CircuitField],
        challenges: online::PreparationChallenges<Base::CircuitField>,
    ) -> Result<Vec<sparse::Polynomial<Base::CircuitField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, source, inputs, challenges);
        online::defaults::polynomials::<Self, online::stages::Native, _>(phase)
    }

    /// Supplies the native witness query points after x and before alpha.
    ///
    /// These fill only `Point::Witness` slots. Input, challenge and setup-fixed
    /// points are resolved by the protocol; consumers constrain arbitrary
    /// witness points to their intended values using the shared query stage.
    ///
    /// # Errors
    ///
    /// The default supplies no points and rejects a nonempty declaration.
    fn native_online_points<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        inputs: &[Base::CircuitField],
        challenges: online::PreparationChallenges<Base::CircuitField>,
    ) -> Result<Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, inputs, challenges);
        online::defaults::points::<Self, online::stages::Native, _>()
    }

    /// Traces the user extension with the online batch's immutable stage
    /// data, beside what [`Self::native_extension_rxs`] takes.
    ///
    /// Consumer circuits reserve the declared online prefix. Their witnesses
    /// must use `online`'s input and query values, including the opposite
    /// field's pre-w polynomial commitment coordinates. The protocol supplies
    /// the helper trace and online stage polynomials separately.
    ///
    /// `pages` are the pages of the extension's paged circuits, as the
    /// registry build cut them, in the order
    /// [`native_extension_pages`](Self::native_extension_pages) gave them: a
    /// prover that traces the pages by them cuts nothing again.
    ///
    /// # Errors
    ///
    /// The default delegates to [`Self::native_extension_rxs`].
    fn native_extension_rxs_with_online<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
        online_openings: &[[Base::CircuitField; 2]; 3 * crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::CircuitField, R>,
        online: Option<
            &online::circuit::Witness<'_, Base::CircuitField, Self, online::stages::Native>,
        >,
        pages: &[Planned<Base::CircuitField>],
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (online, pages);
        Self::native_extension_rxs::<Base, R, HEADER_SIZE, B, RNG>(
            context,
            source,
            online_openings,
            registry,
            rng,
        )
    }

    /// Supplies this step's nested online inputs before any fuse challenge,
    /// as [`native_online_inputs`](Self::native_online_inputs) does the
    /// native ones.
    ///
    /// The returned values are committed once in `online::stages::InputStage`.
    /// Consumers must use those stage wires for data that defines a random test.
    ///
    /// # Errors
    ///
    /// The default supplies only inherited mesh coordinates. Other input
    /// slots require this hook to supply the full input vector.
    fn nested_online_inputs<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, source);
        online::defaults::inputs::<Self, online::stages::Nested, _>()
    }

    /// Supplies nested online polynomials at one commitment deadline, for
    /// the proof the profile's extension runs over in this step, as
    /// [`nested_online_inputs`](Self::nested_online_inputs) does: `source`'s,
    /// or the context's canonical proof without.
    ///
    /// Return only the slots declared for `phase` that are not owned by the
    /// source mesh, in declaration order. The protocol prepares mesh slots.
    /// `inputs` are the immutable pre-w values; `challenges` contains only
    /// challenges sampled before this phase. Prover hooks supply witnesses;
    /// the transcript and registered consumers enforce the relation.
    ///
    /// # Errors
    ///
    /// The default handles empty phases and rejects a phase needing polynomials.
    fn nested_online_polynomials<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
        phase: online::Phase,
        inputs: &[Base::ScalarField],
        challenges: online::PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<sparse::Polynomial<Base::ScalarField, R>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, source, inputs, challenges);
        online::defaults::polynomials::<Self, online::stages::Nested, _>(phase)
    }

    /// Supplies the nested witness query points after x and before alpha.
    ///
    /// These fill only `Point::Witness` slots. Input, challenge and setup-fixed
    /// points are resolved by the protocol; consumers constrain arbitrary
    /// witness points to their intended values using the shared query stage.
    ///
    /// # Errors
    ///
    /// The default supplies no points and rejects a nonempty declaration.
    fn nested_online_points<'params, Base, R, B>(
        context: &Self::Context<'params, Base, R, B>,
        inputs: &[Base::ScalarField],
        challenges: online::PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
    {
        let _ = (context, inputs, challenges);
        online::defaults::points::<Self, online::stages::Nested, _>()
    }

    /// Traces the user extension with the online batch's immutable stage
    /// data and the commitments of the native profile batch, beside what
    /// [`Self::nested_extension_rxs`] takes.
    ///
    /// Consumer circuits reserve the declared online prefix. Their witnesses
    /// must use `online`'s input and query values, including the opposite
    /// field's pre-w polynomial commitment coordinates. The protocol supplies
    /// the helper trace and online stage polynomials separately.
    ///
    /// `pages` are the pages of the extension's paged circuits, as in
    /// [`native_extension_rxs_with_online`](Self::native_extension_rxs_with_online).
    ///
    /// # Errors
    ///
    /// The default delegates to [`Self::nested_extension_rxs`].
    #[allow(clippy::too_many_arguments)]
    fn nested_extension_rxs_with_online<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&<Self::Context<'params, Base, R, B> as ProverContext>::Source>,
        output_commitments: &[Base::HostCurve; crate::header::NUM_ONLINE_FP_POLYS],
        registry: &Registry<'params, Base::ScalarField, R>,
        online: Option<
            &online::circuit::Witness<'_, Base::ScalarField, Self, online::stages::Nested>,
        >,
        native_online_commitments: &[Base::HostCurve],
        pages: &[Planned<Base::ScalarField>],
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (online, native_online_commitments, pages);
        Self::nested_extension_rxs::<Base, R, HEADER_SIZE, B, RNG>(
            context,
            source,
            output_commitments,
            registry,
            rng,
        )
    }

    /// Checks that the constants agree with the extensions and that the
    /// extensions are well formed, and that the endoscaling counts allow
    /// the walk sizes to converge.
    ///
    /// # Errors
    ///
    /// Fails if the [name](Self::NAME) is empty or a built-in profile's on
    /// another profile; if an extension's rx count differs from its
    /// constant, so that a profile declaring one without the other does not
    /// lay out a proof; if either extension is not
    /// [consistent](Extension::is_consistent); if the nested extension names
    /// a statement circuit, which only the native side carries; if an
    /// extension's binding names a stage, an output header slot or a batch
    /// polynomial the step does not have; if the native extension's binding
    /// names an output header slot at all; or if the product of the two
    /// endoscaling counts is at most four.
    fn check() -> Result<()> {
        Self::NATIVE_ONLINE.check()?;
        Self::NESTED_ONLINE.check()?;
        for (mesh, layout, domain) in [
            (
                Self::NATIVE_MESH,
                Self::NATIVE_ONLINE,
                Self::NATIVE_DOMAIN_INPUTS,
            ),
            (
                Self::NESTED_MESH,
                Self::NESTED_ONLINE,
                Self::NESTED_DOMAIN_INPUTS,
            ),
        ] {
            if let Some(mesh) = mesh {
                mesh.check(layout)?;
            }
            // A domain input is a wire of the input stage, and the domain
            // is the mesh's source's.
            if domain.iter().any(|&input| input >= layout.inputs)
                || (!domain.is_empty() && mesh.is_none())
            {
                return Err(Error::Initialization(
                    "the profile's domain inputs are not inputs of a source-registry mesh".into(),
                ));
            }
        }
        // Each of a step's polynomials contributes two points to the other
        // side's walk: the step's own, and those paging adds to it. A full
        // pass must shrink that contribution for a fixed point to exist.
        let step_rxs = (1 + paging::added(Self::PAGE_COUNTS.endoscaling_step))
            * (1 + paging::added(Self::PAGE_COUNTS.nested_endoscaling_step));
        if Self::NATIVE_ENDOSCALINGS_PER_STEP.saturating_mul(Self::NESTED_ENDOSCALINGS_PER_STEP)
            <= 4 * step_rxs
        {
            return Err(Error::Initialization(
                "the profile's endoscaling counts must be nonzero and their product exceed four \
                 for each pair of polynomials a native and a nested step take"
                    .into(),
            ));
        }
        if Self::NAME.is_empty() {
            return Err(Error::Initialization("the profile has no name".into()));
        }
        if !Self::BUILT_IN.is_some_and(BuiltIn::is::<Self>) {
            for name in [Standard::NAME, AGGREGATOR_NAME] {
                if Self::NAME == name {
                    return Err(Error::Initialization(
                        alloc::format!("the profile takes the built-in {name} profile's name")
                            .into(),
                    ));
                }
            }
        }
        let native = Self::native_extension();
        let nested = Self::nested_extension();
        for (side, declared, extension, other) in [
            ("native", Self::NATIVE_EXTENSION, &native, &nested),
            ("nested", Self::NESTED_EXTENSION, &nested, &native),
        ] {
            if declared != extension.rx() {
                return Err(Error::Initialization(
                    alloc::format!(
                        "the profile's {side} extension adds {} rx polynomials but declares {declared}",
                        extension.rx()
                    )
                    .into(),
                ));
            }
            if !extension.is_consistent() {
                return Err(Error::Initialization(
                    alloc::format!("the profile's {side} extension is not well formed").into(),
                ));
            }
            if let Some(binding) = &extension.binding
                && binding
                    .stages
                    .iter()
                    .any(|&stage| (stage as usize) >= other.stages)
            {
                return Err(Error::Initialization(
                    alloc::format!(
                        "the profile's {side} extension binds a stage the other side does not have"
                    )
                    .into(),
                ));
            }
        }
        if nested.statement.is_some() {
            return Err(Error::Initialization(
                "only the native extension carries a statement circuit".into(),
            ));
        }
        // A binding's points are on the curve its side holds: the output
        // header's slots on the nested side alone, and on either side
        // the other field's batch.
        let within =
            |slots: &[u32], count: usize| slots.iter().all(|&slot| (slot as usize) < count);
        if let Some(binding) = &native.binding {
            if !binding.online.is_empty() {
                return Err(Error::Initialization(
                    "the native binding circuit names an output header slot, whose commitment is a point only the nested binding circuit holds".into(),
                ));
            }
            if !within(&binding.batch, Self::NESTED_ONLINE.polynomials.len()) {
                return Err(Error::Initialization(
                    "the native binding circuit names a polynomial the nested online batch does not have".into(),
                ));
            }
        }
        if let Some(binding) = &nested.binding {
            if !within(&binding.online, crate::header::NUM_ONLINE_FP_POLYS) {
                return Err(Error::Initialization(
                    "the nested binding circuit names an output header slot the step does not have"
                        .into(),
                ));
            }
            if !within(&binding.batch, Self::NATIVE_ONLINE.polynomials.len()) {
                return Err(Error::Initialization(
                    "the nested binding circuit names a polynomial the native online batch does not have".into(),
                ));
            }
        }
        online::stages::check::<Self, online::stages::Native>()?;
        online::stages::check::<Self, online::stages::Nested>()?;
        Ok(())
    }
}

/// The token the crate's own profiles carry in [`Profile::BUILT_IN`]: the
/// type it was made for, as the function that names it. Its field is
/// private, so only this crate constructs one, and a copy names the type
/// it was made for rather than the profile that copied it.
#[derive(Clone, Copy, Debug)]
pub struct BuiltIn(pub(crate) fn() -> TypeId);

impl BuiltIn {
    /// Whether the token was made for `P`.
    fn is<P: 'static>(self) -> bool {
        (self.0)() == TypeId::of::<P>()
    }
}

/// One side's registered extension of a profile, and where its paged
/// circuits' entries sit in it.
#[derive(Debug)]
pub(crate) struct Extended {
    extension: Extension,
    pub(crate) placements: Vec<paging::Placement>,
}

impl core::ops::Deref for Extended {
    type Target = Extension;

    fn deref(&self) -> &Extension {
        &self.extension
    }
}

/// The registered native extension, including the online batch helper.
pub(crate) fn native_extension<P: Profile>() -> Arc<Extended> {
    extended::<P>(false)
}

/// The registered nested extension, including the online batch helper.
pub(crate) fn nested_extension<P: Profile>() -> Arc<Extended> {
    extended::<P>(true)
}

/// One side's registered extension of profile `P`, the nested when `nested`
/// is set.
///
/// It is a function of the profile alone, and the circuits ask for it at
/// every index they take into a proof's polynomials. With `std` each thread
/// builds it once per profile; without, every call builds it.
pub(crate) fn extended<P: Profile>(nested: bool) -> Arc<Extended> {
    let build = || {
        let mut extension = if nested {
            online::stages::layout::<P, online::stages::Nested>()
        } else {
            online::stages::layout::<P, online::stages::Native>()
        };
        let placements = paging::extend::<P>(&mut extension, nested);
        Arc::new(Extended {
            extension,
            placements,
        })
    };
    #[cfg(feature = "std")]
    {
        type Built = BTreeMap<(TypeId, bool), Arc<Extended>>;
        std::thread_local! {
            static BUILT: core::cell::RefCell<Built> =
                const { core::cell::RefCell::new(BTreeMap::new()) };
        }
        let key = (TypeId::of::<P>(), nested);
        if let Some(found) = BUILT.with(|built| built.borrow().get(&key).cloned()) {
            return found;
        }
        let made = build();
        BUILT.with(|built| built.borrow_mut().insert(key, made.clone()));
        made
    }
    #[cfg(not(feature = "std"))]
    build()
}

/// Whether `P`'s decompression step carries the source proof's online
/// polynomials: `P` declares a statement circuit and its nested binding
/// names both output slots (see [`Extension::statement`]).
pub(crate) fn decompresses_online_polynomials<P: Profile>() -> bool {
    P::native_extension().statement.is_some()
        && P::nested_extension()
            .binding
            .is_some_and(|binding| binding.online.len() == crate::header::NUM_ONLINE_FP_POLYS)
}

/// A registry slot a profile's circuit hook fills with one internal circuit.
///
/// The hook receives the slot and returns it [`Registered`], which only
/// [`register`](Self::register) produces, so a hook registers one circuit
/// and nothing else, and the layout's indices stay the registry's.
pub struct CircuitSlot<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> CircuitSlot<'params, F, R> {
    /// The slot of `registry`'s next internal circuit.
    pub(crate) fn new(registry: RegistryBuilder<'params, F, R>) -> Self {
        CircuitSlot(registry)
    }

    /// Registers `circuit` as the slot's internal circuit, with a constant
    /// zero appended to its public output.
    ///
    /// The prover names the application circuit's registry slot in the
    /// proof, and the verifier checks only that it lies in the registry's
    /// domain, so every slot but a step's must be unable to satisfy an
    /// application instance. An application instance's linear coefficient
    /// is its output header's suffix, never zero, while a circuit whose last
    /// public output is a constant zero has no wire in that row, so no trace
    /// gives it a linear term. The fuse's circuits end their outputs so, and
    /// this appends the same zero to every extension circuit's, including
    /// one without an output, whose first constraint would otherwise take
    /// the row. The statement and binding circuits' $k(y)$ targets append
    /// the zero too; a circuit without an output keeps $k(y) = 1$. The
    /// profile's prover traces the circuit as it handed it over, without the
    /// zero, which adds no gate: the trace is the registered circuit's.
    ///
    /// # Errors
    ///
    /// Propagates the registry's error.
    pub fn register<C: Circuit<F> + 'params>(
        self,
        circuit: C,
    ) -> Result<Registered<'params, F, R>> {
        self.0
            .register_internal_circuit(Suffixed(circuit))
            .map(|registry| Registered {
                registry,
                registration: Registration::Circuit,
            })
    }

    /// Registers the staged `circuit` as [`register`](Self::register) does
    /// and records the stages it loads, in gate order, for the registry to
    /// check against the profile's declaration
    /// ([`Extension::circuits`]): an extension circuit declared to load
    /// stages must be registered through this method.
    ///
    /// # Errors
    ///
    /// Propagates the registry's error.
    pub fn register_staged<X: MultiStageCircuit<F, R>>(
        self,
        circuit: MultiStage<F, R, X>,
    ) -> Result<Registered<'params, F, R>>
    where
        MultiStage<F, R, X>: 'params,
    {
        let stages = X::Last::gate_ranges();
        self.0
            .register_internal_circuit(Suffixed(circuit))
            .map(|registry| Registered {
                registry,
                registration: Registration::Staged(stages),
            })
    }
}

/// A registry slot a profile's mask hook fills with one mask, a stage
/// mask or a final mask.
///
/// The hook receives the slot and returns it [`Registered`], which only
/// [`register_stage_mask`](Self::register_stage_mask) and
/// [`register_final_mask`](Self::register_final_mask) produce, so a hook
/// registers one mask and nothing else.
pub struct MaskSlot<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> MaskSlot<'params, F, R> {
    /// The slot of `registry`'s next mask.
    pub(crate) fn new(registry: RegistryBuilder<'params, F, R>) -> Self {
        MaskSlot(registry)
    }

    /// Registers the stage mask of `S` in the slot and records the
    /// stage's gates for the registry to check against the profile's
    /// declaration ([`Extension::stages`]).
    ///
    /// # Errors
    ///
    /// Propagates [`StageExt::stage_mask`]'s error.
    pub fn register_stage_mask<S: Stage<F, R>>(self) -> Result<Registered<'params, F, R>> {
        Ok(Registered {
            registry: self.0.register_mask(S::stage_mask()?),
            registration: Registration::StageMask(stage_gates::<F, R, S>()),
        })
    }

    /// Registers the final mask of the circuits whose last stage is `S` in
    /// the slot and records the gate it starts at for the registry to
    /// check against the profile's declaration
    /// ([`Extension::final_masks`]).
    ///
    /// # Errors
    ///
    /// Propagates [`StageExt::final_mask`]'s error.
    pub fn register_final_mask<S: Stage<F, R>>(self) -> Result<Registered<'params, F, R>> {
        Ok(Registered {
            registry: self.0.register_mask(S::final_mask()?),
            registration: Registration::FinalMask(stage_gates::<F, R, S>().end),
        })
    }
}

/// Stage `S`'s gates: what its mask covers and its final mask starts after.
fn stage_gates<F: Field, R: Rank, S: Stage<F, R>>() -> Range<usize> {
    S::skip_gates()..S::skip_gates() + S::num_gates()
}

/// A slot a hook filled: the registry with the slot's one entry registered,
/// and what the entry is, for the registry to check against the profile's
/// declaration.
pub struct Registered<'params, F: Field, R: Rank> {
    registry: RegistryBuilder<'params, F, R>,
    registration: Registration,
}

impl<'params, F: Field, R: Rank> Registered<'params, F, R> {
    /// The registry, with the entry.
    #[cfg(test)]
    pub(crate) fn into_registry(self) -> RegistryBuilder<'params, F, R> {
        self.registry
    }

    /// The registry, with the entry, and what the entry is.
    pub(crate) fn into_parts(self) -> (RegistryBuilder<'params, F, R>, Registration) {
        (self.registry, self.registration)
    }
}

/// What a hook registered in its slot, as the registry checks it against
/// the profile's declaration ([`Extension::check_registered`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Registration {
    /// A circuit whose stages the registry cannot see
    /// ([`CircuitSlot::register`]).
    Circuit,
    /// A staged circuit, with the gates of each stage it loads in gate
    /// order ([`CircuitSlot::register_staged`]).
    Staged(Vec<Range<usize>>),
    /// A stage's mask, over the stage's gates
    /// ([`MaskSlot::register_stage_mask`]).
    StageMask(Range<usize>),
    /// A final mask, from a gate on ([`MaskSlot::register_final_mask`]).
    FinalMask(usize),
}

/// A circuit with a constant zero appended to its public output; see
/// [`CircuitSlot::register`].
struct Suffixed<C>(C);

impl<F: Field, C: Circuit<F>> Circuit<F> for Suffixed<C> {
    type Instance<'source> = C::Instance<'source>;
    type Witness<'source> = C::Witness<'source>;
    type Output = Kind![F; @WithSuffix<'_, _, C::Output>];
    type Aux<'source> = C::Aux<'source>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        let output = self.0.instance(dr, instance)?;
        Ok(WithSuffix::new(output, Element::zero(dr)))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (output, aux) = self.0.witness(dr, witness)?.into_parts();
        Ok(WithAux::new(
            WithSuffix::new(output, Element::zero(dr)),
            aux,
        ))
    }
}

/// The default native extension prover's error: the profile declares a native
/// extension without overriding the prover.
pub(crate) const NO_NATIVE_EXTENSION_PROVER: &str = "the profile's native extension has no prover";
/// The nested counterpart of [`NO_NATIVE_EXTENSION_PROVER`].
pub(crate) const NO_NESTED_EXTENSION_PROVER: &str = "the profile's nested extension has no prover";

/// The lengths of a profile's extension, which are all that the arithmetic
/// index lookups need from it.
#[derive(Clone, Copy)]
pub(crate) struct ExtensionLengths {
    pub circuits: usize,
    pub stages: usize,
    pub masks: usize,
}

/// The lengths of profile `P`'s nested extension when `nested` is set, and
/// of its native extension otherwise.
pub(crate) fn extension_lengths<P: Profile>(nested: bool) -> ExtensionLengths {
    let extension = if nested {
        nested_extension::<P>()
    } else {
        native_extension::<P>()
    };
    ExtensionLengths {
        circuits: extension.circuits.len(),
        stages: extension.stages,
        masks: extension.masks(),
    }
}

/// An extension's polynomials for one proof: its circuits' rx polynomials
/// in circuit order, then its stages' in stage order.
#[derive(Clone, Debug)]
pub struct ExtensionRxs<F: Field, R: Rank> {
    /// The circuits' polynomials.
    pub circuits: Vec<sparse::Polynomial<F, R>>,
    /// The stages' polynomials.
    pub stages: Vec<sparse::Polynomial<F, R>>,
}

impl<F: Field, R: Rank> Default for ExtensionRxs<F, R> {
    fn default() -> Self {
        ExtensionRxs {
            circuits: Vec::new(),
            stages: Vec::new(),
        }
    }
}

/// What a profile adds on one side of the cycle: internal circuits beyond
/// the fuse's own and the stages they load.
///
/// The circuits are registered as internal circuits after the fuse's and
/// its masks, the stage masks and then the final masks, after the fuse's
/// masks, so that the registry's order stays circuits first. Each circuit
/// and each stage has an rx polynomial in the proof; a final mask, the
/// final mask of its circuits' last stage, binds the rx polynomials of the
/// circuits it names, as the fuse's final masks do, and has none. A
/// circuit's claim takes its own rx polynomial and the stages it loads,
/// with $k(y) = 1$ as the fuse's steps have, since an extension circuit
/// carries no instance of its own; the statement
/// circuit's $k(y)$ is instead the output header it exposes, and the
/// binding circuit's the other side's stage commitments it exposes. Every
/// extension circuit's output ends with the zero its slot appends (see
/// [`CircuitSlot::register`]), which those two $k(y)$ values include and
/// which leaves $k(y) = 1$ as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extension {
    /// Each circuit's stages, by index among the stages, in the order the
    /// circuit loads them, which is the order of their gates: a stage's
    /// gates follow its parent's, so the indices number the stages in gate
    /// order and each list is strictly increasing. Its last entry is then
    /// the stage whose final mask covers the circuit's gates.
    pub circuits: Vec<Vec<u32>>,
    /// The number of stages.
    pub stages: usize,
    /// Each final mask's circuits, by index among the circuits, all with the
    /// same last stage.
    pub final_masks: Vec<Vec<u32>>,
    /// The statement circuit, by index among the circuits, for an extension
    /// that verifies a compressed proof: the circuit whose public output is
    /// the output header of the proof it verified, so that its claim's
    /// $k(y)$ binds the proof's own output header to it. `None` for any
    /// other extension, and always on the nested side.
    ///
    /// After the header the output carries the step binding,
    /// [`STEP_BINDING`] elements: the decompression flag and the point at
    /// which the step opened the bootstrap's first slot, the digest the
    /// decompressor staged. Both are zero for an ordinary step.
    ///
    /// The native claim binds the header alone. If the nested binding
    /// names both output slots ([`Binding::online`]), the decompression
    /// step carries the source proof's online polynomials, and the nested
    /// extension must hold its output commitments to the source proof's,
    /// as the aggregator's does. Otherwise the step leaves both output
    /// slots as padding, so every header a decompressed statement can carry
    /// must leave its slots to padding: the step accepts any application
    /// suffix, so [`finalize_with`](crate::ApplicationBuilder::finalize_with)
    /// refuses an application with a step that outputs or reads a header
    /// naming an online polynomial.
    pub statement: Option<u32>,
    /// The binding circuit, for an extension whose circuits take values the
    /// other side's extension computes: the circuit whose public output is
    /// its recomputation of the other side's stages, so that its claim's
    /// $k(y)$ holds it to the commitments the proof carries for them.
    /// `None` for an extension that binds nothing.
    pub binding: Option<Binding>,
}

/// The elements a statement circuit's public output ends with, after the
/// output header: the step binding (see [`Extension::statement`]).
pub const STEP_BINDING: usize = 2;

/// An extension's binding circuit: the circuit, by index among the
/// extension's circuits, whose public output is one point per stage of
/// `stages`, the other side's extension stages by index in that extension,
/// each the circuit's recomputation of that stage's commitment. The
/// claim's $k(y)$ is the $k(y)$ of those stages' commitments as the proof
/// carries them, so the claim holds only if the recomputation matches: the
/// values the circuit's side took from the other side are the ones the
/// other side's stages hold.
///
/// The circuit recomputes a commitment from the stage's values, so the
/// other side commits a bound stage with a zero alpha, and the commitment
/// is then deterministic in the values, or the circuit takes the stage's
/// alpha as a witness and adds its term. The profile must ensure that the
/// output order matches `stages` and that each commitment is recomputed from
/// the values its circuits actually use for that stage. This agreement is part
/// of the trusted setup: a mismatched association can accept unintended
/// statements even when the exposed commitments match the claim's target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The binding circuit, by index among the extension's circuits.
    pub circuit: u32,
    /// The other side's extension stages the circuit's output points
    /// recompute, by index among that extension's stages, in output order.
    pub stages: Vec<u32>,
    /// The slots of the step's output header whose commitments the
    /// circuit's output ends with, after the stages' points, in output
    /// order: a point per slot, which the claim's $k(y)$ holds to the
    /// commitment the proof carries for that slot. A binding circuit's
    /// points are on the curve its side's circuits hold, and the header's
    /// polynomials are committed on the host curve, so only the nested
    /// extension's binding names any.
    ///
    /// A header's slots belong to the application, so a profile whose
    /// nested binding names one must have its circuits use the point only
    /// where the profile's own step fills the slot, as the aggregator's
    /// use it only under the decompression step's flag.
    pub online: Vec<u32>,
    /// The polynomials of the other field's profile batch whose
    /// commitments the circuit's output ends with, after the points of
    /// `online`, in output order. The points are on the curve the
    /// binding's side holds: the nested binding names polynomials of
    /// [`Profile::NATIVE_ONLINE`], and the native binding names
    /// polynomials of [`Profile::NESTED_ONLINE`]. The claim's $k(y)$
    /// holds each point to the commitment the step's walk folded.
    ///
    /// The claim binds the commitment and nothing else. The batch proves
    /// that a claimed value is an opening of the committed polynomial, not
    /// which polynomial was committed. A profile that takes the point for
    /// the commitment of a polynomial it expects must have its circuits
    /// hold an opening of the slot, at a challenge of the step, to the
    /// expected polynomial's value there. The slot's
    /// [`Phase`](online::Phase) must then be no later than that challenge,
    /// and what the expected value depends on must be fixed before it.
    pub batch: Vec<u32>,
}

impl Extension {
    /// No circuits and no stages.
    pub const EMPTY: Self = Extension {
        circuits: Vec::new(),
        stages: 0,
        final_masks: Vec::new(),
        statement: None,
        binding: None,
    };

    /// Whether the extension adds nothing.
    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty() && self.stages == 0 && self.final_masks.is_empty()
    }

    /// The rx polynomials the extension adds: one per circuit and one per
    /// stage.
    pub fn rx(&self) -> usize {
        self.circuits.len() + self.stages
    }

    /// The masks the extension registers: the stage masks, then the
    /// final masks.
    pub fn masks(&self) -> usize {
        self.stages + self.final_masks.len()
    }

    /// The internal circuits the extension registers: its circuits and its
    /// masks.
    pub fn internal(&self) -> usize {
        self.circuits.len() + self.masks()
    }

    /// The circuits a final mask binds, for `mask` an index among the
    /// masks past the stage masks.
    pub fn final_mask(&self, mask: usize) -> &[u32] {
        &self.final_masks[mask - self.stages]
    }

    /// Whether the declaration is well formed: every index the circuits,
    /// final masks, statement and binding name exists; each circuit lists
    /// its stages in strictly increasing order, so in gate order with no
    /// stage twice (see [`circuits`](Self::circuits)); neither a final mask
    /// names a circuit twice nor the binding a stage twice; the statement
    /// and binding circuits differ and the binding names at least one stage;
    /// every circuit that loads a stage is named by exactly one final mask
    /// and a circuit that loads none by no final mask; and a final mask's
    /// circuits share their last stage. A stage's final mask confines the
    /// traces of the circuits whose last stage it is to the gates after it,
    /// so a circuit under no final mask has a trace that can reach into the
    /// stages it loads, and one under another stage's, or whose list ends
    /// in a stage before the last it loads, is checked against the wrong
    /// gates. Whether the binding's stages exist is the other extension's
    /// to say, which [`Profile::check`] asks.
    pub fn is_consistent(&self) -> bool {
        fn distinct(values: &[u32]) -> bool {
            values
                .iter()
                .enumerate()
                .all(|(i, value)| !values[..i].contains(value))
        }
        let in_range = self
            .circuits
            .iter()
            .flatten()
            .all(|&stage| (stage as usize) < self.stages)
            && self
                .final_masks
                .iter()
                .flatten()
                .all(|&circuit| (circuit as usize) < self.circuits.len())
            && self
                .statement
                .is_none_or(|circuit| (circuit as usize) < self.circuits.len())
            && self.binding.as_ref().is_none_or(|binding| {
                (binding.circuit as usize) < self.circuits.len()
                    && self.statement != Some(binding.circuit)
                    && !binding.stages.is_empty()
                    && distinct(&binding.stages)
                    && distinct(&binding.online)
                    && distinct(&binding.batch)
            });
        // In gate order, which leaves `last()` the stage whose final mask
        // covers the circuit, and names no stage twice.
        let increasing = |stages: &[u32]| stages.windows(2).all(|pair| pair[0] < pair[1]);
        in_range
            && self.circuits.iter().all(|stages| increasing(stages))
            && self.final_masks.iter().all(|mask| distinct(mask))
            && self.circuits.iter().enumerate().all(|(circuit, stages)| {
                let masks = self
                    .final_masks
                    .iter()
                    .filter(|mask| mask.contains(&(circuit as u32)))
                    .count();
                masks == usize::from(!stages.is_empty())
            })
            && self.final_masks.iter().all(|mask| {
                let mut last = mask
                    .iter()
                    .map(|&circuit| self.circuits[circuit as usize].last());
                last.next()
                    .is_some_and(|first| last.all(|stage| stage == first))
            })
    }

    /// Checks what the profile's hooks registered for this extension
    /// against the declaration: mask `j` below [`stages`](Self::stages)
    /// is stage `j`'s mask and every later one a final mask; a circuit
    /// declared to load stages was registered as a staged circuit whose
    /// stages are the declared ones in order, each over the gates its mask
    /// covers, under the final mask that starts where its last stage ends;
    /// and a circuit declared to load none loads none. `circuits` and
    /// `masks` are the registrations in the declaration's order; `side`
    /// names the extension in the error.
    ///
    /// What a circuit does with its stages, and whether the statement and
    /// binding circuits expose what their claims assume, is not checked
    /// here: see [`Binding`].
    ///
    /// # Errors
    ///
    /// Fails on the first disagreement.
    pub(crate) fn check_registered(
        &self,
        side: &str,
        circuits: &[Registration],
        masks: &[Registration],
    ) -> Result<()> {
        let refuse = |what: alloc::string::String| {
            Err(Error::Initialization(
                alloc::format!("the profile's {side} extension {what}").into(),
            ))
        };
        if circuits.len() != self.circuits.len() || masks.len() != self.masks() {
            return refuse(alloc::format!(
                "registers {} circuits and {} masks but declares {} and {}",
                circuits.len(),
                masks.len(),
                self.circuits.len(),
                self.masks()
            ));
        }
        let mut stage_masks = Vec::with_capacity(self.stages);
        for (j, registration) in masks.iter().enumerate() {
            match registration {
                Registration::StageMask(gates) if j < self.stages => {
                    stage_masks.push(gates.clone())
                }
                Registration::FinalMask(_) if j >= self.stages => {}
                _ if j < self.stages => {
                    return refuse(alloc::format!(
                        "registers mask {j} as something other than stage {j}'s mask"
                    ));
                }
                _ => {
                    return refuse(alloc::format!(
                        "registers mask {j} as something other than a final mask"
                    ));
                }
            }
        }
        for (k, (registration, declared)) in circuits.iter().zip(&self.circuits).enumerate() {
            let loaded = match registration {
                Registration::Staged(loaded) => loaded,
                Registration::Circuit if declared.is_empty() => continue,
                Registration::Circuit => {
                    return refuse(alloc::format!(
                        "declares that circuit {k} loads stages but registers it as one that loads none"
                    ));
                }
                _ => return refuse(alloc::format!("registers circuit {k} as a mask")),
            };
            let mut expected = Vec::with_capacity(declared.len());
            for &stage in declared {
                match stage_masks.get(stage as usize) {
                    Some(gates) => expected.push(gates.clone()),
                    None => {
                        return refuse(alloc::format!(
                            "declares that circuit {k} loads a stage it does not have"
                        ));
                    }
                }
            }
            if *loaded != expected {
                return refuse(alloc::format!(
                    "declares that circuit {k} loads the stages over gates {expected:?} but registers one over {loaded:?}"
                ));
            }
            let Some(last) = loaded.last() else {
                continue;
            };
            let Some(mask) = self
                .final_masks
                .iter()
                .position(|mask| mask.contains(&(k as u32)))
            else {
                return refuse(alloc::format!("names circuit {k} in no final mask"));
            };
            if masks[self.stages + mask] != Registration::FinalMask(last.end) {
                return refuse(alloc::format!(
                    "registers circuit {k}'s final mask elsewhere than at gate {}, where its last stage ends",
                    last.end
                ));
            }
        }
        Ok(())
    }
}

/// A profile's prover context: what an application of the profile holds
/// across proofs to build its extension over, and what a step can supply
/// in its place.
pub trait ProverContext {
    /// What a step supplies the extension's prover in place of the
    /// context's own proof: the compressed proof a decompression step
    /// decompresses. Uninhabited for a context no step supplies anything
    /// to.
    type Source;
}

/// No context, and nothing a step supplies.
impl ProverContext for () {
    type Source = core::convert::Infallible;
}

/// What a step can supply the extension's prover of an application over
/// `C` in place of its context's proof ([`ProverContext::Source`]).
pub(crate) type Source<'params, C, R, B> = <<<C as ProfiledCycle>::Profile as Profile>::Context<
    'params,
    <C as ProfiledCycle>::Base,
    R,
    B,
> as ProverContext>::Source;

/// The standard profile: the fuse alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Standard;

impl Profile for Standard {
    const NAME: &'static str = "standard";
    const BUILT_IN: Option<BuiltIn> = Some(BuiltIn(TypeId::of::<Self>));
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

/// The aggregator profile's [`NAME`](Profile::NAME), the same for every
/// header size.
pub(crate) const AGGREGATOR_NAME: &str = "aggregator";

/// A cycle with a profile: what every item that lays out a proof is generic
/// over.
pub trait ProfiledCycle: Cycle {
    /// The profile of every proof over this cycle.
    type Profile: Profile;

    /// The cycle this one extends: the same curves, generators and Poseidon
    /// instances in the standard profile, whose proofs the profile's
    /// circuits verify. The standard cycle is its own base.
    type Base: IpaCycle
        + ProfiledCycle<
            Profile = Standard,
            CircuitField = Self::CircuitField,
            ScalarField = Self::ScalarField,
            NestedCurve = Self::NestedCurve,
            HostCurve = Self::HostCurve,
            NestedGenerators = Self::NestedGenerators,
            HostGenerators = Self::HostGenerators,
            CircuitPoseidon = Self::CircuitPoseidon,
            ScalarPoseidon = Self::ScalarPoseidon,
            Params = Self::Params,
        >;
}

// The base cycle supplies the IPA's generators to the profile's circuits,
// which for the Pasta cycle the baked parameters provide; without them the
// Pasta cycle proves in no profile.
#[cfg(feature = "baked")]
impl ProfiledCycle for Pasta {
    type Profile = Standard;
    type Base = Pasta;
}

/// A cycle under another profile: `C`'s curves, generators and Poseidon
/// instances with `P`'s proof shape.
///
/// `Profiled<Pasta, Aggregator<H>>` is the aggregator cycle over the Pasta
/// curves for wallet headers of `H` elements. It is a distinct type from
/// `Pasta`, so an application over one never accepts the other's proofs.
pub struct Profiled<C, P>(PhantomData<(C, P)>);

impl<C, P> Clone for Profiled<C, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C, P> Copy for Profiled<C, P> {}

impl<C, P> Default for Profiled<C, P> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<C, P> fmt::Debug for Profiled<C, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Profiled<{}, {}>", type_name::<C>(), type_name::<P>())
    }
}

impl<C, P> PartialEq for Profiled<C, P> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<C, P> Eq for Profiled<C, P> {}

impl<C: Cycle, P: Profile> Cycle for Profiled<C, P> {
    type CircuitField = C::CircuitField;
    type ScalarField = C::ScalarField;
    type NestedCurve = C::NestedCurve;
    type HostCurve = C::HostCurve;
    type NestedGenerators = C::NestedGenerators;
    type HostGenerators = C::HostGenerators;
    type CircuitPoseidon = C::CircuitPoseidon;
    type ScalarPoseidon = C::ScalarPoseidon;
    type Params = C::Params;

    fn nested_generators(params: &Self::Params) -> &Self::NestedGenerators {
        C::nested_generators(params)
    }

    fn host_generators(params: &Self::Params) -> &Self::HostGenerators {
        C::host_generators(params)
    }

    fn circuit_poseidon(params: &Self::Params) -> &Self::CircuitPoseidon {
        C::circuit_poseidon(params)
    }

    fn scalar_poseidon(params: &Self::Params) -> &Self::ScalarPoseidon {
        C::scalar_poseidon(params)
    }
}

impl<C: IpaCycle, P: Profile> IpaCycle for Profiled<C, P> {
    fn host_u(params: &Self::Params) -> &Self::HostCurve {
        C::host_u(params)
    }

    fn nested_u(params: &Self::Params) -> &Self::NestedCurve {
        C::nested_u(params)
    }

    fn nested_generator(params: &Self::Params, index: usize) -> Option<Self::NestedCurve> {
        C::nested_generator(params, index)
    }
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>, P: Profile> ProfiledCycle for Profiled<C, P> {
    type Profile = P;
    type Base = C;
}

/// The shape a profile gives a proof: its rx polynomial counts and the sizes
/// of the two endoscaling walks.
///
/// The profile's extensions are the roots: each extra rx polynomial on one
/// side is a point the other side's walk folds, so an extension lengthens
/// both walks. The sides size each other. Every native rx polynomial is a
/// point the nested walk folds, the nested walk's steps are nested rx
/// polynomials, every nested rx polynomial is a point the native walk folds,
/// and the native walk's steps are native rx polynomials. Going once around
/// at eight endoscalings per step, a native step adds about a sixteenth of
/// a native step, so the map from a step count to the count the batch then
/// needs converges to a fixed point, which [`Shape::solve`] finds by
/// iteration from one step; more endoscalings per step converge faster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The native rx polynomials: the fixed ones, the walk's steps and the
    /// profile's extension, with the native online batch's helper circuit
    /// and stages when [`Profile::NATIVE_ONLINE`] is nonempty.
    pub native_rx: usize,
    /// The nested-curve points the nested walk folds: the native batch, with
    /// the commitments of the [`Profile::NATIVE_ONLINE`] polynomials.
    pub nested_points: usize,
    /// The nested walk's steps.
    pub nested_steps: usize,
    /// The nested rx polynomials, with the nested online batch's helper
    /// circuit and stages when [`Profile::NESTED_ONLINE`] is nonempty.
    pub nested_rx: usize,
    /// The polynomials of the nested online batch
    /// ([`Profile::NESTED_ONLINE`]).
    pub nested_online: usize,
    /// The host-curve points the native walk folds: the nested batch, with
    /// the commitments of the [`nested_online`](Self::nested_online)
    /// polynomials.
    pub native_points: usize,
    /// The native walk's steps: the fixed point, where the count the batch
    /// needs is the count the native rx polynomials were sized with.
    pub native_steps: usize,
    /// The outgoing source polynomial retained for each active source mesh.
    pub source_polynomials: usize,
}

impl Shape {
    /// The shape of profile `P`.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::solve`]. When used in
    /// a constant layout, an invalid shape fails at compile time.
    pub const fn of<P: Profile>() -> Self {
        let mut shape = Self::solve_with_online(
            P::NATIVE_EXTENSION
                + if P::NATIVE_ONLINE.is_empty() {
                    0
                } else {
                    online::stages::RXS
                }
                + paging::rxs(&P::PAGE_COUNTS, false),
            P::NESTED_EXTENSION
                + if P::NESTED_ONLINE.is_empty() {
                    0
                } else {
                    online::stages::RXS
                }
                + paging::rxs(&P::PAGE_COUNTS, true),
            P::NESTED_ONLINE.polynomials.len(),
            P::NATIVE_ONLINE.polynomials.len(),
            (
                P::NATIVE_ENDOSCALINGS_PER_STEP,
                1 + paging::added(P::PAGE_COUNTS.endoscaling_step),
            ),
            (
                P::NESTED_ENDOSCALINGS_PER_STEP,
                1 + paging::added(P::PAGE_COUNTS.nested_endoscaling_step),
            ),
        );
        shape.source_polynomials =
            P::NATIVE_MESH.is_some() as usize + P::NESTED_MESH.is_some() as usize;
        shape
    }

    /// Solves the walk sizes for the given extensions and nested online
    /// polynomials at the given endoscalings per native and nested step,
    /// iterating the native step count to its fixed point.
    ///
    /// # Panics
    ///
    /// Panics if an endoscaling count is zero or the walk sizes do not
    /// converge within 256 iterations.
    pub const fn solve(
        native_extension: usize,
        nested_extension: usize,
        nested_online: usize,
        native_endoscalings: usize,
        nested_endoscalings: usize,
    ) -> Self {
        Self::solve_with_online(
            native_extension,
            nested_extension,
            nested_online,
            0,
            (native_endoscalings, 1),
            (nested_endoscalings, 1),
        )
    }

    /// As [`solve`](Self::solve), with the step's online Fp polynomials,
    /// and each walk given as the endoscalings a step performs and the
    /// polynomials a step takes: one, or one more for each page a paged
    /// step adds and for its carry stage.
    const fn solve_with_online(
        native_extension: usize,
        nested_extension: usize,
        nested_online: usize,
        native_online: usize,
        native_walk: (usize, usize),
        nested_walk: (usize, usize),
    ) -> Self {
        let mut native_steps = 1;
        let mut rounds = 0;
        loop {
            let shape = Self::with_native_steps(
                native_steps,
                native_extension,
                nested_extension,
                nested_online,
                native_online,
                native_walk,
                nested_walk,
            );
            if shape.native_steps == native_steps {
                return shape;
            }
            rounds += 1;
            assert!(rounds < 256, "the walk sizes did not converge");
            native_steps = shape.native_steps;
        }
    }

    /// One pass around the cycle: the shape that `native_steps` native steps
    /// imply, whose `native_steps` is the count the resulting batch needs.
    const fn with_native_steps(
        native_steps: usize,
        native_extension: usize,
        nested_extension: usize,
        nested_online: usize,
        native_online: usize,
        (native_endoscalings, native_step_rxs): (usize, usize),
        (nested_endoscalings, nested_step_rxs): (usize, usize),
    ) -> Self {
        let native_rx = native::NUM_FIXED_RX + native_steps * native_step_rxs + native_extension;
        let nested_points = nested::num_endoscaling_points(native_rx) + native_online;
        let nested_steps = endoscalar::num_steps(nested_endoscalings, nested_points);
        let nested_rx = nested::NUM_FIXED_RX + nested_steps * nested_step_rxs + nested_extension;
        let native_points = nested::pcs::num_batched_points(nested_rx, nested_online);
        let native_steps = endoscalar::num_steps(native_endoscalings, native_points);
        Shape {
            native_rx,
            nested_points,
            nested_steps,
            nested_rx,
            nested_online,
            native_points,
            native_steps,
            source_polynomials: 0,
        }
    }

    /// Every polynomial a proof of this shape carries: both sides' rx
    /// polynomials, $a$, $b$, `registry_xy` and $p$ on each side, the step's
    /// online Fp polynomials, and each mesh's outgoing source polynomial.
    pub const fn polynomials(&self) -> usize {
        self.native_rx
            + 4
            + self.nested_rx
            + 4
            + crate::header::NUM_ONLINE_FP_POLYS
            + self.source_polynomials
    }
}

// The standard profile's shape is the internal modules' constant layout: the
// native walk's pin and the lists the tests and the fuzzing vocabulary read as
// constants. Each constant must agree with the rederivation, so an edit to
// either side that moves the shape fails here.
const _: () = {
    let shape = Shape::of::<Standard>();
    assert!(shape.native_rx == native::RxIndex::NUM);
    assert!(shape.nested_points == nested::NUM_ENDOSCALING_POINTS);
    assert!(shape.nested_steps == nested::NUM_ENDOSCALING_STEPS);
    assert!(shape.nested_rx == nested::RxIndex::NUM);
    assert!(shape.native_points == native::NUM_ENDOSCALING_POINTS);
    assert!(shape.native_steps == native::NUM_ENDOSCALING_STEPS);
};

/// Profiles with extensions, for the tests of the extension's plumbing.
#[cfg(test)]
#[path = "../../tests/profile_testing.rs"]
pub(crate) mod testing;

#[cfg(test)]
#[path = "../../tests/profile_declarations.rs"]
mod tests;
