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
//! in [`Aggregator`]: the fuse plus the circuits that verify a standard
//! compressed proof in circuit. A wallet's proof then enters an aggregator's
//! fuse as witness data rather than as a child, so the two shapes never have
//! to agree, and only the aggregator's proofs carry the extra polynomials.
//! The aggregator's circuits verify proofs of the standard profile, so the
//! aggregator depends on it; the standard profile knows nothing of the
//! aggregator.
//!
//! A cycle names its profile through [`ProfiledCycle`], so every generic item
//! in this crate reaches the shape through the cycle it already carries, and
//! a wallet proof and an aggregator proof over the same curves are different
//! types. [`Pasta`] proves in the standard profile; [`Profiled`] puts a cycle
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
//! bondings after the fuse's masks, fold a circuit's claim as a step's,
//! and the proof carries the polynomials. An extension may name a
//! statement circuit, whose claim binds an internal step's output header
//! to what the extension verified, and a binding circuit, whose claim
//! binds its side's view of the other side's stages to their commitments.
//! [`Aggregator`] declares the decompression circuits, at the rank with
//! the room for them.
//!
//! # Profile isolation follow-up
//!
//! Track these requirements as profiles and their circuits evolve:
//!
//! - TODO: preserve Standard's setup, wire layout and transcript domains when
//!   adding isolation. Pin proof bytes and RNG consumption against main so any
//!   wallet protocol change is explicit and reviewed separately.
//! - TODO: commit each profile setup's full versioned description, including the
//!   profile, ordered circuits, ranks, capacities, public parameters and
//!   transcript rules/domain tags. Give Aggregator a distinct setup and sample
//!   fresh native/nested registry tags after fixing the description, following
//!   [`Tag`](ragu_circuits::registry::Tag)'s setup contract. Changed descriptions
//!   require new tags even when the profile's name stays the same. The
//!   [`from_beacon`](crate::RegistryTags::from_beacon) labels name every
//!   profile but Standard, so one beacon output and manifest digest never
//!   give two profiles the same tags; they do not stand in for a description
//!   of the profile's own.
//! - TODO: enforce the profile-to-setup association in the application API, with
//!   the expected setup fixed by the verifier. Rust profile types and unchecked
//!   caller-supplied tags do not establish this association on their own.
//! - TODO: carry that binding through proving, recursive verification and
//!   ordinary and compressed verification. Registry-tag binding may supply the
//!   separation; explicit profile transcript domains are an additional option.
//!   If added, preserve Standard's tags and give the outer Aggregator proof
//!   distinct fuse and compression/IPA domains. The inner Standard proof must
//!   still be verified with Standard's setup and transcript domains.
//! - TODO: retain the profile and fixed wire shape in internal gadget types, so
//!   allocation, traversal and equality cannot mix layouts or silently
//!   truncate values from another profile.
//! - TODO: test proof substitution between profiles in both directions, including
//!   profiles with identical shapes, changing each registry tag independently.
//!   Cover ordinary/compressed verification, recursive parents/grandparents
//!   and the decompression circuits' inner-proof verification. Keep the
//!   intended Standard-to-Aggregator decompression as a positive control;
//!   substituting either proof role must fail.
//!
//! TODO: review new verifier circuits independently; profile isolation does
//! not establish the soundness of decompression's outstanding checks.

use alloc::vec::Vec;
use core::{any::type_name, fmt, marker::PhantomData};

use ragu_circuits::{
    BondingObject, Circuit, WithAux,
    polynomials::{AggregatorRank, ProductionRank, Rank, sparse},
    registry::{Registry, RegistryBuilder},
};
#[cfg(feature = "baked")]
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
    extension::Counts,
    prover::{Decompressed, Decompression},
};
use crate::{
    SelectableBackend,
    decompress::extension,
    internal::{endoscalar, native, nested},
    ipa::IpaCycle,
};

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
/// fills the slot it is given, a [`CircuitSlot`] or a [`BondingSlot`],
/// which takes one entry of its kind and nothing else, and the circuit
/// slot ends the circuit's public output with a zero, as the fuse's
/// circuits end theirs (see [`CircuitSlot::register`]). Nothing checks the
/// registered circuits and bondings against the declaration beyond that,
/// so a profile pins the two together in its tests.
///
/// A profile is part of an application's setup description, so its
/// registries take their own [`RegistryTags`](crate::RegistryTags): the
/// standard profile's tags are not another profile's, even over the same
/// curves and steps. [`from_beacon`](crate::RegistryTags::from_beacon)
/// names every profile but the standard one in the labels it derives the
/// tags under, so one beacon output and manifest digest give each profile
/// its own tags.
pub trait Profile: Copy + Default + Eq + fmt::Debug + Send + Sync + 'static {
    /// The profile's name, which
    /// [`from_beacon`](crate::RegistryTags::from_beacon) puts in the labels
    /// it derives the setup tags under, for every profile but the standard
    /// one, whose labels its ceremony fixed. Distinct across profiles and
    /// fixed: a renamed profile derives other tags.
    const NAME: &'static str;

    /// The native rx polynomials the profile adds: its native extension's.
    const NATIVE_EXTENSION: usize;
    /// The nested rx polynomials the profile adds: its nested extension's.
    const NESTED_EXTENSION: usize;

    /// The endoscalings a native endoscaling step performs: what fits a
    /// step beside the stages it reserves at the profile's rank. The walk
    /// over the nested batch takes a step per so many points, so more per
    /// step is fewer steps and fewer polynomials, and the other side's walk
    /// shortens with them. The standard profile's is the production rank's.
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = native::ENDOSCALINGS_PER_STEP;
    /// The endoscalings a nested endoscaling step performs, likewise.
    const NESTED_ENDOSCALINGS_PER_STEP: usize = nested::ENDOSCALINGS_PER_STEP;

    /// What the profile's prover holds across proofs beyond the proof
    /// under construction: the extension's witness source, which an
    /// application takes at
    /// [`finalize_with`](crate::ApplicationBuilder::finalize_with). Nothing
    /// for a profile without an extension.
    type Context<'params, Base, R, B>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    /// The circuits and stages the profile adds on the native side.
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

    /// Registers bonding `bonding` of the native extension, a stage's mask
    /// or a final mask in [`Extension::bondings`] order, into `slot`.
    ///
    /// # Errors
    ///
    /// The default declares no bonding and fails.
    fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        bonding: usize,
        slot: BondingSlot<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (bonding, slot, params);
        Err(Error::Initialization(
            "the profile's native extension has no bondings".into(),
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
    /// [`register_native_bonding`](Self::register_native_bonding).
    ///
    /// # Errors
    ///
    /// The default declares no bonding and fails.
    fn register_nested_bonding<'params, Base, R: Rank>(
        bonding: usize,
        slot: BondingSlot<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (bonding, slot, params);
        Err(Error::Initialization(
            "the profile's nested extension has no bondings".into(),
        ))
    }

    /// The native extension's polynomials for one proof: each circuit's,
    /// assembled against `registry` at the circuit's index in the layout,
    /// then each stage's, blinded from `rng`, over `source`, the proof the
    /// step decompresses, or over the context's canonical proof without.
    ///
    /// # Errors
    ///
    /// The default fills an empty extension and fails for any other.
    fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, source, registry, rng);
        if Self::native_extension().is_empty() {
            Ok(ExtensionRxs::default())
        } else {
            Err(Error::Initialization(
                "the profile's native extension has no prover".into(),
            ))
        }
    }

    /// The nested counterpart of
    /// [`native_extension_rxs`](Self::native_extension_rxs).
    ///
    /// # Errors
    ///
    /// The default fills an empty extension and fails for any other.
    fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, source, registry, rng);
        if Self::nested_extension().is_empty() {
            Ok(ExtensionRxs::default())
        } else {
            Err(Error::Initialization(
                "the profile's nested extension has no prover".into(),
            ))
        }
    }

    /// Checks that the constants agree with the extensions and that the
    /// extensions are well formed.
    ///
    /// # Errors
    ///
    /// Fails if an extension's rx count differs from its constant, so that a
    /// profile declaring one without the other does not lay out a proof; if
    /// either extension is not [consistent](Extension::is_consistent); if
    /// the nested extension names a statement circuit, which only the native
    /// side carries; or if an extension's binding names a stage the other
    /// extension does not have.
    fn check() -> Result<()> {
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
        Ok(())
    }
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
            .map(Registered)
    }
}

/// A registry slot a profile's bonding hook fills with one bonding, a
/// stage's mask or a final mask.
///
/// The hook receives the slot and returns it [`Registered`], which only
/// [`register`](Self::register) produces, so a hook registers one bonding
/// and nothing else.
pub struct BondingSlot<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> BondingSlot<'params, F, R> {
    /// The slot of `registry`'s next bonding.
    pub(crate) fn new(registry: RegistryBuilder<'params, F, R>) -> Self {
        BondingSlot(registry)
    }

    /// Registers `bonding` as the slot's bonding.
    pub fn register(self, bonding: BondingObject<'params, F, R>) -> Registered<'params, F, R> {
        Registered(self.0.register_bonding(bonding))
    }
}

/// A slot a hook filled: the registry with the slot's one entry registered.
pub struct Registered<'params, F: Field, R: Rank>(RegistryBuilder<'params, F, R>);

impl<'params, F: Field, R: Rank> Registered<'params, F, R> {
    /// The registry, with the entry.
    pub(crate) fn into_registry(self) -> RegistryBuilder<'params, F, R> {
        self.0
    }
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
/// the bondings, the stages' masks then the final masks, after the fuse's
/// masks, so that the registry's order stays circuits first. Each circuit
/// and each stage has an rx polynomial in the proof; a final mask, the
/// final mask of its circuits' last stage, binds the rx polynomials of the
/// circuits it names, as the fuse's final masks do, and has none. A circuit's claim takes its own rx polynomial and the
/// stages it loads, with $k(y) = 1$ as the fuse's steps have, since an
/// extension circuit carries no instance of its own; the statement
/// circuit's $k(y)$ is instead the output header it exposes, and the
/// binding circuit's the other side's stage commitments it exposes. Every
/// extension circuit's output ends with the zero its slot appends (see
/// [`CircuitSlot::register`]), which those two $k(y)$ values include and
/// which leaves $k(y) = 1$ as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extension {
    /// Each circuit's stages, by index among the stages, in the order the
    /// circuit loads them.
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
    pub statement: Option<u32>,
    /// The binding circuit, for an extension whose circuits take values the
    /// other side's extension computes: the circuit whose public output is
    /// its recomputation of the other side's stages, so that its claim's
    /// $k(y)$ holds it to the commitments the proof carries for them.
    /// `None` for an extension that binds nothing.
    pub binding: Option<Binding>,
}

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
/// other side commits a bound stage unblinded, and the commitment then
/// hides nothing of the values, or the circuit takes the stage's blinding
/// as a witness and adds its term. Nothing checks the circuit's output
/// against the declaration: a circuit exposing other points, or the stages
/// in another order, fails the claim for every proof rather than passing
/// one it should not, since the $k(y)$ is computed from the commitments
/// the proof carries either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The binding circuit, by index among the extension's circuits.
    pub circuit: u32,
    /// The other side's extension stages the circuit's output points
    /// recompute, by index among that extension's stages, in output order.
    pub stages: Vec<u32>,
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

    /// The bondings the extension registers: the stages' masks, then the
    /// final masks.
    pub fn bondings(&self) -> usize {
        self.stages + self.final_masks.len()
    }

    /// The internal circuits the extension registers: its circuits and its
    /// bondings.
    pub fn internal(&self) -> usize {
        self.circuits.len() + self.bondings()
    }

    /// The circuits a final mask binds, for `bonding` an index among the
    /// bondings past the stages' masks.
    pub fn final_mask(&self, bonding: usize) -> &[u32] {
        &self.final_masks[bonding - self.stages]
    }

    /// Whether the declaration is well formed: every index the circuits,
    /// final masks, statement and binding name exists; neither a circuit
    /// nor a final mask names anything twice, nor the binding a stage
    /// twice; the statement and binding circuits differ and the binding
    /// names at least one stage; every circuit that loads a stage is named
    /// by exactly one final mask and a circuit that loads none by no final
    /// mask; and a final mask's circuits share their last stage. A stage's
    /// final mask confines the traces of the circuits whose last stage it is
    /// to the gates after it, so a circuit under no final mask has a trace
    /// that can reach into the stages it loads, and one under another
    /// stage's is checked against the wrong gates. Whether the binding's
    /// stages exist is the other extension's to say, which
    /// [`Profile::check`] asks.
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
            });
        in_range
            && self.circuits.iter().all(|stages| distinct(stages))
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
}

/// The standard profile: the fuse alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Standard;

impl Profile for Standard {
    const NAME: &'static str = "standard";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
}

/// The aggregator profile: the fuse plus the circuits that verify a
/// [`Standard`] compressed proof in circuit, for wallet proofs over
/// [`Pasta`] at the production rank with `HEADER_SIZE`-element headers.
///
/// The circuits are the decompression module's chunk circuits, laid out as
/// its extension, which an aggregator proves at [`AggregatorRank`]: each
/// polynomial a profile adds is one more commitment the fuse's hashing
/// circuits absorb, one more evaluation its compute-v circuit takes, two
/// more claims its collapse circuits fold and a longer walk whose every
/// step loads the longer points stage, and at the production rank two
/// polynomials per side already push a nested endoscaling step past the
/// budget. At four times the budget the fuse carries the extension, and
/// the hooks refuse any other rank.
///
/// A profile's declaration is a constant, so the circuit counts are
/// pinned per header size ([`native_circuits`](Self::native_circuits))
/// rather than computed from the schedule, and the hooks check the pins
/// against the schedule they register. A header size without a pin does
/// not compile; pin it from the counts the schedule's tests report.
///
/// Every proof of the profile carries the chunk circuits' polynomials, so
/// every fuse runs the chunks over a compressed proof. The application
/// holds a [`Decompression`] of the wallet application it aggregates, taken
/// at [`finalize_with`](crate::ApplicationBuilder::finalize_with), whose
/// canonical compressed proof every fuse decompresses, except the
/// decompression step: it decompresses the wallet proof it is given
/// ([`decompress`](crate::Application::decompress)) and outputs that
/// proof's header. The extension's statement circuit exposes the header
/// the chunks verified, and its claim's $k(y)$ holds a proof of the
/// decompression step to it; each side's binding circuit exposes its
/// recomputation of the other side's stages, and its claim's $k(y)$ holds
/// the two sides to one compressed proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregator<const HEADER_SIZE: usize>;

impl<const HEADER_SIZE: usize> Aggregator<HEADER_SIZE> {
    /// The native chunk circuits of the decompression for
    /// `header_size`-element headers, and how many of them run transcript
    /// chunks, first among them, and digits chunks, last. The
    /// compression's transcript absorbs the three headers, so the
    /// transcript ones grow with the header size.
    ///
    /// # Panics
    ///
    /// Panics, in constant evaluation, for a header size without a pin.
    pub const fn native_circuits(header_size: usize) -> Counts {
        match header_size {
            4 => Counts {
                chunks: 52,
                transcript: 8,
                digits: 1,
            },
            103 => Counts {
                chunks: 57,
                transcript: 13,
                digits: 1,
            },
            _ => panic!("the aggregator profile pins no circuit counts for this header size"),
        }
    }

    /// The nested chunk circuits of the decompression, the same for every
    /// header size: none run transcript chunks, and the digits chunks come
    /// last.
    pub const NESTED_CIRCUITS: Counts = Counts {
        chunks: 32,
        transcript: 0,
        digits: 1,
    };

    /// The endoscalings a step of either walk performs: what fits a step at
    /// the aggregator rank beside the stages it reserves, which cuts the
    /// walks and with them the proof's polynomials by more than the ratio
    /// to the production rank's four, since the sides size each other.
    pub const ENDOSCALINGS_PER_STEP: usize = 14;

    /// Checks that the hooks register at the aggregator rank for the
    /// profile's header size.
    fn accepts<R: Rank>(header_size: usize) -> Result<()> {
        if R::RANK != AggregatorRank::RANK {
            return Err(Error::Initialization(
                "the aggregator profile proves at the aggregator rank".into(),
            ));
        }
        if header_size != HEADER_SIZE {
            return Err(Error::Initialization(
                "the aggregator profile's header size is not the application's".into(),
            ));
        }
        Ok(())
    }
}

impl<const HEADER_SIZE: usize> Profile for Aggregator<HEADER_SIZE> {
    const NAME: &'static str = "aggregator";
    // The chunk circuits, the statement and binding circuits and the
    // stages on the native side; the chunk circuits, the binding circuit
    // and the stages on the nested side.
    const NATIVE_EXTENSION: usize =
        Self::native_circuits(HEADER_SIZE).chunks + 2 + extension::NATIVE_STAGES;
    const NESTED_EXTENSION: usize = Self::NESTED_CIRCUITS.chunks + 1 + extension::NESTED_STAGES;

    const NATIVE_ENDOSCALINGS_PER_STEP: usize = Self::ENDOSCALINGS_PER_STEP;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = Self::ENDOSCALINGS_PER_STEP;

    type Context<'params, Base, R, B>
        = Decompression<'params, Base, R, HEADER_SIZE, B>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    fn native_extension() -> Extension {
        extension::native_layout(Self::native_circuits(HEADER_SIZE))
    }

    fn nested_extension() -> Extension {
        extension::nested_layout(Self::NESTED_CIRCUITS)
    }

    fn register_native_circuit<'params, Base, R: Rank, const H: usize>(
        circuit: usize,
        registry: RegistryBuilder<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        extension::register_native_circuit::<Base, ProductionRank, R, H>(
            circuit,
            Self::native_circuits(HEADER_SIZE),
            registry,
            params,
        )
    }

    fn register_native_bonding<'params, Base, R: Rank, const H: usize>(
        bonding: usize,
        registry: RegistryBuilder<'params, Base::CircuitField, R>,
        _: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(H)?;
        extension::register_native_bonding::<Base, ProductionRank, R, H>(bonding, registry)
    }

    fn register_nested_circuit<'params, Base, R: Rank>(
        circuit: usize,
        registry: RegistryBuilder<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(HEADER_SIZE)?;
        extension::register_nested_circuit::<Base, ProductionRank, R, HEADER_SIZE>(
            circuit,
            Self::NESTED_CIRCUITS,
            registry,
            params,
        )
    }

    fn register_nested_bonding<'params, Base, R: Rank>(
        bonding: usize,
        registry: RegistryBuilder<'params, Base::ScalarField, R>,
        _: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        Self::accepts::<R>(HEADER_SIZE)?;
        extension::register_nested_bonding::<Base, ProductionRank, R, HEADER_SIZE>(
            bonding, registry,
        )
    }

    fn native_extension_rxs<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        registry: &Registry<'params, Base::CircuitField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        Self::accepts::<R>(H)?;
        context.native_rxs::<Self>(source, registry, rng)
    }

    fn nested_extension_rxs<'params, Base, R, const H: usize, B, RNG>(
        context: &Self::Context<'params, Base, R, B>,
        source: Option<&Decompressed<Base>>,
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        Self::accepts::<R>(H)?;
        context.nested_rxs::<Self>(source, registry, rng)
    }
}

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
/// [`Pasta`], so an application over one never accepts the other's proofs.
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
/// at four endoscalings per step, a native step adds about a quarter of a
/// native step, so the map from a step count to the count the batch then
/// needs is a contraction with one fixed point, which [`Shape::solve`] finds
/// by iteration; more endoscalings per step contract faster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// The native rx polynomials: the fixed ones, the walk's steps and the
    /// profile's extension.
    pub native_rx: usize,
    /// The nested-curve points the nested walk folds: the native batch.
    pub nested_points: usize,
    /// The nested walk's steps.
    pub nested_steps: usize,
    /// The nested rx polynomials.
    pub nested_rx: usize,
    /// The host-curve points the native walk folds: the nested batch.
    pub native_points: usize,
    /// The native walk's steps: the fixed point, where the count the batch
    /// needs is the count the native rx polynomials were sized with.
    pub native_steps: usize,
}

impl Shape {
    /// The shape of profile `P`.
    pub const fn of<P: Profile>() -> Self {
        Self::solve(
            P::NATIVE_EXTENSION,
            P::NESTED_EXTENSION,
            P::NATIVE_ENDOSCALINGS_PER_STEP,
            P::NESTED_ENDOSCALINGS_PER_STEP,
        )
    }

    /// Solves the walk sizes for the given extensions at the given
    /// endoscalings per native and nested step, iterating the native step
    /// count to its fixed point.
    pub const fn solve(
        native_extension: usize,
        nested_extension: usize,
        native_endoscalings: usize,
        nested_endoscalings: usize,
    ) -> Self {
        let mut native_steps = 1;
        let mut rounds = 0;
        loop {
            let shape = Self::with_native_steps(
                native_steps,
                native_extension,
                nested_extension,
                native_endoscalings,
                nested_endoscalings,
            );
            if shape.native_steps == native_steps {
                return shape;
            }
            rounds += 1;
            assert!(rounds < 64, "the walk sizes did not converge");
            native_steps = shape.native_steps;
        }
    }

    /// One pass around the cycle: the shape that `native_steps` native steps
    /// imply, whose `native_steps` is the count the resulting batch needs.
    const fn with_native_steps(
        native_steps: usize,
        native_extension: usize,
        nested_extension: usize,
        native_endoscalings: usize,
        nested_endoscalings: usize,
    ) -> Self {
        let native_rx = native::NUM_FIXED_RX + native_steps + native_extension;
        let nested_points = nested::num_endoscaling_points(native_rx);
        let nested_steps = endoscalar::num_steps(nested_endoscalings, nested_points);
        let nested_rx = nested::NUM_FIXED_RX + nested_steps + nested_extension;
        let native_points = nested::pcs::num_batched_points(nested_rx);
        let native_steps = endoscalar::num_steps(native_endoscalings, native_points);
        Shape {
            native_rx,
            nested_points,
            nested_steps,
            nested_rx,
            native_points,
            native_steps,
        }
    }

    /// Every polynomial a proof of this shape carries: both sides' rx
    /// polynomials and, on each side, $a$, $b$, `registry_xy` and $p$.
    pub const fn polynomials(&self) -> usize {
        self.native_rx + 4 + self.nested_rx + 4
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
pub(crate) mod testing {
    use alloc::vec;

    use ragu_circuits::{
        Circuit, CircuitExt, WithAux,
        registry::CircuitIndex,
        staging::{MultiStage, MultiStageCircuit, Stage, StageBuilder, StageExt},
    };
    use ragu_core::{
        Coeff, FixedGenerators,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_primitives::{
        Boolean, Element, NonzeroBank, Point, allocator,
        vec::{ConstLen, FixedVec},
    };
    use udon::curve::EndomorphismAffine as Affine;

    use super::*;
    use crate::step::{Encoded, Index, Step};

    /// A step with unit headers and no witness.
    pub(crate) struct UnitStep;

    impl<C: Cycle> Step<C> for UnitStep {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = ();

        fn witness<
            'dr,
            'source: 'dr,
            D: Driver<'dr, F = C::CircuitField>,
            const HEADER_SIZE: usize,
        >(
            &self,
            dr: &mut D,
            _: DriverValue<D, ()>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, (), HEADER_SIZE>,
                Encoded<'dr, D, (), HEADER_SIZE>,
                Encoded<'dr, D, (), HEADER_SIZE>,
            ),
            DriverValue<D, ()>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut allocator::Standard::new();
            let left = Encoded::new(dr, allocator, left)?;
            let right = Encoded::new(dr, allocator, right)?;
            Ok((
                (left, right, Encoded::from_gadget(())),
                D::unit(),
                D::unit(),
            ))
        }
    }

    /// Two native circuits over two stages, each under its last stage's
    /// final mask, and one nested circuit over one stage under one final
    /// mask, declared but without hooks.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Wider;

    impl Profile for Wider {
        const NAME: &'static str = "wider";
        const NATIVE_EXTENSION: usize = 4;
        const NESTED_EXTENSION: usize = 2;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![0], vec![0, 1]],
                stages: 2,
                final_masks: vec![vec![0], vec![1]],
                statement: None,
                binding: None,
            }
        }

        fn nested_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
                statement: None,
                binding: None,
            }
        }
    }

    /// [`Wider`]'s native side with its second circuit declared the
    /// statement circuit, so that the profile registers the statement step.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Stated;

    impl Profile for Stated {
        const NAME: &'static str = "stated";
        const NATIVE_EXTENSION: usize = 4;
        const NESTED_EXTENSION: usize = 0;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![0], vec![0, 1]],
                stages: 2,
                final_masks: vec![vec![0], vec![1]],
                statement: Some(1),
                binding: None,
            }
        }
    }

    /// Declares one rx polynomial and no extension.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Mismatched;

    impl Profile for Mismatched {
        const NAME: &'static str = "mismatched";
        const NATIVE_EXTENSION: usize = 1;
        const NESTED_EXTENSION: usize = 0;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;
    }

    /// One circuit over one stage under one final mask on each side, with
    /// hooks that register the fuse's own circuits and stages as stand-ins.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Hooked;

    impl Profile for Hooked {
        const NAME: &'static str = "hooked";
        const NATIVE_EXTENSION: usize = 2;
        const NESTED_EXTENSION: usize = 2;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
                statement: None,
                binding: None,
            }
        }

        fn nested_extension() -> Extension {
            Self::native_extension()
        }

        fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            slot.register(native::circuits::bind_endoscalar::Circuit::<Base, R>::new())
        }

        fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            bonding: usize,
            slot: BondingSlot<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            type Stage<C, R, const H: usize> = native::stages::eval::Stage<C, R, H>;
            let mask = match bonding {
                0 => Stage::<Base, R, HEADER_SIZE>::mask()?,
                1 => Stage::<Base, R, HEADER_SIZE>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(slot.register(mask))
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            let circuit = nested::circuits::export::Circuit::<Base::HostCurve, R, Standard>::new();
            slot.register(MultiStage::new(circuit))
        }

        fn register_nested_bonding<'params, Base, R: Rank>(
            bonding: usize,
            slot: BondingSlot<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            type Stage<C, R> = nested::stages::eval::Stage<<C as Cycle>::HostCurve, R, Standard>;
            let mask = match bonding {
                0 => Stage::<Base, R>::mask()?,
                1 => Stage::<Base, R>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(slot.register(mask))
        }
    }

    /// One boolean wire: a circuit over any field, with no instance, that
    /// [`Proving`]'s hooks register on each side.
    pub(crate) struct Trivial<F>(PhantomData<fn() -> F>);

    impl<F> Trivial<F> {
        pub(crate) const fn new() -> Self {
            Trivial(PhantomData)
        }
    }

    impl<F: Field> Circuit<F> for Trivial<F> {
        type Instance<'source> = ();
        type Witness<'source> = ();
        type Output = ();
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Instance<'source>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Ok(())
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        {
            let (bit, square) = Element::alloc_square(dr, D::just(|| F::ONE))?;
            bit.add_coeff(dr, &square, Coeff::NegativeOne)
                .enforce_zero(dr)?;
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// The rx polynomial of a [`Trivial`] circuit at `circuit` in
    /// `registry`, as an extension's only polynomial.
    fn trivial_rxs<F: Field, R: Rank>(
        registry: &Registry<'_, F, R>,
        circuit: CircuitIndex,
        rng: &mut impl CryptoRng,
    ) -> Result<ExtensionRxs<F, R>> {
        let (trace, ()) = Trivial::<F>::new().trace(())?.into_parts();
        Ok(ExtensionRxs {
            circuits: vec![registry.assemble(&trace, circuit, rng)?],
            stages: Vec::new(),
        })
    }

    /// One [`Trivial`] circuit and no stage on each side, with the hooks
    /// that register and prove it: the profile whose extension proves, at
    /// a rank above the production one, where the fuse has room for its
    /// two polynomials.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Proving;

    impl Profile for Proving {
        const NAME: &'static str = "proving";
        const NATIVE_EXTENSION: usize = 1;
        const NESTED_EXTENSION: usize = 1;

        type Context<'params, Base, R, B>
            = ()
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![]],
                stages: 0,
                final_masks: vec![],
                statement: None,
                binding: None,
            }
        }

        fn nested_extension() -> Extension {
            Self::native_extension()
        }

        fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            slot.register(Trivial::<Base::CircuitField>::new())
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            slot.register(Trivial::<Base::ScalarField>::new())
        }

        fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            _: &Self::Context<'params, Base, R, B>,
            _: Option<&Decompressed<Base>>,
            registry: &Registry<'params, Base::CircuitField, R>,
            rng: &mut RNG,
        ) -> Result<ExtensionRxs<Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend,
            RNG: CryptoRng,
        {
            let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
            trivial_rxs(registry, circuit.circuit_index::<Self>(), rng)
        }

        fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            _: &Self::Context<'params, Base, R, B>,
            _: Option<&Decompressed<Base>>,
            registry: &Registry<'params, Base::ScalarField, R>,
            rng: &mut RNG,
        ) -> Result<ExtensionRxs<Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend,
            RNG: CryptoRng,
        {
            let circuit = nested::InternalCircuitIndex::ExtensionCircuit(0);
            trivial_rxs(registry, circuit.circuit_index::<Self>(), rng)
        }
    }

    /// The digits [`Crossing`] sends across the cycle: few, so that summing
    /// their generators is a few gates.
    pub(crate) const DIGITS: usize = 4;

    /// The nested side's one stage under [`Crossing`]: the signed digits,
    /// each $\pm 1$.
    pub(crate) struct DigitsStage<F, R>(PhantomData<fn() -> (F, R)>);

    impl<F, R> Default for DigitsStage<F, R> {
        fn default() -> Self {
            DigitsStage(PhantomData)
        }
    }

    impl<F: Field, R: Rank> Stage<F, R> for DigitsStage<F, R> {
        type Parent = ();
        type Witness<'source> = &'source [F; DIGITS];
        type OutputKind = Kind![F; FixedVec<Element<'_, _>, ConstLen<DIGITS>>];

        fn values() -> usize {
            DIGITS
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            FixedVec::try_from_fn(|i| {
                Element::alloc(dr, &mut (), witness.as_ref().map(|digits| digits[i]))
            })
        }
    }

    /// The nested side's one circuit under [`Crossing`]: over the digits
    /// stage, holding each digit to $\pm 1$.
    pub(crate) struct DigitsCircuit<F, R>(PhantomData<fn() -> (F, R)>);

    impl<F: Field, R: Rank> MultiStageCircuit<F, R> for DigitsCircuit<F, R> {
        type Last = DigitsStage<F, R>;
        type Instance<'source> = ();
        type Witness<'source> = &'source [F; DIGITS];
        type Output = Kind![F; ()];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Instance<'source>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Ok(())
        }

        fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
            &self,
            dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        where
            Self: 'dr,
        {
            let (digits, dr) = dr.add_stage::<DigitsStage<F, R>>()?;
            let dr = dr.finish();
            let digits = digits.unenforced(dr, witness)?;
            for digit in digits.iter() {
                digit
                    .square(dr)?
                    .add_coeff(dr, &Element::one(), Coeff::NegativeOne)
                    .enforce_zero(dr)?;
            }
            Ok(WithAux::new((), D::unit()))
        }
    }

    /// The binding circuit under [`Crossing`] and [`CrossingBack`], on the
    /// side without the digits stage: its public output is the digits
    /// stage's commitment recomputed from the bits it is given, the digits'
    /// generators summed by sign, as the other side's digit $2b - 1$ scales
    /// its generator.
    pub(crate) struct BitsCircuit<P> {
        /// Each digit's generator: the digits stage's commitment with that
        /// digit one and the others zero.
        generators: Vec<P>,
    }

    impl<P: Affine> BitsCircuit<P> {
        /// The circuit over the digits stage's generators at rank `R`, the
        /// stage committed with `generators`: the other side's, the nested
        /// ones for a native circuit and the host ones for a nested one.
        fn new<R: Rank>(generators: &impl FixedGenerators<P>) -> Result<Self> {
            let zeros = [P::Scalar::ZERO; DIGITS];
            let commit = |digits: &[P::Scalar; DIGITS]| {
                DigitsStage::<P::Scalar, R>::rx(P::Scalar::ZERO, digits)
                    .map(|rx| rx.commit_to_affine(generators))
            };
            assert!(
                commit(&zeros)?.coordinates().is_none(),
                "the digits stage has no term beyond the digits"
            );
            let generators = (0..DIGITS)
                .map(|i| {
                    let mut digits = zeros;
                    digits[i] = P::Scalar::ONE;
                    commit(&digits)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(BitsCircuit { generators })
        }
    }

    impl<P: Affine> Circuit<P::Base> for BitsCircuit<P> {
        type Instance<'source> = P;
        type Witness<'source> = &'source [bool; DIGITS];
        type Output = Kind![P::Base; Point<'_, _, P>];
        type Aux<'source> = ();

        fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = P::Base>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'source>>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Point::alloc(dr, instance)
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = P::Base>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
        {
            let sum = NonzeroBank::scope(dr, |dr, bank| {
                let mut sum: Option<Point<'dr, D, P>> = None;
                for (i, &generator) in self.generators.iter().enumerate() {
                    let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|bits| bits[i]))?;
                    let negate = bit.not(dr);
                    let term = Point::constant(dr, generator)?.conditional_negate(dr, &negate)?;
                    sum = Some(match sum {
                        None => term,
                        Some(sum) => sum.add_incomplete(dr, &term, bank)?,
                    });
                }
                sum.ok_or_else(|| Error::InvalidWitness("a digit".into()))
            })?;
            Ok(WithAux::new(sum, D::unit()))
        }
    }

    /// What [`Crossing`]'s prover holds: the parameters, for the digits'
    /// generators, and each side's bits, so that a test can hand the two
    /// sides different values.
    pub(crate) struct CrossingContext<'params, Base: Cycle> {
        pub(crate) params: &'params Base::Params,
        pub(crate) native: [bool; DIGITS],
        pub(crate) nested: [bool; DIGITS],
    }

    /// The signed digits of `bits`: $2b - 1$ each.
    fn signed<F: Field>(bits: &[bool; DIGITS]) -> [F; DIGITS] {
        bits.map(|bit| if bit { F::ONE } else { -F::ONE })
    }

    /// One binding circuit and no stage on the native side, exposing the
    /// digits stage's commitment recomputed from the native bits, and one
    /// circuit over the digits stage on the nested side, holding the
    /// nested bits' signed digits: the profile whose two sides a test can
    /// make agree or disagree, at a rank above the production one.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Crossing;

    impl Profile for Crossing {
        const NAME: &'static str = "crossing";
        const NATIVE_EXTENSION: usize = 1;
        const NESTED_EXTENSION: usize = 2;

        type Context<'params, Base, R, B>
            = CrossingContext<'params, Base>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![]],
                stages: 0,
                final_masks: vec![],
                statement: None,
                binding: Some(Binding {
                    circuit: 0,
                    stages: vec![0],
                }),
            }
        }

        fn nested_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
                statement: None,
                binding: None,
            }
        }

        fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::CircuitField, R>,
            params: &'params Base::Params,
        ) -> Result<Registered<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            let generators = Base::nested_generators(params);
            slot.register(BitsCircuit::<Base::NestedCurve>::new::<R>(generators)?)
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            slot.register(MultiStage::new(DigitsCircuit::<Base::ScalarField, R>(
                PhantomData,
            )))
        }

        fn register_nested_bonding<'params, Base, R: Rank>(
            bonding: usize,
            slot: BondingSlot<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            let mask = match bonding {
                0 => DigitsStage::<Base::ScalarField, R>::mask()?,
                1 => DigitsStage::<Base::ScalarField, R>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(slot.register(mask))
        }

        fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            context: &Self::Context<'params, Base, R, B>,
            _: Option<&Decompressed<Base>>,
            registry: &Registry<'params, Base::CircuitField, R>,
            rng: &mut RNG,
        ) -> Result<ExtensionRxs<Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend,
            RNG: CryptoRng,
        {
            let generators = Base::nested_generators(context.params);
            let (trace, ()) = BitsCircuit::<Base::NestedCurve>::new::<R>(generators)?
                .trace(&context.native)?
                .into_parts();
            let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
            Ok(ExtensionRxs {
                circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
                stages: Vec::new(),
            })
        }

        fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            context: &Self::Context<'params, Base, R, B>,
            _: Option<&Decompressed<Base>>,
            registry: &Registry<'params, Base::ScalarField, R>,
            rng: &mut RNG,
        ) -> Result<ExtensionRxs<Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend,
            RNG: CryptoRng,
        {
            let digits = signed::<Base::ScalarField>(&context.nested);
            let (trace, ()) = MultiStage::new(DigitsCircuit::<Base::ScalarField, R>(PhantomData))
                .trace(&digits)?
                .into_parts();
            let circuit = nested::InternalCircuitIndex::ExtensionCircuit(0);
            Ok(ExtensionRxs {
                circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
                // Unblinded, so that the native side can recompute it.
                stages: vec![DigitsStage::<Base::ScalarField, R>::rx(
                    Base::ScalarField::ZERO,
                    &digits,
                )?],
            })
        }
    }

    /// [`Crossing`] the other way round: one circuit over the digits stage
    /// on the native side, holding the native bits' signed digits, and one
    /// binding circuit and no stage on the nested side, exposing that
    /// stage's commitment recomputed from the nested bits, so that the
    /// nested side binds.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct CrossingBack;

    impl Profile for CrossingBack {
        const NAME: &'static str = "crossing back";
        const NATIVE_EXTENSION: usize = 2;
        const NESTED_EXTENSION: usize = 1;

        type Context<'params, Base, R, B>
            = CrossingContext<'params, Base>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend;

        fn native_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
                statement: None,
                binding: None,
            }
        }

        fn nested_extension() -> Extension {
            Extension {
                circuits: vec![vec![]],
                stages: 0,
                final_masks: vec![],
                statement: None,
                binding: Some(Binding {
                    circuit: 0,
                    stages: vec![0],
                }),
            }
        }

        fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            slot.register(MultiStage::new(DigitsCircuit::<Base::CircuitField, R>(
                PhantomData,
            )))
        }

        fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            bonding: usize,
            slot: BondingSlot<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<Registered<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            let mask = match bonding {
                0 => DigitsStage::<Base::CircuitField, R>::mask()?,
                1 => DigitsStage::<Base::CircuitField, R>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(slot.register(mask))
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            slot: CircuitSlot<'params, Base::ScalarField, R>,
            params: &'params Base::Params,
        ) -> Result<Registered<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            let generators = Base::host_generators(params);
            slot.register(BitsCircuit::<Base::HostCurve>::new::<R>(generators)?)
        }

        fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            context: &Self::Context<'params, Base, R, B>,
            registry: &Registry<'params, Base::CircuitField, R>,
            rng: &mut RNG,
        ) -> Result<ExtensionRxs<Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend,
            RNG: CryptoRng,
        {
            let digits = signed::<Base::CircuitField>(&context.native);
            let (trace, ()) = MultiStage::new(DigitsCircuit::<Base::CircuitField, R>(PhantomData))
                .trace(&digits)?
                .into_parts();
            let circuit = native::InternalCircuitIndex::ExtensionCircuit(0);
            Ok(ExtensionRxs {
                circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
                // Unblinded, so that the nested side can recompute it.
                stages: vec![DigitsStage::<Base::CircuitField, R>::rx(
                    Base::CircuitField::ZERO,
                    &digits,
                )?],
            })
        }

        fn nested_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            context: &Self::Context<'params, Base, R, B>,
            registry: &Registry<'params, Base::ScalarField, R>,
            rng: &mut RNG,
        ) -> Result<ExtensionRxs<Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
            R: Rank,
            B: SelectableBackend,
            RNG: CryptoRng,
        {
            let generators = Base::host_generators(context.params);
            let (trace, ()) = BitsCircuit::<Base::HostCurve>::new::<R>(generators)?
                .trace(&context.nested)?
                .into_parts();
            let circuit = nested::InternalCircuitIndex::ExtensionCircuit(0);
            Ok(ExtensionRxs {
                circuits: vec![registry.assemble(&trace, circuit.circuit_index::<Self>(), rng)?],
                stages: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use ragu_circuits::polynomials::R;

    use super::{
        testing::{Crossing, CrossingBack, CrossingContext, Mismatched, Wider},
        *,
    };

    #[test]
    fn declared_extensions_check() {
        Standard::check().unwrap();
        Aggregator::<4>::check().unwrap();
        Aggregator::<103>::check().unwrap();
        assert!(Aggregator::<4>::native_extension().is_consistent());
        assert!(Aggregator::<4>::nested_extension().is_consistent());
        Wider::check().unwrap();
        Crossing::check().unwrap();
        CrossingBack::check().unwrap();
        assert!(Wider::native_extension().is_consistent());
        assert!(Wider::nested_extension().is_consistent());
        assert!(Mismatched::check().is_err());
    }

    /// A declaration is well formed only with every index in range, nothing
    /// named twice, every staged circuit under exactly one final mask, its
    /// last stage's, and a binding circuit other than the statement circuit
    /// naming at least one stage, none twice.
    #[test]
    fn consistency_binds_every_staged_circuit() {
        use alloc::vec;

        let extension = |circuits, stages, final_masks, statement| Extension {
            circuits,
            stages,
            final_masks,
            statement,
            binding: None,
        };
        // Two staged circuits, each under its last stage's final mask, one
        // without stages under none, and a statement circuit.
        assert!(
            extension(
                vec![vec![0], vec![0, 1], vec![]],
                2,
                vec![vec![0], vec![1]],
                Some(1)
            )
            .is_consistent()
        );
        // A stage, a circuit or a statement circuit out of range.
        assert!(!extension(vec![vec![2]], 2, vec![vec![0]], None).is_consistent());
        assert!(!extension(vec![vec![0]], 1, vec![vec![1]], None).is_consistent());
        assert!(!extension(vec![vec![0]], 1, vec![vec![0]], Some(1)).is_consistent());
        // A staged circuit under no final mask, or under two.
        assert!(!extension(vec![vec![0], vec![0]], 1, vec![vec![0]], None).is_consistent());
        assert!(!extension(vec![vec![0]], 1, vec![vec![0], vec![0]], None).is_consistent());
        // A circuit without stages under a final mask, and an empty one.
        assert!(!extension(vec![vec![]], 1, vec![vec![0]], None).is_consistent());
        assert!(!extension(vec![vec![0]], 1, vec![vec![0], vec![]], None).is_consistent());
        // One final mask over circuits with different last stages.
        assert!(!extension(vec![vec![0], vec![0, 1]], 2, vec![vec![0, 1]], None).is_consistent());
        // A stage or a circuit named twice.
        assert!(!extension(vec![vec![0, 0]], 1, vec![vec![0]], None).is_consistent());
        assert!(!extension(vec![vec![0]], 1, vec![vec![0, 0]], None).is_consistent());

        // Two circuits without stages, the first the statement circuit and
        // the second binding the other side's stages, which the other side
        // is to have.
        let binding = |circuit, stages| Extension {
            circuits: vec![vec![], vec![]],
            stages: 0,
            final_masks: vec![],
            statement: Some(0),
            binding: Some(Binding { circuit, stages }),
        };
        assert!(binding(1, vec![1, 0]).is_consistent());
        // The binding circuit out of range, or the statement circuit.
        assert!(!binding(2, vec![0]).is_consistent());
        assert!(!binding(0, vec![0]).is_consistent());
        // The binding naming no stage, or one twice.
        assert!(!binding(1, vec![]).is_consistent());
        assert!(!binding(1, vec![0, 0]).is_consistent());
    }

    /// The profile's checks refuse a malformed extension, a statement
    /// circuit on the nested side, and a binding naming a stage the other
    /// side does not have, from either side.
    #[test]
    fn malformed_declarations_are_refused() {
        use alloc::vec;

        /// A statement circuit past the circuits.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        struct StrayStatement;

        impl Profile for StrayStatement {
            const NAME: &'static str = "stray statement";
            const NATIVE_EXTENSION: usize = 2;
            const NESTED_EXTENSION: usize = 0;

            type Context<'params, Base, R, B>
                = ()
            where
                Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                R: Rank,
                B: SelectableBackend;

            fn native_extension() -> Extension {
                Extension {
                    circuits: vec![vec![0]],
                    stages: 1,
                    final_masks: vec![vec![0]],
                    statement: Some(1),
                    binding: None,
                }
            }
        }

        /// A statement circuit on the nested side.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        struct NestedStatement;

        impl Profile for NestedStatement {
            const NAME: &'static str = "nested statement";
            const NATIVE_EXTENSION: usize = 0;
            const NESTED_EXTENSION: usize = 2;

            type Context<'params, Base, R, B>
                = ()
            where
                Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                R: Rank,
                B: SelectableBackend;

            fn nested_extension() -> Extension {
                Extension {
                    circuits: vec![vec![0]],
                    stages: 1,
                    final_masks: vec![vec![0]],
                    statement: Some(0),
                    binding: None,
                }
            }
        }

        /// [`Crossing`] with its native binding naming one nested stage
        /// past the one the nested side has.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        struct StrayBinding;

        impl Profile for StrayBinding {
            const NAME: &'static str = "stray binding";
            const NATIVE_EXTENSION: usize = 1;
            const NESTED_EXTENSION: usize = 2;

            type Context<'params, Base, R, B>
                = ()
            where
                Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                R: Rank,
                B: SelectableBackend;

            fn native_extension() -> Extension {
                Extension {
                    circuits: vec![vec![]],
                    stages: 0,
                    final_masks: vec![],
                    statement: None,
                    binding: Some(Binding {
                        circuit: 0,
                        stages: vec![0, 1],
                    }),
                }
            }

            fn nested_extension() -> Extension {
                Crossing::nested_extension()
            }
        }

        /// [`CrossingBack`] with its nested binding naming one native stage
        /// past the one the native side has.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        struct StrayNestedBinding;

        impl Profile for StrayNestedBinding {
            const NAME: &'static str = "stray nested binding";
            const NATIVE_EXTENSION: usize = 2;
            const NESTED_EXTENSION: usize = 1;

            type Context<'params, Base, R, B>
                = ()
            where
                Base: IpaCycle + ProfiledCycle<Profile = Standard>,
                R: Rank,
                B: SelectableBackend;

            fn native_extension() -> Extension {
                CrossingBack::native_extension()
            }

            fn nested_extension() -> Extension {
                Extension {
                    circuits: vec![vec![]],
                    stages: 0,
                    final_masks: vec![],
                    statement: None,
                    binding: Some(Binding {
                        circuit: 0,
                        stages: vec![1],
                    }),
                }
            }
        }

        assert!(StrayStatement::check().is_err());
        assert!(NestedStatement::check().is_err());
        assert!(StrayBinding::check().is_err());
        assert!(StrayNestedBinding::check().is_err());
    }

    #[test]
    fn extension_entries_take_their_places() {
        use native::{InternalCircuitIndex as NativeCircuit, RxIndex as NativeRx};
        use nested::{InternalCircuitIndex as NestedCircuit, RxIndex as NestedRx};

        // The extension lengthens the walks too, so count from the shape.
        let shape = Shape::of::<Wider>();
        let circuits = NativeCircuit::all::<Wider>();
        assert_eq!(circuits.len(), NativeCircuit::num::<Wider>());
        assert_eq!(
            circuits.len(),
            native::NUM_FIXED_INTERNAL + shape.native_steps + 6
        );
        let last_step = circuits
            .iter()
            .rposition(|id| matches!(id, NativeCircuit::EndoscalingStep(_)))
            .unwrap();
        assert_eq!(
            circuits[last_step + 1..last_step + 3],
            [
                NativeCircuit::ExtensionCircuit(0),
                NativeCircuit::ExtensionCircuit(1)
            ]
        );
        assert_eq!(
            circuits[circuits.len() - 4..],
            [
                NativeCircuit::ExtensionBonding(0),
                NativeCircuit::ExtensionBonding(1),
                NativeCircuit::ExtensionBonding(2),
                NativeCircuit::ExtensionBonding(3),
            ]
        );
        assert_eq!(
            NativeCircuit::ExtensionCircuit(1).circuit_index::<Wider>(),
            ragu_circuits::registry::CircuitIndex::new(last_step + 2)
        );

        let rx = NativeRx::all::<Wider>();
        assert_eq!(rx.len(), NativeRx::num::<Wider>());
        assert_eq!(rx.len(), native::NUM_FIXED_RX + shape.native_steps + 4);
        assert_eq!(
            rx[rx.len() - 4..],
            [
                NativeRx::ExtensionCircuit(0),
                NativeRx::ExtensionCircuit(1),
                NativeRx::ExtensionStage(0),
                NativeRx::ExtensionStage(1),
            ]
        );

        let circuits = NestedCircuit::all::<Wider>();
        assert_eq!(circuits.len(), NestedCircuit::num::<Wider>());
        assert_eq!(
            circuits.len(),
            nested::NUM_FIXED_INTERNAL + shape.nested_steps + 3
        );
        let compute_v = circuits
            .iter()
            .position(|&id| id == NestedCircuit::ComputeV)
            .unwrap();
        assert_eq!(circuits[compute_v + 1], NestedCircuit::ExtensionCircuit(0));
        assert_eq!(
            circuits[circuits.len() - 2..],
            [
                NestedCircuit::ExtensionBonding(0),
                NestedCircuit::ExtensionBonding(1)
            ]
        );
        let rx = NestedRx::all::<Wider>();
        assert_eq!(rx.len(), nested::NUM_FIXED_RX + shape.nested_steps + 2);
        assert_eq!(
            rx[rx.len() - 2..],
            [NestedRx::ExtensionCircuit(0), NestedRx::ExtensionStage(0)]
        );
    }

    #[test]
    fn shape_follows_the_declared_extension() {
        assert_eq!(Shape::of::<Wider>(), Shape::solve(4, 2, 4, 4));
        assert_ne!(Shape::of::<Wider>(), Shape::of::<Standard>());
        assert_eq!(
            native::RxIndex::num::<Wider>(),
            Shape::of::<Wider>().native_rx
        );
        assert_eq!(
            nested::RxIndex::num::<Wider>(),
            Shape::of::<Wider>().nested_rx
        );
    }

    #[test]
    fn standard_is_the_crate_layout() {
        let shape = Shape::of::<Standard>();
        assert_eq!(
            shape,
            Shape {
                native_rx: 49,
                nested_points: 113,
                nested_steps: 28,
                nested_rx: 42,
                native_points: 99,
                native_steps: 25,
            }
        );
        assert_eq!(shape.polynomials(), 99);
    }

    /// The aggregator's shape follows its pinned circuits, and grows with
    /// the header size through the transcript circuits.
    #[test]
    fn aggregator_declares_the_decompression() {
        let shape = Shape::of::<Aggregator<4>>();
        let per_step = Aggregator::<4>::ENDOSCALINGS_PER_STEP;
        assert_eq!(
            shape,
            Shape::solve(52 + 2 + 6, 32 + 1 + 5, per_step, per_step)
        );
        assert_eq!(
            Shape::of::<Aggregator<103>>(),
            Shape::solve(57 + 2 + 6, 32 + 1 + 5, per_step, per_step)
        );
        // The knob: at the production rank's four per step the walks are
        // far longer.
        assert!(shape.polynomials() < Shape::solve(52 + 2 + 6, 32 + 1 + 5, 4, 4).polynomials());
        assert!(shape.polynomials() > Shape::of::<Standard>().polynomials());
        std::println!(
            "aggregator at header size 4: {shape:?}, {} polynomials",
            shape.polynomials()
        );
    }

    /// The hooks register only at the aggregator rank, and only for the
    /// profile's header size.
    #[test]
    fn aggregator_hooks_refuse_other_parameters() {
        let params = crate::pasta::baked();
        let at_production_rank = Aggregator::<4>::register_native_circuit::<Pasta, ProductionRank, 4>(
            0,
            RegistryBuilder::new(),
            params,
        );
        assert!(matches!(at_production_rank, Err(Error::Initialization(_))));
        let other_header = Aggregator::<4>::register_native_circuit::<Pasta, AggregatorRank, 103>(
            0,
            RegistryBuilder::new(),
            params,
        );
        assert!(matches!(other_header, Err(Error::Initialization(_))));
        let nested_at_production_rank = Aggregator::<4>::register_nested_circuit::<
            Pasta,
            ProductionRank,
        >(0, RegistryBuilder::new(), params);
        assert!(matches!(
            nested_at_production_rank,
            Err(Error::Initialization(_))
        ));
    }

    #[test]
    fn pasta_proves_in_the_standard_profile() {
        assert_eq!(
            Shape::of::<<Pasta as ProfiledCycle>::Profile>(),
            Shape::of::<Standard>()
        );
        assert_eq!(
            Shape::of::<<Profiled<Pasta, Aggregator<4>> as ProfiledCycle>::Profile>(),
            Shape::of::<Aggregator<4>>()
        );
    }

    #[test]
    fn solve_finds_a_fixed_point_for_wider_profiles() {
        for (native_extension, nested_extension) in
            [(0, 0), (1, 0), (0, 1), (10, 10), (134, 116), (300, 300)]
        {
            let shape = Shape::solve(native_extension, nested_extension, 4, 4);
            let again = Shape::with_native_steps(
                shape.native_steps,
                native_extension,
                nested_extension,
                4,
                4,
            );
            assert_eq!(
                again, shape,
                "({native_extension}, {nested_extension}) is not fixed"
            );
        }
    }

    #[test]
    fn extensions_lengthen_both_walks() {
        // Each extra rx polynomial is two points in the other walk (one per
        // child), so a step there per two, and a quarter of a step back: an
        // extension costs about twice its own count in polynomials overall.
        let base = Shape::solve(0, 0, 4, 4);
        let wider = Shape::solve(100, 0, 4, 4);
        assert!(wider.nested_steps > base.nested_steps);
        assert!(wider.native_steps > base.native_steps);
        let extra = wider.polynomials() - base.polynomials();
        assert!(
            (150..=250).contains(&extra),
            "100 native polynomials cost {extra} overall"
        );
    }

    /// An extension proves: an application in the [`Proving`] profile,
    /// one trivial circuit on each side, seeds, fuses, verifies and
    /// compresses at the rank above the production one, where the fuse
    /// has room for the two polynomials.
    #[test]
    fn an_extension_proves_verifies_and_compresses() -> Result<()> {
        use rand::{SeedableRng, rngs::StdRng};

        use super::testing::{Proving, UnitStep};
        use crate::ApplicationBuilder;

        const HEADER_SIZE: usize = 4;
        assert_ne!(Shape::of::<Proving>(), Shape::of::<Standard>());

        let app = ApplicationBuilder::<Profiled<Pasta, Proving>, R<14>, HEADER_SIZE>::new()
            .register(UnitStep)?
            .finalize(crate::pasta::baked())?;
        let mut rng = StdRng::seed_from_u64(14);
        let (left, ()) = app.seed(&mut rng, UnitStep, ())?;
        let (right, ()) = app.seed(&mut rng, UnitStep, ())?;
        let (fused, ()) = app.fuse(&mut rng, UnitStep, (), left, right)?;
        assert!(app.verify(&fused, &mut rng)?);
        let compressed = app.compress(&fused, &mut rng)?;
        assert!(app.verify_compressed(&compressed)?);
        Ok(())
    }

    /// A binding circuit's claim holds only if its side's values are the
    /// ones the other side's stage holds: a proof whose two sides disagree
    /// fails the decider and the compressed verifier, and so does a parent
    /// over it. Under `P`, with the two sides given their bits through a
    /// [`CrossingContext`].
    fn a_binding_holds_the_sides_to_each_other_under<P>() -> Result<()>
    where
        P: Profile<
            Context<'static, Pasta, R<14>, ragu_backend::ReferenceBackend> = CrossingContext<
                'static,
                Pasta,
            >,
        >,
    {
        use rand::{SeedableRng, rngs::StdRng};

        use super::testing::UnitStep;
        use crate::ApplicationBuilder;

        let params = crate::pasta::baked();
        let application = |native, nested| {
            ApplicationBuilder::<Profiled<Pasta, P>, R<14>, 4>::new()
                .register(UnitStep)?
                .finalize_with(
                    params,
                    CrossingContext {
                        params,
                        native,
                        nested,
                    },
                )
        };
        let bits = [true, false, false, true];
        let mut other = bits;
        other[1] = !other[1];

        let honest = application(bits, bits)?;
        let mut rng = StdRng::seed_from_u64(15);
        let (left, ()) = honest.seed(&mut rng, UnitStep, ())?;
        let (right, ()) = honest.seed(&mut rng, UnitStep, ())?;
        let (fused, ()) = honest.fuse(&mut rng, UnitStep, (), left.clone(), right)?;
        assert!(honest.verify(&fused, &mut rng)?);
        let compressed = honest.compress(&fused, &mut rng)?;
        assert!(honest.verify_compressed(&compressed)?);

        // The same circuits, with the native side given other bits than the
        // digits the nested side holds.
        let disagreeing = application(bits, other)?;
        let (leaf, ()) = disagreeing.seed(&mut rng, UnitStep, ())?;
        assert!(!honest.verify(&leaf, &mut rng)?);
        let compressed = honest.compress(&leaf, &mut rng)?;
        assert!(!honest.verify_compressed(&compressed)?);
        let (parent, ()) = honest.fuse(&mut rng, UnitStep, (), leaf, left)?;
        assert!(!honest.verify(&parent, &mut rng)?);
        Ok(())
    }

    /// The native side binds: [`Crossing`]'s native binding circuit holds
    /// the native bits to the nested digits stage.
    #[test]
    fn a_native_binding_holds_the_sides_to_each_other() -> Result<()> {
        a_binding_holds_the_sides_to_each_other_under::<Crossing>()
    }

    /// The nested side binds: [`CrossingBack`]'s nested binding circuit
    /// holds the nested bits to the native digits stage.
    #[test]
    fn a_nested_binding_holds_the_sides_to_each_other() -> Result<()> {
        a_binding_holds_the_sides_to_each_other_under::<CrossingBack>()
    }

    /// Every polynomial of an extension is bound, on either side: a leaf
    /// with one extension circuit's or stage's polynomial doubled, its
    /// commitment recomputed so that only the claims disagree, fails the
    /// decider and the compressed verifier, and so does a parent over it.
    /// Under `P`, with both sides given the same bits through a
    /// [`CrossingContext`].
    fn extension_polynomials_are_bound_under<P>() -> Result<()>
    where
        P: Profile<
            Context<'static, Pasta, R<14>, ragu_backend::ReferenceBackend> = CrossingContext<
                'static,
                Pasta,
            >,
        >,
    {
        use alloc::format;

        use rand::{SeedableRng, rngs::StdRng};

        use super::testing::UnitStep;
        use crate::ApplicationBuilder;

        let params = crate::pasta::baked();
        let bits = [false, true, true, false];
        let app = ApplicationBuilder::<Profiled<Pasta, P>, R<14>, 4>::new()
            .register(UnitStep)?
            .finalize_with(
                params,
                CrossingContext {
                    params,
                    native: bits,
                    nested: bits,
                },
            )?;
        let mut rng = StdRng::seed_from_u64(16);
        let (leaf, ()) = app.seed(&mut rng, UnitStep, ())?;
        let (sibling, ()) = app.seed(&mut rng, UnitStep, ())?;
        assert!(app.verify(&leaf, &mut rng)?);

        let native_extension = P::native_extension();
        let nested_extension = P::nested_extension();
        let mut corrupted = Vec::new();
        for k in 0..native_extension.circuits.len() as u32 {
            let mut proof = leaf.proof().clone();
            proof.double_native_extension_rx(params, native::RxIndex::ExtensionCircuit(k));
            corrupted.push((format!("native circuit {k}"), proof));
        }
        for j in 0..native_extension.stages as u32 {
            let mut proof = leaf.proof().clone();
            proof.double_native_extension_rx(params, native::RxIndex::ExtensionStage(j));
            corrupted.push((format!("native stage {j}"), proof));
        }
        for k in 0..nested_extension.circuits.len() as u32 {
            let mut proof = leaf.proof().clone();
            proof.double_nested_extension_rx(params, nested::RxIndex::ExtensionCircuit(k));
            corrupted.push((format!("nested circuit {k}"), proof));
        }
        for j in 0..nested_extension.stages as u32 {
            let mut proof = leaf.proof().clone();
            proof.double_nested_extension_rx(params, nested::RxIndex::ExtensionStage(j));
            corrupted.push((format!("nested stage {j}"), proof));
        }
        assert_eq!(
            corrupted.len(),
            native_extension.rx() + nested_extension.rx()
        );

        for (what, proof) in corrupted {
            let pcd = proof.carry::<()>(());
            assert!(!app.verify(&pcd, &mut rng)?, "{what}: the decider");
            let compressed = app.compress(&pcd, &mut rng)?;
            assert!(
                !app.verify_compressed(&compressed)?,
                "{what}: the compressed verifier"
            );
            let (parent, ()) = app.fuse(&mut rng, UnitStep, (), pcd, sibling.clone())?;
            assert!(!app.verify(&parent, &mut rng)?, "{what}: a parent");
        }
        Ok(())
    }

    /// [`Crossing`]'s three polynomials, its binding circuit's and the
    /// nested circuit's and stage's.
    #[test]
    fn extension_polynomials_are_bound_with_a_native_binding() -> Result<()> {
        extension_polynomials_are_bound_under::<Crossing>()
    }

    /// [`CrossingBack`]'s three polynomials, the native circuit's and
    /// stage's and its binding circuit's.
    #[test]
    fn extension_polynomials_are_bound_with_a_nested_binding() -> Result<()> {
        extension_polynomials_are_bound_under::<CrossingBack>()
    }
}
