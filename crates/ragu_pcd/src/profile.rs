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
//! No profile declares an extension yet; [`Aggregator`] says why.
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
//!   require new tags even when the profile's name stays the same.
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
    polynomials::{Rank, sparse},
    registry::{Registry, RegistryBuilder},
};
#[cfg(feature = "baked")]
use ragu_core::pasta::Pasta;
use ragu_core::{Cycle, Error, Result};
use rand::CryptoRng;
use udon::field::Field;

use crate::{
    SelectableBackend,
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
/// final mask as the final mask of its circuits' last stage. Nothing checks
/// the registered circuits and bondings against the declaration, so a
/// profile pins the two together in its tests.
///
/// A profile is part of an application's setup description, so its
/// registries take their own [`RegistryTags`](crate::RegistryTags): the
/// standard profile's tags are not another profile's, even over the same
/// curves and steps.
pub trait Profile: Copy + Default + Eq + fmt::Debug + Send + Sync + 'static {
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

    /// Registers circuit `circuit` of the native extension as an internal
    /// circuit of `registry`, over the base cycle the profile extends (see
    /// [`ProfiledCycle::Base`]): the extension's circuits verify proofs in
    /// the standard profile over the same curves.
    ///
    /// # Errors
    ///
    /// The default declares no circuit and fails.
    fn register_native_circuit<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        circuit: usize,
        registry: RegistryBuilder<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (circuit, registry, params);
        Err(Error::Initialization(
            "the profile's native extension has no circuits".into(),
        ))
    }

    /// Registers bonding `bonding` of the native extension, a stage's mask
    /// or a final mask in [`Extension::bondings`] order, into `registry`.
    ///
    /// # Errors
    ///
    /// The default declares no bonding and fails.
    fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
        bonding: usize,
        registry: RegistryBuilder<'params, Base::CircuitField, R>,
        params: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (bonding, registry, params);
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
        registry: RegistryBuilder<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (circuit, registry, params);
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
        registry: RegistryBuilder<'params, Base::ScalarField, R>,
        params: &'params Base::Params,
    ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        let _ = (bonding, registry, params);
        Err(Error::Initialization(
            "the profile's nested extension has no bondings".into(),
        ))
    }

    /// The native extension's polynomials for one proof: each circuit's,
    /// assembled against `registry` at the circuit's index in the layout,
    /// then each stage's, blinded from `rng`, over the context the
    /// application holds.
    ///
    /// # Errors
    ///
    /// The default fills an empty extension and fails for any other.
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
        let _ = (context, registry, rng);
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
        registry: &Registry<'params, Base::ScalarField, R>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, R>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend,
        RNG: CryptoRng,
    {
        let _ = (context, registry, rng);
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
/// binding circuit's the other side's stage commitments it exposes.
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
/// [`Standard`] compressed proof in circuit.
///
/// Those circuits are the decompression's, which lands separately; until
/// it does, the profile declares nothing and its shape is [`Standard`]'s.
/// At the production rank every circuit of the fuse sits within a few
/// percent of the gate budget, and each polynomial a profile adds is one
/// more commitment its hashing circuits absorb, one more evaluation its
/// compute-v circuit takes, two more claims its collapse circuits fold and
/// a longer walk whose every step loads the longer points stage: two
/// polynomials per side already push a nested endoscaling step past the
/// budget. The decompression is therefore declared at a larger rank,
/// where the fuse has room for it; the declaration, registration, claims,
/// prover hooks, statement and endoscalings per step it needs are in
/// place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregator;

impl Profile for Aggregator {
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;
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
/// `Profiled<Pasta, Aggregator>` is the aggregator cycle over the Pasta
/// curves. It is a distinct type from [`Pasta`], so an application over one
/// never accepts the other's proofs.
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
        Coeff,
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
            registry: RegistryBuilder<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            registry.register_internal_circuit(
                native::circuits::bind_endoscalar::Circuit::<Base, R>::new(),
            )
        }

        fn register_native_bonding<'params, Base, R: Rank, const HEADER_SIZE: usize>(
            bonding: usize,
            registry: RegistryBuilder<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            type Stage<C, R, const H: usize> = native::stages::eval::Stage<C, R, H>;
            let mask = match bonding {
                0 => Stage::<Base, R, HEADER_SIZE>::mask()?,
                1 => Stage::<Base, R, HEADER_SIZE>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(registry.register_bonding(mask))
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            registry: RegistryBuilder<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            let circuit = nested::circuits::export::Circuit::<Base::HostCurve, R, Standard>::new();
            registry.register_internal_circuit(MultiStage::new(circuit))
        }

        fn register_nested_bonding<'params, Base, R: Rank>(
            bonding: usize,
            registry: RegistryBuilder<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            type Stage<C, R> = nested::stages::eval::Stage<<C as Cycle>::HostCurve, R, Standard>;
            let mask = match bonding {
                0 => Stage::<Base, R>::mask()?,
                1 => Stage::<Base, R>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(registry.register_bonding(mask))
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
            registry: RegistryBuilder<'params, Base::CircuitField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            registry.register_internal_circuit(Trivial::<Base::CircuitField>::new())
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            registry: RegistryBuilder<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            registry.register_internal_circuit(Trivial::<Base::ScalarField>::new())
        }

        fn native_extension_rxs<'params, Base, R, const HEADER_SIZE: usize, B, RNG>(
            _: &Self::Context<'params, Base, R, B>,
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

    /// The native side's one circuit under [`Crossing`], its binding
    /// circuit: its public output is the digits stage's commitment
    /// recomputed from the bits it is given, the digits' generators summed
    /// by sign, as the other side's digit $2b - 1$ scales its generator.
    pub(crate) struct BitsCircuit<P> {
        /// Each digit's generator: the digits stage's commitment with that
        /// digit one and the others zero.
        generators: Vec<P>,
    }

    impl<P: Affine> BitsCircuit<P> {
        /// The circuit over the digits stage's generators at rank `R`.
        fn new<C, R>(params: &C::Params) -> Result<Self>
        where
            C: IpaCycle<NestedCurve = P>,
            P: Affine<Scalar = C::ScalarField>,
            R: Rank,
        {
            let generators = C::nested_generators(params);
            let zeros = [C::ScalarField::ZERO; DIGITS];
            let commit = |digits: &[C::ScalarField; DIGITS]| {
                DigitsStage::<C::ScalarField, R>::rx(C::ScalarField::ZERO, digits)
                    .map(|rx| rx.commit_to_affine(generators))
            };
            assert!(
                commit(&zeros)?.coordinates().is_none(),
                "the digits stage has no term beyond the digits"
            );
            let generators = (0..DIGITS)
                .map(|i| {
                    let mut digits = zeros;
                    digits[i] = C::ScalarField::ONE;
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
            registry: RegistryBuilder<'params, Base::CircuitField, R>,
            params: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::CircuitField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            registry.register_internal_circuit(BitsCircuit::new::<Base, R>(params)?)
        }

        fn register_nested_circuit<'params, Base, R: Rank>(
            circuit: usize,
            registry: RegistryBuilder<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            assert_eq!(circuit, 0);
            registry.register_internal_circuit(MultiStage::new(
                DigitsCircuit::<Base::ScalarField, R>(PhantomData),
            ))
        }

        fn register_nested_bonding<'params, Base, R: Rank>(
            bonding: usize,
            registry: RegistryBuilder<'params, Base::ScalarField, R>,
            _: &'params Base::Params,
        ) -> Result<RegistryBuilder<'params, Base::ScalarField, R>>
        where
            Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        {
            let mask = match bonding {
                0 => DigitsStage::<Base::ScalarField, R>::mask()?,
                1 => DigitsStage::<Base::ScalarField, R>::final_mask()?,
                _ => unreachable!("two bondings"),
            };
            Ok(registry.register_bonding(mask))
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
            let (trace, ()) = BitsCircuit::new::<Base, R>(context.params)?
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
}

#[cfg(test)]
mod tests {
    use super::{
        testing::{Crossing, Mismatched, Wider},
        *,
    };

    #[test]
    fn declared_extensions_check() {
        Standard::check().unwrap();
        Aggregator::check().unwrap();
        Wider::check().unwrap();
        Crossing::check().unwrap();
        assert!(Wider::native_extension().is_consistent());
        assert!(Wider::nested_extension().is_consistent());
        assert!(Mismatched::check().is_err());
    }

    /// A declaration is well formed only with every index in range, nothing
    /// named twice, and every staged circuit under exactly one final mask,
    /// its last stage's.
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
    }

    /// The profile's checks refuse a malformed extension and a statement
    /// circuit on the nested side.
    #[test]
    fn malformed_declarations_are_refused() {
        use alloc::vec;

        /// A statement circuit past the circuits.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        struct StrayStatement;

        impl Profile for StrayStatement {
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

        assert!(StrayStatement::check().is_err());
        assert!(NestedStatement::check().is_err());
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

    #[test]
    fn aggregator_matches_standard_until_its_circuits_land() {
        assert_eq!(Shape::of::<Aggregator>(), Shape::of::<Standard>());
    }

    #[test]
    fn pasta_proves_in_the_standard_profile() {
        assert_eq!(
            Shape::of::<<Pasta as ProfiledCycle>::Profile>(),
            Shape::of::<Standard>()
        );
        assert_eq!(
            Shape::of::<<Profiled<Pasta, Aggregator> as ProfiledCycle>::Profile>(),
            Shape::of::<Aggregator>()
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
        use ragu_circuits::polynomials::R;
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
    /// over it.
    #[test]
    fn a_binding_holds_the_sides_to_each_other() -> Result<()> {
        use ragu_circuits::polynomials::R;
        use rand::{SeedableRng, rngs::StdRng};

        use super::testing::{Crossing, CrossingContext, UnitStep};
        use crate::ApplicationBuilder;

        let params = crate::pasta::baked();
        let application = |native, nested| {
            ApplicationBuilder::<Profiled<Pasta, Crossing>, R<14>, 4>::new()
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
}
