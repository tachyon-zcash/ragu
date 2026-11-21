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
//! The extension API is experimental while production decompression is being
//! integrated. Profile authors must review and test agreement between their
//! declarations, registered stages and masks, and the intended circuit relation.
//!
//! The verifier fixes its profile, registries and public parameters at setup.
//! Each registry's tag is derived from the circuits it holds, so profiles that
//! register different circuits have different tags.

use core::{
    any::{TypeId, type_name},
    fmt,
    marker::PhantomData,
};

use ragu_circuits::{polynomials::Rank, registry::Registry};
// Without `baked` the module docs are its only use.
#[cfg_attr(not(feature = "baked"), allow(unused_imports))]
use ragu_core::pasta::Pasta;
use ragu_core::{Cycle, Error, Result};
use rand::CryptoRng;

pub use crate::protocol::nested::online::NUM_ONLINE_FQ_POLYS;
use crate::{
    SelectableBackend,
    ipa::IpaCycle,
    protocol::{native, nested},
};

mod extension;
mod shape;

pub use extension::{Binding, BondingSlot, CircuitSlot, Extension, ExtensionRxs, Registered};
pub use shape::Shape;

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

    /// The native rx polynomials the profile adds: its native extension's.
    const NATIVE_EXTENSION: usize;
    /// The nested rx polynomials the profile adds: its nested extension's.
    const NESTED_EXTENSION: usize;

    /// The number of online polynomials over the scalar field that each
    /// step of the profile commits, at most
    /// [`NUM_ONLINE_FQ_POLYS`].
    ///
    /// A step commits such a polynomial natively, before its challenge
    /// $w$ is drawn. The nested `compute_v` circuit opens it and folds the
    /// opening into the step's own nested batch. The step does not export
    /// the polynomial, so a parent never opens it. Each polynomial adds
    /// one point to the native walk, and a full walk then needs another
    /// step on each side.
    ///
    /// Until decompression lands, each slot holds a fixed placeholder
    /// polynomial, and no circuit constrains its value at the opening
    /// point: the slot proves only that the value is an opening of the
    /// committed polynomial. Do not rely on it for anything else.
    ///
    /// The default is zero, which leaves the proof's shape as it is.
    const ONLINE_FQ_POLYS: usize = 0;

    /// The endoscalings a native endoscaling step performs: what fits a
    /// step beside the stages it reserves at the profile's rank. The walk
    /// over the nested batch takes a step per so many points, so more per
    /// step is fewer steps and fewer polynomials, and the other side's walk
    /// shortens with them. The standard profile's is the production rank's.
    /// Both endoscaling counts must be nonzero and their product must exceed
    /// four, so the mutually dependent walk sizes can converge.
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
    ///
    /// The challenge binders load a native extension's stages, and at the
    /// production rank their largest variant fills the
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
            Err(Error::Initialization(NO_NATIVE_EXTENSION_PROVER.into()))
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
            Err(Error::Initialization(NO_NESTED_EXTENSION_PROVER.into()))
        }
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
    /// a statement circuit, which only the native side carries; or if an
    /// extension's binding names a stage the other extension does not have;
    /// if the product of the two endoscaling counts is at most four; or if
    /// [`ONLINE_FQ_POLYS`](Self::ONLINE_FQ_POLYS) exceeds
    /// [`NUM_ONLINE_FQ_POLYS`].
    fn check() -> Result<()> {
        // Each added step contributes two points to the other side's walk.
        // A full pass must shrink that contribution for a fixed point to exist.
        if Self::NATIVE_ENDOSCALINGS_PER_STEP.saturating_mul(Self::NESTED_ENDOSCALINGS_PER_STEP)
            <= 4
        {
            return Err(Error::Initialization(
                "the profile's endoscaling counts must be nonzero and their product exceed four"
                    .into(),
            ));
        }
        if Self::NAME.is_empty() {
            return Err(Error::Initialization("the profile has no name".into()));
        }
        if Self::ONLINE_FQ_POLYS > NUM_ONLINE_FQ_POLYS {
            return Err(Error::Initialization(
                "the profile commits more online Fq polynomials than a step can open".into(),
            ));
        }
        for (name, profile) in [
            (Standard::NAME, TypeId::of::<Standard>()),
            (Aggregator::NAME, TypeId::of::<Aggregator>()),
        ] {
            if Self::NAME == name && TypeId::of::<Self>() != profile {
                return Err(Error::Initialization(
                    alloc::format!("the profile takes the built-in {name} profile's name").into(),
                ));
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
        Ok(())
    }
}

/// The default native extension prover's error: the profile declares a native
/// extension without overriding the prover.
pub(crate) const NO_NATIVE_EXTENSION_PROVER: &str = "the profile's native extension has no prover";
/// The nested counterpart of [`NO_NATIVE_EXTENSION_PROVER`].
pub(crate) const NO_NESTED_EXTENSION_PROVER: &str = "the profile's nested extension has no prover";

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
    const NAME: &'static str = "aggregator";
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

#[cfg(test)]
pub(crate) mod testing;

#[cfg(test)]
mod tests;
