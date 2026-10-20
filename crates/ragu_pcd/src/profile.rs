//! Proof profiles.
//!
//! A profile is the set of internal circuits a proof carries beyond the
//! fuse's own, and so the shape of the proof: how many polynomials it holds
//! and how long the two endoscaling walks over them run. Every proof an
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
//! with the stages they load, and registers them through its hooks. The
//! internal modules place the circuits after the fuse's endoscaling steps
//! and the bondings after the fuse's masks, fold a circuit's claim as a
//! step's, and the proof carries the polynomials. No profile declares an
//! extension yet; [`Aggregator`] says why.

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
pub trait Profile: Copy + Default + Eq + fmt::Debug + Send + Sync + 'static {
    /// The native rx polynomials the profile adds: its native extension's.
    const NATIVE_EXTENSION: usize;
    /// The nested rx polynomials the profile adds: its nested extension's.
    const NESTED_EXTENSION: usize;

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
    /// then each stage's, blinded from `rng`.
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

    /// Checks that the constants agree with the extensions.
    ///
    /// # Errors
    ///
    /// Fails if an extension's rx count differs from its constant, so that a
    /// profile declaring one without the other does not lay out a proof.
    fn check() -> Result<()> {
        for (side, declared, extension) in [
            ("native", Self::NATIVE_EXTENSION, Self::native_extension()),
            ("nested", Self::NESTED_EXTENSION, Self::nested_extension()),
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
/// and each stage has an rx polynomial in the proof; a final mask binds the
/// rx polynomials of the circuits it names, as the fuse's final masks do,
/// and has none. A circuit's claim takes its own rx polynomial and the
/// stages it loads, with $k(y) = 1$ as the fuse's steps have: an extension
/// circuit carries no instance of its own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extension {
    /// Each circuit's stages, by index among the stages, in the order the
    /// circuit loads them.
    pub circuits: Vec<Vec<u32>>,
    /// The number of stages.
    pub stages: usize,
    /// Each final mask's circuits, by index among the circuits.
    pub final_masks: Vec<Vec<u32>>,
}

impl Extension {
    /// No circuits and no stages.
    pub const EMPTY: Self = Extension {
        circuits: Vec::new(),
        stages: 0,
        final_masks: Vec::new(),
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

    /// Whether every index the circuits and final masks name exists.
    pub fn is_consistent(&self) -> bool {
        self.circuits
            .iter()
            .flatten()
            .all(|&stage| (stage as usize) < self.stages)
            && self
                .final_masks
                .iter()
                .flatten()
                .all(|&circuit| (circuit as usize) < self.circuits.len())
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
/// Those circuits are the decompression's, which lands separately; the
/// profile declares nothing yet and its shape is
/// [`Standard`]'s: every circuit of the fuse sits within a few percent of
/// the gate budget, and each polynomial a profile adds is one more
/// commitment its hashing circuits absorb, one more evaluation its
/// compute-v circuit takes, two more claims its collapse circuits fold and
/// a longer walk whose every step loads the longer points stage. Two
/// polynomials per side already push a nested endoscaling step past the
/// budget. The fuse's own circuits have to scale with the profile before
/// an extension can be proved; the extension's declaration, registration
/// and claims are in place for when they do.
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
/// and the native walk's steps are native rx polynomials. Going once around,
/// a native step adds about a quarter of a native step, so the map from a
/// step count to the count the batch then needs is a contraction with one
/// fixed point, which [`Shape::solve`] finds by iteration.
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
        Self::solve(P::NATIVE_EXTENSION, P::NESTED_EXTENSION)
    }

    /// Solves the walk sizes for the given extensions, iterating the native
    /// step count to its fixed point.
    pub const fn solve(native_extension: usize, nested_extension: usize) -> Self {
        let mut native_steps = 1;
        let mut rounds = 0;
        loop {
            let shape = Self::with_native_steps(native_steps, native_extension, nested_extension);
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
    ) -> Self {
        let native_rx = native::NUM_FIXED_RX + native_steps + native_extension;
        let nested_points = nested::num_endoscaling_points(native_rx);
        let nested_steps =
            endoscalar::num_steps::<{ nested::ENDOSCALINGS_PER_STEP }>(nested_points);
        let nested_rx = nested::NUM_FIXED_RX + nested_steps + nested_extension;
        let native_points = nested::pcs::num_batched_points(nested_rx);
        let native_steps =
            endoscalar::num_steps::<{ native::ENDOSCALINGS_PER_STEP }>(native_points);
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

    use ragu_circuits::staging::{MultiStage, StageExt};

    use super::*;

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
            }
        }

        fn nested_extension() -> Extension {
            Extension {
                circuits: vec![vec![0]],
                stages: 1,
                final_masks: vec![vec![0]],
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
}

#[cfg(test)]
mod tests {
    use super::{
        testing::{Mismatched, Wider},
        *,
    };

    #[test]
    fn declared_extensions_check() {
        Standard::check().unwrap();
        Aggregator::check().unwrap();
        Wider::check().unwrap();
        assert!(Wider::native_extension().is_consistent());
        assert!(Wider::nested_extension().is_consistent());
        assert!(Mismatched::check().is_err());
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
        assert_eq!(Shape::of::<Wider>(), Shape::solve(4, 2));
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
            let shape = Shape::solve(native_extension, nested_extension);
            let again =
                Shape::with_native_steps(shape.native_steps, native_extension, nested_extension);
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
        let base = Shape::solve(0, 0);
        let wider = Shape::solve(100, 0);
        assert!(wider.nested_steps > base.nested_steps);
        assert!(wider.native_steps > base.native_steps);
        let extra = wider.polynomials() - base.polynomials();
        assert!(
            (150..=250).contains(&extra),
            "100 native polynomials cost {extra} overall"
        );
    }
}
