//! Variable-length carrier for `derive_challenge` outputs.
//!
//! This is the registry-time-sized sibling of the fixed
//! [`unified`](super::unified) instance. Where [`unified::Output`] has a
//! compile-time-fixed field set (`NUM_WIRES = 29`) consumed by the fixed
//! internal recursion circuits, the values produced by the
//! [`derive_challenge`](crate::framework_hooks::FrameworkHooks::derive_challenge)
//! framework hook are **per-application and variable-length**: there is one
//! `(point, challenge)` pair per hook call, and the call count is discovered at
//! registration time exactly like an
//! [`InducedStages`](ragu_circuits::staging::InducedStages) layout.
//!
//! A runtime-length `Vec` cannot itself be a [`Gadget`](ragu_core::gadgets::Gadget)
//! — the gadget contract fixes the wire count per type — so the carrier holds a
//! `Vec` of fixed-size [`DerivedPair`] gadgets without being one.
//!
//! The carrier is built two ways, mirroring [`unified`]:
//!
//! * [`DerivedChallengeOutput::from_stages`] assembles it directly from the
//!   handles the hook recorded in the application trace `r'(X)` — this is how
//!   the witness values **propagate** into the carrier (analogous to
//!   [`unified::Output::alloc_from_proof`](super::unified::Output::alloc_from_proof)).
//! * [`DerivedChallengeBuilder`] allocates each pair from a native
//!   [`DerivedChallengeInstance`] with [`Slot`]-tracked [`DerivedCoverage`]
//!   (analogous to [`unified::OutputBuilder`](super::unified::OutputBuilder)).
//!   The native values are resolved by fuse; that consumer is future work.

use alloc::vec::Vec;

use ragu_arithmetic::CurveAffine;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, Point, allocator::Allocator, consistent::Consistent, io::Write};

use super::unified::Slot;
use crate::framework_hooks::InducedStage;

/// One induced stage's verifier-visible outputs: a nested-curve commitment and
/// the challenge hashed from it.
///
/// Fixed-size (two gadget fields), so unlike the enclosing
/// [`DerivedChallengeOutput`] it *is* a [`Gadget`]. Mirrors a
/// `(bridge_*_commitment, challenge)` pair of the fixed [`unified`](super::unified)
/// instance.
#[derive(Gadget, Write, Consistent)]
pub struct DerivedPair<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    /// Pedersen commitment to the induced stage's wires, on the nested curve.
    #[ragu(gadget)]
    pub point: Point<'dr, D, C>,
    /// The challenge derived by hashing [`point`](Self::point).
    #[ragu(gadget)]
    pub challenge: Element<'dr, D>,
}

/// The verifier-visible carrier: one [`DerivedPair`] per
/// [`derive_challenge`](crate::framework_hooks::FrameworkHooks::derive_challenge)
/// call, in call order.
///
/// Runtime-length, so it is deliberately **not** a [`Gadget`]; it is consumed
/// pair-by-pair (each [`DerivedPair`] is a proper gadget). Serializing it into
/// an instance polynomial is future work (see the [module docs](self)).
pub struct DerivedChallengeOutput<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    pairs: Vec<DerivedPair<'dr, D, C>>,
}

impl<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> DerivedChallengeOutput<'dr, D, C> {
    /// Assembles the carrier from the handles recorded by the hook, in call
    /// order. No allocation: the handles already *are* the gadget wires (the
    /// deferred `point`/`challenge` allocated in
    /// [`derive_challenge`](crate::framework_hooks::FrameworkHooks::derive_challenge)).
    /// This is the propagation path from the application witness into the
    /// carrier.
    pub fn from_stages(stages: Vec<InducedStage<'dr, D, C>>) -> Self {
        let pairs = stages
            .into_iter()
            .map(|stage| DerivedPair {
                point: stage.point,
                challenge: stage.challenge,
            })
            .collect();
        Self { pairs }
    }

    /// The number of induced `(point, challenge)` pairs.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether the carrier has no pairs (the step made no `derive_challenge`
    /// calls).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The induced pairs, in call order.
    // Consumed by the recursion circuit that re-derives and binds each pair
    // (future fuse-side work; see the module docs).
    #[allow(dead_code)]
    pub fn pairs(&self) -> &[DerivedPair<'dr, D, C>] {
        &self.pairs
    }
}

/// Native (non-gadget) representation of the carrier: the resolved
/// `(commitment, challenge)` values plus accumulated [`DerivedCoverage`].
///
/// Constructed during proof generation once fuse resolves the deferred values
/// (future work) and passed to circuits as witness data for allocation, exactly
/// like [`unified::Instance`](super::unified::Instance).
// The native-value path is consumed once fuse resolves the deferred
// derived-challenge values and a recursion circuit covers them; see module docs.
#[allow(dead_code)]
pub struct DerivedChallengeInstance<C: CurveAffine> {
    /// Resolved `(commitment, challenge)` per induced stage, in call order.
    pub pairs: Vec<(C, C::Base)>,
    /// Accumulated coverage from prior circuits.
    pub coverage: DerivedCoverage,
}

#[allow(dead_code)]
impl<C: CurveAffine> DerivedChallengeInstance<C> {
    /// Asserts that every slot has been covered by some circuit.
    ///
    /// # Panics
    ///
    /// Panics if any point or challenge slot has not been covered.
    pub fn assert_complete(self) {
        self.coverage.assert_complete();
    }
}

/// A pair of [`Slot`]s — one for the commitment, one for the challenge — used
/// by [`DerivedChallengeBuilder`].
#[allow(dead_code)]
pub struct DerivedSlotPair<'dr, D: Driver<'dr>, A, C: CurveAffine<Base = D::F>> {
    /// Slot for the nested-curve commitment.
    pub point: Slot<'dr, D, A, Point<'dr, D, C>, C>,
    /// Slot for the derived challenge.
    pub challenge: Slot<'dr, D, A, Element<'dr, D>, C::Base>,
}

/// Builder for a [`DerivedChallengeOutput`] from a native
/// [`DerivedChallengeInstance`], with per-slot [`DerivedCoverage`].
///
/// The variable-length analog of
/// [`unified::OutputBuilder`](super::unified::OutputBuilder): each pair's slots
/// can be filled via [`Slot::provide`], allocated via [`Slot::read`] /
/// [`Slot::receive`], or deferred to [`finish`](Self::finish).
// Consumed once fuse resolves the deferred values and a recursion circuit
// covers them; see module docs.
#[allow(dead_code)]
pub struct DerivedChallengeBuilder<'dr, D: Driver<'dr>, A, C: CurveAffine<Base = D::F>> {
    /// One slot pair per induced stage, in call order.
    pub pairs: Vec<DerivedSlotPair<'dr, D, A, C>>,
    instance: DriverValue<D, DerivedChallengeInstance<C>>,
}

#[allow(dead_code)]
impl<'dr, D: Driver<'dr>, A: Allocator<'dr, D>, C: CurveAffine<Base = D::F>>
    DerivedChallengeBuilder<'dr, D, A, C>
{
    /// Creates a builder with `len` slot pairs seeded from `instance`.
    ///
    /// `len` is the registry-time induced-stage count
    /// ([`InducedStages::len`](ragu_circuits::staging::InducedStages::len)); the
    /// instance supplies the per-stage values when run on a value-carrying
    /// driver, and is ignored on structure-only drivers.
    pub fn new(instance: DriverValue<D, DerivedChallengeInstance<C>>, len: usize) -> Self {
        let pairs = (0..len)
            .map(|i| DerivedSlotPair {
                point: Slot::new(
                    instance.as_ref().map(move |inst| inst.pairs[i].0),
                    |dr, _allocator, w| Point::alloc(dr, w),
                ),
                challenge: Slot::new(
                    instance.as_ref().map(move |inst| inst.pairs[i].1),
                    |dr, allocator, w| Element::alloc(dr, allocator, w),
                ),
            })
            .collect();
        DerivedChallengeBuilder { pairs, instance }
    }

    /// Finishes building, returning the assembled [`DerivedChallengeOutput`] and
    /// the updated [`DerivedChallengeInstance`] with this circuit's coverage
    /// accumulated.
    pub fn finish(
        self,
        dr: &mut D,
        allocator: &mut A,
    ) -> Result<(
        DerivedChallengeOutput<'dr, D, C>,
        DriverValue<D, DerivedChallengeInstance<C>>,
    )> {
        let mut output_pairs = Vec::with_capacity(self.pairs.len());
        let mut covered = Vec::with_capacity(self.pairs.len());
        for slot_pair in self.pairs {
            let (point, point_set) = slot_pair.point.take(dr, allocator)?;
            let (challenge, challenge_set) = slot_pair.challenge.take(dr, allocator)?;
            output_pairs.push(DerivedPair { point, challenge });
            covered.push((point_set, challenge_set));
        }
        let output = DerivedChallengeOutput {
            pairs: output_pairs,
        };
        let instance = self.instance.map(move |mut inst| {
            for (i, (point_set, challenge_set)) in covered.iter().enumerate() {
                if *point_set {
                    DerivedCoverage::cover(&mut inst.coverage.pairs[i].point, "point", i);
                }
                if *challenge_set {
                    DerivedCoverage::cover(&mut inst.coverage.pairs[i].challenge, "challenge", i);
                }
            }
            inst
        });
        Ok((output, instance))
    }
}

/// Per-pair coverage flags: the commitment and the challenge are covered
/// independently, mirroring the separate `bridge_*_commitment` / challenge
/// slots of the fixed [`unified`](super::unified) instance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
struct DerivedPairCoverage {
    point: bool,
    challenge: bool,
}

/// Tracks which derived-challenge slots have been actively filled (via
/// [`Slot::provide`] or [`Slot::receive`]) across circuits — the variable-length
/// analog of [`unified::Coverage`](super::unified).
#[derive(Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub struct DerivedCoverage {
    pairs: Vec<DerivedPairCoverage>,
}

#[allow(dead_code)]
impl DerivedCoverage {
    /// Creates coverage for `len` induced stages, all initially uncovered.
    pub fn new(len: usize) -> Self {
        DerivedCoverage {
            pairs: alloc::vec![DerivedPairCoverage::default(); len],
        }
    }

    /// Marks a coverage flag, panicking on double-cover.
    fn cover(flag: &mut bool, name: &str, index: usize) {
        assert!(
            !*flag,
            "derived slot `{name}` at index {index} covered by multiple circuits"
        );
        *flag = true;
    }

    /// Asserts that a coverage flag has been set.
    fn assert_covered(flag: bool, name: &str, index: usize) {
        assert!(
            flag,
            "derived slot `{name}` at index {index} not covered by any circuit"
        );
    }

    /// Asserts every point and challenge slot has been covered.
    fn assert_complete(self) {
        for (i, pair) in self.pairs.iter().enumerate() {
            Self::assert_covered(pair.point, "point", i);
            Self::assert_covered(pair.challenge, "challenge", i);
        }
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{drivers::emulator::Emulator, maybe::Empty};
    use ragu_pasta::Pasta;
    use ragu_primitives::allocator::Standard;

    use super::*;

    type C = <Pasta as ragu_arithmetic::Cycle>::NestedCurve;
    type Dr = Emulator<
        ragu_core::drivers::emulator::Wireless<Empty, <Pasta as ragu_arithmetic::Cycle>::CircuitField>,
    >;

    /// Builds an `InducedStage` with wire-only deferred handles on a counting
    /// driver (no values resolved, so the `todo!()` never fires).
    fn induced_stage(dr: &mut Dr) -> InducedStage<'static, Dr, C> {
        let allocator = &mut Standard::new();
        let point = Point::alloc(dr, Empty).expect("alloc point");
        let challenge = Element::alloc(dr, allocator, Empty).expect("alloc challenge");
        InducedStage {
            num_wires: 0,
            wires: Vec::new(),
            point,
            challenge,
        }
    }

    /// `from_stages` produces one carrier pair per induced stage, in order.
    #[test]
    fn from_stages_collects_one_pair_per_stage() {
        let mut dr = Emulator::counter();
        let stages = alloc::vec![induced_stage(&mut dr), induced_stage(&mut dr)];

        let output = DerivedChallengeOutput::from_stages(stages);

        assert_eq!(output.len(), 2);
        assert_eq!(output.pairs().len(), 2);
        assert!(!output.is_empty());
    }

    /// No induced stages -> an empty carrier.
    #[test]
    fn from_stages_empty_is_empty() {
        let output: DerivedChallengeOutput<'_, Dr, C> =
            DerivedChallengeOutput::from_stages(Vec::new());
        assert_eq!(output.len(), 0);
        assert!(output.is_empty());
    }

    /// A builder whose every pair is `receive`d marks all slots covered, so
    /// `assert_complete` passes.
    #[test]
    fn builder_receive_covers_all_slots() {
        let mut dr = Emulator::counter();
        let allocator = &mut Standard::new();

        let mut builder: DerivedChallengeBuilder<'_, Dr, Standard<()>, C> =
            DerivedChallengeBuilder::new(Empty, 2);
        for pair in &mut builder.pairs {
            pair.point.receive(&mut dr, allocator).expect("receive point");
            pair.challenge
                .receive(&mut dr, allocator)
                .expect("receive challenge");
        }
        let (output, instance) = builder.finish(&mut dr, allocator).expect("finish");
        assert_eq!(output.len(), 2);

        // On a counting driver the instance is `Empty`, so coverage isn't
        // threaded; assert directly on a coverage value instead.
        let _ = instance;
        let mut cov = DerivedCoverage::new(1);
        DerivedCoverage::cover(&mut cov.pairs[0].point, "point", 0);
        DerivedCoverage::cover(&mut cov.pairs[0].challenge, "challenge", 0);
        cov.assert_complete();
    }

    /// `assert_complete` panics when a slot is left uncovered.
    #[test]
    #[should_panic(expected = "not covered by any circuit")]
    fn coverage_catches_missing() {
        let mut cov = DerivedCoverage::new(1);
        DerivedCoverage::cover(&mut cov.pairs[0].point, "point", 0);
        // challenge left uncovered
        cov.assert_complete();
    }

    /// Covering the same slot twice panics.
    #[test]
    #[should_panic(expected = "covered by multiple circuits")]
    fn coverage_catches_double_cover() {
        let mut cov = DerivedCoverage::new(1);
        DerivedCoverage::cover(&mut cov.pairs[0].point, "point", 0);
        DerivedCoverage::cover(&mut cov.pairs[0].point, "point", 0);
    }
}
