//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Raw accumulator checks ([`RxComponent::AbA`] paired with
//!   [`RxComponent::AbB`]): $k(y) = c$
//! - Circuit checks: [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
//!   ($k(y) = 1$) and the instance circuits
//!   ([`INSTANCE`](InternalCircuitIndex::INSTANCE), $k(y)$ the nested
//!   unified instance's)
//! - Masking checks (every stage mask, the final staged masks, and the
//!   loading circuit): $k(y) = 0$

use alloc::{borrow::Cow, vec::Vec};
use core::iter::once;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, vec::Len};
use udon::field::Field;

use super::{InternalCircuitIndex, RxComponent, RxIndex};
use crate::{
    internal::revdot::{Builder, Source, sum_polynomials},
    profile::Profile,
};

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
pub trait Processor<P: Profile, Rx> {
    /// Processes a raw claim with `a` and `b` traces provided directly
    /// ($k(y) = c$).
    fn raw_claim(&mut self, a: Rx, b: Rx);

    /// Process an internal circuit claim whose trace is the sum of the given
    /// rxs ($k(y) = 1$ for [`EndoscalingStep`], the nested unified
    /// instance's $k(y)$ for the instance circuits).
    ///
    /// [`EndoscalingStep`]: InternalCircuitIndex::EndoscalingStep
    fn internal_circuit_claim(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a claim whose trace is the Horner fold (with $z$) of the given
    /// rxs, with one rx per fold slot ($k(y) = 0$).
    ///
    /// The default implementation wraps each rx as a single-element group and
    /// delegates to [`grouped_bonding_claim`](Self::grouped_bonding_claim).
    fn bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) -> Result<()> {
        self.grouped_bonding_claim(id, rxs.map(core::iter::once))
    }

    /// Process a claim whose trace is the Horner fold (with $z$) of per-group
    /// sums, where each fold slot holds the sum of one inner iterator
    /// ($k(y) = 0$).
    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Rx>>,
    ) -> Result<()>;
}

impl<'m, 'rx, P: Profile, F: Field, R: Rank, B: ragu_backend::Backend>
    Processor<P, &'rx sparse::Polynomial<F, R>>
    for Builder<'m, 'rx, Cow<'rx, sparse::Polynomial<F, R>>, F, R, B>
{
    fn raw_claim(&mut self, a: &'rx sparse::Polynomial<F, R>, b: &'rx sparse::Polynomial<F, R>) {
        self.raw_impl(Cow::Borrowed(a), Cow::Borrowed(b));
    }

    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index::<P>();
        let rx = sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index::<P>();
        let folded = self.fold_bonding_groups(groups);
        self.bonding_impl(circuit_id, folded);
        Ok(())
    }
}

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Raw accumulator checks ($k(y) = c$): one per proof
/// 2. Circuit checks: [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step ($k(y) = 1$), then each instance circuit
///    ([`INSTANCE`](InternalCircuitIndex::INSTANCE), $k(y)$ the nested
///    unified instance's), each interleaved across proofs
/// 3. Masking checks ($k(y) = 0$): every stage mask, the final staged masks,
///    and the loading circuit, each folded across proofs
///
/// This ordering must match the ky_elements ordering from [`ky_values`].
pub fn build<P: Profile, S, Pr>(source: &S, processor: &mut Pr) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    Pr: Processor<P, S::Rx>,
{
    use RxComponent::{AbA, AbB, Rx};

    // Raw accumulator claims (interleaved per proof)
    for (a, b) in source.rx(AbA).zip(source.rx(AbB)) {
        processor.raw_claim(a, b);
    }

    for id in InternalCircuitIndex::all::<P>() {
        use InternalCircuitIndex::*;
        match id {
            // A step's trace sits beside the endoscalar stage and the
            // points of its own segment of the walk: the points stage's
            // one polynomial for a walk of one segment.
            EndoscalingStep(step) => {
                let segment = super::segments::<P>().locate(step as usize).0;
                for ((step_rx, endo_rx), pts_rx) in source
                    .rx(Rx(RxIndex::EndoscalingStep(step)))
                    .zip(source.rx(Rx(RxIndex::EndoscalarStage)))
                    .zip(source.rx(Rx(super::segment_rx::<P>(segment))))
                {
                    processor.internal_circuit_claim(id, [step_rx, endo_rx, pts_rx].into_iter());
                }
            }
            // The instance circuits: each one's rx and every stage it
            // loads, which is every nested stage but the boundaries stage,
            // with the points of the walk's last segment, where the
            // walk's result is.
            Collapse | ComputeV => {
                let own = RxIndex::INSTANCE[InternalCircuitIndex::INSTANCE
                    .iter()
                    .position(|&circuit| circuit == id)
                    .expect("an instance circuit")];
                let mut loaded = alloc::vec![
                    own,
                    RxIndex::EndoscalarStage,
                    RxIndex::BridgeHash,
                    super::segment_rx::<P>(super::segments::<P>().count() - 1),
                    RxIndex::BridgePreamble,
                    RxIndex::BridgeSPrime,
                    RxIndex::BridgeInnerError,
                    RxIndex::BridgeOuterError,
                    RxIndex::BridgeAB,
                    RxIndex::BridgeQuery,
                    RxIndex::BridgeF,
                    RxIndex::BridgeEval,
                    RxIndex::ChallengeStage,
                ];
                // For a fold verified in chunks, the circuit registered in
                // `collapse`'s place holds the fold's targets to their
                // stage.
                if id == Collapse && super::is_fold_chunked::<P>() {
                    loaded.push(super::fold_targets_rx::<P>());
                }
                for rxs in per_proof(source, loaded) {
                    processor.internal_circuit_claim(id, rxs.into_iter());
                }
            }
            // A circuit of the fuse's own among the extension's: its rx and
            // the fuse's stages it reads. Its k(y) is the nested unified
            // instance's (see `ky_values`).
            ExtensionCircuit(k) if super::builtin_circuit::<P>(k as usize).is_some() => {
                let own = RxIndex::ExtensionCircuit(k);
                let loaded = match super::builtin_circuit::<P>(k as usize).expect("checked above") {
                    // A first-layer chunk of the fold: the preamble, the
                    // targets stage, both error stages and the challenges.
                    super::BuiltinCircuit::FoldInner(_) => alloc::vec![
                        own,
                        RxIndex::BridgePreamble,
                        super::fold_targets_rx::<P>(),
                        RxIndex::BridgeInnerError,
                        RxIndex::BridgeOuterError,
                        RxIndex::ChallengeStage,
                    ],
                    // The fold's second layer: the outer error stage and
                    // the challenges.
                    super::BuiltinCircuit::FoldOuter => {
                        alloc::vec![own, RxIndex::BridgeOuterError, RxIndex::ChallengeStage]
                    }
                };
                for rxs in per_proof(source, loaded) {
                    processor.internal_circuit_claim(id, rxs.into_iter());
                }
            }
            // An extension circuit: its rx and the extension stages it loads
            // (k(y) = 1).
            ExtensionCircuit(k) => {
                let extension = crate::profile::nested_extension::<P>();
                let mut per_proof: Vec<Vec<S::Rx>> = Vec::new();
                for index in [RxIndex::ExtensionCircuit(k)].into_iter().chain(
                    extension.circuits[k as usize]
                        .iter()
                        .map(|&stage| RxIndex::ExtensionStage(stage)),
                ) {
                    for (i, rx) in source.rx(Rx(index)).enumerate() {
                        if per_proof.len() <= i {
                            per_proof.push(Vec::new());
                        }
                        per_proof[i].push(rx);
                    }
                }
                for rxs in per_proof {
                    processor.internal_circuit_claim(id, rxs.into_iter());
                }
            }
            // An extension bonding: a stage's mask over its rx, or a final
            // mask over its circuits' rxs.
            ExtensionBonding(j) => {
                let extension = crate::profile::nested_extension::<P>();
                if (j as usize) < extension.stages {
                    processor.bonding_claim(id, source.rx(Rx(RxIndex::ExtensionStage(j))))?;
                } else {
                    processor.bonding_claim(
                        id,
                        extension
                            .final_mask(j as usize)
                            .iter()
                            .flat_map(|&k| source.rx(Rx(RxIndex::ExtensionCircuit(k)))),
                    )?;
                }
            }
            EndoscalarStage => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::EndoscalarStage)))?;
            }
            PointsStage => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::PointsStage)))?;
            }
            PointsFinalStaged => {
                let num_steps = super::NumSteps::<P>::len();
                let final_rxs = (0..num_steps)
                    .flat_map(|step| source.rx(Rx(RxIndex::EndoscalingStep(step as u32))));
                processor.bonding_claim(id, final_rxs)?;
            }
            BridgePreamble => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgePreamble)))?;
            }
            BridgeHash => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeHash)))?;
            }
            BridgeSPrime => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeSPrime)))?;
            }
            BridgeInnerError => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeInnerError)))?;
            }
            BridgeOuterError => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeOuterError)))?;
            }
            BridgeAB => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeAB)))?;
            }
            BridgeQuery => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeQuery)))?;
            }
            BridgeF => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeF)))?;
            }
            BridgeEval => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgeEval)))?;
            }
            ChallengeStage => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::ChallengeStage)))?;
            }
            // The instance circuits end on the challenge stage, and so do
            // the circuits of a fold verified in chunks.
            ChallengeFinalStaged => {
                let offset = super::builtin_circuit_offset::<P>();
                let fold = (0..super::num_builtin_circuits::<P>())
                    .map(|circuit| RxIndex::ExtensionCircuit((offset + circuit) as u32));
                let final_rxs = RxIndex::INSTANCE
                    .iter()
                    .copied()
                    .chain(fold)
                    .flat_map(|own| source.rx(Rx(own)));
                processor.bonding_claim(id, final_rxs)?;
            }
            Loading => loading_claim::<P, S, Pr>(source, processor, id, 0)?,
            LoadingSegment(segment) => {
                loading_claim::<P, S, Pr>(source, processor, id, segment as usize)?
            }
        }
    }

    Ok(())
}

/// Each proof's polynomials at `indices`, in that order: one list per proof
/// of the source.
fn per_proof<S>(source: &S, indices: impl IntoIterator<Item = RxIndex>) -> Vec<Vec<S::Rx>>
where
    S: Source<RxComponent = RxComponent>,
{
    let mut per_proof: Vec<Vec<S::Rx>> = Vec::new();
    for index in indices {
        for (i, rx) in source.rx(RxComponent::Rx(index)).enumerate() {
            if per_proof.len() <= i {
                per_proof.push(Vec::new());
            }
            per_proof[i].push(rx);
        }
    }
    per_proof
}

/// The loading claim of segment `segment` of the walk, folded across
/// proofs: each proof's group sums the segment's points, the boundaries
/// stage for a walk of several segments, and the bridge stages the loading
/// circuit reads.
fn loading_claim<P: Profile, S, Pr>(
    source: &S,
    processor: &mut Pr,
    id: InternalCircuitIndex,
    segment: usize,
) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    Pr: Processor<P, S::Rx>,
{
    use RxComponent::Rx;

    let mut loaded = alloc::vec![super::segment_rx::<P>(segment)];
    if super::segments::<P>().is_split() {
        loaded.push(super::boundaries_rx::<P>());
    }
    loaded.extend([
        RxIndex::BridgePreamble,
        RxIndex::BridgeSPrime,
        RxIndex::BridgeInnerError,
        RxIndex::BridgeAB,
        RxIndex::BridgeQuery,
        RxIndex::BridgeF,
    ]);
    let mut per_proof: Vec<Vec<S::Rx>> = Vec::new();
    for index in loaded {
        for (i, rx) in source.rx(Rx(index)).enumerate() {
            if per_proof.len() <= i {
                per_proof.push(Vec::new());
            }
            per_proof[i].push(rx);
        }
    }
    processor.grouped_bonding_claim(id, per_proof.into_iter().map(Vec::into_iter))
}

/// Trait for providing $k(y)$ values for nested claim verification.
pub trait KySource {
    /// The $k(y)$ value type.
    type Ky: Clone;

    /// The raw accumulator claims' values, one per proof:
    /// $c = \operatorname{revdot}(a, b)$.
    fn raw_c(&self) -> impl Iterator<Item = Self::Ky>;

    /// One value of $1$ per proof, for the endoscaling step checks.
    ///
    /// Repeated once per endoscaling step by [`ky_prefix`]. The `+ Clone`
    /// bound is required for `repeat_n`.
    fn ones(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// The nested unified instance's $k(y)$, one per proof, for collapse.
    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// Compute-v's target, including the online helper's public values.
    fn compute_v_ky(&self) -> impl Iterator<Item = Self::Ky>;

    /// The online helper's target, one per proof when active.
    fn online_helper_ky(&self) -> impl Iterator<Item = Self::Ky>;

    /// One value per proof for the binding circuit of the profile's nested
    /// extension: the $k(y)$ of what it exposes, as
    /// [`binding_ky`](crate::internal::ky::binding_ky) computes it, and
    /// none for a profile without one.
    fn binding_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// Returns 0 for stage checks.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over $k(y)$ values in nested claim order: the
/// [`ky_prefix`] of the raw and circuit claims, followed by infinite zeros
/// (for stage checks).
pub fn ky_values<P: Profile, S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    ky_prefix::<P, _>(source).chain(core::iter::repeat(source.zero()))
}

/// Build a finite iterator over the raw and circuit claims' $k(y)$ values,
/// in nested claim order: [`ky_values`] before the stage checks' zeros.
///
/// Returns:
/// - The raw accumulator values (one per proof)
/// - `num_steps` copies of the per-proof ones (for EndoscalingStep circuit
///   checks, interleaved across proofs exactly as [`build`] emits them)
/// - The per-proof collapse targets, then the compute-v targets
/// - One copy of the per-proof ones per extension circuit of profile `P`,
///   except the binding and online helper circuits, which use their targets
pub fn ky_prefix<P: Profile, S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    let num_steps = super::NumSteps::<P>::len();

    source
        .raw_c()
        .chain(core::iter::repeat_n(source.ones(), num_steps).flatten())
        .chain(source.unified_ky())
        .chain(source.compute_v_ky())
        .chain({
            let extension = crate::profile::nested_extension::<P>();
            let ones: Vec<S::Ky> = source.ones().collect();
            let binding: Vec<S::Ky> = source.binding_ky().collect();
            assert!(
                extension.binding.is_none() || binding.len() == ones.len(),
                "a profile with a binding circuit takes one binding value per proof"
            );
            let helper_ky: Vec<S::Ky> = source.online_helper_ky().collect();
            let helper = crate::profile::online::stages::helper::<
                P,
                crate::profile::online::stages::Nested,
            >();
            assert!(
                helper.is_none() || helper_ky.len() == ones.len(),
                "an online batch takes one helper target per proof"
            );
            let bound = extension.binding.as_ref().map(|binding| binding.circuit);
            // A circuit of the fuse's own takes the nested unified instance.
            let unified: Vec<S::Ky> = source.unified_ky().collect();
            (0..extension.circuits.len() as u32).flat_map(move |circuit| {
                if super::builtin_circuit::<P>(circuit as usize).is_some() {
                    unified.clone()
                } else if bound == Some(circuit) {
                    binding.clone()
                } else if helper == Some(circuit) {
                    helper_ky.clone()
                } else {
                    ones.clone()
                }
            })
        })
}

/// [`KySource`] for the two child proofs of a fuse step, inside a driver.
///
/// Carries each child's raw accumulator value $c$, nested unified $k(y)$
/// and binding circuit's $k(y)$ as elements, and the constant one and
/// zero the other checks take.
pub struct TwoProofKySource<'dr, D: Driver<'dr>> {
    pub left_raw_c: Element<'dr, D>,
    pub right_raw_c: Element<'dr, D>,
    pub left_unified: Element<'dr, D>,
    pub right_unified: Element<'dr, D>,
    pub left_compute_v: Element<'dr, D>,
    pub right_compute_v: Element<'dr, D>,
    pub left_online_helper: Option<Element<'dr, D>>,
    pub right_online_helper: Option<Element<'dr, D>>,
    pub left_binding: Option<Element<'dr, D>>,
    pub right_binding: Option<Element<'dr, D>>,
    pub one: Element<'dr, D>,
    pub zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> TwoProofKySource<'dr, D> {
    /// Create a [`TwoProofKySource`] from the children's raw `c` values,
    /// unified $k(y)$ values, `compute_v` circuits' $k(y)$ values, and the
    /// online helper and binding circuits' $k(y)$ values, `None` for a
    /// profile without one.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dr: &mut D,
        left_raw_c: Element<'dr, D>,
        right_raw_c: Element<'dr, D>,
        left_unified: Element<'dr, D>,
        right_unified: Element<'dr, D>,
        left_compute_v: Element<'dr, D>,
        right_compute_v: Element<'dr, D>,
        left_online_helper: Option<Element<'dr, D>>,
        right_online_helper: Option<Element<'dr, D>>,
        left_binding: Option<Element<'dr, D>>,
        right_binding: Option<Element<'dr, D>>,
    ) -> Self {
        Self {
            left_raw_c,
            right_raw_c,
            left_unified,
            right_unified,
            left_compute_v,
            right_compute_v,
            left_online_helper,
            right_online_helper,
            left_binding,
            right_binding,
            one: Element::one(),
            zero: Element::zero(dr),
        }
    }
}

impl<'dr, D: Driver<'dr>> KySource for TwoProofKySource<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Element<'dr, D>> {
        once(self.left_raw_c.clone()).chain(once(self.right_raw_c.clone()))
    }

    fn ones(&self) -> impl Iterator<Item = Element<'dr, D>> + Clone {
        once(self.one.clone()).chain(once(self.one.clone()))
    }

    fn unified_ky(&self) -> impl Iterator<Item = Element<'dr, D>> + Clone {
        once(self.left_unified.clone()).chain(once(self.right_unified.clone()))
    }

    fn compute_v_ky(&self) -> impl Iterator<Item = Element<'dr, D>> {
        [self.left_compute_v.clone(), self.right_compute_v.clone()].into_iter()
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = Element<'dr, D>> {
        self.left_online_helper
            .iter()
            .chain(self.right_online_helper.iter())
            .cloned()
    }

    fn binding_ky(&self) -> impl Iterator<Item = Element<'dr, D>> + Clone {
        self.left_binding
            .iter()
            .chain(self.right_binding.iter())
            .cloned()
    }

    fn zero(&self) -> Element<'dr, D> {
        self.zero.clone()
    }
}
