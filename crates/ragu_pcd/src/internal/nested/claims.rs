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

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

use super::{InternalCircuitIndex, NUM_INSTANCE_CIRCUITS, RxComponent, RxIndex};
use crate::internal::claims::{Builder, Source, sum_polynomials};

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
pub trait Processor<Rx> {
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

impl<'m, 'rx, F: PrimeField, R: Rank, B: ragu_backend::Backend>
    Processor<&'rx sparse::Polynomial<F, R>>
    for Builder<'m, 'rx, Cow<'rx, sparse::Polynomial<F, R>>, F, R, B>
{
    fn raw_claim(&mut self, a: &'rx sparse::Polynomial<F, R>, b: &'rx sparse::Polynomial<F, R>) {
        self.a.push(Cow::Borrowed(a));
        self.b.push(Cow::Borrowed(b));
    }

    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index();
        let rx = sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index();
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
pub fn build<S, P>(source: &S, processor: &mut P) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx>,
{
    use RxComponent::{AbA, AbB, Rx};

    // Raw accumulator claims (interleaved per proof)
    for (a, b) in source.rx(AbA).zip(source.rx(AbB)) {
        processor.raw_claim(a, b);
    }

    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        match id {
            EndoscalingStep(step) => {
                for ((step_rx, endo_rx), pts_rx) in source
                    .rx(Rx(RxIndex::EndoscalingStep(step)))
                    .zip(source.rx(Rx(RxIndex::EndoscalarStage)))
                    .zip(source.rx(Rx(RxIndex::PointsStage)))
                {
                    processor.internal_circuit_claim(id, [step_rx, endo_rx, pts_rx].into_iter());
                }
            }
            // The instance circuits: each one's rx and every stage it
            // reserves, which is every nested stage.
            Export | Collapse | ComputeV => {
                let own = RxIndex::INSTANCE[InternalCircuitIndex::INSTANCE
                    .iter()
                    .position(|&circuit| circuit == id)
                    .expect("an instance circuit")];
                let loaded = [
                    own,
                    RxIndex::EndoscalarStage,
                    RxIndex::PointsStage,
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
                let mut per_proof: Vec<Vec<S::Rx>> = Vec::new();
                for index in loaded {
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
            EndoscalarStage => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::EndoscalarStage)))?;
            }
            PointsStage => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::PointsStage)))?;
            }
            PointsFinalStaged => {
                let num_steps = super::NUM_ENDOSCALING_STEPS;
                let final_rxs = (0..num_steps)
                    .flat_map(|step| source.rx(Rx(RxIndex::EndoscalingStep(step as u32))));
                processor.bonding_claim(id, final_rxs)?;
            }
            BridgePreamble => {
                processor.bonding_claim(id, source.rx(Rx(RxIndex::BridgePreamble)))?;
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
            ChallengeFinalStaged => {
                let final_rxs = RxIndex::INSTANCE.iter().flat_map(|&own| source.rx(Rx(own)));
                processor.bonding_claim(id, final_rxs)?;
            }
            Loading => {
                let groups = source
                    .rx(Rx(RxIndex::PointsStage))
                    .zip(source.rx(Rx(RxIndex::BridgePreamble)))
                    .zip(source.rx(Rx(RxIndex::BridgeSPrime)))
                    .zip(source.rx(Rx(RxIndex::BridgeInnerError)))
                    .zip(source.rx(Rx(RxIndex::BridgeAB)))
                    .zip(source.rx(Rx(RxIndex::BridgeQuery)))
                    .zip(source.rx(Rx(RxIndex::BridgeF)))
                    .map(|((((((ps, bp), bs), bi), ba), bq), bf)| {
                        [ps, bp, bs, bi, ba, bq, bf].into_iter()
                    });
                processor.grouped_bonding_claim(id, groups)?;
            }
        }
    }

    Ok(())
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
    /// Repeated once per endoscaling step by [`ky_values`]. The `+ Clone`
    /// bound is required for `repeat_n`.
    fn ones(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// The nested unified instance's $k(y)$, one per proof, for the
    /// instance circuit checks.
    ///
    /// Repeated once per instance circuit by [`ky_values`]. The `+ Clone`
    /// bound is required for `repeat_n`.
    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone;

    /// Returns 0 for stage checks.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over $k(y)$ values in nested claim order.
///
/// Returns:
/// - The raw accumulator values (one per proof)
/// - `num_steps` copies of the per-proof ones (for EndoscalingStep circuit
///   checks, interleaved across proofs exactly as [`build`] emits them)
/// - `NUM_INSTANCE_CIRCUITS` copies of the per-proof unified $k(y)$ values
///   (for the instance circuit checks, interleaved the same way)
/// - Infinite zeros (for stage checks)
pub fn ky_values<S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    let num_steps = super::NUM_ENDOSCALING_STEPS;

    source
        .raw_c()
        .chain(core::iter::repeat_n(source.ones(), num_steps).flatten())
        .chain(core::iter::repeat_n(source.unified_ky(), NUM_INSTANCE_CIRCUITS).flatten())
        .chain(core::iter::repeat(source.zero()))
}

/// [`KySource`] for the two child proofs of a fuse step, inside a driver.
///
/// Carries each child's raw accumulator value $c$ and nested unified $k(y)$
/// as elements, and the constant one and zero the other checks take.
pub struct TwoProofKySource<'dr, D: Driver<'dr>> {
    pub left_raw_c: Element<'dr, D>,
    pub right_raw_c: Element<'dr, D>,
    pub left_unified: Element<'dr, D>,
    pub right_unified: Element<'dr, D>,
    pub one: Element<'dr, D>,
    pub zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> TwoProofKySource<'dr, D> {
    /// Create a [`TwoProofKySource`] from the children's raw `c` values and
    /// unified $k(y)$ values.
    pub fn new(
        dr: &mut D,
        left_raw_c: Element<'dr, D>,
        right_raw_c: Element<'dr, D>,
        left_unified: Element<'dr, D>,
        right_unified: Element<'dr, D>,
    ) -> Self {
        Self {
            left_raw_c,
            right_raw_c,
            left_unified,
            right_unified,
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

    fn zero(&self) -> Element<'dr, D> {
        self.zero.clone()
    }
}
