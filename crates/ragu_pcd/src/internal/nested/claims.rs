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
//! - Masking checks (every stage mask and the final staged masks):
//!   $k(y) = 0$

use alloc::{borrow::Cow, vec::Vec};
use core::iter::once;

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{Result, drivers::Driver};
use ragu_primitives::{Element, vec::Len};
use udon::field::Field;

use super::{InternalCircuitIndex, RxComponent, RxIndex};
use crate::{
    internal::revdot::{Builder, Source, sum_polynomials},
    profile::{Profile, paging},
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
    /// Returns `Result<()>` because the evaluation context requires fallible
    /// fold operations.
    fn mask_claim(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>)
    -> Result<()>;
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

    fn mask_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index::<P>();
        let folded = self.fold_mask(rxs);
        self.mask_impl(circuit_id, folded);
        Ok(())
    }
}

/// A nested circuit a profile can page: the polynomial of its own slot and
/// the stages its claim loads, in the order it reserves them. A step
/// reserves the bridge-hash stage without loading it, so that stage is not
/// in its list.
fn pageable(circuit: paging::Circuit) -> (RxIndex, Vec<RxIndex>) {
    let every = || RxIndex::STAGES.into_iter().collect();
    match circuit {
        paging::Circuit::NestedCollapse => (RxIndex::INSTANCE[0], every()),
        paging::Circuit::NestedComputeV => (RxIndex::INSTANCE[1], every()),
        paging::Circuit::NestedEndoscalingStep(step) => (
            RxIndex::EndoscalingStep(step),
            alloc::vec![RxIndex::EndoscalarStage, RxIndex::PointsStage],
        ),
        _ => unreachable!("a nested circuit"),
    }
}

/// The stages each page of a paged circuit loads, which are its circuit's,
/// and its carry stage.
fn page_stages(placement: &paging::Placement) -> Vec<RxIndex> {
    pageable(placement.circuit)
        .1
        .into_iter()
        .chain([RxIndex::ExtensionStage(placement.carry)])
        .collect()
}

/// The polynomials at `indices`, for each proof.
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

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Raw accumulator checks ($k(y) = c$): one per proof
/// 2. Circuit checks: [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step ($k(y) = 1$), then each instance circuit
///    ([`INSTANCE`](InternalCircuitIndex::INSTANCE), $k(y)$ the nested
///    unified instance's), each interleaved across proofs
/// 3. Masking checks ($k(y) = 0$): every stage mask and the final staged
///    masks, each folded across proofs
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

    // A circuit its profile pages is its last page, which loads the
    // circuit's stages and its carry stage, as every page of it does.
    let pages = paging::placements::<P>(true);
    let paged = |circuit: InternalCircuitIndex| {
        let which = match circuit {
            InternalCircuitIndex::Collapse => paging::Circuit::NestedCollapse,
            InternalCircuitIndex::ComputeV => paging::Circuit::NestedComputeV,
            InternalCircuitIndex::EndoscalingStep(step) => {
                paging::Circuit::NestedEndoscalingStep(step)
            }
            _ => return None,
        };
        pages.iter().find(|placement| placement.circuit == which)
    };

    for id in InternalCircuitIndex::all::<P>() {
        use InternalCircuitIndex::*;
        match id {
            // A paged step is its last page.
            EndoscalingStep(step) if paged(id).is_some() => {
                let placement = paged(id).expect("a paged step");
                let loaded = once(RxIndex::EndoscalingStep(step)).chain(page_stages(placement));
                for rxs in per_proof(source, loaded) {
                    processor.internal_circuit_claim(id, rxs.into_iter());
                }
            }
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
            Collapse | ComputeV => {
                let own = RxIndex::INSTANCE[InternalCircuitIndex::INSTANCE
                    .iter()
                    .position(|&circuit| circuit == id)
                    .expect("an instance circuit")];
                let stages = match paged(id) {
                    Some(placement) => page_stages(placement),
                    None => RxIndex::STAGES.to_vec(),
                };
                for rxs in per_proof(source, once(own).chain(stages)) {
                    processor.internal_circuit_claim(id, rxs.into_iter());
                }
            }
            // An extension circuit: its rx and the extension stages it loads
            // (k(y) = 1).
            ExtensionCircuit(k) => {
                let extension = crate::profile::nested_extension::<P>();
                // A page loads its circuit's stages beside its carry
                // stage, which is the extension stage it is declared to
                // load.
                let loaded = match pages
                    .iter()
                    .find_map(|placement| placement.page(k).map(|_| page_stages(placement)))
                {
                    Some(stages) => stages,
                    None => extension.circuits[k as usize]
                        .iter()
                        .map(|&stage| RxIndex::ExtensionStage(stage))
                        .collect(),
                };
                for rxs in per_proof(source, once(RxIndex::ExtensionCircuit(k)).chain(loaded)) {
                    processor.internal_circuit_claim(id, rxs.into_iter());
                }
            }
            // An extension mask: a stage's mask over its rx, or a final
            // mask over its circuits' rxs.
            ExtensionMask(j) => {
                let extension = crate::profile::nested_extension::<P>();
                if (j as usize) < extension.stages {
                    processor.mask_claim(id, source.rx(Rx(RxIndex::ExtensionStage(j))))?;
                } else {
                    // The mask of a circuit's last page covers the
                    // circuit's own polynomial, which is that page's.
                    let last_pages = pages
                        .iter()
                        .find(|placement| placement.masks_last(j))
                        .map(|placement| source.rx(Rx(pageable(placement.circuit).0)))
                        .into_iter()
                        .flatten();
                    processor.mask_claim(
                        id,
                        extension
                            .final_mask(j as usize)
                            .iter()
                            .flat_map(|&k| source.rx(Rx(RxIndex::ExtensionCircuit(k))))
                            .chain(last_pages),
                    )?;
                }
            }
            // The final mask of the steps' last stage, over the steps: a
            // paged step is under its pages' mask instead.
            PointsFinalStaged => {
                let num_steps = super::NumSteps::<P>::len();
                let final_rxs = (0..num_steps as u32)
                    .filter(|&step| paged(EndoscalingStep(step)).is_none())
                    .flat_map(|step| source.rx(Rx(RxIndex::EndoscalingStep(step))));
                processor.mask_claim(id, final_rxs)?;
            }
            ChallengeFinalStaged => {
                let final_rxs = RxIndex::INSTANCE.iter().flat_map(|&own| source.rx(Rx(own)));
                processor.mask_claim(id, final_rxs)?;
            }
            // Every other entry is a stage's mask, over the stage's rx.
            _ => {
                let stage = id.stage().expect("a stage's mask");
                processor.mask_claim(id, source.rx(Rx(stage)))?;
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
            (0..extension.circuits.len() as u32).flat_map(move |circuit| {
                if bound == Some(circuit) {
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
