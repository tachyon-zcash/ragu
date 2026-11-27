//! Negative tests of the claims paging adds: what a page's mask and its
//! carry stage's mask forbid is refused, and a carried value is read where
//! it is written.
//!
//! The corruption vocabulary edits a coefficient and leaves its commitment,
//! so the verifier's commitment check refuses the proof before any claim
//! is looked at. These tests look at the claims themselves instead. They
//! build the proof's claims as the verifier does, through the claim lists
//! the prover, the verifier and the fuse's circuits share, over the
//! registry the application registered, and compare each claim's value
//! before and after a value is planted on one wire of one polynomial. A
//! claim whose value moved no longer holds: the proof verified, so every
//! claim held before.
//!
//! - A page's own polynomial is zero off the page's own gates: on the
//!   gates of the carry stage and on the gates below its own, which are
//!   those of the stages. The mask over its own gates refuses
//!   a value there, the last page's included, whose polynomial is the
//!   circuit's own.
//! - A carry stage's polynomial is zero off the stage's gates, which its
//!   stage mask refuses a value off of.
//! - Every page that names a carry slot sums the one carry polynomial: a
//!   value planted on a slot moves the claim of the page that holds the
//!   slot to its wires and that of a page that reads it.
//! - A page's claim sums its own polynomial, its circuit's carry stage's,
//!   and those of stages: each of the last is held, by the mask over it,
//!   to the gates of a stage the page reserves, and every page's claim
//!   sums it, as every page loads every stage. Every internal circuit of
//!   the profile is paged, so these are all of its circuit claims.
//!
//! A value planted where a mask allows one leaves that mask's claim as it
//! was, so a claim that moves is one that tells the two apart.

use alloc::{format, string::String, vec, vec::Vec};
use core::{fmt::Debug, ops::Range};

use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    paging::{Layout, Planned, Stages},
    polynomials::{AggregatorRank, Rank, WalletRank, sparse},
    registry::{CircuitIndex, Registry, RegistryBuilder},
};
use ragu_core::{
    Result,
    pasta::{Fp, Fq, Pasta},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{Circuit, Slot, slots};
use crate::{
    Application, ApplicationBuilder, Proof, SelectableBackend,
    fuzzing::corrupt::{NativeRx, NestedRx, RxComponent as NativeComponent},
    internal::{
        native, nested,
        revdot::{Builder, Source},
    },
    ipa::IpaCycle,
    profile::{
        Aggregator, Cut, Pages, Profile, Profiled, ProfiledCycle, Standard, testing::UnitStep,
    },
};

const HEADER_SIZE: usize = 4;
type R = WalletRank;
type C = Profiled<Pasta, AllPaged>;

/// The standard profile with every internal circuit cut into pages: the
/// circuits in two, and both walks' steps in three, so that every
/// internal circuit's claim is a page's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AllPaged;

impl Profile for AllPaged {
    const NAME: &'static str = "all-paged";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const PAGES: Pages = Pages {
        endoscaling_step: Cut::pages(3),
        nested_endoscaling_step: Cut::pages(3),
        ..Pages::uniform(2)
    };
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 12;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 12;

    type Context<'params, Base, R, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        R: Rank,
        B: SelectableBackend;

    crate::paged_internal_circuits!();
}

/// A wire of a gate that holds a value of a stage.
#[derive(Clone, Copy, Debug)]
enum Wire {
    A,
    D,
}

/// A polynomial that is one at wire `wire` of gate `gate` and zero
/// elsewhere, in the trace layout.
fn planted<F: Field>(gate: usize, wire: Wire) -> sparse::Polynomial<F, R> {
    let n = R::n();
    let degree = match wire {
        Wire::A => 2 * n - 1 - gate,
        Wire::D => 4 * n - 1 - gate,
    };
    let mut coeffs = vec![F::ZERO; degree + 1];
    coeffs[degree] = F::ONE;
    sparse::Polynomial::from_coeffs(coeffs)
}

/// A claim of a claim list, by what it is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claim<Id> {
    Raw,
    Application,
    Circuit(Id),
    Mask(Id),
}

/// Records each claim a claim list builds, in order, with what it sums.
struct Labels<Id, Rx>(Vec<(Claim<Id>, Vec<Rx>)>);

impl<P: Profile, Rx, App> native::claims::Processor<P, Rx, App>
    for Labels<native::InternalCircuitIndex, Rx>
{
    fn raw_claim(&mut self, a: Rx, b: Rx) {
        self.0.push((Claim::Raw, vec![a, b]));
    }

    fn circuit_claim(&mut self, _: App, rxs: impl Iterator<Item = Rx>) {
        self.0.push((Claim::Application, rxs.collect()));
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) {
        self.0.push((Claim::Circuit(id), rxs.collect()));
    }

    fn mask_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) -> Result<()> {
        self.0.push((Claim::Mask(id), rxs.collect()));
        Ok(())
    }
}

impl<P: Profile, Rx> nested::claims::Processor<P, Rx> for Labels<nested::InternalCircuitIndex, Rx> {
    fn raw_claim(&mut self, a: Rx, b: Rx) {
        self.0.push((Claim::Raw, vec![a, b]));
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) {
        self.0.push((Claim::Circuit(id), rxs.collect()));
    }

    fn mask_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) -> Result<()> {
        self.0.push((Claim::Mask(id), rxs.collect()));
        Ok(())
    }
}

/// One proof's native polynomials by name, as [`NativeOf`] gives them:
/// what a claim sums, without the polynomials.
struct NativeNames;

impl Source for NativeNames {
    type RxComponent = native::RxComponent;
    type Rx = native::RxComponent;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Self::Rx> {
        match component {
            native::RxComponent::AbA | native::RxComponent::AbB => None,
            native::RxComponent::Rx(_) => Some(component),
        }
        .into_iter()
    }

    fn applications(&self) -> impl Iterator<Item = (CircuitIndex, [Self::Rx; 2])> {
        core::iter::empty()
    }
}

/// One proof's nested polynomials by name, as [`NestedOf`] gives them.
struct NestedNames;

impl Source for NestedNames {
    type RxComponent = nested::RxComponent;
    type Rx = nested::RxComponent;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Self::Rx> {
        core::iter::once(component)
    }

    fn applications(&self) -> impl Iterator<Item = ((), [Self::Rx; 2])> {
        core::iter::empty()
    }
}

/// One proof's native polynomials, as the verifier's source gives them:
/// without the raw claim's, whose target the verifier derives from them.
struct NativeOf<'rx>(&'rx Proof<C, R>);

impl<'rx> Source for NativeOf<'rx> {
    type RxComponent = native::RxComponent;
    type Rx = &'rx sparse::Polynomial<Fp, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Self::Rx> {
        let proof = self.0;
        match component {
            native::RxComponent::AbA | native::RxComponent::AbB => None,
            native::RxComponent::Rx(_) => Some(&proof[component]),
        }
        .into_iter()
    }

    fn applications(&self) -> impl Iterator<Item = (CircuitIndex, [Self::Rx; 2])> {
        core::iter::empty()
    }
}

/// One proof's nested polynomials, as the verifier's source gives them.
struct NestedOf<'rx>(&'rx Proof<C, R>);

impl<'rx> Source for NestedOf<'rx> {
    type RxComponent = nested::RxComponent;
    type Rx = &'rx sparse::Polynomial<Fq, R>;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Self::Rx> {
        let proof = self.0;
        core::iter::once(&proof[component])
    }

    fn applications(&self) -> impl Iterator<Item = ((), [Self::Rx; 2])> {
        core::iter::empty()
    }
}

/// One synthetic proof's rx polynomials. All are zero except `at`, whose
/// value is planted on one wire. This lets the production profile's claims
/// be tested without constructing a decompression proof.
struct NativePlanted<'rx> {
    zero: &'rx sparse::Polynomial<Fp, R>,
    at: native::RxComponent,
    value: &'rx sparse::Polynomial<Fp, R>,
}

impl<'rx> Source for NativePlanted<'rx> {
    type RxComponent = native::RxComponent;
    type Rx = &'rx sparse::Polynomial<Fp, R>;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = Self::Rx> {
        match component {
            native::RxComponent::AbA | native::RxComponent::AbB => None,
            native::RxComponent::Rx(_) => Some(if component == self.at {
                self.value
            } else {
                self.zero
            }),
        }
        .into_iter()
    }

    fn applications(&self) -> impl Iterator<Item = (CircuitIndex, [Self::Rx; 2])> {
        core::iter::empty()
    }
}

struct NestedPlanted<'rx> {
    zero: &'rx sparse::Polynomial<Fq, R>,
    at: nested::RxComponent,
    value: &'rx sparse::Polynomial<Fq, R>,
}

impl<'rx> Source for NestedPlanted<'rx> {
    type RxComponent = nested::RxComponent;
    type Rx = &'rx sparse::Polynomial<Fq, R>;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = Self::Rx> {
        core::iter::once(if component == self.at {
            self.value
        } else {
            self.zero
        })
    }

    fn applications(&self) -> impl Iterator<Item = ((), [Self::Rx; 2])> {
        core::iter::empty()
    }
}

/// The value of each native claim of `proof`, in the claim list's order.
fn native_values(
    app: &Application<'_, C, R, HEADER_SIZE>,
    proof: &Proof<C, R>,
    (y, z): (Fp, Fp),
) -> Result<Vec<Fp>> {
    let source = NativeOf(proof);
    let mut builder = Builder::<_, Fp, R, ReferenceBackend>::new(app.native_registry(), y, z);
    native::claims::build::<AllPaged, _, _>(&source, &mut builder)?;
    let claims = builder.finish();
    Ok(claims
        .a
        .iter()
        .zip(&claims.b)
        .map(|(a, b)| ReferenceBackend::sparse_revdot(a, b))
        .collect())
}

fn native_aggregator_values<const H: usize>(
    registry: &Registry<'_, Fp, R>,
    source: &NativePlanted<'_>,
    (y, z): (Fp, Fp),
) -> Result<Vec<Fp>> {
    let mut builder = Builder::<_, Fp, R, ReferenceBackend>::new(registry, y, z);
    native::claims::build::<Aggregator<H>, _, _>(source, &mut builder)?;
    let claims = builder.finish();
    Ok(claims
        .a
        .iter()
        .zip(&claims.b)
        .map(|(a, b)| ReferenceBackend::sparse_revdot(a, b))
        .collect())
}

fn nested_aggregator_values<const H: usize>(
    registry: &Registry<'_, Fq, R>,
    source: &NestedPlanted<'_>,
    (y, z): (Fq, Fq),
) -> Result<Vec<Fq>> {
    let mut builder = Builder::<_, Fq, R, ReferenceBackend>::new(registry, y, z);
    nested::claims::build::<Aggregator<H>, _, _>(source, &mut builder)?;
    let claims = builder.finish();
    Ok(claims
        .a
        .iter()
        .zip(&claims.b)
        .map(|(a, b)| ReferenceBackend::sparse_revdot(a, b))
        .collect())
}

/// The value of each nested claim of `proof`, in the claim list's order.
fn nested_values(
    app: &Application<'_, C, R, HEADER_SIZE>,
    proof: &Proof<C, R>,
    (y, z): (Fq, Fq),
) -> Result<Vec<Fq>> {
    let source = NestedOf(proof);
    let mut builder = Builder::<_, Fq, R, ReferenceBackend>::new(app.nested_registry(), y, z);
    nested::claims::build::<AllPaged, _, _>(&source, &mut builder)?;
    let claims = builder.finish();
    Ok(claims
        .a
        .iter()
        .zip(&claims.b)
        .map(|(a, b)| ReferenceBackend::sparse_revdot(a, b))
        .collect())
}

/// The polynomial of page `page` of `slot`'s circuit: an extension
/// circuit's, or the circuit's own for its last page.
fn native_page(slot: &Slot, page: usize) -> native::RxComponent {
    use native::RxIndex::*;
    native::RxComponent::Rx(if page < slot.last() {
        ExtensionCircuit(slot.circuits.start + page as u32)
    } else {
        match slot.circuit {
            Circuit::Hashes1 => Hashes1,
            Circuit::Hashes2 => Hashes2,
            Circuit::Collapse => Collapse,
            Circuit::ComputeV => ComputeV,
            Circuit::BindChallenges(k) => BindChallenges(k),
            Circuit::BindBeta => BindBeta,
            Circuit::BindEndoscalar => BindEndoscalar,
            Circuit::EndoscalingStep(step) => EndoscalingStep(step),
            other => unreachable!("{other:?} is a nested circuit"),
        }
    })
}

/// The circuit whose claim page `page` of `slot`'s circuit has.
fn native_circuit(slot: &Slot, page: usize) -> native::InternalCircuitIndex {
    use native::InternalCircuitIndex::*;
    if page < slot.last() {
        return ExtensionCircuit(slot.circuits.start + page as u32);
    }
    match slot.circuit {
        Circuit::Hashes1 => Hashes1Circuit,
        Circuit::Hashes2 => Hashes2Circuit,
        Circuit::Collapse => CollapseCircuit,
        Circuit::ComputeV => ComputeVCircuit,
        Circuit::BindChallenges(k) => BindChallengesCircuit(k),
        Circuit::BindBeta => BindBetaCircuit,
        Circuit::BindEndoscalar => BindEndoscalarCircuit,
        Circuit::EndoscalingStep(step) => EndoscalingStep(step),
        other => unreachable!("{other:?} is a nested circuit"),
    }
}

/// The nested counterpart of [`native_page`].
fn nested_page(slot: &Slot, page: usize) -> nested::RxComponent {
    use nested::RxIndex::*;
    nested::RxComponent::Rx(if page < slot.last() {
        ExtensionCircuit(slot.circuits.start + page as u32)
    } else {
        match slot.circuit {
            Circuit::NestedCollapse => Collapse,
            Circuit::NestedComputeV => ComputeV,
            Circuit::NestedEndoscalingStep(step) => EndoscalingStep(step),
            other => unreachable!("{other:?} is a native circuit"),
        }
    })
}

/// The nested counterpart of [`native_circuit`].
fn nested_circuit(slot: &Slot, page: usize) -> nested::InternalCircuitIndex {
    use nested::InternalCircuitIndex::*;
    if page < slot.last() {
        return ExtensionCircuit(slot.circuits.start + page as u32);
    }
    match slot.circuit {
        Circuit::NestedCollapse => Collapse,
        Circuit::NestedComputeV => ComputeV,
        Circuit::NestedEndoscalingStep(step) => EndoscalingStep(step),
        other => unreachable!("{other:?} is a native circuit"),
    }
}

/// One side of a proof, as its claim list names things.
struct Side<'a, Id, Rx> {
    name: &'a str,
    /// The side's paged circuits, and the layout and stages each was
    /// registered with.
    slots: &'a [Slot],
    plans: &'a [(Layout, Stages)],
    /// The side's claims in order, each with the polynomials it sums.
    claims: &'a [(Claim<Id>, Vec<Rx>)],
    /// The circuit whose claim a page has.
    circuit: fn(&Slot, usize) -> Id,
    /// An extension mask.
    mask: fn(u32) -> Id,
    /// A page's polynomial.
    page: fn(&Slot, usize) -> Rx,
    /// An extension stage's polynomial.
    stage: fn(u32) -> Rx,
    /// Whether every circuit claim is a page's. Production profiles may
    /// leave some circuits whole.
    every_circuit_paged: bool,
    /// A later walk step to probe as well as the first one.
    later_step: Option<u32>,
}

/// Whether the masks over polynomial `rx` hold it to the gates of `span`:
/// they allow it a value on the span's first gate and refuse it one on the
/// gate before the span and on the gate after it. `known` keeps what was
/// found.
fn held_to<Id, Rx: Copy + Debug + PartialEq>(
    claims: &[(Claim<Id>, Vec<Rx>)],
    known: &mut Vec<(Rx, Range<usize>, bool)>,
    moved: &mut impl FnMut(Rx, usize, Wire) -> Result<Vec<bool>>,
    rx: Rx,
    span: &Range<usize>,
) -> Result<bool> {
    if span.is_empty() {
        return Ok(false);
    }
    if let Some((_, _, held)) = known
        .iter()
        .find(|(other, gates, _)| *other == rx && gates == span)
    {
        return Ok(*held);
    }
    let masks: Vec<usize> = claims
        .iter()
        .enumerate()
        .filter(|(_, (label, sums))| matches!(label, Claim::Mask(_)) && sums.contains(&rx))
        .map(|(index, _)| index)
        .collect();
    assert!(!masks.is_empty(), "{rx:?} is under no mask");
    let mut refused = |gate: usize| -> Result<bool> {
        let moved = moved(rx, gate, Wire::D)?;
        Ok(masks.iter().any(|&mask| moved[mask]))
    };
    // The blind gate's wire is no mask's to refuse.
    let held = !refused(span.start)?
        && (span.start <= 1 || refused(span.start - 1)?)
        && (span.end >= R::blind_gate() || refused(span.end)?);
    known.push((rx, span.clone(), held));
    Ok(held)
}

/// Checks one side's paged circuits. `moved` plants a value at a wire of a
/// gate of a polynomial and tells which claims' values it moved.
fn holds<Id, Rx>(
    side: &Side<'_, Id, Rx>,
    mut moved: impl FnMut(Rx, usize, Wire) -> Result<Vec<bool>>,
) -> Result<()>
where
    Id: Copy + Debug + PartialEq,
    Rx: Copy + Debug + PartialEq,
{
    let name = side.name;
    let claim = |label: Claim<Id>| {
        side.claims
            .iter()
            .position(|(other, _)| *other == label)
            .unwrap_or_else(|| panic!("the {name} claims have no {label:?}"))
    };
    assert_eq!(
        side.slots.len(),
        side.plans.len(),
        "a plan for each paged circuit"
    );
    let mut known = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    let (mut pages, mut carries, mut stages) = (0, 0, 0);
    let mut seen = vec![false; side.claims.len()];
    for (slot, (layout, loads)) in side.slots.iter().zip(side.plans) {
        // A walk's steps are cut alike: the first stands for them where a
        // value is planted. What every step's claims sum is looked at.
        let planted = !matches!(
            slot.circuit,
            Circuit::EndoscalingStep(step) | Circuit::NestedEndoscalingStep(step)
                if step > 0 && Some(step) != side.later_step
        );
        let which = slot.circuit;

        for page in (0..=slot.last()).filter(|_| planted) {
            let own = claim(Claim::Mask((side.mask)(slot.mask)));
            let window = layout.window();
            let polynomial = (side.page)(slot, page);

            // On the carry stage's gates.
            if !layout.carry.is_empty() {
                assert!(
                    moved(polynomial, layout.carry.start, Wire::D)?[own],
                    "{name} {which:?}: page {page}'s mask allows its polynomial a value on the \
                     carry stage, at gate {}",
                    layout.carry.start
                );
            }
            // On the gate below its own: of a stage it loads, or of its
            // circuit's last stage.
            if window.start > 1 {
                assert!(
                    moved(polynomial, window.start - 1, Wire::D)?[own],
                    "{name} {which:?}: page {page}'s mask allows its polynomial a value below \
                     its own gates, at gate {}",
                    window.start - 1
                );
            }
            // On its own gates the mask says nothing.
            if !window.is_empty() {
                assert!(
                    !moved(polynomial, window.start, Wire::D)?[own],
                    "{name} {which:?}: page {page}'s mask refuses its polynomial a value on its \
                     own gate {}",
                    window.start
                );
            }
            pages += 1;
        }

        // The circuit's carry stage.
        let (stage, gates) = (slot.carry, &layout.carry);
        if planted && !gates.is_empty() {
            let own = claim(Claim::Mask((side.mask)(stage)));
            let polynomial = (side.stage)(stage);
            assert!(
                moved(polynomial, gates.start - 1, Wire::D)?[own],
                "{name} {which:?}: the carry stage's mask allows its polynomial a value off its \
                 gates, at gate {}",
                gates.start - 1
            );
            // Its first slot: the mask says nothing of it, and the pages
            // that name it are the one that holds it to its wires and
            // those that read it.
            let slot_moved = moved(polynomial, gates.start, Wire::A)?;
            assert!(
                !slot_moved[own],
                "{name} {which:?}: the carry stage's mask refuses a value on its own gate {}",
                gates.start
            );
            let named = (0..=slot.last())
                .filter(|&page| slot_moved[claim(Claim::Circuit((side.circuit)(slot, page)))])
                .count();
            assert!(
                named >= 2,
                "{name} {which:?}: a value on a slot of the carry stage moved the claims of \
                 {named} pages, where one holds the slot and another reads it"
            );
            carries += 1;
        }

        // What each page's claim sums: its own polynomial and the carry
        // stage's, once each, and those of stages.
        let sums = |page: usize| &side.claims[claim(Claim::Circuit((side.circuit)(slot, page)))].1;
        for page in 0..=slot.last() {
            seen[claim(Claim::Circuit((side.circuit)(slot, page)))] = true;
            let own = (side.page)(slot, page);
            let carried = (side.stage)(slot.carry);
            for rx in [&own, &carried] {
                let times = sums(page).iter().filter(|other| *other == rx).count();
                if times != 1 {
                    wrong.push(format!(
                        "{which:?}: page {page}'s claim sums {rx:?} {times} times"
                    ));
                }
            }
            // A stage's polynomial is held to the gates of a stage the page
            // reserves, each to a stage of its own. A sum does not depend on
            // the order of its terms, so a claim may list its stages in
            // another order than the circuit reserves them; a stage it
            // reserves and whose polynomial its claim leaves out is passed
            // over.
            let mut unmatched: Vec<(usize, &Range<usize>)> =
                loads.spans.iter().enumerate().collect();
            for &rx in sums(page)
                .iter()
                .filter(|rx| **rx != own && **rx != carried)
            {
                let mut found = None;
                for (place, &(stage, span)) in unmatched.iter().enumerate() {
                    if held_to(side.claims, &mut known, &mut moved, rx, span)? {
                        found = Some((place, stage));
                        break;
                    }
                }
                let found = found.map(|(place, stage)| {
                    unmatched.remove(place);
                    stage
                });
                let Some(stage) = found else {
                    wrong.push(format!(
                        "{which:?}: page {page}'s claim sums {rx:?}, which no mask holds to the \
                         gates of a stage the page reserves, of {:?}",
                        loads.spans
                    ));
                    continue;
                };
                // Every page loads the stage, so every page's claim sums it.
                for other in 0..=slot.last() {
                    if !sums(other).contains(&rx) {
                        wrong.push(format!(
                            "{which:?}: page {other} loads stage {stage}, and its claim does not \
                             sum {rx:?}"
                        ));
                    }
                }
                stages += 1;
            }
        }
    }
    assert!(wrong.is_empty(), "the {name} side: {wrong:#?}");
    let unseen: Vec<_> = side
        .claims
        .iter()
        .zip(&seen)
        .filter(|((label, _), seen)| matches!(label, Claim::Circuit(_)) && !**seen)
        .map(|((label, _), _)| *label)
        .collect();
    if side.every_circuit_paged {
        assert!(
            unseen.is_empty(),
            "the {name} side has circuit claims that are no page's: {unseen:?}"
        );
    }
    assert!(
        pages > 0 && carries > 0 && stages > 0,
        "the {name} side has pages, carry stages and stages to check"
    );
    Ok(())
}

/// The layout and the stages each of one side's paged circuits was
/// registered with.
fn plans<F: Field>(plans: &[Option<Planned<F>>]) -> Vec<(Layout, Stages)> {
    plans
        .iter()
        .map(|planned| {
            let planned = planned
                .as_ref()
                .expect("every paged circuit was registered");
            (planned.layout().clone(), planned.stages().clone())
        })
        .collect()
}

#[test]
fn pages_and_carry_stages_are_held_to_their_gates() -> Result<()> {
    let params = crate::pasta::baked();
    let app = ApplicationBuilder::<C, R, HEADER_SIZE>::new()
        .register(UnitStep)?
        .finalize(params)?;
    let mut rng = StdRng::seed_from_u64(0x0009_a6ed);
    let (left, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (right, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), left, right)?;
    assert!(app.verify_uncompressed(&parent, &mut rng)?);
    let honest = parent.proof().clone();

    // The native side.
    {
        let points = (
            Fp::random(|bytes| rng.fill_bytes(bytes)),
            Fp::random(|bytes| rng.fill_bytes(bytes)),
        );
        let slots = slots::<AllPaged>(false);
        let mut labels: Labels<native::InternalCircuitIndex, native::RxComponent> =
            Labels(Vec::new());
        native::claims::build::<AllPaged, _, _>(&NativeNames, &mut labels)?;
        let clean = native_values(&app, &honest, points)?;
        assert_eq!(labels.0.len(), clean.len(), "a value for each claim");
        holds(
            &Side {
                name: "native",
                slots: &slots,
                plans: &plans(&app.native_plans.0),
                claims: &labels.0,
                circuit: native_circuit,
                mask: native::InternalCircuitIndex::ExtensionMask,
                page: native_page,
                stage: |stage| native::RxComponent::Rx(native::RxIndex::ExtensionStage(stage)),
                every_circuit_paged: true,
                later_step: None,
            },
            |polynomial, gate, wire| {
                let native::RxComponent::Rx(index) = polynomial else {
                    unreachable!("a claim's polynomials are rx polynomials")
                };
                let mut proof = honest.clone();
                proof
                    .native_component_mut(NativeComponent::Rx(NativeRx::from_internal(index)))
                    .add_assign(&planted(gate, wire));
                let values = native_values(&app, &proof, points)?;
                Ok(values.iter().zip(&clean).map(|(a, b)| a != b).collect())
            },
        )?;
    }

    // The nested side.
    {
        let points = (
            Fq::random(|bytes| rng.fill_bytes(bytes)),
            Fq::random(|bytes| rng.fill_bytes(bytes)),
        );
        let slots = slots::<AllPaged>(true);
        let mut labels: Labels<nested::InternalCircuitIndex, nested::RxComponent> =
            Labels(Vec::new());
        nested::claims::build::<AllPaged, _, _>(&NestedNames, &mut labels)?;
        let clean = nested_values(&app, &honest, points)?;
        assert_eq!(labels.0.len(), clean.len(), "a value for each claim");
        holds(
            &Side {
                name: "nested",
                slots: &slots,
                plans: &plans(&app.nested_plans.0),
                claims: &labels.0,
                circuit: nested_circuit,
                mask: nested::InternalCircuitIndex::ExtensionMask,
                page: nested_page,
                stage: |stage| nested::RxComponent::Rx(nested::RxIndex::ExtensionStage(stage)),
                every_circuit_paged: true,
                later_step: None,
            },
            |polynomial, gate, wire| {
                let nested::RxComponent::Rx(index) = polynomial else {
                    unreachable!("a page's claim sums rx polynomials")
                };
                let mut proof = honest.clone();
                proof
                    .nested_rx_mut(NestedRx::from_internal(index))
                    .add_assign(&planted(gate, wire));
                let values = nested_values(&app, &proof, points)?;
                Ok(values.iter().zip(&clean).map(|(a, b)| a != b).collect())
            },
        )?;
    }
    Ok(())
}

/// The AllPaged test pages every internal circuit with an honest proof.
/// This test uses the production aggregator profile and its registered
/// circuits, then plants a value in one proof polynomial at a time. It
/// checks the first and last walk steps as well as the non-step pages.
fn aggregator_claims_bind_pages_and_carries<const H: usize>() -> Result<()> {
    type P<const H: usize> = Aggregator<H>;
    type C<const H: usize> = Profiled<Pasta, P<H>>;

    assert_eq!(R::RANK, AggregatorRank::RANK, "the aggregator's rank");
    let params = crate::pasta::baked();
    let log2_circuits = native::total_circuit_counts::<P<H>>(0).1;
    let (native_registry, native_plans) = native::register_all::<C<H>, R, H>(
        RegistryBuilder::new(),
        params,
        log2_circuits,
        0,
        Some(Fp::ONE),
        Some(4),
    )?;
    let (nested_registry, nested_plans) =
        nested::register_all::<C<H>, R>(RegistryBuilder::new(), params, Some(Fq::ONE), Some(4))?;
    let native_registry = native_registry.finalize()?;
    let nested_registry = nested_registry.finalize()?;
    let mut rng = StdRng::seed_from_u64(0x1030_a6ed);

    {
        let points = (
            Fp::random(|bytes| rng.fill_bytes(bytes)),
            Fp::random(|bytes| rng.fill_bytes(bytes)),
        );
        let slots = slots::<P<H>>(false);
        let later_step = slots
            .iter()
            .filter_map(|slot| match slot.circuit {
                Circuit::EndoscalingStep(step) => Some(step),
                _ => None,
            })
            .max()
            .expect("the aggregator pages its native walk");
        assert!(later_step > 0);
        let mut labels: Labels<native::InternalCircuitIndex, native::RxComponent> =
            Labels(Vec::new());
        native::claims::build::<P<H>, _, _>(&NativeNames, &mut labels)?;
        let zero = sparse::Polynomial::<Fp, R>::default();
        let clean = native_aggregator_values::<H>(
            &native_registry,
            &NativePlanted {
                zero: &zero,
                at: native::RxComponent::Rx(native::RxIndex::Preamble),
                value: &zero,
            },
            points,
        )?;
        assert_eq!(labels.0.len(), clean.len(), "a value for each native claim");
        holds(
            &Side {
                name: "aggregator native",
                slots: &slots,
                plans: &plans(&native_plans.0),
                claims: &labels.0,
                circuit: native_circuit,
                mask: native::InternalCircuitIndex::ExtensionMask,
                page: native_page,
                stage: |stage| native::RxComponent::Rx(native::RxIndex::ExtensionStage(stage)),
                every_circuit_paged: false,
                later_step: Some(later_step),
            },
            |polynomial, gate, wire| {
                let native::RxComponent::Rx(_) = polynomial else {
                    unreachable!("a page's polynomial is an rx polynomial")
                };
                let value = planted::<Fp>(gate, wire);
                let source = NativePlanted {
                    zero: &zero,
                    at: polynomial,
                    value: &value,
                };
                let values = native_aggregator_values::<H>(&native_registry, &source, points)?;
                Ok(values.iter().zip(&clean).map(|(a, b)| a != b).collect())
            },
        )?;
    }

    {
        let points = (
            Fq::random(|bytes| rng.fill_bytes(bytes)),
            Fq::random(|bytes| rng.fill_bytes(bytes)),
        );
        let slots = slots::<P<H>>(true);
        let later_step = slots
            .iter()
            .filter_map(|slot| match slot.circuit {
                Circuit::NestedEndoscalingStep(step) => Some(step),
                _ => None,
            })
            .max()
            .expect("the aggregator pages its nested walk");
        assert!(later_step > 0);
        let mut labels: Labels<nested::InternalCircuitIndex, nested::RxComponent> =
            Labels(Vec::new());
        nested::claims::build::<P<H>, _, _>(&NestedNames, &mut labels)?;
        let zero = sparse::Polynomial::<Fq, R>::default();
        let clean = nested_aggregator_values::<H>(
            &nested_registry,
            &NestedPlanted {
                zero: &zero,
                at: nested::RxComponent::Rx(nested::RxIndex::PointsStage),
                value: &zero,
            },
            points,
        )?;
        assert_eq!(labels.0.len(), clean.len(), "a value for each nested claim");
        holds(
            &Side {
                name: "aggregator nested",
                slots: &slots,
                plans: &plans(&nested_plans.0),
                claims: &labels.0,
                circuit: nested_circuit,
                mask: nested::InternalCircuitIndex::ExtensionMask,
                page: nested_page,
                stage: |stage| nested::RxComponent::Rx(nested::RxIndex::ExtensionStage(stage)),
                every_circuit_paged: false,
                later_step: Some(later_step),
            },
            |polynomial, gate, wire| {
                let nested::RxComponent::Rx(_) = polynomial else {
                    unreachable!("a page's polynomial is an rx polynomial")
                };
                let value = planted::<Fq>(gate, wire);
                let source = NestedPlanted {
                    zero: &zero,
                    at: polynomial,
                    value: &value,
                };
                let values = nested_aggregator_values::<H>(&nested_registry, &source, points)?;
                Ok(values.iter().zip(&clean).map(|(a, b)| a != b).collect())
            },
        )?;
    }
    Ok(())
}

#[test]
fn production_aggregator_claims_bind_pages_and_carries() -> Result<()> {
    aggregator_claims_bind_pages_and_carries::<4>()
}

#[cfg(ragu_pcd_nightly_tests)]
#[test]
#[ignore = "checks production claim and mask bindings at the widest header"]
fn widest_aggregator_claims_bind_pages_and_carries() -> Result<()> {
    aggregator_claims_bind_pages_and_carries::<195>()
}

/// A page before its circuit's last is registered with the zero suffix
/// every extension circuit's public output takes. Its k(Y) is still 1, the
/// target its claim is held to: the suffix adds a zero term, and the page's
/// only output is its ONE.
#[test]
fn a_registered_page_is_held_to_one() -> Result<()> {
    use ragu_circuits::CircuitExt;

    let params = crate::pasta::baked();
    let paged =
        super::split(
            Circuit::Hashes2,
            native::circuits::hashes_2::Circuit::<
                C,
                R,
                HEADER_SIZE,
                native::RevdotParameters<AllPaged>,
            >::new(params),
            Cut::pages(2),
        )?;
    paged.check()?;
    let mut rng = StdRng::seed_from_u64(0x5ff1);
    let y = Fp::random(|bytes| rng.fill_bytes(bytes));
    for page in 0..paged.num_pages() - 1 {
        let page = paged.page(page);
        assert_eq!(page.ky((), y)?, Fp::ONE, "a page's k(y) is one");
        assert_eq!(
            crate::profile::Suffixed(page).ky((), y)?,
            Fp::ONE,
            "the page as it is registered is held to one"
        );
    }
    Ok(())
}
