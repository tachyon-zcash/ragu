//! What each pageable internal circuit's claims sum, and what they are
//! held to, over the claims the fuse builds.
//!
//! A circuit's claim sums the polynomials of the stages it loads, and the
//! circuit's constraints read those stages' wires at the gates it reserves
//! for them. Nothing where a registry is built ties the claim lists to the
//! circuits, nor did it before paging. These tests do, each driving
//! [`build`](crate::internal::native::claims::build) on a source whose
//! every polynomial is its own index, so that what they check is what the
//! prover, the verifier and the in-circuit fold sum:
//!
//! - every page of a circuit the aggregator pages sums the stages the
//!   circuit's claim summed before paging, pinned here, beside its carry
//!   stage;
//! - every stage a claim sums is one its circuit reserves, at most once,
//!   and every stage the circuit reserves that the claim leaves out is one
//!   whose wires it reads none of;
//! - every page's own polynomial, the last page's included, is under the
//!   one mask claim over its own gates, and each carry stage under its
//!   stage's;
//! - the circuit claims come before the mask claims and are as many as
//!   their targets, each page's being one, so that no claim is held to the
//!   zeros the targets end in or to another claim's target.

use alloc::{vec, vec::Vec};
use core::any::type_name;

use ragu_circuits::{
    paging::{Pageable, Stages, reads},
    polynomials::{Rank, WalletRank},
    staging::{MultiStage, Stage},
};
use ragu_core::{Cycle, pasta::Pasta};
use udon::field::Field;

use crate::{
    internal::{endoscalar, native, nested, revdot::Source},
    profile::{
        Aggregator, Profile, Profiled, ProfiledCycle, paging,
        testing::{Twin, Wider},
    },
};

/// A source of one proof whose every polynomial is its own index.
struct Labels;

impl Source for Labels {
    type RxComponent = native::RxComponent;
    type Rx = native::RxIndex;
    type AppCircuitId = ();

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = native::RxIndex> {
        match component {
            native::RxComponent::Rx(index) => Some(index),
            native::RxComponent::AbA | native::RxComponent::AbB => None,
        }
        .into_iter()
    }

    fn applications(&self) -> impl Iterator<Item = ((), [native::RxIndex; 2])> {
        core::iter::empty()
    }
}

/// The nested side's [`Labels`].
struct NestedLabels;

impl Source for NestedLabels {
    type RxComponent = nested::RxComponent;
    type Rx = nested::RxIndex;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = nested::RxIndex> {
        match component {
            nested::RxComponent::Rx(index) => Some(index),
            nested::RxComponent::AbA | nested::RxComponent::AbB => None,
        }
        .into_iter()
    }

    fn applications(&self) -> impl Iterator<Item = ((), [nested::RxIndex; 2])> {
        core::iter::empty()
    }
}

/// What a claim `build` makes is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Claimed<Id> {
    /// A raw or an application claim.
    Other,
    /// An internal circuit's claim.
    Circuit(Id),
    /// A mask's claim.
    Mask(Id),
}

/// The claims `build` makes, in order, each with the indices it sums.
struct Recorded<Id, Rx>(Vec<(Claimed<Id>, Vec<Rx>)>);

impl<Id: Copy, Rx: Clone> Recorded<Id, Rx> {
    /// The internal circuit claims, in order.
    fn circuits(&self) -> impl Iterator<Item = (Id, Vec<Rx>)> + '_ {
        self.0.iter().filter_map(|(claimed, rxs)| match claimed {
            Claimed::Circuit(id) => Some((*id, rxs.clone())),
            _ => None,
        })
    }

    /// The mask claims, in order.
    fn masks(&self) -> impl Iterator<Item = (Id, &[Rx])> + '_ {
        self.0.iter().filter_map(|(claimed, rxs)| match claimed {
            Claimed::Mask(id) => Some((*id, rxs.as_slice())),
            _ => None,
        })
    }
}

impl<P: Profile> native::claims::Processor<P, native::RxIndex, ()>
    for Recorded<native::InternalCircuitIndex, native::RxIndex>
{
    fn raw_claim(&mut self, a: native::RxIndex, b: native::RxIndex) {
        self.0.push((Claimed::Other, vec![a, b]));
    }

    fn circuit_claim(&mut self, _: (), rxs: impl Iterator<Item = native::RxIndex>) {
        self.0.push((Claimed::Other, rxs.collect()));
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = native::RxIndex>,
    ) {
        self.0.push((Claimed::Circuit(id), rxs.collect()));
    }

    fn mask_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = native::RxIndex>,
    ) -> ragu_core::Result<()> {
        self.0.push((Claimed::Mask(id), rxs.collect()));
        Ok(())
    }
}

impl<P: Profile> nested::claims::Processor<P, nested::RxIndex>
    for Recorded<nested::InternalCircuitIndex, nested::RxIndex>
{
    fn raw_claim(&mut self, a: nested::RxIndex, b: nested::RxIndex) {
        self.0.push((Claimed::Other, vec![a, b]));
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = nested::RxIndex>,
    ) {
        self.0.push((Claimed::Circuit(id), rxs.collect()));
    }

    fn mask_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = nested::RxIndex>,
    ) -> ragu_core::Result<()> {
        self.0.push((Claimed::Mask(id), rxs.collect()));
        Ok(())
    }
}

/// The claims `build` makes for profile `P` on the native side.
fn native_recorded<P: Profile>() -> Recorded<native::InternalCircuitIndex, native::RxIndex> {
    let mut recorded = Recorded(Vec::new());
    native::claims::build::<P, _, _>(&Labels, &mut recorded).expect("the native claims");
    recorded
}

/// The claims `build` makes for profile `P` on the nested side.
fn nested_recorded<P: Profile>() -> Recorded<nested::InternalCircuitIndex, nested::RxIndex> {
    let mut recorded = Recorded(Vec::new());
    nested::claims::build::<P, _, _>(&NestedLabels, &mut recorded).expect("the nested claims");
    recorded
}

/// The polynomial of a native pageable circuit's own slot, which is its
/// last page's.
fn native_own(circuit: paging::Circuit) -> native::RxIndex {
    use native::RxIndex as Rx;
    use paging::Circuit;
    match circuit {
        Circuit::Hashes1 => Rx::Hashes1,
        Circuit::Hashes2 => Rx::Hashes2,
        Circuit::Collapse => Rx::Collapse,
        Circuit::ComputeV => Rx::ComputeV,
        Circuit::BindChallenges(k) => Rx::BindChallenges(k),
        Circuit::BindBeta => Rx::BindBeta,
        Circuit::BindEndoscalar => Rx::BindEndoscalar,
        Circuit::EndoscalingStep(step) => Rx::EndoscalingStep(step),
        Circuit::NestedCollapse | Circuit::NestedComputeV | Circuit::NestedEndoscalingStep(_) => {
            unreachable!("a native circuit")
        }
    }
}

/// The nested side's [`native_own`].
fn nested_own(circuit: paging::Circuit) -> nested::RxIndex {
    use nested::RxIndex as Rx;
    use paging::Circuit;
    match circuit {
        Circuit::NestedCollapse => Rx::INSTANCE[0],
        Circuit::NestedComputeV => Rx::INSTANCE[1],
        Circuit::NestedEndoscalingStep(step) => Rx::EndoscalingStep(step),
        _ => unreachable!("a nested circuit"),
    }
}

/// The claims of each pageable circuit, one for each of its pages, as the
/// stages they sum: each claim's own polynomial and, for a paged circuit,
/// its carry stage, which every page sums last, are taken off.
type ByCircuit<Rx> = Vec<(paging::Circuit, Vec<Vec<Rx>>)>;

/// Files `stages`, a claim of `circuit`'s whose own polynomial is `own`.
fn file<Rx: Copy + PartialEq + core::fmt::Debug>(
    by_circuit: &mut ByCircuit<Rx>,
    placements: &[paging::Placement],
    (circuit, own): (paging::Circuit, Rx),
    mut stages: Vec<Rx>,
    carry: impl Fn(u32) -> Rx,
) {
    assert_eq!(
        stages.first(),
        Some(&own),
        "{circuit:?}: its own polynomial"
    );
    stages.remove(0);
    if let Some(placement) = placements
        .iter()
        .find(|placement| placement.circuit == circuit)
    {
        assert_eq!(
            stages.pop(),
            Some(carry(placement.carry)),
            "{circuit:?}: its carry stage, last"
        );
    }
    match by_circuit.iter_mut().find(|(of, _)| *of == circuit) {
        Some((_, claims)) => claims.push(stages),
        None => by_circuit.push((circuit, vec![stages])),
    }
}

/// Checks that each paged circuit has a claim for each of its pages, and
/// any other one claim.
fn check_counts<Rx>(by_circuit: &ByCircuit<Rx>, placements: &[paging::Placement]) {
    for placement in placements {
        assert!(
            by_circuit.iter().any(|(of, _)| *of == placement.circuit),
            "{:?} is paged and has no claim",
            placement.circuit
        );
    }
    for (circuit, claims) in by_circuit {
        let pages = placements
            .iter()
            .find(|placement| placement.circuit == *circuit)
            .map_or(1, |placement| placement.last() + 1);
        assert_eq!(claims.len(), pages, "{circuit:?}: a claim for each page");
    }
}

/// The native claims of `P`'s pageable circuits.
fn native_claims<P: Profile>() -> ByCircuit<native::RxIndex> {
    use native::{InternalCircuitIndex as Id, RxIndex as Rx};
    use paging::Circuit;

    let recorded = native_recorded::<P>();
    let placements = paging::placements::<P>(false);
    let mut by_circuit = Vec::new();
    for (id, stages) in recorded.circuits() {
        let filed = match id {
            Id::Hashes1Circuit => (Circuit::Hashes1, Rx::Hashes1),
            Id::Hashes2Circuit => (Circuit::Hashes2, Rx::Hashes2),
            Id::CollapseCircuit => (Circuit::Collapse, Rx::Collapse),
            Id::ComputeVCircuit => (Circuit::ComputeV, Rx::ComputeV),
            Id::BindChallengesCircuit(k) => (Circuit::BindChallenges(k), Rx::BindChallenges(k)),
            Id::BindBetaCircuit => (Circuit::BindBeta, Rx::BindBeta),
            Id::BindEndoscalarCircuit => (Circuit::BindEndoscalar, Rx::BindEndoscalar),
            Id::EndoscalingStep(step) => {
                (Circuit::EndoscalingStep(step), Rx::EndoscalingStep(step))
            }
            Id::ExtensionCircuit(k) => match placements
                .iter()
                .find(|placement| placement.page(k).is_some())
            {
                Some(placement) => (placement.circuit, Rx::ExtensionCircuit(k)),
                None => continue,
            },
            _ => continue,
        };
        file(
            &mut by_circuit,
            &placements,
            filed,
            stages,
            Rx::ExtensionStage,
        );
    }
    check_counts(&by_circuit, &placements);
    by_circuit
}

/// The nested claims of `P`'s pageable circuits.
fn nested_claims<P: Profile>() -> ByCircuit<nested::RxIndex> {
    use nested::{InternalCircuitIndex as Id, RxIndex as Rx};
    use paging::Circuit;

    let recorded = nested_recorded::<P>();
    let placements = paging::placements::<P>(true);
    let mut by_circuit = Vec::new();
    for (id, stages) in recorded.circuits() {
        let filed = match id {
            Id::Collapse => (Circuit::NestedCollapse, Rx::INSTANCE[0]),
            Id::ComputeV => (Circuit::NestedComputeV, Rx::INSTANCE[1]),
            Id::EndoscalingStep(step) => (
                Circuit::NestedEndoscalingStep(step),
                Rx::EndoscalingStep(step),
            ),
            Id::ExtensionCircuit(k) => match placements
                .iter()
                .find(|placement| placement.page(k).is_some())
            {
                Some(placement) => (placement.circuit, Rx::ExtensionCircuit(k)),
                None => continue,
            },
            _ => continue,
        };
        file(
            &mut by_circuit,
            &placements,
            filed,
            stages,
            Rx::ExtensionStage,
        );
    }
    check_counts(&by_circuit, &placements);
    by_circuit
}

/// The stages each native circuit's claim summed before paging: the arms
/// of `main`'s `build`, as they read for the aggregator, whose collapse and
/// `compute_v` take the points binding stage. Pinned, not derived from the
/// lists the claims are built from, so that a change to those lists fails
/// here even when it moves a circuit's pages with it.
fn native_before_paging(circuit: paging::Circuit) -> Vec<native::RxIndex> {
    use native::RxIndex::*;
    use paging::Circuit;
    match circuit {
        Circuit::Hashes1 => vec![Preamble, OuterError],
        Circuit::Hashes2 => vec![OuterError],
        Circuit::Collapse => vec![PointsBinding, Preamble, InnerError, OuterError],
        Circuit::ComputeV => vec![PointsBinding, Preamble, Query, Eval],
        Circuit::BindChallenges(_) => vec![Preamble, Query, Eval],
        Circuit::BindBeta => vec![PointsBinding, Preamble],
        Circuit::BindEndoscalar | Circuit::EndoscalingStep(_) => vec![
            PointsBinding,
            PointsPreamble,
            PointsRegistryWx,
            PointsAb,
            PointsF,
            PointsWalk,
        ],
        Circuit::NestedCollapse | Circuit::NestedComputeV | Circuit::NestedEndoscalingStep(_) => {
            unreachable!("a native circuit")
        }
    }
}

/// The nested side's [`native_before_paging`]: every nested stage for the
/// instance circuits, and the endoscalar's and the points' for a step.
fn nested_before_paging(circuit: paging::Circuit) -> Vec<nested::RxIndex> {
    use nested::RxIndex::*;
    use paging::Circuit;
    match circuit {
        Circuit::NestedCollapse | Circuit::NestedComputeV => vec![
            EndoscalarStage,
            BridgeHash,
            PointsStage,
            BridgePreamble,
            BridgeSPrime,
            BridgeInnerError,
            BridgeOuterError,
            BridgeAB,
            BridgeQuery,
            BridgeF,
            BridgeEval,
            ChallengeStage,
        ],
        Circuit::NestedEndoscalingStep(_) => vec![EndoscalarStage, PointsStage],
        _ => unreachable!("a nested circuit"),
    }
}

fn check_parity<P: Profile>() {
    let native = native_claims::<P>();
    let nested = nested_claims::<P>();
    assert!(
        !paging::placements::<P>(false).is_empty() && !paging::placements::<P>(true).is_empty(),
        "the aggregator pages on both sides"
    );
    for (circuit, claims) in native {
        let expected = native_before_paging(circuit);
        for (page, stages) in claims.iter().enumerate() {
            assert_eq!(stages, &expected, "{circuit:?}, claim {page}");
        }
    }
    for (circuit, claims) in nested {
        let expected = nested_before_paging(circuit);
        for (page, stages) in claims.iter().enumerate() {
            assert_eq!(stages, &expected, "{circuit:?}, claim {page}");
        }
    }
}

/// Every page of every circuit the aggregator pages sums the stages the
/// circuit's claim summed before paging, and its carry stage: no page
/// leaves out a stage the circuit's claim sums, or sums one it does not.
#[test]
fn aggregator_pages_sum_the_stages_of_their_unpaged_circuit() {
    check_parity::<Aggregator<1>>();
    check_parity::<Aggregator<4>>();
    check_parity::<Aggregator<195>>();
}

/// Collects `S`'s stage and the `depth - 1` before it, by type, in the
/// order the circuit reserves them.
fn chain<F: Field, R: Rank, S: Stage<F, R>>(depth: usize, names: &mut Vec<&'static str>) {
    if depth > 0 {
        chain::<F, R, S::Parent>(depth - 1, names);
        names.push(type_name::<S>());
    }
}

/// Checks each of `claims`, the stages a claim of `circuit` sums by type,
/// against the stages `circuit` reserves and the wires it reads of them.
fn check_reserved<F: Field, R: Rank, S: Pageable<F, R>>(
    which: paging::Circuit,
    circuit: MultiStage<F, R, S>,
    claims: &[Vec<&'static str>],
) {
    let stages = Stages::of::<F, R, S>();
    let mut reserved = Vec::new();
    chain::<F, R, S::Last>(stages.spans.len(), &mut reserved);
    let read = reads(&circuit, &stages, 1)
        .expect("the circuit walks")
        .remove(0);
    for (index, claim) in claims.iter().enumerate() {
        let mut summed = vec![false; reserved.len()];
        for stage in claim {
            let place = reserved
                .iter()
                .position(|name| name == stage)
                .unwrap_or_else(|| {
                    panic!("{which:?}, claim {index}: sums {stage}, which it does not reserve")
                });
            assert!(
                !summed[place],
                "{which:?}, claim {index}: sums {stage} twice"
            );
            summed[place] = true;
        }
        for (a, span) in stages.spans.iter().enumerate() {
            for (b, other) in stages.spans.iter().enumerate().skip(a + 1) {
                assert!(
                    !(summed[a] && summed[b] && span.start < other.end && other.start < span.end),
                    "{which:?}, claim {index}: sums {} and {}, which share gates",
                    reserved[a],
                    reserved[b]
                );
            }
        }
        for (place, &wires) in read.iter().enumerate() {
            assert!(
                summed[place] || wires == 0,
                "{which:?}, claim {index}: reads {wires} wires of {}, which it does not sum",
                reserved[place]
            );
        }
    }
}

/// The type of the native stage `rx` is the polynomial of, as its mask is
/// registered.
fn native_stage<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>(
    rx: native::RxIndex,
) -> &'static str {
    use native::{
        RxIndex::*,
        stages::{eval, inner_error, outer_error, points, preamble, query},
    };
    type Revdot<C> = native::RevdotParameters<<C as ProfiledCycle>::Profile>;
    match rx {
        Preamble => type_name::<preamble::Stage<C, R, HEADER_SIZE>>(),
        InnerError => type_name::<inner_error::Stage<C, R, HEADER_SIZE, Revdot<C>>>(),
        OuterError => type_name::<outer_error::Stage<C, R, HEADER_SIZE, Revdot<C>>>(),
        Query => type_name::<query::Stage<C, R, HEADER_SIZE>>(),
        Eval => type_name::<eval::Stage<C, R, HEADER_SIZE>>(),
        PointsBinding => type_name::<points::BindingStage<C::NestedCurve, C::Profile>>(),
        PointsPreamble => type_name::<points::PreambleStage<C::NestedCurve, C::Profile>>(),
        PointsRegistryWx => type_name::<points::RegistryWxStage<C::NestedCurve, C::Profile>>(),
        PointsAb => type_name::<points::AbStage<C::NestedCurve, C::Profile>>(),
        PointsF => type_name::<points::FStage<C::NestedCurve, C::Profile>>(),
        PointsWalk => type_name::<points::WalkStage<C::NestedCurve, C::Profile>>(),
        other => panic!("{other:?} is not a native stage a pageable circuit reserves"),
    }
}

/// The type of the nested stage `rx` is the polynomial of, as its mask is
/// registered.
fn nested_stage<C: ProfiledCycle, R: Rank>(rx: nested::RxIndex) -> &'static str {
    use nested::{
        RxIndex::*,
        stages::{
            ab, bridge_hash, challenges, eval, f, inner_error, outer_error, preamble, query,
            s_prime,
        },
    };
    type H<C> = <C as Cycle>::HostCurve;
    type P<C> = <C as ProfiledCycle>::Profile;
    match rx {
        EndoscalarStage => type_name::<endoscalar::EndoscalarStage>(),
        BridgeHash => type_name::<bridge_hash::Stage<H<C>>>(),
        PointsStage => type_name::<nested::PointsStage<H<C>, P<C>>>(),
        BridgePreamble => type_name::<preamble::Stage<H<C>, R, P<C>>>(),
        BridgeSPrime => type_name::<s_prime::Stage<H<C>, R, P<C>>>(),
        BridgeInnerError => type_name::<inner_error::Stage<H<C>, R, P<C>>>(),
        BridgeOuterError => type_name::<outer_error::Stage<H<C>, R, P<C>>>(),
        BridgeAB => type_name::<ab::Stage<H<C>, R, P<C>>>(),
        BridgeQuery => type_name::<query::Stage<H<C>, R, P<C>>>(),
        BridgeF => type_name::<f::Stage<H<C>, R, P<C>>>(),
        BridgeEval => type_name::<eval::Stage<H<C>, R, P<C>>>(),
        ChallengeStage => type_name::<challenges::Stage<H<C>, R, P<C>>>(),
        other => panic!("{other:?} is not a nested stage a pageable circuit reserves"),
    }
}

/// The claims of `which`, by the types of the stages they sum.
fn typed<Rx: Copy>(
    claims: &ByCircuit<Rx>,
    which: paging::Circuit,
    stage: impl Fn(Rx) -> &'static str,
) -> Vec<Vec<&'static str>> {
    let (_, claims) = claims
        .iter()
        .find(|(of, _)| *of == which)
        .unwrap_or_else(|| panic!("{which:?} has a claim"));
    claims
        .iter()
        .map(|claim| claim.iter().map(|&rx| stage(rx)).collect())
        .collect()
}

fn check_reservations<C: ProfiledCycle, const HEADER_SIZE: usize>(params: &C::Params) {
    use native::circuits;
    use paging::Circuit;
    type R = WalletRank;
    type Revdot<C> = native::RevdotParameters<<C as ProfiledCycle>::Profile>;

    let log2_circuits = native::total_circuit_counts::<C::Profile>(3).1;
    let claims = native_claims::<C::Profile>();
    let stage = native_stage::<C, R, HEADER_SIZE>;
    let of = |which| typed(&claims, which, stage);

    check_reserved(
        Circuit::Hashes1,
        circuits::hashes_1::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(params, log2_circuits),
        &of(Circuit::Hashes1),
    );
    check_reserved(
        Circuit::Hashes2,
        circuits::hashes_2::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(params),
        &of(Circuit::Hashes2),
    );
    check_reserved(
        Circuit::Collapse,
        circuits::collapse::Circuit::<C, R, HEADER_SIZE, Revdot<C>>::new(),
        &of(Circuit::Collapse),
    );
    check_reserved(
        Circuit::ComputeV,
        circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new(),
        &of(Circuit::ComputeV),
    );
    for k in 0..native::NUM_BINDERS as u32 {
        // The macro names the binding circuit `Circuit`.
        let which = Circuit::BindChallenges(k);
        let claims = of(which);
        crate::with_binder!(k, C, R, HEADER_SIZE, params, |circuit| {
            check_reserved(which, circuit, &claims)
        });
    }
    check_reserved(
        Circuit::BindBeta,
        circuits::bind_beta::Circuit::<C, R, HEADER_SIZE>::new(params),
        &of(Circuit::BindBeta),
    );
    check_reserved(
        Circuit::BindEndoscalar,
        circuits::bind_endoscalar::Circuit::<C, R>::new(),
        &of(Circuit::BindEndoscalar),
    );
    let mut steps = 0;
    for id in native::InternalCircuitIndex::all::<C::Profile>() {
        if let native::InternalCircuitIndex::EndoscalingStep(step) = id {
            check_reserved(
                Circuit::EndoscalingStep(step),
                circuits::endoscaling_step::Circuit::<C, R>::new(step as usize),
                &of(Circuit::EndoscalingStep(step)),
            );
            steps += 1;
        }
    }
    assert!(steps > 0, "the native walk has steps");

    let claims = nested_claims::<C::Profile>();
    let stage = nested_stage::<C, R>;
    let of = |which| typed(&claims, which, stage);
    check_reserved(
        Circuit::NestedCollapse,
        MultiStage::new(nested::circuits::collapse::Circuit::<
            C::HostCurve,
            R,
            C::Profile,
        >::new()),
        &of(Circuit::NestedCollapse),
    );
    check_reserved(
        Circuit::NestedComputeV,
        MultiStage::new(nested::circuits::compute_v::Circuit::<
            C::HostCurve,
            R,
            C::Profile,
        >::new()),
        &of(Circuit::NestedComputeV),
    );
    let mut steps = 0;
    for id in nested::InternalCircuitIndex::all::<C::Profile>() {
        if let nested::InternalCircuitIndex::EndoscalingStep(step) = id {
            check_reserved(
                Circuit::NestedEndoscalingStep(step),
                MultiStage::new(nested::EndoscalingStep::<C::HostCurve, R, C::Profile>::new(
                    step as usize,
                )),
                &of(Circuit::NestedEndoscalingStep(step)),
            );
            steps += 1;
        }
    }
    assert!(steps > 0, "the nested walk has steps");
}

/// Every claim of every pageable circuit, paged or whole, sums stages its
/// circuit reserves, each once and none sharing gates, and leaves out only
/// stages whose wires the circuit reads none of.
#[test]
fn claims_sum_the_stages_their_circuits_reserve() {
    let params = crate::pasta::baked();
    check_reservations::<Pasta, 4>(params);
    check_reservations::<Profiled<Pasta, Wider>, 4>(params);
    check_reservations::<Profiled<Pasta, Twin>, 4>(params);
    check_reservations::<Profiled<Pasta, Aggregator<4>>, 4>(params);
}

/// Checks that each page of each of `placements` has its own polynomial `own`
/// under exactly one claim of its circuit's pages' mask and under no other
/// circuit's, and that each carry stage's polynomial is under its stage's
/// mask claim alone.
fn check_masks<Id: Copy + PartialEq + core::fmt::Debug, Rx: Copy + PartialEq + core::fmt::Debug>(
    side: &str,
    recorded: &Recorded<Id, Rx>,
    placements: &[paging::Placement],
    (mask, carry): (impl Fn(u32) -> Id, impl Fn(u32) -> Rx),
    own: impl Fn(&paging::Placement, usize) -> Rx,
) {
    assert!(!placements.is_empty(), "the {side} side pages a circuit");
    let under = |placement: &paging::Placement, polynomial: Rx| {
        recorded
            .masks()
            .filter(|(id, rxs)| *id == mask(placement.mask) && rxs.contains(&polynomial))
            .count()
    };
    for placement in placements {
        let which = placement.circuit;
        for page in 0..=placement.last() {
            let polynomial = own(placement, page);
            assert_eq!(
                under(placement, polynomial),
                1,
                "{side} {which:?}: page {page}'s polynomial {polynomial:?} under its pages' mask"
            );
            for other in placements.iter().filter(|other| other.circuit != which) {
                assert_eq!(
                    under(other, polynomial),
                    0,
                    "{side} {which:?}: page {page}'s polynomial under {:?}'s pages' mask",
                    other.circuit
                );
            }
        }
        let stage = carry(placement.carry);
        let holding: Vec<(Id, &[Rx])> = recorded
            .masks()
            .filter(|(_, rxs)| rxs.contains(&stage))
            .collect();
        assert_eq!(
            holding,
            [(mask(placement.carry), &[stage][..])],
            "{side} {which:?}: its carry stage is under its stage's mask alone"
        );
    }
}

/// Every page's own polynomial, the last page's included, is under the one
/// mask claim over its own gates, which keeps it off the stages it loads
/// and off its carry stage; every carry stage is under its stage's mask.
#[test]
fn every_page_is_under_the_mask_over_its_own_gates() {
    fn check<P: Profile>() {
        let placements = paging::placements::<P>(false);
        check_masks(
            "native",
            &native_recorded::<P>(),
            &placements,
            (
                native::InternalCircuitIndex::ExtensionMask,
                native::RxIndex::ExtensionStage,
            ),
            |placement, page| match page < placement.last() {
                true => native::RxIndex::ExtensionCircuit(placement.circuits.start + page as u32),
                false => native_own(placement.circuit),
            },
        );
        let placements = paging::placements::<P>(true);
        check_masks(
            "nested",
            &nested_recorded::<P>(),
            &placements,
            (
                nested::InternalCircuitIndex::ExtensionMask,
                nested::RxIndex::ExtensionStage,
            ),
            |placement, page| match page < placement.last() {
                true => nested::RxIndex::ExtensionCircuit(placement.circuits.start + page as u32),
                false => nested_own(placement.circuit),
            },
        );
    }
    check::<Aggregator<1>>();
    check::<Aggregator<4>>();
    check::<Aggregator<195>>();
}

/// The target a claim is held to, by what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    UnifiedBridge,
    Unified,
    ComputeVBridge,
    ComputeV,
    OnlineHelper,
    BindEndoscalar,
    One,
    Statement,
    Binding,
    Zero,
}

/// One proof's targets, each named by what it is, with neither a raw nor
/// an application claim's, as [`Labels`] makes neither.
struct Targets;

impl native::claims::KySource for Targets {
    type Ky = Target;

    fn raw_c(&self) -> impl Iterator<Item = Target> {
        core::iter::empty()
    }

    fn application_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::empty()
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::once(Target::UnifiedBridge)
    }

    fn compute_v_bridge_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::once(Target::ComputeVBridge)
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::once(Target::OnlineHelper)
    }

    fn unified_ky(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::Unified)
    }

    fn bind_endoscalar_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::once(Target::BindEndoscalar)
    }

    fn ones(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::One)
    }

    fn statement_ky(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::Statement)
    }

    fn binding_ky(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::Binding)
    }

    fn zero(&self) -> Target {
        Target::Zero
    }
}

impl nested::claims::KySource for Targets {
    type Ky = Target;

    fn raw_c(&self) -> impl Iterator<Item = Target> {
        core::iter::empty()
    }

    fn ones(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::One)
    }

    fn unified_ky(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::Unified)
    }

    fn compute_v_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::once(Target::ComputeV)
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = Target> {
        core::iter::once(Target::OnlineHelper)
    }

    fn binding_ky(&self) -> impl Iterator<Item = Target> + Clone {
        core::iter::once(Target::Binding)
    }

    fn zero(&self) -> Target {
        Target::Zero
    }
}

/// Checks that `recorded`'s circuit claims come before its mask claims and
/// are as many as `targets`, and that each claim `expected` names a target
/// for is held to it.
fn check_aligned<Id: Copy + core::fmt::Debug, Rx>(
    side: &str,
    recorded: &Recorded<Id, Rx>,
    targets: &[Target],
    expected: impl Fn(Id) -> Option<Target>,
) {
    let first_mask = recorded
        .0
        .iter()
        .position(|(claimed, _)| matches!(claimed, Claimed::Mask(_)))
        .unwrap_or(recorded.0.len());
    assert!(
        recorded.0[first_mask..]
            .iter()
            .all(|(claimed, _)| matches!(claimed, Claimed::Mask(_))),
        "{side}: a circuit claim after a mask claim, which the targets' zeros would hold"
    );
    assert_eq!(
        first_mask,
        targets.len(),
        "{side}: a target for each circuit claim"
    );
    for ((claimed, _), &target) in recorded.0.iter().zip(targets) {
        if let Claimed::Circuit(id) = claimed
            && let Some(expected) = expected(*id)
        {
            assert_eq!(target, expected, "{side}: the target of {id:?}");
        }
    }
}

/// Every circuit claim, each page's included, is held to its own target:
/// the claims and the targets line up, so that no claim is held to the
/// zeros the targets end in, or to the target of another, and each page
/// before a circuit's last is held to one.
#[test]
fn every_circuit_claim_is_held_to_its_target() {
    fn check<P: Profile>() {
        use native::InternalCircuitIndex as Native;
        use nested::InternalCircuitIndex as Nested;

        let native_placements = paging::placements::<P>(false);
        let targets: Vec<Target> = native::claims::ky_prefix::<P, _>(&Targets).collect();
        check_aligned("native", &native_recorded::<P>(), &targets, |id| match id {
            Native::Hashes1Circuit => Some(Target::UnifiedBridge),
            Native::Hashes2Circuit | Native::CollapseCircuit => Some(Target::Unified),
            Native::ComputeVCircuit => Some(Target::ComputeVBridge),
            Native::BindChallengesCircuit(_) | Native::BindBetaCircuit => Some(Target::Unified),
            Native::BindEndoscalarCircuit => Some(Target::BindEndoscalar),
            Native::EndoscalingStep(_) => Some(Target::One),
            Native::ExtensionCircuit(k) => native_placements
                .iter()
                .any(|placement| placement.page(k).is_some())
                .then_some(Target::One),
            _ => None,
        });

        let nested_placements = paging::placements::<P>(true);
        let targets: Vec<Target> = nested::claims::ky_prefix::<P, _>(&Targets).collect();
        check_aligned("nested", &nested_recorded::<P>(), &targets, |id| match id {
            Nested::EndoscalingStep(_) => Some(Target::One),
            Nested::Collapse => Some(Target::Unified),
            Nested::ComputeV => Some(Target::ComputeV),
            Nested::ExtensionCircuit(k) => nested_placements
                .iter()
                .any(|placement| placement.page(k).is_some())
                .then_some(Target::One),
            _ => None,
        });
    }
    check::<crate::profile::Standard>();
    check::<Wider>();
    check::<Twin>();
    check::<Aggregator<1>>();
    check::<Aggregator<4>>();
    check::<Aggregator<195>>();
}
