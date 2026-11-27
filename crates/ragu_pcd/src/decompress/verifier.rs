//! The decompressed verifier, each side as straight-line code.
//!
//! A side's verifier is one function over a driver ([`native_side`] and
//! [`nested_side`]): it reads the compressed proof off the side's stages,
//! does the native verifier's arithmetic in its field, the scalar checks
//! of the other curve's reduction and the point checks of its own curve's,
//! and returns the points the side exposes. The side's whole circuit
//! ([`WholeCircuit`](super::whole::WholeCircuit)) runs it over the stages'
//! wires, and the pager cuts that circuit into pages; the prover runs the
//! same function natively to fill the two stages a side writes, its lifts
//! and its digits ([`Cells`]).
//!
//! The verifier's parts follow one another as the native verifier's do:
//! the two transcripts; the challenges' lifts; the targets, the reduction,
//! the batch and the IPA's scalars; the claims' points; the fold, batch
//! and IPA as Horner chains; the full-width scalings; the stages the side
//! recomputes of the other's; the digits of the scalars the other side
//! scales by; and the curve membership of every point a stage holds, which
//! the stages load unenforced. The two sides share everything from the
//! reduction on ([`body`]); they differ in how they obtain their
//! challenges and in the stages each recomputes of the other's: the
//! circuit-field side absorbs each run of the scalar field's values the
//! transcript covers as the run stage's commitment, a point the prover
//! supplies, endoscales the lifts stage's generators by the challenges it
//! squeezed, and, as it scales by the scalar-field side's digits, sums
//! their generators by sign into the digits stage's commitment; the
//! scalar-field side does the last for the circuit-field side's digits.
//! The absorbed run commitments and each side's recomputations of the
//! lifts and digits stages are what the side exposes.
//!
//! What a side's verifier is laid out by beside its stage layout, the
//! claims' structure, the wire bindings' degrees and the generators of the
//! other side's stages, is a pure function of the proof system's constants
//! ([`Tables`]). Two ranks are in play: `K`, the compressed proof's, sizes
//! what the verifier loads and checks, and `R`, the rank its circuit is
//! proven at, places the stages the two sides recompute of each other.
//!
//! A cut of the circuit carries what the gates after it read of the gates
//! before it, so the verifier keeps what it reads near where it reads it.
//! A challenge's bits are read where they scale: the circuit-field side
//! scales what a challenge scales of the stages it recomputes right where
//! it squeezes the challenge, a chain reads its challenge's bits again
//! every few scalings ([`SCALINGS`]), each read held to the challenge, and
//! a round challenge of the IPA scales both points it scales off one read.
//! A full-width scalar's digits are allocated one at a time, each where
//! the chain takes it ([`Run::scale`]).

use alloc::{sync::Arc, vec, vec::Vec};
use core::{iter::once, marker::PhantomData};

use ragu_circuits::{
    polynomials::Rank,
    registry::CircuitIndex,
    staging::{stage_wire_indices, wire_degree, wires_of},
};
use ragu_core::{
    Coeff, Cycle, Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, Endoscalar, EndoscalarChallenge, GadgetExt, NonzeroBank, Point,
    consistent::Consistent, poseidon::Sponge,
};
use udon::{
    curve::{EndomorphismAffine as Affine, Projective},
    field::Field,
};

use super::{
    circuits::{Prepared, View},
    gadgets::{
        batch,
        derive::{self, Digits},
        ipa, revdot,
    },
    online::{self, input},
    side::{Native, NativeTargets, Nested, NestedTargets, Side},
    stages::{
        self, AB_TERMS, Layout, MESSAGE_SCALARS, MessageScalars, digits_degrees, lifts_degrees,
        native_scalars, nested_scalars, num_runs,
    },
};
use crate::{
    RAGU_TAG,
    compress::{
        instance::{
            NativeEval, NativePreamble, NativeQuery, NestedEval, NestedPreamble, NestedQuery,
            OPENED, degrees,
        },
        revdot::{
            OpeningClaim,
            claims::Kind,
            fold::{Derived, Layout as FoldLayout, Weights},
            native_components, native_position, nested_components, nested_position,
        },
    },
    internal::{
        native::{
            self,
            claims::ky_values as native_ky_values,
            stages::{eval::generator_index, preamble::ProofInputs},
        },
        nested::{
            self, claims::ky_values as nested_ky_values, stages::challenges as challenge_stage,
            unified as nested_unified,
        },
        revdot::Source,
    },
    ipa::{IPA_TAG, IpaCycle},
    profile::{ProfiledCycle, Standard},
};

/// The scalings a challenge's bits are read for: a chain reads them again
/// after that many, each read held to the challenge, so that a cut of the
/// circuit through a chain carries the bits of few scalings.
const SCALINGS: usize = 2;

/// The distinct challenges whose bits one stretch of a sum of scaled terms
/// reads.
const READS: usize = 1;

/// The digits of a full-width scaling that share one check of its
/// additions ([`NonzeroBank`]): a cut of the circuit through a scaling
/// carries that check's running product and no digit.
const DIGITS: usize = 32;

/// A claim's structure: its kind, the groups of commitment positions its
/// $a$ sums and Horner-folds under $z$, and the position of a raw claim's
/// $b$.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ClaimPlan {
    pub kind: Kind,
    pub groups: Vec<Vec<usize>>,
    pub b: Option<usize>,
}

/// The compression's challenge count per curve: the four sampled, the
/// fold's four, $\rho$, $r$, $\alpha$, $u$, $\beta$, $\xi$, $z$ and the
/// rounds'.
pub(crate) const fn challenges_per_curve<K: Rank>() -> usize {
    4 + 4 + 2 + 3 + 2 + K::RANK as usize
}

/// Positions of a curve's compression challenges, in the order the
/// transcript squeezes them: within the challenges a side squeezes of one
/// curve, and within their lifts in a lifts stage.
pub(crate) mod squeezed {
    pub const W: usize = 0;
    pub const Y: usize = 1;
    pub const Z: usize = 2;
    pub const SIGMA: usize = 3;
    pub const MU: usize = 4;
    pub const NU: usize = 5;
    pub const MU_PRIME: usize = 6;
    pub const NU_PRIME: usize = 7;
    pub const RHO: usize = 8;
    pub const R: usize = 9;
    pub const ALPHA: usize = 10;
    pub const U: usize = 11;
    pub const BETA: usize = 12;
    pub const XI: usize = 13;
    pub const IPA_Z: usize = 14;
    pub const ROUNDS: usize = 15;
}

/// Positions of the fuse's challenges among those the circuit-field side
/// squeezes, in [`nested::Challenges::in_order`] order.
pub(crate) mod fuse {
    pub const W: usize = 0;
    pub const Y: usize = 1;
    pub const X: usize = 5;
    pub const U: usize = 7;
    pub const PRE_BETA: usize = 8;
    /// The challenges the scalar-field side lifts, in the order its lifts
    /// stage holds them, after the nested curve's compression challenges.
    pub const LIFTED: [usize; 4] = [X, Y, U, W];
}

/// Records the claims' structure as the decider enumerates them.
struct Planner {
    claims: Vec<ClaimPlan>,
}

impl Planner {
    fn circuit(&mut self, circuit: CircuitIndex, rxs: impl Iterator<Item = usize>) {
        self.claims.push(ClaimPlan {
            kind: Kind::Circuit(circuit),
            groups: vec![rxs.collect()],
            b: None,
        });
    }

    fn mask(&mut self, circuit: CircuitIndex, rxs: impl Iterator<Item = usize>) {
        self.claims.push(ClaimPlan {
            kind: Kind::Mask(circuit),
            groups: rxs.map(|rx| vec![rx]).collect(),
            b: None,
        });
    }

    fn raw(&mut self, a: usize, b: usize) {
        self.claims.push(ClaimPlan {
            kind: Kind::Raw,
            groups: vec![vec![a]],
            b: Some(b),
        });
    }

    fn masked(&mut self, positions: impl IntoIterator<Item = usize>) {
        for (m, position) in positions.into_iter().enumerate() {
            self.claims.push(ClaimPlan {
                kind: Kind::Masked(m),
                groups: vec![vec![position]],
                b: None,
            });
        }
    }
}

impl native::claims::Processor<Standard, usize, CircuitIndex> for Planner {
    fn raw_claim(&mut self, a: usize, b: usize) {
        self.raw(a, b);
    }

    fn circuit_claim(&mut self, circuit_id: CircuitIndex, rxs: impl Iterator<Item = usize>) {
        self.circuit(circuit_id, rxs);
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = usize>,
    ) {
        self.circuit(id.circuit_index::<Standard>(), rxs);
    }

    fn mask_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = usize>,
    ) -> Result<()> {
        self.mask(id.circuit_index::<Standard>(), rxs);
        Ok(())
    }
}

impl nested::claims::Processor<Standard, usize> for Planner {
    fn raw_claim(&mut self, a: usize, b: usize) {
        self.raw(a, b);
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = usize>,
    ) {
        self.circuit(id.circuit_index::<Standard>(), rxs);
    }

    fn mask_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = usize>,
    ) -> Result<()> {
        self.mask(id.circuit_index::<Standard>(), rxs);
        Ok(())
    }
}

/// A source over the native components by position. A proof folds its own
/// application claim, so its verifier's claims name internal circuits
/// alone, and the claims are the same for every application circuit.
struct NativePositions;

impl Source for NativePositions {
    type RxComponent = native::RxComponent;
    type Rx = usize;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = usize> {
        once(native_position::<Standard>(component))
    }

    fn applications(&self) -> impl Iterator<Item = (CircuitIndex, [usize; 2])> {
        core::iter::empty()
    }
}

struct NestedPositions;

impl Source for NestedPositions {
    type RxComponent = nested::RxComponent;
    type Rx = usize;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = usize> {
        once(nested_position::<Standard>(component))
    }

    fn applications(&self) -> impl Iterator<Item = ((), [usize; 2])> {
        core::iter::empty()
    }
}

/// The native claims' plans, then the wire bindings', in the compressed
/// verifier's order, over positions within the native commitments.
pub(crate) fn native_claims() -> Result<Vec<ClaimPlan>> {
    let mut planner = Planner { claims: Vec::new() };
    native::claims::build::<Standard, _, _>(&NativePositions, &mut planner)?;
    planner.masked(
        [
            native::RxIndex::Preamble,
            native::RxIndex::Query,
            native::RxIndex::Eval,
            native::RxIndex::PointsAb,
            native::RxIndex::PointsF,
        ]
        .map(|index| native_position::<Standard>(native::RxComponent::Rx(index))),
    );
    Ok(planner.claims)
}

/// The nested claims' plans, as [`native_claims`] lists them, over
/// positions within the nested commitments.
pub(crate) fn nested_claims() -> Result<Vec<ClaimPlan>> {
    let mut planner = Planner { claims: Vec::new() };
    nested::claims::build::<Standard, _, _>(&NestedPositions, &mut planner)?;
    planner.masked(
        [
            nested::RxIndex::BridgePreamble,
            nested::RxIndex::BridgeQuery,
            nested::RxIndex::BridgeEval,
        ]
        .map(|index| nested_position::<Standard>(nested::RxComponent::Rx(index))),
    );
    Ok(planner.claims)
}

/// A coefficient of the `ab` bridge stage: which of its values it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbValue {
    /// A coordinate of the native $A$ commitment, $x$ then $y$.
    A(usize),
    /// A coordinate of the native $B$ commitment.
    B(usize),
    /// A coordinate of the native points stage's commitment.
    PointsAb(usize),
    /// The `ab` bridge stage's alpha, `bridge_alpha` squared.
    Alpha,
}

/// The `ab` bridge stage's layout: the generator index each of its
/// values lands on, read off the stage polynomial over placeholder
/// values.
pub(crate) fn ab_layout<C: ProfiledCycle<Profile = Standard>, K: Rank>()
-> Result<Vec<(usize, AbValue)>> {
    let wires = stage_wire_indices::<
        C::ScalarField,
        K,
        nested::stages::ab::Stage<C::HostCurve, K, Standard>,
    >(|out| {
        let mut wires = wires_of(&out.a)?;
        wires.extend(wires_of(&out.b)?);
        wires.extend(wires_of(&out.native_points_ab)?);
        Ok(wires)
    })?;
    let values = [
        AbValue::A(0),
        AbValue::A(1),
        AbValue::B(0),
        AbValue::B(1),
        AbValue::PointsAb(0),
        AbValue::PointsAb(1),
    ];
    let mut terms: Vec<(usize, AbValue)> = wires
        .into_iter()
        .map(wire_degree::<K>)
        .zip(values)
        .collect();
    // The alpha sits at the SYSTEM gate, before the stage's own gates.
    terms.push((alpha_degree::<K>(), AbValue::Alpha));
    Ok(terms)
}

/// The coefficient degree of a stage polynomial's alpha:
/// [`StageExt::rx`](ragu_circuits::staging::StageExt::rx) puts it at the
/// SYSTEM gate alone, gate zero, whose $a$ wire `wire_degree` numbers
/// $2n - 1$.
fn alpha_degree<K: Rank>() -> usize {
    2 * K::n() - 1
}

/// The coefficient degrees of the native wire bindings' stage wires, in
/// the order [`Instance::native_bindings`] lists the bindings and their
/// wires: the preamble's children, the query stage's registry values, the
/// eval stage's evaluations, and the points stages' coordinates.
///
/// [`Instance::native_bindings`]: crate::compress::instance::Instance::native_bindings
pub(crate) fn native_binding_degrees<C: ProfiledCycle, R: Rank, const HEADER_SIZE: usize>()
-> Result<[Vec<usize>; 5]> {
    Ok([
        degrees::<_, R, NativePreamble<C, R, HEADER_SIZE>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.unified.x)?);
                wires.extend(wires_of(&child.unified.y)?);
            }
            Ok(wires)
        })?,
        degrees::<_, R, NativeQuery<C, R, HEADER_SIZE>>(|out| {
            let mut wires = wires_of(&out.fixed_registry)?;
            wires.extend(wires_of(&out.registry_wxy)?);
            wires.extend(wires_of(&out.registry_xy_at_circuit_id)?);
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.child_registry_xy_at_current_w)?);
                wires.extend(wires_of(&child.current_registry_wy_at_child_x)?);
            }
            Ok(wires)
        })?,
        degrees::<_, R, NativeEval<C, R, HEADER_SIZE>>(|out| {
            let e = &out.evaluations;
            let mut wires = Vec::new();
            for element in [
                &e.registry_wx0,
                &e.registry_wx1,
                &e.registry_wy,
                &e.a_poly,
                &e.b_poly,
                &e.registry_xy,
            ] {
                wires.extend(wires_of(element)?);
            }
            Ok(wires)
        })?,
        degrees::<_, R, native::stages::points::AbStage<C::NestedCurve, C::Profile>>(|stage| {
            let mut wires = wires_of(&stage.a)?;
            wires.extend(wires_of(&stage.b)?);
            Ok(wires)
        })?,
        degrees::<_, R, native::stages::points::FStage<C::NestedCurve, C::Profile>>(|stage| {
            wires_of(&stage.registry_xy)
        })?,
    ])
}

/// The coefficient degrees of the nested wire bindings' stage wires, in
/// the order [`Instance::nested_bindings`] lists them: the bridge
/// preamble's children, the bridge query's registry values and the bridge
/// eval's evaluations.
///
/// [`Instance::nested_bindings`]: crate::compress::instance::Instance::nested_bindings
pub(crate) fn nested_binding_degrees<C: ProfiledCycle, R: Rank>() -> Result<[Vec<usize>; 3]> {
    Ok([
        degrees::<_, R, NestedPreamble<C, R>>(|out| {
            let mut wires = Vec::new();
            for child in [&out.left, &out.right] {
                wires.extend(wires_of(&child.nested.x)?);
                wires.extend(wires_of(&child.nested.y)?);
            }
            Ok(wires)
        })?,
        degrees::<_, R, NestedQuery<C, R>>(|out| {
            let q = &out.nested;
            let mut wires = wires_of(&q.fixed_registry)?;
            wires.extend(wires_of(&q.registry_wxy)?);
            for child in [&q.left, &q.right] {
                wires.extend(wires_of(&child.child_registry_xy_at_current_w)?);
                wires.extend(wires_of(&child.current_registry_wy_at_child_x)?);
            }
            Ok(wires)
        })?,
        degrees::<_, R, NestedEval<C, R>>(|out| {
            let e = &out.nested;
            let mut wires = Vec::new();
            for element in [
                &e.registry_wx0,
                &e.registry_wx1,
                &e.registry_wy,
                &e.a_poly,
                &e.b_poly,
                &e.registry_xy,
            ] {
                wires.extend(wires_of(element)?);
            }
            Ok(wires)
        })?,
    ])
}

/// What a side's verifier is laid out by, beside the driver it runs under:
/// a pure function of the proof system's constants and of the two ranks.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Tables {
    /// The side's stage layout.
    pub layout: Layout,
    /// The claims of the reduction the side checks in its field.
    pub claims: Vec<ClaimPlan>,
    /// The claims of the reduction whose points the side checks.
    pub point_claims: Vec<ClaimPlan>,
    /// The wire bindings' degrees, by binding, in the verifier's order.
    pub bindings: Vec<Vec<usize>>,
    /// The generator each digit of the other side's digits stage lands on,
    /// value by value: a scalar's width of them per value in the side's
    /// foreign scalars' order, then one per flag.
    pub foreign: Vec<usize>,
    /// The scalar field's values whose digits the circuit-field side
    /// scales generators by for the `ab` bridge, with the generator each
    /// lands on, in that side's foreign scalars' order after $v$, $c$ and
    /// $c b z$.
    pub ab_terms: Vec<(usize, AbValue)>,
    /// Circuit-field side: the generator each lift of the scalar-field
    /// side's lifts stage lands on, by lift. Empty on the scalar-field
    /// side, whose lifts the other side recomputes.
    pub lifts: Vec<usize>,
}

/// The circuit-field side's tables for a proof at rank `K`, in a circuit at
/// rank `R`.
pub(crate) fn native_tables<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<Tables> {
    Ok(Tables {
        layout: Layout::native::<C::CircuitField, K, HEADER_SIZE>(),
        claims: native_claims()?,
        point_claims: nested_claims()?,
        bindings: native_binding_degrees::<C, K, HEADER_SIZE>()?.to_vec(),
        foreign: digits_degrees::<C, Nested, K, R, HEADER_SIZE>(),
        ab_terms: ab_layout::<C, K>()?,
        lifts: lifts_degrees::<C, Nested, K, R, HEADER_SIZE>(),
    })
}

/// The scalar-field side's tables, as [`native_tables`].
pub(crate) fn nested_tables<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<Tables> {
    Ok(Tables {
        layout: Layout::nested::<C::ScalarField, Standard, K>(),
        claims: nested_claims()?,
        point_claims: native_claims()?,
        bindings: nested_binding_degrees::<C, K>()?.to_vec(),
        foreign: digits_degrees::<C, Native, K, R, HEADER_SIZE>(),
        ab_terms: ab_layout::<C, K>()?,
        lifts: Vec::new(),
    })
}

/// The key of side `S`'s tables for proofs at rank `K` in a circuit at
/// rank `R`.
struct Kept<C, S, K, R, const HEADER_SIZE: usize>(PhantomData<fn() -> (C, S, K, R)>);

/// Side `S`'s tables for proofs at rank `K` in a circuit at rank `R`, built
/// once ([`memo`]): what the side's whole circuit and the prover's run of
/// the side are laid out by.
///
/// # Errors
///
/// As [`Side::tables`].
pub(crate) fn tables<C, S, K, R, const HEADER_SIZE: usize>() -> Result<Arc<Tables>>
where
    C: Cycle,
    S: Side<C>,
    K: Rank,
    R: Rank,
{
    memo::<Kept<C, S, K, R, HEADER_SIZE>, _>(|| S::tables::<K, R, HEADER_SIZE>().map(Arc::new))
}

/// A stage the side writes, its lifts or its digits: the stage's wires
/// where the side's circuit loads them, each held to what the side writes
/// there; or what the side wrote, where the prover runs it to fill the
/// stage.
pub(crate) enum Cells<'a, 'dr, D: Driver<'dr>> {
    Loaded(&'a [Element<'dr, D>]),
    Filled(Vec<Option<Element<'dr, D>>>),
}

impl<'dr, D: Driver<'dr>> Cells<'_, 'dr, D> {
    /// A stage of `len` values for the side to fill.
    pub(crate) fn blank(len: usize) -> Self {
        Cells::Filled(vec![None; len])
    }

    /// Writes `value` at `slot`: holds the stage's wire to it, or keeps it.
    fn write(&mut self, dr: &mut D, slot: usize, value: Element<'dr, D>) -> Result<()> {
        match self {
            Cells::Loaded(wires) => value.enforce_equal(dr, &wires[slot]),
            Cells::Filled(values) => {
                values[slot] = Some(value);
                Ok(())
            }
        }
    }

    /// The stage's value at `slot`: its wire, or what the side wrote.
    fn read(&self, slot: usize) -> Result<Element<'dr, D>> {
        match self {
            Cells::Loaded(wires) => Ok(wires[slot].clone()),
            Cells::Filled(values) => values[slot].clone().ok_or_else(|| {
                Error::InvalidWitness("a side reads a stage's value before it writes it".into())
            }),
        }
    }

    /// What the side wrote, slot by slot, where it filled the stage.
    pub(crate) fn filled(self) -> Option<Vec<Option<Element<'dr, D>>>> {
        match self {
            Cells::Loaded(_) => None,
            Cells::Filled(values) => Some(values),
        }
    }
}

/// A challenge that scales points, by how the side obtains its
/// endoscalar.
pub(crate) struct Challenge<'dr, D: Driver<'dr>> {
    /// What tells the challenge from the others of its curve the side
    /// scales points by, its index in [`squeezed`] order; where it was
    /// squeezed on the other side, its index into the side's challenge
    /// bits, which is its lifts stage slot too.
    key: usize,
    /// The element the side squeezed, where it squeezed the challenge: the
    /// side reads its endoscalar off it, constraining it into range.
    raw: Option<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> Clone for Challenge<'dr, D> {
    fn clone(&self) -> Self {
        Challenge {
            key: self.key,
            raw: self.raw.clone(),
        }
    }
}

impl<'dr, D: Driver<'dr>> Challenge<'dr, D> {
    /// A challenge this side squeezed as `raw`, told apart by `key`.
    fn squeezed(key: usize, raw: &Element<'dr, D>) -> Self {
        Challenge {
            key,
            raw: Some(raw.clone()),
        }
    }

    /// The challenge at `id` of the side's challenge bits, squeezed on the
    /// other side: the side allocates its bits as witnesses and holds
    /// their lift to the lifts stage's slot `id`, which the other side's
    /// recomputation of that stage binds to the challenge it squeezed.
    fn bits(id: usize) -> Self {
        Challenge { key: id, raw: None }
    }
}

/// A point a chain reads: a wire, or a fixed point, which takes no wire
/// until the chain reads it.
enum Src<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> {
    Wire(Point<'dr, D, P>),
    Fixed(P),
    /// Minus a fixed point.
    Negated(P),
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Clone for Src<'dr, D, P> {
    fn clone(&self) -> Self {
        match self {
            Src::Wire(point) => Src::Wire(point.clone()),
            Src::Fixed(point) => Src::Fixed(*point),
            Src::Negated(point) => Src::Negated(*point),
        }
    }
}

impl<'dr, D: Driver<'dr>, P: Affine<Base = D::F>> Src<'dr, D, P> {
    fn point(&self, dr: &mut D) -> Result<Point<'dr, D, P>> {
        match self {
            Src::Wire(point) => Ok(point.clone()),
            Src::Fixed(point) => Point::constant(dr, *point),
            Src::Negated(point) => Ok(Point::constant(dr, *point)?.negate(dr)),
        }
    }
}

/// A point's coordinates, $x$ then $y$.
fn coordinates<'dr, D: Driver<'dr>, P: Affine<Base = D::F>>(
    dr: &mut D,
    point: &Point<'dr, D, P>,
) -> Result<[Element<'dr, D>; 2]> {
    let mut coordinates = Vec::with_capacity(2);
    GadgetExt::write(point, dr, &mut coordinates)?;
    coordinates
        .try_into()
        .map_err(|_| Error::InvalidWitness("a point has two coordinates".into()))
}

/// The signed digit $2 b - 1$ of a bit $b$.
fn signed<'dr, D: Driver<'dr>>(dr: &mut D, bit: &Element<'dr, D>) -> Element<'dr, D> {
    bit.scale(dr, Coeff::Two)
        .add_coeff(dr, &Element::one(), Coeff::NegativeOne)
}

/// One side's verifier as it runs under a driver: the stages it reads,
/// the two it writes, and what its checks take beside them.
pub(crate) struct Run<'a, 'w, 'dr, D, C, S>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    pub tables: &'a Tables,
    pub instance: View<'a, 'dr, D, S::P>,
    pub messages: View<'a, 'dr, D, S::P>,
    /// The online input stage's values, as the fuse lays them out.
    pub online_input: &'a [Element<'dr, D>],
    /// The online query stage's values, likewise.
    pub online_query: &'a [Element<'dr, D>],
    pub lifts: Cells<'a, 'dr, D>,
    pub digits: Cells<'a, 'dr, D>,
    pub generators: &'a [S::P],
    pub u: S::P,
    pub poseidon: &'dr S::Poseidon,
    /// The side's prepared witness, when the driver has one.
    pub witness: DriverValue<D, &'w Prepared<C, S>>,
    /// Each foreign scalar's part of the other side's digits stage
    /// commitment, by the scalar's index, as the scalings leave them.
    bound: Vec<Option<Point<'dr, D, S::P>>>,
    /// Each foreign flag's part of it, by the flag's index, as the
    /// equalities under the flags leave them.
    flag_bound: Vec<Option<Point<'dr, D, S::P>>>,
    /// Circuit-field side: the compression transcript's digest, its last
    /// squeeze, once the side has replayed the transcript.
    pub digest: Option<Element<'dr, D>>,
}

impl<'a, 'w, 'dr, D, C, S> Run<'a, 'w, 'dr, D, C, S>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    /// A run of side `S` over the stages' values `instance`, `messages`
    /// and `online`, the input stage's then the query stage's, writing
    /// `lifts` and `digits`.
    ///
    /// # Panics
    ///
    /// Panics unless the other side's digits stage holds whole scalars'
    /// digits, then the flags the side takes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tables: &'a Tables,
        instance: View<'a, 'dr, D, S::P>,
        messages: View<'a, 'dr, D, S::P>,
        online: [&'a [Element<'dr, D>]; 2],
        lifts: Cells<'a, 'dr, D>,
        digits: Cells<'a, 'dr, D>,
        (generators, u, poseidon): (&'a [S::P], S::P, &'dr S::Poseidon),
        witness: DriverValue<D, &'w Prepared<C, S>>,
    ) -> Self {
        let width = derive::digit_width::<S::Other>();
        assert_eq!(
            (tables.foreign.len() - S::FLAGS) % width,
            0,
            "the other side holds whole scalars' digits, then its flags'"
        );
        let scalars = (tables.foreign.len() - S::FLAGS) / width;
        Run {
            tables,
            instance,
            messages,
            online_input: online[0],
            online_query: online[1],
            lifts,
            digits,
            generators,
            u,
            poseidon,
            witness,
            bound: vec![None; scalars],
            flag_bound: vec![None; S::FLAGS],
            digest: None,
        }
    }

    /// The instance stage's commitment at `position` of the side's curve's
    /// commitments.
    fn commitment(&self, position: usize) -> Point<'dr, D, S::P> {
        self.instance.points[self.tables.layout.instance.commitments.at(position)].clone()
    }

    /// The instance stage's scalar at `index` of the side's scalars.
    fn scalar(&self, index: usize) -> Element<'dr, D> {
        self.instance.elements[self.tables.layout.instance.scalars.at(index)].clone()
    }

    /// The messages stage's point at `index` of the side's curve's point
    /// messages.
    fn message_point(&self, index: usize) -> Point<'dr, D, S::P> {
        self.messages.points[self.tables.layout.messages.points_of_curve.at(index)].clone()
    }

    /// The scalar messages of the reduction this side checks.
    fn message_scalars(&self) -> MessageScalars<'_, Element<'dr, D>> {
        let span = self.tables.layout.messages.scalars;
        MessageScalars(&self.messages.elements[span.start..span.start + span.len])
    }

    /// The lifts stage's value at `slot`: a challenge's lift.
    fn lift(&self, slot: usize) -> Result<Element<'dr, D>> {
        self.lifts.read(slot)
    }

    /// The other field's value at `id` of the side's foreign scalars.
    fn foreign(&self, id: usize) -> DriverValue<D, S::Other> {
        self.witness.as_ref().map(|w| w.aux.foreign[id])
    }

    /// The endoscalar of the challenge at `id` of the side's challenge
    /// bits, allocated from them and held to nothing: what the side lifts
    /// into the lifts stage's slot every other use holds its bits to.
    fn bits(&self, dr: &mut D, id: usize) -> Result<Endoscalar<'dr, D>> {
        let bits = self.witness.as_ref().map(|w| w.aux.challenge_bits[id]);
        Endoscalar::alloc(dr, bits)
    }

    /// A challenge's endoscalar: read off the squeezed element,
    /// constrained into range, or allocated from its bits and held, by
    /// its lift, to the challenge's lifts stage slot. The bits are
    /// witnesses of the read, so every read of a challenge from bits pays
    /// for the lift that holds them.
    fn endoscalar(&self, dr: &mut D, challenge: &Challenge<'dr, D>) -> Result<Endoscalar<'dr, D>> {
        Ok(match &challenge.raw {
            Some(raw) => {
                Endoscalar::extract(EndoscalarChallenge::from_element(dr, &mut (), raw.clone())?)
            }
            None => {
                let bits = self.witness.as_ref().map(|w| w.aux.read(challenge.key));
                let endoscalar = Endoscalar::alloc(dr, bits)?;
                endoscalar
                    .lift(dr)?
                    .enforce_equal(dr, &self.lift(challenge.key)?)?;
                endoscalar
            }
        })
    }

    /// The sum of `points`.
    fn add(
        &self,
        dr: &mut D,
        points: impl IntoIterator<Item = Point<'dr, D, S::P>>,
    ) -> Result<Point<'dr, D, S::P>> {
        let mut points = points.into_iter();
        let first = points
            .next()
            .ok_or_else(|| Error::InvalidWitness("a sum has a term".into()))?;
        NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = first;
            for term in points {
                acc = acc.add_incomplete(dr, &term, bank)?;
            }
            Ok(acc)
        })
    }

    /// A Horner chain over `points` under `scale_by`, from the last
    /// present point back to the first; `None` entries scale alone. `None`
    /// if no point is present.
    fn horner(
        &self,
        dr: &mut D,
        points: &[Option<Src<'dr, D, S::P>>],
        scale_by: &Challenge<'dr, D>,
    ) -> Result<Option<Point<'dr, D, S::P>>> {
        let Some(first) = points.iter().rposition(Option::is_some) else {
            return Ok(None);
        };
        let mut acc = match &points[first] {
            Some(init) => init.point(dr)?,
            None => unreachable!("the chain starts from a present point"),
        };
        let steps: Vec<&Option<Src<'dr, D, S::P>>> = points[..first].iter().rev().collect();
        for stretch in steps.chunks(SCALINGS) {
            let endoscalar = self.endoscalar(dr, scale_by)?;
            acc = NonzeroBank::scope(dr, |dr, bank| {
                let mut acc = acc;
                for add in stretch {
                    let scaled = endoscalar.group_scale(dr, &acc)?;
                    acc = match add {
                        Some(add) => {
                            let add = add.point(dr)?;
                            scaled.add_incomplete(dr, &add, bank)?
                        }
                        None => scaled,
                    };
                }
                Ok(acc)
            })?;
        }
        Ok(Some(acc))
    }

    /// One stretch of a sum of scaled terms onto `acc`, each challenge's
    /// endoscalar read once.
    fn add_scaled(
        &self,
        dr: &mut D,
        acc: Point<'dr, D, S::P>,
        terms: &[&(Src<'dr, D, S::P>, Option<Challenge<'dr, D>>)],
    ) -> Result<Point<'dr, D, S::P>> {
        let mut endoscalars: Vec<(usize, Endoscalar<'dr, D>)> = Vec::new();
        NonzeroBank::scope(dr, |dr, bank| {
            let mut acc = acc;
            for (point, scale_by) in terms.iter().map(|term| (&term.0, &term.1)) {
                let point = point.point(dr)?;
                let term = match scale_by {
                    Some(challenge) => {
                        let read = endoscalars.iter().find(|(key, _)| *key == challenge.key);
                        let endoscalar = match read {
                            Some((_, endoscalar)) => endoscalar.clone(),
                            None => {
                                let endoscalar = self.endoscalar(dr, challenge)?;
                                endoscalars.push((challenge.key, endoscalar.clone()));
                                endoscalar
                            }
                        };
                        endoscalar.group_scale(dr, &point)?
                    }
                    None => point,
                };
                acc = acc.add_incomplete(dr, &term, bank)?;
            }
            Ok(acc)
        })
    }

    /// The sum of `terms`, each scaled by its challenge or added alone,
    /// from `init`, in stretches of [`SCALINGS`] scalings by [`READS`]
    /// challenges.
    fn sum(
        &self,
        dr: &mut D,
        init: Point<'dr, D, S::P>,
        terms: &[(Src<'dr, D, S::P>, Option<Challenge<'dr, D>>)],
    ) -> Result<Point<'dr, D, S::P>> {
        let mut acc = init;
        let mut stretch: Vec<&(Src<'dr, D, S::P>, Option<Challenge<'dr, D>>)> = Vec::new();
        let mut scalings = 0;
        // The challenges the stretch reads so far.
        let mut reads: Vec<usize> = Vec::new();
        for term in terms {
            let key = term.1.as_ref().map(|challenge| challenge.key);
            let cost = usize::from(key.is_some());
            let read = usize::from(key.is_some_and(|key| !reads.contains(&key)));
            let full = scalings + cost > SCALINGS || reads.len() + read > READS;
            if full && !stretch.is_empty() {
                acc = self.add_scaled(dr, acc, &stretch)?;
                stretch.clear();
                scalings = 0;
                reads.clear();
            }
            stretch.push(term);
            scalings += cost;
            if let Some(key) = key.filter(|key| !reads.contains(key)) {
                reads.push(key);
            }
        }
        if !stretch.is_empty() {
            acc = self.add_scaled(dr, acc, &stretch)?;
        }
        Ok(acc)
    }

    /// Adds the fixed `point` scaled by `endoscalar`, a challenge's the
    /// side has at hand, onto the running sum `sum`, or starts it.
    fn add_term(
        &self,
        dr: &mut D,
        sum: &mut Option<Point<'dr, D, S::P>>,
        endoscalar: &Endoscalar<'dr, D>,
        point: S::P,
    ) -> Result<()> {
        let point = Point::constant(dr, point)?;
        let term = endoscalar.group_scale(dr, &point)?;
        *sum = Some(match sum.take() {
            None => term,
            Some(sum) => NonzeroBank::scope(dr, |dr, bank| sum.add_incomplete(dr, &term, bank))?,
        });
        Ok(())
    }

    /// The claims' points. A circuit claim's point is the sum of its one
    /// group's components. A mask claim's groups hold one component each,
    /// Horner-folded under `z`.
    fn claims(
        &self,
        dr: &mut D,
        claims: &[ClaimPlan],
        z: &Challenge<'dr, D>,
    ) -> Result<Vec<Point<'dr, D, S::P>>> {
        let mut points = Vec::with_capacity(claims.len());
        for claim in claims {
            let mut groups = Vec::with_capacity(claim.groups.len());
            for group in &claim.groups {
                groups.push(self.add(dr, group.iter().map(|&p| self.commitment(p)))?);
            }
            points.push(match groups.len() {
                1 => groups.remove(0),
                _ => {
                    // The fold weights the first group highest, as the
                    // shaper does.
                    let reversed: Vec<_> = groups
                        .into_iter()
                        .rev()
                        .map(|group| Some(Src::Wire(group)))
                        .collect();
                    self.horner(dr, &reversed, z)?
                        .ok_or_else(|| Error::InvalidWitness("a claim has a group".into()))?
                }
            });
        }
        Ok(points)
    }

    /// The fold of one derived commitment: each group's Horner chain
    /// under `inner` over the claims `pick` keeps, then the groups' under
    /// `outer`.
    fn fold(
        &self,
        dr: &mut D,
        claims: &[ClaimPlan],
        points: &[Point<'dr, D, S::P>],
        pick: impl Fn(&ClaimPlan) -> bool,
        inner: &Challenge<'dr, D>,
        outer: &Challenge<'dr, D>,
    ) -> Result<Point<'dr, D, S::P>> {
        let layout = FoldLayout::new(claims.len());
        let mut groups = Vec::with_capacity(layout.groups());
        for g in 0..layout.groups() {
            let members: Vec<Option<Src<'dr, D, S::P>>> = layout
                .members(g)
                .map(|i| pick(&claims[i]).then(|| Src::Wire(points[i].clone())))
                .collect();
            // A group none of whose claims is picked has no chain.
            groups.push(self.horner(dr, &members, inner)?.map(Src::Wire));
        }
        self.horner(dr, &groups, outer)?
            .ok_or_else(|| Error::InvalidWitness("a derived polynomial has a term".into()))
    }

    /// The part of the other side's digits stage commitment over `digits`:
    /// each digit's generator, `generators` names them, added or
    /// subtracted by its bit, onto `init` or from nothing.
    fn bind_sum(
        &self,
        dr: &mut D,
        digits: &Digits<'dr, D>,
        generators: &[usize],
        init: Option<Point<'dr, D, S::P>>,
    ) -> Result<Point<'dr, D, S::P>> {
        assert_eq!(generators.len(), digits.len(), "one generator per digit");
        let mut acc = init;
        NonzeroBank::scope(dr, |dr, bank| {
            for (bit, &generator) in digits.bits().iter().zip(generators) {
                let base = Point::constant(dr, self.generators[generator])?;
                let negate = bit.not(dr);
                let term = base.conditional_negate(dr, &negate)?;
                acc = Some(match acc.take() {
                    None => term,
                    Some(acc) => acc.add_incomplete(dr, &term, bank)?,
                });
            }
            acc.ok_or_else(|| Error::InvalidWitness("a scalar has a digit".into()))
        })
    }

    /// $k P$ for the full-width scalar at `id` of the side's foreign
    /// scalars, a value of the other field whose digits the side allocates
    /// as witnesses and the other side's digits stage binds: the
    /// signed-digit chain over its digits, from the top down, from
    /// `offset`. With `remove_offset = false` the result retains the
    /// signed-digit offset, so that a zero scalar still has an affine
    /// point; what sums it subtracts that offset.
    ///
    /// A scalar is scaled by once: its digits' part of the other side's
    /// digits stage commitment, each digit's generator added or subtracted
    /// by its bit, rides along, for [`digits_sum`](Self::digits_sum) to
    /// take.
    ///
    /// # Panics
    ///
    /// Panics if the scalar was scaled by before.
    fn scale(
        &mut self,
        dr: &mut D,
        point: &Point<'dr, D, S::P>,
        id: usize,
        offset: S::P,
        remove_offset: bool,
    ) -> Result<Point<'dr, D, S::P>> {
        assert!(
            self.bound[id].is_none(),
            "a foreign scalar binds its digits once"
        );
        let n = derive::digit_width::<S::Other>();
        let tables = self.tables;
        let mut acc: Option<Point<'dr, D, S::P>> = None;
        let mut bound: Option<Point<'dr, D, S::P>> = None;
        // Each digit is allocated where the chain takes it, and its
        // generator joins the other side's digits stage commitment right
        // after, so that a cut of the circuit carries no digit: the
        // chain's accumulator and the commitment's alone.
        let mut hi = n;
        while hi > 0 {
            let lo = hi.saturating_sub(DIGITS);
            let (chain, part) = NonzeroBank::scope(dr, |dr, bank| {
                let (mut chain, mut part) = (acc.take(), bound.take());
                for i in (lo..hi).rev() {
                    let digit = Digits::alloc_range(dr, self.foreign(id), i..i + 1)?;
                    chain = Some(derive::scale_chain(
                        dr,
                        point,
                        &digit,
                        chain.take(),
                        offset,
                        bank,
                    )?);
                    let base = Point::constant(dr, self.generators[tables.foreign[id * n + i]])?;
                    let negate = digit.bits()[0].not(dr);
                    let term = base.conditional_negate(dr, &negate)?;
                    part = Some(match part.take() {
                        None => term,
                        Some(part) => part.add_incomplete(dr, &term, bank)?,
                    });
                }
                if lo == 0 && remove_offset {
                    let chained = chain
                        .take()
                        .ok_or_else(|| Error::InvalidWitness("a scalar has a digit".into()))?;
                    chain = Some(derive::scale_shift(dr, chained, offset, n, bank)?);
                }
                Ok((chain, part))
            })?;
            (acc, bound) = (chain, part);
            hi = lo;
        }
        self.bound[id] = bound;
        acc.ok_or_else(|| Error::InvalidWitness("a scaling has a digit".into()))
    }

    /// Holds the points of each pair equal under the other side's flag
    /// `flag`: its bit, by index into the side's foreign flags, which the
    /// side allocates as a witness and the other side's digits stage
    /// binds, its signed digit's part of that stage's commitment riding
    /// along as a scaling's digits' does. A flag is taken once.
    ///
    /// # Panics
    ///
    /// Panics if the flag was taken before.
    fn equal_if(
        &mut self,
        dr: &mut D,
        flag: usize,
        pairs: &[[Point<'dr, D, S::P>; 2]],
    ) -> Result<()> {
        assert!(
            self.flag_bound[flag].is_none(),
            "a foreign flag binds its digit once"
        );
        // Bind the flag once to the digit sent by the other side, and use
        // the same bit for each point comparison.
        let value = self.witness.as_ref().map(|w| w.aux.flags[flag]);
        let bit = Boolean::alloc(dr, &mut (), value)?;
        for [left, right] in pairs {
            let left = coordinates(dr, left)?;
            let right = coordinates(dr, right)?;
            for (left, right) in left.iter().zip(&right) {
                let gap = left.sub(dr, right);
                bit.element().mul(dr, &gap)?.enforce_zero(dr)?;
            }
        }
        let width = derive::digit_width::<S::Other>();
        let generator = self.tables.foreign[self.bound.len() * width + flag];
        let digit = Digits::of_flag(bit);
        self.flag_bound[flag] = Some(self.bind_sum(dr, &digit, &[generator], None)?);
        Ok(())
    }

    /// The other side's digits stage commitment: the sum of every foreign
    /// scalar's part, each scaling having left one, and of every foreign
    /// flag's.
    fn digits_sum(&self, dr: &mut D) -> Result<Point<'dr, D, S::P>> {
        let parts = self
            .bound
            .iter()
            .chain(&self.flag_bound)
            .map(|part| {
                part.clone().ok_or_else(|| {
                    Error::InvalidWitness(
                        "every foreign scalar is scaled by, and every foreign flag taken".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.add(dr, parts)
    }

    /// The signed digits of this side's full-width `scalars`, bound to
    /// them, into the digits stage in order: the other side's foreign
    /// scalars, which it scales by their digits. Then each of `flags`, an
    /// element the side holds to zero or one, as the signed digit
    /// $2 f - 1$.
    fn write_digits(
        &mut self,
        dr: &mut D,
        scalars: &[Element<'dr, D>],
        flags: &[Element<'dr, D>],
    ) -> Result<()> {
        let layout = self.tables.layout;
        assert_eq!(flags.len(), layout.flags, "every flag has its digit");
        let width = derive::digit_width::<S::F>();
        assert_eq!(
            width * scalars.len(),
            layout.digits - layout.flags,
            "the digits stage holds every scalar's digits"
        );
        let mut slot = 0;
        for scalar in scalars {
            // The digits, bound to the scalar, as the signed digits 2b - 1
            // the other side scales by.
            let digits = Digits::alloc_bound(dr, scalar)?;
            for bit in digits.bits() {
                let digit = signed(dr, &bit.element());
                self.digits.write(dr, slot, digit)?;
                slot += 1;
            }
        }
        for flag in flags {
            let digit = signed(dr, flag);
            self.digits.write(dr, slot, digit)?;
            slot += 1;
        }
        Ok(())
    }

    /// The reduction's challenges from this side's lifts.
    fn revdot_challenges(&self) -> Result<revdot::Challenges<'dr, D>> {
        Ok(revdot::Challenges {
            z: self.lift(squeezed::Z)?,
            weights: Weights {
                mu: self.lift(squeezed::MU)?,
                nu: self.lift(squeezed::NU)?,
                mu_prime: self.lift(squeezed::MU_PRIME)?,
                nu_prime: self.lift(squeezed::NU_PRIME)?,
            },
            rho: self.lift(squeezed::RHO)?,
            r: self.lift(squeezed::R)?,
        })
    }

    fn revdot_messages(&self) -> revdot::Messages<'dr, D> {
        let m = self.message_scalars();
        revdot::Messages {
            inner_epsilon: m.inner_epsilon().clone(),
            outer_epsilon: m.outer_epsilon().clone(),
            openings: m.openings().to_vec(),
            p_at_inverse_r: m.p_at_inverse_r().clone(),
            q_at_r: m.q_at_r().clone(),
        }
    }

    /// The batch and the IPA's scalars over the reduction's openings and
    /// the instance's, `opening` its point and values, the fuse's $u$ as
    /// this side holds it, $v$, $a(u)$ and $b(u)$, leaving $v$ and
    /// $c b z$. `digest` is the compression transcript's last squeeze on
    /// the side whose instance carries a step binding.
    #[allow(clippy::too_many_arguments)]
    fn batch_ipa<K: Rank>(
        &self,
        dr: &mut D,
        challenges: &revdot::Challenges<'dr, D>,
        messages: &revdot::Messages<'dr, D>,
        inverse_r: &Element<'dr, D>,
        target: Element<'dr, D>,
        [u, v, a_at_u, b_at_u]: [Element<'dr, D>; 4],
        restriction_at_w: Element<'dr, D>,
        digest: Option<&Element<'dr, D>>,
    ) -> Result<[Element<'dr, D>; 2]> {
        let rounds = K::RANK as usize;
        let mut claims = revdot::openings(dr, challenges, messages, inverse_r, target)?;
        let base = Derived::ALL.len() + 2;
        let claim = |poly, point: &Element<'dr, D>, value: Element<'dr, D>| OpeningClaim {
            poly,
            point: point.clone(),
            value,
        };
        claims.extend([
            claim(base, &self.lift(squeezed::W)?, restriction_at_w),
            claim(base + 1, &u, v),
            claim(base + 2, &u, a_at_u),
            claim(base + 3, &u, b_at_u),
        ]);
        let m = self.message_scalars();
        let batched = batch::verify(
            dr,
            &claims,
            base + OPENED,
            &batch::Challenges {
                alpha: self.lift(squeezed::ALPHA)?,
                u: self.lift(squeezed::U)?,
                beta: self.lift(squeezed::BETA)?,
            },
            &batch::Messages {
                evaluations: m.evaluations().to_vec(),
            },
        )?;
        let rounds = (0..rounds)
            .map(|j| self.lift(squeezed::ROUNDS + j))
            .collect::<Result<Vec<_>>>()?;
        // The step's batch of this field opens the IPA's s(X) at the
        // step's y, and the query stage holds the point and the value.
        // The polynomial the step committed takes the value of s(X)
        // there, so its commitment, which the other side holds its G'
        // to, is that of s(X).
        let query = self.online_query;
        let point = &query[online::QUERY_Y];
        let opening = &query[online::Values::value_at(S::ONLINE.ipa())];
        let expected = ipa::s_at(dr, &rounds, point)?;
        let gap = opening.sub(dr, &expected);
        // The circuit-field side holds the host curve's under the
        // decompression flag, as the other side holds the commitment to
        // G' under it. The scalar-field side holds the nested curve's
        // in every step, as the other side exposes its G' in every step.
        let step = self.tables.layout.instance.step;
        if step.len != 0 {
            let elements = self.instance.elements;
            let flag = &elements[step.at(stages::step::FLAG)];
            flag.mul(dr, &gap)?.enforce_zero(dr)?;
            // And the digest the step staged before its challenge is the
            // transcript's last squeeze: the round messages of both
            // curves' IPAs, and so both challenge polynomials, were fixed
            // before the point either is opened at.
            let digest = digest.ok_or_else(|| {
                Error::InvalidWitness(
                    "the side whose instance carries a step binding squeezes the digest".into(),
                )
            })?;
            let staged = &elements[step.at(stages::step::DIGEST)];
            let gap = staged.sub(dr, digest);
            flag.mul(dr, &gap)?.enforce_zero(dr)?;
        } else {
            gap.enforce_zero(dr)?;
        }
        let scalars = ipa::verify(
            dr,
            &batched.point,
            &ipa::Challenges {
                z: self.lift(squeezed::IPA_Z)?,
                rounds,
            },
            &ipa::Messages { c: m.c().clone() },
        )?;
        Ok([batched.value, scalars.u.negate(dr)])
    }

    /// The IPA's point checks for this side's curve from the batched
    /// commitment `batched`: the left-hand side's sum with each round's
    /// check, the three scalings by the foreign scalars at `scalars` and
    /// the final equality. Returns $G'$, which the prover supplies.
    fn ipa(
        &mut self,
        dr: &mut D,
        batched: Point<'dr, D, S::P>,
        rounds: usize,
        xi: &Challenge<'dr, D>,
        round_challenge: impl Fn(usize) -> Challenge<'dr, D>,
        scalars: [usize; 3],
    ) -> Result<Point<'dr, D, S::P>> {
        use stages::message_points::*;
        let mut left = self.sum(
            dr,
            batched,
            &[(
                Src::Wire(self.message_point(S_COMMITMENT)),
                Some(xi.clone()),
            )],
        )?;
        for j in 0..rounds {
            // The round's witness point u_j^{-1} L_j, which the prover
            // supplies and u_j scales back to L_j, and u_j R_j, both off
            // one read of the challenge.
            let value = self.witness.as_ref().map(|w| w.supplied.inverse_scaled[j]);
            let scaled = Point::alloc(dr, value)?;
            let endoscalar = self.endoscalar(dr, &round_challenge(j))?;
            endoscalar
                .group_scale(dr, &scaled)?
                .enforce_equal(dr, &self.message_point(l(j)))?;
            let scaled_r = endoscalar.group_scale(dr, &self.message_point(r(j)))?;
            left = NonzeroBank::scope(dr, |dr, bank| {
                left.add_incomplete(dr, &scaled, bank)?
                    .add_incomplete(dr, &scaled_r, bank)
            })?;
        }

        let g_prime = Point::alloc(dr, self.witness.as_ref().map(|w| w.supplied.g_prime))?;
        let bases = [
            Src::Fixed(self.generators[0]),
            Src::Wire(g_prime.clone()),
            Src::Fixed(self.u),
        ];
        let mut scaled = Vec::with_capacity(bases.len());
        for (i, (base, scalar)) in bases.into_iter().zip(scalars).enumerate() {
            // Keep a distinct offset in each term. A zero scalar then
            // produces a nonidentity point, and the sum removes all three
            // offsets together below.
            let offset = (self.generators[1] * S::Other::from(1u64 << i)).to_affine();
            let base = base.point(dr)?;
            scaled.push(self.scale(dr, &base, scalar, offset, false)?);
        }
        let width = derive::digit_width::<S::Other>();
        let correction = derive::scale_offset(self.generators[1], width);
        let correction = (correction * S::Other::from(7u64)).to_affine();
        let right = self.sum(
            dr,
            scaled[0].clone(),
            &[
                (Src::Wire(scaled[1].clone()), None),
                (Src::Wire(scaled[2].clone()), None),
                (Src::Negated(correction), None),
            ],
        )?;
        left.enforce_equal(dr, &right)?;
        Ok(g_prime)
    }
}

/// A transcript as the native verifier runs it, with the commitment it
/// absorbs for a run of scalar-field values before whatever ends the run:
/// [`foreign`](Self::foreign) marks that such values were absorbed, and
/// the next absorption or squeeze absorbs the next run's commitment, a
/// point the prover supplies, when they were.
struct Replay<'w, 'dr, D, C, S>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    sponge: Sponge<'dr, D, S::Poseidon>,
    witness: DriverValue<D, &'w Prepared<C, S>>,
    /// The runs' commitments absorbed so far, in order.
    runs: Vec<Point<'dr, D, S::P>>,
    pending: bool,
}

impl<'w, 'dr, D, C, S> Replay<'w, 'dr, D, C, S>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
{
    /// A transcript under `tag`, which it absorbs as [`Transcript::new`]
    /// does: the length, then each 16-byte chunk as a little-endian
    /// integer.
    ///
    /// [`Transcript::new`]: crate::internal::transcript::Transcript::new
    fn new(dr: &mut D, run: &Run<'_, 'w, 'dr, D, C, S>, tag: &[u8]) -> Result<Self> {
        let mut sponge = Sponge::new(dr, run.poseidon);
        let chunks = tag.chunks(16).map(|chunk| {
            let bytes: [u8; 16] = core::array::from_fn(|i| chunk.get(i).copied().unwrap_or(0));
            u128::from_le_bytes(bytes)
        });
        for value in once(tag.len() as u128).chain(chunks) {
            let element = Element::constant(dr, D::F::from_u128(value));
            sponge.absorb(dr, &element)?;
        }
        Ok(Replay {
            sponge,
            witness: run.witness.as_ref().map(|w| *w),
            runs: Vec::new(),
            pending: false,
        })
    }

    /// Absorbs a point: its coordinates, $x$ then $y$.
    fn point(&mut self, dr: &mut D, point: &Point<'dr, D, S::P>) -> Result<()> {
        for coordinate in &coordinates(dr, point)? {
            self.sponge.absorb(dr, coordinate)?;
        }
        Ok(())
    }

    /// Absorbs the run's commitment, if a run is pending.
    fn flush(&mut self, dr: &mut D) -> Result<()> {
        if self.pending {
            let next = self.runs.len();
            let value = self.witness.as_ref().map(|w| w.supplied.runs[next]);
            let run = Point::alloc(dr, value)?;
            self.point(dr, &run)?;
            self.runs.push(run);
            self.pending = false;
        }
        Ok(())
    }

    /// Scalar-field values absorbed: the run's commitment covers them.
    fn foreign(&mut self) {
        self.pending = true;
    }

    fn absorb(&mut self, dr: &mut D, element: &Element<'dr, D>) -> Result<()> {
        self.flush(dr)?;
        self.sponge.absorb(dr, element)
    }

    fn absorb_point(&mut self, dr: &mut D, point: &Point<'dr, D, S::P>) -> Result<()> {
        self.flush(dr)?;
        self.point(dr, point)
    }

    fn squeeze(&mut self, dr: &mut D) -> Result<Element<'dr, D>> {
        self.flush(dr)?;
        self.sponge.squeeze(dr)
    }

    /// The runs' commitments the transcript absorbed. Values pending at
    /// the end precede no challenge and are not absorbed, as the verifier
    /// leaves them.
    fn finish(self) -> Vec<Point<'dr, D, S::P>> {
        self.runs
    }
}

/// What the shared part of a side's verifier takes from the side.
struct Body<'x, 'dr, D: Driver<'dr>> {
    /// Every claim's target of the reduction the side checks in its
    /// field, in claim order.
    targets: Vec<Element<'dr, D>>,
    /// The wire bindings' expected values, by binding: a `None` is a
    /// registry value the prover supplies.
    expected: Vec<Vec<Option<Element<'dr, D>>>>,
    /// The instance's openings' point and values: the fuse's $u$ as the
    /// side holds it, $v$, $a(u)$ and $b(u)$.
    opening: [Element<'dr, D>; 4],
    /// Elements beyond $v$, $c$ and $c b z$ whose digits the side binds
    /// for the other.
    extra_digits: Vec<Element<'dr, D>>,
    /// The compression challenge at a [`squeezed`] index of the reduction
    /// whose points the side checks.
    point_challenge: &'x dyn Fn(usize) -> Challenge<'dr, D>,
    /// The number of that curve's listed components, after which its
    /// registry restriction's and $p$'s commitments sit.
    components: usize,
    /// The positions of that curve's $A$ and $B$ commitments.
    ab: [usize; 2],
    /// The proof's online inputs as the side holds them, each with the
    /// input stage's wire it is held to.
    inputs: Vec<(Element<'dr, D>, usize)>,
    /// The compression transcript's last squeeze, on the side that
    /// squeezes it.
    digest: Option<Element<'dr, D>>,
}

/// What both sides share: the reduction, the batch and the IPA's scalars
/// in the side's field, then the claims, the folds, the batched commitment
/// and the IPA's points on the side's curve. Returns the elements whose
/// digits the side holds for the other, which its verifier ends with
/// ([`Run::write_digits`]), and its $G'$.
fn body<'dr, D, C, S, K>(
    dr: &mut D,
    run: &mut Run<'_, '_, 'dr, D, C, S>,
    body: Body<'_, 'dr, D>,
) -> Result<(Vec<Element<'dr, D>>, Point<'dr, D, S::P>)>
where
    D: Driver<'dr>,
    C: Cycle,
    S: Side<C, F = D::F>,
    K: Rank,
{
    let tables = run.tables;
    let layout = tables.layout;
    let rounds = K::RANK as usize;

    // The registry's evaluations, which the prover supplies: the
    // restriction at (r, y) of each circuit a claim names, the claims
    // naming one circuit sharing it, since the restriction is the
    // circuit's; the restriction at the compression's w; and the wire
    // bindings' registry values.
    let mut named: Vec<(CircuitIndex, Element<'dr, D>)> = Vec::new();
    for claim in &tables.claims {
        if let Kind::Circuit(circuit) | Kind::Mask(circuit) = claim.kind
            && !named.iter().any(|(listed, _)| *listed == circuit)
        {
            let index = named.len();
            let value = run.witness.as_ref().map(|w| w.supplied.restrictions[index]);
            named.push((circuit, Element::alloc(dr, &mut (), value)?));
        }
    }
    let restriction_at_w = {
        let value = run.witness.as_ref().map(|w| w.supplied.restriction_at_w);
        Element::alloc(dr, &mut (), value)?
    };
    assert_eq!(
        body.expected.len(),
        tables.bindings.len(),
        "the expected values of every wire binding"
    );
    let mut registry_values = Vec::new();
    let mut bindings = Vec::with_capacity(tables.bindings.len());
    for (b, (degrees, expected)) in tables.bindings.iter().zip(body.expected).enumerate() {
        assert_eq!(degrees.len(), expected.len(), "one value per bound wire");
        let mut values = Vec::with_capacity(expected.len());
        for (i, value) in expected.into_iter().enumerate() {
            values.push(match value {
                Some(value) => value,
                None => {
                    let value = run.witness.as_ref().map(|w| w.supplied.bindings[b][i]);
                    let value = Element::alloc(dr, &mut (), value)?;
                    registry_values.push(value.clone());
                    value
                }
            });
        }
        bindings.push(revdot::Binding {
            degrees: degrees.clone(),
            expected: values,
        });
    }
    // Held to the query stage's wires, which the step's fuse proves are
    // the wallet registry's: each named circuit's restriction, the
    // instance's opening, then the wire bindings' values in the order the
    // verifier lists them, the query's and the eval's. And each of the
    // proof's inputs, a coordinate or point the side derives or loads, to
    // the input stage's wire it names, which the step committed before its
    // challenge and the evaluations are taken at.
    {
        let online = S::ONLINE;
        let value = |wire: usize| &run.online_query[online::Values::value_at(wire)];
        for (circuit, restriction) in &named {
            restriction.enforce_equal(dr, value(online.claim(usize::from(*circuit))))?;
        }
        restriction_at_w.enforce_equal(dr, value(online.at_w_c()))?;
        let wires: Vec<usize> = online
            .query_binding()
            .into_iter()
            .chain(online.eval_binding().into_iter().flatten())
            .collect();
        assert_eq!(
            registry_values.len(),
            wires.len(),
            "one value wire per registry value the wire bindings expect"
        );
        for (registry_value, wire) in registry_values.iter().zip(wires) {
            registry_value.enforce_equal(dr, value(wire))?;
        }
        for (input, index) in &body.inputs {
            let wire = &run.online_input[online::Values::input_at(*index)];
            input.enforce_equal(dr, wire)?;
        }
    }

    // The reduction: the fold's weights at r, each wire binding's expected
    // value and mask at r, the folded claim's public parts and the split
    // identity, leaving p(0)'s value; then the batch and the IPA's
    // scalars, leaving v and c b z.
    let challenges = run.revdot_challenges()?;
    let messages = run.revdot_messages();
    let at_r = revdot::weights::<_, K>(dr, tables.claims.len(), &challenges)?;
    let sigma = run.lift(squeezed::SIGMA)?;
    let bound = revdot::bindings_at::<_, K>(dr, &bindings, &sigma, &challenges.r)?;
    let public = revdot::Public {
        kinds: tables.claims.iter().map(|claim| claim.kind).collect(),
        targets: body.targets,
        restrictions: named,
        bindings,
    };
    let target = revdot::public::<_, K>(dr, &public, &challenges, &messages, &at_r, &bound)?;
    let [v, cbz] = run.batch_ipa::<K>(
        dr,
        &challenges,
        &messages,
        &at_r.inverse_r,
        target,
        body.opening,
        restriction_at_w,
        body.digest.as_ref(),
    )?;
    // The digits of v, c and cbz, the full-width scalars the other side
    // scales by, and whatever else it needs from this field.
    let mut digits = vec![v, run.message_scalars().c().clone(), cbz];
    digits.extend(body.extra_digits);

    // The point checks of the side's curve under its reduction's
    // challenges.
    let challenge = body.point_challenge;
    let claim_points = run.claims(dr, &tables.point_claims, &challenge(squeezed::Z))?;
    let a = run.fold(
        dr,
        &tables.point_claims,
        &claim_points,
        |_| true,
        &challenge(squeezed::MU),
        &challenge(squeezed::MU_PRIME),
    )?;
    let dilated = run.fold(
        dr,
        &tables.point_claims,
        &claim_points,
        |claim| matches!(claim.kind, Kind::Circuit(_)),
        &challenge(squeezed::NU),
        &challenge(squeezed::NU_PRIME),
    )?;
    // The raw polynomial: the raw claims' b under the b weights, here the
    // one raw claim's at weight one.
    let raw_b: Vec<(usize, usize)> = tables
        .point_claims
        .iter()
        .enumerate()
        .filter_map(|(i, claim)| claim.b.map(|b| (i, b)))
        .collect();
    assert_eq!(raw_b.len(), 1, "one raw claim at the first slot");
    assert_eq!(raw_b[0].0, 0);
    let raw = run.commitment(raw_b[0].1);
    let batched = {
        use stages::message_points::*;
        // The batch weights f highest: a Horner chain from f down.
        let terms: Vec<Option<Src<'dr, D, S::P>>> = [
            run.message_point(F),
            a,
            dilated,
            raw,
            run.message_point(INNER),
            run.message_point(OUTER),
            run.message_point(P),
            run.message_point(Q),
            run.commitment(body.components),
            run.commitment(body.components + 1),
            run.commitment(body.ab[0]),
            run.commitment(body.ab[1]),
        ]
        .into_iter()
        .rev()
        .map(|point| Some(Src::Wire(point)))
        .collect();
        run.horner(dr, &terms, &challenge(squeezed::BETA))?
            .ok_or_else(|| Error::InvalidWitness("the batch has a term".into()))?
    };
    let g_prime = run.ipa(
        dr,
        batched,
        rounds,
        &challenge(squeezed::XI),
        |j| challenge(squeezed::ROUNDS + j),
        [0, 1, 2],
    )?;

    // Every point a stage holds, held to the curve: the stages load their
    // points unenforced, so the equation their allocation emits does not
    // reach the circuit on its own. The instance's and the messages'
    // commitments; the points the prover supplies beside the stages are
    // allocated on the curve, and the side's own are sums and scalings of
    // these.
    for position in layout.instance.commitments.positions() {
        run.instance.points[position].enforce_consistent(dr)?;
    }
    for position in layout.messages.points_of_curve.positions() {
        run.messages.points[position].enforce_consistent(dr)?;
    }
    Ok((digits, g_prime))
}

/// The claims' targets of the circuit-field side's reduction, every
/// claim's in claim order: allocates the native unified instance, binds it
/// to the instance stage and to the fuse's challenges the side squeezed,
/// `fuse`, and derives the targets as the fuse does.
fn native_targets<'dr, D, C, const HEADER_SIZE: usize>(
    dr: &mut D,
    run: &Run<'_, '_, 'dr, D, C, Native>,
    fuse: &[Element<'dr, D>],
) -> Result<Vec<Element<'dr, D>>>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
{
    let witness = &run.witness;
    let inputs = ProofInputs::<D, C, HEADER_SIZE>::alloc_from_parts(
        dr,
        witness.as_ref().map(|w| w.extra.output_header.as_slice()),
        witness.as_ref().map(|w| w.extra.omega_j),
        // The standard profile has no statement circuit, so its steps
        // expose no step binding.
        witness.as_ref().map(|_| -> &[C::CircuitField] { &[] }),
        witness.as_ref().map(|w| &w.extra.unified),
        // Nor has it an online batch: no online commitments, sums or
        // mesh claims.
        witness.as_ref().map(|_| -> &[C::NestedCurve] { &[] }),
        witness.as_ref().map(|_| -> &[C::CircuitField] { &[] }),
        witness.as_ref().map(|_| -> &[C::CircuitField] { &[] }),
    )?;
    let layout = run.tables.layout.instance;
    let commitment = |component| run.commitment(nested_position::<Standard>(component));
    let bridge = |index| commitment(nested::RxComponent::Rx(index));
    let listed = nested_components::<Standard>().count();
    let unified = &inputs.unified;
    {
        use nested::RxIndex::*;
        for (ours, theirs) in [
            (bridge(BridgeHash), &unified.bridge_hash_commitment),
            (bridge(BridgePreamble), &unified.bridge_preamble_commitment),
            (bridge(BridgeSPrime), &unified.bridge_s_prime_commitment),
            (
                bridge(BridgeInnerError),
                &unified.bridge_inner_error_commitment,
            ),
            (
                bridge(BridgeOuterError),
                &unified.bridge_outer_error_commitment,
            ),
            (bridge(BridgeAB), &unified.bridge_ab_commitment),
            (bridge(BridgeQuery), &unified.bridge_query_commitment),
            (bridge(BridgeF), &unified.bridge_f_commitment),
            (bridge(BridgeEval), &unified.bridge_eval_commitment),
            (
                run.commitment(listed + 2),
                &unified.nested_challenges_partial,
            ),
            (run.commitment(listed + 1), &unified.nested_p_commitment),
            (
                commitment(nested::RxComponent::AbA),
                &unified.nested_a_commitment,
            ),
            (
                commitment(nested::RxComponent::AbB),
                &unified.nested_b_commitment,
            ),
            (
                run.commitment(listed),
                &unified.nested_registry_xy_commitment,
            ),
        ] {
            ours.enforce_equal(dr, theirs)?;
        }
    }
    for (ours, theirs) in fuse.iter().zip([
        &unified.w,
        &unified.y,
        &unified.z,
        &unified.mu,
        &unified.mu_prime,
        &unified.x,
        &unified.alpha,
        &unified.u,
        &unified.pre_beta,
    ]) {
        ours.enforce_equal(dr, theirs)?;
    }
    run.scalar(native_scalars::C)
        .enforce_equal(dr, &unified.c)?;
    run.scalar(native_scalars::V)
        .enforce_equal(dr, &unified.v)?;
    run.scalar(native_scalars::OMEGA_J)
        .enforce_equal(dr, &inputs.circuit_id)?;
    for (position, theirs) in layout
        .output_header
        .positions()
        .zip(inputs.output_header.iter())
    {
        run.instance.elements[position].enforce_equal(dr, theirs)?;
    }
    // The proof folded its own application claim, so its verifier has no
    // application target: the `hashes_1` claim's, over the unified
    // instance, the output header and the circuit id, and the unified
    // one, which the standard profile's `compute_v` claim takes too,
    // having no online batch to export for.
    let y = run.lift(squeezed::Y)?;
    let (unified, unified_bridge) = inputs.unified_ky_values(dr, &y)?;
    let targets = NativeTargets {
        c: run.scalar(native_scalars::C),
        unified_bridge,
        unified,
        one: Element::one(),
        zero: Element::zero(dr),
    };
    Ok(native_ky_values::<Standard, _>(&targets)
        .take(run.tables.claims.len())
        .collect())
}

/// The claims' targets of the scalar-field side's reduction, as
/// [`native_targets`]: allocates the nested unified instance, binds it to
/// the instance stage and to the lifts of the fuse's challenges, and
/// derives the targets.
fn nested_targets<'dr, D, C, K>(
    dr: &mut D,
    run: &Run<'_, '_, 'dr, D, C, Nested>,
) -> Result<Vec<Element<'dr, D>>>
where
    D: Driver<'dr, F = C::ScalarField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
{
    let output = nested_unified::Output::<D, C::HostCurve>::alloc(
        dr,
        &mut (),
        run.witness.as_ref().map(|w| &w.extra.unified),
    )?;
    // The fuse's x, y and u, in `fuse::LIFTED` order after the nested
    // curve's compression challenges in the lifts stage.
    let fuse_lifts = challenges_per_curve::<K>();
    for (i, ours) in [&output.x, &output.y, &output.u].into_iter().enumerate() {
        ours.enforce_equal(dr, &run.lift(fuse_lifts + i)?)?;
    }
    output.c.enforce_equal(dr, &run.scalar(nested_scalars::C))?;
    output.v.enforce_equal(dr, &run.scalar(nested_scalars::V))?;
    let listed = native_components::<Standard>().count();
    let exported: [usize; nested_unified::NUM_EXPORTED] = {
        use native::{RxComponent::*, RxIndex::*};
        [
            native_position::<Standard>(Rx(Preamble)),
            native_position::<Standard>(Rx(InnerError)),
            native_position::<Standard>(Rx(OuterError)),
            native_position::<Standard>(Rx(Query)),
            native_position::<Standard>(Rx(Eval)),
            native_position::<Standard>(AbA),
            native_position::<Standard>(AbB),
            listed,
            listed + 1,
            native_position::<Standard>(Rx(PointsBinding)),
            native_position::<Standard>(Rx(PointsPreamble)),
            native_position::<Standard>(Rx(PointsRegistryWx)),
            native_position::<Standard>(Rx(PointsAb)),
            native_position::<Standard>(Rx(PointsF)),
            listed + 2,
            listed + 3,
        ]
    };
    for (position, theirs) in exported.iter().zip(output.exported.iter()) {
        run.commitment(*position).enforce_equal(dr, theirs)?;
    }
    let y = run.lift(squeezed::Y)?;
    let targets = NestedTargets {
        c: run.scalar(nested_scalars::C),
        unified: output.ky(dr, &y)?,
        one: Element::one(),
        zero: Element::zero(dr),
    };
    Ok(nested_ky_values::<Standard, _>(&targets)
        .take(run.tables.claims.len())
        .collect())
}

/// A step of one curve's part of the compression's transcript.
#[derive(Clone, Copy)]
enum Message {
    /// The curve's point message at an index of
    /// [`message_points`](mod@stages::message_points).
    Point(usize),
    /// Its scalar message at an index of [`MessageScalars`].
    Scalar(usize),
    /// A challenge of the curve's, the next in [`squeezed`] order.
    Squeeze,
}

/// One curve's part of the compression's transcript after the sampled
/// challenges, as the native verifier absorbs its messages and squeezes
/// its challenges from [`squeezed::MU`] on: each step, in order.
fn curve_messages(rounds: usize) -> Vec<Message> {
    use Message::{Point, Scalar, Squeeze};
    use stages::message_points::*;
    let mut steps = vec![
        Point(INNER),
        // mu, nu
        Squeeze,
        Squeeze,
        Point(OUTER),
        // mu', nu'
        Squeeze,
        Squeeze,
        Scalar(0),
        Scalar(1),
        // rho
        Squeeze,
        Point(P),
        Point(Q),
        // r
        Squeeze,
    ];
    steps.extend((2..2 + Derived::ALL.len() + 2).map(Scalar));
    // alpha
    steps.push(Squeeze);
    steps.push(Point(F));
    // u
    steps.push(Squeeze);
    let evaluations = 4 + Derived::ALL.len();
    steps.extend((evaluations..evaluations + Derived::ALL.len() + 2 + OPENED).map(Scalar));
    // beta
    steps.push(Squeeze);
    steps.push(Point(S_COMMITMENT));
    // xi, z
    steps.extend([Squeeze, Squeeze]);
    for j in 0..rounds {
        // u_j
        steps.extend([Point(l(j)), Point(r(j)), Squeeze]);
    }
    steps.push(Scalar(MESSAGE_SCALARS - 1));
    steps
}

/// The circuit-field side of the decompressed verifier for a proof at
/// rank `K`, over the nested curve: returns the points the side exposes,
/// the commitments of the transcript's runs, then its recomputations of
/// the scalar-field side's lifts and digits stages, then the nested
/// curve's $G'$, which the proof's consumer holds to the commitment of
/// $s(X)$ in the step's nested batch.
pub(crate) fn native_side<'dr, D, C, K, const HEADER_SIZE: usize>(
    dr: &mut D,
    run: &mut Run<'_, '_, 'dr, D, C, Native>,
) -> Result<Vec<Point<'dr, D, C::NestedCurve>>>
where
    D: Driver<'dr, F = C::CircuitField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
{
    let tables = run.tables;
    let instance = tables.layout.instance;
    let messages = tables.layout.messages;
    let rounds = K::RANK as usize;
    let per_curve = challenges_per_curve::<K>();
    let bridge = |run: &Run<'_, '_, 'dr, D, C, Native>, index| {
        run.commitment(nested_position::<Standard>(nested::RxComponent::Rx(index)))
    };

    // What a challenge the side squeezes scales, off one read of its
    // endoscalar, right where it is squeezed, so that a cut of the circuit
    // carries no challenge's bits to another use: its generator of the
    // scalar-field side's lifts stage, whose commitment the side
    // recomputes in the stage's order, the nested curve's compression
    // challenges, the fuse's x, y, u and w, then the host curve's; its
    // generator of the challenge stage, for a challenge of the fuse's;
    // and its lift into this side's lifts stage, for one of the host
    // curve's, whose reduction this side checks.
    let lifts_generator = |run: &Run<'_, '_, 'dr, D, C, Native>, position: usize| {
        run.generators[run.tables.lifts[position]]
    };
    assert_eq!(
        tables.lifts.len(),
        2 * per_curve + fuse::LIFTED.len(),
        "one lift per challenge"
    );
    let read = |dr: &mut D, raw: &Element<'dr, D>| -> Result<Endoscalar<'dr, D>> {
        Ok(Endoscalar::extract(EndoscalarChallenge::from_element(
            dr,
            &mut (),
            raw.clone(),
        )?))
    };
    let mut lifts_sum = None;
    let mut challenge_stage_sum = None;

    // The fuse's transcript: its challenges, replayed from the bridge
    // commitments under the fuse's tag, in
    // [`nested::Challenges::in_order`] order. Each scales its generator of
    // the challenge stage, pre_beta its own.
    let fuse: Vec<Element<'dr, D>> = {
        use nested::RxIndex::*;
        let mut t = Replay::new(dr, run, RAGU_TAG)?;
        let mut fuse = Vec::with_capacity(challenge_stage::NUM + 1);
        // The bridge commitment absorbed before each challenge, if one is.
        let absorbed = [
            Some(BridgePreamble),
            Some(BridgeSPrime),
            None,
            Some(BridgeInnerError),
            Some(BridgeOuterError),
            Some(BridgeAB),
            Some(BridgeQuery),
            Some(BridgeF),
            Some(BridgeEval),
        ];
        for (i, absorbed) in absorbed.into_iter().enumerate() {
            if let Some(index) = absorbed {
                t.absorb_point(dr, &bridge(run, index))?;
            }
            let raw = t.squeeze(dr)?;
            let endoscalar = read(dr, &raw)?;
            let stage = match i {
                fuse::PRE_BETA => challenge_stage::BETA_INDEX,
                i => i,
            };
            let generator = run.generators[generator_index::<C, K>(stage)];
            run.add_term(dr, &mut challenge_stage_sum, &endoscalar, generator)?;
            if let Some(lifted) = fuse::LIFTED.iter().position(|&lifted| lifted == i) {
                let generator = lifts_generator(run, per_curve + lifted);
                run.add_term(dr, &mut lifts_sum, &endoscalar, generator)?;
            }
            fuse.push(raw);
        }
        fuse
    };

    // The challenge stage: each challenge's lift times its generator, the
    // base-case sign's term, and pre_beta's.
    {
        // The verifier of a proof reads the base case off its circuit id:
        // a proof that took it is one of the bootstrap step. The sign's
        // term is the generator, negated unless it did.
        let bootstrap = crate::step::InternalStepIndex::Bootstrap.circuit_index::<Standard>()?;
        let bootstrap = Element::constant(dr, bootstrap.omega_j());
        let id = run.scalar(native_scalars::OMEGA_J);
        let base_case = id.is_equal(dr, &mut (), &bootstrap)?;
        let negate = base_case.not(dr);
        let sign = run.generators[generator_index::<C, K>(challenge_stage::SIGN_INDEX)];
        let sign = Point::constant(dr, sign)?.conditional_negate(dr, &negate)?;
        let terms = challenge_stage_sum
            .take()
            .ok_or_else(|| Error::InvalidWitness("the challenge stage has challenges".into()))?;
        let stage = run.add(dr, [terms, sign])?;
        stage.enforce_equal(dr, &bridge(run, nested::RxIndex::ChallengeStage))?;
    }

    // The compression's transcript: the statement, both curves' sampled
    // challenges, then each curve's messages, the scalar field's values
    // among them as the run's commitment before the next challenge. The
    // host curve's challenges, in [`squeezed`] order, the nested curve's,
    // and the commitment of each run of the scalar field's values, which
    // the prover supplies and the side exposes.
    let (own, other, runs) = {
        let mut t = Replay::new(dr, run, IPA_TAG)?;
        let mut own: Vec<Element<'dr, D>> = Vec::with_capacity(per_curve);
        let mut other: Vec<Element<'dr, D>> = Vec::with_capacity(per_curve);
        // A challenge of the host curve's: its lift, into the lifts stage
        // in [`squeezed`] order, and its term of the scalar-field side's.
        let mut squeeze_own = |dr: &mut D,
                               t: &mut Replay<'_, 'dr, D, C, Native>,
                               run: &mut Run<'_, '_, 'dr, D, C, Native>|
         -> Result<()> {
            let raw = t.squeeze(dr)?;
            let endoscalar = read(dr, &raw)?;
            let lift = endoscalar.lift(dr)?;
            run.lifts.write(dr, own.len(), lift)?;
            let generator = lifts_generator(run, per_curve + fuse::LIFTED.len() + own.len());
            run.add_term(dr, &mut lifts_sum, &endoscalar, generator)?;
            own.push(raw);
            Ok(())
        };
        t.absorb(dr, &run.scalar(native_scalars::OMEGA_J))?;
        // The host commitments.
        t.foreign();
        for i in native_scalars::C..=native_scalars::B_AT_U {
            t.absorb(dr, &run.scalar(i))?;
        }
        for position in instance.commitments.positions() {
            t.absorb_point(dr, &run.instance.points[position])?;
        }
        // The scalar field's instance values.
        t.foreign();
        for position in instance.output_header.positions() {
            t.absorb(dr, &run.instance.elements[position])?;
        }
        for _ in 0..4 {
            squeeze_own(dr, &mut t, run)?;
        }
        // The host curve's: its points are the scalar field's, its scalars
        // this field's.
        let mut deferred = Vec::with_capacity(4);
        for _ in 0..4 {
            deferred.push(t.squeeze(dr)?);
        }
        for step in curve_messages(rounds) {
            match step {
                Message::Point(_) => t.foreign(),
                Message::Scalar(i) => {
                    t.absorb(dr, &run.messages.elements[messages.scalars.at(i)])?;
                }
                Message::Squeeze => squeeze_own(dr, &mut t, run)?,
            }
        }
        // The nested curve's: its points this field's, its scalars the
        // scalar field's. A challenge of its scales its term of the
        // scalar-field side's lifts stage.
        let mut squeezed_other = |dr: &mut D,
                                  run: &mut Run<'_, '_, 'dr, D, C, Native>,
                                  raw: Element<'dr, D>|
         -> Result<()> {
            let endoscalar = read(dr, &raw)?;
            let generator = lifts_generator(run, other.len());
            run.add_term(dr, &mut lifts_sum, &endoscalar, generator)?;
            other.push(raw);
            Ok(())
        };
        for raw in deferred {
            squeezed_other(dr, run, raw)?;
        }
        for step in curve_messages(rounds) {
            match step {
                Message::Point(i) => t.absorb_point(dr, &run.message_point(i))?,
                Message::Scalar(_) => t.foreign(),
                Message::Squeeze => {
                    let raw = t.squeeze(dr)?;
                    squeezed_other(dr, run, raw)?;
                }
            }
        }
        (own, other, t.finish())
    };
    assert_eq!(own.len(), per_curve, "the host curve's challenges");
    assert_eq!(other.len(), per_curve, "the nested curve's challenges");
    assert_eq!(runs.len(), num_runs::<K>(), "every run is absorbed");
    let lifts_sum =
        lifts_sum.ok_or_else(|| Error::InvalidWitness("the lifts stage has lifts".into()))?;
    // The transcript's last squeeze, after which it absorbs only the
    // nested IPA's final scalar: the digest of everything both IPAs' round
    // challenges are squeezed from.
    let digest = other[squeezed::ROUNDS + rounds - 1].clone();
    run.digest = Some(digest.clone());
    let other_challenge = |i: usize| Challenge::squeezed(i, &other[i]);

    // The wire bindings: the preamble's children from the instance, the
    // query's values from the registry, the eval's from the registry
    // around a(u) and b(u), and the points stages' from the nested
    // commitments' coordinates.
    let ab = [
        nested_position::<Standard>(nested::RxComponent::AbA),
        nested_position::<Standard>(nested::RxComponent::AbB),
    ];
    let components = nested_components::<Standard>().count();
    let expected = {
        let [ax, ay] = coordinates(dr, &run.commitment(ab[0]))?;
        let [bx, by] = coordinates(dr, &run.commitment(ab[1]))?;
        let [gx, gy] = coordinates(dr, &run.commitment(components))?;
        vec![
            (native_scalars::LEFT_X..=native_scalars::RIGHT_Y)
                .map(|i| Some(run.scalar(i)))
                .collect(),
            vec![None; tables.bindings[1].len()],
            vec![
                None,
                None,
                None,
                Some(run.scalar(native_scalars::A_AT_U)),
                Some(run.scalar(native_scalars::B_AT_U)),
                None,
            ],
            vec![Some(ax), Some(ay), Some(bx), Some(by)],
            vec![Some(gx), Some(gy)],
        ]
    };
    // The compression's challenges as the transcript lifts them, the
    // fuse's as it squeezes them, the children's values and the proof's
    // own circuit's domain point as the instance holds them.
    let inputs = vec![
        (run.lift(squeezed::R)?, input::R),
        (run.lift(squeezed::Y)?, input::Y_C),
        (fuse[fuse::X].clone(), input::X),
        (fuse[fuse::Y].clone(), input::Y),
        (run.scalar(native_scalars::LEFT_X), input::LEFT_X),
        (run.scalar(native_scalars::LEFT_Y), input::LEFT_Y),
        (run.scalar(native_scalars::RIGHT_X), input::RIGHT_X),
        (run.scalar(native_scalars::RIGHT_Y), input::RIGHT_Y),
        (fuse[fuse::U].clone(), input::U),
        (fuse[fuse::W].clone(), input::W),
        (run.lift(squeezed::W)?, input::W_C),
        (run.scalar(native_scalars::OMEGA_J), input::CIRCUIT),
    ];
    let targets = native_targets::<_, C, HEADER_SIZE>(dr, run, &fuse)?;
    let opening = [
        fuse[fuse::U].clone(),
        run.scalar(native_scalars::V),
        run.scalar(native_scalars::A_AT_U),
        run.scalar(native_scalars::B_AT_U),
    ];
    let (digits, g_prime) = body::<_, C, Native, K>(
        dr,
        run,
        Body {
            targets,
            expected,
            opening,
            extra_digits: Vec::new(),
            point_challenge: &other_challenge,
            components,
            ab,
            inputs,
            digest: Some(digest),
        },
    )?;

    // The ab bridge: its coefficients' digits times their generators.
    {
        let mut scaled = Vec::with_capacity(tables.ab_terms.len());
        for (k, &(index, which)) in tables.ab_terms.iter().enumerate() {
            let base = Point::constant(dr, run.generators[index])?;
            scaled.push(run.scale(dr, &base, 3 + k, run.u, which != AbValue::Alpha)?);
        }
        let mut terms: Vec<_> = scaled[1..]
            .iter()
            .map(|point| (Src::Wire(point.clone()), None))
            .collect();
        // The alpha term may be zero. Its scale retains the fixed offset
        // rather than leaving the identity.
        let width = derive::digit_width::<C::ScalarField>();
        terms.push((Src::Negated(derive::scale_offset(run.u, width)), None));
        let ab_bridge = run.sum(dr, scaled[0].clone(), &terms)?;
        ab_bridge.enforce_equal(dr, &bridge(run, nested::RxIndex::BridgeAB))?;
    }

    // The scalar-field side's digits stage, from the scalings' parts, and
    // this side's digits for it, last of all, so that only what follows
    // them reads the digits stage. The decompression flag crosses to the
    // scalar-field side as a digit.
    let digits_sum = run.digits_sum(dr)?;
    let exposed: Vec<_> = runs
        .into_iter()
        .chain([lifts_sum, digits_sum, g_prime])
        .collect();
    let flag = run.instance.elements[instance.step.at(stages::step::FLAG)].clone();
    run.write_digits(dr, &digits, &[flag])?;
    Ok(exposed)
}

/// The scalar-field side of the decompressed verifier for a proof at rank
/// `K`, over the host curve: returns the points the side exposes, its
/// recomputation of the circuit-field side's digits stage, then the two
/// application output commitments and the commitment of the host IPA's
/// $s(X)$ in the native batch of the step that proves the side.
pub(crate) fn nested_side<'dr, D, C, K>(
    dr: &mut D,
    run: &mut Run<'_, '_, 'dr, D, C, Nested>,
) -> Result<Vec<Point<'dr, D, C::HostCurve>>>
where
    D: Driver<'dr, F = C::ScalarField>,
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
{
    let tables = run.tables;
    let instance = tables.layout.instance;
    let per_curve = challenges_per_curve::<K>();
    let lifted = fuse::LIFTED.len();

    // The lifts: the nested curve's compression challenges, the fuse's x,
    // y, u and w and the host curve's compression challenges, all squeezed
    // on the other side, from their bits, into the lifts stage in that
    // order, which the other side recomputes. Each fills the slot every
    // other use of the challenge holds its bits' lift to, so it allocates
    // the bits alone and lets the write hold them.
    for id in 0..2 * per_curve + lifted {
        let lift = run.bits(dr, id)?.lift(dr)?;
        run.lifts.write(dr, id, lift)?;
    }
    let fuse_lift = |run: &Run<'_, '_, 'dr, D, C, Nested>, i: usize| run.lift(per_curve + i);

    // The wire bindings on the nested side.
    let expected = vec![
        (nested_scalars::LEFT_X..=nested_scalars::RIGHT_Y)
            .map(|i| Some(run.scalar(i)))
            .collect(),
        vec![None; tables.bindings[1].len()],
        vec![
            None,
            None,
            None,
            Some(run.scalar(nested_scalars::A_AT_U)),
            Some(run.scalar(nested_scalars::B_AT_U)),
            None,
        ],
    ];

    // The ab bridge's values, whose digits the other side scales by: the
    // coordinates of the host curve's A, B and points-ab commitments and
    // the stage's alpha, bridge_alpha squared.
    let ab = [
        native_position::<Standard>(native::RxComponent::AbA),
        native_position::<Standard>(native::RxComponent::AbB),
    ];
    let extra_digits = {
        let a = coordinates(dr, &run.commitment(ab[0]))?;
        let b = coordinates(dr, &run.commitment(ab[1]))?;
        let points_ab =
            native_position::<Standard>(native::RxComponent::Rx(native::RxIndex::PointsAb));
        let points_ab = coordinates(dr, &run.commitment(points_ab))?;
        let mut digits = Vec::with_capacity(tables.ab_terms.len());
        for &(_, which) in &tables.ab_terms {
            digits.push(match which {
                AbValue::A(i) => a[i].clone(),
                AbValue::B(i) => b[i].clone(),
                AbValue::PointsAb(i) => points_ab[i].clone(),
                AbValue::Alpha => run.scalar(nested_scalars::BRIDGE_ALPHA).square(dr)?,
            });
        }
        digits
    };

    // The lifts the lifts stage holds, in `fuse::LIFTED` order for the
    // fuse's, and the children's values as the instance holds them.
    let inputs = vec![
        (run.lift(squeezed::R)?, input::R),
        (run.lift(squeezed::Y)?, input::Y_C),
        (fuse_lift(run, 0)?, input::X),
        (fuse_lift(run, 1)?, input::Y),
        (run.scalar(nested_scalars::LEFT_X), input::LEFT_X),
        (run.scalar(nested_scalars::LEFT_Y), input::LEFT_Y),
        (run.scalar(nested_scalars::RIGHT_X), input::RIGHT_X),
        (run.scalar(nested_scalars::RIGHT_Y), input::RIGHT_Y),
        (fuse_lift(run, 2)?, input::U),
        (fuse_lift(run, 3)?, input::W),
        (run.lift(squeezed::W)?, input::W_C),
    ];
    let targets = nested_targets::<_, C, K>(dr, run)?;
    let opening = [
        fuse_lift(run, 2)?,
        run.scalar(nested_scalars::V),
        run.scalar(nested_scalars::A_AT_U),
        run.scalar(nested_scalars::B_AT_U),
    ];
    let (digits, g_prime) = body::<_, C, Nested, K>(
        dr,
        run,
        Body {
            targets,
            expected,
            opening,
            extra_digits,
            point_challenge: &|i| Challenge::bits(per_curve + lifted + i),
            components: native_components::<Standard>().count(),
            ab,
            inputs,
            digest: None,
        },
    )?;

    // The binding claim ties these commitments to the aggregator's PCS.
    // Under the decompression flag, its application slots carry the wallet
    // proof's own commitments, and the native batch's s(X) commits to G'.
    let mut outputs = Vec::with_capacity(crate::header::NUM_ONLINE_FP_POLYS);
    for i in 0..crate::header::NUM_ONLINE_FP_POLYS {
        let value = run.witness.as_ref().map(|w| w.supplied.outputs[i]);
        outputs.push(Point::alloc(dr, value)?);
    }
    let host_ipa = Point::alloc(dr, run.witness.as_ref().map(|w| w.supplied.host_ipa))?;
    let wallet_start = instance
        .commitments
        .at(instance.commitments.len - outputs.len());
    let pairs: Vec<[Point<'dr, D, C::HostCurve>; 2]> = outputs
        .iter()
        .enumerate()
        .map(|(i, output)| {
            [
                output.clone(),
                run.instance.points[wallet_start + i].clone(),
            ]
        })
        .chain([[host_ipa.clone(), g_prime]])
        .collect();
    run.equal_if(dr, 0, &pairs)?;

    let digits_sum = run.digits_sum(dr)?;
    let exposed: Vec<_> = once(digits_sum).chain(outputs).chain([host_ipa]).collect();
    assert_eq!(
        digits.len(),
        3 + AB_TERMS,
        "the ab bridge's terms are pinned"
    );
    run.write_digits(dr, &digits, &[])?;
    Ok(exposed)
}

/// The values a side's tables are the pure function of their types for,
/// built once and kept: under `std`, one process-wide map from the [`TypeId`] of a key
/// type, which names the function and its type parameters, to the value
/// built for it; without `std`, rebuilt on each request, which costs time
/// alone. Only a successful build is kept. The build runs outside the lock,
/// so callers racing on a first request may each build; every one returns
/// the value kept first.
///
/// [`TypeId`]: core::any::TypeId
#[cfg(feature = "std")]
fn memo<Key: 'static, T: Clone + Send + Sync + 'static>(
    build: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use core::any::{Any, TypeId};
    use std::{
        boxed::Box,
        collections::BTreeMap,
        sync::{Mutex, OnceLock, PoisonError},
    };
    static MEMO: OnceLock<Mutex<BTreeMap<TypeId, Box<dyn Any + Send + Sync>>>> = OnceLock::new();
    let memo = MEMO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let key = TypeId::of::<Key>();
    let kept = memo
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
        .map(|value| {
            value
                .downcast_ref::<T>()
                .expect("a key names one type")
                .clone()
        });
    if let Some(value) = kept {
        return Ok(value);
    }
    let value = build()?;
    Ok(memo
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(key)
        .or_insert_with(|| Box::new(value))
        .downcast_ref::<T>()
        .expect("a key names one type")
        .clone())
}

#[cfg(not(feature = "std"))]
#[allow(
    clippy::extra_unused_type_parameters,
    reason = "the key names the kept value, which only the std build keeps"
)]
fn memo<Key: 'static, T>(build: impl FnOnce() -> Result<T>) -> Result<T> {
    build()
}
