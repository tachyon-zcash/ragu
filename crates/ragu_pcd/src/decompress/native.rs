//! The circuit-field side of the decompression ([`Native`]): the
//! compressed proof's verifier in the circuit field, over the nested
//! curve, as one circuit ([`Circuit`]) that the pager cuts into the pages
//! of the aggregator profile's native extension
//! ([`NATIVE_PAGES`](crate::profile::Aggregator::NATIVE_PAGES)).
//!
//! The side checks the native reduction's scalars in its field and the
//! nested reduction's points on its curve ([`native_tables`]). It replays
//! the compression's transcripts with the Poseidon sponge, absorbing each
//! run of the scalar field's values as the commitment of the run's stage,
//! a point the prover supplies, and binds the native unified instance to
//! the instance stage and to the fuse's challenges it squeezed
//! ([`native_targets`]). It recomputes the scalar-field side's lifts
//! stage, endoscaling its generators by the challenges it squeezed, and
//! that side's digits stage, summing the digits' generators by sign as it
//! scales by them. Its public output is the run commitments, the two
//! recomputations and the nested IPA's $G'$ ([`native_side`]).
//!
//! What both sides share, the paging of the circuit among it, is
//! [`common`](super::common).

use alloc::{sync::Arc, vec, vec::Vec};
use core::{iter::once, marker::PhantomData};

use ragu_circuits::{
    WithAux,
    paging::Pageable,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder, wires_of},
};
use ragu_core::{
    Cycle, Error, FixedGenerators, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, Endoscalar, EndoscalarChallenge, GadgetExt, Point, vec::FixedVec};

use super::{
    common::{
        AbValue, Body, Carried, Cells, Challenge, Exposed, Prepared, Replay, Run, Side,
        SideCircuit, Src, Tables, View, Whole, ab_layout, body, challenges_per_curve, coordinates,
        fuse, native_claims, nested_claims, squeezed,
    },
    gadgets::derive::{self},
    nested::Nested,
    online::input,
    stages::{
        self, DigitsStage, InstanceStage, Layout, LiftsStage, MESSAGE_SCALARS, MessagesStage,
        OnlineInputStage, OnlineQueryStage, StageShape, digits_degrees, lifts_degrees,
        native_scalars, num_runs,
    },
};
use crate::{
    RAGU_TAG,
    compress::{
        instance::{NativeEval, NativePreamble, NativeQuery, OPENED, degrees},
        revdot::{fold::Derived, nested_components, nested_position},
    },
    internal::{
        native::{
            self,
            claims::{KySource as NativeKySource, ky_values as native_ky_values},
            stages::{eval::generator_index, preamble::ProofInputs},
            unified as native_unified,
        },
        nested::{self, stages::challenges as challenge_stage},
    },
    ipa::{IPA_TAG, IpaCycle},
    profile::{PageCount, ProfiledCycle, Standard},
};

/// The circuit-field side's whole circuit: its verifier ([`native_side`])
/// over its stages, for a proof at rank `K` in polynomials of rank `R`.
pub(crate) struct Circuit<'p, C: Cycle, K, R, const HEADER_SIZE: usize> {
    tables: Arc<Tables>,
    params: &'p C::Params,
    _marker: PhantomData<fn() -> (K, R)>,
}

impl<C: Cycle, K, R, const HEADER_SIZE: usize> Clone for Circuit<'_, C, K, R, HEADER_SIZE> {
    fn clone(&self) -> Self {
        Circuit {
            tables: self.tables.clone(),
            params: self.params,
            _marker: PhantomData,
        }
    }
}

impl<'p, C, K, R, const HEADER_SIZE: usize> Circuit<'p, C, K, R, HEADER_SIZE>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    /// The side's whole circuit, laid out by `tables`, the side's
    /// ([`tables`](super::common::tables)).
    pub(crate) fn new(
        tables: Arc<Tables>,
        params: &'p C::Params,
    ) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            tables,
            params,
            _marker: PhantomData,
        })
    }
}

impl<C, K, R, const HEADER_SIZE: usize> MultiStageCircuit<C::CircuitField, R>
    for Circuit<'_, C, K, R, HEADER_SIZE>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    type Last = DigitsStage<C, Native, K, R, HEADER_SIZE>;
    type Instance<'source> = FixedVec<C::NestedCurve, Exposed<C, Native, K>>;
    type Witness<'source> = &'source Prepared<C, Native>;
    type Output =
        Kind![C::CircuitField; FixedVec<Point<'_, _, C::NestedCurve>, Exposed<C, Native, K>>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Point::alloc(dr, instance.as_ref().map(|points| points[i])))
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (online_input, dr) = dr.add_stage::<OnlineInputStage<C, Native, R>>()?;
        let (online_query, dr) = dr.add_stage::<OnlineQueryStage<C, Native, R>>()?;
        let (instance, dr) = dr.add_stage::<InstanceStage<C, Native, K, R, HEADER_SIZE>>()?;
        let (messages, dr) = dr.add_stage::<MessagesStage<C, Native, K, R, HEADER_SIZE>>()?;
        let (lifts, dr) = dr.add_stage::<LiftsStage<C, Native, K, R, HEADER_SIZE>>()?;
        let (digits, dr) = dr.add_stage::<DigitsStage<C, Native, K, R, HEADER_SIZE>>()?;
        let dr = dr.finish();
        let online_input =
            online_input.unenforced(dr, witness.as_ref().map(|w| &w.online_input))?;
        let online_query =
            online_query.unenforced(dr, witness.as_ref().map(|w| &w.online_query))?;
        let instance = instance.unenforced(dr, witness.as_ref().map(|w| &w.instance))?;
        let messages = messages.unenforced(dr, witness.as_ref().map(|w| &w.messages))?;
        let lifts = lifts.unenforced(dr, witness.as_ref().map(|w| &w.lifts))?;
        let digits = digits.unenforced(dr, witness.as_ref().map(|w| &w.digits))?;

        let mut run = Run::new(
            &self.tables,
            View {
                points: &instance.points[..],
                elements: &instance.elements[..],
            },
            View {
                points: &messages.points[..],
                elements: &messages.elements[..],
            },
            [&online_input.elements[..], &online_query.elements[..]],
            Cells::Loaded(&lifts.elements[..]),
            Cells::Loaded(&digits.elements[..]),
            (
                <Native as Side<C>>::generators(self.params),
                <Native as Side<C>>::u(self.params),
                <Native as Side<C>>::poseidon(self.params),
            ),
            witness,
        );
        let exposed = native_side::<_, C, K, HEADER_SIZE>(dr, &mut run)?;
        if exposed.len() != <Native as Side<C>>::exposed::<K>() {
            return Err(Error::InvalidWitness(
                "the side's verifier exposes the side's points".into(),
            ));
        }
        Ok(WithAux::new(FixedVec::try_from(exposed)?, D::unit()))
    }
}

impl<C, K, R, const HEADER_SIZE: usize> Pageable<C::CircuitField, R>
    for Circuit<'_, C, K, R, HEADER_SIZE>
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    type Carry = Carried<C, Native>;
}

/// The circuit-field side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Native;

/// What the circuit-field side's targets derive from: the native
/// unified instance, the output header and the circuit id's domain point.
pub(crate) struct NativeExtra<C: Cycle> {
    pub unified: native_unified::Instance<C>,
    pub output_header: Vec<C::CircuitField>,
    pub omega_j: C::CircuitField,
}

/// The native targets as elements, for
/// [`ky_values`](crate::internal::native::claims::ky_values).
pub(crate) struct NativeTargets<'dr, D: Driver<'dr>> {
    pub c: Element<'dr, D>,
    pub unified_bridge: Element<'dr, D>,
    pub unified: Element<'dr, D>,
    pub one: Element<'dr, D>,
    pub zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> NativeKySource for NativeTargets<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.c.clone())
    }

    fn application_ky(&self) -> impl Iterator<Item = Self::Ky> {
        // A proof folds its own application claim, so its verifier has no
        // application target.
        core::iter::empty()
    }

    fn unified_bridge_ky(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.unified_bridge.clone())
    }

    fn compute_v_bridge_ky(&self) -> impl Iterator<Item = Self::Ky> {
        // The standard profile has no online batch to export for, so the
        // `compute_v` circuit's instance is the unified one.
        once(self.unified.clone())
    }

    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.unified.clone())
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = Self::Ky> {
        // The standard profile has no online batch, so no online helper.
        core::iter::empty()
    }

    fn bind_endoscalar_ky(&self) -> impl Iterator<Item = Self::Ky> {
        // The standard profile has no online batch, so the circuit's
        // instance is the unified one.
        once(self.unified.clone())
    }

    fn ones(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.one.clone())
    }

    fn statement_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        // The compressed proofs decompressed are the standard profile's,
        // which has no statement circuit and so no statement value.
        core::iter::empty()
    }

    fn binding_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        // Nor a binding circuit.
        core::iter::empty()
    }

    fn zero(&self) -> Self::Ky {
        self.zero.clone()
    }
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Side<C> for Native {
    type F = C::CircuitField;
    type Other = C::ScalarField;
    type P = C::NestedCurve;
    type Q = C::HostCurve;
    type Poseidon = C::CircuitPoseidon;
    type Extra = NativeExtra<C>;

    #[cfg(test)]
    const NAME: &'static str = "circuit-field";

    const ONLINE: super::online::Values = super::online::Values::NATIVE;
    const PAGES: PageCount = super::aggregator::NATIVE_PAGES;
    /// The scalar-field side has no flag for this side to take.
    const FLAGS: usize = 0;

    /// The scalar-field side's run stages, then its lifts and digits
    /// stages, then the commitment of the nested IPA's $s(X)$ in the
    /// nested batch of the step that proves the side.
    fn exposed<K: Rank>() -> usize {
        num_runs::<K>() + 3
    }

    fn front_shapes<K: Rank, const HEADER_SIZE: usize>() -> Vec<StageShape> {
        let layout = <Self as Side<C>>::layout::<K, HEADER_SIZE>();
        alloc::vec![layout.instance_shape(), layout.messages_shape()]
    }

    fn generators(params: &C::Params) -> &[Self::P] {
        C::nested_generators(params).g()
    }

    fn u(params: &C::Params) -> Self::P {
        *C::nested_u(params)
    }

    fn poseidon(params: &C::Params) -> &Self::Poseidon {
        C::circuit_poseidon(params)
    }

    fn layout<K: Rank, const HEADER_SIZE: usize>() -> Layout {
        Layout::native::<C::CircuitField, K, HEADER_SIZE>()
    }

    fn tables<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Tables> {
        native_tables::<C, K, R, HEADER_SIZE>()
    }

    fn verify<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        run: &mut Run<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Point<'dr, D, Self::P>>> {
        native_side::<_, C, K, HEADER_SIZE>(dr, run)
    }
}

impl<C, K, R, const HEADER_SIZE: usize> SideCircuit<C, K, R, HEADER_SIZE> for Native
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
{
    type Circuit<'p> = Circuit<'p, C, K, R, HEADER_SIZE>;

    fn circuit(tables: Arc<Tables>, params: &C::Params) -> Whole<'_, C, Self, K, R, HEADER_SIZE> {
        Circuit::new(tables, params)
    }
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

/// A step of one curve's part of the compression's transcript.
#[derive(Clone, Copy)]
enum Message {
    /// The curve's point message at an index of
    /// [`message_points`](mod@stages::message_points).
    Point(usize),
    /// Its scalar message at an index of
    /// [`MessageScalars`](stages::MessageScalars).
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
