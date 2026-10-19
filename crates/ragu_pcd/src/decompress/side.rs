//! The two sides of the decompression proof behind one interface, so that
//! the stages, the chunk schedule, the chunk executor and the chunk
//! circuits are written once.
//!
//! A side runs in one field of the cycle over the points of the curve
//! whose base field it is: the circuit-field side ([`Native`]) in the
//! circuit field over the nested curve, the scalar-field side ([`Nested`])
//! in the scalar field over the host curve. Each side does the native
//! verifier's arithmetic in its field, the scalar checks of the other
//! curve's reduction and the point checks of its own curve's, so the two
//! sides are mirror images up to how they obtain their inputs: the
//! circuit-field side replays the transcripts and holds the other field's
//! values through bridges, the scalar-field side takes its challenges from
//! their bits and derives its targets from the nested unified instance.

use alloc::vec::Vec;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Cycle, FixedGenerators, PoseidonPermutation, Result,
    drivers::Driver,
    gadgets::{Bound, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, WithSuffix, io::Write};
use udon::{
    curve::{Affine as _, EndomorphismAffine as Affine},
    field::Field,
};

use super::{
    circuit::{AbValue, NativeTargets, NestedTargets, SideWitness, Witness},
    program::{self, Schedule, squeezed},
    run::Ctx,
    stages::{
        self, Layout, Values, bridge, bridge_point, message_points_of, message_scalars,
        native_scalars, nested_scalars,
    },
};
use crate::{
    CompressedProof,
    compress::{
        Messages,
        instance::Instance,
        revdot::{native_components, native_position, nested_components, nested_position},
    },
    internal::{
        native::{
            self, claims::ky_values as native_ky_values, stages::preamble::ProofInputs,
            unified as native_unified,
        },
        nested::{self, claims::ky_values as nested_ky_values, unified as nested_unified},
    },
    ipa::IpaCycle,
    profile::{ProfiledCycle, Standard},
    proof::bridge_alpha_power,
};

/// One side of the decompression proof.
pub(crate) trait Side<C: Cycle>: Copy + Default + Send + Sync + 'static {
    /// The side's field: the one its circuits are over.
    type F: Field;
    /// The other field of the cycle.
    type Other: Field;
    /// The curve whose points the side holds: its base field is `F`.
    type P: Affine<Base = Self::F, Scalar = Self::Other>;
    /// The curve whose reduction the side checks in its field: its scalar
    /// field is `F`.
    type Q: Affine<Base = Self::Other, Scalar = Self::F>;
    /// The Poseidon permutation over `F`.
    type Poseidon: PoseidonPermutation<Self::F>;
    /// What the side's chunks need beyond the stages: its unified instance
    /// and the headers the targets derive from.
    type Extra: Send + Sync;
    /// The chunk circuits' public output: what the side's internal
    /// circuits carry.
    type Output: GadgetKind<Self::F> + Write<Self::F>;

    const NAME: &'static str;

    /// The fixed generators of `P`.
    fn generators(params: &C::Params) -> &[Self::P];
    /// The IPA's $U$ on `P`.
    fn u(params: &C::Params) -> Self::P;
    fn poseidon(params: &C::Params) -> &Self::Poseidon;
    fn layout<R: Rank, const HEADER_SIZE: usize>() -> Layout;
    /// The side's chunk schedule.
    fn schedule<R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule>;
    /// The instance stage's values.
    fn instance(
        params: &C::Params,
        instance: &Instance<C>,
        output_header: &[C::CircuitField],
    ) -> Values<Self::F, Self::P>;
    /// The messages stage's values.
    fn messages(params: &C::Params, proof: &CompressedProof<C>) -> Values<Self::F, Self::P>;
    /// The transcript stage's points, the bridges; its elements, the sponge
    /// states, the prover's run fills.
    fn transcript(
        params: &C::Params,
        instance: &Instance<C>,
        proof: &CompressedProof<C>,
    ) -> Values<Self::F, Self::P>;
    /// The witness of the reduction the side checks in its field.
    fn own(witness: &Witness<C>) -> &SideWitness<Self::Q>;
    /// The witness of the reduction whose points the side checks.
    fn other(witness: &Witness<C>) -> &SideWitness<Self::P>;
    /// The messages of the reduction whose points the side checks.
    fn other_messages(proof: &CompressedProof<C>) -> &Messages<Self::P>;
    /// The other field's full-width scalars the side scales by, in the
    /// schedule's [`ScalarRef::Bits`](program::ScalarRef::Bits) order.
    fn foreign(witness: &Witness<C>, schedule: &Schedule) -> Result<Vec<Self::Other>>;
    fn extra(witness: &Witness<C>) -> Result<Self::Extra>;
    /// The chunk circuits' public output.
    fn output<'dr, D: Driver<'dr, F = Self::F>>(dr: &mut D) -> Bound<'dr, D, Self::Output>;
    /// The targets chunk: allocates the side's unified instance, binds it
    /// to the stages and returns the claims' base targets in the
    /// schedule's [`Regions::targets`](program::Regions::targets) order.
    fn targets<'dr, D: Driver<'dr, F = Self::F>, R: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Element<'dr, D>>>;
    /// Every claim's target in claim order, from the targets chunk's
    /// outputs.
    fn ky_targets<'dr, D: Driver<'dr, F = Self::F>>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Vec<Element<'dr, D>>;
}

/// The circuit-field side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Native;

/// The scalar-field side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Nested;

/// What the circuit-field side's targets chunk allocates: the native
/// unified instance, the headers and the circuit id's domain point.
pub(crate) struct NativeExtra<C: Cycle> {
    pub unified: native_unified::Instance<C>,
    pub left_header: Vec<C::CircuitField>,
    pub right_header: Vec<C::CircuitField>,
    pub output_header: Vec<C::CircuitField>,
    pub omega_j: C::CircuitField,
}

/// What the scalar-field side's targets chunk allocates: the nested
/// unified instance.
pub(crate) struct NestedExtra<C: Cycle> {
    pub unified: nested_unified::Instance<C::HostCurve>,
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Side<C> for Native {
    type F = C::CircuitField;
    type Other = C::ScalarField;
    type P = C::NestedCurve;
    type Q = C::HostCurve;
    type Poseidon = C::CircuitPoseidon;
    type Extra = NativeExtra<C>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, ()>];

    const NAME: &'static str = "circuit-field";

    fn generators(params: &C::Params) -> &[Self::P] {
        C::nested_generators(params).g()
    }

    fn u(params: &C::Params) -> Self::P {
        *C::nested_u(params)
    }

    fn poseidon(params: &C::Params) -> &Self::Poseidon {
        C::circuit_poseidon(params)
    }

    fn layout<R: Rank, const HEADER_SIZE: usize>() -> Layout {
        Layout::native::<R, HEADER_SIZE>()
    }

    fn schedule<R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule> {
        program::native_schedule::<C, R, HEADER_SIZE>()
    }

    fn instance(
        _: &C::Params,
        instance: &Instance<C>,
        output_header: &[C::CircuitField],
    ) -> Values<Self::F, Self::P> {
        let mut points = instance.nested.clone();
        points.extend([
            instance.nested_registry_xy,
            instance.nested_p,
            instance.nested_challenges_partial,
        ]);
        let (l, r) = (instance.left, instance.right);
        let mut elements = alloc::vec![
            instance.circuit_id.omega_j(),
            instance.c,
            instance.v,
            l.x,
            l.y,
            l.id,
            r.x,
            r.y,
            r.id,
            instance.a_at_u,
            instance.b_at_u,
        ];
        elements.extend_from_slice(&instance.left_header);
        elements.extend_from_slice(&instance.right_header);
        elements.extend_from_slice(output_header);
        Values { points, elements }
    }

    fn messages(_: &C::Params, proof: &CompressedProof<C>) -> Values<Self::F, Self::P> {
        Values {
            points: message_points_of(&proof.nested),
            elements: message_scalars(&proof.native),
        }
    }

    fn transcript(
        params: &C::Params,
        instance: &Instance<C>,
        proof: &CompressedProof<C>,
    ) -> Values<Self::F, Self::P> {
        let mut points: Vec<C::NestedCurve> = instance
            .native
            .iter()
            .copied()
            .chain([instance.native_registry_xy, instance.native_p])
            .map(|point| bridge_point::<C>(params, point))
            .collect();
        points.extend(
            Nested::instance(params, instance, &[])
                .elements
                .into_iter()
                .map(|value| bridge::<C>(params, &[value])),
        );
        points.extend(
            message_points_of(&proof.native)
                .into_iter()
                .map(|point| bridge_point::<C>(params, point)),
        );
        points.extend(
            message_scalars(&proof.nested)
                .into_iter()
                .map(|value| bridge::<C>(params, &[value])),
        );
        Values {
            points,
            elements: Vec::new(),
        }
    }

    fn own(witness: &Witness<C>) -> &SideWitness<Self::Q> {
        &witness.native
    }

    fn other(witness: &Witness<C>) -> &SideWitness<Self::P> {
        &witness.nested
    }

    fn other_messages(proof: &CompressedProof<C>) -> &Messages<Self::P> {
        &proof.nested
    }

    fn foreign(witness: &Witness<C>, schedule: &Schedule) -> Result<Vec<Self::Other>> {
        let instance = &witness.proof.instance;
        let other = Self::other(witness);
        let mut foreign = alloc::vec![other.v, witness.proof.nested.opening.c, other.cbz];
        let coordinates = |point: C::HostCurve| -> Result<[C::ScalarField; 2]> {
            let (x, y) = point.coordinates().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("a commitment is the identity".into())
            })?;
            Ok([x, y])
        };
        let a = coordinates(instance.native_commitment(native::RxComponent::AbA))?;
        let b = coordinates(instance.native_commitment(native::RxComponent::AbB))?;
        let points_ab = coordinates(
            instance.native_commitment(native::RxComponent::Rx(native::RxIndex::PointsAb)),
        )?;
        let alpha = bridge_alpha_power(instance.bridge_alpha, nested::RxIndex::BridgeAB);
        foreign.extend(schedule.ab_terms.iter().map(|&(_, which)| match which {
            AbValue::A(i) => a[i],
            AbValue::B(i) => b[i],
            AbValue::PointsAb(i) => points_ab[i],
            AbValue::Alpha => alpha,
        }));
        Ok(foreign)
    }

    fn extra(witness: &Witness<C>) -> Result<Self::Extra> {
        let instance = &witness.proof.instance;
        Ok(NativeExtra {
            unified: instance.unified(&witness.fuse),
            left_header: instance.left_header.clone(),
            right_header: instance.right_header.clone(),
            output_header: witness.header.clone(),
            omega_j: instance.circuit_id.omega_j(),
        })
    }

    fn output<'dr, D: Driver<'dr, F = Self::F>>(dr: &mut D) -> Bound<'dr, D, Self::Output> {
        WithSuffix::new((), Element::zero(dr))
    }

    fn targets<'dr, D: Driver<'dr, F = Self::F>, R: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Element<'dr, D>>> {
        let witness = &ctx.witness;
        let inputs = ProofInputs::<D, C, HEADER_SIZE>::alloc_from_parts(
            dr,
            witness.as_ref().map(|w| w.extra.left_header.as_slice()),
            witness.as_ref().map(|w| w.extra.right_header.as_slice()),
            witness.as_ref().map(|w| w.extra.output_header.as_slice()),
            witness.as_ref().map(|w| w.extra.omega_j),
            witness.as_ref().map(|w| &w.extra.unified),
        )?;
        let layout = ctx.schedule.layout.instance;
        let regions = &ctx.schedule.regions;
        let points = ctx.loaded.instance.points;
        let elements = ctx.loaded.instance.elements;
        let commitment = |component| {
            &points[layout
                .commitments
                .at(nested_position::<Standard>(component))]
        };
        let bridge = |index| commitment(nested::RxComponent::Rx(index));
        let listed = nested_components::<Standard>().count();
        let unified = &inputs.unified;
        {
            use nested::RxIndex::*;
            for (ours, theirs) in [
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
                    &points[layout.commitments.at(listed + 2)],
                    &unified.nested_challenges_partial,
                ),
                (
                    &points[layout.commitments.at(listed + 1)],
                    &unified.nested_p_commitment,
                ),
                (
                    commitment(nested::RxComponent::AbA),
                    &unified.nested_a_commitment,
                ),
                (
                    commitment(nested::RxComponent::AbB),
                    &unified.nested_b_commitment,
                ),
                (
                    &points[layout.commitments.at(listed)],
                    &unified.nested_registry_xy_commitment,
                ),
            ] {
                ours.enforce_equal(dr, theirs)?;
            }
        }
        for (slot, theirs) in regions.fuse.iter().zip([
            &unified.w,
            &unified.y,
            &unified.z,
            &unified.mu,
            &unified.nu,
            &unified.mu_prime,
            &unified.nu_prime,
            &unified.x,
            &unified.alpha,
            &unified.u,
            &unified.pre_beta,
        ]) {
            ctx.work(*slot).enforce_equal(dr, theirs)?;
        }
        elements[layout.scalars.at(native_scalars::C)].enforce_equal(dr, &unified.c)?;
        elements[layout.scalars.at(native_scalars::V)].enforce_equal(dr, &unified.v)?;
        elements[layout.scalars.at(native_scalars::OMEGA_J)]
            .enforce_equal(dr, &inputs.circuit_id)?;
        for (span, theirs) in [
            (layout.left_header, inputs.children.left.iter()),
            (layout.right_header, inputs.children.right.iter()),
            (layout.output_header, inputs.output_header.iter()),
        ] {
            for (position, theirs) in span.positions().zip(theirs) {
                elements[position].enforce_equal(dr, theirs)?;
            }
        }
        let y = ctx.work(regions.lifts[squeezed::Y]);
        let (unified, bridge) = inputs.unified_ky_values(dr, &y)?;
        let application = inputs.application_ky(dr, &y)?;
        Ok(alloc::vec![application, bridge, unified])
    }

    fn ky_targets<'dr, D: Driver<'dr, F = Self::F>>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Vec<Element<'dr, D>> {
        let layout = ctx.schedule.layout.instance;
        let regions = &ctx.schedule.regions;
        let targets = NativeTargets {
            c: ctx.loaded.instance.elements[layout.scalars.at(native_scalars::C)].clone(),
            application: ctx.work(regions.targets[0]),
            unified_bridge: ctx.work(regions.targets[1]),
            unified: ctx.work(regions.targets[2]),
            one: Element::one(),
            zero: Element::zero(dr),
        };
        native_ky_values::<Standard, _>(&targets)
            .take(ctx.schedule.claims.len())
            .collect()
    }
}

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Side<C> for Nested {
    type F = C::ScalarField;
    type Other = C::CircuitField;
    type P = C::HostCurve;
    type Q = C::NestedCurve;
    type Poseidon = C::ScalarPoseidon;
    type Extra = NestedExtra<C>;
    type Output = Kind![C::ScalarField; ()];

    const NAME: &'static str = "scalar-field";

    fn generators(params: &C::Params) -> &[Self::P] {
        C::host_generators(params).g()
    }

    fn u(params: &C::Params) -> Self::P {
        *C::host_u(params)
    }

    fn poseidon(params: &C::Params) -> &Self::Poseidon {
        C::scalar_poseidon(params)
    }

    fn layout<R: Rank, const HEADER_SIZE: usize>() -> Layout {
        Layout::nested::<R>()
    }

    fn schedule<R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule> {
        program::nested_schedule::<C, R, HEADER_SIZE>()
    }

    fn instance(
        _: &C::Params,
        instance: &Instance<C>,
        _: &[C::CircuitField],
    ) -> Values<Self::F, Self::P> {
        let mut points = instance.native.clone();
        points.extend([instance.native_registry_xy, instance.native_p]);
        let (l, r) = (instance.nested_left, instance.nested_right);
        let elements = alloc::vec![
            instance.bridge_alpha,
            instance.nested_c,
            instance.nested_v,
            l.x,
            l.y,
            r.x,
            r.y,
            instance.nested_a_at_u,
            instance.nested_b_at_u,
        ];
        assert_eq!(elements.len(), stages::NESTED_SCALARS);
        Values { points, elements }
    }

    fn messages(_: &C::Params, proof: &CompressedProof<C>) -> Values<Self::F, Self::P> {
        Values {
            points: message_points_of(&proof.native),
            elements: message_scalars(&proof.nested),
        }
    }

    fn transcript(
        _: &C::Params,
        _: &Instance<C>,
        _: &CompressedProof<C>,
    ) -> Values<Self::F, Self::P> {
        Values {
            points: Vec::new(),
            elements: Vec::new(),
        }
    }

    fn own(witness: &Witness<C>) -> &SideWitness<Self::Q> {
        &witness.nested
    }

    fn other(witness: &Witness<C>) -> &SideWitness<Self::P> {
        &witness.native
    }

    fn other_messages(proof: &CompressedProof<C>) -> &Messages<Self::P> {
        &proof.native
    }

    fn foreign(witness: &Witness<C>, _: &Schedule) -> Result<Vec<Self::Other>> {
        let other = Self::other(witness);
        Ok(alloc::vec![
            other.v,
            witness.proof.native.opening.c,
            other.cbz
        ])
    }

    fn extra(witness: &Witness<C>) -> Result<Self::Extra> {
        Ok(NestedExtra {
            unified: witness.proof.instance.nested_unified(&witness.fuse)?,
        })
    }

    fn output<'dr, D: Driver<'dr, F = Self::F>>(_: &mut D) -> Bound<'dr, D, Self::Output> {}

    fn targets<'dr, D: Driver<'dr, F = Self::F>, R: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Element<'dr, D>>> {
        let output = nested_unified::Output::<D, C::HostCurve>::alloc(
            dr,
            &mut (),
            ctx.witness.as_ref().map(|w| &w.extra.unified),
        )?;
        let layout = ctx.schedule.layout.instance;
        let regions = &ctx.schedule.regions;
        let points = ctx.loaded.instance.points;
        let elements = ctx.loaded.instance.elements;
        for (slot, ours) in regions
            .fuse_lifts
            .iter()
            .zip([&output.x, &output.y, &output.u])
        {
            ours.enforce_equal(dr, &ctx.work(*slot))?;
        }
        output
            .c
            .enforce_equal(dr, &elements[layout.scalars.at(nested_scalars::C)])?;
        output
            .v
            .enforce_equal(dr, &elements[layout.scalars.at(nested_scalars::V)])?;
        let listed = native_components::<Standard>().count();
        let exported = {
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
                native_position::<Standard>(Rx(PointsChildren)),
                native_position::<Standard>(Rx(PointsRegistryWx)),
                native_position::<Standard>(Rx(PointsAb)),
                native_position::<Standard>(Rx(PointsF)),
            ]
        };
        for (position, theirs) in exported.iter().zip(output.exported.iter()) {
            points[layout.commitments.at(*position)].enforce_equal(dr, theirs)?;
        }
        let y = ctx.work(regions.lifts[squeezed::Y]);
        Ok(alloc::vec![output.ky(dr, &y)?])
    }

    fn ky_targets<'dr, D: Driver<'dr, F = Self::F>>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Vec<Element<'dr, D>> {
        let layout = ctx.schedule.layout.instance;
        let regions = &ctx.schedule.regions;
        let targets = NestedTargets {
            c: ctx.loaded.instance.elements[layout.scalars.at(nested_scalars::C)].clone(),
            unified: ctx.work(regions.targets[0]),
            one: Element::one(),
            zero: Element::zero(dr),
        };
        nested_ky_values::<Standard, _>(&targets)
            .take(ctx.schedule.claims.len())
            .collect()
    }
}
