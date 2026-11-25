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
//! circuit-field side replays the transcripts, absorbing the other field's
//! values as the commitments of their runs, which it holds to the
//! scalar-field side's run stages; the scalar-field side takes its
//! challenges from their bits and derives its targets from the nested
//! unified instance.
//!
//! The prover's half of a side, what it reads off a compressed proof to
//! fill the side's stages, is [`Prepare`](super::prover::Prepare).

use alloc::vec::Vec;
use core::iter::once;

use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Cycle, FixedGenerators, PoseidonPermutation, Result,
    drivers::Driver,
    gadgets::{Bound, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, io::Write};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    circuits::Ctx,
    program::{self, Schedule, squeezed},
    stages::{Layout, StageShape, native_scalars, nested_front, nested_scalars, num_runs},
};
use crate::{
    compress::revdot::{native_components, native_position, nested_components, nested_position},
    internal::{
        native::{
            self,
            claims::{KySource as NativeKySource, ky_values as native_ky_values},
            stages::preamble::ProofInputs,
            unified as native_unified,
        },
        nested::{
            self,
            claims::{KySource as NestedKySource, ky_values as nested_ky_values},
            unified as nested_unified,
        },
    },
    ipa::IpaCycle,
    profile::{ProfiledCycle, Standard},
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
    /// and what else the targets derive from.
    type Extra: Send + Sync;
    /// The chunk circuits' public output: nothing, on either side, since a
    /// chunk carries no instance. The slot a chunk is registered through
    /// appends the zero that keeps it from standing in for an application
    /// circuit (see [`CircuitSlot::register`](crate::profile::CircuitSlot::register)).
    type Output: GadgetKind<Self::F> + Write<Self::F>;

    #[cfg(test)]
    const NAME: &'static str;

    /// The wires of the aggregator's online stages of the side's field,
    /// which every circuit of the side loads first: the wallet registry's
    /// evaluations the side's chunks read are their query stage's values.
    const ONLINE: super::online::Values;
    /// How many flags the side takes from the other side, whose digits
    /// follow the foreign scalars' in that side's digits stage.
    const FLAGS: usize;
    /// The points the side's binding circuit exposes for a proof at rank
    /// `K`: the other side's stage commitments it absorbed or recomputed,
    /// in the order the profile's [`Binding`](crate::profile::Binding)
    /// names the stages.
    fn exposed<K: Rank>() -> usize;
    /// The shapes of the side's front stages, in chain order (see
    /// [`Front`](super::stages::Front)).
    fn front_shapes<K: Rank, const HEADER_SIZE: usize>() -> Vec<StageShape>;

    /// The fixed generators of `P`.
    fn generators(params: &C::Params) -> &[Self::P];
    /// The IPA's $U$ on `P`.
    fn u(params: &C::Params) -> Self::P;
    fn poseidon(params: &C::Params) -> &Self::Poseidon;
    /// The side's stage layout for a proof at rank `K`.
    fn layout<K: Rank, const HEADER_SIZE: usize>() -> Layout;
    /// The side's chunk schedule for a proof at rank `K`, cut for chunk
    /// circuits at rank `R`.
    fn schedule<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule>;
    /// The side's schedule for its sizes alone, which the stages' lengths
    /// take (see [`Foreign`](program::Foreign)).
    fn sizes<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule>;
    /// The chunk circuits' public output.
    fn output<'dr, D: Driver<'dr, F = Self::F>>(dr: &mut D) -> Bound<'dr, D, Self::Output>;
    /// The targets chunk: allocates the side's unified instance, binds it
    /// to the stages and returns the claims' base targets in the
    /// schedule's [`Regions::targets`](program::Regions::targets) order.
    fn targets<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
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
/// unified instance, the output header and the circuit id's domain point.
pub(crate) struct NativeExtra<C: Cycle> {
    pub unified: native_unified::Instance<C>,
    pub output_header: Vec<C::CircuitField>,
    pub omega_j: C::CircuitField,
}

/// What the scalar-field side's targets chunk allocates: the nested
/// unified instance.
pub(crate) struct NestedExtra<C: Cycle> {
    pub unified: nested_unified::Instance<C::HostCurve>,
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
        // The standard profile exports no online Fq commitment and has no
        // online batch, so the circuit's instance is the unified one.
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

/// The nested targets as elements.
pub(crate) struct NestedTargets<'dr, D: Driver<'dr>> {
    pub c: Element<'dr, D>,
    pub unified: Element<'dr, D>,
    pub one: Element<'dr, D>,
    pub zero: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> NestedKySource for NestedTargets<'dr, D> {
    type Ky = Element<'dr, D>;

    fn raw_c(&self) -> impl Iterator<Item = Self::Ky> {
        once(self.c.clone())
    }

    fn ones(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.one.clone())
    }

    fn unified_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        once(self.unified.clone())
    }

    fn compute_v_ky(&self) -> impl Iterator<Item = Self::Ky> {
        // The standard profile exports no online Fq opening and has no
        // online batch, so the circuit's instance is the unified one.
        once(self.unified.clone())
    }

    fn online_helper_ky(&self) -> impl Iterator<Item = Self::Ky> {
        // Nor an online helper.
        core::iter::empty()
    }

    fn binding_ky(&self) -> impl Iterator<Item = Self::Ky> + Clone {
        // The standard profile's nested extension has no binding circuit.
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
    type Output = Kind![C::CircuitField; ()];

    #[cfg(test)]
    const NAME: &'static str = "circuit-field";

    const ONLINE: super::online::Values = super::online::Values::NATIVE;
    /// The scalar-field side has no flag for this side to take.
    const FLAGS: usize = 0;

    /// The scalar-field side's run stages, then its lifts and digits
    /// stages, then the commitment of the nested IPA's $s(X)$ in the
    /// nested batch of the step that proves the chunks.
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

    fn schedule<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule> {
        program::native_schedule::<C, K, R, HEADER_SIZE>()
    }

    fn sizes<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule> {
        program::native_sizes::<C, K, R, HEADER_SIZE>()
    }

    fn output<'dr, D: Driver<'dr, F = Self::F>>(_: &mut D) -> Bound<'dr, D, Self::Output> {}

    fn targets<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Element<'dr, D>>> {
        let witness = &ctx.witness;
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
            &unified.mu_prime,
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
        for (position, theirs) in layout
            .output_header
            .positions()
            .zip(inputs.output_header.iter())
        {
            elements[position].enforce_equal(dr, theirs)?;
        }
        // The proof folded its own application claim, so its verifier has
        // no application target: the `hashes_1` claim's, over the unified
        // instance, the output header and the circuit id, and the unified
        // one, which the standard profile's `compute_v` claim takes too,
        // having no online batch to export for.
        let y = ctx.lift(regions.lifts[squeezed::Y]);
        let (unified, bridge) = inputs.unified_ky_values(dr, &y)?;
        Ok(alloc::vec![bridge, unified])
    }

    fn ky_targets<'dr, D: Driver<'dr, F = Self::F>>(
        dr: &mut D,
        ctx: &Ctx<'_, '_, 'dr, D, C, Self>,
    ) -> Vec<Element<'dr, D>> {
        let layout = ctx.schedule.layout.instance;
        let regions = &ctx.schedule.regions;
        let targets = NativeTargets {
            c: ctx.loaded.instance.elements[layout.scalars.at(native_scalars::C)].clone(),
            unified_bridge: ctx.work(regions.targets[0]),
            unified: ctx.work(regions.targets[1]),
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

    #[cfg(test)]
    const NAME: &'static str = "scalar-field";

    const ONLINE: super::online::Values = super::online::Values::NESTED;
    /// The decompression flag, which the circuit-field side's statement
    /// circuit binds.
    const FLAGS: usize = 1;

    /// The other side's digits stage, the two application output
    /// commitments and the host IPA helper's native batch commitment.
    fn exposed<K: Rank>() -> usize {
        2 + crate::header::NUM_ONLINE_FP_POLYS
    }

    fn front_shapes<K: Rank, const HEADER_SIZE: usize>() -> Vec<StageShape> {
        let layout = <Self as Side<C>>::layout::<K, HEADER_SIZE>();
        nested_front::<K>(&layout)
            .iter()
            .map(|source| source.shape())
            .collect()
    }

    fn generators(params: &C::Params) -> &[Self::P] {
        C::host_generators(params).g()
    }

    fn u(params: &C::Params) -> Self::P {
        *C::host_u(params)
    }

    fn poseidon(params: &C::Params) -> &Self::Poseidon {
        C::scalar_poseidon(params)
    }

    fn layout<K: Rank, const HEADER_SIZE: usize>() -> Layout {
        Layout::nested::<C::ScalarField, Standard, K>()
    }

    fn schedule<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule> {
        program::nested_schedule::<C, K, R, HEADER_SIZE>()
    }

    fn sizes<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Schedule> {
        program::nested_sizes::<C, K, R, HEADER_SIZE>()
    }

    fn output<'dr, D: Driver<'dr, F = Self::F>>(_: &mut D) -> Bound<'dr, D, Self::Output> {}

    fn targets<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
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
            ours.enforce_equal(dr, &ctx.lift(*slot))?;
        }
        output
            .c
            .enforce_equal(dr, &elements[layout.scalars.at(nested_scalars::C)])?;
        output
            .v
            .enforce_equal(dr, &elements[layout.scalars.at(nested_scalars::V)])?;
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
            points[layout.commitments.at(*position)].enforce_equal(dr, theirs)?;
        }
        let y = ctx.lift(regions.lifts[squeezed::Y]);
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
