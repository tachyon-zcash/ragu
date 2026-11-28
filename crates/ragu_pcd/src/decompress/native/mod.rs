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
//! ([`native_targets`](circuit::native_targets)). It recomputes the
//! scalar-field side's lifts stage, endoscaling its generators by the
//! challenges it squeezed, and
//! that side's digits stage, summing the digits' generators by sign as it
//! scales by them. Its public output is the run commitments, the two
//! recomputations and the nested IPA's $G'$ ([`Circuit`]), then the
//! zero every extension circuit's output ends with.
//!
//! The side's whole circuit, its verifier among it, is [`circuit`]; the
//! stages that open its chain, [`stages`]. This module holds what the side
//! is configured by: its [`Side`] and [`SideCircuit`] impls and the tables
//! its verifier is laid out by. What both sides share, the paging of the
//! circuit among it, is [`common`](super::common).

pub(crate) mod circuit;
pub(crate) mod stages;

use alloc::{sync::Arc, vec::Vec};
use core::iter::once;

pub(crate) use circuit::Circuit;
use ragu_circuits::{polynomials::Rank, staging::wires_of};
use ragu_core::{Cycle, FixedGenerators, Result, drivers::Driver};
use ragu_primitives::Element;

use super::{
    common::{Side, SideCircuit, Tables, Whole, ab_layout, native_claims, nested_claims},
    nested::Nested,
    stages::{Layout, StageShape, digits_degrees, lifts_degrees, num_runs},
};
use crate::{
    compress::instance::{NativeEval, NativePreamble, NativeQuery, degrees},
    internal::native::{self, claims::KySource as NativeKySource, unified as native_unified},
    ipa::IpaCycle,
    profile::{PageCount, ProfiledCycle, Standard},
};

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
