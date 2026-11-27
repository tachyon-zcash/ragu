//! The scalar-field side of the decompression ([`Nested`]): the
//! compressed proof's verifier in the scalar field, over the host curve,
//! as one circuit ([`Circuit`]) that the pager cuts into the pages of the
//! aggregator profile's nested extension
//! ([`NESTED_PAGES`](crate::profile::Aggregator::NESTED_PAGES)).
//!
//! The side checks the nested reduction's scalars in its field and the
//! native reduction's points on its curve ([`nested_tables`]). It squeezes
//! no challenge: it takes each from its bits, and every read holds the
//! bits' lift to the challenge's slot of the lifts stage. It binds the
//! nested unified instance to the instance stage and to the lifts of the
//! fuse's challenges ([`nested_targets`](circuit::nested_targets)), and
//! recomputes the circuit-field side's digits stage, summing the digits'
//! generators by sign as it scales by them. Its public output is that
//! recomputation, the two application output commitments and the
//! commitment of the host IPA's $s(X)$ in the native batch of the step
//! that proves the side ([`Circuit`]), then the zero every extension
//! circuit's output ends with.
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
pub(crate) use stages::Runs;
use stages::nested_front;

use super::{
    common::{Side, SideCircuit, Tables, Whole, ab_layout, native_claims, nested_claims},
    native::Native,
    stages::{Layout, StageShape, digits_degrees},
};
use crate::{
    compress::instance::{NestedEval, NestedPreamble, NestedQuery, degrees},
    internal::nested::{claims::KySource as NestedKySource, unified as nested_unified},
    ipa::IpaCycle,
    profile::{PageCount, ProfiledCycle, Standard},
};

/// The scalar-field side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Nested;

/// What the scalar-field side's targets derive from: the nested
/// unified instance.
pub(crate) struct NestedExtra<C: Cycle> {
    pub unified: nested_unified::Instance<C::HostCurve>,
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
        // The standard profile has no online batch, so the circuit's
        // instance is the unified one.
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

impl<C: IpaCycle + ProfiledCycle<Profile = Standard>> Side<C> for Nested {
    type F = C::ScalarField;
    type Other = C::CircuitField;
    type P = C::HostCurve;
    type Q = C::NestedCurve;
    type Poseidon = C::ScalarPoseidon;
    type Extra = NestedExtra<C>;

    #[cfg(test)]
    const NAME: &'static str = "scalar-field";

    const ONLINE: super::online::Values = super::online::Values::NESTED;
    const PAGES: PageCount = super::aggregator::NESTED_PAGES;
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

    fn tables<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Tables> {
        nested_tables::<C, K, R, HEADER_SIZE>()
    }
}

impl<C, K, R, const HEADER_SIZE: usize> SideCircuit<C, K, R, HEADER_SIZE> for Nested
where
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Runs,
    R: Rank,
{
    type Circuit<'p> = Circuit<'p, C, K, R, HEADER_SIZE>;

    fn circuit(tables: Arc<Tables>, params: &C::Params) -> Whole<'_, C, Self, K, R, HEADER_SIZE> {
        Circuit::new(tables, params)
    }
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

/// The scalar-field side's tables, as
/// [`native_tables`](super::native::native_tables).
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
