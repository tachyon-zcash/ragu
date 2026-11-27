//! The two sides of the decompression proof behind one interface, so that
//! the stages, the verifier's shared part and the whole circuit are
//! written once.
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
use ragu_core::{Cycle, FixedGenerators, PoseidonPermutation, Result, drivers::Driver};
use ragu_primitives::{Element, Point};
use udon::{curve::EndomorphismAffine as Affine, field::Field};

use super::{
    stages::{Layout, StageShape, nested_front, num_runs},
    verifier::{self, Run, Tables},
};
use crate::{
    internal::{
        native::{claims::KySource as NativeKySource, unified as native_unified},
        nested::{claims::KySource as NestedKySource, unified as nested_unified},
    },
    ipa::IpaCycle,
    profile::{PageCount, ProfiledCycle, Standard},
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
    /// What the side's verifier needs beyond the stages: its unified
    /// instance and what else the targets derive from.
    type Extra: Send + Sync;

    #[cfg(test)]
    const NAME: &'static str;

    /// The wires of the aggregator's online stages of the side's field,
    /// which every circuit of the side loads first: the wallet registry's
    /// evaluations the side's verifier reads are their query stage's values.
    const ONLINE: super::online::Values;
    /// How many flags the side takes from the other side, whose digits
    /// follow the foreign scalars' in that side's digits stage.
    const FLAGS: usize;
    /// What the aggregator profile pins for the side's whole circuit
    /// ([`WholeCircuit`](super::whole::WholeCircuit)): the pages it is cut
    /// into and the values its carry stage holds.
    const PAGES: PageCount;
    /// The points the side's whole circuit exposes for a proof at rank
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
    /// What the side's verifier is laid out by beside its stage layout,
    /// for a proof at rank `K` in a circuit at rank `R`.
    ///
    /// # Errors
    ///
    /// Fails if the claims cannot be enumerated or a stage's wires cannot
    /// be read off its layout.
    fn tables<K: Rank, R: Rank, const HEADER_SIZE: usize>() -> Result<Tables>;
    /// The side's verifier for a proof at rank `K`, run over `run`'s
    /// stages: returns the points the side exposes, in the order the
    /// profile's [`Binding`](crate::profile::Binding) names what they hold
    /// to.
    ///
    /// # Errors
    ///
    /// Fails if a gadget does, or if the witness is not the side's.
    fn verify<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        run: &mut Run<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Point<'dr, D, Self::P>>>;
}

/// The circuit-field side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Native;

/// The scalar-field side.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Nested;

/// What the circuit-field side's targets derive from: the native
/// unified instance, the output header and the circuit id's domain point.
pub(crate) struct NativeExtra<C: Cycle> {
    pub unified: native_unified::Instance<C>,
    pub output_header: Vec<C::CircuitField>,
    pub omega_j: C::CircuitField,
}

/// What the scalar-field side's targets derive from: the nested
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
        verifier::native_tables::<C, K, R, HEADER_SIZE>()
    }

    fn verify<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        run: &mut Run<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Point<'dr, D, Self::P>>> {
        verifier::native_side::<_, C, K, HEADER_SIZE>(dr, run)
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
        verifier::nested_tables::<C, K, R, HEADER_SIZE>()
    }

    fn verify<'dr, D: Driver<'dr, F = Self::F>, K: Rank, const HEADER_SIZE: usize>(
        dr: &mut D,
        run: &mut Run<'_, '_, 'dr, D, C, Self>,
    ) -> Result<Vec<Point<'dr, D, Self::P>>> {
        verifier::nested_side::<_, C, K>(dr, run)
    }
}
