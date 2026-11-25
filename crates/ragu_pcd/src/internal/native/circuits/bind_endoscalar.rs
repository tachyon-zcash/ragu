//! Circuit binding the native endoscaling walk at both ends: the walk
//! stage's endoscalar bits to `pre_beta`, every points stage to the curve,
//! and the persistent polynomial commitments to the unified instance.
//!
//! The endoscaling steps walk the nested batch's commitments with the bits
//! and hoisted bit products the [`WalkStage`] holds. This circuit reads
//! `pre_beta` from the unified instance, extracts the endoscalar from it
//! exactly as `compute_v` does, hoists its products, and enforces the stage's
//! gadget equal to that wire by wire, so that the walk is by the transcript's
//! $\beta$. It loads every input stage enforced, so that every
//! point the walk consumes lies on the curve. It covers the
//! [`nested_p_commitment`] slot, enforcing it equal to the walk's last
//! interstitial: a parent walks the cached $P_n$ and holds that copy against
//! this slot in its `bind_beta`, which is what makes the nested batch's
//! commitment the walk's result rather than the prover's choice. `pre_beta`
//! itself is `hashes_2`'s.
//!
//! The same export binds the walked $A_n$, $B_n$ and `registry_xy` to the
//! polynomials retained by the decider and copied by the next parent. The
//! parent's `bind_beta` compares its walked copies against these slots.
//!
//! In a profile whose native binding circuit names online Fq polynomials
//! of the step ([`Binding::online`](crate::profile::Binding::online)),
//! the circuit's instance ends with their commitments, read off the
//! preamble stage the walk takes them from: the parent holds them once
//! for this claim and for the binding circuit's, so the point the
//! binding circuit exposes is the one the step committed before $w$ and
//! its walk folded. Any other profile's instance is the unified instance
//! alone.
//!
//! # A walk of several segments
//!
//! A profile whose walk is cut into segments (see
//! [`Walk`](crate::internal::native::Walk)) keeps the endoscalar's bits in
//! [`BitsStage`] and its steps' outputs in a polynomial of [`SegmentStage`]
//! per segment. The circuit then binds the bits stage's gadget to
//! `pre_beta` and loads the polynomial of the segment the walk ends in,
//! whose last interstitial is $P_n$. It loads one polynomial of that stage,
//! so it cannot hold every point the walk consumes to the curve: the steps
//! do, each for the copies it reads, and the
//! [`walk_loading`](super::walk_loading) bondings carry that to the input
//! stages, which the circuit loads unenforced. It still holds the points of
//! the binding stage the walk does not fold to the curve: no step reads
//! them.
//!
//! [`nested_p_commitment`]: unified::Output::nested_p_commitment

use core::marker::PhantomData;

use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Endoscalar, EndoscalarChallenge, GadgetExt as _, HoistedEndoscalar, Point, WithSuffix,
    allocator::Standard,
    consistent::Consistent,
    io::Write,
    vec::{CollectFixed, FixedVec},
};

use super::super::{
    segments,
    stages::points::{
        AbStage, BindingStage, BitsStage, BoundariesStage, FStage, Inputs, PreambleStage,
        RegistryWxStage, SegmentStage, WalkStage, WalkWitness,
    },
    unified::{self, OutputBuilder},
};
use crate::{
    internal::nested::online::{BoundCommitmentsLen, bound_commitments},
    profile::{
        Profile, ProfiledCycle,
        online::stages::{Nested, PolynomialsLen},
    },
};

/// The circuit's public output: the unified instance, then the
/// commitments of the step's online Fq polynomials its profile exports,
/// then the actual nested online walk points.
#[derive(Gadget, Write)]
pub struct Output<'dr, D: Driver<'dr>, C: ProfiledCycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
    #[ragu(gadget)]
    pub online_fq: FixedVec<Point<'dr, D, C::NestedCurve>, BoundCommitmentsLen<C::Profile>>,
    #[ragu(gadget)]
    pub online_points: FixedVec<Point<'dr, D, C::NestedCurve>, PolynomialsLen<C::Profile, Nested>>,
}

/// Circuit binding the walk stage's endoscalar bits to `pre_beta`, the
/// points stages to the curve and the persistent polynomial commitments
/// to the instance.
pub struct Circuit<C: Cycle, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C: ProfiledCycle, R: Rank> Circuit<C, R> {
    pub fn new() -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            _marker: PhantomData,
        })
    }
}

/// Witness for the binding circuit.
pub struct Witness<'a, C: ProfiledCycle> {
    /// The unified instance, for `pre_beta`.
    pub unified: unified::Instance<C>,
    /// The points stages' values.
    pub inputs: &'a Inputs<C::NestedCurve, C::Profile>,
    /// The walk stage's value.
    pub walk: &'a WalkWitness<C::NestedCurve, C::Profile>,
}

impl<C: ProfiledCycle, R: Rank> MultiStageCircuit<C::CircuitField, R> for Circuit<C, R> {
    type Last = WalkStage<C::NestedCurve, C::Profile>;
    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C>;
    type Output = Kind![C::CircuitField; WithSuffix<'_, _, Output<'_, _, C>>];
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (binding, builder) = builder.add_stage::<BindingStage<C::NestedCurve, C::Profile>>()?;
        let (bits, builder) = builder.add_stage::<BitsStage<C::NestedCurve, C::Profile>>()?;
        let (segment, builder) = builder.add_stage::<SegmentStage<C::NestedCurve, C::Profile>>()?;
        let builder = builder.skip_stage::<BoundariesStage<C::NestedCurve, C::Profile>>()?;
        let (preamble, builder) =
            builder.add_stage::<PreambleStage<C::NestedCurve, C::Profile>>()?;
        let (registry_wx, builder) =
            builder.add_stage::<RegistryWxStage<C::NestedCurve, C::Profile>>()?;
        let (ab, builder) = builder.add_stage::<AbStage<C::NestedCurve, C::Profile>>()?;
        let (f, builder) = builder.add_stage::<FStage<C::NestedCurve, C::Profile>>()?;
        let (walk, builder) = builder.add_stage::<WalkStage<C::NestedCurve, C::Profile>>()?;
        let dr = builder.finish();

        let geometry = segments::<C::Profile>();
        let inputs = witness.as_ref().map(|w| w.inputs);
        let (preamble, registry_wx, ab, f) = if geometry.is_split() {
            // The steps hold the points they fold to the curve, on their
            // segments' copies, which the loading bondings hold to these
            // stages. No step reads the points the walk does not fold: the
            // children's exported online Fq commitments and the step's
            // nested online input stage, all in the binding stage.
            let binding = binding.unenforced(dr, inputs.as_ref().map(|i| &i.binding))?;
            for point in binding
                .online_input
                .iter()
                .chain(binding.left.online_fq.iter())
                .chain(binding.right.online_fq.iter())
            {
                point.enforce_consistent(dr)?;
            }
            (
                preamble.unenforced(dr, inputs.as_ref().map(|i| &i.preamble))?,
                registry_wx.unenforced(dr, inputs.as_ref().map(|i| &i.registry_wx))?,
                ab.unenforced(dr, inputs.as_ref().map(|i| &i.ab))?,
                f.unenforced(dr, inputs.as_ref().map(|i| &i.f))?,
            )
        } else {
            // Enforced: every point the walk consumes lies on the curve.
            let _ = binding.enforced(dr, inputs.as_ref().map(|i| &i.binding))?;
            (
                preamble.enforced(dr, inputs.as_ref().map(|i| &i.preamble))?,
                registry_wx.enforced(dr, inputs.as_ref().map(|i| &i.registry_wx))?,
                ab.enforced(dr, inputs.as_ref().map(|i| &i.ab))?,
                f.enforced(dr, inputs.as_ref().map(|i| &i.f))?,
            )
        };
        let walk = walk.unenforced(dr, witness.as_ref().map(|w| w.walk))?;
        // The endoscalar's gadget and the walk's result: the walk stage's
        // and its last interstitial, or, for a walk of several segments,
        // the bits stage's and the last interstitial of the segment the
        // walk ends in.
        let (endoscalar, walked_p) = if geometry.is_split() {
            let bits = bits.unenforced(dr, witness.as_ref().map(|w| w.walk))?;
            let segment =
                segment.unenforced(dr, witness.as_ref().map(|w| w.walk.last_segment()))?;
            (
                bits[0].clone(),
                segment.interstitials[geometry.last_local_step()].clone(),
            )
        } else {
            (walk.endoscalar[0].clone(), walk.p().clone())
        };

        let allocator = &mut Standard::new();
        let mut unified_output = OutputBuilder::new(witness.map(|w| w.unified));

        // The walk stage's contracts: its bits are the canonical extraction
        // of `pre_beta` and its products are the products of those bits.
        // Hoisting the extracted endoscalar derives the products, and the
        // conservative equality transfers both to the stage's wires.
        let pre_beta = unified_output.pre_beta.read(dr, allocator)?;
        let pre_beta = EndoscalarChallenge::from_element(dr, allocator, pre_beta)?;
        let extracted = HoistedEndoscalar::hoist(dr, Endoscalar::extract(pre_beta))?;
        extracted.enforce_conservative_equal(dr, &endoscalar)?;

        // The walk's last interstitial is P_n: pin it to the instance, where
        // a parent reads it.
        let p = unified_output.nested_p_commitment.receive(dr, allocator)?;
        walked_p.enforce_equal(dr, &p)?;

        let a = unified_output.nested_a_commitment.receive(dr, allocator)?;
        ab.a.enforce_equal(dr, &a)?;
        let b = unified_output.nested_b_commitment.receive(dr, allocator)?;
        ab.b.enforce_equal(dr, &b)?;
        let registry_xy = unified_output
            .nested_registry_xy_commitment
            .receive(dr, allocator)?;
        f.registry_xy.enforce_equal(dr, &registry_xy)?;

        // The online Fq commitments the profile exports, as the walk
        // takes them.
        let online_fq = FixedVec::try_from(
            bound_commitments::<C::Profile>()
                .iter()
                .map(|&slot| preamble.online_fq[slot as usize].clone())
                .collect::<alloc::vec::Vec<_>>(),
        )?;
        let online_points = preamble
            .online_fq
            .iter()
            .skip(C::Profile::ONLINE_FQ_POLYS)
            .chain(registry_wx.online_points.iter())
            .chain(ab.online_points.iter())
            .chain(f.online_points.iter())
            .cloned()
            .collect_fixed()?;
        let (output, aux) = unified_output.finish_with(dr, allocator, |unified| Output {
            unified,
            online_fq,
            online_points,
        })?;
        Ok(WithAux::new(output, aux))
    }
}
