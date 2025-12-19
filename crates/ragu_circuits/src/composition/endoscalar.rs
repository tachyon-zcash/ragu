use arithmetic::{CurveAffine, Uendo};
use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Gadget, GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element, Endoscalar, Point,
    io::Write,
    vec::{ConstLen, FixedVec},
};

use alloc::vec::Vec;

use crate::{
    polynomials::Rank,
    staging::{Stage, StageBuilder, StagedCircuit},
};

#[derive(Default)]
pub struct EndoscalarStage;

#[derive(Default)]
pub struct SlotStage<C: CurveAffine, const NUM_SLOTS: usize>(core::marker::PhantomData<C>);

impl<F: Field, R: Rank> Stage<F, R> for EndoscalarStage {
    type Parent = ();

    fn values() -> usize {
        Uendo::BITS as usize
    }

    type Witness<'source> = Uendo;
    type OutputKind = Kind![F; Endoscalar<'_, _>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        Endoscalar::alloc(dr, witness)
    }
}

impl<C: CurveAffine, R: Rank, const NUM_SLOTS: usize> Stage<C::Base, R>
    for SlotStage<C, NUM_SLOTS>
{
    type Parent = EndoscalarStage;

    fn values() -> usize {
        // (x, y) coordinates for each slot.
        2 * NUM_SLOTS
    }

    type Witness<'source> = FixedVec<C, ConstLen<NUM_SLOTS>>;
    type OutputKind = Kind![C::Base; FixedVec<Point<'_, _, C>, ConstLen<NUM_SLOTS>>];

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::Base>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        FixedVec::try_from_fn(|i| Point::alloc(dr, witness.view().map(|w| w[i])))
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum Read {
    Input,
    Dummy,
    Slot(usize),
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct Endoscaling<C: CurveAffine, R: Rank, const NUM_SLOTS: usize> {
    pub a: Read,
    pub b: Read,
    pub c: Read,
    pub d: Read,
    pub e: Read,

    pub output: usize,

    pub _marker: core::marker::PhantomData<(C, R)>,
}

pub struct EndoscalingWitness<C: CurveAffine, const NUM_SLOTS: usize> {
    pub endoscalar: Uendo,
    pub slots: FixedVec<C, ConstLen<NUM_SLOTS>>,
    pub input: C,
}

pub struct EndoscalingInstance<C: CurveAffine, const NUM_SLOTS: usize> {
    pub input: C,
    pub output: C,
}

#[derive(Gadget, Write)]
pub struct EndoscalingOutput<'dr, D: Driver<'dr>, C: CurveAffine> {
    #[ragu(gadget)]
    input: Point<'dr, D, C>,
    #[ragu(gadget)]
    output: Point<'dr, D, C>,
}

impl<C: CurveAffine, R: Rank, const NUM_SLOTS: usize> StagedCircuit<C::Base, R>
    for Endoscaling<C, R, NUM_SLOTS>
{
    type Final = SlotStage<C, NUM_SLOTS>;
    type Instance<'source> = EndoscalingInstance<C, NUM_SLOTS>;
    type Witness<'source> = EndoscalingWitness<C, NUM_SLOTS>;
    type Output = Kind![C::Base; EndoscalingOutput<'_, _, C>];
    type Aux<'source> = C;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<C::Base>>::Rebind<'dr, D>> {
        let input = Point::alloc(dr, instance.view().map(|instance| instance.input))?;
        let output = Point::alloc(dr, instance.view().map(|instance| instance.output))?;
        Ok(EndoscalingOutput { input, output })
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<C::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let (endoscalar_guard, dr) = dr.add_stage::<EndoscalarStage>()?;
        let (slots_guard, dr) = dr.add_stage::<SlotStage<C, NUM_SLOTS>>()?;
        let dr = dr.finish();

        let endoscalar = endoscalar_guard.unenforced(dr, witness.view().map(|w| w.endoscalar))?;
        let slots = slots_guard.unenforced(dr, witness.view().map(|w| w.slots.clone()))?;

        let input = Point::alloc(dr, witness.view().map(|w| w.input))?;
        let dummy = Point::constant(dr, C::generator())?;

        let load_slot = |read: Read| match read {
            Read::Input => input.clone(),
            Read::Dummy => dummy.clone(),
            Read::Slot(i) => slots[i].clone(),
        };

        let a = load_slot(self.a);
        let b = load_slot(self.b);
        let c = load_slot(self.c);
        let d = load_slot(self.d);
        let e = load_slot(self.e);

        let mut results = Vec::with_capacity(5);

        let mut nonzero_acc = Element::one();

        // a
        let mut acc = a.clone();
        acc = endoscalar.group_scale(dr, &acc)?;
        results.push(acc.clone());
        // b
        acc = acc.add_incomplete(dr, &b, Some(&mut nonzero_acc))?;
        acc = endoscalar.group_scale(dr, &acc)?;
        results.push(acc.clone());
        // c
        acc = acc.add_incomplete(dr, &c, Some(&mut nonzero_acc))?;
        acc = endoscalar.group_scale(dr, &acc)?;
        results.push(acc.clone());
        // d
        acc = acc.add_incomplete(dr, &d, Some(&mut nonzero_acc))?;
        acc = endoscalar.group_scale(dr, &acc)?;
        results.push(acc.clone());
        // e
        acc = acc.add_incomplete(dr, &e, Some(&mut nonzero_acc))?;
        results.push(acc.clone());

        nonzero_acc.invert(dr)?; // Ensure that coincident x-coordinates did not occur during point additions.

        let output = results[self.output].clone();
        let output_value = output.value();

        Ok((EndoscalingOutput { input, output }, output_value))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EndoscalarStage, Endoscaling, EndoscalingInstance, EndoscalingWitness, Read, SlotStage,
    };
    use crate::{
        CircuitExt,
        polynomials::{self},
        staging::{StageExt, Staged},
    };
    use arithmetic::Uendo;
    use ff::Field;
    use group::Curve;
    use group::prime::PrimeCurveAffine;
    use ragu_core::Result;
    use ragu_pasta::{EpAffine, EqAffine, Fp, Fq};
    use ragu_primitives::vec::FixedVec;
    use rand::{Rng, thread_rng};

    type R = polynomials::R<13>;

    #[test]
    fn test_endoscaling_circuit() -> Result<()> {
        const NUM_SLOTS: usize = 143;

        let endoscalar: Uendo = thread_rng().r#gen();
        let input = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let values =
            FixedVec::from_fn(|_| (EpAffine::generator() * Fq::random(thread_rng())).to_affine());

        let stage_circuit = Endoscaling::<EpAffine, R, NUM_SLOTS> {
            a: Read::Input,
            b: Read::Slot(0),
            c: Read::Slot(1),
            d: Read::Slot(2),
            e: Read::Slot(3),
            output: 4,
            _marker: core::marker::PhantomData,
        };
        let staged_circuit = Staged::new(stage_circuit);

        let endoscalar_s = EndoscalarStage::into_object()?;
        let slot_s = SlotStage::<EpAffine, NUM_SLOTS>::into_object()?;
        let final_s = SlotStage::<EpAffine, NUM_SLOTS>::final_into_object()?;

        let endoscalar_rx = <EndoscalarStage as StageExt<Fp, R>>::rx(endoscalar)?;
        let slot_rx = <SlotStage<EpAffine, NUM_SLOTS> as StageExt<Fp, R>>::rx(values.clone())?;
        let key = Fp::ONE;
        let (final_rx, output) = staged_circuit.rx::<R>(
            EndoscalingWitness {
                endoscalar,
                slots: values,
                input,
            },
            key,
        )?;

        let endoscaling_s = staged_circuit.clone().into_object()?;

        let y = Fp::random(thread_rng());
        let ky = staged_circuit.ky(EndoscalingInstance { input, output })?;

        assert_eq!(endoscalar_rx.revdot(&endoscalar_s.sy(y, key)), Fp::ZERO);
        assert_eq!(slot_rx.revdot(&slot_s.sy(y, key)), Fp::ZERO);
        assert_eq!(final_rx.revdot(&final_s.sy(y, key)), Fp::ZERO);

        let mut lhs = final_rx.clone();
        lhs.add_assign(&endoscalar_rx);
        lhs.add_assign(&slot_rx);
        assert_eq!(
            lhs.revdot(&endoscaling_s.sy(y, key)),
            arithmetic::eval(&ky, y)
        );

        Ok(())
    }

    #[test]
    fn test_pallas_endoscaling_circuit_new() -> Result<()> {
        /// Thin alias for the Fq-side endoscaling gadget: reuses `Endoscaling<C, R, N>` with `C = EqAffine` (Vesta).
        type EndoFq<const N: usize, R> = Endoscaling<EqAffine, R, N>;

        type R = polynomials::R<13>;
        const NUM_SLOTS: usize = 143;

        let endoscalar: Uendo = thread_rng().r#gen();
        let input = (EqAffine::generator() * Fp::random(thread_rng())).to_affine();
        let values =
            FixedVec::from_fn(|_| (EqAffine::generator() * Fp::random(thread_rng())).to_affine());

        let stage_circuit = EndoFq::<NUM_SLOTS, R> {
            a: Read::Input,
            b: Read::Slot(0),
            c: Read::Slot(1),
            d: Read::Slot(2),
            e: Read::Slot(3),
            output: 4,
            _marker: core::marker::PhantomData,
        };
        let staged_circuit = Staged::new(stage_circuit);

        let key = Fq::ONE;
        let (final_rx, _output) = staged_circuit.rx::<R>(
            EndoscalingWitness {
                endoscalar,
                slots: values,
                input,
            },
            key,
        )?;

        let final_s = SlotStage::<EqAffine, NUM_SLOTS>::final_into_object()?;
        let y = Fq::random(thread_rng());

        assert_eq!(final_rx.revdot(&final_s.sy(y, key)), Fq::ZERO);

        Ok(())
    }

    #[test]
    fn test_vesta_endoscaling_circuit_new() -> Result<()> {
        /// Thin alias for the Fq-side endoscaling gadget:
        /// reuses `Endoscaling<C, R, N>` with `C = EpAffine` (Pallas).
        type EndoFp<const N: usize, R> = Endoscaling<EpAffine, R, N>;

        const NUM_SLOTS: usize = 143;

        let endoscalar: Uendo = thread_rng().r#gen();
        let input = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let values =
            FixedVec::from_fn(|_| (EpAffine::generator() * Fq::random(thread_rng())).to_affine());

        let stage_circuit = EndoFp::<NUM_SLOTS, R> {
            a: Read::Input,
            b: Read::Slot(0),
            c: Read::Slot(1),
            d: Read::Slot(2),
            e: Read::Slot(3),
            output: 4,
            _marker: core::marker::PhantomData,
        };
        let staged_circuit = Staged::new(stage_circuit);

        let key = Fp::ONE;
        let (final_rx, _output) = staged_circuit.rx::<R>(
            EndoscalingWitness {
                endoscalar,
                slots: values,
                input,
            },
            key,
        )?;

        let final_s = SlotStage::<EpAffine, NUM_SLOTS>::final_into_object()?;
        let y = Fp::random(thread_rng());

        assert_eq!(final_rx.revdot(&final_s.sy(y, key)), Fp::ZERO);

        Ok(())
    }
}
