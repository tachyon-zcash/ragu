//! Deferred R values from the prior step that are **now native over Fq (Vesta)**.
//! We allocate (stage) them directly in the Fq circuit and perform endoscaling
//! in this round using the existing endoscalar gadget.

use crate::staging::common::endoscalar::Endoscaling;
use ragu_pasta::EqAffine;

/// Thin alias for the Fq-side endoscaling gadget:
/// reuses `Endoscaling<C, R, N>` with `C = EqAffine` (Vesta).
type EndoFq<const N: usize, R> = Endoscaling<EqAffine, R, N>;

#[cfg(test)]
mod tests {
    use arithmetic::Uendo;
    use ff::Field;
    use pasta_curves::group::Curve;
    use pasta_curves::group::prime::PrimeCurveAffine;
    use ragu_circuits::{
        CircuitExt,
        polynomials::{self, Rank},
        staging::{StageExt, Staged},
    };
    use ragu_core::Result;
    use ragu_pasta::{EqAffine, Fp, Fq};
    use rand::{Rng, thread_rng};

    use crate::staging::{
        common::endoscalar::{EndoscalingWitness, Read, SlotStage},
        fq::endoscale::EndoFq,
    };

    type R = polynomials::R<13>;

    #[test]
    fn test_endoscaling_circuit_new() -> Result<()> {
        const NUM_SLOTS: usize = 143;

        let endoscalar: Uendo = thread_rng().r#gen();
        let input = (EqAffine::generator() * Fp::random(thread_rng())).to_affine();
        let values = [(EqAffine::generator() * Fp::random(thread_rng())).to_affine(); NUM_SLOTS];

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

        let (final_rx, _output) = staged_circuit.rx::<R>(EndoscalingWitness {
            endoscalar,
            slots: values,
            input,
        })?;

        let final_s = SlotStage::<EqAffine, NUM_SLOTS>::final_into_object()?;
        let y = Fq::random(thread_rng());
        let z = Fq::random(thread_rng());

        let mut rhs = final_rx.clone();
        rhs.dilate(z);
        rhs.add_assign(&final_s.sy(y));
        rhs.add_assign(&R::tz(z));
        assert_eq!(final_rx.revdot(&rhs), Fq::ZERO);

        Ok(())
    }
}
