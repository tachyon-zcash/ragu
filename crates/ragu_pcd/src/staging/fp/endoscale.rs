//! Deferred R values from the previous round, which are now native in Fp (Pallas).
//! We stage them directly over Fp and endoscale them in this round using the existing
//! endoscaling gadget.

use crate::staging::common::endoscalar::Endoscaling;
use ragu_pasta::EpAffine;

/// Thin alias for the endoscaling gadget on the Fp side, reusing
/// the generic `Endoscaling<C, R, N> with C = EpAffine` with C = EpAffine.
type EndoFp<const N: usize, R> = Endoscaling<EpAffine, R, N>;

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
    use ragu_pasta::{EpAffine, Fp, Fq};
    use rand::{Rng, thread_rng};

    use crate::staging::{
        common::endoscalar::{EndoscalingWitness, Read, SlotStage},
        fp::endoscale::EndoFp,
    };

    type R = polynomials::R<13>;

    #[test]
    fn test_endoscaling_circuit_new() -> Result<()> {
        const NUM_SLOTS: usize = 143;

        let endoscalar: Uendo = thread_rng().r#gen();
        let input = (EpAffine::generator() * Fq::random(thread_rng())).to_affine();
        let values = [(EpAffine::generator() * Fq::random(thread_rng())).to_affine(); NUM_SLOTS];

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

        let (final_rx, _output) = staged_circuit.rx::<R>(EndoscalingWitness {
            endoscalar,
            slots: values,
            input,
        })?;

        let final_s = SlotStage::<EpAffine, NUM_SLOTS>::final_into_object()?;
        let y = Fp::random(thread_rng());
        let z = Fp::random(thread_rng());

        let mut rhs = final_rx.clone();
        rhs.dilate(z);
        rhs.add_assign(&final_s.sy(y));
        rhs.add_assign(&R::tz(z));
        assert_eq!(final_rx.revdot(&rhs), Fp::ZERO);

        Ok(())
    }
}
