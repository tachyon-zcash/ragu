//! Verifier input-length regression checks.

use alloc::{vec, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::TestRank;
use ragu_core::pasta::{Fp, Pasta};

use super::*;

#[test]
fn short_targets_reject_before_public_evaluations() {
    type Host = <Pasta as Cycle>::HostCurve;

    // Keep the length guard independent of proof construction; the full
    // compression tests exercise the real transcript and proof checks.
    struct Transcript;
    impl IpaTranscript<Host> for Transcript {
        fn write_point(&mut self, _: Host) -> Result<()> {
            Ok(())
        }
        fn write_scalar(&mut self, _: Fp) -> Result<()> {
            Ok(())
        }
        fn squeeze_challenge(&mut self) -> Result<Fp> {
            Ok(Fp::from(7))
        }
    }

    let count = fold::GROUP + 1;
    let shapes: Vec<_> = (0..count)
        .map(|_| Shape {
            kind: Kind::Raw,
            a: vec![(Fp::ONE, ())],
            b: vec![(Fp::ONE, ())],
        })
        .collect();
    let point = Host::generator();
    let reduction = Reduction {
        fold: fold::Fold {
            inner: point,
            outer: point,
            inner_epsilon: Fp::ZERO,
            outer_epsilon: Fp::ZERO,
        },
        p: point,
        q: point,
        openings: vec![Fp::ZERO; Derived::ALL.len()],
        p_at_inverse_r: Fp::ZERO,
        q_at_r: Fp::ZERO,
    };
    let result = verify::<_, TestRank, ReferenceBackend, _>(
        &shapes,
        core::iter::repeat_n(Fp::ZERO, count - 1),
        |_| point,
        |_, _| panic!("missing targets must reject before evaluating public parts"),
        &reduction,
        Fp::from(3),
        &mut Transcript,
    );
    assert!(
        matches!(result, Err(Error::VectorLengthMismatch { expected, actual }) if expected == count && actual == count - 1)
    );
}
