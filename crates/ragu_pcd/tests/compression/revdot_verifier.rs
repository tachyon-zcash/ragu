//! Verifier input-length regression checks.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::TestRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Fq, Pasta},
};

use super::*;
use crate::profile::Standard;

type Host = <Pasta as Cycle>::HostCurve;

/// More claims than one fold group holds, so the layout spans two.
const COUNT: usize = fold::GROUP + 1;

/// One shape of each kind, over a single component.
fn shapes(kinds: &[Kind]) -> Vec<Shape<(), Fp>> {
    kinds
        .iter()
        .map(|&kind| Shape {
            kind,
            a: vec![(Fp::ONE, ())],
            b: if kind == Kind::Raw {
                vec![(Fp::ONE, ())]
            } else {
                Vec::new()
            },
        })
        .collect()
}

/// Runs the verifier over claims of `kinds` with `targets`, returning its
/// result and how many public parts it evaluated.
fn run(
    kinds: &[Kind],
    targets: impl Iterator<Item = Fp>,
) -> (Result<Option<Openings<Host>>>, usize) {
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
    let evaluated = AtomicUsize::new(0);
    let result = verify::<_, TestRank, ReferenceBackend, _>(
        &shapes(kinds),
        targets,
        |_| point,
        |_, _| {
            evaluated.fetch_add(1, Ordering::Relaxed);
            (Fp::ZERO, Fp::ZERO)
        },
        &reduction,
        Fp::from(3),
        &mut Transcript,
    );
    (result, evaluated.load(Ordering::Relaxed))
}

fn assert_mismatch(
    (result, evaluated): (Result<Option<Openings<Host>>>, usize),
    expected: usize,
    actual: usize,
) {
    assert!(
        matches!(result, Err(Error::VectorLengthMismatch { expected: e, actual: a }) if e == expected && a == actual),
        "expected a mismatch of {actual} targets against {expected}: {result:?}"
    );
    assert_eq!(evaluated, 0, "a mismatch must reject before public parts");
}

#[test]
fn short_targets_reject_before_public_evaluations() {
    assert_mismatch(
        run(
            &[Kind::Raw; COUNT],
            core::iter::repeat_n(Fp::ZERO, COUNT - 1),
        ),
        COUNT,
        COUNT - 1,
    );
}

#[test]
fn extra_targets_reject_before_public_evaluations() {
    assert_mismatch(
        run(
            &[Kind::Raw; COUNT],
            core::iter::repeat_n(Fp::ZERO, COUNT + 1),
        ),
        COUNT,
        COUNT + 1,
    );

    // An unbounded stream is read only one target past the claims.
    assert_mismatch(
        run(&[Kind::Raw; COUNT], core::iter::repeat(Fp::ZERO)),
        COUNT,
        COUNT + 1,
    );
}

#[test]
fn only_raw_and_circuit_claims_take_targets() {
    let circuit = CircuitIndex::new(0);
    let kinds = [
        Kind::Raw,
        Kind::Bonding(circuit),
        Kind::Circuit(circuit),
        Kind::Masked(0),
        Kind::Circuit(circuit),
    ];
    let targets = claim_targets(&shapes(&kinds), [2u64, 3, 5].map(Fp::from).into_iter()).unwrap();
    assert_eq!(targets, [2u64, 0, 3, 0, 5].map(Fp::from));

    // Through the verifier, over enough claims for two groups: the exact
    // count reaches every claim's public parts, and a target for every
    // claim is too many.
    let kinds: Vec<_> = (0..COUNT).map(|i| kinds[i % kinds.len()]).collect();
    let taking = kinds.iter().filter(|kind| kind.takes_target()).count();
    let (result, evaluated) = run(&kinds, core::iter::repeat_n(Fp::ZERO, taking));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(evaluated, kinds.len());
    assert_mismatch(
        run(&kinds, core::iter::repeat_n(Fp::ZERO, kinds.len())),
        taking,
        taking + 1,
    );
}

/// The targets [`claim_targets`] pairs with the decider's claims by kind are
/// the ones the unbounded `ky_values` stream, which the uncompressed decider
/// and the fuse circuits consume, gives them by position.
#[test]
fn claim_targets_match_positional_ky_values() {
    let native_ky = NativeKy {
        c: Some(Fp::from(2)),
        unified: Fp::from(3),
        unified_bridge: Fp::from(5),
        application: Fp::from(7),
        statement: None,
        binding: None,
    };
    let masked = [Masked::new(
        native::RxComponent::AbA,
        vec![0],
        vec![Fp::ONE],
        Fp::ONE,
    )];
    let shapes =
        claims::native_shapes::<Standard, _>(CircuitIndex::new(0), Fp::from(11), &masked).unwrap();
    assert_eq!(
        claim_targets(
            &shapes,
            native::claims::ky_prefix::<Standard, _>(&native_ky)
        )
        .unwrap(),
        native::claims::ky_values::<Standard, _>(&native_ky)
            .take(shapes.len())
            .collect::<Vec<_>>(),
    );

    let nested_ky = NestedKy {
        c: Fq::from(2),
        unified: Fq::from(3),
        binding: None,
    };
    let masked = [Masked::new(
        nested::RxComponent::AbA,
        vec![0],
        vec![Fq::ONE],
        Fq::ONE,
    )];
    let shapes = claims::nested_shapes::<Standard, _>(Fq::from(11), &masked).unwrap();
    assert_eq!(
        claim_targets(
            &shapes,
            nested::claims::ky_prefix::<Standard, _>(&nested_ky)
        )
        .unwrap(),
        nested::claims::ky_values::<Standard, _>(&nested_ky)
            .take(shapes.len())
            .collect::<Vec<_>>(),
    );
}
