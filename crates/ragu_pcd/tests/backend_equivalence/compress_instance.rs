//! Backend equivalence for recomputed nested-stage commitments.

use ragu_acceleration::{AcceleratedBackend, AcceleratedProver};
use ragu_backend::ReferenceBackend;
use ragu_core::{
    Cycle,
    pasta::{Fq, Pasta},
};
use udon::field::Field;

use super::{HEADER_SIZE, Instance, TestR, replay, setup};
use crate::internal::nested;

#[test]
fn recomputed_stages_match_across_backends() {
    let (_, _, instance) = setup();
    let challenges = replay(&instance);
    let generators = Pasta::nested_generators(crate::pasta::baked());
    let check = |instance: &Instance<Pasta>, expected| {
        let verify = |result| assert_eq!(result, expected);
        verify(
            instance
                .stages_match::<TestR, ReferenceBackend, HEADER_SIZE>(&challenges, generators)
                .unwrap(),
        );
        verify(
            instance
                .stages_match::<TestR, AcceleratedBackend, HEADER_SIZE>(&challenges, generators)
                .unwrap(),
        );
        verify(
            instance
                .stages_match::<TestR, AcceleratedProver, HEADER_SIZE>(&challenges, generators)
                .unwrap(),
        );
    };
    check(&instance, true);

    let mut tampered = instance.clone();
    tampered.bridge_alpha += Fq::ONE;
    check(&tampered, false);

    // Each comparison must remain separate: corrupt either stage's claimed
    // commitment without changing the already replayed challenges.
    for stage in [nested::RxIndex::ChallengeStage, nested::RxIndex::BridgeAB] {
        let mut tampered = instance.clone();
        let index = super::super::nested_position(nested::RxComponent::Rx(stage));
        tampered.nested[index] = -tampered.nested[index];
        check(&tampered, false);
    }
}
