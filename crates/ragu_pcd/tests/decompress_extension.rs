//! The decompression circuits as the aggregator profile's extension: the
//! pinned layout is the schedules', the hooks register every chunk and
//! stage at the aggregator rank and refuse the production rank, and an
//! application over the profile builds at the aggregator rank, where
//! every fuse circuit fits with the extension's polynomials.

use ragu_circuits::{
    polynomials::{AggregatorRank, ProductionRank},
    registry::RegistryBuilder,
};
use ragu_core::{
    Error,
    pasta::{Fp, Fq, Pasta},
};

use super::{native, nested};
use crate::{
    ApplicationBuilder,
    decompress::support::{HEADER_SIZE, TestR},
    profile::{Aggregator, BondingSlot, CircuitSlot, Profile, Profiled, Shape, Standard},
};

type P = Aggregator<HEADER_SIZE>;

/// The pinned layouts are the schedules' at the aggregator rank, for the
/// test header size and for the internal tests', and lay out as the
/// module says: transcript chunks first, over four native stages and
/// three nested ones.
#[test]
fn pinned_layout_is_the_schedules() {
    assert_eq!(
        P::native_extension(),
        native::<Pasta, ProductionRank, AggregatorRank, HEADER_SIZE>().unwrap()
    );
    assert_eq!(
        P::nested_extension(),
        nested::<Pasta, ProductionRank, AggregatorRank, HEADER_SIZE>().unwrap()
    );
    assert_eq!(
        Aggregator::<103>::native_extension(),
        native::<Pasta, ProductionRank, AggregatorRank, 103>().unwrap()
    );
    assert_eq!(
        Aggregator::<103>::nested_extension(),
        nested::<Pasta, ProductionRank, AggregatorRank, 103>().unwrap()
    );

    let native = P::native_extension();
    let (chunks, transcript) = P::native_chunks(HEADER_SIZE);
    assert_eq!(native.circuits.len(), chunks);
    assert_eq!(native.stages, 4);
    assert!(
        native.circuits[..transcript]
            .iter()
            .all(|c| c == &[0, 1, 2, 3])
    );
    assert!(
        native.circuits[transcript..]
            .iter()
            .all(|c| c == &[0, 1, 2])
    );
    assert_eq!(native.final_masks.len(), 2);
    assert_eq!(native.final_masks[0].len(), chunks - transcript);
    assert_eq!(native.final_masks[1].len(), transcript);
    assert!(native.is_consistent());

    let nested = P::nested_extension();
    assert_eq!(nested.circuits.len(), P::NESTED_CHUNKS);
    assert_eq!(nested.stages, 3);
    assert!(nested.circuits.iter().all(|c| c == &[0, 1, 2]));
    assert_eq!(nested.final_masks.len(), 1);
    assert!(nested.is_consistent());
}

/// Every chunk and bonding of both sides registers through the hooks at
/// the aggregator rank, one past the last fails, and the production rank
/// is refused.
#[test]
fn hooks_register_every_chunk_and_stage() {
    let params = crate::pasta::baked_aggregator();
    let native = P::native_extension();
    let mut registry = RegistryBuilder::<Fp, AggregatorRank>::new();
    for circuit in 0..native.circuits.len() {
        registry = P::register_native_circuit::<Pasta, AggregatorRank, HEADER_SIZE>(
            circuit,
            CircuitSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    for bonding in 0..native.bondings() {
        registry = P::register_native_bonding::<Pasta, AggregatorRank, HEADER_SIZE>(
            bonding,
            BondingSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    assert_eq!(registry.num_internal_circuits(), native.internal());
    assert!(matches!(
        P::register_native_bonding::<Pasta, AggregatorRank, HEADER_SIZE>(
            native.bondings(),
            BondingSlot::new(registry),
            params
        ),
        Err(Error::Initialization(_))
    ));
    assert!(matches!(
        P::register_native_circuit::<Pasta, TestR, HEADER_SIZE>(
            0,
            CircuitSlot::new(RegistryBuilder::new()),
            params
        ),
        Err(Error::Initialization(_))
    ));

    let nested = P::nested_extension();
    let mut registry = RegistryBuilder::<Fq, AggregatorRank>::new();
    for circuit in 0..nested.circuits.len() {
        registry = P::register_nested_circuit::<Pasta, AggregatorRank>(
            circuit,
            CircuitSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    for bonding in 0..nested.bondings() {
        registry = P::register_nested_bonding::<Pasta, AggregatorRank>(
            bonding,
            BondingSlot::new(registry),
            params,
        )
        .unwrap()
        .into_registry();
    }
    assert_eq!(registry.num_internal_circuits(), nested.internal());
    assert!(matches!(
        P::register_nested_circuit::<Pasta, TestR>(
            0,
            CircuitSlot::new(RegistryBuilder::new()),
            params
        ),
        Err(Error::Initialization(_))
    ));
}

/// The profile's shape is wider than the standard one, and an application
/// over it builds its registries at the aggregator rank: every fuse
/// circuit fits the budget with the extension's polynomials, and every
/// chunk circuit registers beside them. Finalizing then proves the
/// bootstrap, which stops at the extension's prover, the next step.
#[test]
fn the_fuse_fits_at_the_aggregator_rank() {
    let standard = Shape::of::<Standard>();
    let shape = Shape::of::<P>();
    assert_eq!(
        shape.native_rx,
        standard.native_rx + P::NATIVE_EXTENSION + shape.native_steps - standard.native_steps
    );
    assert!(shape.nested_steps > standard.nested_steps);

    let result = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
        .finalize(crate::pasta::baked_aggregator());
    assert!(
        matches!(result, Err(Error::Initialization(_))),
        "the registries build and the bootstrap stops at the extension's prover"
    );
}
