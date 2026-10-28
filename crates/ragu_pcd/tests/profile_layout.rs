//! Profile identity and fixed wire traversal for the native value gadgets.

use core::any::TypeId;

use ragu_circuits::{polynomials::ProductionRank, staging::Stage};
use ragu_core::{
    Error, Result,
    convert::extract_wires,
    gadgets::Gadget,
    maybe::Maybe,
    pasta::{Fp, Pasta},
};
use ragu_primitives::{Element, Simulator};
use udon::field::Field;

use crate::{
    internal::{
        native::{
            InternalCircuitIndex, InternalCircuitValues, RxIndex, RxValues,
            stages::{eval, query},
        },
        tests::assert_stage_values,
    },
    profile::{
        Aggregator, Profile, Profiled, Standard,
        testing::{Twin, Wider},
    },
};

#[test]
fn equal_shapes_keep_distinct_gadget_kinds() {
    type StdQuery =
        <query::Stage<Pasta, ProductionRank, 4> as Stage<Fp, ProductionRank>>::OutputKind;
    type TwinQuery = <query::Stage<Profiled<Pasta, Twin>, ProductionRank, 4> as Stage<
        Fp,
        ProductionRank,
    >>::OutputKind;
    type StdEval = <eval::Stage<Pasta, ProductionRank, 4> as Stage<Fp, ProductionRank>>::OutputKind;
    type TwinEval = <eval::Stage<Profiled<Pasta, Twin>, ProductionRank, 4> as Stage<
        Fp,
        ProductionRank,
    >>::OutputKind;

    assert_eq!(
        query::Stage::<Pasta, ProductionRank, 4>::values(),
        query::Stage::<Profiled<Pasta, Twin>, ProductionRank, 4>::values()
    );
    assert_eq!(
        eval::Stage::<Pasta, ProductionRank, 4>::values(),
        eval::Stage::<Profiled<Pasta, Twin>, ProductionRank, 4>::values()
    );
    assert_ne!(TypeId::of::<StdQuery>(), TypeId::of::<TwinQuery>());
    assert_ne!(TypeId::of::<StdEval>(), TypeId::of::<TwinEval>());
}

fn check_traversal<P: Profile>() -> Result<()> {
    let mut dr = Simulator::<Fp>::new();
    let internal_ids = InternalCircuitIndex::all::<P>();
    let rx_ids = RxIndex::all::<P>();

    let mut position = 0;
    let internal = InternalCircuitValues::<_, P>::from_fn(|id| {
        assert_eq!(id, internal_ids[position]);
        position += 1;
        Element::constant(&mut dr, Fp::from(position as u64))
    });
    let internal_wires = extract_wires(&internal, |wire| *wire)?;
    assert_eq!(
        internal_wires,
        (1..=internal_ids.len())
            .map(|i| Fp::from(i as u64))
            .collect::<alloc::vec::Vec<_>>()
    );
    assert_eq!(internal.num_wires()?, internal_ids.len());
    dr.reset();
    internal.enforce_conservative_equal(&mut dr, &internal.clone())?;
    assert_eq!(dr.num_constraints(), internal_ids.len());
    for &changed in &internal_ids {
        let other = InternalCircuitValues::<_, P>::from_fn(|id| {
            let value = *internal.get(id).value().take();
            Element::constant(
                &mut dr,
                value + if id == changed { Fp::ONE } else { Fp::ZERO },
            )
        });
        assert!(
            matches!(
                internal.enforce_conservative_equal(&mut dr, &other),
                Err(Error::InvalidWitness(_))
            ),
            "omitted internal value {changed:?}"
        );
    }

    let mut position = 0;
    let rx = RxValues::<_, P>::from_fn(|id| {
        assert_eq!(id, rx_ids[position]);
        position += 1;
        Element::constant(&mut dr, Fp::from(position as u64))
    });
    let rx_wires = extract_wires(&rx, |wire| *wire)?;
    assert_eq!(
        rx_wires,
        (1..=rx_ids.len())
            .map(|i| Fp::from(i as u64))
            .collect::<alloc::vec::Vec<_>>()
    );
    assert_eq!(rx.num_wires()?, rx_ids.len());
    dr.reset();
    rx.enforce_conservative_equal(&mut dr, &rx.clone())?;
    assert_eq!(dr.num_constraints(), rx_ids.len());
    for &changed in &rx_ids {
        let other = RxValues::<_, P>::from_fn(|id| {
            let value = *rx.get(id).value().take();
            Element::constant(
                &mut dr,
                value + if id == changed { Fp::ONE } else { Fp::ZERO },
            )
        });
        assert!(
            matches!(
                rx.enforce_conservative_equal(&mut dr, &other),
                Err(Error::InvalidWitness(_))
            ),
            "omitted rx value {changed:?}"
        );
    }
    Ok(())
}

#[test]
fn mapping_and_equality_visit_every_profile_value() -> Result<()> {
    check_traversal::<Standard>()?;
    check_traversal::<Twin>()?;
    check_traversal::<Aggregator<4>>()?;
    check_traversal::<Wider>()
}

#[test]
fn allocation_matches_the_profile_stage_sizes() {
    assert_stage_values(&query::Stage::<Pasta, ProductionRank, 4>::default());
    assert_stage_values(&eval::Stage::<Pasta, ProductionRank, 4>::default());
    assert_stage_values(&query::Stage::<Profiled<Pasta, Twin>, ProductionRank, 4>::default());
    assert_stage_values(&eval::Stage::<Profiled<Pasta, Twin>, ProductionRank, 4>::default());
    assert_stage_values(&query::Stage::<Profiled<Pasta, Wider>, ProductionRank, 4>::default());
    assert_stage_values(&eval::Stage::<Profiled<Pasta, Wider>, ProductionRank, 4>::default());
}
