//! The stage layout the compression and the chunk circuits share: the
//! generators the arithmetic layout names for each run stage, the trailing
//! stage, the lifts stage and the digits stage are the ones the stage types
//! land their wires on, on both sides, so the compression's run commitments
//! are the run stages' commitments and each side's recomputations are the
//! other side's stages'.

use alloc::vec::Vec;

use ragu_circuits::{
    polynomials::{AggregatorRank, ProductionRank},
    staging::{stage_wire_indices, wire_degree, wires_of},
};
use ragu_core::{
    Cycle, FixedGenerators,
    pasta::{Fp, Fq, Pasta},
};
use udon::curve::Affine as _;

use super::{
    DigitsStage, Layout, LiftsStage, RunIndex, Runs, TrailingStage, digits_degrees, lifts_degrees,
    nested_front, num_runs, run_bases, run_degrees, trailing_source,
};
use crate::{
    decompress::{
        side::{Native, Nested},
        support::HEADER_SIZE,
    },
    ipa::IpaCycle,
    profile::Standard,
};

type K = ProductionRank;
type R = AggregatorRank;

/// The generators a values stage's wires land on, read off `$stage` over
/// the field `$f`.
macro_rules! typed {
    ($f:ty, $stage:ty) => {
        stage_wire_indices::<$f, R, $stage>(|out| {
            let mut wires = wires_of(&out.points)?;
            wires.extend(wires_of(&out.elements)?);
            Ok(wires)
        })
        .unwrap()
        .into_iter()
        .map(wire_degree::<R>)
        .collect::<Vec<usize>>()
    };
}

/// Every run stage lands its wires where the arithmetic layout says, in
/// the run's absorption order, and the trailing stage after them.
#[test]
fn run_stages_land_where_the_layout_says() {
    let layout = Layout::nested::<Fq, Standard, K>();
    let degrees = run_degrees::<K, R>(&layout);
    assert_eq!(degrees.len(), num_runs::<K>());
    for (index, expected) in degrees.iter().enumerate() {
        let typed = <K as Runs>::Last::wire_degrees::<Pasta, K, R>(index).unwrap();
        assert_eq!(&typed, expected, "run {index}");
        assert_eq!(
            expected.len(),
            nested_front::<K>(&layout)[index].shape().values()
        );
    }
    let trailing = typed!(Fq, TrailingStage<Pasta, K, R>);
    let skip = 1 + nested_front::<K>(&layout)[..num_runs::<K>()]
        .iter()
        .map(|source| source.shape().gates())
        .sum::<usize>();
    let shape = trailing_source(&layout).shape();
    let (_, expected) = super::shape_degrees::<R>(skip, shape);
    assert_eq!(trailing, expected);
}

/// The lifts and digits stages of both sides land their wires where the
/// arithmetic layout says, which the other side recomputes them at.
#[test]
fn lifts_and_digits_stages_land_where_the_layout_says() {
    assert_eq!(
        typed!(Fq, LiftsStage<Pasta, Nested, K, R, HEADER_SIZE>),
        lifts_degrees::<Pasta, Nested, K, R, HEADER_SIZE>()
    );
    assert_eq!(
        typed!(Fq, DigitsStage<Pasta, Nested, K, R, HEADER_SIZE>),
        digits_degrees::<Pasta, Nested, K, R, HEADER_SIZE>()
    );
    assert_eq!(
        typed!(Fp, LiftsStage<Pasta, Native, K, R, HEADER_SIZE>),
        lifts_degrees::<Pasta, Native, K, R, HEADER_SIZE>()
    );
    assert_eq!(
        typed!(Fp, DigitsStage<Pasta, Native, K, R, HEADER_SIZE>),
        digits_degrees::<Pasta, Native, K, R, HEADER_SIZE>()
    );
}

/// The Standard parameters reach every run's generators through the baked
/// stage reach, at the same points as the aggregator's table, so a wallet
/// over `baked()` and its aggregator over `baked_aggregator()` commit a
/// run alike.
#[test]
fn standard_parameters_reach_the_runs_generators() {
    let layout = Layout::nested::<Fq, Standard, K>();
    let gates: usize = nested_front::<K>(&layout)[..num_runs::<K>()]
        .iter()
        .map(|source| source.shape().gates())
        .sum();
    assert!(
        gates <= crate::pasta::STAGE_REACH,
        "the runs take {gates} gates, past the baked stage reach"
    );
    let standard = run_bases::<Pasta, K>(crate::pasta::baked()).unwrap();
    let aggregator = run_bases::<Pasta, K>(crate::pasta::baked_aggregator()).unwrap();
    assert_eq!(standard, aggregator);
    let table = Pasta::nested_generators(crate::pasta::baked_aggregator()).g();
    for (bases, degrees) in standard.iter().zip(run_degrees::<K, R>(&layout)) {
        for (base, degree) in bases.iter().zip(degrees) {
            assert!(
                degree >= Pasta::nested_generators(crate::pasta::baked()).g().len(),
                "the runs lie past the Standard table"
            );
            assert_eq!(*base, table[degree]);
            assert!(!base.is_identity());
        }
    }
    assert_eq!(
        Pasta::nested_generator(crate::pasta::baked(), table.len()),
        None,
        "nothing past the aggregator rank"
    );
}
