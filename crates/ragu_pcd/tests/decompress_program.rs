//! The chunk schedules: they cut both sides of the verifier into chunks,
//! each slot written by one chunk before any reads it, the transcripts cut
//! only where the sponge allows, and the counts reported.

use alloc::vec::Vec;

use ragu_circuits::polynomials::{AggregatorRank, ProductionRank, Rank};
use ragu_core::{Cycle, PoseidonPermutation, pasta::Pasta};

use super::{
    Chunk, ElementSrc, Last, Limits, Op, PointSrc, Schedule, Step, native_schedule, nested_schedule,
};

const HEADER_SIZE: usize = 4;
/// The sponge state's width.
const STATE: usize =
    <<Pasta as Cycle>::CircuitPoseidon as PoseidonPermutation<<Pasta as Cycle>::CircuitField>>::T;

/// Every work slot a chunk reads was written by an earlier chunk, or is
/// prover-supplied, every slot is written at most once, every sponge
/// state is saved before it is resumed, every lift and digit is written,
/// every exposed point is written, and every stage position read is
/// within the layout.
fn check(schedule: &Schedule) {
    let layout = &schedule.layout;
    let mut elements = alloc::vec![false; schedule.elements];
    let mut points = alloc::vec![false; schedule.points];
    let mut states = alloc::vec![false; schedule.states];
    let mut lifts = alloc::vec![false; layout.lifts];
    let mut digits = alloc::vec![false; layout.digits];
    let digit_scalars: usize = schedule
        .chunks
        .iter()
        .map(|chunk| match chunk {
            Chunk::Digits { scalars } => scalars.len(),
            _ => 0,
        })
        .sum();
    let width = layout.digits / digit_scalars;
    assert_eq!(width * digit_scalars, layout.digits, "whole scalars");
    let regions = &schedule.regions;
    for &slot in regions
        .restrictions
        .iter()
        .flatten()
        .chain(&regions.registry_values)
        .chain([&regions.restriction_at_w])
    {
        elements[slot] = true;
    }
    for &slot in regions.inverse_scaled.iter().chain([&regions.g_prime]) {
        points[slot] = true;
    }
    let read_point = |src: &PointSrc, points: &[bool]| match src {
        PointSrc::Work(slot) => assert!(points[*slot], "point slot {slot} read before written"),
        PointSrc::Instance(p) => assert!(*p < layout.instance.points),
        PointSrc::Message(p) => assert!(*p < layout.messages.points),
        PointSrc::Bridge(p) => assert!(*p < layout.transcript.points),
        PointSrc::Generator(_) | PointSrc::U => {}
    };
    let read_element =
        |src: &ElementSrc, elements: &[bool], points: &[bool], lifts: &[bool]| match src {
            ElementSrc::Work(slot) => {
                assert!(elements[*slot], "element slot {slot} read before written")
            }
            ElementSrc::Lift(slot) => assert!(lifts[*slot], "lift slot {slot} read before written"),
            ElementSrc::Instance(p) | ElementSrc::InstanceSquared(p) => {
                assert!(*p < layout.instance.elements)
            }
            ElementSrc::Message(p) => assert!(*p < layout.messages.elements),
            ElementSrc::Coordinate(point, which) => {
                assert!(*which < 2);
                read_point(point, points);
            }
        };
    let write_element = |slot: usize, elements: &mut [bool]| {
        assert!(!elements[slot], "element slot {slot} written twice");
        elements[slot] = true;
    };
    let write_point = |slot: usize, points: &mut [bool]| {
        assert!(!points[slot], "point slot {slot} written twice");
        points[slot] = true;
    };
    for chunk in &schedule.chunks {
        match chunk {
            Chunk::Transcript {
                state_in,
                ops,
                state_out,
                ..
            } => {
                if let Some(state) = state_in {
                    for i in 0..STATE {
                        assert!(states[state + i], "state {state} resumed before saved");
                    }
                }
                for op in ops {
                    match op {
                        Op::Absorb(src) => read_element(src, &elements, &points, &lifts),
                        Op::AbsorbConst(_) => {}
                        Op::Squeeze(slot) => write_element(*slot, &mut elements),
                    }
                }
                if let Some(state) = state_out {
                    for i in 0..STATE {
                        assert!(!states[state + i], "state {state} saved twice");
                        states[state + i] = true;
                    }
                }
            }
            Chunk::Lift { pairs } => {
                for (_, out) in pairs {
                    assert!(!lifts[*out], "lift slot {out} written twice");
                    lifts[*out] = true;
                }
            }
            Chunk::Targets { out } => {
                for &slot in out {
                    write_element(slot, &mut elements);
                }
            }
            Chunk::RevdotWeights { out } => {
                for &slot in out {
                    write_element(slot, &mut elements);
                }
            }
            Chunk::Bindings { out } => {
                for slots in out {
                    for &slot in slots {
                        write_element(slot, &mut elements);
                    }
                }
            }
            Chunk::RevdotPublic { out } => write_element(*out, &mut elements),
            Chunk::BatchIpa { out } => {
                for &slot in out {
                    write_element(slot, &mut elements);
                }
            }
            Chunk::Digits { scalars } => {
                for (src, first) in scalars {
                    read_element(src, &elements, &points, &lifts);
                    for (slot, written) in digits.iter_mut().enumerate().skip(*first).take(width) {
                        assert!(!*written, "digit slot {slot} written twice");
                        *written = true;
                    }
                }
            }
            Chunk::Sums { sums } => {
                for (out, terms) in sums {
                    for term in terms {
                        read_point(term, &points);
                    }
                    write_point(*out, &mut points);
                }
            }
            Chunk::Chain(chain) => {
                if let Some(init) = &chain.init {
                    read_point(init, &points);
                }
                for step in &chain.steps {
                    match step {
                        Step::Horner { add, .. } => {
                            if let Some(add) = add {
                                read_point(add, &points);
                            }
                        }
                        Step::AddScaled { point, .. } => read_point(point, &points),
                    }
                }
                write_point(chain.out, &mut points);
            }
            Chunk::Checks { checks } => {
                for (point, _, expected) in checks {
                    read_point(point, &points);
                    read_point(expected, &points);
                }
            }
            Chunk::Scale {
                point,
                init,
                out,
                digits: (lo, hi),
                bind,
                ..
            } => {
                read_point(point, &points);
                if let Some(init) = init {
                    assert!(points[*init], "a scaling continues a written part");
                }
                write_point(*out, &mut points);
                if let Some(bind) = bind {
                    assert_eq!(bind.generators.len(), hi - lo, "one generator per digit");
                    if let Some(init) = bind.init {
                        assert!(points[init], "a binding continues a written part");
                    }
                    write_point(bind.out, &mut points);
                }
            }
            Chunk::Sign { out, .. } => write_point(*out, &mut points),
            Chunk::Equal { left, right } => {
                read_point(left, &points);
                read_point(right, &points);
            }
        }
    }
    assert!(
        states.iter().all(|&saved| saved),
        "every state slot is saved"
    );
    assert!(
        lifts.iter().all(|&written| written),
        "every lift is written"
    );
    assert!(
        digits.iter().all(|&written| written),
        "every digit is written"
    );
    for &slot in &regions.exposed {
        assert!(points[slot], "exposed point {slot} is written");
    }
}

/// Both sides' schedules for a production-rank proof in chunk circuits at
/// rank `R` are consistent, and their counts are reported.
fn schedules_are_consistent<R: Rank>() {
    let native = native_schedule::<Pasta, ProductionRank, R, HEADER_SIZE>().unwrap();
    let nested = nested_schedule::<Pasta, ProductionRank, R, HEADER_SIZE>().unwrap();
    check(&native);
    check(&nested);
    let kinds = |schedule: &Schedule| {
        let mut counts: Vec<(&str, usize)> = Vec::new();
        for chunk in &schedule.chunks {
            let name = match chunk {
                Chunk::Transcript { .. } => "transcript",
                Chunk::Lift { .. } => "lift",
                Chunk::Targets { .. } => "targets",
                Chunk::RevdotWeights { .. } => "revdot weights",
                Chunk::Bindings { .. } => "bindings",
                Chunk::RevdotPublic { .. } => "revdot public",
                Chunk::BatchIpa { .. } => "batch and ipa scalars",
                Chunk::Digits { .. } => "digits",
                Chunk::Sums { .. } => "sums",
                Chunk::Chain(_) => "chain",
                Chunk::Checks { .. } => "checks",
                Chunk::Scale { .. } => "scale",
                Chunk::Sign { .. } => "sign",
                Chunk::Equal { .. } => "equal",
            };
            match counts.iter_mut().find(|(n, _)| *n == name) {
                Some((_, count)) => *count += 1,
                None => counts.push((name, 1)),
            }
        }
        counts
    };
    for (name, schedule) in [("native", &native), ("nested", &nested)] {
        std::println!(
            "{name} at rank {}: {} chunks, {} work elements, {} work points, {} states: {:?}",
            R::RANK,
            schedule.chunks.len(),
            schedule.elements,
            schedule.points,
            schedule.states,
            kinds(schedule)
        );
    }
}

#[test]
fn production_rank_schedules_are_consistent() {
    schedules_are_consistent::<ProductionRank>();
}

#[test]
fn aggregator_rank_schedules_are_consistent() {
    schedules_are_consistent::<AggregatorRank>();
}

/// The production rank's limits are the fitted ones; the aggregator rank's
/// hold twice the work per chunk, a full-width scaling in one chunk, and
/// pack circuits to seven eighths of the budget.
#[test]
fn limits_scale_with_the_rank() {
    assert_eq!(Limits::at::<ProductionRank>(), Limits::FITTED);
    let fitted = Limits::FITTED;
    assert_eq!(
        Limits::at::<AggregatorRank>(),
        Limits {
            scalings: 2 * fitted.scalings,
            permutations: 2 * fitted.permutations,
            lifts: 2 * fitted.lifts,
            checks: 2 * fitted.checks,
            sums: 2 * fitted.sums,
            digits: 2 * fitted.digits,
            scale_parts: 1,
            fill: AggregatorRank::n() / 8 * 7,
        }
    );
}

/// The native chunk count grows with the header size, since the
/// compression's transcript absorbs the three headers; the nested count
/// does not, so a profile pinning the counts pins them per header size.
#[test]
fn native_counts_follow_the_header_size() {
    use super::chunk_counts;
    let (native_small, nested_small) =
        chunk_counts::<Pasta, ProductionRank, AggregatorRank, 4>().unwrap();
    let (native_large, nested_large) =
        chunk_counts::<Pasta, ProductionRank, AggregatorRank, 103>().unwrap();
    std::println!(
        "aggregator rank: {native_small}/{nested_small} chunks at header size 4, \
         {native_large}/{nested_large} at 103"
    );
    assert!(native_large > native_small);
    assert_eq!(nested_large, nested_small);
}

/// The circuits partition the chunks in order, the transcript circuits
/// first and holding transcript chunks alone, and the counts are reported.
fn circuits_pack_the_chunks<R: Rank>() {
    for (name, schedule) in [
        (
            "native",
            native_schedule::<Pasta, ProductionRank, R, HEADER_SIZE>().unwrap(),
        ),
        (
            "nested",
            nested_schedule::<Pasta, ProductionRank, R, HEADER_SIZE>().unwrap(),
        ),
    ] {
        let mut next = 0;
        let mut seen = Last::Transcript;
        for circuit in &schedule.circuits {
            assert_eq!(circuit.chunks.start, next, "{name}: consecutive");
            assert!(!circuit.chunks.is_empty(), "{name}: no empty circuit");
            next = circuit.chunks.end;
            assert!(
                schedule.chunks[circuit.chunks.clone()]
                    .iter()
                    .all(|chunk| chunk.last() == circuit.last),
                "{name}: a circuit's chunks share their last stage"
            );
            // Transcript circuits first, then work, then digits.
            let order = |last: Last| match last {
                Last::Transcript => 0,
                Last::Work => 1,
                Last::Digits => 2,
            };
            assert!(
                order(circuit.last) >= order(seen),
                "{name}: circuits in transcript, work, digits order"
            );
            seen = circuit.last;
        }
        assert_eq!(next, schedule.chunks.len(), "{name}: every chunk");
        let count = |last: Last| schedule.circuits.iter().filter(|c| c.last == last).count();
        std::println!(
            "{name} at rank {}: {} circuits ({} transcript, {} digits) over {} chunks",
            R::RANK,
            schedule.circuits.len(),
            count(Last::Transcript),
            count(Last::Digits),
            schedule.chunks.len()
        );
    }
}

#[test]
fn production_rank_circuits_pack_the_chunks() {
    circuits_pack_the_chunks::<ProductionRank>();
}

#[test]
fn aggregator_rank_circuits_pack_the_chunks() {
    circuits_pack_the_chunks::<AggregatorRank>();
}
