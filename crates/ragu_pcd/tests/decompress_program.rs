//! The chunk schedules: they cut both sides of the verifier into chunks,
//! each slot written by one chunk before any reads it, the transcripts cut
//! only where the sponge allows, and the counts reported.

use alloc::vec::Vec;

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{Cycle, PoseidonPermutation, pasta::Pasta};

use super::{Chunk, ElementSrc, Op, PointSrc, Schedule, Step, native_schedule, nested_schedule};

const HEADER_SIZE: usize = 4;
/// The sponge state's width.
const STATE: usize =
    <<Pasta as Cycle>::CircuitPoseidon as PoseidonPermutation<<Pasta as Cycle>::CircuitField>>::T;

/// Every work slot a chunk reads was written by an earlier chunk, or is
/// prover-supplied, every slot is written at most once, every sponge
/// state is saved before it is resumed, and every stage position read is
/// within the layout.
fn check(schedule: &Schedule) {
    let layout = &schedule.layout;
    let mut elements = alloc::vec![false; schedule.elements];
    let mut points = alloc::vec![false; schedule.points];
    let mut states = alloc::vec![false; schedule.states];
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
    let read_element = |src: &ElementSrc, elements: &[bool], points: &[bool]| match src {
        ElementSrc::Work(slot) => {
            assert!(elements[*slot], "element slot {slot} read before written")
        }
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
            } => {
                if let Some(state) = state_in {
                    for i in 0..STATE {
                        assert!(states[state + i], "state {state} resumed before saved");
                    }
                }
                for op in ops {
                    match op {
                        Op::Absorb(src) => read_element(src, &elements, &points),
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
                    write_element(*out, &mut elements);
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
                for src in scalars {
                    read_element(src, &elements, &points);
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
                point, init, out, ..
            } => {
                read_point(point, &points);
                if let Some(init) = init {
                    assert!(points[*init], "a scaling continues a written part");
                }
                write_point(*out, &mut points);
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
}

#[test]
fn schedules_are_consistent() {
    let native = native_schedule::<Pasta, ProductionRank, HEADER_SIZE>().unwrap();
    let nested = nested_schedule::<Pasta, ProductionRank, HEADER_SIZE>().unwrap();
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
            "{name}: {} chunks, {} work elements, {} work points, {} states: {:?}",
            schedule.chunks.len(),
            schedule.elements,
            schedule.points,
            schedule.states,
            kinds(schedule)
        );
    }
}
