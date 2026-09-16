//! T08: authenticate all saved-state coordinates, then resume in the right
//! order. The prefix and unrelated semantic wires remain pinned. Hashes1's
//! state-copy cut has a satisfying local witness; Hashes2 accepts a suffix
//! recomputed from a false state, demonstrating where authentication belongs.

use alloc::vec;

use ragu_arithmetic::CurveAffine;
use ragu_testing::patcher::{Capture, Event};

use super::*;
use crate::fuse::tests::transcript_tests::replay_for;

type Seed = HeaderStep<(), (), ApplicationHeader, 0>;
type Merge = HeaderStep<ApplicationHeader, ApplicationHeader, ApplicationHeader, 1>;
type Outer<C> = native::stages::outer_error::Stage<C, R, 4, native::RevdotParameters>;

const CHALLENGES: [&str; 11] = [
    "w", "y", "z", "mu", "nu", "mu_prime", "nu_prime", "x", "alpha", "u", "pre_beta",
];

fn points<C: Cycle>(cap: &Capture<C::CircuitField>) -> [C::NestedCurve; 8] {
    [
        "bridge_preamble_commitment",
        "bridge_s_prime_commitment",
        "bridge_inner_error_commitment",
        "bridge_outer_error_commitment",
        "bridge_ab_commitment",
        "bridge_query_commitment",
        "bridge_f_commitment",
        "bridge_eval_commitment",
    ]
    .map(|name| {
        let xy = unified_slot_positions(name);
        C::NestedCurve::from_xy(
            cap.recorder.values[cap.instance[xy[0]]],
            cap.recorder.values[cap.instance[xy[1]]],
        )
        .unwrap()
    })
}

fn state_wires<C: Cycle>(cap: &Capture<C::CircuitField>) -> Result<Vec<usize>> {
    Ok(
        stage_wire_indices::<C::CircuitField, R, Outer<C>>(|s| wires_of(&s.sponge_state))?
            .into_iter()
            .map(|i| cap.stage_wires[i])
            .collect(),
    )
}

fn challenge_wires<F: Field>(cap: &Capture<F>) -> [usize; 11] {
    CHALLENGES.map(|name| cap.instance[unified_slot_positions(name)[0]])
}

fn repaired<F: Field>(cap: &Capture<F>, edits: &[(usize, F)], cuts: &[usize]) -> Vec<F> {
    let mut values = cap.recorder.values.clone();
    for &(wire, value) in edits {
        values[wire] = value;
    }
    let pins: Vec<_> = cap
        .instance
        .iter()
        .chain(&cap.stage_wires)
        .copied()
        .collect();
    let before = values.clone();
    let remaining: Vec<_> = cap
        .recorder
        .events
        .iter()
        .enumerate()
        .filter(|(i, _)| !cuts.contains(i))
        .map(|(_, e)| e.clone())
        .collect();
    repair(&remaining, &mut values, &pins);
    for pin in pins {
        assert_eq!(values[pin], before[pin], "semantic pin {pin}");
    }
    values
}

fn check_live<'w, F: Field, Cir: Circuit<F>>(
    cap: &Capture<F>,
    circuit: &Cir,
    witness: &impl Fn() -> Result<Cir::Witness<'w>>,
    values: Vec<F>,
    accepted: bool,
) -> Result<()> {
    let recorded = constraints_hold(&cap.recorder.events, &values);
    let live = playback(circuit, witness()?, values)?;
    assert_eq!(recorded, live);
    assert_eq!(live, accepted, "recorded/live saved-state verdict");
    Ok(())
}

struct Checker<'params, C: Cycle> {
    params: &'params C::Params,
    donor: Option<Vec<C::CircuitField>>,
    observed: Vec<C::CircuitField>,
    visited: [usize; 2],
}

impl<C: Cycle> InternalCircuitVisitor<C> for Checker<'_, C> {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let index = match spec.name.as_str() {
            "hashes_1" => 0,
            "hashes_2" => 1,
            _ => return Ok(()),
        };
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        let wires = state_wires::<C>(&cap)?;
        let state: Vec<_> = wires.iter().map(|w| cap.recorder.values[*w]).collect();
        let points = points::<C>(&cap);
        let expected = replay_for::<C>(self.params, &points, None, &[])?;
        let challenge_wires = challenge_wires(&cap);
        let challenges = challenge_wires.map(|w| cap.recorder.values[w]);
        assert_eq!(
            state, expected.state,
            "Hashes1 state matches independent prefix"
        );
        assert_eq!(
            challenges, expected.challenges,
            "live circuit squeeze order"
        );
        assert_eq!(
            replay_for::<C>(self.params, &points, Some((&state, 0)), &[])?.challenges,
            challenges
        );
        check_live(
            &cap,
            circuit,
            &make_witness,
            cap.recorder.values.clone(),
            true,
        )?;
        if index == 0 {
            self.observed = state.clone();
        } else {
            assert_eq!(
                state, self.observed,
                "both circuits share the same staged state"
            );
        }
        let Some(donor) = &self.donor else {
            self.visited[index] += 1;
            return Ok(());
        };
        assert_eq!(state.len(), 5, "all Pasta sponge coordinates");
        assert_eq!(donor.len(), state.len());
        for (coordinate, &wire) in wires.iter().enumerate() {
            assert_ne!(donor[coordinate], state[coordinate]);
            let mut spliced = state.clone();
            spliced[coordinate] = donor[coordinate];
            if index == 0 {
                // Only the direct computed-state/staged-state equality may
                // be removed. All permutations, copies and other checks stay.
                let cuts: Vec<_> = cap
                    .recorder
                    .events
                    .iter()
                    .enumerate()
                    .filter_map(|(i, e)| match e {
                        Event::Enforce { terms }
                            if terms.len() == 2
                                && terms.iter().any(|(w, _)| *w == wire)
                                && terms[0].1 != C::CircuitField::ZERO
                                && terms[0].1 == -terms[1].1 =>
                        {
                            Some(i)
                        }
                        _ => None,
                    })
                    .collect();
                let values = repaired(&cap, &[(wire, donor[coordinate])], &cuts);
                let remaining: Vec<_> = cap
                    .recorder
                    .events
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !cuts.contains(i))
                    .map(|(_, e)| e.clone())
                    .collect();
                assert!(
                    constraints_hold(&remaining, &values),
                    "satisfying state-copy cut"
                );
                check_live(&cap, circuit, &make_witness, values.clone(), false)?;
                assert_eq!(cuts.len(), 1, "one authentication edge per coordinate");
                let Event::Enforce { terms } = &cap.recorder.events[cuts[0]] else {
                    unreachable!()
                };
                let residual: C::CircuitField = terms.iter().map(|(w, c)| values[*w] * c).sum();
                let weight = terms.iter().find(|(w, _)| *w == wire).unwrap().1;
                assert_eq!(residual, weight * (donor[coordinate] - state[coordinate]));
            } else {
                let suffix =
                    replay_for::<C>(self.params, &points, Some((&spliced, 0)), &[])?.challenges;
                assert_eq!(suffix[..3], challenges[..3]);
                assert_ne!(suffix[3..], challenges[3..]);
                let mut edits = vec![(wire, donor[coordinate])];
                edits.extend(
                    challenge_wires[3..]
                        .iter()
                        .copied()
                        .zip(suffix[3..].iter().copied()),
                );
                // Fully consistent later advice accepts in Hashes2. The
                // frozen prefix still rejects this state in Hashes1 above.
                let values = repaired(&cap, &edits, &[]);
                check_live(&cap, circuit, &make_witness, values, true)?;
                // Change one derived output while retaining the same false
                // state: output determinism remains enforced independently.
                edits.push((challenge_wires[7], suffix[7] + C::CircuitField::ONE));
                let values = repaired(&cap, &edits, &[]);
                check_live(&cap, circuit, &make_witness, values, false)?;
            }
            self.visited[index] += 1;
        }
        if index == 1 {
            // Skip a buffered block, crossing a permutation boundary, and
            // repair every later challenge. The source state stays frozen.
            let wrong = replay_for::<C>(self.params, &points, Some((&state, 4)), &[])?.challenges;
            assert_ne!(wrong[3..], challenges[3..]);
            // mu and nu alias the stage coordinates; never overwrite them
            // while claiming the state is pinned. Their numerical mismatch
            // already detects the boundary error. Test the derived suffix
            // separately with those two source coordinates held fixed.
            assert_ne!(wrong[3], challenges[3]);
            assert_ne!(wrong[5..], challenges[5..]);
            let edits: Vec<_> = challenge_wires[5..]
                .iter()
                .copied()
                .zip(wrong[5..].iter().copied())
                .collect();
            let values = repaired(&cap, &edits, &[]);
            check_live(&cap, circuit, &make_witness, values, false)?;
        }
        Ok(())
    }
}

fn exercise(base_case: bool) -> Result<()> {
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(Seed::new())?
        .register(Merge::new())?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x873_0801);
    let left = app.seed(&mut rng, Seed::new(), Fp::from(17))?.0;
    let right = app.seed(&mut rng, Seed::new(), Fp::from(71))?.0;
    let mut checker = Checker::<Pasta> {
        params: Pasta::baked(),
        donor: None,
        observed: Vec::new(),
        visited: [0; 2],
    };
    for seed in [0x873_0802, 0x873_0803] {
        let mut rng = StdRng::seed_from_u64(seed);
        if base_case {
            capture_internal_circuits_seeded(
                &app,
                &mut rng,
                Seed::new(),
                Fp::from(88),
                &mut checker,
            )?;
        } else {
            capture_internal_circuits(
                &app,
                &mut rng,
                Merge::new(),
                Fp::from(88),
                left.clone(),
                right.clone(),
                &mut checker,
            )?;
        }
        if checker.donor.is_none() {
            checker.donor = Some(checker.observed.clone());
        }
    }
    assert_eq!(
        checker.visited,
        [6, 6],
        "donor plus every coordinate in both circuits"
    );
    Ok(())
}

#[test]
fn saved_transcript_state_splices_and_squeeze_order_seed() -> Result<()> {
    exercise(true)
}

#[test]
fn saved_transcript_state_splices_and_squeeze_order_fused() -> Result<()> {
    exercise(false)
}
