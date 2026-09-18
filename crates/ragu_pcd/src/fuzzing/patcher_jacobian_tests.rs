//! O06: Jacobian-kernel proposals against production accumulator circuits.
//!
//! Public instance wires and the whole staged commitment frontier stay
//! frozen. The intact graph admits movement only in genuinely slack pooled
//! allocator advice, which must preserve every declared output under exact
//! finite-field evaluation and live playback. As a mutation calibration, a
//! smallest direct accumulator-contract cut is then found: the sparse kernel
//! must expose its stage output, the cut graph must accept the exact moved
//! witness, and both the complete recording and live circuit must reject it.

use ragu_testing::patcher::{
    Capture, Event, ProbeOutcome, allocation_waste, constraints_hold, jacobian_kernel,
    jacobian_probe, jacobian_witness, playback,
};

use super::*;

type Leaf = HeaderStep<(), (), ApplicationHeader, 0>;
type Both = HeaderStep<ApplicationHeader, ApplicationHeader, ApplicationHeader, 1>;

struct Checker {
    visited: [bool; 2],
}

impl Checker {
    fn check<'w, F: Field, Cir: Circuit<F>>(
        &self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[F],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let cap = capture_with_stage_values(circuit, make_witness()?, stage_values)?;
        let context = &spec.name;
        let honest = &cap.recorder.values;
        assert!(constraints_hold(&cap.recorder.events, honest), "{context}");
        assert!(
            playback(circuit, make_witness()?, honest.clone())?,
            "{context}: honest live playback"
        );
        let resolution = spec.resolve(&cap.instance, &cap.stage_wires)?;

        self.check_allocator_slack(&cap, &resolution, circuit, &make_witness, context)?;
        self.check_accumulator_cut(&cap, &resolution, circuit, &make_witness, context)?;
        Ok(())
    }

    fn check_allocator_slack<'w, F: Field, Cir: Circuit<F>>(
        &self,
        cap: &Capture<F>,
        resolution: &Resolution,
        circuit: &Cir,
        make_witness: &impl Fn() -> Result<Cir::Witness<'w>>,
        context: &str,
    ) -> Result<()> {
        let honest = &cap.recorder.values;
        let frontier: Vec<_> = cap
            .instance
            .iter()
            .chain(&cap.stage_wires)
            .copied()
            .collect();

        for (b, c) in allocation_waste(&cap.recorder.events, honest) {
            if frontier.contains(&b) || frontier.contains(&c) {
                continue;
            }
            // The allocation gate is a·b=c with honest b=c=0. Its sparse
            // kernel coordinates the otherwise wasted b and c wires; this
            // is an exact affine relation, even when c also has c·d=0.
            let basis = jacobian_kernel(&cap.recorder.events, honest, &[b, c]);
            let Some(direction) = basis.iter().find(|direction| direction.entries().len() > 1)
            else {
                continue;
            };
            let committed: Vec<_> = direction.entries().iter().map(|(wire, _)| *wire).collect();
            let Some(candidate) = jacobian_witness(
                &cap.recorder.events,
                honest,
                &frontier,
                direction,
                F::ONE,
                &committed,
            ) else {
                continue;
            };
            assert!(
                matches!(
                    jacobian_probe(
                        &cap.recorder.events,
                        honest,
                        &frontier,
                        &resolution.outputs,
                        direction,
                        F::ONE,
                        &committed,
                    ),
                    ProbeOutcome::OutputsPinned
                ),
                "{context}: slack advice cannot move an accumulator output",
            );
            assert!(
                committed
                    .iter()
                    .any(|&wire| candidate[wire] != honest[wire]),
                "{context}: nonzero proposal"
            );
            for &wire in &frontier {
                assert_eq!(candidate[wire], honest[wire], "{context}: frontier {wire}");
            }
            assert!(
                playback(circuit, make_witness()?, candidate)?,
                "{context}: exact slack proposal survives live playback"
            );
            return Ok(());
        }
        panic!("{context}: no exact Jacobian direction in pooled allocator slack");
    }

    fn check_accumulator_cut<'w, F: Field, Cir: Circuit<F>>(
        &self,
        cap: &Capture<F>,
        resolution: &Resolution,
        circuit: &Cir,
        make_witness: &impl Fn() -> Result<Cir::Witness<'w>>,
        context: &str,
    ) -> Result<()> {
        let honest = &cap.recorder.values;
        let full = &cap.recorder.events;
        let frontier: Vec<_> = cap
            .instance
            .iter()
            .chain(&cap.stage_wires)
            .copied()
            .collect();

        for &output in &resolution.outputs {
            if !cap.stage_wires.contains(&output)
                || !jacobian_kernel(full, honest, &[output]).is_empty()
            {
                continue;
            }
            let mentions: Vec<_> = full
                .iter()
                .enumerate()
                .filter_map(|(i, event)| match event {
                    Event::Lin { out, terms } => (*out == output
                        || terms.iter().any(|(wire, _)| *wire == output))
                    .then_some(i),
                    Event::Gate { a, b, c } => {
                        (*a == output || *b == output || *c == output).then_some(i)
                    }
                    Event::Enforce { terms } => {
                        terms.iter().any(|(wire, _)| *wire == output).then_some(i)
                    }
                    Event::Extra { c, d } => (*c == output || *d == output).then_some(i),
                })
                .collect();
            assert!(
                mentions.len() <= 16,
                "{context}: direct accumulator neighborhood unexpectedly has {} events",
                mentions.len(),
            );

            // Search by cardinality. Native collapse has a single terminal
            // binding; nested collapse also consumes the same value in its
            // outer fold, so its minimal direct cut contains another event.
            for cut_size in 1..=mentions.len() {
                for mask in 1usize..(1usize << mentions.len()) {
                    if mask.count_ones() as usize != cut_size {
                        continue;
                    }
                    let cuts: Vec<_> = mentions
                        .iter()
                        .enumerate()
                        .filter(|(bit, _)| mask & (1 << bit) != 0)
                        .map(|(_, event)| *event)
                        .collect();
                    let remaining: Vec<_> = full
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| !cuts.contains(i))
                        .map(|(_, event)| event.clone())
                        .collect();
                    let basis = jacobian_kernel(&remaining, honest, &[output]);
                    let Some(direction) = basis.first() else {
                        continue;
                    };
                    let frozen: Vec<_> = frontier
                        .iter()
                        .copied()
                        .filter(|wire| *wire != output)
                        .collect();
                    let ProbeOutcome::OutputsMoved { witness, moved } = jacobian_probe(
                        &remaining,
                        honest,
                        &frozen,
                        &[output],
                        direction,
                        F::ONE,
                        &[output],
                    ) else {
                        continue;
                    };
                    assert_eq!(moved.len(), 1, "{context}: one watched accumulator");
                    assert_eq!(moved[0].0, output, "{context}: moved accumulator");
                    assert!(
                        constraints_hold(&remaining, &witness),
                        "{context}: exact satisfying cut control"
                    );
                    assert!(
                        !constraints_hold(full, &witness),
                        "{context}: accumulator contract rejects the proposal"
                    );
                    for &wire in &frontier {
                        if wire != output {
                            assert_eq!(witness[wire], honest[wire], "{context}: frontier {wire}");
                        }
                    }
                    assert!(
                        !playback(circuit, make_witness()?, witness)?,
                        "{context}: live circuit rejects the cut witness"
                    );
                    return Ok(());
                }
            }
        }
        panic!("{context}: no terminal accumulator equality calibration found");
    }

    fn assert_complete(self) {
        assert_eq!(self.visited, [true; 2]);
    }
}

impl<C: Cycle> InternalCircuitVisitor<C> for Checker {
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == "inner_collapse" {
            assert!(!core::mem::replace(&mut self.visited[0], true));
            self.check(spec, circuit, stage_values, make_witness)?;
        }
        Ok(())
    }

    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        if spec.name == "nested_collapse" {
            assert!(!core::mem::replace(&mut self.visited[1], true));
            self.check(spec, circuit, stage_values, make_witness)?;
        }
        Ok(())
    }
}

#[test]
fn jacobian_proposals_respect_accumulator_commitment_frontiers() -> Result<()> {
    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(Leaf::new())?
        .register(Both::new())?
        .finalize(Pasta::baked())?;
    let mut rng = StdRng::seed_from_u64(0x873_0006);
    let (left, _) = app.seed(&mut rng, Leaf::new(), Fp::from(19))?;
    let (right, _) = app.seed(&mut rng, Leaf::new(), Fp::from(43))?;
    let mut checker = Checker {
        visited: [false; 2],
    };
    capture_internal_circuits(
        &app,
        &mut rng,
        Both::new(),
        Fp::from(71),
        left,
        right,
        &mut checker,
    )?;
    checker.assert_complete();
    Ok(())
}
