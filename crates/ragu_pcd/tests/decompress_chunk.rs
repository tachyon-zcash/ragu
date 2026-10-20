//! The chunk circuits on a real compressed proof, as the prover and the
//! decider would see them: every chunk of both sides fits the gate budget
//! with its stages loaded, at the proof's own rank and at the aggregator
//! rank, its stage polynomials are well formed under their masks, its
//! trace satisfies the circuit with the honest stages, and a stage value
//! tampered with after the prover's run fails some chunk.

use alloc::{format, string::String, sync::Arc, vec::Vec};

use ragu_circuits::{
    BondingObject, CircuitExt,
    polynomials::{AggregatorRank, Rank, sparse},
    staging::{MultiStage, MultiStageCircuit, StageExt},
};
use ragu_core::pasta::{Fp, Fq, Pasta};
use ragu_testing::registry::TestRegistryBuilder;
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::field::Field;

use super::{Circuit, TranscriptCircuit, is_transcript};
use crate::decompress::{
    program::{Chunk, Schedule},
    run::{Prepared, Sides},
    side::{Native, Nested, Side},
    stages::{InstanceStage, MessagesStage, TranscriptStage, WorkStage, native_scalars},
    support::{HEADER_SIZE, Setup, TestR},
};

/// Both sides prepared for chunk circuits at rank `R`.
fn sides<R: Rank>(setup: &Setup) -> Sides<Pasta> {
    let pcd = setup.proof.clone().carry(());
    Sides::prepare::<TestR, R, HEADER_SIZE, _, ()>(&setup.app, &pcd).expect("the proof verifies")
}

/// The schedule the chunk circuits at rank `R` are built from, as the
/// registry would build them.
fn circuit_schedule<S: Side<Pasta>, R: Rank>() -> Arc<Schedule> {
    Arc::new(S::schedule::<TestR, R, HEADER_SIZE>().unwrap())
}

fn kind(chunk: &Chunk) -> &'static str {
    match chunk {
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
    }
}

/// What one chunk's check reports.
struct Report {
    gates: usize,
    /// Whether the stage polynomials are well formed and the trace
    /// satisfies the circuit.
    satisfied: bool,
}

/// Checks the staged `circuit` over `prepared` with its stage polynomials
/// `stages` and their `masks`: registers it alone, assembles its trace and
/// checks the masks and the circuit identity at a random point.
fn check<S: Side<Pasta>, R: Rank, X>(
    circuit: MultiStage<S::F, R, X>,
    prepared: &Prepared<Pasta, S>,
    stages: Vec<sparse::Polynomial<S::F, R>>,
    masks: Vec<BondingObject<'static, S::F, R>>,
    final_mask: BondingObject<'static, S::F, R>,
    rng: &mut StdRng,
) -> crate::Result<Report>
where
    X: MultiStageCircuit<S::F, R> + Clone + 'static,
    for<'s> X: MultiStageCircuit<S::F, R, Witness<'s> = &'s Prepared<Pasta, S>, Instance<'s> = ()>,
{
    let gates = ragu_circuits::testing::synthesis_counts(&circuit)?.num_gates;
    let trace = circuit.trace(prepared)?.into_output();
    let mut builder = TestRegistryBuilder::<S::F, R>::new();
    let handle = builder.register_circuit(circuit.clone())?;
    let mask_handles: Vec<_> = masks
        .into_iter()
        .map(|mask| builder.register_bonding(mask))
        .collect();
    let final_handle = builder.register_bonding(final_mask);
    let registry = builder.finalize()?;
    let y = S::F::random(|bytes| rng.fill_bytes(bytes));
    let mut satisfied = true;
    for (stage, handle) in stages.iter().zip(&mask_handles) {
        satisfied &= stage.revdot(&registry.y(*handle, y)) == S::F::ZERO;
    }
    let final_rx = registry.assemble(&trace, handle, S::F::ZERO)?;
    satisfied &= final_rx.revdot(&registry.y(final_handle, y)) == S::F::ZERO;
    let mut rx = final_rx;
    for stage in &stages {
        rx.add_assign(stage);
    }
    satisfied &= rx.revdot(&registry.y(handle, y)) == circuit.ky((), y)?;
    Ok(Report { gates, satisfied })
}

/// Runs chunk `index` of side `S` at rank `R` over `prepared`.
fn run_chunk<S: Side<Pasta>, R: Rank>(
    schedule: &Arc<Schedule>,
    index: usize,
    prepared: &Prepared<Pasta, S>,
    rng: &mut StdRng,
) -> crate::Result<Report> {
    type Instance<S, R> = InstanceStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Messages<S, R> = MessagesStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Work<S, R> = WorkStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Transcript<S, R> = TranscriptStage<Pasta, S, TestR, R, HEADER_SIZE>;
    let params = crate::pasta::baked();
    let zero = S::F::ZERO;
    let mut stages = alloc::vec![
        <Instance<S, R> as StageExt<S::F, R>>::rx(zero, &prepared.instance)?,
        <Messages<S, R> as StageExt<S::F, R>>::rx(zero, &prepared.messages)?,
        <Work<S, R> as StageExt<S::F, R>>::rx(zero, &prepared.work)?,
    ];
    let mut masks = alloc::vec![
        <Instance<S, R> as StageExt<S::F, R>>::mask()?,
        <Messages<S, R> as StageExt<S::F, R>>::mask()?,
        <Work<S, R> as StageExt<S::F, R>>::mask()?,
    ];
    if is_transcript(schedule, index) {
        let circuit = TranscriptCircuit::<Pasta, S, TestR, R, HEADER_SIZE>::new(
            index,
            schedule.clone(),
            params,
        );
        stages.push(<Transcript<S, R> as StageExt<S::F, R>>::rx(
            zero,
            &prepared.transcript,
        )?);
        masks.push(<Transcript<S, R> as StageExt<S::F, R>>::mask()?);
        let final_mask = <Transcript<S, R> as StageExt<S::F, R>>::final_mask()?;
        check(circuit, prepared, stages, masks, final_mask, rng)
    } else {
        let circuit =
            Circuit::<Pasta, S, TestR, R, HEADER_SIZE>::new(index, schedule.clone(), params);
        let final_mask = <Work<S, R> as StageExt<S::F, R>>::final_mask()?;
        check(circuit, prepared, stages, masks, final_mask, rng)
    }
}

/// Every chunk of side `S` at rank `R` fits the budget and is satisfied by
/// `prepared`, reporting every chunk that is not.
fn check_side<S: Side<Pasta>, R: Rank>(prepared: &Prepared<Pasta, S>) {
    let schedule = circuit_schedule::<S, R>();
    let mut rng = StdRng::seed_from_u64(7);
    let mut failures: Vec<String> = Vec::new();
    let mut largest: Vec<(&'static str, usize, usize)> = Vec::new();
    for index in 0..schedule.chunks.len() {
        let kind = kind(&schedule.chunks[index]);
        match run_chunk::<S, R>(&schedule, index, prepared, &mut rng) {
            Ok(report) => {
                if report.gates > R::n() {
                    failures.push(format!(
                        "chunk {index} ({kind}) uses {} gates of {}",
                        report.gates,
                        R::n()
                    ));
                }
                if !report.satisfied {
                    failures.push(format!("chunk {index} ({kind}) is not satisfied"));
                }
                match largest.iter_mut().find(|(k, _, _)| *k == kind) {
                    Some(entry) if entry.2 >= report.gates => {}
                    Some(entry) => *entry = (kind, index, report.gates),
                    None => largest.push((kind, index, report.gates)),
                }
            }
            Err(e) => failures.push(format!("chunk {index} ({kind}) fails: {e:?}")),
        }
    }
    std::println!(
        "{} at rank {}: {} chunks, {} work elements, {} work points, {} states; largest per kind of {} gates:",
        S::NAME,
        R::RANK,
        schedule.chunks.len(),
        schedule.elements,
        schedule.points,
        schedule.states,
        R::n()
    );
    for (kind, index, gates) in &largest {
        std::println!("  {kind}: chunk {index} at {gates} gates");
    }
    assert!(
        failures.is_empty(),
        "{} side:\n{}",
        S::NAME,
        failures.join("\n")
    );
}

#[test]
fn every_chunk_fits_and_is_satisfied() {
    let setup = Setup::new();
    let sides = sides::<TestR>(&setup);
    check_side::<Native, TestR>(&sides.native);
    check_side::<Nested, TestR>(&sides.nested);
}

/// The aggregator's configuration: the chunks at the aggregator rank over
/// a production-rank proof.
#[test]
fn every_chunk_fits_at_the_aggregator_rank() {
    let setup = Setup::new();
    let sides = sides::<AggregatorRank>(&setup);
    check_side::<Native, AggregatorRank>(&sides.native);
    check_side::<Nested, AggregatorRank>(&sides.nested);
}

/// Some chunk of side `S` rejects `prepared`.
fn rejected<S: Side<Pasta>>(prepared: &Prepared<Pasta, S>) -> bool {
    let schedule = circuit_schedule::<S, TestR>();
    let mut rng = StdRng::seed_from_u64(11);
    (0..schedule.chunks.len()).any(|index| {
        !run_chunk::<S, TestR>(&schedule, index, prepared, &mut rng)
            .is_ok_and(|report| report.satisfied)
    })
}

#[test]
fn rejects_tampered_stages() {
    let setup = Setup::new();
    let mut sides = sides::<TestR>(&setup);

    // A message: the native inner epsilon fails the reduction's identity.
    sides.native.messages.elements[0] += Fp::ONE;
    assert!(rejected(&sides.native), "a tampered message fails a chunk");
    sides.native.messages.elements[0] -= Fp::ONE;

    // The instance: c fails the targets' binding to the unified instance.
    let c = sides
        .native
        .schedule
        .layout
        .instance
        .scalars
        .at(native_scalars::C);
    sides.native.instance.elements[c] += Fp::ONE;
    assert!(rejected(&sides.native), "a tampered instance fails a chunk");
    sides.native.instance.elements[c] -= Fp::ONE;

    // The work stage: a squeezed challenge fails its transcript chunk.
    let w = sides.native.schedule.regions.squeezed[0];
    sides.native.work.elements[w] += Fp::ONE;
    assert!(
        rejected(&sides.native),
        "a tampered challenge fails a chunk"
    );
    sides.native.work.elements[w] -= Fp::ONE;

    // The scalar-field side's messages likewise.
    sides.nested.messages.elements[0] += Fq::ONE;
    assert!(
        rejected(&sides.nested),
        "a tampered nested message fails a chunk"
    );
    sides.nested.messages.elements[0] -= Fq::ONE;

    assert!(
        !rejected(&sides.native) && !rejected(&sides.nested),
        "restored, both accept"
    );
}
