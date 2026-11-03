//! The chunk circuits on a real compressed proof, as the prover and the
//! decider would see them: every circuit of both sides fits the gate
//! budget with its stages loaded at the aggregator rank, its stage
//! polynomials are well formed under their masks, its trace satisfies the
//! circuit with the honest stages, and a stage value tampered with after
//! the prover's run fails some circuit. Each side's binding circuit exposes
//! the other side's actual stage commitments, the run stages' the
//! transcript absorbed among them, and not those of another proof's side.

use alloc::{format, string::String, sync::Arc, vec::Vec};

use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    BondingObject, CircuitExt,
    polynomials::{AggregatorRank, Rank, sparse},
    staging::{MultiStage, MultiStageCircuit, StageExt},
};
use ragu_core::{
    Cycle,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::vec::{ConstLen, FixedVec};
use ragu_testing::registry::TestRegistryBuilder;
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field,
};

use super::{BindingCircuit, Circuit, DigitsCircuit, StatementCircuit, TranscriptCircuit, last};
use crate::decompress::{
    program::{Chunk, Last, Schedule, challenges_per_curve, squeezed},
    run::{Prepared, Sides},
    side::{Native, Nested, Side},
    stages::{
        DigitsStage, Front, InstanceStage, LiftsStage, Run, TranscriptStage, WorkStage,
        native_scalars, num_runs, runs,
    },
    support::{HEADER_SIZE, Setup, TestR},
};

/// The rank the chunk circuits are checked at: the aggregator's
/// configuration, the chunks at the aggregator rank over a wallet-rank
/// proof.
type SmallR = AggregatorRank;

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

/// The kinds of the chunks circuit `index` runs, as `kind+kind×n`.
fn describe(schedule: &Schedule, index: usize) -> String {
    let mut parts: Vec<(&'static str, usize)> = Vec::new();
    for &chunk in &schedule.circuits[index].chunks {
        let kind = kind(&schedule.chunks[chunk]);
        match parts.last_mut() {
            Some((last, count)) if *last == kind => *count += 1,
            _ => parts.push((kind, 1)),
        }
    }
    parts
        .iter()
        .map(|(kind, count)| {
            if *count > 1 {
                format!("{kind}×{count}")
            } else {
                String::from(*kind)
            }
        })
        .collect::<Vec<_>>()
        .join("+")
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

/// The polynomials and masks of the stages every circuit of side `S`
/// loads, unblinded: the front, the lifts and the work stages.
#[allow(clippy::type_complexity)]
fn common_stages<S: Front<Pasta, TestR, R, HEADER_SIZE>, R: Rank>(
    prepared: &Prepared<Pasta, S>,
) -> crate::Result<(
    Vec<sparse::Polynomial<S::F, R>>,
    Vec<BondingObject<'static, S::F, R>>,
)> {
    type Lifts<S, R> = LiftsStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Work<S, R> = WorkStage<Pasta, S, TestR, R, HEADER_SIZE>;
    let zero = S::F::ZERO;
    let mut stages = Vec::new();
    let mut masks = Vec::new();
    for index in 0..S::stages() {
        stages.push(S::rx(index, zero, prepared)?);
        masks.push(S::mask(index)?);
    }
    stages.extend([
        <Lifts<S, R> as StageExt<S::F, R>>::rx(zero, &prepared.lifts)?,
        <Work<S, R> as StageExt<S::F, R>>::rx(zero, &prepared.work)?,
    ]);
    masks.extend([
        <Lifts<S, R> as StageExt<S::F, R>>::mask()?,
        <Work<S, R> as StageExt<S::F, R>>::mask()?,
    ]);
    Ok((stages, masks))
}

/// Runs circuit `index` of side `S` at rank `R` over `prepared`.
fn run_circuit<S: Front<Pasta, TestR, R, HEADER_SIZE>, R: Rank>(
    schedule: &Arc<Schedule>,
    index: usize,
    prepared: &Prepared<Pasta, S>,
    rng: &mut StdRng,
) -> crate::Result<Report> {
    type Work<S, R> = WorkStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Transcript<S, R> = TranscriptStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Digits<S, R> = DigitsStage<Pasta, S, TestR, R, HEADER_SIZE>;
    let params = crate::pasta::baked_aggregator();
    let zero = S::F::ZERO;
    let (mut stages, mut masks) = common_stages::<S, R>(prepared)?;
    match last(schedule, index) {
        Last::Transcript => {
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
        }
        Last::Digits => {
            let circuit = DigitsCircuit::<Pasta, S, TestR, R, HEADER_SIZE>::new(
                index,
                schedule.clone(),
                params,
            );
            stages.push(<Digits<S, R> as StageExt<S::F, R>>::rx(
                zero,
                &prepared.digits,
            )?);
            masks.push(<Digits<S, R> as StageExt<S::F, R>>::mask()?);
            let final_mask = <Digits<S, R> as StageExt<S::F, R>>::final_mask()?;
            check(circuit, prepared, stages, masks, final_mask, rng)
        }
        Last::Work => {
            let circuit =
                Circuit::<Pasta, S, TestR, R, HEADER_SIZE>::new(index, schedule.clone(), params);
            let final_mask = <Work<S, R> as StageExt<S::F, R>>::final_mask()?;
            check(circuit, prepared, stages, masks, final_mask, rng)
        }
    }
}

/// Every circuit of side `S` at rank `R` fits the budget and is satisfied
/// by `prepared`, reporting every circuit that is not.
fn check_side<S: Front<Pasta, TestR, R, HEADER_SIZE>, R: Rank>(prepared: &Prepared<Pasta, S>) {
    let schedule = circuit_schedule::<S, R>();
    let mut rng = StdRng::seed_from_u64(7);
    let mut failures: Vec<String> = Vec::new();
    let mut largest: Vec<(String, usize, usize)> = Vec::new();
    let mut all: Vec<(usize, String, usize)> = Vec::new();
    for index in 0..schedule.circuits.len() {
        let kind = describe(&schedule, index);
        match run_circuit::<S, R>(&schedule, index, prepared, &mut rng) {
            Ok(report) => {
                all.push((index, kind.clone(), report.gates));
                if report.gates > R::n() {
                    failures.push(format!(
                        "circuit {index} ({kind}) uses {} gates of {}",
                        report.gates,
                        R::n()
                    ));
                }
                if !report.satisfied {
                    failures.push(format!("circuit {index} ({kind}) is not satisfied"));
                }
                match largest.iter_mut().find(|(k, _, _)| *k == kind) {
                    Some(entry) if entry.2 >= report.gates => {}
                    Some(entry) => *entry = (kind.clone(), index, report.gates),
                    None => largest.push((kind.clone(), index, report.gates)),
                }
            }
            Err(e) => failures.push(format!("circuit {index} ({kind}) fails: {e:?}")),
        }
    }
    std::println!(
        "{} at rank {}: {} circuits over {} chunks, {} work elements, {} work points, {} states; largest per kind of {} gates:",
        S::NAME,
        R::RANK,
        schedule.circuits.len(),
        schedule.chunks.len(),
        schedule.elements,
        schedule.points,
        schedule.states,
        R::n()
    );
    for (kind, index, gates) in &largest {
        std::println!("  {kind}: circuit {index} at {gates} gates");
    }
    std::println!("every circuit:");
    for (index, kind, gates) in &all {
        std::println!("  {index}: {kind} ({gates} gates)");
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
    let sides = sides::<SmallR>(&setup);
    check_side::<Native, SmallR>(&sides.native);
    check_side::<Nested, SmallR>(&sides.nested);
}

/// Some circuit of side `S` rejects `prepared`.
fn rejected<S: Front<Pasta, TestR, SmallR, HEADER_SIZE>>(prepared: &Prepared<Pasta, S>) -> bool {
    let schedule = circuit_schedule::<S, SmallR>();
    let mut rng = StdRng::seed_from_u64(11);
    (0..schedule.circuits.len()).any(|index| {
        !run_circuit::<S, SmallR>(&schedule, index, prepared, &mut rng)
            .is_ok_and(|report| report.satisfied)
    })
}

#[test]
fn rejects_tampered_stages() {
    let setup = Setup::new();
    let mut sides = sides::<SmallR>(&setup);

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

/// A chunk that scales by a challenge taken from bits holds those bits to
/// the lifts stage. The scalar-field side is re-run with other bits for
/// the host curve's $\beta$, which only point chains scale by, and with
/// the $G'$ a prover choosing those bits would pick, since nothing binds
/// it yet: the one that keeps the IPA's final equality. Every chunk is
/// then consistent with the other bits; the lifts stage alone is restored
/// to the honest lifts. A circuit that runs no lift chunk then fails: the
/// chains' bits cannot differ from the lift chunk's.
#[test]
fn chains_hold_their_bits_to_the_lifts_stage() {
    let setup = Setup::new();
    let params = crate::pasta::baked_aggregator();
    let mut sides = sides::<SmallR>(&setup);
    let nested = &mut sides.nested;
    let honest_lifts = nested.lifts.clone();
    let beta = challenges_per_curve::<TestR>() + 3 + squeezed::BETA;
    nested.aux.challenge_bits[beta] = nested.aux.challenge_bits[beta].flip_bit(5);
    nested.run::<TestR, HEADER_SIZE>(params).unwrap();
    // The final equality is $\text{left} = v G_0 + c G' + c b z U$: solve
    // it for $G'$ under the other bits' left-hand side.
    let (ipa_left, g_prime) = (
        nested.schedule.regions.ipa_left,
        nested.schedule.regions.g_prime,
    );
    let [v, c, cbz] = [
        nested.aux.foreign[0],
        nested.aux.foreign[1],
        nested.aux.foreign[2],
    ];
    let left = nested.work.points[ipa_left].to_projective();
    let g_0 = <Nested as Side<Pasta>>::generators(params)[0];
    let u = <Nested as Side<Pasta>>::u(params);
    let scaled = (left - g_0 * v - u * cbz).to_affine();
    nested.work.points[g_prime] = (scaled * c.invert().expect("c is nonzero")).to_affine();
    nested.run::<TestR, HEADER_SIZE>(params).unwrap();
    nested.lifts = honest_lifts;

    let schedule = circuit_schedule::<Nested, SmallR>();
    let mut rng = StdRng::seed_from_u64(17);
    let without_lift_chunks = (0..schedule.circuits.len()).filter(|&index| {
        !schedule.circuits[index]
            .chunks
            .iter()
            .any(|&chunk| matches!(schedule.chunks[chunk], Chunk::Lift { .. }))
    });
    assert!(
        without_lift_chunks.into_iter().any(|index| {
            !run_circuit::<Nested, SmallR>(&schedule, index, nested, &mut rng)
                .is_ok_and(|report| report.satisfied)
        }),
        "a chain over other bits than the lifts stage's fails a chunk"
    );
}

/// The statement circuit exposes the instance stage's output header as its
/// public output: at the aggregator rank its trace satisfies the circuit
/// at that header's $k(y)$ and at no other's.
#[test]
fn statement_circuit_exposes_the_output_header() {
    type Instance = InstanceStage<Pasta, Native, TestR, AggregatorRank, HEADER_SIZE>;
    let setup = Setup::new();
    let sides = sides::<AggregatorRank>(&setup);
    let prepared = &sides.native;
    let schedule = circuit_schedule::<Native, AggregatorRank>();
    let circuit = StatementCircuit::<Pasta, Native, TestR, AggregatorRank, HEADER_SIZE>::new(
        schedule.clone(),
    );
    let gates = ragu_circuits::testing::synthesis_counts(&circuit)
        .unwrap()
        .num_gates;
    assert!(gates <= AggregatorRank::n());

    let span = schedule.layout.instance.output_header;
    let header: Vec<Fp> = span
        .positions()
        .map(|position| prepared.instance.elements[position])
        .collect();
    let trace = circuit.trace(prepared).unwrap().into_parts().0;
    let mut builder = TestRegistryBuilder::<Fp, AggregatorRank>::new();
    let handle = builder.register_circuit(circuit.clone()).unwrap();
    let mask =
        builder.register_bonding(<Instance as StageExt<Fp, AggregatorRank>>::mask().unwrap());
    let final_mask =
        builder.register_bonding(<Instance as StageExt<Fp, AggregatorRank>>::final_mask().unwrap());
    let registry = builder.finalize().unwrap();
    let mut rng = StdRng::seed_from_u64(13);
    let y = Fp::random(|bytes| rng.fill_bytes(bytes));

    let stage =
        <Instance as StageExt<Fp, AggregatorRank>>::rx(Fp::ZERO, &prepared.instance).unwrap();
    assert_eq!(stage.revdot(&registry.y(mask, y)), Fp::ZERO);
    let mut rx = registry.assemble(&trace, handle, Fp::ZERO).unwrap();
    assert_eq!(rx.revdot(&registry.y(final_mask, y)), Fp::ZERO);
    rx.add_assign(&stage);
    let own: FixedVec<Fp, ConstLen<HEADER_SIZE>> = FixedVec::try_from(header.clone()).unwrap();
    assert_eq!(
        rx.revdot(&registry.y(handle, y)),
        circuit.ky(own, y).unwrap()
    );
    let mut other = header;
    other[0] += Fp::ONE;
    let other: FixedVec<Fp, ConstLen<HEADER_SIZE>> = FixedVec::try_from(other).unwrap();
    assert_ne!(
        rx.revdot(&registry.y(handle, y)),
        circuit.ky(other, y).unwrap()
    );
}

/// The commitments of the stages the other side's binding circuit exposes,
/// unblinded, at the aggregator rank: the scalar-field side's run stages,
/// which the transcript absorbed, and its lifts and digits stages, which
/// the circuit-field side recomputes; and the circuit-field side's digits
/// stage.
fn bound_commitments(
    sides: &Sides<Pasta>,
) -> (
    Vec<<Pasta as Cycle>::NestedCurve>,
    Vec<<Pasta as Cycle>::HostCurve>,
) {
    type R = AggregatorRank;
    type NestedLifts = LiftsStage<Pasta, Nested, TestR, R, HEADER_SIZE>;
    type NestedDigits = DigitsStage<Pasta, Nested, TestR, R, HEADER_SIZE>;
    type NativeDigits = DigitsStage<Pasta, Native, TestR, R, HEADER_SIZE>;
    let params = crate::pasta::baked_aggregator();
    let nested = &sides.nested;
    let nested_commit = |rx: &sparse::Polynomial<Fq, R>| {
        ReferenceBackend::sparse_commit_to_affine(rx, Pasta::nested_generators(params))
    };
    let mut of_nested: Vec<_> = (0..num_runs::<TestR>())
        .map(|run| {
            nested_commit(
                &<Nested as Front<Pasta, TestR, R, HEADER_SIZE>>::rx(run, Fq::ZERO, nested)
                    .unwrap(),
            )
        })
        .collect();
    of_nested.extend([
        nested_commit(&<NestedLifts as StageExt<Fq, R>>::rx(Fq::ZERO, &nested.lifts).unwrap()),
        nested_commit(&<NestedDigits as StageExt<Fq, R>>::rx(Fq::ZERO, &nested.digits).unwrap()),
    ]);
    let of_native = alloc::vec![ReferenceBackend::sparse_commit_to_affine(
        &<NativeDigits as StageExt<Fp, R>>::rx(Fp::ZERO, &sides.native.digits).unwrap(),
        Pasta::host_generators(params),
    )];
    (of_nested, of_native)
}

/// The points a side's work stage holds at its exposed slots.
fn exposed<S: Side<Pasta>>(prepared: &Prepared<Pasta, S>) -> Vec<S::P> {
    prepared
        .schedule
        .regions
        .exposed
        .iter()
        .map(|&slot| prepared.work.points[slot])
        .collect()
}

/// At the aggregator rank, each side's recomputations are the other
/// side's actual stage commitments, and its binding circuit's trace
/// satisfies the circuit at their $k(y)$ and at no other's. Two sides
/// prepared from different compressions of the same proof disagree on
/// every one of them: the challenges, the scalars and the messages all
/// differ.
#[test]
fn binding_circuits_expose_the_other_sides_commitments() {
    type R = AggregatorRank;
    type NativeWork = WorkStage<Pasta, Native, TestR, R, HEADER_SIZE>;
    let setup = Setup::new();
    let sides = sides::<R>(&setup);
    let (of_nested, of_native) = bound_commitments(&sides);
    assert_eq!(exposed(&sides.native), of_nested);
    assert_eq!(exposed(&sides.nested), of_native);

    // The native binding circuit's claim at the exposed points' k(y).
    let schedule = circuit_schedule::<Native, R>();
    let circuit = BindingCircuit::<Pasta, Native, TestR, R, HEADER_SIZE>::new(schedule.clone());
    let gates = ragu_circuits::testing::synthesis_counts(&circuit)
        .unwrap()
        .num_gates;
    assert!(gates <= R::n());
    let prepared = &sides.native;
    let trace = circuit.trace(prepared).unwrap().into_parts().0;
    let mut builder = TestRegistryBuilder::<Fp, R>::new();
    let handle = builder.register_circuit(circuit.clone()).unwrap();
    let final_mask =
        builder.register_bonding(<NativeWork as StageExt<Fp, R>>::final_mask().unwrap());
    let registry = builder.finalize().unwrap();
    let mut rng = StdRng::seed_from_u64(17);
    let y = Fp::random(|bytes| rng.fill_bytes(bytes));
    let mut rx = registry.assemble(&trace, handle, Fp::ZERO).unwrap();
    assert_eq!(rx.revdot(&registry.y(final_mask, y)), Fp::ZERO);
    let (stages, _) = common_stages::<Native, R>(prepared).unwrap();
    for stage in stages {
        rx.add_assign(&stage);
    }
    let own = FixedVec::try_from(of_nested.clone()).unwrap();
    assert_eq!(
        rx.revdot(&registry.y(handle, y)),
        circuit.ky(own, y).unwrap()
    );
    let mut other = of_nested.clone();
    other[0] = -other[0];
    let other = FixedVec::try_from(other).unwrap();
    assert_ne!(
        rx.revdot(&registry.y(handle, y)),
        circuit.ky(other, y).unwrap()
    );

    // Another compression of the same proof: the sides prepared from it
    // expose its commitments, not this one's. The runs before the first
    // blinded message are functions of the proof and the challenges the
    // instance fixes, and agree; from that message on, by the IPA's
    // masking commitment at the latest, every run differs, and so do the
    // lifts and the digits.
    let other = setup
        .app
        .compress(&setup.app.bootstrap_pcd(), &mut StdRng::seed_from_u64(2))
        .unwrap();
    let other = Sides::prepare::<TestR, R, HEADER_SIZE, _, ()>(&setup.app, &other).unwrap();
    let (other_nested, other_native) = bound_commitments(&other);
    let ours = exposed(&sides.native);
    let first = ours
        .iter()
        .zip(&other_nested)
        .position(|(ours, theirs)| ours != theirs)
        .expect("the compressions differ");
    let masking = runs::<TestR>()
        .iter()
        .position(|run| *run == Run::SCommitment)
        .expect("the IPA's masking commitment is a run");
    assert!(first >= 2, "the instance's runs agree");
    assert!(first <= masking, "the IPA's masking commitment is blinded");
    assert!(
        ours[first..]
            .iter()
            .zip(&other_nested[first..])
            .all(|(ours, theirs)| ours != theirs),
        "every run from the first blinded message on, the lifts and the digits differ between compressions"
    );
    assert_ne!(exposed(&sides.nested), other_native);
}

/// The gates every chunk of side `S` takes on its own at rank `R`, beyond
/// the stages its circuit loads, against the schedule's estimate of it,
/// each chunk synthesized as a circuit of its own; and the stages each kind
/// of circuit loads, synthesized as a circuit of no chunks, against the
/// schedule's count of them. The table is printed. Returns what fails: an
/// estimate below a chunk's measure, which the packer would overfill a
/// circuit by, or estimates more than a twentieth above the side's
/// measures in all, which would leave every aggregator proof carrying
/// circuits it need not.
fn measure_chunks<S: Front<Pasta, TestR, R, HEADER_SIZE>, R: Rank>(
    prepared: &Prepared<Pasta, S>,
) -> Vec<String> {
    use crate::decompress::program::{CircuitPlan, gates};
    let params = crate::pasta::baked_aggregator();
    let synthesize = |schedule: &Arc<Schedule>, index: usize| -> usize {
        match last(schedule, index) {
            Last::Transcript => {
                ragu_circuits::testing::synthesis_counts(&TranscriptCircuit::<
                    Pasta,
                    S,
                    TestR,
                    R,
                    HEADER_SIZE,
                >::new(
                    index, schedule.clone(), params
                ))
            }
            Last::Digits => {
                ragu_circuits::testing::synthesis_counts(&DigitsCircuit::<
                    Pasta,
                    S,
                    TestR,
                    R,
                    HEADER_SIZE,
                >::new(
                    index, schedule.clone(), params
                ))
            }
            Last::Work => {
                ragu_circuits::testing::synthesis_counts(
                    &Circuit::<Pasta, S, TestR, R, HEADER_SIZE>::new(
                        index,
                        schedule.clone(),
                        params,
                    ),
                )
            }
        }
        .unwrap()
        .num_gates
    };
    let mut failures = Vec::new();
    // The stages alone: a circuit of no chunks of each kind.
    let kinds = [Last::Work, Last::Transcript, Last::Digits];
    let mut empty = prepared.schedule.clone();
    empty.circuits = kinds
        .iter()
        .map(|&last| CircuitPlan {
            chunks: Vec::new(),
            last,
        })
        .collect();
    let empty = Arc::new(empty);
    let loading: Vec<usize> = (0..kinds.len()).map(|i| synthesize(&empty, i)).collect();
    for (i, &last) in kinds.iter().enumerate() {
        let counted = prepared.schedule.stage_gates(last);
        std::println!(
            "{} {last:?} stages: {} gates, counted {counted}",
            S::NAME,
            loading[i]
        );
        if counted != loading[i] {
            failures.push(format!(
                "{} {last:?} circuits load {} gates of stages, counted {counted}",
                S::NAME,
                loading[i]
            ));
        }
    }
    let load = |last: Last| loading[kinds.iter().position(|&k| k == last).unwrap()];
    // Every chunk alone.
    let mut single = prepared.schedule.clone();
    single.circuits = (0..prepared.schedule.chunks.len())
        .map(|i| CircuitPlan {
            chunks: alloc::vec![i],
            last: prepared.schedule.chunks[i].last(),
        })
        .collect();
    let single = Arc::new(single);
    let mut by_kind: Vec<(&'static str, usize, usize, usize)> = Vec::new();
    let (mut measured_total, mut estimated_total) = (0, 0);
    for (i, chunk) in prepared.schedule.chunks.iter().enumerate() {
        let measured = synthesize(&single, i) - load(chunk.last());
        let estimate = gates(chunk);
        measured_total += measured;
        estimated_total += estimate;
        match by_kind.iter_mut().find(|(k, _, _, _)| *k == kind(chunk)) {
            Some(entry) => {
                entry.1 += 1;
                entry.2 += measured;
                entry.3 += estimate;
            }
            None => by_kind.push((kind(chunk), 1, measured, estimate)),
        }
        if estimate < measured {
            failures.push(format!(
                "{} chunk {i} ({}) measures {measured} gates, estimated {estimate}",
                S::NAME,
                kind(chunk)
            ));
        }
    }
    std::println!(
        "{} chunks by kind (count, measured, estimated): {by_kind:?}; in all {measured_total} measured, {estimated_total} estimated",
        S::NAME
    );
    if estimated_total > measured_total + measured_total / 20 {
        failures.push(format!(
            "{} chunks measure {measured_total} gates in all, estimated {estimated_total}",
            S::NAME
        ));
    }
    failures
}

/// The packer's estimates hold to what the chunks and stages measure, on
/// both sides: an upper bound on every chunk, within a twentieth in all,
/// and the stages' gates exactly.
#[test]
fn estimates_cover_every_chunk() {
    let setup = Setup::new();
    let sides = sides::<SmallR>(&setup);
    let mut failures = measure_chunks::<Native, SmallR>(&sides.native);
    failures.extend(measure_chunks::<Nested, SmallR>(&sides.nested));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
