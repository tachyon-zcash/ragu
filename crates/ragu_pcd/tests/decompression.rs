//! The decompression's two circuits, each side's verifier cut into pages,
//! on real compressed proofs: each side's whole circuit is satisfied by
//! the stages the prover's run of the side fills, a value tampered with
//! after that run fails it, and each side exposes the other side's actual
//! stage commitments; the circuits cut into the pages the aggregator pins;
//! and an aggregator over the profile decompresses a wallet proof into a
//! proof of its own.

use alloc::vec::Vec;

use ragu_backend::{Backend, ReferenceBackend};
use ragu_circuits::{
    CircuitExt, MaskObject,
    polynomials::{AggregatorRank, Rank, WalletRank, sparse},
    staging::{Stage, StageExt, wire_degree},
};
use ragu_core::{
    Cycle, FixedGenerators,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{
    extract_endoscalar, lift_endoscalar,
    vec::{ConstLen, FixedVec},
};
use ragu_testing::{
    patcher::{Capture, Event, Recorder, capture_with_stage_values, constraints_hold},
    registry::TestRegistryBuilder,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field,
};

use super::{
    circuits::{Prepared, StatementCircuit},
    online::{self, Values},
    prover::{Prepare, Sides, Witness},
    side::{Native, Nested, Side},
    stages::{
        DigitsStage, Front, InstanceStage, LiftsStage, OnlineInputStage, OnlineQueryStage, Run,
        message_points, native_scalars, num_runs, runs,
    },
    verifier::{challenges_per_curve, fuse, squeezed},
    whole::{Whole, WholeCarry, WholeCircuit, cut},
};
use crate::{Application, ApplicationBuilder, CompressedProof, ipa::convert_challenge};

std::thread_local! {
    // The hook's site runs on the thread invoking fuse, outside its
    // parallel jobs. Other tests and worker threads always see false.
    static OTHER_NESTED_IPA_POLYNOMIAL: core::cell::Cell<bool> =
        const { core::cell::Cell::new(false) };
}

/// Runs `f` with an aggregator prover that commits, in its nested batch,
/// the challenge polynomial of other round challenges than the nested
/// IPA's, and restores the honest prover on unwind.
pub(crate) fn with_other_nested_ipa_polynomial<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            OTHER_NESTED_IPA_POLYNOMIAL.set(false);
        }
    }
    assert!(!OTHER_NESTED_IPA_POLYNOMIAL.get());
    let _reset = Reset;
    OTHER_NESTED_IPA_POLYNOMIAL.set(true);
    f()
}

/// Test hook: changes the round challenges the prover builds the nested
/// IPA's challenge polynomial from, when
/// [`with_other_nested_ipa_polynomial`] asks.
pub(crate) fn mutate_nested_ipa_rounds<F: Field>(rounds: &mut [F]) {
    if OTHER_NESTED_IPA_POLYNOMIAL.get() {
        rounds[0] += F::ONE;
    }
}

/// The wallet's rank.
pub(crate) type TestR = WalletRank;
/// The rank the whole circuits are proven at.
type R = AggregatorRank;
pub(crate) const HEADER_SIZE: usize = 4;
type App = Application<'static, Pasta, TestR, HEADER_SIZE>;

/// A wallet application and a compressed bootstrap proof of it.
struct Setup {
    app: App,
    proof: CompressedProof<Pasta>,
}

impl Setup {
    fn new() -> Self {
        let app = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(crate::pasta::baked_aggregator())
            .expect("failed to create test application");
        let pcd = app.bootstrap_pcd();
        let proof = app
            .compress(&pcd, &mut StdRng::seed_from_u64(1))
            .expect("compress should not error")
            .into_parts()
            .0;
        Setup { app, proof }
    }

    /// Both sides prepared for whole circuits at the aggregator rank.
    fn sides(&self) -> Sides<Pasta> {
        let pcd = self.proof.clone().carry(());
        Sides::prepare::<TestR, R, HEADER_SIZE, _, ()>(&self.app, &pcd).expect("the proof verifies")
    }
}

/// The polynomials and masks of every stage side `S`'s whole circuit
/// loads, in the order it loads them, each with a zero alpha: the online
/// stages, the front's, and the lifts and digits stages.
#[allow(clippy::type_complexity)]
fn loaded_stages<S: Front<Pasta, TestR, R, HEADER_SIZE>>(
    prepared: &Prepared<Pasta, S>,
) -> (Vec<sparse::Polynomial<S::F, R>>, Vec<MaskObject<R>>) {
    type Input<S> = OnlineInputStage<Pasta, S, R>;
    type Query<S> = OnlineQueryStage<Pasta, S, R>;
    type Lifts<S> = LiftsStage<Pasta, S, TestR, R, HEADER_SIZE>;
    type Digits<S> = DigitsStage<Pasta, S, TestR, R, HEADER_SIZE>;
    let zero = S::F::ZERO;
    let mut stages = alloc::vec![
        <Input<S> as StageExt<S::F, R>>::rx(zero, &prepared.online_input).expect("the input stage"),
        <Query<S> as StageExt<S::F, R>>::rx(zero, &prepared.online_query).expect("the query stage"),
    ];
    let mut masks = alloc::vec![
        <Input<S> as StageExt<S::F, R>>::stage_mask().expect("the input stage's mask"),
        <Query<S> as StageExt<S::F, R>>::stage_mask().expect("the query stage's mask"),
    ];
    for index in 0..S::stages() {
        stages.push(S::rx(index, zero, prepared).expect("a front stage"));
        masks.push(S::stage_mask(index).expect("a front stage's mask"));
    }
    stages.push(Lifts::<S>::rx(zero, &prepared.lifts).expect("the lifts stage"));
    masks.push(Lifts::<S>::stage_mask().expect("the lifts stage's mask"));
    stages.push(Digits::<S>::rx(zero, &prepared.digits).expect("the digits stage"));
    masks.push(Digits::<S>::stage_mask().expect("the digits stage's mask"));
    (stages, masks)
}

/// The honest values of the wires side `S`'s whole circuit reserves, two
/// per reserved gate in the order the stages inject them, as
/// `capture_with_stage_values` takes them: read off the stages'
/// polynomials, each of which holds its stage's values at its wires'
/// degrees whatever its alpha.
fn reserved<S: Front<Pasta, TestR, R, HEADER_SIZE>>(prepared: &Prepared<Pasta, S>) -> Vec<S::F> {
    type Digits<S> = DigitsStage<Pasta, S, TestR, R, HEADER_SIZE>;
    let coefficients: Vec<Vec<S::F>> = loaded_stages(prepared)
        .0
        .iter()
        .map(|stage| stage.iter_coeffs().collect())
        .collect();
    // The digits stage is the last the circuit reserves: its end, the
    // SYSTEM gate aside, is every reserved gate.
    let gates = <Digits<S> as Stage<S::F, R>>::skip_gates()
        + <Digits<S> as StageExt<S::F, R>>::num_gates()
        - 1;
    (0..2 * gates)
        .map(|index| {
            let degree = wire_degree::<R>(index);
            coefficients
                .iter()
                .fold(S::F::ZERO, |sum, stage| sum + stage[degree])
        })
        .collect()
}

/// Side `S`'s whole circuit, laid out as `prepared` is.
fn circuit<S: Front<Pasta, TestR, R, HEADER_SIZE>>(
    prepared: &Prepared<Pasta, S>,
) -> Whole<'static, Pasta, S, TestR, R, HEADER_SIZE> {
    WholeCircuit::new(prepared.tables.clone(), crate::pasta::baked_aggregator())
}

/// Captures side `S`'s whole circuit over `prepared`, with the stages'
/// values `prepared` holds: the production verifier over the production
/// stages.
///
/// # Errors
///
/// Fails if `prepared` does not satisfy the circuit.
fn capture<S: Front<Pasta, TestR, R, HEADER_SIZE>>(
    prepared: &Prepared<Pasta, S>,
) -> ragu_core::Result<Capture<S::F>> {
    capture_with_stage_values(&circuit(prepared), prepared, &reserved(prepared))
}

/// Side `S`'s whole circuit rejects `prepared`.
fn rejected<S: Front<Pasta, TestR, R, HEADER_SIZE>>(prepared: &Prepared<Pasta, S>) -> bool {
    capture(prepared).is_err()
}

/// The points side `S`'s verifier exposes over `prepared`, as the prover's
/// run of the side leaves them.
fn exposed<S: Prepare<Pasta>>(prepared: &Prepared<Pasta, S>) -> Vec<S::P> {
    prepared
        .run::<TestR, HEADER_SIZE>(crate::pasta::baked_aggregator())
        .expect("the side runs")
        .exposed
}

/// Fills `prepared`'s lifts and digits stages again, by the prover's run
/// of the side over what `prepared` now holds.
fn refill<S: Prepare<Pasta>>(prepared: &mut Prepared<Pasta, S>) {
    let ran = prepared
        .run::<TestR, HEADER_SIZE>(crate::pasta::baked_aggregator())
        .expect("the side runs");
    prepared.lifts.elements = ran.lifts;
    prepared.digits.elements = ran.digits;
}

/// Side `S`'s stage polynomials are well formed: each is under its
/// stage's mask, at a random point.
fn well_formed<S: Front<Pasta, TestR, R, HEADER_SIZE>>(
    prepared: &Prepared<Pasta, S>,
    rng: &mut StdRng,
) {
    let (stages, masks) = loaded_stages(prepared);
    let mut builder = TestRegistryBuilder::<S::F, R>::new();
    let masks: Vec<_> = masks
        .into_iter()
        .map(|mask| builder.register_mask(mask))
        .collect();
    let registry = builder.finalize().expect("a registry of the stages' masks");
    let y = S::F::random(|bytes| rng.fill_bytes(bytes));
    for (index, (stage, mask)) in stages.iter().zip(masks).enumerate() {
        assert_eq!(
            stage.revdot(&registry.y(mask, y)),
            S::F::ZERO,
            "{} stage {index} is under its mask",
            S::NAME
        );
    }
}

/// Each side's stage polynomials are well formed under their masks, and
/// its whole circuit is satisfied by the stages the prover's run of the
/// side fills.
#[test]
fn the_whole_circuits_are_satisfied() {
    let setup = Setup::new();
    let sides = setup.sides();
    let mut rng = StdRng::seed_from_u64(11);
    well_formed(&sides.native, &mut rng);
    well_formed(&sides.nested, &mut rng);
    let native = capture(&sides.native).expect("the circuit-field side is satisfied");
    assert!(constraints_hold(
        &native.recorder.events,
        &native.recorder.values
    ));
    let nested = capture(&sides.nested).expect("the scalar-field side is satisfied");
    assert!(constraints_hold(
        &nested.recorder.events,
        &nested.recorder.values
    ));
}

/// The two sides' lifts and IPA scalar digits agree with the native
/// verifier's values. This compares the new verifier's filled stages with
/// values computed before it runs, independently of the page checker.
#[test]
fn the_sides_match_the_native_verifiers_challenges_and_scalars() {
    let setup = Setup::new();
    let pcd = setup.proof.clone().carry(());
    let witness = Witness::prepare::<TestR, HEADER_SIZE, _, ()>(&setup.app, &pcd)
        .expect("the proof verifies");
    let native =
        Prepared::<Pasta, Native>::new::<TestR, R, HEADER_SIZE>(setup.app.params, &witness)
            .expect("the native side prepares");
    let nested =
        Prepared::<Pasta, Nested>::new::<TestR, R, HEADER_SIZE>(setup.app.params, &witness)
            .expect("the nested side prepares");
    let lifts: Vec<Fp> = witness
        .native
        .raw
        .in_order()
        .into_iter()
        .map(|raw| lift_endoscalar(extract_endoscalar(raw).expect("a squeeze is in range")))
        .collect();
    assert_eq!(native.lifts.elements, lifts, "the host curve's challenges");
    let digest = native.digest.expect("the side squeezes the digest");
    assert_eq!(
        convert_challenge::<Fp, Fq>(digest).ok(),
        witness.nested.raw.in_order().last().copied(),
        "the digest is the nested curve's last round challenge"
    );

    let mut lifts: Vec<Fq> = witness
        .nested
        .raw
        .in_order()
        .into_iter()
        .map(|raw| lift_endoscalar(extract_endoscalar(raw).expect("a squeeze is in range")))
        .collect();
    let fuse_challenges = witness.fuse.in_order();
    lifts.extend(fuse::LIFTED.map(|index| {
        lift_endoscalar::<Fq>(
            extract_endoscalar(fuse_challenges[index]).expect("a squeeze is in range"),
        )
    }));
    lifts.extend(
        witness.native.raw.in_order().into_iter().map(|raw| {
            lift_endoscalar::<Fq>(extract_endoscalar(raw).expect("a squeeze is in range"))
        }),
    );
    assert_eq!(nested.lifts.elements, lifts, "the other side's challenges");

    // A signed digit represents +1 or -1. Reconstruct each scalar from
    // the stage's digits and compare it with the native verifier's value.
    fn scalar<F: Field>(digits: &[F]) -> F {
        let mut value = F::ZERO;
        let mut power = F::ONE;
        for &digit in digits {
            assert!(digit == F::ONE || digit == -F::ONE, "a signed digit");
            value += digit * power;
            power = power.double();
        }
        value
    }
    let native_width = Fp::CAPACITY as usize + 1;
    for (index, expected) in [
        witness.native.v,
        witness.proof.native.opening.c,
        witness.native.cbz,
    ]
    .into_iter()
    .enumerate()
    {
        let first = index * native_width;
        assert_eq!(
            scalar(&native.digits.elements[first..first + native_width]),
            expected,
            "the native IPA scalar at {index}"
        );
    }
    assert_eq!(
        native.digits.elements[3 * native_width],
        -Fp::ONE,
        "the decompression flag is unset outside a step"
    );
    let nested_width = Fq::CAPACITY as usize + 1;
    for (index, expected) in [
        witness.nested.v,
        witness.proof.nested.opening.c,
        witness.nested.cbz,
    ]
    .into_iter()
    .enumerate()
    {
        let first = index * nested_width;
        assert_eq!(
            scalar(&nested.digits.elements[first..first + nested_width]),
            expected,
            "the nested IPA scalar at {index}"
        );
    }
}

/// Where the circuit-field side's stage wires sit among its circuit's
/// reserved wires: the stages in chain order, each two wires a gate, a
/// point's $x$ then $y$ before the elements.
struct StageWires {
    messages: usize,
}

impl StageWires {
    fn native() -> Self {
        type Instance = InstanceStage<Pasta, Native, TestR, R, HEADER_SIZE>;
        StageWires {
            messages: 2
                * (Values::NATIVE.prefix_gates() + <Instance as StageExt<Fp, R>>::num_gates()),
        }
    }

    /// The two reserved wires of message point `position`.
    fn message_point(&self, position: usize) -> [usize; 2] {
        [
            self.messages + 2 * position,
            self.messages + 2 * position + 1,
        ]
    }
}

/// The verifier holds the points a stage holds to the curve itself: the
/// stages load their points unenforced, so this is the equation that holds
/// the nested reduction's $[f]$ to the curve. With $[f]$'s stage wires
/// rewritten to $(0, 1)$, which lies on no Pasta curve since $5$ is a
/// non-residue in both fields, the circuit's constraints do not hold.
#[test]
fn the_verifier_rejects_an_off_curve_f() {
    let setup = Setup::new();
    let sides = setup.sides();
    let prepared = &sides.native;
    let position = prepared
        .tables
        .layout
        .messages
        .points_of_curve
        .at(message_points::F);
    let [fx, fy] = StageWires::native().message_point(position);
    let capture = capture(prepared).expect("the honest circuit satisfies its constraints");
    let (events, stage_wires) = (&capture.recorder.events, &capture.stage_wires);
    let honest = &capture.recorder.values;
    assert_eq!(
        (honest[stage_wires[fx]], honest[stage_wires[fy]]),
        prepared.messages.points[position]
            .coordinates()
            .expect("[f] is not the identity"),
        "the wires are [f]'s"
    );
    // The curve equation is a constraint over the stage's two wires alone:
    // with them rewritten and every other wire as it was, a constraint
    // fails, whatever the wires derived from them would be.
    let mut changed = honest.clone();
    changed[stage_wires[fx]] = Fp::ZERO;
    changed[stage_wires[fy]] = Fp::ONE;
    assert!(
        !constraints_hold(events, &changed),
        "the verifier rejects [f] = (0, 1)"
    );
}

/// What a few wires decide by themselves in a recorded circuit: the wires
/// they force, and whether the constraints over forced wires alone hold.
///
/// A wire is forced where a linear combination or a gate's product is of
/// forced wires, or where a constraint names forced wires and one other.
/// Whatever the rest of the circuit holds, no witness with the given
/// values satisfies it if such a constraint fails.
struct Forced<F> {
    /// The pass each wire was last forced in, and its value then.
    forced: Vec<u32>,
    values: Vec<F>,
    pass: u32,
}

impl<F: Field> Forced<F> {
    fn new(wires: usize) -> Self {
        Forced {
            forced: alloc::vec![0; wires],
            values: alloc::vec![F::ZERO; wires],
            pass: 0,
        }
    }

    fn known(&self, wire: usize) -> bool {
        self.forced[wire] == self.pass
    }

    fn force(&mut self, wire: usize, value: F) {
        self.forced[wire] = self.pass;
        self.values[wire] = value;
    }

    /// Whether every constraint over the wires `held` force holds, with
    /// `held` at the values given.
    fn holds(&mut self, events: &[Event<F>], held: [(usize, F); 2]) -> bool {
        self.pass += 1;
        self.force(Recorder::<F>::ONE, F::ONE);
        for (wire, value) in held {
            self.force(wire, value);
        }
        // A walk of the events forces what follows from the wires forced
        // so far; a constraint may force a wire of an earlier event, so
        // they are walked until a walk forces nothing.
        let mut grew = true;
        while grew {
            grew = false;
            for event in events {
                match event {
                    Event::Lin { out, terms } => {
                        if !self.known(*out) && terms.iter().all(|&(wire, _)| self.known(wire)) {
                            let value = terms.iter().fold(F::ZERO, |sum, &(wire, coeff)| {
                                sum + coeff * self.values[wire]
                            });
                            self.force(*out, value);
                            grew = true;
                        }
                    }
                    Event::Gate { a, b, c } => {
                        if self.known(*a) && self.known(*b) && !self.known(*c) {
                            self.force(*c, self.values[*a] * self.values[*b]);
                            grew = true;
                        }
                    }
                    Event::Enforce { terms } => {
                        let mut free = terms.iter().filter(|&&(wire, _)| !self.known(wire));
                        if let (Some(&(wire, coeff)), None) = (free.next(), free.next())
                            && let Some(inverse) = coeff.invert()
                        {
                            let rest = terms
                                .iter()
                                .filter(|&&(other, _)| other != wire)
                                .fold(F::ZERO, |sum, &(other, coeff)| {
                                    sum + coeff * self.values[other]
                                });
                            self.force(wire, -rest * inverse);
                            grew = true;
                        }
                    }
                    Event::Extra { .. } => {}
                }
            }
        }
        events.iter().all(|event| match event {
            Event::Enforce { terms } => {
                !terms.iter().all(|&(wire, _)| self.known(wire))
                    || terms.iter().fold(F::ZERO, |sum, &(wire, coeff)| {
                        sum + coeff * self.values[wire]
                    }) == F::ZERO
            }
            Event::Gate { a, b, c } => {
                !(self.known(*a) && self.known(*b) && self.known(*c))
                    || self.values[*a] * self.values[*b] == self.values[*c]
            }
            _ => true,
        })
    }
}

/// Each side holds every point its stages hold to the curve: the stages
/// load their points unenforced, so the side's verifier emits the curve
/// equation for each of the instance's commitments and of the messages'.
/// For every such point, what its two stage wires force by themselves is
/// satisfied by the point and is not by $(0, 1)$, which lies on no Pasta
/// curve: no witness of the circuit has the point off the curve, whatever
/// the other wires hold.
#[test]
fn every_stage_point_is_held_to_the_curve() {
    fn check<S: Front<Pasta, TestR, R, HEADER_SIZE>>(prepared: &Prepared<Pasta, S>) {
        let capture = capture(prepared).expect("the honest circuit satisfies its constraints");
        let (events, stage_wires) = (&capture.recorder.events, &capture.stage_wires);
        let honest = &capture.recorder.values;
        let layout = prepared.tables.layout;
        let points = layout
            .instance
            .commitments
            .positions()
            .map(|position| prepared.instance.points[position])
            .chain(
                layout
                    .messages
                    .points_of_curve
                    .positions()
                    .map(|position| prepared.messages.points[position]),
            );
        let mut forced = Forced::new(honest.len());
        // The stage wires taken for a point so far: two stage slots that
        // hold one point are two pairs of wires.
        let mut taken = alloc::collections::BTreeSet::new();
        let mut checked = 0;
        for (index, point) in points.enumerate() {
            let (x, y) = point.coordinates().expect("a stage holds no identity");
            let at = (0..stage_wires.len() - 1)
                .find(|&at| {
                    !taken.contains(&at)
                        && honest[stage_wires[at]] == x
                        && honest[stage_wires[at + 1]] == y
                })
                .unwrap_or_else(|| panic!("{} point {index} has its stage wires", S::NAME));
            taken.insert(at);
            let wires = [stage_wires[at], stage_wires[at + 1]];
            assert!(
                forced.holds(events, [(wires[0], x), (wires[1], y)]),
                "{} point {index} satisfies what its wires force",
                S::NAME
            );
            assert!(
                !forced.holds(events, [(wires[0], S::F::ZERO), (wires[1], S::F::ONE)]),
                "{} point {index} at (0, 1) is rejected by what its two wires force alone",
                S::NAME
            );
            checked += 1;
        }
        assert_eq!(
            checked,
            layout.instance.commitments.len + layout.messages.points_of_curve.len,
            "every point of the side's stages"
        );
    }
    let setup = Setup::new();
    let sides = setup.sides();
    check(&sides.native);
    check(&sides.nested);
}

/// Each side rejects every scalar it holds of the proof, moved by one:
/// every scalar message of the reduction it checks, and every scalar and
/// header element of its instance.
#[test]
fn every_tampered_scalar_is_rejected() {
    fn check<S: Front<Pasta, TestR, R, HEADER_SIZE>>(prepared: &mut Prepared<Pasta, S>) {
        let layout = prepared.tables.layout;
        for position in layout.messages.scalars.positions() {
            prepared.messages.elements[position] += S::F::ONE;
            assert!(
                rejected(prepared),
                "{} message scalar {position} moved is rejected",
                S::NAME
            );
            prepared.messages.elements[position] -= S::F::ONE;
        }
        let instance = layout.instance;
        for position in instance
            .scalars
            .positions()
            .chain(instance.output_header.positions())
        {
            prepared.instance.elements[position] += S::F::ONE;
            assert!(
                rejected(prepared),
                "{} instance element {position} moved is rejected",
                S::NAME
            );
            prepared.instance.elements[position] -= S::F::ONE;
        }
        assert!(!rejected(prepared), "the restored stages are accepted");
    }
    let setup = Setup::new();
    let mut sides = setup.sides();
    check(&mut sides.native);
    check(&mut sides.nested);
}

/// What holds each message of the reduction, on the scalar-field side.
/// The side takes its challenges as bits, so a message moved leaves them
/// as they were; with the side's lifts and digits filled again over the
/// moved message, nothing the side writes disagrees with it, and what is
/// left to reject it is the reduction.
///
/// The five derived openings, $p(1/r)$ and $q(r)$ enter the split
/// identity, which rejects each. The two $\varepsilon$ enter the target
/// of $p(0)$ alone, an opening the batch takes: the side accepts them
/// moved, and its $v$ moves with them, which the other side's IPA holds
/// through the digits.
#[test]
fn the_reduction_holds_each_message() {
    use crate::compress::revdot::fold::Derived;

    let setup = Setup::new();
    let mut sides = setup.sides();
    let nested = &mut sides.nested;
    let scalars = nested.tables.layout.messages.scalars;
    let honest = nested.digits.elements.clone();
    let messages = 2 + Derived::ALL.len() + 2;
    assert_eq!(messages, 9);
    for message in 0..messages {
        let position = scalars.at(message);
        nested.messages.elements[position] += Fq::ONE;
        refill(nested);
        if message < 2 {
            assert!(
                !rejected(nested),
                "epsilon {message} is not in the split identity"
            );
            assert_ne!(
                nested.digits.elements, honest,
                "epsilon {message} moved moves the digits of v"
            );
        } else {
            assert!(
                rejected(nested),
                "the split identity rejects message {message} moved"
            );
        }
        nested.messages.elements[position] -= Fq::ONE;
    }
    refill(nested);
    assert_eq!(nested.digits.elements, honest);
    assert!(!rejected(nested), "the restored messages are accepted");
}

/// The IPA's point checks reject a witness point other than the proof's:
/// a round's $u_j^{-1} L_j$, which the round's challenge must scale back
/// to $L_j$, and $G'$, which nothing but the final equality holds outside
/// a decompression step.
#[test]
fn the_ipa_rejects_other_witness_points() {
    fn check<S: Front<Pasta, TestR, R, HEADER_SIZE>>(prepared: &mut Prepared<Pasta, S>) {
        // Another point of the curve: the point doubled.
        let other = |point: S::P| (point * S::Other::ONE.double()).to_affine();
        let g_prime = prepared.supplied.g_prime;
        prepared.supplied.g_prime = other(g_prime);
        assert!(
            rejected(prepared),
            "{}: the final equality rejects another G'",
            S::NAME
        );
        prepared.supplied.g_prime = g_prime;
        let last = prepared.supplied.inverse_scaled.len() - 1;
        for round in [0, last] {
            let scaled = prepared.supplied.inverse_scaled[round];
            prepared.supplied.inverse_scaled[round] = other(scaled);
            assert!(
                rejected(prepared),
                "{}: round {round} rejects another witness point",
                S::NAME
            );
            prepared.supplied.inverse_scaled[round] = scaled;
        }
        assert!(!rejected(prepared), "the proof's points are accepted");
    }
    let setup = Setup::new();
    let mut sides = setup.sides();
    check(&mut sides.native);
    check(&mut sides.nested);
}

#[test]
fn rejects_tampered_stages() {
    let setup = Setup::new();
    let mut sides = setup.sides();

    // A message: the native inner epsilon fails the reduction's identity.
    sides.native.messages.elements[0] += Fp::ONE;
    assert!(rejected(&sides.native), "a tampered message is rejected");
    sides.native.messages.elements[0] -= Fp::ONE;

    // The instance: c fails the targets' binding to the unified instance.
    let scalars = sides.native.tables.layout.instance.scalars;
    let c = scalars.at(native_scalars::C);
    sides.native.instance.elements[c] += Fp::ONE;
    assert!(rejected(&sides.native), "a tampered instance is rejected");
    sides.native.instance.elements[c] -= Fp::ONE;

    // The circuit id is shared by transcript replay, the targets and the
    // challenge stage's base-case sign.
    let id = scalars.at(native_scalars::OMEGA_J);
    sides.native.instance.elements[id] += Fp::ONE;
    assert!(rejected(&sides.native), "a tampered circuit id is rejected");
    sides.native.instance.elements[id] -= Fp::ONE;

    // The stages the side fills: a lift other than the challenge's the
    // transcript squeezes, and a digit other than the scalar's.
    sides.native.lifts.elements[squeezed::W] += Fp::ONE;
    assert!(rejected(&sides.native), "a tampered lift is rejected");
    sides.native.lifts.elements[squeezed::W] -= Fp::ONE;
    sides.native.digits.elements[0] = -sides.native.digits.elements[0];
    assert!(rejected(&sides.native), "a tampered digit is rejected");
    sides.native.digits.elements[0] = -sides.native.digits.elements[0];

    // The registry's evaluations are the online query stage's, which the
    // step's fuse proves: an evaluation the prover supplies other than its
    // wire, a wire other than the evaluation the verifier reads, and an
    // input other than the coordinate the verifier derives are each
    // rejected.
    {
        let supplied = &mut sides.native.supplied;
        supplied.restriction_at_w += Fp::ONE;
        assert!(
            rejected(&sides.native),
            "a restriction at w other than its wire is rejected"
        );
        sides.native.supplied.restriction_at_w -= Fp::ONE;
        let last = sides.native.supplied.restrictions.len() - 1;
        for index in [0, last] {
            sides.native.supplied.restrictions[index] += Fp::ONE;
            assert!(
                rejected(&sides.native),
                "a restriction other than its wire is rejected"
            );
            sides.native.supplied.restrictions[index] -= Fp::ONE;
        }
        // The query binding's values are the registry's, every one.
        let last = sides.native.supplied.bindings[1].len() - 1;
        for index in [0, last] {
            sides.native.supplied.bindings[1][index] += Fp::ONE;
            assert!(
                rejected(&sides.native),
                "a registry value other than its wire is rejected"
            );
            sides.native.supplied.bindings[1][index] -= Fp::ONE;
        }
        let values = Values::NATIVE;
        for wire in [
            values.claim(0),
            values.fixed(0),
            values.at_w(),
            values.at_circuit(),
            values.at_u(),
            values.at_w_c(),
            values.children()[0],
            values.children_y()[1],
            values.children_u()[0],
            values.u_y(),
        ] {
            let position = Values::value_at(wire);
            sides.native.online_query.elements[position] += Fp::ONE;
            assert!(
                rejected(&sides.native),
                "a query wire other than the evaluation read is rejected"
            );
            sides.native.online_query.elements[position] -= Fp::ONE;
        }
        for input in online::MESH.inherited_coordinates().len()..online::input::NATIVE {
            let position = Values::input_at(input);
            sides.native.online_input.elements[position] += Fp::ONE;
            assert!(
                rejected(&sides.native),
                "an input other than the proof's coordinate is rejected"
            );
            sides.native.online_input.elements[position] -= Fp::ONE;
        }
        let values = Values::NESTED;
        for wire in [
            values.claim(0),
            values.at_w(),
            values.at_w_c(),
            values.u_y(),
        ] {
            let position = Values::value_at(wire);
            sides.nested.online_query.elements[position] += Fq::ONE;
            assert!(
                rejected(&sides.nested),
                "a nested query wire other than the evaluation read is rejected"
            );
            sides.nested.online_query.elements[position] -= Fq::ONE;
        }
        for input in online::MESH.inherited_coordinates().len()..online::input::NESTED {
            let position = Values::input_at(input);
            sides.nested.online_input.elements[position] += Fq::ONE;
            assert!(
                rejected(&sides.nested),
                "a nested input other than the proof's coordinate is rejected"
            );
            sides.nested.online_input.elements[position] -= Fq::ONE;
        }
    }

    // The scalar-field side's messages and stages likewise.
    sides.nested.messages.elements[0] += Fq::ONE;
    assert!(
        rejected(&sides.nested),
        "a tampered nested message is rejected"
    );
    sides.nested.messages.elements[0] -= Fq::ONE;
    sides.nested.lifts.elements[squeezed::W] += Fq::ONE;
    assert!(
        rejected(&sides.nested),
        "a tampered nested lift is rejected"
    );
    sides.nested.lifts.elements[squeezed::W] -= Fq::ONE;
    sides.nested.digits.elements[0] = -sides.nested.digits.elements[0];
    assert!(
        rejected(&sides.nested),
        "a tampered nested digit is rejected"
    );
    sides.nested.digits.elements[0] = -sides.nested.digits.elements[0];

    assert!(
        !rejected(&sides.native) && !rejected(&sides.nested),
        "restored, both accept"
    );
}

/// The $G'$ that keeps the host IPA's final equality on the scalar-field
/// side when its left-hand side moves by `moved` or its $v$ becomes `v`:
/// the equality is $\text{left} = v G_0 + c G' + c b z U$, and nothing
/// holds $G'$ outside the decompression step.
fn rebalanced(
    nested: &Prepared<Pasta, Nested>,
    moved: <Pasta as Cycle>::HostCurve,
    v: Fp,
) -> <Pasta as Cycle>::HostCurve {
    let params = crate::pasta::baked_aggregator();
    let [honest_v, c, cbz] = [
        nested.aux.foreign[0],
        nested.aux.foreign[1],
        nested.aux.foreign[2],
    ];
    let g_0 = <Nested as Side<Pasta>>::generators(params)[0];
    let u = <Nested as Side<Pasta>>::u(params);
    let left = g_0 * honest_v + nested.supplied.g_prime * c + u * cbz + moved.to_projective();
    let scaled = (left - g_0 * v - u * cbz).to_affine();
    (scaled * c.invert().expect("c is nonzero")).to_affine()
}

/// What scales by a challenge taken from bits holds those bits to the
/// lifts stage. The scalar-field side reads other bits for the host
/// curve's $\xi$ where it scales by it, the one place, than the bits it
/// lifts into the lifts stage, with the $G'$ a prover reading those bits
/// would pick, the one that keeps the IPA's final equality: every point
/// check is then consistent with the other bits, and the circuit fails,
/// since the bits read are not the lifts stage's. With the challenge
/// itself the other bits, the stage following, it is satisfied, so the
/// failure is the read's alone.
#[test]
fn chains_hold_their_bits_to_the_lifts_stage() {
    let setup = Setup::new();
    let mut sides = setup.sides();
    let nested = &mut sides.nested;
    let xi = challenges_per_curve::<TestR>() + fuse::LIFTED.len() + squeezed::XI;
    let honest = nested.aux.challenge_bits[xi];
    let other = honest.flip_bit(5);
    // The left-hand side holds [xi] S, so it moves by the difference of
    // the lifts times the IPA's masking commitment.
    let s_commitment = nested.messages.points[nested
        .tables
        .layout
        .messages
        .points_of_curve
        .at(message_points::S_COMMITMENT)];
    let moved = lift_endoscalar::<Fp>(other) - lift_endoscalar::<Fp>(honest);
    let v = nested.aux.foreign[0];
    nested.supplied.g_prime = rebalanced(nested, (s_commitment * moved).to_affine(), v);

    nested.aux.read = Some((xi, other));
    assert!(
        rejected(nested),
        "a read of other bits than the lifts stage's fails the circuit"
    );
    nested.aux.read = None;
    nested.aux.challenge_bits[xi] = other;
    refill(nested);
    assert!(
        !rejected(nested),
        "with the lifts stage following the bits, the circuit is satisfied"
    );
}

/// What scales a point by a full-width scalar of the other field takes
/// the scalar's digits as witnesses and sums their generators into its
/// recomputation of the other side's digits stage. The scalar-field side
/// takes another $v$ for the host curve's final check, with the $G'$ that
/// keeps the IPA's final equality under it: the side's circuit is then
/// satisfied, and what the side exposes for the circuit-field side's
/// digits stage is no longer that stage's commitment, so the binding claim
/// is what fails.
#[test]
fn scalings_hold_their_digits_to_the_other_sides_stage() {
    let setup = Setup::new();
    let mut sides = setup.sides();
    let (_, of_native) = bound_commitments(&sides);
    assert_eq!(exposed(&sides.nested), of_native);

    let nested = &mut sides.nested;
    let v = nested.aux.foreign[0] + Fp::ONE;
    let identity = <Pasta as Cycle>::HostCurve::identity();
    nested.supplied.g_prime = rebalanced(nested, identity, v);
    nested.aux.foreign[0] = v;
    assert!(
        !rejected(nested),
        "the circuit is satisfied under the other digits"
    );
    assert_ne!(
        exposed(nested)[0],
        of_native[0],
        "the recomputed digits stage is no longer the circuit-field side's"
    );
}

/// The step binding holds the host curve's $G'$ in the decompression
/// step and nothing in any other. The polynomial $s(X)$ over the round
/// challenges the circuit-field side holds commits to the
/// $G'$ the scalar-field side holds. With the flag set, the circuit-field
/// side accepts the opening of that polynomial and no other value, and
/// the transcript's last squeeze as the staged digest and no other value,
/// and the scalar-field side accepts that commitment as the host batch
/// commitment and no other point. With it unset, none is held. The flag is
/// the same on both sides only when the scalar-field side's recomputation
/// of the circuit-field side's digits stage is that stage's commitment.
#[test]
fn the_step_binding_holds_g_prime_to_the_host_batch_commitment() {
    type NativeDigits = DigitsStage<Pasta, Native, TestR, R, HEADER_SIZE>;
    let setup = Setup::new();
    let params = crate::pasta::baked_aggregator();
    let sides = setup.sides();
    let mut rng = StdRng::seed_from_u64(29);
    let digits_commitment = |native: &Prepared<Pasta, Native>| {
        ReferenceBackend::sparse_commit_to_affine(
            &<NativeDigits as StageExt<Fp, R>>::rx(Fp::ZERO, &native.digits).unwrap(),
            Pasta::host_generators(params),
        )
    };

    // s(X) over the host IPA's round challenges, and its commitment.
    let native = &sides.native;
    let rounds = &native.lifts.elements[squeezed::ROUNDS..];
    let s = crate::ipa::challenge_polynomial(rounds);
    let poly = sparse::Polynomial::<Fp, R>::from_coeffs(s);
    let commitment: <Pasta as Cycle>::HostCurve =
        ReferenceBackend::sparse_commit_to_affine(&poly, Pasta::host_generators(params));
    assert_eq!(
        commitment, sides.nested.supplied.g_prime,
        "s(X) commits to G'"
    );

    // The circuit-field side: the opening of s(X) at a point, or not,
    // and the transcript's digest, its last squeeze, or not.
    let x = Fp::random(|bytes| rng.fill_bytes(bytes));
    let y = poly.eval(x);
    let digest = native.digest.expect("the circuit-field side has a digest");
    let query = |opening| {
        let mut query = native.online_query.elements.clone();
        query[online::QUERY_Y] = x;
        query[Values::value_at(Values::NATIVE.ipa())] = opening;
        query
    };
    let prepared = |opening, digest| {
        native
            .for_decompression::<TestR, HEADER_SIZE>(params, digest)
            .unwrap()
            .with_online(native.online_input.elements.clone(), query(opening))
            .unwrap()
    };
    let opened = prepared(y, digest);
    assert!(
        !rejected(&opened),
        "the opening of s(X) and the digest are accepted"
    );
    let other = prepared(y + Fp::ONE, digest);
    assert!(rejected(&other), "another value is rejected under the flag");
    let other_digest = prepared(y, digest + Fp::ONE);
    assert!(
        rejected(&other_digest),
        "another digest is rejected under the flag"
    );
    let step = native.tables.layout.instance.step;
    for held in [other, other_digest] {
        let mut unset = held;
        unset.instance.elements[step.at(0)] = Fp::ZERO;
        refill(&mut unset);
        assert!(!rejected(&unset), "nothing is held without the flag");
    }

    let nested = &sides.nested;
    let span = nested.tables.layout.instance.commitments;
    let wallet_slots = core::array::from_fn(|i| nested.instance.points[span.at(span.len - 2 + i)]);
    let prepare = |flag, slots, ipa| nested.for_step(flag, slots, ipa);
    let held = prepare(true, wallet_slots, commitment);
    assert!(
        !rejected(&held),
        "the wallet slots and IPA commitment are accepted"
    );
    let stray = Pasta::host_generators(params).g()[7];
    assert!(
        rejected(&prepare(true, wallet_slots, stray)),
        "another IPA point is rejected"
    );
    for i in 0..wallet_slots.len() {
        let mut wrong = wallet_slots;
        wrong[i] = stray;
        assert!(
            rejected(&prepare(true, wrong, commitment)),
            "wallet slot {i} is bound"
        );
    }
    let free = prepare(false, [stray; 2], stray);
    assert!(!rejected(&free), "no point is held without the flag");
    assert_eq!(&exposed(&free)[1..], &[stray; 3]);

    // The flag crosses in the digits stage: the scalar-field side's
    // recomputation is the stage's commitment only under the same flag.
    assert_eq!(exposed(&held)[0], digits_commitment(&opened));
    assert_eq!(exposed(&free)[0], digits_commitment(native));
    assert_ne!(exposed(&free)[0], digits_commitment(&opened));
    assert_ne!(exposed(&held)[0], digits_commitment(native));
}

/// The nested curve's $G'$ is the commitment of $s(X)$ in the step's
/// nested batch, in every step. The polynomial $s(X)$ over the round
/// challenges the scalar-field side holds commits to the $G'$
/// the circuit-field side holds and exposes. The scalar-field side
/// accepts the opening of that polynomial at the query stage's $y$ and no
/// other value, under no flag.
#[test]
fn the_nested_batch_opening_holds_the_nested_g_prime() {
    let setup = Setup::new();
    let params = crate::pasta::baked_aggregator();
    let sides = setup.sides();
    let mut rng = StdRng::seed_from_u64(31);

    // s(X) over the nested IPA's round challenges, and its commitment.
    let nested = &sides.nested;
    let rounds = &nested.lifts.elements[squeezed::ROUNDS..challenges_per_curve::<TestR>()];
    let poly = sparse::Polynomial::<Fq, R>::from_coeffs(crate::ipa::challenge_polynomial(rounds));
    let commitment: <Pasta as Cycle>::NestedCurve =
        ReferenceBackend::sparse_commit_to_affine(&poly, Pasta::nested_generators(params));
    let native = &sides.native;
    let g_prime = native.supplied.g_prime;
    assert_eq!(commitment, g_prime, "s(X) commits to G'");
    assert_eq!(
        exposed(native).last(),
        Some(&g_prime),
        "the circuit-field side exposes its G'"
    );

    // Prepared outside a step, the side holds the opening at zero.
    assert!(!rejected(nested), "s(0) = 1 is accepted");
    let x = Fq::random(|bytes| rng.fill_bytes(bytes));
    let y = poly.eval(x);
    let prepared = |opening| {
        let mut query = nested.online_query.elements.clone();
        query[online::QUERY_Y] = x;
        query[Values::value_at(Values::NESTED.ipa())] = opening;
        nested
            .clone()
            .with_online(nested.online_input.elements.clone(), query)
            .unwrap()
    };
    assert!(!rejected(&prepared(y)), "the opening of s(X) is accepted");
    assert!(
        rejected(&prepared(y + Fq::ONE)),
        "another value is rejected"
    );
    // The side has no flag for this check: the decompression flag it
    // takes from the other side holds the points alone.
    let held: [_; 2] = core::array::from_fn(|i| nested.supplied.outputs[i]);
    for flag in [false, true] {
        let stepped = prepared(y + Fq::ONE).for_step(flag, held, nested.supplied.host_ipa);
        assert!(rejected(&stepped), "another value is rejected");
    }
}

/// The statement circuit exposes the instance stage's output header as its
/// public output: at the aggregator rank its trace satisfies the circuit
/// at that header's $k(y)$ and at no other's.
#[test]
fn statement_circuit_exposes_the_output_header() {
    type Instance = InstanceStage<Pasta, Native, TestR, R, HEADER_SIZE>;
    type Input = OnlineInputStage<Pasta, Native, R>;
    type Query = OnlineQueryStage<Pasta, Native, R>;
    let setup = Setup::new();
    let sides = setup.sides();
    let prepared = &sides.native;
    let circuit = StatementCircuit::<Pasta, Native, TestR, R, HEADER_SIZE>::new();
    let gates = ragu_circuits::testing::synthesis_counts(&circuit)
        .unwrap()
        .num_gates;
    assert!(gates <= R::blind_gate());

    let span = prepared.tables.layout.instance.output_header;
    let header: Vec<Fp> = span
        .positions()
        .map(|position| prepared.instance.elements[position])
        .collect();
    let trace = circuit.trace(prepared).unwrap().into_parts().0;
    let mut builder = TestRegistryBuilder::<Fp, R>::new();
    let handle = builder.register_circuit(circuit.clone()).unwrap();
    let mask = builder.register_mask(<Instance as StageExt<Fp, R>>::stage_mask().unwrap());
    let final_mask = builder.register_mask(<Instance as StageExt<Fp, R>>::final_mask().unwrap());
    let registry = builder.finalize().unwrap();
    let mut rng = StdRng::seed_from_u64(13);
    let y = Fp::random(|bytes| rng.fill_bytes(bytes));

    let stage = <Instance as StageExt<Fp, R>>::rx(Fp::ZERO, &prepared.instance).unwrap();
    assert_eq!(stage.revdot(&registry.y(mask, y)), Fp::ZERO);
    let mut rx = registry.assemble(&trace, handle, Fp::ZERO).unwrap();
    assert_eq!(rx.revdot(&registry.y(final_mask, y)), Fp::ZERO);
    rx.add_assign(&stage);
    // The online stages come first in every circuit of the side.
    rx.add_assign(&<Input as StageExt<Fp, R>>::rx(Fp::ZERO, &prepared.online_input).unwrap());
    rx.add_assign(&<Query as StageExt<Fp, R>>::rx(Fp::ZERO, &prepared.online_query).unwrap());
    // Prepared outside a step, the side's step binding is all zero.
    let step = || -> FixedVec<Fp, ConstLen<{ crate::profile::STEP_BINDING }>> {
        FixedVec::try_from(alloc::vec![Fp::ZERO; crate::profile::STEP_BINDING]).unwrap()
    };
    let own: FixedVec<Fp, ConstLen<HEADER_SIZE>> = FixedVec::try_from(header.clone()).unwrap();
    assert_eq!(
        rx.revdot(&registry.y(handle, y)),
        circuit.ky((own, step()), y).unwrap()
    );
    let mut other = header;
    other[0] += Fp::ONE;
    let other: FixedVec<Fp, ConstLen<HEADER_SIZE>> = FixedVec::try_from(other).unwrap();
    assert_ne!(
        rx.revdot(&registry.y(handle, y)),
        circuit.ky((other, step()), y).unwrap()
    );
}

/// The points each side's whole circuit exposes: the zero-alpha
/// commitments of the scalar-field side's run stages, which the transcript
/// absorbed, and of its lifts and digits stages, which the circuit-field
/// side recomputes, then the nested curve's $G'$ that side holds; and the
/// commitment of the circuit-field side's digits stage, then the output
/// commitments and the host IPA's commitment the scalar-field side holds,
/// placeholders outside a step.
fn bound_commitments(
    sides: &Sides<Pasta>,
) -> (
    Vec<<Pasta as Cycle>::NestedCurve>,
    Vec<<Pasta as Cycle>::HostCurve>,
) {
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
        // The nested curve's G', which the circuit-field side holds.
        sides.native.supplied.g_prime,
    ]);
    let mut of_native = alloc::vec![ReferenceBackend::sparse_commit_to_affine(
        &<NativeDigits as StageExt<Fp, R>>::rx(Fp::ZERO, &sides.native.digits).unwrap(),
        Pasta::host_generators(params),
    )];
    of_native.extend(nested.supplied.outputs.iter().copied());
    of_native.push(nested.supplied.host_ipa);
    (of_nested, of_native)
}

/// Each side's recomputations are the other side's actual stage
/// commitments, and its whole circuit's public output, which its last page
/// carries to the binding claim, is those points' coordinates in order.
/// Two sides prepared from different compressions of the same proof
/// disagree on every one of them: the challenges, the scalars and the
/// messages all differ.
#[test]
fn whole_circuits_expose_the_other_sides_commitments() {
    let setup = Setup::new();
    let sides = setup.sides();
    let (of_nested, of_native) = bound_commitments(&sides);
    assert_eq!(exposed(&sides.native), of_nested);
    assert_eq!(exposed(&sides.nested), of_native);

    // Each circuit's public output is the exposed points.
    fn output<S: Front<Pasta, TestR, R, HEADER_SIZE>>(prepared: &Prepared<Pasta, S>) -> Vec<S::F> {
        let captured = capture(prepared).expect("the circuit is satisfied");
        captured
            .instance
            .iter()
            .map(|&wire| captured.recorder.values[wire])
            .collect()
    }
    fn coordinates<P: udon::curve::Affine>(points: &[P]) -> Vec<P::Base> {
        points
            .iter()
            .flat_map(|point| {
                let (x, y) = point
                    .coordinates()
                    .expect("a commitment is not the identity");
                [x, y]
            })
            .collect()
    }
    assert_eq!(output(&sides.native), coordinates(&of_nested));
    assert_eq!(output(&sides.nested), coordinates(&of_native));

    // Another compression of the same proof: the sides prepared from it
    // expose its commitments, not this one's. The runs before the first
    // random message are functions of the proof and the challenges the
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
    assert!(first <= masking, "the IPA's masking commitment is random");
    assert!(
        ours[first..]
            .iter()
            .zip(&other_nested[first..])
            .all(|(ours, theirs)| ours != theirs),
        "every run from the first random message on, the lifts and the digits differ between compressions"
    );
    assert_ne!(exposed(&sides.nested), other_native);
}

/// Side `S`'s whole circuit cuts into the pages its side pins, over the
/// carry stage it pins, and the pages are the circuit's: every page loads
/// every stage of the circuit, then the carry stage, and holds its own
/// gates from there to the polynomial's end.
fn cuts_into<S, const H: usize>()
where
    S: Front<Pasta, TestR, R, H>,
{
    use ragu_circuits::staging::Stage;

    let params = crate::pasta::baked_aggregator();
    let paged =
        cut::<Pasta, S, TestR, R, H>(params).expect("the circuit cuts into its pinned pages");
    assert_eq!(paged.num_pages(), S::PAGES.num_pages());

    let (stages, layout) = (paged.stages().clone(), paged.layout().clone());
    assert_eq!(stages.carry, S::PAGES.carry());
    assert!(
        paged.report().slots <= stages.carry,
        "the carry stage holds what the pages carry"
    );
    // The chain a page reserves: the circuit's stages, where the circuit
    // has them, then the carry stage, and the page's own gates after it.
    let chain = <WholeCarry<Pasta, S, TestR, R, H> as Stage<S::F, R>>::gate_ranges();
    assert_eq!(&chain[..chain.len() - 1], &stages.spans[..]);
    assert_eq!(chain.last(), Some(&layout.carry));
    assert_eq!(layout.carry.start, stages.own_start());
    assert_eq!(layout.window(), layout.carry.end..R::blind_gate());
    paged.check().expect("the pages are the circuit's");
}

#[test]
fn the_whole_circuits_cut_into_their_pinned_pages() {
    cuts_into::<Native, HEADER_SIZE>();
    cuts_into::<Nested, HEADER_SIZE>();
    cuts_into::<Native, 1>();
}

/// The decompression's circuits as the aggregator profile's extension:
/// the pinned layout is the pages', the hooks register every page, the
/// statement circuit and every stage and mask at the aggregator rank and
/// refuse any other, and an application over the profile builds at the
/// aggregator rank, where every fuse circuit fits with the extension's
/// polynomials, and its bootstrap proof verifies with the pages run over
/// the wallet application's canonical compressed proof. A wallet proof
/// decompresses into a proof of the aggregator carrying its header; one
/// relabelled on the way fails, and so do one whose two sides were
/// prepared from different compressed proofs and one of another wallet
/// application's registry.
mod aggregator {
    use alloc::{string::ToString, vec::Vec};

    use ragu_circuits::{
        polynomials::{AggregatorRank, R, Rank, WalletRank},
        registry::{CircuitIndex, RegistryBuilder},
    };
    use ragu_core::{
        Cycle, Error, Result,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
        pasta::{Fp, Fq, Pasta},
    };
    use ragu_primitives::{Element, GadgetExt, allocator::Allocator};
    use rand::{SeedableRng, rngs::StdRng};
    use udon::field::Field;

    use super::{HEADER_SIZE, Setup, TestR};
    use crate::{
        Application, ApplicationBuilder, CompressedProof,
        decompress::{
            aggregator::{native_layout, nested_layout},
            prover::{Decompressed, Sides},
            stages::num_runs,
        },
        header::{Dummy, Header, Suffix},
        profile::{
            Aggregator, CircuitSlot, Decompression, MaskSlot, Profile, Profiled, Shape, Standard,
        },
        step::{Encoded, Index, Step, internal::decompress::Decompress},
    };

    type P = Aggregator<HEADER_SIZE>;

    fn padding() -> [Vec<Fp>; 2] {
        core::array::from_fn(|_| alloc::vec![Fp::ONE])
    }

    /// Every page loads every stage of its side's whole circuit and the
    /// carry stage. One mask covers every page's own gates; the statement
    /// circuit follows the native pages, with its own mask.
    #[test]
    fn pinned_layout_is_the_pages() {
        let runs = num_runs::<WalletRank>() as u32;

        let native = P::native_extension();
        let count = P::NATIVE_PAGES.num_pages();
        assert_eq!(native, native_layout(count, runs as usize));
        assert_eq!(native.circuits.len(), count + 1);
        // The instance, messages and lifts stages, the digits stage and the
        // carry stage.
        assert_eq!(native.stages, 5);
        assert!(
            native.circuits[..count]
                .iter()
                .all(|c| c == &[0, 1, 2, 3, 4])
        );
        assert_eq!(native.circuits[count], [0]);
        assert_eq!(native.statement, Some(count as u32));
        let binding = native.binding.as_ref().expect("the native side binds");
        assert_eq!(binding.circuit, count as u32 - 1, "the last page");
        assert_eq!(
            binding.stages,
            (0..runs).chain([runs + 1, runs + 2]).collect::<Vec<_>>(),
            "the run stages, then the lifts and digits stages"
        );
        assert_eq!(native.final_masks.len(), 2);
        assert_eq!(native.final_masks[0], (0..count as u32).collect::<Vec<_>>());
        assert_eq!(native.final_masks[1], [count as u32]);
        assert!(native.is_consistent());

        let nested = P::nested_extension();
        let count = P::NESTED_PAGES.num_pages();
        assert_eq!(nested, nested_layout(count, runs as usize));
        assert_eq!(nested.circuits.len(), count);
        // A stage per run, the trailing, lifts and digits stages and the
        // carry stage.
        assert_eq!(nested.stages as u32, runs + 4);
        let all_stages: Vec<u32> = (0..runs + 4).collect();
        assert!(nested.circuits.iter().all(|c| c == &all_stages));
        assert_eq!(nested.final_masks.len(), 1);
        assert_eq!(nested.final_masks[0], (0..count as u32).collect::<Vec<_>>());
        assert_eq!(nested.statement, None);
        let binding = nested.binding.as_ref().expect("the nested side binds");
        assert_eq!(binding.circuit, count as u32 - 1, "the last page");
        assert_eq!(binding.stages, [3], "the native digits stage");
        assert!(nested.is_consistent());
        P::check().unwrap();
    }

    /// The pinned counts cover the allowed header widths. Every page loads
    /// the full stage list, so all widths use the same declared count.
    #[test]
    fn uniform_stage_pins_cover_header_sizes() {
        assert_eq!(Aggregator::<195>::NATIVE_PAGES, P::NATIVE_PAGES);
        assert_eq!(Aggregator::<195>::NESTED_PAGES, P::NESTED_PAGES);
        assert_eq!(Aggregator::<195>::NATIVE_EXTENSION, P::NATIVE_EXTENSION);
        assert_eq!(Aggregator::<195>::NESTED_EXTENSION, P::NESTED_EXTENSION);
    }

    /// A rank other than the aggregator's.
    type OtherRank = R<13>;

    /// Every page, the statement circuit and every mask of both sides
    /// registers at the aggregator rank at the maximum profile width: each
    /// side's pages are cut and held to its whole circuit once, and each is
    /// then registered at its extension circuit. A page is registered
    /// once, a build with a page left is refused, an index past the last
    /// fails, and a rank other than the aggregator's is refused.
    #[test]
    fn hooks_register_every_page_and_stage() {
        use crate::profile::paging::Registrar;

        const H: usize = 195;
        type Wide = Aggregator<H>;

        let params = crate::pasta::baked_aggregator();
        let native = Wide::native_extension();
        let mut registry = RegistryBuilder::<Fp, AggregatorRank>::new();
        let mut pages = Registrar::new::<Wide>(false);
        pages
            .declare(Wide::native_extension_pages::<Pasta, AggregatorRank, H>(params).unwrap())
            .unwrap();
        for circuit in 0..native.circuits.len() {
            registry = if pages.is_page(circuit as u32) {
                pages.page(registry, circuit as u32).unwrap().0
            } else {
                Wide::register_native_circuit::<Pasta, AggregatorRank, H>(
                    circuit,
                    CircuitSlot::new(registry),
                    params,
                )
                .unwrap()
                .into_registry()
            };
        }
        assert!(
            (0..Wide::NATIVE_PAGES.num_pages() as u32).all(|circuit| pages.is_page(circuit)),
            "every native page is the registrar's"
        );
        assert!(!pages.is_page(Wide::NATIVE_PAGES.num_pages() as u32));
        // A page is registered once.
        assert!(matches!(
            pages.page(RegistryBuilder::new(), 0),
            Err(Error::Initialization(_))
        ));
        pages.finish().unwrap();
        for mask in 0..native.masks() {
            registry = Wide::register_native_mask::<Pasta, AggregatorRank, H>(
                mask,
                MaskSlot::new(registry),
                params,
            )
            .unwrap()
            .into_registry();
        }
        assert_eq!(registry.num_internal_circuits(), native.internal());
        assert!(matches!(
            Wide::register_native_circuit::<Pasta, AggregatorRank, H>(
                native.circuits.len(),
                CircuitSlot::new(RegistryBuilder::new()),
                params
            ),
            Err(Error::Initialization(_))
        ));
        assert!(matches!(
            Wide::register_native_mask::<Pasta, AggregatorRank, H>(
                native.masks(),
                MaskSlot::new(registry),
                params
            ),
            Err(Error::Initialization(_))
        ));
        assert!(matches!(
            Wide::native_extension_pages::<Pasta, OtherRank, H>(params),
            Err(Error::Initialization(_))
        ));
        assert!(matches!(
            Wide::register_native_circuit::<Pasta, OtherRank, H>(
                Wide::NATIVE_PAGES.num_pages(),
                CircuitSlot::new(RegistryBuilder::new()),
                params
            ),
            Err(Error::Initialization(_))
        ));
        assert!(matches!(
            Wide::register_native_mask::<Pasta, OtherRank, H>(
                0,
                MaskSlot::new(RegistryBuilder::new()),
                params
            ),
            Err(Error::Initialization(_))
        ));

        let nested = Wide::nested_extension();
        let mut registry = RegistryBuilder::<Fq, AggregatorRank>::new();
        let mut pages = Registrar::new::<Wide>(true);
        pages
            .declare(Wide::nested_extension_pages::<Pasta, AggregatorRank>(params).unwrap())
            .unwrap();
        // Pages other than the profile pins are refused where they are
        // made, and two paged circuits cannot take one extension circuit.
        {
            use crate::profile::{PageCount, paging::ExtensionPages};

            let checked = crate::decompress::whole::checked::<
                Pasta,
                crate::decompress::side::Nested,
                WalletRank,
                AggregatorRank,
                H,
            >(params)
            .unwrap();
            let pinned = Wide::NESTED_PAGES;
            for other in [
                PageCount::new(pinned.num_pages() + 1).carrying(pinned.carry()),
                PageCount::new(pinned.num_pages()).carrying(pinned.carry() + 2),
            ] {
                assert!(matches!(
                    ExtensionPages::new(0, other, &checked),
                    Err(Error::Initialization(_))
                ));
            }
            let twice = (0..2)
                .map(|_| ExtensionPages::new(0, pinned, &checked).unwrap())
                .collect();
            assert!(matches!(
                Registrar::new::<Wide>(true).declare(twice),
                Err(Error::Initialization(_))
            ));
        }
        // A build that leaves a page unregistered is refused.
        let mut short = Registrar::new::<Wide>(true);
        short
            .declare(Wide::nested_extension_pages::<Pasta, AggregatorRank>(params).unwrap())
            .unwrap();
        short.page(RegistryBuilder::new(), 0).unwrap();
        assert!(matches!(short.finish(), Err(Error::Initialization(_))));
        for circuit in 0..nested.circuits.len() {
            assert!(
                pages.is_page(circuit as u32),
                "every nested circuit is a page"
            );
            registry = pages.page(registry, circuit as u32).unwrap().0;
        }
        pages.finish().unwrap();
        for mask in 0..nested.masks() {
            registry = Wide::register_nested_mask::<Pasta, AggregatorRank>(
                mask,
                MaskSlot::new(registry),
                params,
            )
            .unwrap()
            .into_registry();
        }
        assert_eq!(registry.num_internal_circuits(), nested.internal());
        assert!(matches!(
            Wide::register_nested_circuit::<Pasta, AggregatorRank>(
                nested.circuits.len(),
                CircuitSlot::new(RegistryBuilder::new()),
                params
            ),
            Err(Error::Initialization(_))
        ));
        assert!(matches!(
            Wide::nested_extension_pages::<Pasta, OtherRank>(params),
            Err(Error::Initialization(_))
        ));
        assert!(matches!(
            Wide::register_nested_mask::<Pasta, OtherRank>(
                0,
                MaskSlot::new(RegistryBuilder::new()),
                params
            ),
            Err(Error::Initialization(_))
        ));
    }

    /// The profile's shape is wider than the standard one, and an application
    /// over it builds at the aggregator rank: every fuse circuit fits the
    /// budget with the extension's polynomials, every page registers beside
    /// them and none can stand in for an application circuit, and the
    /// bootstrap proof, with the pages run over the wallet application's
    /// canonical compressed proof, verifies.
    #[test]
    fn the_fuse_fits_at_the_aggregator_rank() {
        let standard = Shape::of::<Standard>();
        let shape = Shape::of::<P>();
        // The extension's polynomials, the online batch's three stages and its
        // helper's, the pages' and their carry stages', and the walk's, each
        // step with its pages.
        use crate::profile::paging::{added, rxs};
        assert_eq!(
            shape.native_rx,
            standard.native_rx
                + P::NATIVE_EXTENSION
                + crate::profile::online::stages::RXS
                + rxs(&P::PAGE_COUNTS, false)
                + shape.native_steps * (1 + added(P::PAGE_COUNTS.endoscaling_step))
                - standard.native_steps
        );
        // The walks fold more points at fewer steps per the profile's
        // endoscalings per step.
        assert!(shape.nested_points > standard.nested_points);
        assert!(shape.nested_steps < standard.nested_steps);

        let setup = Setup::new();
        let mut rng = StdRng::seed_from_u64(5);
        let decompression = Decompression::new(setup.app, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .finalize_with(crate::pasta::baked_aggregator(), decompression)
            .unwrap();
        crate::internal::tests::assert_only_steps_satisfy_application_instances(&app);
        let bootstrap = app.bootstrap.clone().expect("finalized").carry::<()>(());
        assert!(app.verify_uncompressed(&bootstrap, &mut rng).unwrap());
    }

    /// A header carrying one field element.
    struct Value;

    impl Header<Fp> for Value {
        const SUFFIX: Suffix = Suffix::new(7);
        type OnlinePolyCommit = (crate::header::Padding, crate::header::Padding);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    /// A header of another type at [`Value`]'s suffix.
    struct Other;

    impl Header<Fp> for Other {
        const SUFFIX: Suffix = Suffix::new(7);
        type OnlinePolyCommit = (crate::header::Padding, crate::header::Padding);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    /// A seed step outputting its witness as an [`Other`] header.
    struct OtherLeaf;

    impl<C: Cycle<CircuitField = Fp>> Step<C> for OtherLeaf {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = Fp;
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = Other;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
            &self,
            dr: &mut D,
            _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
            witness: DriverValue<D, Fp>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, Other, H>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut ragu_primitives::allocator::Standard::new();
            let left = Encoded::new(dr, allocator, left)?;
            let right = Encoded::new(dr, allocator, right)?;
            let output = Encoded::new(dr, allocator, witness.clone())?;
            Ok(((left, right, output), witness, D::unit()))
        }
    }

    /// A seed step outputting its witness as a [`Value`] header.
    struct Leaf;

    impl<C: Cycle<CircuitField = Fp>> Step<C> for Leaf {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = Fp;
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = Value;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
            &self,
            dr: &mut D,
            _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
            witness: DriverValue<D, Fp>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, Value, H>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut ragu_primitives::allocator::Standard::new();
            let left = Encoded::new(dr, allocator, left)?;
            let right = Encoded::new(dr, allocator, right)?;
            let output = Encoded::new(dr, allocator, witness.clone())?;
            Ok(((left, right, output), witness, D::unit()))
        }
    }

    /// A kind of online polynomial.
    #[derive(Clone, Copy)]
    struct Carried;

    impl crate::header::OnlinePoly for Carried {}

    #[derive(Clone, Copy)]
    struct CarriedSecond;
    impl crate::header::OnlinePoly for CarriedSecond {}

    /// A header with two application polynomials.
    struct Carrying;

    impl Header<Fp> for Carrying {
        const SUFFIX: Suffix = Suffix::new(8);
        type OnlinePolyCommit = (Carried, CarriedSecond);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    /// A seed step with two constant application polynomials.
    struct CarryingLeaf;

    impl<C: Cycle<CircuitField = Fp>> Step<C> for CarryingLeaf {
        const INDEX: Index = Index::new(0);
        type Witness<'source> = (Fp, [Fp; 2]);
        const NUM_STAGED: usize = 2;

        fn prepare(
            &self,
            witness: &Self::Witness<'_>,
            _: crate::step::HeaderInput<'_, Fp, ()>,
            _: crate::step::HeaderInput<'_, Fp, ()>,
        ) -> Result<crate::step::Prepared<Fp, Carrying>> {
            Ok(crate::step::Prepared::new()
                .poly(Carried, [witness.1[0]])
                .poly(CarriedSecond, [witness.1[1]])
                .stage(witness.1))
        }
        type Aux<'source> = ();
        type Left = ();
        type Right = ();
        type Output = Carrying;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
            &self,
            dr: &mut D,
            oracles: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
            witness: DriverValue<D, Self::Witness<'source>>,
            left: DriverValue<D, ()>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, Carrying, H>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut ragu_primitives::allocator::Standard::new();
            let left = Encoded::new(dr, allocator, left)?;
            let right = Encoded::new(dr, allocator, right)?;
            let zeta = oracles.zeta().clone();
            let first = oracles.output(Carried).open(dr, &zeta)?;
            let second = oracles.output(CarriedSecond).open(dr, &zeta)?;
            first.enforce_equal(dr, &oracles.staged()[0])?;
            second.enforce_equal(dr, &oracles.staged()[1])?;
            let data = witness.map(|(data, _)| data);
            let output = Encoded::new(dr, allocator, data.clone())?;
            Ok(((left, right, output), data, D::unit()))
        }
    }

    /// A wallet application with a leaf step, for proofs with a header.
    fn wallet() -> Application<'static, Pasta, TestR, HEADER_SIZE> {
        ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize(crate::pasta::baked_aggregator())
            .unwrap()
    }

    /// Every consumer of a decompression agrees on it, `accepts` or not: the
    /// ordinary verifier, the compressed verifier on its compression, and the
    /// ordinary verifier on a parent that folds its claims, its
    /// rerandomization. The three compute the step binding's claim from the
    /// proof alike, each on its own path.
    fn every_consumer(
        app: &Application<'_, Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>,
        pcd: crate::Pcd<Profiled<Pasta, P>, AggregatorRank, Value>,
        accepts: bool,
        rng: &mut StdRng,
        case: &str,
    ) {
        assert!(
            matches!(app.verify_uncompressed(&pcd, &mut *rng), Ok(v) if v == accepts),
            "{case}: ordinary verifier"
        );
        let compressed = app.compress(&pcd, &mut *rng).unwrap();
        assert!(
            matches!(app.verify_compressed(&compressed), Ok(v) if v == accepts),
            "{case}: compressed verifier"
        );
        let parent = app.rerandomize(pcd, &mut *rng).unwrap();
        assert!(
            matches!(app.verify_uncompressed(&parent, &mut *rng), Ok(v) if v == accepts),
            "{case}: as a child"
        );
    }

    /// A wallet's compressed proof decompresses into a proof of the aggregator
    /// carrying the wallet proof's header and data, which verifies; the same
    /// decompression under another header fails, since the statement circuit's
    /// claim holds the decompression step's output header to the decompressed
    /// statement's. A decompression with a substituted output polynomial
    /// fails the nested binding to the wallet proof's commitments.
    #[test]
    fn decompresses_a_wallet_proof() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(9);
        let wallet = wallet();
        let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
        let compressed = wallet.compress(&leaf, &mut rng).unwrap();
        assert!(wallet.verify_compressed(&compressed).unwrap());

        let decompression = Decompression::new(wallet, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap();
        let node = app.decompress(&mut rng, &compressed).unwrap();
        assert_eq!(*node.data(), Fp::from(42));
        every_consumer(&app, node.clone(), true, &mut rng, "the decompression");

        // The step commits the nested IPA's s(X) in its nested batch. The
        // proof carries the commitment for its verifier, which holds the
        // fuse's walk and the side's binding circuit to the same point: with
        // another commitment, a claim fails.
        let (proof, data) = node.clone().into_parts();
        let ipa = crate::decompress::online::slot::IPA;
        let mut other = proof.clone();
        other.nested_online_commitments[ipa] = -other.nested_online_commitments[ipa];
        assert!(
            matches!(
                app.verify_uncompressed(&other.carry::<Value>(data), &mut rng),
                Ok(false)
            ),
            "another batch commitment fails"
        );
        // The left opening's point exposes the staged digest. The
        // `hashes_1` and statement claims bind it to the step.
        assert_eq!(proof.step_binding.len(), 1);
        for i in 0..proof.step_binding.len() {
            let mut other = proof.clone();
            other.step_binding[i] += Fp::ONE;
            assert!(
                matches!(
                    app.verify_uncompressed(&other.carry::<Value>(data), &mut rng),
                    Ok(false)
                ),
                "another step binding value fails: {i}"
            );
        }

        let decompressed = app.context().prepare(&compressed).unwrap();
        let (relabelled, ()) = app
            .fuse_with_source(
                &mut rng,
                Decompress::<Value>::new(true),
                (Fp::from(43), padding(), decompressed.transcript_digest()),
                app.bootstrap_pcd(),
                app.bootstrap_pcd(),
                Some(&decompressed),
            )
            .unwrap();
        assert!(
            matches!(app.verify_uncompressed(&relabelled, &mut rng), Ok(false)),
            "a relabelled decompression fails"
        );

        // A prover who puts another polynomial in either output slot has
        // internally consistent PCS openings, but the commitment disagrees
        // with the one the extension verified. Check all consuming paths.
        for slot in 0..2 {
            let mut wrong = padding();
            wrong[slot] = alloc::vec![Fp::from(2)];
            let (other_slot, ()) = app
                .fuse_with_source(
                    &mut rng,
                    Decompress::<Value>::new(true),
                    (Fp::from(42), wrong, decompressed.transcript_digest()),
                    app.bootstrap_pcd(),
                    app.bootstrap_pcd(),
                    Some(&decompressed),
                )
                .unwrap();
            every_consumer(
                &app,
                other_slot,
                false,
                &mut rng,
                "another output polynomial",
            );
        }

        // The transcript digest: the step stages the compression transcript's
        // last squeeze before its challenge, so both IPAs' round challenges,
        // and both challenge polynomials, are fixed before the point they are
        // opened at. A step that stages another value exposes a digest the
        // native side's transcript does not squeeze, and its proof fails.
        let decompressed = app.context().prepare(&compressed).unwrap();
        let (other_digest, ()) = app
            .fuse_with_source(
                &mut rng,
                Decompress::<Value>::new(true),
                (
                    Fp::from(42),
                    padding(),
                    decompressed.transcript_digest() + Fp::ONE,
                ),
                app.bootstrap_pcd(),
                app.bootstrap_pcd(),
                Some(&decompressed),
            )
            .unwrap();
        every_consumer(
            &app,
            other_digest,
            false,
            &mut rng,
            "a decompression that staged another digest",
        );

        // The nested curve's binding, from the prover's side: a step that
        // commits, in its nested batch, the challenge polynomial of other
        // round challenges opens that polynomial's own commitment, which
        // agrees with the proof, but the opening is not s(X)'s and the
        // commitment not the nested IPA's G'.
        let decompressed = app.context().prepare(&compressed).unwrap();
        let (other_ipa, ()) = super::with_other_nested_ipa_polynomial(|| {
            app.fuse_with_source(
                &mut rng,
                Decompress::<Value>::new(true),
                (Fp::from(42), padding(), decompressed.transcript_digest()),
                app.bootstrap_pcd(),
                app.bootstrap_pcd(),
                Some(&decompressed),
            )
        })
        .unwrap();
        every_consumer(
            &app,
            other_ipa,
            false,
            &mut rng,
            "a decompression whose nested batch holds another polynomial",
        );
    }

    /// A compressed proof the wallet application's verifier rejects up front is
    /// refused before any proving: `decompress` fails with the admission's own
    /// rejection on a circuit id outside the registry's domain, an IPA opening
    /// a round pair short of the rank and a recomputed nested stage that does
    /// not commit as the instance claims.
    #[test]
    fn refuses_a_proof_the_wallet_rejects() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(17);
        let wallet = wallet();
        let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
        let (proof, data) = wallet.compress(&leaf, &mut rng).unwrap().into_parts();
        let decompression = Decompression::new(wallet, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap();
        let wallet = app.context().wallet();

        let edits: [(&str, fn(&mut CompressedProof<Pasta>)); 3] = [
            ("an out-of-domain circuit id", |proof| {
                proof.instance.circuit_id = CircuitIndex::new(u32::MAX as usize);
            }),
            ("a round pair short of the rank", |proof| {
                proof.native.opening.rounds.pop();
            }),
            ("a stage that does not commit as claimed", |proof| {
                proof.instance.bridge_alpha += Fq::ONE;
            }),
        ];
        for (case, edit) in edits {
            let mut edited = proof.clone();
            edit(&mut edited);
            let Err(rejection) = wallet.admit_compressed(&edited) else {
                panic!("{case}: the wallet admits it");
            };
            let edited = edited.carry::<Value>(data);
            assert!(
                matches!(wallet.verify_compressed(&edited), Ok(false)),
                "{case}: the wallet's verifier rejects it"
            );
            let Err(error) = app.decompress(&mut rng, &edited) else {
                panic!("{case}: decompresses");
            };
            assert_eq!(error.to_string(), rejection.to_string(), "{case}");
        }
    }

    /// Two pages that load the same stages, under one mask of their own gates,
    /// do not stand in for each other: with the stages as they are, a proof
    /// whose polynomials for two such pages are swapped fails both verifiers,
    /// on either side.
    #[test]
    fn pages_sharing_stages_are_not_interchangeable() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(31);
        let decompression = Decompression::new(wallet(), &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap();
        let (leaf, _) = app.seed(&mut rng, Leaf, Fp::from(5)).unwrap();
        assert!(app.verify_uncompressed(&leaf, &mut rng).unwrap());

        let rejected = |pcd: crate::Pcd<Profiled<Pasta, P>, AggregatorRank, Value>,
                        rng: &mut StdRng,
                        case: &str| {
            assert!(
                matches!(app.verify_uncompressed(&pcd, &mut *rng), Ok(false)),
                "{case}: the decider"
            );
            let compressed = app
                .compress(&pcd, rng)
                .and_then(|compressed| app.verify_compressed(&compressed));
            assert!(
                matches!(compressed, Ok(false)),
                "{case}: the compressed verifier"
            );
        };
        // The first two pages of the circuit-field side.
        let (mut proof, data) = leaf.clone().into_parts();
        proof.native_extension_circuit_rxs.swap(0, 1);
        rejected(
            proof.carry::<Value>(data),
            &mut rng,
            "circuit-field pages swapped",
        );
        // The first two pages of the scalar-field side.
        let (mut proof, data) = leaf.into_parts();
        proof.nested_extension_circuit_rxs.swap(0, 1);
        rejected(
            proof.carry::<Value>(data),
            &mut rng,
            "scalar-field pages swapped",
        );
    }

    /// The decompression step cannot output the dummy header, whose suffix
    /// would let a decompressed proof stand as the base case: the step's
    /// uniform encoding holds the suffix wire away from it, so no proof of the
    /// step with that header exists, whatever the extension verified.
    #[test]
    fn a_decompression_cannot_output_the_dummy_suffix() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(37);
        let wallet = wallet();
        let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
        let compressed = wallet.compress(&leaf, &mut rng).unwrap();
        let decompression = Decompression::new(wallet, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap();
        let decompressed = app.context().prepare(&compressed).unwrap();
        match app.fuse_with_source(
            &mut rng,
            Decompress::<Dummy>::new(true),
            ((), padding(), decompressed.transcript_digest()),
            app.bootstrap_pcd(),
            app.bootstrap_pcd(),
            Some(&decompressed),
        ) {
            Err(_) => {}
            Ok((forged, ())) => assert!(
                matches!(app.verify_uncompressed(&forged, &mut rng), Ok(false)),
                "a decompression under the dummy header fails"
            ),
        }
    }

    /// The pages use the generators at their rank, so a decompression into
    /// pages past the rank the wallet application's tables reach, the Standard
    /// ones, is refused with an error rather than a panic. The aggregator rank
    /// is the wallet's, which those tables reach.
    #[test]
    fn tables_short_of_the_pages_rank_are_refused() {
        /// A rank past the Standard tables.
        type Past = R<15>;
        let wallet = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize(crate::pasta::baked())
            .unwrap();
        let decompression = Decompression::<Pasta, Past, HEADER_SIZE, _>::new(
            wallet,
            &mut StdRng::seed_from_u64(40),
        );
        assert!(matches!(decompression, Err(Error::Initialization(_))));
    }

    /// The aggregator reads a decompressed statement with the wallet's own
    /// header type: an application registering another type at a suffix the
    /// wallet's steps output, or no header there, does not build; nor does one
    /// over other parameters than its wallet application's, whose traces the
    /// pages registered over its own would not match.
    #[test]
    fn the_aggregator_reads_statements_with_the_wallets_headers() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(41);
        let other_params =
            ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
                .register(Leaf)
                .unwrap()
                .finalize_with(
                    crate::pasta::baked(),
                    Decompression::new(wallet(), &mut rng).unwrap(),
                );
        assert!(
            matches!(other_params, Err(Error::Initialization(_))),
            "other parameters than the wallet's"
        );
        let other = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(OtherLeaf)
            .unwrap()
            .finalize_with(pasta, Decompression::new(wallet(), &mut rng).unwrap());
        assert!(
            matches!(other, Err(Error::Initialization(_))),
            "another header type at the wallet's suffix"
        );
        let none = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(crate::profile::testing::UnitStep)
            .unwrap()
            .finalize_with(pasta, Decompression::new(wallet(), &mut rng).unwrap());
        assert!(
            matches!(none, Err(Error::Initialization(_))),
            "no header at the wallet's suffix"
        );
    }

    /// A prover cannot pass another wallet application's proof through the
    /// decompression, whichever stage it writes that application's registry
    /// in. The other application registers one more step, under our wallet's
    /// registry tags: a collision no prover can produce, which the test
    /// installs so that the two aggregators' own registries are the same and
    /// only the wallet registry their batches certify tells them apart.
    ///
    /// With the other registry's evaluations supplied alone, under our
    /// aggregator's batches, the page that holds them to the query stage is
    /// unsatisfied. With the batches over the other registry too, as the
    /// aggregator built over that application proves them, every circuit of
    /// our registries is satisfied and the terminal check is what fails: the
    /// verifier evaluates the wallet registry it holds, uncompressed and
    /// compressed.
    #[test]
    fn another_applications_registry_is_rejected_in_either_stage() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(47);
        let ours_wallet = wallet();
        let other_wallet = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .with_native_tag(ours_wallet.native_registry.tag())
            .with_nested_tag(ours_wallet.nested_registry.tag())
            .register(Leaf)
            .unwrap()
            .register(Join)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let (leaf, _) = other_wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
        let compressed = other_wallet.compress(&leaf, &mut rng).unwrap();
        assert!(other_wallet.verify_compressed(&compressed).unwrap());
        assert!(
            !matches!(ours_wallet.verify_compressed(&compressed), Ok(true)),
            "the proof is not one of our wallet application's"
        );

        let aggregator = |wallet, rng: &mut StdRng| {
            ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
                .register(Leaf)
                .unwrap()
                .register(Join)
                .unwrap()
                .finalize_with(pasta, Decompression::new(wallet, rng).unwrap())
                .unwrap()
        };
        let ours = aggregator(ours_wallet, &mut rng);
        let theirs = aggregator(other_wallet, &mut rng);
        assert_eq!(
            (ours.native_registry.tag(), ours.nested_registry.tag()),
            (theirs.native_registry.tag(), theirs.nested_registry.tag()),
            "the aggregators' own registries are the same"
        );
        assert!(
            ours.decompress(&mut rng, &compressed).is_err(),
            "our prover refuses the proof before proving"
        );

        // The evaluations alone: the other application's, as its own
        // verifier computes them, under our aggregator's batches, which
        // open our wallet's registry.
        let prepared = theirs.context().prepare(&compressed).unwrap();
        let (forged, ()) = ours
            .fuse_with_source(
                &mut rng,
                Decompress::<Value>::new(true),
                (Fp::from(42), padding(), prepared.transcript_digest()),
                ours.bootstrap_pcd(),
                ours.bootstrap_pcd(),
                Some(&prepared),
            )
            .unwrap();
        assert!(
            matches!(ours.verify_uncompressed(&forged, &mut rng), Ok(false)),
            "evaluations of another registry than the batches' fail a page"
        );

        // Both stages: the other aggregator's decompression, whose batches
        // open the other application's registry, is a proof of the registries
        // the two aggregators share, and our verifier's terminal check
        // evaluates our wallet's registry.
        let node = theirs.decompress(&mut rng, &compressed).unwrap();
        assert!(theirs.verify_uncompressed(&node, &mut rng).unwrap());
        assert!(
            matches!(ours.verify_uncompressed(&node, &mut rng), Ok(false)),
            "batches over another registry fail the terminal check"
        );
        let compressed = theirs.compress(&node, &mut rng).unwrap();
        assert!(theirs.verify_compressed(&compressed).unwrap());
        assert!(
            matches!(ours.verify_compressed(&compressed), Ok(false)),
            "and its compression the compressed verifier's"
        );
    }

    /// A wallet step that drops the polynomial slots while preserving the data.
    struct PadCarrying;

    impl<C: Cycle<CircuitField = Fp>> Step<C> for PadCarrying {
        const INDEX: Index = Index::new(1);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = Carrying;
        type Right = ();
        type Output = Value;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
            &self,
            dr: &mut D,
            _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, ()>,
        ) -> Result<(
            (
                Encoded<'dr, D, Carrying, H>,
                Encoded<'dr, D, (), H>,
                Encoded<'dr, D, Value, H>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut ragu_primitives::allocator::Standard::new();
            let value = Element::alloc(dr, allocator, left.clone())?;
            Ok((
                (
                    Encoded::from_gadget(value.clone()),
                    Encoded::new(dr, allocator, right)?,
                    Encoded::from_gadget(value),
                ),
                left,
                D::unit(),
            ))
        }
    }

    /// An aggregator must register every header its wallet outputs, padding
    /// or not. Registering both, it decompresses either output.
    #[test]
    fn decompression_accepts_a_padded_output_from_a_wallet_with_online_polynomials() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(42);
        let wallet = || {
            ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
                .register(CarryingLeaf)
                .unwrap()
                .register(PadCarrying)
                .unwrap()
                .finalize(pasta)
                .unwrap()
        };

        // The wallet outputs `Carrying` and `Value`; an aggregator that
        // registers `Value` alone is refused.
        let missing = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize_with(pasta, Decompression::new(wallet(), &mut rng).unwrap());
        assert!(
            matches!(missing, Err(Error::Initialization(ref reason)) if reason.to_string().contains("registers no header")),
            "an unregistered header that carries online polynomials"
        );

        let wallet = wallet();
        let (carrying, _) = wallet
            .seed(&mut rng, CarryingLeaf, (Fp::from(42), [Fp::ONE; 2]))
            .unwrap();
        let carrying_proof = wallet.compress(&carrying, &mut rng).unwrap();
        let (padded, _) = wallet
            .fuse(
                &mut rng,
                PadCarrying,
                (),
                carrying,
                wallet.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let padded_proof = wallet.compress(&padded, &mut rng).unwrap();
        assert!(wallet.verify_compressed(&carrying_proof).unwrap());
        assert!(wallet.verify_compressed(&padded_proof).unwrap());
        // The carrying header declares a polynomial even when its commitment
        // happens to equal the padding commitment.
        assert_eq!(
            carrying_proof.online_commitments(),
            padded_proof.online_commitments(),
        );

        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(CarryingLeaf)
            .unwrap()
            .register(PadCarrying)
            .unwrap()
            .finalize_with(pasta, Decompression::new(wallet, &mut rng).unwrap())
            .unwrap();
        let carried = app
            .decompress_with_polynomials(&mut rng, &carrying_proof, padding())
            .unwrap();
        assert!(app.verify_uncompressed(&carried, &mut rng).unwrap());

        let decompressed = app.decompress(&mut rng, &padded_proof).unwrap();
        assert_eq!(*decompressed.data(), Fp::from(42));
        let parent = app.rerandomize(decompressed, &mut rng).unwrap();
        let compressed = app.compress(&parent, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed).unwrap());
    }

    /// A profile whose decompression step pads its output slots refuses every
    /// header that names an online polynomial, output or read: a decompressed
    /// statement can land at any application suffix.
    #[test]
    fn a_padding_decompression_refuses_headers_with_online_polynomials() {
        use crate::profile::testing::{Decompressing, StatementContext};
        type Padded = Profiled<Pasta, Decompressing>;
        let params = crate::pasta::baked_aggregator();
        let refused = |result: Result<Application<'_, Padded, AggregatorRank, HEADER_SIZE>>| matches!(result, Err(Error::Initialization(ref reason)) if reason.to_string().contains("names an online polynomial"));

        let outputs = ApplicationBuilder::<Padded, AggregatorRank, HEADER_SIZE>::new()
            .register(CarryingLeaf)
            .unwrap()
            .finalize_with(params, StatementContext::default());
        assert!(refused(outputs), "a step that outputs `Carrying`");

        let reads = ApplicationBuilder::<Padded, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(PadCarrying)
            .unwrap()
            .finalize_with(params, StatementContext::default());
        assert!(refused(reads), "a step that reads `Carrying`");
    }

    #[test]
    fn decompression_preserves_both_wallet_commitments_for_the_next_fuse() {
        let params = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(103);
        let wallet = ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
            .register(CarryingLeaf)
            .unwrap()
            .finalize(params)
            .unwrap();
        let (leaf, ()) = wallet
            .seed(
                &mut rng,
                CarryingLeaf,
                (Fp::from(42), [Fp::from(5), Fp::from(7)]),
            )
            .unwrap();
        let polynomials = leaf.polynomials();
        let compressed = wallet.compress(&leaf, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(CarryingLeaf)
            .unwrap()
            .finalize_with(params, Decompression::new(wallet, &mut rng).unwrap())
            .unwrap();
        // Coefficients that do not commit to the wallet proof's commitments
        // are refused before any proving.
        for slot in 0..polynomials.len() {
            let mut wrong = polynomials.clone();
            wrong[slot][0] += Fp::ONE;
            assert!(
                matches!(
                    app.decompress_with_polynomials(&mut rng, &compressed, wrong),
                    Err(Error::InvalidWitness(ref reason))
                        if reason.to_string().contains("online commitments")
                ),
                "other coefficients in slot {slot}"
            );
        }
        let node = app
            .decompress_with_polynomials(&mut rng, &compressed, polynomials.clone())
            .unwrap();
        assert_eq!(node.data(), leaf.data());
        assert_eq!(node.commitments(), compressed.online_commitments());
        assert_eq!(node.polynomials(), polynomials);
        assert!(app.verify_uncompressed(&node, &mut rng).unwrap());

        // Rerandomize opens both child slots and copies them through the fuses.
        let parent = app.rerandomize(node, &mut rng).unwrap();
        let result = app.compress(&parent, &mut rng).unwrap();
        assert_eq!(result.online_commitments(), compressed.online_commitments());
        assert!(app.verify_compressed(&result).unwrap());
    }

    /// Decompressed wallet proofs recurse: two fuse under a step of the
    /// aggregator's own, and the result fuses with a third, each level
    /// verifying uncompressed and the last compressed too.
    #[test]
    fn decompressed_proofs_recurse() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(43);
        let wallet = wallet();
        let mut compressed = |value: u64| {
            let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(value)).unwrap();
            wallet.compress(&leaf, &mut rng).unwrap()
        };
        let (a, b, c) = (compressed(41), compressed(42), compressed(43));
        let decompression = Decompression::new(wallet, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .register(Join)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap();
        let a = app.decompress(&mut rng, &a).unwrap();
        let b = app.decompress(&mut rng, &b).unwrap();
        let c = app.decompress(&mut rng, &c).unwrap();
        let (ab, ()) = app.fuse(&mut rng, Join, (), a, b).unwrap();
        assert_eq!(*ab.data(), Fp::from(83));
        assert!(app.verify_uncompressed(&ab, &mut rng).unwrap());
        let (abc, ()) = app.fuse(&mut rng, Join, (), ab, c).unwrap();
        assert_eq!(*abc.data(), Fp::from(126));
        assert!(app.verify_uncompressed(&abc, &mut rng).unwrap());
        let compressed = app.compress(&abc, &mut rng).unwrap();
        assert!(app.verify_compressed(&compressed).unwrap());
    }

    /// A decompression whose circuit-field side was prepared from one
    /// compression of a wallet proof and whose scalar-field side from another
    /// fails: each side is consistent with itself, and every page of both
    /// accepts, but the binding circuits' claims hold each side's view of
    /// the other to that side's actual stages, which the two compressions'
    /// challenges, scalars and messages do not share. Without the binding the
    /// proof verifies, with each side verifying a compressed proof of its
    /// own.
    #[test]
    fn sides_from_different_proofs_are_rejected() {
        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(23);
        let wallet = wallet();
        let (leaf, _) = wallet.seed(&mut rng, Leaf, Fp::from(42)).unwrap();
        let first = wallet.compress(&leaf, &mut rng).unwrap();
        let second = wallet.compress(&leaf, &mut rng).unwrap();
        assert!(wallet.verify_compressed(&first).unwrap());
        assert!(wallet.verify_compressed(&second).unwrap());

        let decompression = Decompression::new(wallet, &mut rng).unwrap();
        let app = ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
            .register(Leaf)
            .unwrap()
            .finalize_with(pasta, decompression)
            .unwrap();
        let first = app.context().prepare(&first).unwrap();
        let second = app.context().prepare(&second).unwrap();
        let mixed = Decompressed(Sides {
            native: first.0.native,
            nested: second.0.nested,
        });
        let (node, ()) = app
            .fuse_with_source(
                &mut rng,
                Decompress::<Value>::new(true),
                (Fp::from(42), padding(), mixed.transcript_digest()),
                app.bootstrap_pcd(),
                app.bootstrap_pcd(),
                Some(&mixed),
            )
            .unwrap();
        assert!(
            matches!(app.verify_uncompressed(&node, &mut rng), Ok(false)),
            "a decompression of two proofs fails"
        );
        let compressed = app.compress(&node, &mut rng).unwrap();
        assert!(
            matches!(app.verify_compressed(&compressed), Ok(false)),
            "and so does its compression"
        );
    }

    /// A step fusing two [`Value`] headers into their sum.
    struct Join;

    impl<C: Cycle<CircuitField = Fp>> Step<C> for Join {
        const INDEX: Index = Index::new(1);
        type Witness<'source> = ();
        type Aux<'source> = ();
        type Left = Value;
        type Right = Value;
        type Output = Value;

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const H: usize>(
            &self,
            dr: &mut D,
            _: &mut crate::step::Oracles<'_, 'dr, D, C, Self>,
            _: DriverValue<D, ()>,
            left: DriverValue<D, Fp>,
            right: DriverValue<D, Fp>,
        ) -> Result<(
            (
                Encoded<'dr, D, Value, H>,
                Encoded<'dr, D, Value, H>,
                Encoded<'dr, D, Value, H>,
            ),
            DriverValue<D, Fp>,
            DriverValue<D, ()>,
        )> {
            let allocator = &mut ragu_primitives::allocator::Standard::new();
            let left_element = Element::alloc(dr, allocator, left)?;
            let right_element = Element::alloc(dr, allocator, right)?;
            let sum = left_element.add(dr, &right_element);
            let data = sum.value().map(|v| *v);
            Ok((
                (
                    Encoded::from_gadget(left_element),
                    Encoded::from_gadget(right_element),
                    Encoded::from_gadget(sum),
                ),
                data,
                D::unit(),
            ))
        }
    }

    /// The points and scalars one curve's messages carry: the fold's two
    /// commitments and two epsilons, p and q, the openings; the batch's f and
    /// evaluations; the IPA's s, rounds and c.
    fn messages_size<P: udon::curve::Affine>(
        messages: &crate::compress::Messages<P>,
    ) -> (usize, usize) {
        let points = 2 + 2 + 1 + 1 + 2 * messages.opening.rounds.len();
        let scalars = 2 + messages.reduction.openings.len() + messages.batch.evaluations.len() + 1;
        (points, scalars)
    }

    /// The points and scalars a compressed proof carries over the cycle.
    fn compressed_size<C: Cycle>(proof: &crate::CompressedProof<C>) -> (usize, usize) {
        let instance = &proof.instance;
        let points = instance.native.len() + 2 + instance.nested.len() + 3;
        // The circuit id and the bridge alpha, the four accumulator values,
        // each child's x and y on both fields, and a(u) and b(u) on both.
        let _ = instance;
        let scalars = 1 + 1 + 4 + 4 + 4 + 4;
        let native = messages_size(&proof.native);
        let nested = messages_size(&proof.nested);
        (points + native.0 + nested.0, scalars + native.1 + nested.1)
    }

    /// The coefficients an uncompressed proof stores: its sparse rx
    /// polynomials' blocks, `registry_xy` and `p` on each side, and the two
    /// accumulators per side taken as dense.
    fn stored_coefficients<C: crate::profile::ProfiledCycle, R: Rank>(
        proof: &crate::Proof<C, R>,
    ) -> usize {
        use crate::internal::{native, nested};
        let mut stored = 0;
        for index in native::RxIndex::all::<C::Profile>() {
            stored += proof[index].iter_stored_coeffs().count();
        }
        for index in nested::RxIndex::all::<C::Profile>() {
            stored += proof[index].iter_stored_coeffs().count();
        }
        stored += proof.native_registry_xy_poly().iter_stored_coeffs().count();
        stored += proof.native_p_poly().iter_stored_coeffs().count();
        stored += proof.nested_registry_xy_poly().iter_stored_coeffs().count();
        stored += proof.nested_p_poly().iter_stored_coeffs().count();
        stored + 4 * R::num_coeffs()
    }

    /// Timings and sizes of both roles, printed; run alone on an idle machine
    /// with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn timings() {
        use std::time::Instant;

        let pasta = crate::pasta::baked_aggregator();
        let mut rng = StdRng::seed_from_u64(21);
        macro_rules! timed {
            ($label:expr, $e:expr) => {{
                let start = Instant::now();
                let value = $e;
                std::println!("{:<40} {:>8.2} s", $label, start.elapsed().as_secs_f64());
                value
            }};
        }
        let report = |role: &str,
                      polynomials: usize,
                      rank: u32,
                      stored: usize,
                      (points, scalars): (usize, usize)| {
            std::println!(
                "{role}: {polynomials} polynomials of 2^{rank} coefficients ({:.1} MB dense, {:.1} MB stored); compressed proof {points} points + {scalars} scalars ({:.1} KB at 32 bytes each)",
                polynomials as f64 * (1u64 << rank) as f64 * 32.0 / 1e6,
                stored as f64 * 32.0 / 1e6,
                (points + scalars) as f64 * 32.0 / 1e3
            );
        };

        // The wallet.
        let wallet = timed!(
            "wallet finalize (registries + bootstrap)",
            ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE>::new()
                .register(Leaf)
                .unwrap()
                .register(Join)
                .unwrap()
                .finalize(pasta)
                .unwrap()
        );
        let (leaf_a, _) = timed!(
            "wallet seed (one fuse)",
            wallet.seed(&mut rng, Leaf, Fp::from(1)).unwrap()
        );
        let (leaf_b, _) = wallet.seed(&mut rng, Leaf, Fp::from(2)).unwrap();
        let (node, _) = timed!(
            "wallet fuse (two children)",
            wallet.fuse(&mut rng, Join, (), leaf_a, leaf_b).unwrap()
        );
        assert!(timed!(
            "wallet verify (uncompressed)",
            wallet.verify_uncompressed(&node, &mut rng).unwrap()
        ));
        let compressed = timed!("wallet compress", wallet.compress(&node, &mut rng).unwrap());
        assert!(timed!(
            "wallet verify_compressed",
            wallet.verify_compressed(&compressed).unwrap()
        ));
        report(
            "wallet",
            Shape::of::<Standard>().polynomials(),
            WalletRank::RANK,
            stored_coefficients(node.proof()),
            compressed_size(compressed.proof()),
        );

        // The aggregator.
        let decompression = timed!(
            "aggregator canonical decompression",
            Decompression::new(wallet, &mut rng).unwrap()
        );
        let aggregator = timed!(
            "aggregator finalize (registries + bootstrap)",
            ApplicationBuilder::<Profiled<Pasta, P>, AggregatorRank, HEADER_SIZE>::new()
                .register(Leaf)
                .unwrap()
                .register(Join)
                .unwrap()
                .finalize_with(crate::pasta::baked_aggregator(), decompression)
                .unwrap()
        );
        let _ = timed!(
            "aggregator prepare (the sides' native run)",
            aggregator.context().prepare(&compressed).unwrap()
        );
        let node_a = timed!(
            "aggregator decompress (prepare + fuse)",
            aggregator.decompress(&mut rng, &compressed).unwrap()
        );
        let node_b = aggregator.decompress(&mut rng, &compressed).unwrap();
        let parent = timed!(
            "aggregator fuse (two children)",
            aggregator
                .fuse(&mut rng, Join, (), node_a, node_b)
                .unwrap()
                .0
        );
        assert!(timed!(
            "aggregator verify (uncompressed)",
            aggregator.verify_uncompressed(&parent, &mut rng).unwrap()
        ));
        let compressed = timed!(
            "aggregator compress",
            aggregator.compress(&parent, &mut rng).unwrap()
        );
        assert!(timed!(
            "aggregator verify_compressed",
            aggregator.verify_compressed(&compressed).unwrap()
        ));
        report(
            "aggregator",
            Shape::of::<P>().polynomials(),
            AggregatorRank::RANK,
            stored_coefficients(parent.proof()),
            compressed_size(compressed.proof()),
        );
    }
}
