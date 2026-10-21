//! The decompressed verifier as a program of chunks: each chunk a circuit
//! under the gate budget that loads the stages, reads what earlier chunks
//! left in the work stage, does one slice of the verifier's work, and
//! leaves its results in the work stage for later chunks, as the fuse's
//! endoscaling steps pass their accumulator through the walk stage.
//!
//! A [`Schedule`] is a pure function of the proof system's constants and
//! of the chunk circuits' rank: the same list of [`Chunk`] descriptors
//! drives the prover, which runs every chunk natively to fill the work
//! stage, and each chunk circuit, which runs its run of descriptors and
//! holds their results to the work stage's wires. Every slot a descriptor names
//! is a constant, so each chunk's circuit is fixed. Two ranks are in play:
//! `K`, the compressed proof's, sizes what the chunks load and check, and
//! `R`, the chunk circuits', sets how much work a chunk takes
//! ([`Limits`]).
//!
//! A circuit runs a run of consecutive chunks: the chunks are cut to
//! pieces of half a circuit's budget, then packed in order into circuits
//! by an estimate of their gates ([`gates`]) up to the budget's fill
//! ([`Limits::fill`]), transcript chunks among themselves since they load
//! a stage the others do not ([`Schedule::circuits`]). The estimate is
//! pessimistic; the chunk tests measure the circuits.
//!
//! The chunks' kinds mirror the verifier's parts: the two transcripts,
//! sliced at the sponge's permutation boundaries; the challenges' lifts;
//! the targets, the reduction, the batch and the IPA's scalars; the
//! claims' points; the fold, batch and IPA chains as Horner steps; the
//! full-width scalings; the recomputed stages; and the digits of the
//! scalars the other side scales by. The two sides share everything from
//! the targets on ([`body`]); they differ in how they obtain their
//! challenges and in the stages each recomputes of the other's: the
//! circuit-field side sums the bridges it absorbed into the scalar-field
//! side's instance and messages stage commitments, endoscales the lifts
//! stage's generators by the challenges it squeezed, and, as it scales by
//! the scalar-field side's digits, sums their generators by sign into the
//! digits stage's commitment; the scalar-field side does the last for the
//! circuit-field side's digits. Each side's recomputations end in work
//! slots its binding circuit exposes ([`Regions::exposed`]).
//!
//! Each side's schedule names the generators of the other side's digits
//! stage, which comes after that side's work stage, whose size that
//! side's schedule sets: taken literally, each schedule would wait on the
//! other. The generators only fill the scaling chunks' [`Bind`]s; no slot
//! depends on them, so a schedule built from the count of the other
//! side's scalars alone ([`Foreign::Scalars`]) has every slot the full one
//! has. The stages' lengths take that build ([`Side::sizes`]), the digits
//! stage's generators follow from it, and only the full schedules
//! ([`Side::schedule`]) ask across.
//!
//! [`Side::sizes`]: super::side::Side::sizes
//! [`Side::schedule`]: super::side::Side::schedule

use alloc::{vec, vec::Vec};
use core::iter::once;

use ragu_circuits::{
    polynomials::Rank,
    registry::CircuitIndex,
    staging::{stage_wire_indices, wire_degree, wires_of},
};
use ragu_core::{Cycle, PoseidonPermutation, Result};
use udon::field::Field;

use super::{
    circuit::AbValue,
    side::{Native, Nested},
    stages::{
        AB_TERMS, Layout, MESSAGE_SCALARS, digits_degrees, lifts_degrees, native_scalars,
        nested_scalars,
    },
};
use crate::{
    RAGU_TAG,
    compress::{
        instance::{OPENED, native_binding_degrees, nested_binding_degrees},
        revdot::{
            claims::Kind,
            fold::{Derived, Layout as FoldLayout},
            native_components, native_position, nested_components, nested_position,
        },
    },
    internal::{
        claims::Source,
        native::{self, stages::eval::generator_index},
        nested::{self, stages::challenges as challenge_stage},
    },
    ipa::{IPA_TAG, IpaCycle},
    profile::{ProfiledCycle, Standard},
};

/// A point a chunk reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PointSrc {
    /// An instance stage point, by position in the side's
    /// [`InstanceLayout`](super::stages::InstanceLayout).
    Instance(usize),
    /// A messages stage point, by position in the side's
    /// [`MessagesLayout`](super::stages::MessagesLayout).
    Message(usize),
    /// A transcript stage point, a bridge, by position in the side's
    /// [`TranscriptLayout`](super::stages::TranscriptLayout).
    Bridge(usize),
    /// A work stage point slot.
    Work(usize),
    /// A fixed generator of the side's curve.
    Generator(usize),
    /// The IPA's $U$ generator of the side's curve.
    U,
}

/// An element a chunk reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElementSrc {
    /// An instance stage element, by position.
    Instance(usize),
    /// A messages stage element, by position.
    Message(usize),
    /// A work stage element slot.
    Work(usize),
    /// A lifts stage element slot: a challenge's lift.
    Lift(usize),
    /// A coordinate of a point, $x$ for 0 and $y$ for 1.
    Coordinate(PointSrc, u8),
    /// The square of an instance stage element: the `ab` bridge's
    /// blinding.
    InstanceSquared(usize),
}

/// A transcript operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Absorb(ElementSrc),
    /// Absorbs a constant.
    AbsorbConst(u128),
    /// Squeezes a challenge into a work element slot.
    Squeeze(usize),
}

/// Absorbs a point: its coordinates, $x$ then $y$, each its own
/// operation so that the transcript may be cut between them.
fn absorb_point(ops: &mut Vec<Op>, point: PointSrc) {
    ops.push(Op::Absorb(ElementSrc::Coordinate(point, 0)));
    ops.push(Op::Absorb(ElementSrc::Coordinate(point, 1)));
}

/// A challenge that scales points, by how a chunk obtains its endoscalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChallengeRef {
    /// The squeezed element at a work slot of this side: the chunk reads
    /// its endoscalar, constraining it into range.
    Raw(usize),
    /// A challenge squeezed on the other side, by index into the side's
    /// challenge bits: the chunk allocates its bits as witnesses, bound
    /// across the cycle by the stage that holds them.
    Bits(usize),
}

/// A full-width scalar a chunk scales a point by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalarRef {
    /// An element of this side's field, whose digits the chunk allocates
    /// and binds to it.
    Element(ElementSrc),
    /// A value of the other field, by index into the side's foreign
    /// scalars, whose digits the chunk allocates as witnesses.
    Bits(usize),
}

/// One step of a point chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// $\text{acc} = e \cdot \text{acc} + P$, or $e \cdot \text{acc}$ alone.
    Horner {
        scale_by: ChallengeRef,
        add: Option<PointSrc>,
    },
    /// $\text{acc} = \text{acc} + e \cdot P$, or $\text{acc} + P$ alone.
    AddScaled {
        point: PointSrc,
        scale_by: Option<ChallengeRef>,
    },
}

/// A chunk of a point chain: from `init`, or from nothing, through
/// `steps`, into the work point slot `out`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainChunk {
    pub init: Option<PointSrc>,
    pub steps: Vec<Step>,
    pub out: usize,
}

/// A chunk of the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Chunk {
    /// Transcript operations: the sponge resumed from the transcript
    /// stage's state at `state_in`, or fresh, and saved to `state_out`, or
    /// not, when the transcript ends.
    Transcript {
        state_in: Option<usize>,
        ops: Vec<Op>,
        state_out: Option<usize>,
        /// The permutations the chunk performs, the saved state's included.
        permutations: usize,
    },
    /// Lifts of challenges into lifts stage slots.
    Lift {
        pairs: Vec<(ChallengeRef, usize)>,
    },
    /// The claims' base targets into work slots: on the circuit-field side
    /// the application's, the unified bridge's and the unified one's; on
    /// the scalar-field side the unified one's alone.
    Targets {
        out: Vec<usize>,
    },
    /// The fold's $W(r)$ for both layers, $t(r, z)$ and $1/r$.
    RevdotWeights {
        out: [usize; 4],
    },
    /// Each wire binding's expected value and mask at $r$.
    Bindings {
        out: Vec<[usize; 2]>,
    },
    /// The folded claim's public parts and the split identity, leaving
    /// $p(0)$'s value.
    RevdotPublic {
        out: usize,
    },
    /// The batch and the IPA's scalars, leaving $v$ and $c b z$.
    BatchIpa {
        out: [usize; 2],
    },
    /// The signed digits of full-width elements of this field, bound to
    /// them, into the digits stage from the slot each names.
    Digits {
        scalars: Vec<(ElementSrc, usize)>,
    },
    /// Sums of points into work point slots.
    Sums {
        sums: Vec<(usize, Vec<PointSrc>)>,
    },
    Chain(ChainChunk),
    /// Checks that each `by` scales `point` to `expected`.
    Checks {
        checks: Vec<(PointSrc, ChallengeRef, PointSrc)>,
    },
    /// One part of $k P$ for the full-width `scalar`: the signed-digit
    /// chain over the digits `digits` names, from the accumulator at
    /// `init`, or from `offset` when the part is the first, ended by the
    /// offset's removal when `finish`, into `out`; and, for a scalar of
    /// the other field, the same digits' part of the other side's digits
    /// stage commitment (`bind`).
    Scale {
        point: PointSrc,
        scalar: ScalarRef,
        offset: PointSrc,
        digits: (usize, usize),
        init: Option<usize>,
        finish: bool,
        out: usize,
        bind: Option<Bind>,
    },
    /// The base-case sign's term of the challenge stage: the generator,
    /// negated unless both headers are the dummy's.
    Sign {
        generator: usize,
        out: usize,
    },
    /// Enforces that `left` equals `right`.
    Equal {
        left: PointSrc,
        right: PointSrc,
    },
}

/// One part of the other side's digits stage commitment, over the digits
/// of one scalar a [`Chunk::Scale`] scales by: the signed sum, by the
/// digits' bits, of `generators`, the generator of each digit's wire in
/// the other side's digits stage, from the accumulator at `init` or from
/// nothing, into `out`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bind {
    pub generators: Vec<usize>,
    pub init: Option<usize>,
    pub out: usize,
}

/// The last stage a chunk needs, which sets the circuit kind it is packed
/// into: every chunk loads the instance, messages, lifts and work stages,
/// the transcript chunks and the bridge sums the transcript stage after
/// them, and the digits chunks the digits stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Last {
    Work,
    Transcript,
    Digits,
}

impl Chunk {
    /// The last stage the chunk needs.
    pub(crate) fn last(&self) -> Last {
        match self {
            Chunk::Transcript { .. } => Last::Transcript,
            Chunk::Digits { .. } => Last::Digits,
            Chunk::Sums { sums } => {
                if sums
                    .iter()
                    .flat_map(|(_, terms)| terms)
                    .any(|term| matches!(term, PointSrc::Bridge(_)))
                {
                    Last::Transcript
                } else {
                    Last::Work
                }
            }
            _ => Last::Work,
        }
    }
}

/// A claim's structure: its kind, the groups of commitment positions its
/// $a$ sums and Horner-folds under $z$, and the position of a raw claim's
/// $b$.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ClaimPlan {
    pub kind: Kind,
    pub groups: Vec<Vec<usize>>,
    pub b: Option<usize>,
}

/// A wire binding's structure: the degrees and where each expected value
/// comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BindingPlan {
    pub degrees: Vec<usize>,
    pub expected: Vec<ElementSrc>,
}

/// The work stage's regions one side's chunks share, by slot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Regions {
    /// Circuit-field side: the fuse's raw challenges, in
    /// [`nested::Challenges::in_order`] order.
    pub fuse: Vec<usize>,
    /// Circuit-field side: the compression's raw challenges of the host
    /// curve, in [`squeezed`] order.
    pub squeezed: Vec<usize>,
    /// Circuit-field side: the nested curve's, likewise.
    pub other_squeezed: Vec<usize>,
    /// The lifts of the compression challenges of the curve whose
    /// reduction this side checks, in [`squeezed`] order: lifts stage
    /// slots.
    pub lifts: Vec<usize>,
    /// Scalar-field side: the lifts of the fuse's $x$, $y$ and $u$, after
    /// [`lifts`](Self::lifts) in the lifts stage.
    pub fuse_lifts: Vec<usize>,
    /// Scalar-field side: the lifts of the host curve's compression
    /// challenges, whose points it checks, after
    /// [`fuse_lifts`](Self::fuse_lifts) in the lifts stage; the
    /// circuit-field side recomputes the stage in that order.
    pub point_lifts: Vec<usize>,
    /// The claims' base targets: application, unified bridge, unified on
    /// the circuit-field side; unified alone on the scalar-field side.
    pub targets: Vec<usize>,
    /// The registry restriction at $(r, y)$ of each claim that names a
    /// circuit, by claim index, prover-supplied.
    pub restrictions: Vec<Option<usize>>,
    /// The registry restriction at the compression's $w$, prover-supplied.
    pub restriction_at_w: usize,
    /// $W_\text{inner}(r)$, $W_\text{outer}(r)$, $t(r, z)$ and $1/r$.
    pub revdot: [usize; 4],
    /// Each wire binding's expected value and mask at $r$, by binding.
    pub bindings_at: Vec<[usize; 2]>,
    /// $p(0)$'s value.
    pub target_p0: usize,
    /// $v$ and $c b z$.
    pub batch: [usize; 2],
    /// The instance's openings' point and values: the fuse's $u$ as this
    /// side holds it, $v$, $a(u)$ and $b(u)$.
    pub opening: Vec<ElementSrc>,
    /// The wire bindings' registry values, prover-supplied.
    pub registry_values: Vec<usize>,
    /// The claims' points, by claim index.
    pub claims: Vec<usize>,
    /// The fold's $\[A\]$, dilated and raw commitments.
    pub derived: [usize; 3],
    /// The batched commitment.
    pub batched: usize,
    /// The IPA's witness points $u_j^{-1} L_j$, prover-supplied.
    pub inverse_scaled: Vec<usize>,
    /// $G'$, prover-supplied.
    pub g_prime: usize,
    /// The IPA's left-hand side and its three scaled terms.
    pub ipa_left: usize,
    pub ipa_terms: [usize; 3],
    /// Circuit-field side: the recomputed challenge stage commitment and
    /// `ab` bridge commitment.
    pub challenge_stage: usize,
    pub ab_bridge: usize,
    /// Circuit-field side: the sums of the bridges of the scalar-field
    /// side's instance and messages stages' values, its recomputation of
    /// those stages' commitments.
    pub bridge_sums: [usize; 2],
    /// Circuit-field side: the recomputed commitment of the scalar-field
    /// side's lifts stage.
    pub lifts_sum: usize,
    /// The recomputed commitment of the other side's digits stage.
    pub digits_sum: usize,
    /// The work points the side's binding circuit exposes, in the order
    /// the profile's [`Binding`](crate::profile::Binding) names the
    /// stages they recompute.
    pub exposed: Vec<usize>,
}

/// One side's schedule: its chunks, the stage layout, the work stage's
/// size, the claims and bindings the reduction runs over, and the regions.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Schedule {
    pub chunks: Vec<Chunk>,
    /// The circuits: each a run of consecutive chunks, in order, every
    /// chunk in exactly one, the transcript chunks' circuits first and
    /// the digits chunks' last.
    pub circuits: Vec<CircuitPlan>,
    pub layout: Layout,
    /// The work stage's element and point counts.
    pub elements: usize,
    pub points: usize,
    /// The transcript stage's element count: the sponge states saved.
    pub states: usize,
    /// The claims of the reduction this side checks in its field.
    pub claims: Vec<ClaimPlan>,
    pub bindings: Vec<BindingPlan>,
    pub regions: Regions,
    /// The scalar field's values whose digits the circuit-field side
    /// scales generators by for the `ab` bridge, with the generator each
    /// lands on, in the side's foreign scalars' order after $v$, $c$ and
    /// $c b z$.
    pub ab_terms: Vec<(usize, AbValue)>,
}

/// The circuit a run of chunks makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CircuitPlan {
    /// The chunks' indices, consecutive.
    pub chunks: core::ops::Range<usize>,
    /// The last stage the chunks need, which every chunk of the run
    /// shares.
    pub last: Last,
}

/// The gates a circuit pays before its chunks: loading the stages every
/// chunk loads, with room for the estimate's error. A digits circuit pays
/// its digits stage on top ([`pack`]).
const OVERHEAD: usize = 400;

/// The gates a chunk's work takes, estimated from each kind's measured
/// cost per item, over the circuit's [`OVERHEAD`]. Pessimistic by a few
/// percent, so that circuits packed to the fill by it stay within the
/// budget; the chunk tests measure the circuits.
pub(crate) fn gates(chunk: &Chunk) -> usize {
    match chunk {
        Chunk::Transcript {
            ops, permutations, ..
        } => 100 + 320 * permutations + 4 * ops.len(),
        Chunk::Lift { pairs } => 330 * pairs.len(),
        Chunk::Targets { .. } => 200,
        Chunk::RevdotWeights { .. } => 1500,
        Chunk::Bindings { .. } => 1150,
        Chunk::RevdotPublic { .. } => 400,
        Chunk::BatchIpa { .. } => 150,
        Chunk::Digits { scalars } => 420 * scalars.len(),
        Chunk::Sums { sums } => {
            60 + sums
                .iter()
                .map(|(_, terms)| 10 + 6 * terms.len())
                .sum::<usize>()
        }
        Chunk::Chain(chain) => {
            50 + chain
                .steps
                .iter()
                .map(|step| match step {
                    Step::Horner { .. } => 730,
                    Step::AddScaled {
                        scale_by: Some(_), ..
                    } => 730,
                    Step::AddScaled { scale_by: None, .. } => 20,
                })
                .sum::<usize>()
        }
        Chunk::Checks { checks } => 730 * checks.len(),
        Chunk::Scale { digits, bind, .. } => {
            150 + (10 + if bind.is_some() { 8 } else { 0 }) * (digits.1 - digits.0)
        }
        Chunk::Sign { .. } => 60,
        Chunk::Equal { .. } => 40,
    }
}

/// Packs `chunks`, in order, into circuits of at most `fill` gates by
/// [`gates`], a chunk that exceeds the fill alone in its circuit, and
/// chunks of different last stages never together. A digits circuit
/// reserves its digits stage's gates, `digits` wires at two per gate,
/// which the others do not.
fn pack(chunks: &[Chunk], fill: usize, digits: usize) -> Vec<CircuitPlan> {
    let overhead = |last: Last| match last {
        Last::Digits => OVERHEAD + digits.div_ceil(2),
        Last::Work | Last::Transcript => OVERHEAD,
    };
    let mut circuits = Vec::new();
    let mut start = 0;
    let mut used = overhead(chunks[0].last());
    for (index, chunk) in chunks.iter().enumerate() {
        let cost = gates(chunk);
        if index > start && (chunk.last() != chunks[start].last() || used + cost > fill) {
            circuits.push(CircuitPlan {
                chunks: start..index,
                last: chunks[start].last(),
            });
            start = index;
            used = overhead(chunk.last());
        }
        used += cost;
    }
    if start < chunks.len() {
        circuits.push(CircuitPlan {
            chunks: start..chunks.len(),
            last: chunks[start].last(),
        });
    }
    circuits
}

/// Allocates work slots, and the lifts, transcript and digits stages'.
#[derive(Default)]
struct Slots {
    elements: usize,
    points: usize,
    states: usize,
    lifts: usize,
    digits: usize,
}

impl Slots {
    /// A saved sponge state's `width` consecutive transcript slots.
    fn state(&mut self, width: usize) -> usize {
        self.states += width;
        self.states - width
    }

    /// `n` consecutive lifts stage slots.
    fn lifts(&mut self, n: usize) -> Vec<usize> {
        let first = self.lifts;
        self.lifts += n;
        (first..first + n).collect()
    }

    /// `n` consecutive digits stage slots, returning the first.
    fn digits(&mut self, n: usize) -> usize {
        self.digits += n;
        self.digits - n
    }

    fn element(&mut self) -> usize {
        self.elements += 1;
        self.elements - 1
    }

    fn elements(&mut self, n: usize) -> Vec<usize> {
        (0..n).map(|_| self.element()).collect()
    }

    fn point(&mut self) -> usize {
        self.points += 1;
        self.points - 1
    }

    fn points(&mut self, n: usize) -> Vec<usize> {
        (0..n).map(|_| self.point()).collect()
    }
}

/// How much of each kind of work a chunk takes, and how full a circuit
/// packs.
///
/// [`FITTED`](Self::FITTED) fits a circuit of [`FITTED_GATES`] gates with
/// its stages loaded. Every kind's cost is linear in its count, so a
/// schedule for chunk circuits at rank `R` takes [`at`](Self::at): the
/// fitted limits scaled to half of `R`'s budget, so that a circuit packs
/// several chunks, up to [`fill`](Self::fill).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Endoscalings per chain chunk.
    pub scalings: usize,
    /// Permutations per transcript chunk, the saved state's included.
    pub permutations: usize,
    /// Lifts per lift chunk.
    pub lifts: usize,
    /// Checks per check chunk.
    pub checks: usize,
    /// Point sums per sums chunk.
    pub sums: usize,
    /// Digit decompositions per digits chunk.
    pub digits: usize,
    /// The parts a full-width scaling is cut into.
    pub scale_parts: usize,
    /// The gates a circuit's chunks are packed up to, as [`gates`]
    /// estimates them.
    pub fill: usize,
}

/// The gate budget [`Limits::FITTED`] is fitted to: the production rank's
/// $2^{11}$.
const FITTED_GATES: usize = 1 << 11;

/// The part of a budget a circuit packs up to: the rest covers the
/// estimate's error.
const fn fill_of(budget: usize) -> usize {
    budget / 8 * 7
}

impl Limits {
    /// The limits fitted to [`FITTED_GATES`].
    pub(crate) const FITTED: Limits = Limits {
        scalings: 2,
        permutations: 4,
        lifts: 3,
        checks: 2,
        sums: 24,
        digits: 3,
        scale_parts: 2,
        fill: fill_of(FITTED_GATES),
    };

    /// The limits for chunk circuits at rank `R`: the fitted limits times
    /// the multiple of [`FITTED_GATES`] in half the budget, a scaling cut
    /// into that many times fewer parts, and the fill of the budget. A
    /// budget below twice the fitted one keeps the fitted limits.
    pub(crate) fn at<R: Rank>() -> Self {
        let scale = (R::n() / (2 * FITTED_GATES)).max(1);
        let fitted = Self::FITTED;
        Limits {
            scalings: fitted.scalings * scale,
            permutations: fitted.permutations * scale,
            lifts: fitted.lifts * scale,
            checks: fitted.checks * scale,
            sums: fitted.sums * scale,
            digits: fitted.digits * scale,
            scale_parts: fitted.scale_parts.div_ceil(scale),
            fill: fill_of(R::n()),
        }
    }
}

/// The compression's challenge count per curve: the four sampled, the
/// fold's four, $\rho$, $r$, $\alpha$, $u$, $\beta$, $\xi$, $z$ and the
/// rounds'.
pub(crate) const fn challenges_per_curve<K: Rank>() -> usize {
    4 + 4 + 2 + 3 + 2 + K::RANK as usize
}

/// Positions within [`Regions::squeezed`] and [`Regions::lifts`].
pub(crate) mod squeezed {
    pub const W: usize = 0;
    pub const Y: usize = 1;
    pub const Z: usize = 2;
    pub const SIGMA: usize = 3;
    pub const MU: usize = 4;
    pub const NU: usize = 5;
    pub const MU_PRIME: usize = 6;
    pub const NU_PRIME: usize = 7;
    pub const RHO: usize = 8;
    pub const R: usize = 9;
    pub const ALPHA: usize = 10;
    pub const U: usize = 11;
    pub const BETA: usize = 12;
    pub const XI: usize = 13;
    pub const IPA_Z: usize = 14;
    pub const ROUNDS: usize = 15;
}

/// Positions within [`Regions::fuse`].
pub(crate) mod fuse {
    pub const W: usize = 0;
    pub const Y: usize = 1;
    pub const Z: usize = 2;
    pub const X: usize = 7;
    pub const ALPHA: usize = 8;
    pub const U: usize = 9;
    pub const PRE_BETA: usize = 10;
}

/// The tag a transcript absorbs, as the constants [`Transcript::new`]
/// absorbs: the length, then each 16-byte chunk as a little-endian
/// integer.
///
/// [`Transcript::new`]: crate::internal::transcript::Transcript::new
fn tag_ops(tag: &[u8]) -> Vec<Op> {
    once(Op::AbsorbConst(tag.len() as u128))
        .chain(tag.chunks(16).map(|chunk| {
            let bytes: [u8; 16] = core::array::from_fn(|i| chunk.get(i).copied().unwrap_or(0));
            Op::AbsorbConst(u128::from_le_bytes(bytes))
        }))
        .collect()
}

/// Cuts transcript `ops` into chunks at the sponge's legal boundaries, by
/// a permutation budget, saving the state between them in the transcript
/// stage.
fn transcript_chunks<P: PoseidonPermutation<F>, F: Field>(
    ops: Vec<Op>,
    slots: &mut Slots,
    limit: usize,
) -> Vec<Chunk> {
    enum Mode {
        Absorb { buffered: usize },
        Squeeze { available: usize },
    }
    let rate = P::RATE;
    let mut chunks = Vec::new();
    let mut current: Vec<Op> = Vec::new();
    let mut state_in = None;
    let mut permutations = 0usize;
    let mut mode = Mode::Absorb { buffered: 0 };
    for op in ops {
        // The permutations this op costs and whether a cut is legal before
        // it: in absorb mode with a non-empty buffer that is full or that
        // the op's squeeze would permute anyway.
        let (cost, legal) = match (&mode, op) {
            (Mode::Absorb { buffered }, Op::Squeeze(_)) => (1, *buffered > 0),
            (Mode::Absorb { buffered }, _) => (usize::from(*buffered == rate), *buffered == rate),
            (Mode::Squeeze { available }, Op::Squeeze(_)) => (usize::from(*available == 0), false),
            (Mode::Squeeze { .. }, _) => (0, false),
        };
        if legal && permutations + cost + 1 > limit && !current.is_empty() {
            let state_out = slots.state(P::T);
            chunks.push(Chunk::Transcript {
                state_in,
                ops: core::mem::take(&mut current),
                state_out: Some(state_out),
                permutations: permutations + 1,
            });
            state_in = Some(state_out);
            // Saving the state permutes once, after which the resumed
            // sponge stands in squeeze mode with the rate available.
            permutations = 0;
            mode = Mode::Squeeze { available: rate };
        }
        // Apply the op to the mode.
        match op {
            Op::Squeeze(_) => {
                match &mut mode {
                    Mode::Absorb { .. } => {
                        permutations += 1;
                        mode = Mode::Squeeze { available: rate };
                    }
                    Mode::Squeeze { available } => {
                        if *available == 0 {
                            permutations += 1;
                            *available = rate;
                        }
                    }
                }
                if let Mode::Squeeze { available } = &mut mode {
                    *available -= 1;
                }
            }
            _ => match &mut mode {
                Mode::Squeeze { .. } => mode = Mode::Absorb { buffered: 1 },
                Mode::Absorb { buffered } => {
                    if *buffered == rate {
                        permutations += 1;
                        *buffered = 0;
                    }
                    *buffered += 1;
                }
            },
        }
        current.push(op);
    }
    if !current.is_empty() {
        chunks.push(Chunk::Transcript {
            state_in,
            ops: current,
            state_out: None,
            permutations,
        });
    }
    chunks
}

/// Records the claims' structure as the decider enumerates them.
struct Planner {
    claims: Vec<ClaimPlan>,
}

impl Planner {
    fn circuit(&mut self, circuit: CircuitIndex, rxs: impl Iterator<Item = usize>) {
        self.claims.push(ClaimPlan {
            kind: Kind::Circuit(circuit),
            groups: vec![rxs.collect()],
            b: None,
        });
    }

    fn bonding(
        &mut self,
        circuit: CircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = usize>>,
    ) {
        self.claims.push(ClaimPlan {
            kind: Kind::Bonding(circuit),
            groups: groups.map(|group| group.collect()).collect(),
            b: None,
        });
    }

    fn raw(&mut self, a: usize, b: usize) {
        self.claims.push(ClaimPlan {
            kind: Kind::Raw,
            groups: vec![vec![a]],
            b: Some(b),
        });
    }

    fn masked(&mut self, positions: impl IntoIterator<Item = usize>) {
        for (m, position) in positions.into_iter().enumerate() {
            self.claims.push(ClaimPlan {
                kind: Kind::Masked(m),
                groups: vec![vec![position]],
                b: None,
            });
        }
    }
}

impl native::claims::Processor<Standard, usize, CircuitIndex> for Planner {
    fn raw_claim(&mut self, a: usize, b: usize) {
        self.raw(a, b);
    }

    fn circuit_claim(&mut self, circuit_id: CircuitIndex, rx: usize) {
        self.circuit(circuit_id, once(rx));
    }

    fn internal_circuit_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        rxs: impl Iterator<Item = usize>,
    ) {
        self.circuit(id.circuit_index::<Standard>(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: native::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = usize>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index::<Standard>(), groups);
        Ok(())
    }
}

impl nested::claims::Processor<Standard, usize> for Planner {
    fn raw_claim(&mut self, a: usize, b: usize) {
        self.raw(a, b);
    }

    fn internal_circuit_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        rxs: impl Iterator<Item = usize>,
    ) {
        self.circuit(id.circuit_index::<Standard>(), rxs);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: nested::InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = usize>>,
    ) -> Result<()> {
        self.bonding(id.circuit_index::<Standard>(), groups);
        Ok(())
    }
}

/// The application circuit's index in a schedule's claims. The chunk
/// circuits are fixed for every application circuit, so a schedule names
/// the proof's own circuit by this index, which no internal circuit holds,
/// and the prover supplies that circuit's restriction under it.
pub(crate) const APPLICATION: CircuitIndex = CircuitIndex::from_u32(u32::MAX);

/// A source over the native components by position, with the application
/// circuit under [`APPLICATION`].
struct NativePositions {
    circuit_id: CircuitIndex,
}

impl Source for NativePositions {
    type RxComponent = native::RxComponent;
    type Rx = usize;
    type AppCircuitId = CircuitIndex;

    fn rx(&self, component: native::RxComponent) -> impl Iterator<Item = usize> {
        once(native_position::<Standard>(component))
    }

    fn app_circuits(&self) -> impl Iterator<Item = CircuitIndex> {
        once(self.circuit_id)
    }
}

struct NestedPositions;

impl Source for NestedPositions {
    type RxComponent = nested::RxComponent;
    type Rx = usize;
    type AppCircuitId = ();

    fn rx(&self, component: nested::RxComponent) -> impl Iterator<Item = usize> {
        once(nested_position::<Standard>(component))
    }

    fn app_circuits(&self) -> impl Iterator<Item = ()> {
        core::iter::empty()
    }
}

/// The native claims' plans, the application circuit's under
/// [`APPLICATION`], then the wire bindings', in the compressed verifier's
/// order, over positions within the native commitments.
pub(crate) fn native_claims() -> Result<Vec<ClaimPlan>> {
    let mut planner = Planner { claims: Vec::new() };
    let source = NativePositions {
        circuit_id: APPLICATION,
    };
    native::claims::build::<Standard, _, _>(&source, &mut planner)?;
    planner.masked(
        [
            native::RxIndex::Preamble,
            native::RxIndex::Query,
            native::RxIndex::Eval,
            native::RxIndex::PointsAb,
            native::RxIndex::PointsF,
        ]
        .map(|index| native_position::<Standard>(native::RxComponent::Rx(index))),
    );
    Ok(planner.claims)
}

/// The nested claims' plans, as [`native_claims`] lists them, over
/// positions within the nested commitments.
pub(crate) fn nested_claims() -> Result<Vec<ClaimPlan>> {
    let mut planner = Planner { claims: Vec::new() };
    nested::claims::build::<Standard, _, _>(&NestedPositions, &mut planner)?;
    planner.masked(
        [
            nested::RxIndex::BridgePreamble,
            nested::RxIndex::BridgeQuery,
            nested::RxIndex::BridgeEval,
        ]
        .map(|index| nested_position::<Standard>(nested::RxComponent::Rx(index))),
    );
    Ok(planner.claims)
}

/// What a schedule knows of the other side's digits stage: the generator
/// each of its digits lands on, value by value, a scalar's width of them
/// per value in the side's foreign scalars' order, or only how many
/// scalars it holds. A schedule built from the count alone has every
/// slot the full one has and no generator
/// ([`Side::sizes`](super::side::Side::sizes)): the stages'
/// lengths take it, so that the other side's digits stage, which comes
/// after its work stage, can be laid out from it without the two sides'
/// schedules each waiting on the other.
pub(crate) enum Foreign {
    Scalars(usize),
    Degrees(Vec<usize>),
}

/// Builds one side's schedule.
struct Builder {
    layout: Layout,
    /// The digit count of a full-width scalar of the other field.
    scalar_bits: usize,
    foreign: Foreign,
    limits: Limits,
    slots: Slots,
    regions: Regions,
    chunks: Vec<Chunk>,
    /// Each foreign scalar's part of the other side's digits stage
    /// commitment, by the scalar's index, as the scalings leave them.
    bound: Vec<Option<usize>>,
}

impl Builder {
    fn new(layout: Layout, scalar_bits: usize, foreign: Foreign, limits: Limits) -> Self {
        let scalars = match &foreign {
            Foreign::Scalars(scalars) => *scalars,
            Foreign::Degrees(degrees) => {
                assert_eq!(
                    degrees.len() % scalar_bits,
                    0,
                    "the other side holds whole scalars' digits"
                );
                degrees.len() / scalar_bits
            }
        };
        Builder {
            layout,
            scalar_bits,
            foreign,
            limits,
            slots: Slots::default(),
            regions: Regions::default(),
            chunks: Vec::new(),
            bound: alloc::vec![None; scalars],
        }
    }

    /// $k P$ for a full-width scalar, as [`Limits::scale_parts`] chunks
    /// over consecutive runs of its digits, from the top down, into `out`.
    /// A scalar of the other field is scaled by once: its digits' part of
    /// the other side's digits stage commitment rides along, into a slot
    /// [`digits_sum`](Self::digits_sum) takes.
    fn scale(&mut self, point: PointSrc, scalar: ScalarRef, offset: PointSrc, out: usize) {
        let n = self.scalar_bits;
        let parts = self.limits.scale_parts;
        let bound = match scalar {
            ScalarRef::Bits(id) => {
                assert!(
                    self.bound[id].is_none(),
                    "a foreign scalar binds its digits once"
                );
                let slot = self.slots.point();
                self.bound[id] = Some(slot);
                Some((id, slot))
            }
            ScalarRef::Element(_) => None,
        };
        let mut init = None;
        let mut bind_init = None;
        for part in 0..parts {
            // Part `p` covers the digits of the `p`-th run from the top.
            let hi = n - part * n / parts;
            let lo = n - (part + 1) * n / parts;
            let last = part + 1 == parts;
            let slot = if last { out } else { self.slots.point() };
            let bind = bound.map(|(id, out)| {
                let slot = if last { out } else { self.slots.point() };
                let bind = Bind {
                    generators: match &self.foreign {
                        Foreign::Degrees(degrees) => degrees[id * n + lo..id * n + hi].to_vec(),
                        Foreign::Scalars(_) => Vec::new(),
                    },
                    init: bind_init,
                    out: slot,
                };
                bind_init = Some(slot);
                bind
            });
            self.chunks.push(Chunk::Scale {
                point,
                scalar,
                offset,
                digits: (lo, hi),
                init,
                finish: last,
                out: slot,
                bind,
            });
            init = Some(slot);
        }
    }

    /// The other side's digits stage commitment: the sum of every foreign
    /// scalar's part, each scaling having left one, into
    /// [`Regions::digits_sum`].
    fn digits_sum(&mut self) {
        let terms: Vec<PointSrc> = self
            .bound
            .iter()
            .map(|slot| PointSrc::Work(slot.expect("every foreign scalar was scaled by")))
            .collect();
        self.regions.digits_sum = self.slots.point();
        self.chunks.push(Chunk::Sums {
            sums: vec![(self.regions.digits_sum, terms)],
        });
    }

    /// The signed digits of this side's full-width `scalars`, bound to
    /// them, into the digits stage in order: the other side's foreign
    /// scalars, which it scales by their digits.
    fn digits(&mut self, scalars: Vec<ElementSrc>) {
        let width = self.layout.digits / scalars.len();
        assert_eq!(width * scalars.len(), self.layout.digits);
        let scalars: Vec<(ElementSrc, usize)> = scalars
            .into_iter()
            .map(|src| (src, self.slots.digits(width)))
            .collect();
        for batch in scalars.chunks(self.limits.digits) {
            self.chunks.push(Chunk::Digits {
                scalars: batch.to_vec(),
            });
        }
    }

    /// Cuts a Horner chain over `points`, from the last present point back
    /// to the first, into chain chunks by the scaling budget, ending in
    /// `out`; `None` entries scale alone. Returns false if no point is
    /// present.
    fn horner(&mut self, points: &[Option<PointSrc>], scale_by: ChallengeRef, out: usize) -> bool {
        let Some(first) = points.iter().rposition(|point| point.is_some()) else {
            return false;
        };
        let init = points[first];
        let mut steps: Vec<Step> = points[..first]
            .iter()
            .rev()
            .map(|&add| Step::Horner { scale_by, add })
            .collect();
        if steps.is_empty() {
            self.chunks
                .push(Chunk::Chain(ChainChunk { init, steps, out }));
            return true;
        }
        let mut acc_in = init;
        while !steps.is_empty() {
            let take = steps.len().min(self.limits.scalings);
            let rest = steps.split_off(take);
            let last = rest.is_empty();
            let slot = if last { out } else { self.slots.point() };
            self.chunks.push(Chunk::Chain(ChainChunk {
                init: acc_in,
                steps,
                out: slot,
            }));
            acc_in = Some(PointSrc::Work(slot));
            steps = rest;
        }
        true
    }

    /// Cuts a sum of scaled terms, from `init`, into chain chunks by the
    /// scaling budget, ending in `out`.
    fn sum(&mut self, init: PointSrc, terms: &[(PointSrc, Option<ChallengeRef>)], out: usize) {
        let mut acc_in = init;
        let mut steps = Vec::new();
        let mut scalings = 0;
        for (i, &(point, scale_by)) in terms.iter().enumerate() {
            let cost = usize::from(scale_by.is_some());
            if scalings + cost > self.limits.scalings && !steps.is_empty() {
                let slot = self.slots.point();
                self.chunks.push(Chunk::Chain(ChainChunk {
                    init: Some(acc_in),
                    steps: core::mem::take(&mut steps),
                    out: slot,
                }));
                acc_in = PointSrc::Work(slot);
                scalings = 0;
            }
            steps.push(Step::AddScaled { point, scale_by });
            scalings += cost;
            if i + 1 == terms.len() {
                self.chunks.push(Chunk::Chain(ChainChunk {
                    init: Some(acc_in),
                    steps: core::mem::take(&mut steps),
                    out,
                }));
            }
        }
    }

    /// The fold of one derived commitment: each group's Horner chain
    /// under `inner` over the claims `pick` keeps, then the groups' under
    /// `outer`.
    fn fold(
        &mut self,
        claims: &[ClaimPlan],
        pick: impl Fn(&ClaimPlan) -> bool,
        inner: ChallengeRef,
        outer: ChallengeRef,
        out: usize,
    ) {
        let layout = FoldLayout::new(claims.len());
        let claim_points = self.regions.claims.clone();
        let mut groups: Vec<Option<PointSrc>> = Vec::with_capacity(layout.groups());
        for g in 0..layout.groups() {
            let members: Vec<Option<PointSrc>> = layout
                .members(g)
                .map(|i| pick(&claims[i]).then_some(PointSrc::Work(claim_points[i])))
                .collect();
            let slot = self.slots.point();
            if self.horner(&members, inner, slot) {
                groups.push(Some(PointSrc::Work(slot)));
            } else {
                groups.push(None);
            }
        }
        assert!(
            self.horner(&groups, outer, out),
            "a derived polynomial has a term"
        );
    }

    /// The claims' points: sums of their groups' components into work
    /// slots, and for a claim with several groups the Horner fold of the
    /// group sums under $z$.
    fn claims(&mut self, claims: &[ClaimPlan], z: ChallengeRef) {
        let commitments = self.layout.instance.commitments;
        let claim_points = self.slots.points(claims.len());
        let mut sums: Vec<(usize, Vec<PointSrc>)> = Vec::new();
        let mut folds: Vec<(Vec<Option<PointSrc>>, usize)> = Vec::new();
        let instance = |group: &[usize]| -> Vec<PointSrc> {
            group
                .iter()
                .map(|&p| PointSrc::Instance(commitments.at(p)))
                .collect()
        };
        for (i, claim) in claims.iter().enumerate() {
            if claim.groups.len() == 1 {
                sums.push((claim_points[i], instance(&claim.groups[0])));
            } else {
                let mut group_slots = Vec::with_capacity(claim.groups.len());
                for group in &claim.groups {
                    let slot = self.slots.point();
                    sums.push((slot, instance(group)));
                    group_slots.push(Some(PointSrc::Work(slot)));
                }
                folds.push((group_slots, claim_points[i]));
            }
        }
        for batch in sums.chunks(self.limits.sums) {
            self.chunks.push(Chunk::Sums {
                sums: batch.to_vec(),
            });
        }
        for (group_slots, out) in folds {
            // The fold weights the first group highest, as the shaper does.
            let reversed: Vec<_> = group_slots.into_iter().rev().collect();
            self.horner(&reversed, z, out);
        }
        self.regions.claims = claim_points;
    }

    /// The IPA's chunks for this side's curve: the left-hand side's sum,
    /// the round checks, the three scalings and the final equality.
    fn ipa(
        &mut self,
        rounds: usize,
        xi: ChallengeRef,
        round_challenge: impl Fn(usize) -> ChallengeRef,
        scalars: [ScalarRef; 3],
    ) {
        use super::stages::message_points::*;
        let points = self.layout.messages.points_of_curve;
        let message = |i: usize| PointSrc::Message(points.at(i));
        self.regions.inverse_scaled = self.slots.points(rounds);
        self.regions.g_prime = self.slots.point();
        self.regions.ipa_left = self.slots.point();
        let mut terms = vec![(message(S_COMMITMENT), Some(xi))];
        let mut checks = Vec::with_capacity(rounds);
        for j in 0..rounds {
            let scaled = PointSrc::Work(self.regions.inverse_scaled[j]);
            terms.push((scaled, None));
            terms.push((message(r(j)), Some(round_challenge(j))));
            checks.push((scaled, round_challenge(j), message(l(j))));
        }
        let (batched, ipa_left) = (self.regions.batched, self.regions.ipa_left);
        self.sum(PointSrc::Work(batched), &terms, ipa_left);
        for batch in checks.chunks(self.limits.checks) {
            self.chunks.push(Chunk::Checks {
                checks: batch.to_vec(),
            });
        }
        self.regions.ipa_terms = [self.slots.point(), self.slots.point(), self.slots.point()];
        for (i, (point, scalar)) in [
            (PointSrc::Generator(0), scalars[0]),
            (PointSrc::Work(self.regions.g_prime), scalars[1]),
            (PointSrc::U, scalars[2]),
        ]
        .into_iter()
        .enumerate()
        {
            let out = self.regions.ipa_terms[i];
            self.scale(point, scalar, PointSrc::Generator(1), out);
        }
        let right = self.slots.point();
        let terms = self.regions.ipa_terms;
        self.sum(
            PointSrc::Work(terms[0]),
            &[
                (PointSrc::Work(terms[1]), None),
                (PointSrc::Work(terms[2]), None),
            ],
            right,
        );
        self.chunks.push(Chunk::Equal {
            left: PointSrc::Work(ipa_left),
            right: PointSrc::Work(right),
        });
    }

    /// The wire bindings' plans from their degrees and expected sources,
    /// a `None` source a registry value the prover supplies.
    fn bindings(&mut self, plans: Vec<(Vec<usize>, Vec<Option<ElementSrc>>)>) -> Vec<BindingPlan> {
        plans
            .into_iter()
            .map(|(degrees, expected)| {
                assert_eq!(degrees.len(), expected.len(), "one value per bound wire");
                let expected = expected
                    .into_iter()
                    .map(|src| {
                        src.unwrap_or_else(|| {
                            let slot = self.slots.element();
                            self.regions.registry_values.push(slot);
                            ElementSrc::Work(slot)
                        })
                    })
                    .collect();
                BindingPlan { degrees, expected }
            })
            .collect()
    }

    fn finish(
        self,
        claims: Vec<ClaimPlan>,
        bindings: Vec<BindingPlan>,
        ab_terms: Vec<(usize, AbValue)>,
    ) -> Schedule {
        assert_eq!(
            self.slots.lifts, self.layout.lifts,
            "the lifts stage holds every lift"
        );
        assert_eq!(
            self.slots.digits, self.layout.digits,
            "the digits stage holds every digit"
        );
        let circuits = pack(&self.chunks, self.limits.fill, self.layout.digits);
        Schedule {
            chunks: self.chunks,
            circuits,
            layout: self.layout,
            elements: self.slots.elements,
            points: self.slots.points,
            states: self.slots.states,
            claims,
            bindings,
            regions: self.regions,
            ab_terms,
        }
    }
}

/// What the shared part of a schedule takes from its side.
struct Body<'a> {
    /// The claims of the reduction this side checks in its field.
    scalar_claims: &'a [ClaimPlan],
    /// The number of base targets the targets chunk leaves.
    targets: usize,
    /// The wire bindings' degrees and expected sources.
    bindings: Vec<(Vec<usize>, Vec<Option<ElementSrc>>)>,
    /// Elements beyond $v$, $c$ and $c b z$ whose digits this side binds
    /// for the other.
    extra_digits: Vec<ElementSrc>,
    /// The claims of the reduction whose points this side checks.
    point_claims: &'a [ClaimPlan],
    /// That reduction's compression challenge at a [`squeezed`] index.
    point_challenge: &'a dyn Fn(usize) -> ChallengeRef,
    /// The number of that curve's listed components, after which its
    /// registry restriction's and $p$'s commitments sit.
    components: usize,
    /// The positions of that curve's $A$ and $B$ commitments.
    ab: [usize; 2],
}

/// The chunks both sides share: the targets, the reduction, the batch and
/// the IPA's scalars in this side's field, then the claims, the folds, the
/// batched commitment and the IPA's points on this side's curve. Returns
/// the wire bindings' plans and the elements whose digits this side holds
/// for the other, which the side's schedule ends with ([`Builder::digits`]).
fn body<K: Rank>(b: &mut Builder, body: Body<'_>) -> (Vec<BindingPlan>, Vec<ElementSrc>) {
    let rounds = K::RANK as usize;
    let layout = b.layout;
    let message_scalar = |i: usize| ElementSrc::Message(layout.messages.scalars.at(i));
    let message_point = |i: usize| PointSrc::Message(layout.messages.points_of_curve.at(i));
    let commitment = |p: usize| PointSrc::Instance(layout.instance.commitments.at(p));

    b.regions.targets = b.slots.elements(body.targets);
    b.chunks.push(Chunk::Targets {
        out: b.regions.targets.clone(),
    });
    b.regions.restrictions = body
        .scalar_claims
        .iter()
        .map(|claim| match claim.kind {
            Kind::Circuit(_) | Kind::Bonding(_) => Some(b.slots.element()),
            _ => None,
        })
        .collect();
    b.regions.restriction_at_w = b.slots.element();
    let bindings = b.bindings(body.bindings);
    b.regions.revdot = [
        b.slots.element(),
        b.slots.element(),
        b.slots.element(),
        b.slots.element(),
    ];
    b.chunks.push(Chunk::RevdotWeights {
        out: b.regions.revdot,
    });
    b.regions.bindings_at = (0..bindings.len())
        .map(|_| [b.slots.element(), b.slots.element()])
        .collect();
    b.chunks.push(Chunk::Bindings {
        out: b.regions.bindings_at.clone(),
    });
    b.regions.target_p0 = b.slots.element();
    b.chunks.push(Chunk::RevdotPublic {
        out: b.regions.target_p0,
    });
    b.regions.batch = [b.slots.element(), b.slots.element()];
    b.chunks.push(Chunk::BatchIpa {
        out: b.regions.batch,
    });
    // The digits of v, c and cbz, the full-width scalars the other side
    // scales by, and whatever else it needs from this field.
    let mut digits = vec![
        ElementSrc::Work(b.regions.batch[0]),
        message_scalar(MESSAGE_SCALARS - 1),
        ElementSrc::Work(b.regions.batch[1]),
    ];
    digits.extend(body.extra_digits);

    // The point checks of this side's curve under its reduction's
    // challenges.
    let challenge = body.point_challenge;
    b.claims(body.point_claims, challenge(squeezed::Z));
    b.regions.derived = [b.slots.point(), b.slots.point(), b.slots.point()];
    let derived = b.regions.derived;
    b.fold(
        body.point_claims,
        |_| true,
        challenge(squeezed::MU),
        challenge(squeezed::MU_PRIME),
        derived[0],
    );
    b.fold(
        body.point_claims,
        |claim| matches!(claim.kind, Kind::Circuit(_)),
        challenge(squeezed::NU),
        challenge(squeezed::NU_PRIME),
        derived[1],
    );
    // The raw polynomial: the raw claims' b under the b weights, here the
    // one raw claim's at weight one.
    let raw_b = body
        .point_claims
        .iter()
        .enumerate()
        .filter_map(|(i, claim)| claim.b.map(|b| (i, b)))
        .collect::<Vec<_>>();
    assert_eq!(raw_b.len(), 1, "one raw claim at the first slot");
    assert_eq!(raw_b[0].0, 0);
    b.chunks.push(Chunk::Sums {
        sums: vec![(derived[2], vec![commitment(raw_b[0].1)])],
    });
    b.regions.batched = b.slots.point();
    {
        use super::stages::message_points::*;
        // The batch weights f highest: a Horner chain from f down.
        let terms: Vec<Option<PointSrc>> = [
            message_point(F),
            PointSrc::Work(derived[0]),
            PointSrc::Work(derived[1]),
            PointSrc::Work(derived[2]),
            message_point(INNER),
            message_point(OUTER),
            message_point(P),
            message_point(Q),
            commitment(body.components),
            commitment(body.components + 1),
            commitment(body.ab[0]),
            commitment(body.ab[1]),
        ]
        .into_iter()
        .rev()
        .map(Some)
        .collect();
        let batched = b.regions.batched;
        b.horner(&terms, challenge(squeezed::BETA), batched);
    }
    b.ipa(
        rounds,
        challenge(squeezed::XI),
        |j| challenge(squeezed::ROUNDS + j),
        [ScalarRef::Bits(0), ScalarRef::Bits(1), ScalarRef::Bits(2)],
    );
    (bindings, digits)
}

/// The `ab` bridge stage's layout: the generator index each of its
/// values lands on, read off the stage polynomial over placeholder
/// values.
pub(crate) fn ab_layout<C: ProfiledCycle<Profile = Standard>, K: Rank>()
-> Result<Vec<(usize, AbValue)>> {
    let wires = stage_wire_indices::<
        C::ScalarField,
        K,
        nested::stages::ab::Stage<C::HostCurve, K, Standard>,
    >(|out| {
        let mut wires = wires_of(&out.a)?;
        wires.extend(wires_of(&out.b)?);
        wires.extend(wires_of(&out.native_points_ab)?);
        Ok(wires)
    })?;
    let values = [
        AbValue::A(0),
        AbValue::A(1),
        AbValue::B(0),
        AbValue::B(1),
        AbValue::PointsAb(0),
        AbValue::PointsAb(1),
    ];
    let mut terms: Vec<(usize, AbValue)> = wires
        .into_iter()
        .map(wire_degree::<K>)
        .zip(values)
        .collect();
    // The blinding sits at the SYSTEM gate, before the stage's own gates.
    terms.push((blinding_degree::<K>(), AbValue::Alpha));
    Ok(terms)
}

/// The coefficient degree of a stage polynomial's blinding term:
/// [`StageExt::rx`](ragu_circuits::staging::StageExt::rx) puts it at the
/// SYSTEM gate alone, gate zero, whose $a$ wire `wire_degree` numbers
/// $2n - 1$.
fn blinding_degree<K: Rank>() -> usize {
    2 * K::n() - 1
}

/// The circuit-field side's schedule for a proof at rank `K`, cut for
/// chunk circuits at rank `R`.
pub(crate) fn native_schedule<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<Schedule> {
    native_schedule_with::<C, K, R, HEADER_SIZE>(Foreign::Degrees(digits_degrees::<
        C,
        Nested,
        K,
        R,
        HEADER_SIZE,
    >()?))
}

/// The circuit-field side's schedule for its sizes alone (see
/// [`Foreign`]).
pub(crate) fn native_sizes<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<Schedule> {
    native_schedule_with::<C, K, R, HEADER_SIZE>(Foreign::Scalars(3 + AB_TERMS))
}

fn native_schedule_with<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>(
    foreign: Foreign,
) -> Result<Schedule> {
    type P<C> = <C as Cycle>::CircuitPoseidon;
    let layout = Layout::native::<C::CircuitField, K, HEADER_SIZE>();
    let mut b = Builder::new(
        layout,
        C::ScalarField::CAPACITY as usize + 1,
        foreign,
        Limits::at::<R>(),
    );
    let claims = native_claims()?;
    let nested_plans = nested_claims()?;
    let rounds = K::RANK as usize;
    let instance = layout.instance;
    let messages = layout.messages;
    let transcript = layout.transcript;
    let commitment = |p: usize| PointSrc::Instance(instance.commitments.at(p));
    let scalar = |i: usize| ElementSrc::Instance(instance.scalars.at(i));

    // The fuse's transcript.
    b.regions.fuse = b.slots.elements(challenge_stage::NUM + 1);
    {
        use nested::RxIndex::*;
        let mut ops = tag_ops(RAGU_TAG);
        let fuse = &b.regions.fuse;
        let squeeze = |ops: &mut Vec<Op>, i: usize| ops.push(Op::Squeeze(fuse[i]));
        let nested_bridge =
            |index| commitment(nested_position::<Standard>(nested::RxComponent::Rx(index)));
        absorb_point(&mut ops, nested_bridge(BridgePreamble));
        squeeze(&mut ops, 0);
        absorb_point(&mut ops, nested_bridge(BridgeSPrime));
        squeeze(&mut ops, 1);
        squeeze(&mut ops, 2);
        absorb_point(&mut ops, nested_bridge(BridgeInnerError));
        squeeze(&mut ops, 3);
        squeeze(&mut ops, 4);
        absorb_point(&mut ops, nested_bridge(BridgeOuterError));
        squeeze(&mut ops, 5);
        squeeze(&mut ops, 6);
        absorb_point(&mut ops, nested_bridge(BridgeAB));
        squeeze(&mut ops, 7);
        absorb_point(&mut ops, nested_bridge(BridgeQuery));
        squeeze(&mut ops, 8);
        absorb_point(&mut ops, nested_bridge(BridgeF));
        squeeze(&mut ops, 9);
        absorb_point(&mut ops, nested_bridge(BridgeEval));
        squeeze(&mut ops, 10);
        let chunks =
            transcript_chunks::<P<C>, C::CircuitField>(ops, &mut b.slots, b.limits.permutations);
        b.chunks.extend(chunks);
    }

    // The compression's transcript: the statement, both curves' sampled
    // challenges, then each curve's messages.
    let per_curve = challenges_per_curve::<K>();
    b.regions.squeezed = b.slots.elements(per_curve);
    b.regions.other_squeezed = b.slots.elements(per_curve);
    {
        let mut ops = tag_ops(IPA_TAG);
        ops.push(Op::Absorb(scalar(native_scalars::OMEGA_J)));
        ops.extend(
            instance
                .left_header
                .positions()
                .chain(instance.right_header.positions())
                .map(ElementSrc::Instance)
                .map(Op::Absorb),
        );
        for p in transcript.commitment_bridges.positions() {
            absorb_point(&mut ops, PointSrc::Bridge(p));
        }
        ops.extend(
            (native_scalars::C..=native_scalars::B_AT_U)
                .map(scalar)
                .map(Op::Absorb),
        );
        for p in instance.commitments.positions() {
            absorb_point(&mut ops, PointSrc::Instance(p));
        }
        for p in transcript.bridged.positions() {
            absorb_point(&mut ops, PointSrc::Bridge(p));
        }
        ops.extend(
            instance
                .output_header
                .positions()
                .map(ElementSrc::Instance)
                .map(Op::Absorb),
        );
        for i in 0..4 {
            ops.push(Op::Squeeze(b.regions.squeezed[i]));
        }
        for i in 0..4 {
            ops.push(Op::Squeeze(b.regions.other_squeezed[i]));
        }
        let side_ops = |ops: &mut Vec<Op>,
                        squeezed: &[usize],
                        point: &dyn Fn(usize) -> PointSrc,
                        scalar: &dyn Fn(&mut Vec<Op>, usize)| {
            use squeezed::*;

            use super::stages::message_points::*;
            absorb_point(ops, point(INNER));
            ops.push(Op::Squeeze(squeezed[MU]));
            ops.push(Op::Squeeze(squeezed[NU]));
            absorb_point(ops, point(OUTER));
            ops.push(Op::Squeeze(squeezed[MU_PRIME]));
            ops.push(Op::Squeeze(squeezed[NU_PRIME]));
            scalar(ops, 0);
            scalar(ops, 1);
            ops.push(Op::Squeeze(squeezed[RHO]));
            absorb_point(ops, point(P));
            absorb_point(ops, point(Q));
            ops.push(Op::Squeeze(squeezed[R]));
            for i in 2..2 + Derived::ALL.len() + 2 {
                scalar(ops, i);
            }
            ops.push(Op::Squeeze(squeezed[ALPHA]));
            absorb_point(ops, point(F));
            ops.push(Op::Squeeze(squeezed[U]));
            let evaluations = 4 + Derived::ALL.len();
            for i in evaluations..evaluations + Derived::ALL.len() + 2 + OPENED {
                scalar(ops, i);
            }
            ops.push(Op::Squeeze(squeezed[BETA]));
            absorb_point(ops, point(S_COMMITMENT));
            ops.push(Op::Squeeze(squeezed[XI]));
            ops.push(Op::Squeeze(squeezed[IPA_Z]));
            for j in 0..rounds {
                absorb_point(ops, point(l(j)));
                absorb_point(ops, point(r(j)));
                ops.push(Op::Squeeze(squeezed[ROUNDS + j]));
            }
            scalar(ops, MESSAGE_SCALARS - 1);
        };
        side_ops(
            &mut ops,
            &b.regions.squeezed,
            &|i| PointSrc::Bridge(transcript.point_bridges.at(i)),
            &|ops, i| ops.push(Op::Absorb(ElementSrc::Message(messages.scalars.at(i)))),
        );
        side_ops(
            &mut ops,
            &b.regions.other_squeezed,
            &|i| PointSrc::Message(messages.points_of_curve.at(i)),
            &|ops, i| absorb_point(ops, PointSrc::Bridge(transcript.scalar_bridges.at(i))),
        );
        let chunks =
            transcript_chunks::<P<C>, C::CircuitField>(ops, &mut b.slots, b.limits.permutations);
        b.chunks.extend(chunks);
    }

    // The bridges summed by the stage of the scalar-field side they commit
    // to: the instance stage's, the host commitments' and the scalar
    // field's instance values', then the messages stage's, the host point
    // messages' and the scalar field's message values'.
    b.regions.bridge_sums = [b.slots.point(), b.slots.point()];
    for (out, spans) in [
        (
            b.regions.bridge_sums[0],
            [transcript.commitment_bridges, transcript.bridged],
        ),
        (
            b.regions.bridge_sums[1],
            [transcript.point_bridges, transcript.scalar_bridges],
        ),
    ] {
        let terms: Vec<PointSrc> = spans
            .into_iter()
            .flat_map(|span| span.positions())
            .map(PointSrc::Bridge)
            .collect();
        b.chunks.push(Chunk::Sums {
            sums: vec![(out, terms)],
        });
    }

    // The lifts of the host curve's challenges, whose reduction this side
    // checks.
    b.regions.lifts = b.slots.lifts(per_curve);
    for batch in (0..per_curve).collect::<Vec<_>>().chunks(b.limits.lifts) {
        b.chunks.push(Chunk::Lift {
            pairs: batch
                .iter()
                .map(|&i| (ChallengeRef::Raw(b.regions.squeezed[i]), b.regions.lifts[i]))
                .collect(),
        });
    }
    b.regions.opening = vec![
        ElementSrc::Work(b.regions.fuse[fuse::U]),
        scalar(native_scalars::V),
        scalar(native_scalars::A_AT_U),
        scalar(native_scalars::B_AT_U),
    ];

    // The wire bindings: the preamble's children from the instance, the
    // query's values from the registry, the eval's from the registry
    // around a(u) and b(u), and the points stages' from the nested
    // commitments' coordinates.
    let degrees = native_binding_degrees::<C, K, HEADER_SIZE>()?;
    let ab_a = commitment(nested_position::<Standard>(nested::RxComponent::AbA));
    let ab_b = commitment(nested_position::<Standard>(nested::RxComponent::AbB));
    let registry_xy = commitment(nested_components::<Standard>().count());
    let bindings = {
        let [preamble, query, eval, points_ab, points_f] = degrees;
        vec![
            (
                preamble,
                (native_scalars::LEFT_X..=native_scalars::RIGHT_ID)
                    .map(|i| Some(scalar(i)))
                    .collect(),
            ),
            (query.clone(), vec![None; query.len()]),
            (
                eval,
                vec![
                    None,
                    None,
                    None,
                    Some(scalar(native_scalars::A_AT_U)),
                    Some(scalar(native_scalars::B_AT_U)),
                    None,
                ],
            ),
            (
                points_ab,
                vec![
                    Some(ElementSrc::Coordinate(ab_a, 0)),
                    Some(ElementSrc::Coordinate(ab_a, 1)),
                    Some(ElementSrc::Coordinate(ab_b, 0)),
                    Some(ElementSrc::Coordinate(ab_b, 1)),
                ],
            ),
            (
                points_f,
                vec![
                    Some(ElementSrc::Coordinate(registry_xy, 0)),
                    Some(ElementSrc::Coordinate(registry_xy, 1)),
                ],
            ),
        ]
    };

    let other_squeezed = b.regions.other_squeezed.clone();
    let (bindings, digits) = body::<K>(
        &mut b,
        Body {
            scalar_claims: &claims,
            targets: 3,
            bindings,
            extra_digits: Vec::new(),
            point_claims: &nested_plans,
            point_challenge: &|i| ChallengeRef::Raw(other_squeezed[i]),
            components: nested_components::<Standard>().count(),
            ab: [
                nested_position::<Standard>(nested::RxComponent::AbA),
                nested_position::<Standard>(nested::RxComponent::AbB),
            ],
        },
    );

    // The challenge stage: each challenge's lift times its generator, the
    // base-case sign's term, and pre_beta's.
    b.regions.challenge_stage = b.slots.point();
    {
        let sign = b.slots.point();
        b.chunks.push(Chunk::Sign {
            generator: generator_index::<C, K>(challenge_stage::SIGN_INDEX),
            out: sign,
        });
        let fuse_slots = b.regions.fuse.clone();
        let mut terms: Vec<(PointSrc, Option<ChallengeRef>)> = (1..challenge_stage::NUM)
            .map(|i| {
                (
                    PointSrc::Generator(generator_index::<C, K>(i)),
                    Some(ChallengeRef::Raw(fuse_slots[i])),
                )
            })
            .collect();
        terms.push((PointSrc::Work(sign), None));
        terms.push((
            PointSrc::Generator(generator_index::<C, K>(challenge_stage::BETA_INDEX)),
            Some(ChallengeRef::Raw(fuse_slots[fuse::PRE_BETA])),
        ));
        // A chain cannot start from a scaling, so the first challenge's
        // term is its own chunk's output.
        let first = b.slots.point();
        b.chunks.push(Chunk::Chain(ChainChunk {
            init: None,
            steps: vec![Step::AddScaled {
                point: PointSrc::Generator(generator_index::<C, K>(0)),
                scale_by: Some(ChallengeRef::Raw(fuse_slots[0])),
            }],
            out: first,
        }));
        let out = b.regions.challenge_stage;
        b.sum(PointSrc::Work(first), &terms, out);
        b.chunks.push(Chunk::Equal {
            left: PointSrc::Work(out),
            right: commitment(nested_position::<Standard>(nested::RxComponent::Rx(
                nested::RxIndex::ChallengeStage,
            ))),
        });
    }

    // The ab bridge: its coefficients' digits times their generators.
    let ab_terms = ab_layout::<C, K>()?;
    b.regions.ab_bridge = b.slots.point();
    {
        let scaled = b.slots.points(ab_terms.len());
        for (k, &(index, _)) in ab_terms.iter().enumerate() {
            b.scale(
                PointSrc::Generator(index),
                ScalarRef::Bits(3 + k),
                PointSrc::U,
                scaled[k],
            );
        }
        let terms: Vec<(PointSrc, Option<ChallengeRef>)> = scaled[1..]
            .iter()
            .map(|&slot| (PointSrc::Work(slot), None))
            .collect();
        let out = b.regions.ab_bridge;
        b.sum(PointSrc::Work(scaled[0]), &terms, out);
        b.chunks.push(Chunk::Equal {
            left: PointSrc::Work(out),
            right: commitment(nested_position::<Standard>(nested::RxComponent::Rx(
                nested::RxIndex::BridgeAB,
            ))),
        });
    }

    // The scalar-field side's lifts stage: each lift's generator scaled
    // by the challenge's bits, in the stage's order, the nested curve's
    // compression challenges, the fuse's x, y and u, then the host
    // curve's.
    b.regions.lifts_sum = b.slots.point();
    {
        let generators = lifts_degrees::<C, Nested, K, R, HEADER_SIZE>()?;
        let raw: Vec<usize> = b
            .regions
            .other_squeezed
            .clone()
            .into_iter()
            .chain([fuse::X, fuse::Y, fuse::U].map(|i| b.regions.fuse[i]))
            .chain(b.regions.squeezed.clone())
            .collect();
        assert_eq!(generators.len(), raw.len(), "one lift per challenge");
        let mut terms: Vec<(PointSrc, Option<ChallengeRef>)> = generators
            .iter()
            .zip(&raw)
            .map(|(&generator, &slot)| {
                (
                    PointSrc::Generator(generator),
                    Some(ChallengeRef::Raw(slot)),
                )
            })
            .collect();
        // A chain cannot start from a scaling, so the first lift's term is
        // its own chunk's output.
        let (point, scale_by) = terms.remove(0);
        let first = b.slots.point();
        b.chunks.push(Chunk::Chain(ChainChunk {
            init: None,
            steps: vec![Step::AddScaled { point, scale_by }],
            out: first,
        }));
        let out = b.regions.lifts_sum;
        b.sum(PointSrc::Work(first), &terms, out);
    }

    // The scalar-field side's digits stage, from the scalings' parts, and
    // this side's digits for it, last of all.
    b.digits_sum();
    b.regions.exposed = vec![
        b.regions.bridge_sums[0],
        b.regions.bridge_sums[1],
        b.regions.lifts_sum,
        b.regions.digits_sum,
    ];
    b.digits(digits);

    Ok(b.finish(claims, bindings, ab_terms))
}

/// The scalar-field side's schedule for a proof at rank `K`, cut for
/// chunk circuits at rank `R`.
pub(crate) fn nested_schedule<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<Schedule> {
    nested_schedule_with::<C, K, R, HEADER_SIZE>(Foreign::Degrees(digits_degrees::<
        C,
        Native,
        K,
        R,
        HEADER_SIZE,
    >()?))
}

/// The scalar-field side's schedule for its sizes alone (see
/// [`Foreign`]).
pub(crate) fn nested_sizes<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<Schedule> {
    nested_schedule_with::<C, K, R, HEADER_SIZE>(Foreign::Scalars(3))
}

fn nested_schedule_with<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>(
    foreign: Foreign,
) -> Result<Schedule> {
    let layout = Layout::nested::<C::ScalarField, Standard, K>();
    let mut b = Builder::new(
        layout,
        C::CircuitField::CAPACITY as usize + 1,
        foreign,
        Limits::at::<R>(),
    );
    let claims = nested_claims()?;
    let native_plans = native_claims()?;
    let per_curve = challenges_per_curve::<K>();
    let instance = layout.instance;
    let commitment = |p: usize| PointSrc::Instance(instance.commitments.at(p));
    let scalar = |i: usize| ElementSrc::Instance(instance.scalars.at(i));

    // The lifts: the nested curve's compression challenges, the fuse's x,
    // y and u and the host curve's compression challenges, all squeezed on
    // the other side, from their bits, into the lifts stage in that order,
    // which the other side recomputes.
    b.regions.lifts = b.slots.lifts(per_curve);
    b.regions.fuse_lifts = b.slots.lifts(3);
    b.regions.point_lifts = b.slots.lifts(per_curve);
    {
        let pairs: Vec<(ChallengeRef, usize)> = (0..per_curve)
            .map(|i| (ChallengeRef::Bits(i), b.regions.lifts[i]))
            .chain((0..3).map(|i| (ChallengeRef::Bits(per_curve + i), b.regions.fuse_lifts[i])))
            .chain((0..per_curve).map(|i| {
                (
                    ChallengeRef::Bits(per_curve + 3 + i),
                    b.regions.point_lifts[i],
                )
            }))
            .collect();
        for batch in pairs.chunks(b.limits.lifts) {
            b.chunks.push(Chunk::Lift {
                pairs: batch.to_vec(),
            });
        }
    }
    b.regions.opening = vec![
        ElementSrc::Lift(b.regions.fuse_lifts[2]),
        scalar(nested_scalars::V),
        scalar(nested_scalars::A_AT_U),
        scalar(nested_scalars::B_AT_U),
    ];

    // The wire bindings on the nested side.
    let degrees = nested_binding_degrees::<C, K>()?;
    let bindings = {
        let [preamble, query, eval] = degrees;
        vec![
            (
                preamble,
                (nested_scalars::LEFT_X..=nested_scalars::RIGHT_Y)
                    .map(|i| Some(scalar(i)))
                    .collect(),
            ),
            (query.clone(), vec![None; query.len()]),
            (
                eval,
                vec![
                    None,
                    None,
                    None,
                    Some(scalar(nested_scalars::A_AT_U)),
                    Some(scalar(nested_scalars::B_AT_U)),
                    None,
                ],
            ),
        ]
    };

    // The ab bridge's values, whose digits the other side scales by: the
    // coordinates of the host curve's A, B and points-ab commitments and
    // the blinding, bridge_alpha squared.
    let ab_terms = ab_layout::<C, K>()?;
    let extra_digits = {
        let ab_a = commitment(native_position::<Standard>(native::RxComponent::AbA));
        let ab_b = commitment(native_position::<Standard>(native::RxComponent::AbB));
        let points_ab = commitment(native_position::<Standard>(native::RxComponent::Rx(
            native::RxIndex::PointsAb,
        )));
        ab_terms
            .iter()
            .map(|&(_, which)| match which {
                AbValue::A(i) => ElementSrc::Coordinate(ab_a, i as u8),
                AbValue::B(i) => ElementSrc::Coordinate(ab_b, i as u8),
                AbValue::PointsAb(i) => ElementSrc::Coordinate(points_ab, i as u8),
                AbValue::Alpha => {
                    ElementSrc::InstanceSquared(instance.scalars.at(nested_scalars::BRIDGE_ALPHA))
                }
            })
            .collect()
    };

    let (bindings, digits) = body::<K>(
        &mut b,
        Body {
            scalar_claims: &claims,
            targets: 1,
            bindings,
            extra_digits,
            point_claims: &native_plans,
            point_challenge: &|i| ChallengeRef::Bits(per_curve + 3 + i),
            components: native_components::<Standard>().count(),
            ab: [
                native_position::<Standard>(native::RxComponent::AbA),
                native_position::<Standard>(native::RxComponent::AbB),
            ],
        },
    );

    // The circuit-field side's digits stage, from the scalings' parts, and
    // this side's digits for it, last of all.
    b.digits_sum();
    b.regions.exposed = vec![b.regions.digits_sum];
    assert_eq!(
        digits.len(),
        3 + AB_TERMS,
        "the ab bridge's terms are pinned"
    );
    b.digits(digits);

    Ok(b.finish(claims, bindings, ab_terms))
}

/// The number of chunks of each side for a proof at rank `K` in chunk
/// circuits at rank `R`.
pub(crate) fn chunk_counts<
    C: IpaCycle + ProfiledCycle<Profile = Standard>,
    K: Rank,
    R: Rank,
    const HEADER_SIZE: usize,
>() -> Result<(usize, usize)> {
    Ok((
        native_schedule::<C, K, R, HEADER_SIZE>()?.chunks.len(),
        nested_schedule::<C, K, R, HEADER_SIZE>()?.chunks.len(),
    ))
}

#[cfg(test)]
#[path = "../../tests/decompress_program.rs"]
mod tests;
