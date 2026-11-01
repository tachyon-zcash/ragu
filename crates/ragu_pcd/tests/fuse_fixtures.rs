//! Golden fixtures for the fuse pipeline and the compressed verifier.
//!
//! The fixtures under `tests/fixtures/fuse/` pin selected executions of
//! [`Application::fuse`] and [`Application::verify_compressed`]. Changes to
//! those executions fail the `fuse fixtures` CI job. They follow the
//! golden-proof harness of zakura-common's `sensei`
//! crate: the prover replays a committed randomness tape and must reproduce
//! the committed proof byte for byte, consuming exactly the tape.
//!
//! The verifier side follows zakura-common's Halo2 and Orchard verifier
//! fingerprints: the verifier runs on each committed proof under a recorder
//! (see [`crate::ipa::fingerprint`]), and its transcript schedule and final
//! MSMs must match the committed record, so a change to how it reads a proof
//! shows even when its verdict does not. Tampered copies must be rejected,
//! and at the check they should fail.
//!
//! Each scenario is one proof in a fixed tree of fuses, with four files:
//!
//! - `<scenario>.rng-u64s-le`: the randomness the fuse drew, as little-endian
//!   `u64` words. Checking replays it and fails if the prover asks for more
//!   or leaves any unused, so the randomness schedule is pinned along with
//!   the output.
//! - `<scenario>.proof`: the header data and the compressed proof, in the
//!   test-local encoding below. The prover must reproduce these bytes, and
//!   the verifier must accept them as committed, without re-proving. The
//!   encoding is a fixture format, not a wire format. Compression draws a
//!   megabyte of blinding per proof, too much to commit as a tape, so its
//!   randomness comes from the frozen generator under a fixed seed and is
//!   pinned by its word count and by these bytes.
//! - `<scenario>.digests`: one BLAKE2b-256 digest per primary field of the
//!   uncompressed [`Proof`] the fuse produced, in declaration order, then the
//!   word counts the fuse and the compression drew and the `.proof` file's
//!   length. The uncompressed proof is over ten megabytes at production
//!   rank, so this stands in for committing it: a mismatch names the fields
//!   that drifted, and the file's diff in a pull request reads as the list
//!   of stages the change touched. The `wire.*` lines then pin the wire
//!   format (see `crate::wire`): the codec's field order, the length and
//!   digest of the proof's and the compressed proof's payload bytes. A change
//!   to the proof's fields, their order, a codec
//!   or an element's spelling fails them until the fixtures are regenerated
//!   and the schema version bumped.
//! - `<scenario>.fingerprint`: the verifier's run on the `.proof`: digests of
//!   what its transcript absorbed and squeezed, with counts, and of each
//!   curve's final IPA MSM, every scalar and proof-dependent base.
//!
//! After an intended change, regenerate with
//!
//! ```console
//! RAGU_FIXTURES=write cargo test --release -p ragu_pcd --all-features --lib proof::fuse_fixture_tests
//! ```
//!
//! and review the diff: it should name exactly the stages the change was
//! meant to touch.
//!
//! Every scenario runs once per profile, the wallet's [`Standard`] and the
//! [`Aggregator`]. Both currently produce identical proofs, so they check
//! the same fixtures in `standard/`. Only the standard prover writes them
//! when regenerating.
//!
//! [`Standard`]: crate::profile::Standard
//!
//! The steps are the fixtures' own: `ragu_testing`'s implement the `Step` of
//! the dev-dependency copy of this crate and cannot be registered from inside
//! it, and borrowing another suite's would let an edit there churn these
//! fixtures. Like sensei's harness, this one shares no code with the tests
//! around it.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{convert::Infallible, marker::PhantomData};
use std::{fs, path::PathBuf};

use blake2b_simd::{Params, State};
use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{ProductionRank, Rank, sparse},
    registry::CircuitIndex,
};
use ragu_core::{
    Cycle, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{Fp, Pasta, PastaParams},
};
use ragu_primitives::{
    Element,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};
use rand::{TryCryptoRng, TryRng};
use udon::{curve::Affine, field::Field};

use super::Proof;
use crate::{
    Application, ApplicationBuilder, CompressedProof, Pcd,
    compress::{
        Messages,
        batch::Batch,
        instance::{Child, Instance, NestedChild},
        revdot::{Reduction, fold::Fold},
    },
    header::{Header, Suffix},
    ipa::{
        IpaCycle, IpaProof,
        fingerprint::{self, Event},
    },
    profile::{Aggregator, Profile, Profiled, ProfiledCycle},
    step::{Encoded, Index, Step, internal::bootstrap::Bootstrap},
};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;
type App<C> = Application<'static, C, R, HEADER_SIZE>;
type TestPcd<C> = Pcd<C, R, Value>;

/// A profile of the Pasta cycle the fixtures prove in.
trait FixtureCycle: IpaCycle + ProfiledCycle + Cycle<CircuitField = Fp, Params = PastaParams> {
    /// The fixtures' application: their four steps at production rank, on
    /// the baked parameters.
    fn app() -> App<Self>;
}

impl<C> FixtureCycle for C
where
    C: IpaCycle + ProfiledCycle + Cycle<CircuitField = Fp, Params = PastaParams>,
    <C::Profile as Profile>::Context<'static, C::Base, R, ReferenceBackend>: Default,
{
    fn app() -> App<C> {
        ApplicationBuilder::<C, R, HEADER_SIZE>::new()
            .register(Seed::new())
            .and_then(|b| b.register(Merge::new()))
            .and_then(|b| b.register(UnitLeft::new()))
            .and_then(|b| b.register(UnitRight::new()))
            .and_then(|b| b.finalize(crate::pasta::baked()))
            .expect("the application must build")
    }
}

/// The fixtures' header: one field element.
struct Value;

impl Header<Fp> for Value {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

/// Hashes both child headers and a salt into a [`Value`].
struct HashStep<L, H, const I: usize>(PhantomData<(L, H)>);

impl<L, H, const I: usize> HashStep<L, H, I> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Cy, L: Header<Fp>, H: Header<Fp>, const I: usize> Step<Cy> for HashStep<L, H, I>
where
    Cy: Cycle<CircuitField = Fp, Params = PastaParams>,
{
    const INDEX: Index = Index::new(I);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = L;
    type Right = H;
    type Output = Value;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Fp>,
        left: DriverValue<D, L::Data>,
        right: DriverValue<D, H::Data>,
    ) -> Result<(
        (
            Encoded<'dr, D, L, N>,
            Encoded<'dr, D, H, N>,
            Encoded<'dr, D, Value, N>,
        ),
        DriverValue<D, Fp>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let salt = Element::alloc(dr, allocator, witness)?;
        let mut sponge = Sponge::new(dr, Cy::circuit_poseidon(crate::pasta::baked()));
        let mut inputs = Vec::new();
        left.clone().write(dr, &mut inputs)?;
        right.clone().write(dr, &mut inputs)?;
        for input in inputs {
            sponge.absorb(dr, &input)?;
        }
        sponge.absorb(dr, &salt)?;
        let output = sponge.squeeze(dr)?;
        let data = output.value().map(|v| *v);
        Ok(((left, right, Encoded::from_gadget(output)), data, D::unit()))
    }
}

/// A seed: hashes two base-case children and a salt.
type Seed = HashStep<(), (), 0>;
/// Hashes two [`Value`] children and a salt.
type Merge = HashStep<Value, Value, 1>;
/// Hashes a base-case left child, a [`Value`] right child and a salt.
type UnitLeft = HashStep<(), Value, 2>;
/// Registered so the application has the support suite's shape; no
/// scenario fuses with it.
type UnitRight = HashStep<Value, (), 3>;

/// The command that rewrites the fixtures from the current prover.
const REGENERATE: &str = "RAGU_FIXTURES=write cargo test --release -p ragu_pcd --all-features --lib proof::fuse_fixture_tests";

/// The first bytes of every `.proof` file.
const MAGIC: &[u8; 8] = b"ragufx01";

/// The scenarios: a fixed tree of fuses over the fixtures' steps.
///
/// ```text
///                     rerandomize
///                          |
///                      merge_abcd
///                      /        \
///               merge_ab        merge_cd
///               /      \        /      \
///           seed_a  seed_b  seed_c  seed_d
///                  (each over the bootstrap proof)
/// ```
///
/// The `bootstrap` fixture is the base case every seed fuses as both
/// children; `unit_left` fuses it beside a seed as a `()`-header child.
/// Only `seed_a` and `merge_ab` have snapshots at their respective depths;
/// their siblings are deterministic inputs to the retained parent fixtures.
const BOOTSTRAP: &str = "bootstrap";
const SEED_A: &str = "seed_a";
const MERGE_AB: &str = "merge_ab";
const MERGE_ABCD: &str = "merge_abcd";
const UNIT_LEFT: &str = "unit_left";
const RERANDOMIZE: &str = "rerandomize";

/// The seed a scenario's tape is recorded from: a fixed prefix over a small
/// tag, so the seeds are recognizable and never collide. Retained fixtures
/// replay their committed tapes; their sibling inputs use this seed directly.
const fn seed(tag: u64) -> u64 {
    0x5241_4755_4658_0000 | tag
}

/// A prover's randomness as a tape of `u64` words, in the manner of sensei's
/// `.rng-u64s-le` goldens.
///
/// Checking a snapshot replays the committed tape and fails when the prover
/// asks for a word it does not hold; regenerating appends words from SplitMix64
/// as they are drawn and writes the result. Sibling inputs also use this
/// generator, without writing a tape. Either way `fill_bytes` takes whole
/// words, so a request's word count is fixed by its length, and the number
/// of words consumed pins the randomness schedule.
///
/// The generator is not cryptographically secure and must never produce a
/// real proof. It serves here only because the fixtures are synthetic test
/// data whose one requirement is a reproducible, platform-independent
/// stream that no dependency version can change: `StdRng` is pinned by
/// `Cargo.lock` but not by `rand`'s API. Changing it changes every tape
/// regenerated afterwards, and the sibling inputs to the retained parents.
struct Tape {
    words: Vec<u64>,
    cursor: usize,
    /// The generator state the next recorded word comes from, when
    /// recording.
    generator: Option<u64>,
}

impl Tape {
    fn replay(bytes: &[u8]) -> Self {
        assert!(
            bytes.len().is_multiple_of(8),
            "a tape is a whole number of little-endian u64 words"
        );
        Self {
            words: bytes
                .chunks_exact(8)
                .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
                .collect(),
            cursor: 0,
            generator: None,
        }
    }

    fn record(seed: u64) -> Self {
        Self {
            words: Vec::new(),
            cursor: 0,
            generator: Some(seed),
        }
    }

    fn consumed(&self) -> usize {
        self.cursor
    }

    fn unused(&self) -> usize {
        self.words.len() - self.cursor
    }

    fn bytes(&self) -> Vec<u8> {
        self.words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
    }

    fn word(&mut self) -> u64 {
        if self.cursor == self.words.len() {
            let state = self.generator.as_mut().unwrap_or_else(|| {
                panic!(
                    "the prover drew more randomness than the fixture's tape holds\nregenerate with\n    {REGENERATE}"
                )
            });
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut word = *state;
            word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            self.words.push(word ^ (word >> 31));
        }
        let word = self.words[self.cursor];
        self.cursor += 1;
        word
    }
}

impl TryRng for Tape {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        Ok(self.word() as u32)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        Ok(self.word())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.word().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Tape {}

/// A BLAKE2b-256 digest of canonical bytes.
struct Digest(State);

impl Digest {
    fn new() -> Self {
        Self(Params::new().hash_length(32).to_state())
    }

    fn u64(&mut self, value: u64) {
        self.0.update(&value.to_le_bytes());
    }

    fn field<F: Field>(&mut self, value: &F) {
        self.0.update(value.to_bytes().as_ref());
    }

    fn point<P: Affine>(&mut self, value: &P) {
        self.0.update(value.to_bytes().as_ref());
    }

    fn fields<F: Field>(&mut self, values: &[F]) {
        self.u64(values.len() as u64);
        for value in values {
            self.field(value);
        }
    }

    /// Every coefficient in degree order, zeros included, so the digest is
    /// of the polynomial and not of its sparse storage.
    fn poly<F: Field, K: Rank>(&mut self, poly: &sparse::Polynomial<F, K>) {
        self.u64(K::num_coeffs() as u64);
        for coeff in poly.iter_coeffs() {
            self.field(&coeff);
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        self.0.update(bytes);
    }

    fn tagged(&mut self, tag: u8, bytes: &[u8]) {
        self.0.update(&[tag]);
        self.bytes(bytes);
    }

    fn hex(self) -> String {
        self.0
            .finalize()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn digest(write: impl FnOnce(&mut Digest)) -> String {
    let mut digest = Digest::new();
    write(&mut digest);
    digest.hex()
}

/// The `key = value` lines of a `.digests` file, in order.
#[derive(Default)]
struct Lines(Vec<(String, String)>);

impl Lines {
    fn push(&mut self, key: impl Into<String>, value: impl ToString) {
        self.0.push((key.into(), value.to_string()));
    }

    fn field<F: Field>(&mut self, key: &str, value: &F) {
        self.push(key, digest(|d| d.field(value)));
    }

    fn fields<F: Field>(&mut self, key: &str, values: &[F]) {
        self.push(key, digest(|d| d.fields(values)));
    }

    fn point<P: Affine>(&mut self, key: &str, value: &P) {
        self.push(key, digest(|d| d.point(value)));
    }

    fn poly<F: Field, K: Rank>(&mut self, key: &str, poly: &sparse::Polynomial<F, K>) {
        self.push(key, digest(|d| d.poly(poly)));
    }

    fn polys<F: Field, K: Rank>(&mut self, key: &str, polys: &[sparse::Polynomial<F, K>]) {
        for (i, poly) in polys.iter().enumerate() {
            self.poly(&format!("{key}[{i}]"), poly);
        }
    }

    fn render(&self) -> String {
        let mut text = String::new();
        for (key, value) in &self.0 {
            text.push_str(key);
            text.push_str(" = ");
            text.push_str(value);
            text.push('\n');
        }
        text
    }

    fn parse(text: &str) -> Self {
        Self(
            text.lines()
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let (key, value) = line
                        .split_once(" = ")
                        .expect("a fixture line is `key = value`");
                    (key.into(), value.into())
                })
                .collect(),
        )
    }
}

/// The digests of a proof's primary fields, in declaration order.
///
/// The destructuring is exhaustive: a field added to [`Proof`] does not
/// compile here until the fixture decides whether to pin it. The cached
/// commitments are derived from the polynomials they commit, and the bridge
/// `ab` polynomial from the commitments it carries, so they are not pinned
/// separately.
fn proof_lines<C: Cycle>(proof: &Proof<C, R>, lines: &mut Lines) {
    let Proof {
        bridge_alpha,
        circuit_id,
        left_header,
        right_header,
        native_application_rx,
        native_preamble_rx,
        native_inner_error_rx,
        native_outer_error_rx,
        native_a_poly,
        native_b_poly,
        native_query_rx,
        native_registry_xy_poly,
        native_eval_rx,
        native_p_poly,
        native_hashes_1_rx,
        native_hashes_2_rx,
        native_collapse_rx,
        native_compute_v_rx,
        native_bind_challenges_rxs,
        native_bind_beta_rx,
        native_bind_endoscalar_rx,
        native_endoscaling_step_rxs,
        native_extension_circuit_rxs,
        native_extension_stage_rxs,
        native_points_binding_rx,
        native_points_children_rx,
        native_points_registry_wx_rx,
        native_points_ab_rx,
        native_points_f_rx,
        native_points_walk_rx,
        bridge_preamble_rx,
        bridge_s_prime_rx,
        bridge_inner_error_rx,
        bridge_outer_error_rx,
        bridge_query_rx,
        bridge_f_rx,
        bridge_eval_rx,
        bridge_ab_rx: _,
        nested_endoscaling_step_rxs,
        nested_extension_circuit_rxs,
        nested_extension_stage_rxs,
        nested_endoscalar_rx,
        nested_points_rx,
        nested_a_poly,
        nested_b_poly,
        nested_registry_xy_poly,
        nested_p_poly,
        nested_challenges_rx,
        nested_challenges_partial,
        nested_collapse_rx,
        nested_compute_v_rx,
        nested_endoscaling_step_commitments: _,
        nested_extension_circuit_commitments: _,
        nested_extension_stage_commitments: _,
        nested_endoscalar_commitment: _,
        nested_points_commitment: _,
        nested_a_commitment: _,
        nested_b_commitment: _,
        nested_registry_xy_commitment: _,
        nested_p_commitment: _,
        nested_challenges_commitment: _,
        nested_collapse_commitment: _,
        nested_compute_v_commitment: _,
        w,
        y,
        z,
        mu,
        mu_prime,
        x,
        alpha,
        u,
        pre_beta,
        native_application_commitment: _,
        native_preamble_commitment: _,
        native_inner_error_commitment: _,
        native_outer_error_commitment: _,
        native_a_commitment: _,
        native_b_commitment: _,
        native_query_commitment: _,
        native_registry_xy_commitment: _,
        native_eval_commitment: _,
        native_p_commitment: _,
        native_hashes_1_commitment: _,
        native_hashes_2_commitment: _,
        native_collapse_commitment: _,
        native_compute_v_commitment: _,
        native_bind_challenges_commitments: _,
        native_bind_beta_commitment: _,
        native_bind_endoscalar_commitment: _,
        native_endoscaling_step_commitments: _,
        native_extension_circuit_commitments: _,
        native_extension_stage_commitments: _,
        native_points_binding_commitment: _,
        native_points_children_commitment: _,
        native_points_registry_wx_commitment: _,
        native_points_ab_commitment: _,
        native_points_f_commitment: _,
        native_points_walk_commitment: _,
        bridge_preamble_commitment: _,
        bridge_s_prime_commitment: _,
        bridge_inner_error_commitment: _,
        bridge_outer_error_commitment: _,
        bridge_query_commitment: _,
        bridge_f_commitment: _,
        bridge_eval_commitment: _,
        bridge_ab_commitment: _,
    } = proof;

    lines.push("circuit_id", usize::from(*circuit_id));
    lines.fields("left_header", left_header);
    lines.fields("right_header", right_header);
    lines.field("bridge_alpha", bridge_alpha);

    lines.poly("native_application_rx", native_application_rx);
    lines.poly("native_preamble_rx", native_preamble_rx);
    lines.poly("native_inner_error_rx", native_inner_error_rx);
    lines.poly("native_outer_error_rx", native_outer_error_rx);
    lines.poly("native_a_poly", native_a_poly);
    lines.poly("native_b_poly", native_b_poly);
    lines.poly("native_query_rx", native_query_rx);
    lines.poly("native_registry_xy_poly", native_registry_xy_poly);
    lines.poly("native_eval_rx", native_eval_rx);
    lines.poly("native_p_poly", native_p_poly);
    lines.poly("native_hashes_1_rx", native_hashes_1_rx);
    lines.poly("native_hashes_2_rx", native_hashes_2_rx);
    lines.poly("native_collapse_rx", native_collapse_rx);
    lines.poly("native_compute_v_rx", native_compute_v_rx);
    lines.polys("native_bind_challenges_rxs", native_bind_challenges_rxs);
    lines.poly("native_bind_beta_rx", native_bind_beta_rx);
    lines.poly("native_bind_endoscalar_rx", native_bind_endoscalar_rx);
    lines.polys("native_endoscaling_step_rxs", native_endoscaling_step_rxs);
    lines.polys("native_extension_circuit_rxs", native_extension_circuit_rxs);
    lines.polys("native_extension_stage_rxs", native_extension_stage_rxs);
    lines.poly("native_points_binding_rx", native_points_binding_rx);
    lines.poly("native_points_children_rx", native_points_children_rx);
    lines.poly("native_points_registry_wx_rx", native_points_registry_wx_rx);
    lines.poly("native_points_ab_rx", native_points_ab_rx);
    lines.poly("native_points_f_rx", native_points_f_rx);
    lines.poly("native_points_walk_rx", native_points_walk_rx);

    lines.poly("bridge_preamble_rx", bridge_preamble_rx);
    lines.poly("bridge_s_prime_rx", bridge_s_prime_rx);
    lines.poly("bridge_inner_error_rx", bridge_inner_error_rx);
    lines.poly("bridge_outer_error_rx", bridge_outer_error_rx);
    lines.poly("bridge_query_rx", bridge_query_rx);
    lines.poly("bridge_f_rx", bridge_f_rx);
    lines.poly("bridge_eval_rx", bridge_eval_rx);

    lines.polys("nested_endoscaling_step_rxs", nested_endoscaling_step_rxs);
    lines.polys("nested_extension_circuit_rxs", nested_extension_circuit_rxs);
    lines.polys("nested_extension_stage_rxs", nested_extension_stage_rxs);
    lines.poly("nested_endoscalar_rx", nested_endoscalar_rx);
    lines.poly("nested_points_rx", nested_points_rx);
    lines.poly("nested_a_poly", nested_a_poly);
    lines.poly("nested_b_poly", nested_b_poly);
    lines.poly("nested_registry_xy_poly", nested_registry_xy_poly);
    lines.poly("nested_p_poly", nested_p_poly);
    lines.poly("nested_challenges_rx", nested_challenges_rx);
    lines.point("nested_challenges_partial", nested_challenges_partial);
    lines.poly("nested_collapse_rx", nested_collapse_rx);
    lines.poly("nested_compute_v_rx", nested_compute_v_rx);

    lines.field("w", w);
    lines.field("y", y);
    lines.field("z", z);
    lines.field("mu", mu);
    lines.field("mu_prime", mu_prime);
    lines.field("x", x);
    lines.field("alpha", alpha);
    lines.field("u", u);
    lines.field("pre_beta", pre_beta);
}

/// Encoding of the header data a `.proof` file carries ahead of the proof.
trait FixtureHeader: Header<Fp> {
    fn write(data: &Self::Data, out: &mut Writer);
    fn read(cursor: &mut Cursor<'_>) -> Option<Self::Data>;
}

impl FixtureHeader for () {
    fn write(_: &(), _: &mut Writer) {}

    fn read(_: &mut Cursor<'_>) -> Option<()> {
        Some(())
    }
}

impl FixtureHeader for Value {
    fn write(data: &Fp, out: &mut Writer) {
        out.field(data);
    }

    fn read(cursor: &mut Cursor<'_>) -> Option<Fp> {
        cursor.field()
    }
}

/// Canonical fields and points, little-endian `u32` lengths.
#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn u32(&mut self, value: usize) {
        let value = u32::try_from(value).expect("fixture lengths fit in u32");
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn field<F: Field>(&mut self, value: &F) {
        self.0.extend_from_slice(value.to_bytes().as_ref());
    }

    fn point<P: Affine>(&mut self, value: &P) {
        self.0.extend_from_slice(value.to_bytes().as_ref());
    }

    fn fields<F: Field>(&mut self, values: &[F]) {
        self.u32(values.len());
        for value in values {
            self.field(value);
        }
    }

    fn points<P: Affine>(&mut self, values: &[P]) {
        self.u32(values.len());
        for value in values {
            self.point(value);
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let bytes = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }

    fn u32(&mut self) -> Option<usize> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
    }

    fn field<F: Field>(&mut self) -> Option<F> {
        let mut repr = F::ZERO.to_bytes();
        let len = repr.as_ref().len();
        repr.as_mut().copy_from_slice(self.take(len)?);
        F::from_bytes(repr)
    }

    fn point<P: Affine>(&mut self) -> Option<P> {
        let mut repr = P::identity().to_bytes();
        let len = repr.as_ref().len();
        repr.as_mut().copy_from_slice(self.take(len)?);
        P::from_bytes(repr)
    }

    fn fields<F: Field>(&mut self) -> Option<Vec<F>> {
        let len = self.u32()?;
        (0..len).map(|_| self.field()).collect()
    }

    fn points<P: Affine>(&mut self) -> Option<Vec<P>> {
        let len = self.u32()?;
        (0..len).map(|_| self.point()).collect()
    }
}

/// Encodes a compressed proof, exhaustively over its fields, so that a field
/// added to the instance or the messages does not compile here until the
/// fixtures account for it.
fn encode_compressed<C: Cycle>(proof: &CompressedProof<C>, out: &mut Writer) {
    let CompressedProof {
        instance,
        native,
        nested,
    } = proof;
    out.0.extend_from_slice(MAGIC);

    let Instance {
        circuit_id,
        left_header,
        right_header,
        native: native_commitments,
        native_registry_xy,
        native_p,
        nested: nested_commitments,
        nested_registry_xy,
        nested_p,
        nested_challenges_partial,
        bridge_alpha,
        c,
        v,
        nested_c,
        nested_v,
        left,
        right,
        a_at_u,
        b_at_u,
        nested_left,
        nested_right,
        nested_a_at_u,
        nested_b_at_u,
    } = instance;
    out.u32(usize::from(*circuit_id));
    out.fields(left_header);
    out.fields(right_header);
    out.points(native_commitments);
    out.point(native_registry_xy);
    out.point(native_p);
    out.points(nested_commitments);
    out.point(nested_registry_xy);
    out.point(nested_p);
    out.point(nested_challenges_partial);
    out.field(bridge_alpha);
    out.field(c);
    out.field(v);
    out.field(nested_c);
    out.field(nested_v);
    for Child { x, y, id } in [left, right] {
        out.field(x);
        out.field(y);
        out.field(id);
    }
    out.field(a_at_u);
    out.field(b_at_u);
    for NestedChild { x, y } in [nested_left, nested_right] {
        out.field(x);
        out.field(y);
    }
    out.field(nested_a_at_u);
    out.field(nested_b_at_u);

    encode_messages(native, out);
    encode_messages(nested, out);
}

fn encode_messages<P: Affine>(messages: &Messages<P>, out: &mut Writer) {
    let Messages {
        reduction,
        batch,
        opening,
    } = messages;
    let Reduction {
        fold,
        p,
        q,
        openings,
        p_at_inverse_r,
        q_at_r,
    } = reduction;
    let Fold {
        inner,
        outer,
        inner_epsilon,
        outer_epsilon,
    } = fold;
    out.point(inner);
    out.point(outer);
    out.field(inner_epsilon);
    out.field(outer_epsilon);
    out.point(p);
    out.point(q);
    out.fields(openings);
    out.field(p_at_inverse_r);
    out.field(q_at_r);

    let Batch { f, evaluations } = batch;
    out.point(f);
    out.fields(evaluations);

    let IpaProof {
        s_commitment,
        rounds,
        c,
    } = opening;
    out.point(s_commitment);
    out.u32(rounds.len());
    for (left, right) in rounds {
        out.point(left);
        out.point(right);
    }
    out.field(c);
}

fn decode_compressed<C: Cycle>(cursor: &mut Cursor<'_>) -> Option<CompressedProof<C>> {
    if cursor.take(MAGIC.len())? != MAGIC {
        return None;
    }
    let circuit_id = CircuitIndex::new(cursor.u32()?);
    let left_header = cursor.fields()?;
    let right_header = cursor.fields()?;
    let native_commitments = cursor.points()?;
    let native_registry_xy = cursor.point()?;
    let native_p = cursor.point()?;
    let nested_commitments = cursor.points()?;
    let nested_registry_xy = cursor.point()?;
    let nested_p = cursor.point()?;
    let nested_challenges_partial = cursor.point()?;
    let bridge_alpha = cursor.field()?;
    let c = cursor.field()?;
    let v = cursor.field()?;
    let nested_c = cursor.field()?;
    let nested_v = cursor.field()?;
    let mut child = || {
        Some(Child {
            x: cursor.field()?,
            y: cursor.field()?,
            id: cursor.field()?,
        })
    };
    let left = child()?;
    let right = child()?;
    let a_at_u = cursor.field()?;
    let b_at_u = cursor.field()?;
    let mut nested_child = || {
        Some(NestedChild {
            x: cursor.field()?,
            y: cursor.field()?,
        })
    };
    let nested_left = nested_child()?;
    let nested_right = nested_child()?;
    let nested_a_at_u = cursor.field()?;
    let nested_b_at_u = cursor.field()?;
    let instance = Instance {
        circuit_id,
        left_header,
        right_header,
        native: native_commitments,
        native_registry_xy,
        native_p,
        nested: nested_commitments,
        nested_registry_xy,
        nested_p,
        nested_challenges_partial,
        bridge_alpha,
        c,
        v,
        nested_c,
        nested_v,
        left,
        right,
        a_at_u,
        b_at_u,
        nested_left,
        nested_right,
        nested_a_at_u,
        nested_b_at_u,
    };
    let native = decode_messages(cursor)?;
    let nested = decode_messages(cursor)?;
    Some(CompressedProof {
        instance,
        native,
        nested,
    })
}

fn decode_messages<P: Affine>(cursor: &mut Cursor<'_>) -> Option<Messages<P>> {
    let fold = Fold {
        inner: cursor.point()?,
        outer: cursor.point()?,
        inner_epsilon: cursor.field()?,
        outer_epsilon: cursor.field()?,
    };
    let reduction = Reduction {
        fold,
        p: cursor.point()?,
        q: cursor.point()?,
        openings: cursor.fields()?,
        p_at_inverse_r: cursor.field()?,
        q_at_r: cursor.field()?,
    };
    let batch = Batch {
        f: cursor.point()?,
        evaluations: cursor.fields()?,
    };
    let s_commitment = cursor.point()?;
    let rounds = (0..cursor.u32()?)
        .map(|_| Some((cursor.point()?, cursor.point()?)))
        .collect::<Option<Vec<_>>>()?;
    let opening = IpaProof {
        s_commitment,
        rounds,
        c: cursor.field()?,
    };
    Some(Messages {
        reduction,
        batch,
        opening,
    })
}

fn writing() -> bool {
    std::env::var_os("RAGU_FIXTURES").is_some_and(|mode| mode == "write")
}

/// The shared fixture directory and the profile label failures carry.
struct Fixtures {
    dir: PathBuf,
    profile: &'static str,
}

impl Fixtures {
    fn of<C: ProfiledCycle>() -> Self {
        let profile = <C::Profile as Profile>::NAME;
        // Aggregator currently has the standard layout. Checking the same
        // snapshots guards that agreement without storing duplicate files.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fuse/standard");
        if writing() {
            fs::create_dir_all(&dir).expect("the fixture directory can be created");
        }
        Self { dir, profile }
    }

    fn label(&self, name: &str) -> String {
        format!("{}/{name}", self.profile)
    }

    fn path(&self, name: &str, extension: &str) -> PathBuf {
        self.dir.join(format!("{name}.{extension}"))
    }

    fn read(&self, name: &str, extension: &str) -> Vec<u8> {
        let path = self.path(name, extension);
        fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read fixture {}: {error}\nregenerate with\n    {REGENERATE}",
                path.display()
            )
        })
    }

    fn write(&self, name: &str, extension: &str, bytes: &[u8]) {
        fs::write(self.path(name, extension), bytes).expect("the fixture directory is writable");
    }

    /// The tape a scenario replays, or a fresh one when regenerating.
    fn tape(&self, name: &str, tag: u64) -> Tape {
        if writing() {
            Tape::record(seed(tag))
        } else {
            Tape::replay(&self.read(name, "rng-u64s-le"))
        }
    }
}

/// The mismatches between the reproduced digests and the committed ones,
/// one line each.
fn compare_lines(label: &str, actual: &Lines, committed: &Lines) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (key, value) in &actual.0 {
        match committed.0.iter().find(|(k, _)| k == key) {
            None => mismatches.push(format!("{label}: {key} is not in the fixture")),
            Some((_, expected)) if expected != value => {
                mismatches.push(format!("{label}: {key} changed"));
            }
            Some(_) => {}
        }
    }
    for (key, _) in &committed.0 {
        if !actual.0.iter().any(|(k, _)| k == key) {
            mismatches.push(format!("{label}: {key} is no longer produced"));
        }
    }
    mismatches
}

/// Checks one scenario after its fuse ran under `tape`: the tape is exactly
/// consumed, the uncompressed verifier accepts the proof, compressing it
/// under the fixed seed reproduces the committed `.proof` bytes, and the
/// digests match. When regenerating, writes the three files instead.
fn check<C: FixtureCycle, H: FixtureHeader>(
    app: &App<C>,
    fixtures: &Fixtures,
    name: &str,
    tag: u64,
    pcd: &Pcd<C, R, H>,
    tape: &Tape,
    failures: &mut Vec<String>,
) {
    let label = fixtures.label(name);
    let mut lines = Lines::default();
    proof_lines(pcd.proof(), &mut lines);

    // The verifier's randomness is not part of the fixture.
    let mut verifier = Tape::record(seed(0xff00));
    assert!(
        app.verify_uncompressed(pcd, &mut verifier)
            .expect("verification must not error"),
        "{label}: the uncompressed verifier rejected the reproduced proof"
    );

    let mut compress_rng = Tape::record(seed(0x100 | tag));
    let compressed = app
        .compress(pcd, &mut compress_rng)
        .expect("compression must succeed");

    let mut proof = Writer::default();
    H::write(pcd.data(), &mut proof);
    encode_compressed(compressed.proof(), &mut proof);

    lines.push("rng.fuse.words", tape.consumed());
    lines.push("rng.compress.words", compress_rng.consumed());
    lines.push("proof.bytes", proof.0.len());
    wire_lines(pcd.proof(), compressed.proof(), &mut lines);

    if writing() {
        fixtures.write(name, "rng-u64s-le", &tape.bytes());
        fixtures.write(name, "proof", &proof.0);
        fixtures.write(name, "digests", lines.render().as_bytes());
        let fingerprint = accepted_fingerprint::<C, H>(app, &label, &proof.0);
        fixtures.write(name, "fingerprint", fingerprint.render().as_bytes());
        return;
    }

    if tape.unused() != 0 {
        failures.push(format!(
            "{label}: the fuse left {} words of the tape unused",
            tape.unused()
        ));
    }
    if fixtures.read(name, "proof") != proof.0 {
        failures.push(format!("{label}: the compressed proof changed"));
    }
    let committed = Lines::parse(&String::from_utf8(fixtures.read(name, "digests")).unwrap());
    failures.extend(compare_lines(&label, &lines, &committed));
}

fn seed_scenario<C: FixtureCycle>(app: &App<C>, tape: &mut Tape, salt: u64) -> TestPcd<C> {
    let (pcd, ()) = app
        .seed(tape, Seed::new(), Fp::from(salt))
        .expect("seeding must succeed");
    pcd
}

fn merge_scenario<C: FixtureCycle>(
    app: &App<C>,
    tape: &mut Tape,
    salt: u64,
    left: TestPcd<C>,
    right: TestPcd<C>,
) -> TestPcd<C> {
    let (pcd, ()) = app
        .fuse(tape, Merge::new(), Fp::from(salt), left, right)
        .expect("fusing two nodes must succeed");
    pcd
}

/// The prover reproduces every committed fixture of `C`'s profile.
///
/// The bootstrap proof `finalize` proves under `StdRng` is replaced by the
/// `bootstrap` scenario's, since every seed fuses it as both children and
/// the fixtures must move with fuse alone, not with `rand`'s generator.
fn prover_fixtures<C: FixtureCycle>() {
    let fixtures = Fixtures::of::<C>();
    let mut app = C::app();
    let mut failures = Vec::new();

    let mut bootstrap_tape = fixtures.tape(BOOTSTRAP, 1);
    let (bootstrap, ()) = app
        .fuse(
            &mut bootstrap_tape,
            Bootstrap::new(),
            (),
            app.dummy_pcd(),
            app.dummy_pcd(),
        )
        .expect("the bootstrap step must fuse");
    app.bootstrap = Some(bootstrap.proof().clone());
    check(
        &app,
        &fixtures,
        BOOTSTRAP,
        1,
        &bootstrap,
        &bootstrap_tape,
        &mut failures,
    );

    let mut seed_tape = fixtures.tape(SEED_A, 2);
    let seed_a = seed_scenario(&app, &mut seed_tape, 13);
    check(
        &app,
        &fixtures,
        SEED_A,
        2,
        &seed_a,
        &seed_tape,
        &mut failures,
    );

    // Keep distinct children and the original tree, but only snapshot one
    // seed and one merge at this depth. Their parents pin these inputs too.
    let seed_b = seed_scenario(&app, &mut Tape::record(seed(3)), 17);
    let seed_c = seed_scenario(&app, &mut Tape::record(seed(4)), 19);
    let seed_d = seed_scenario(&app, &mut Tape::record(seed(5)), 23);

    let mut unit_tape = fixtures.tape(UNIT_LEFT, 6);
    let (unit_left, ()) = app
        .fuse(
            &mut unit_tape,
            UnitLeft::new(),
            Fp::from(29u64),
            app.bootstrap_pcd(),
            seed_a.clone(),
        )
        .expect("fusing a unit child must succeed");
    check(
        &app,
        &fixtures,
        UNIT_LEFT,
        6,
        &unit_left,
        &unit_tape,
        &mut failures,
    );

    let mut merge_tape = fixtures.tape(MERGE_AB, 7);
    let merge_ab = merge_scenario(&app, &mut merge_tape, 31, seed_a, seed_b);
    check(
        &app,
        &fixtures,
        MERGE_AB,
        7,
        &merge_ab,
        &merge_tape,
        &mut failures,
    );
    let merge_cd = merge_scenario(&app, &mut Tape::record(seed(8)), 37, seed_c, seed_d);

    let mut merge_tape = fixtures.tape(MERGE_ABCD, 9);
    let merge_abcd = merge_scenario(&app, &mut merge_tape, 41, merge_ab, merge_cd);
    check(
        &app,
        &fixtures,
        MERGE_ABCD,
        9,
        &merge_abcd,
        &merge_tape,
        &mut failures,
    );

    // The first rerandomization also proves the seeded trivial proof the
    // step fuses against, so this tape covers both.
    let mut rerandomize_tape = fixtures.tape(RERANDOMIZE, 10);
    let rerandomized = app
        .rerandomize(merge_abcd, &mut rerandomize_tape)
        .expect("rerandomization must succeed");
    check(
        &app,
        &fixtures,
        RERANDOMIZE,
        10,
        &rerandomized,
        &rerandomize_tape,
        &mut failures,
    );

    assert!(
        failures.is_empty(),
        "the fuse fixtures changed:\n  {}\n\nIf the change is intended, regenerate them with\n    {REGENERATE}\nand review the diff.",
        failures.join("\n  ")
    );
}

/// The `wire.*` lines: the codec's field order, the length and digest of
/// each payload as the wire format encodes it.
/// These pin the wire format itself, apart from the fixture encoding above.
fn wire_lines<C: FixtureCycle>(
    proof: &Proof<C, R>,
    compressed: &CompressedProof<C>,
    lines: &mut Lines,
) {
    lines.push("wire.fields", super::codec::WIRE_FIELDS.join(","));
    let bytes = proof.to_bytes().unwrap();
    let payload = &bytes[crate::wire::ENVELOPE_SIZE..];
    lines.push("wire.proof.bytes", payload.len());
    lines.push("wire.proof.digest", digest(|d| d.bytes(payload)));
    let bytes = compressed.to_bytes().unwrap();
    let payload = &bytes[crate::wire::ENVELOPE_SIZE..];
    lines.push("wire.compressed.bytes", payload.len());
    lines.push("wire.compressed.digest", digest(|d| d.bytes(payload)));
}

/// Decodes a `.proof` file: header data, then the compressed proof, with
/// nothing after.
fn decode_fixture<C: Cycle, H: FixtureHeader>(
    bytes: &[u8],
) -> Option<(H::Data, CompressedProof<C>)> {
    let mut cursor = Cursor::new(bytes);
    let data = H::read(&mut cursor)?;
    let proof = decode_compressed::<C>(&mut cursor)?;
    cursor.finished().then_some((data, proof))
}

/// Runs the compressed verifier under the fingerprint recorder.
fn verifier_run<C: FixtureCycle, H: FixtureHeader>(
    app: &App<C>,
    data: H::Data,
    proof: CompressedProof<C>,
) -> (Result<bool>, Vec<Event>) {
    fingerprint::capture(|| app.verify_compressed(&proof.carry::<H>(data)))
}

/// Whether each final IPA MSM a run evaluated was the identity, in order:
/// the host curve's, then the nested curve's.
fn msm_verdicts(events: &[Event]) -> Vec<bool> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Msm { identity, .. } => Some(*identity),
            _ => None,
        })
        .collect()
}

/// A verifier run as `.fingerprint` lines: what its transcript absorbed and
/// squeezed, and the final MSM of each curve's IPA.
///
/// `verifier.transcript` digests the whole interleaved schedule;
/// `verifier.absorbed` and `verifier.squeezed` split it, so a mismatch says
/// whether the verifier read the proof differently or derived different
/// challenges from the same reads. Each MSM's digest covers every scalar in
/// evaluation order and every proof-dependent base, so it pins the
/// coefficient structure the check assembles, not only that it vanished.
fn fingerprint_lines(events: &[Event]) -> Lines {
    let mut transcript = Digest::new();
    let mut absorbed = Digest::new();
    let mut squeezed = Digest::new();
    let (mut points, mut scalars, mut challenges) = (0u64, 0u64, 0u64);
    let mut msms = Vec::new();
    for event in events {
        match event {
            Event::Point(bytes) => {
                points += 1;
                transcript.tagged(0, bytes);
                absorbed.tagged(0, bytes);
            }
            Event::Scalar(bytes) => {
                scalars += 1;
                transcript.tagged(1, bytes);
                absorbed.tagged(1, bytes);
            }
            Event::Challenge(bytes) => {
                challenges += 1;
                transcript.tagged(2, bytes);
                squeezed.tagged(2, bytes);
            }
            Event::Msm {
                scalars,
                bases,
                identity,
            } => msms.push((scalars, bases, *identity)),
        }
    }

    let mut lines = Lines::default();
    lines.push("verifier.transcript", transcript.hex());
    lines.push("verifier.absorbed", absorbed.hex());
    lines.push("verifier.absorbed.points", points);
    lines.push("verifier.absorbed.scalars", scalars);
    lines.push("verifier.squeezed", squeezed.hex());
    lines.push("verifier.squeezed.challenges", challenges);
    lines.push("verifier.msms", msms.len());
    for ((scalars, bases, identity), side) in msms.into_iter().zip(["native", "nested"]) {
        lines.push(
            format!("verifier.msm.{side}"),
            digest(|d| {
                d.u64(scalars.len() as u64);
                for scalar in scalars {
                    d.bytes(scalar);
                }
                d.u64(bases.len() as u64);
                for base in bases {
                    d.bytes(base);
                }
            }),
        );
        lines.push(format!("verifier.msm.{side}.scalars"), scalars.len());
        lines.push(format!("verifier.msm.{side}.bases"), bases.len());
        lines.push(format!("verifier.msm.{side}.identity"), identity);
    }
    lines
}

/// The fingerprint of the verifier accepting a `.proof` file, for writing
/// it. The prover test writes it beside the proof it just encoded, since the
/// verifier test cannot read a proof that is still being written.
fn accepted_fingerprint<C: FixtureCycle, H: FixtureHeader>(
    app: &App<C>,
    label: &str,
    bytes: &[u8],
) -> Lines {
    let (data, proof) = decode_fixture::<C, H>(bytes).expect("the encoded proof decodes");
    let (verdict, events) = verifier_run::<C, H>(app, data, proof);
    assert!(
        matches!(verdict, Ok(true)),
        "{label}: the verifier rejected the proof just produced"
    );
    assert_eq!(
        msm_verdicts(&events),
        [true, true],
        "{label}: the capture did not see both final MSMs"
    );
    fingerprint_lines(&events)
}

/// A committed `.proof` decodes and re-encodes to the same bytes; the
/// verifier accepts it without re-proving, and its run matches the
/// committed `.fingerprint`; and each tampered copy is rejected where it
/// should be, as zakura-common's rejected Orchard captures are.
fn verify_fixture<C: FixtureCycle, H: FixtureHeader>(
    app: &App<C>,
    fixtures: &Fixtures,
    name: &str,
    failures: &mut Vec<String>,
) {
    let label = fixtures.label(name);
    let bytes = fixtures.read(name, "proof");

    let Some((data, proof)) = decode_fixture::<C, H>(&bytes) else {
        failures.push(format!("{label}: the committed proof does not decode"));
        return;
    };
    let mut again = Writer::default();
    H::write(&data, &mut again);
    encode_compressed(&proof, &mut again);
    if again.0 != bytes {
        failures.push(format!("{label}: re-encoding changed the bytes"));
    }

    let (verdict, events) = verifier_run::<C, H>(app, data.clone(), proof.clone());
    if !matches!(verdict, Ok(true)) {
        failures.push(format!(
            "{label}: the verifier rejected the committed compressed proof"
        ));
    }
    let committed = Lines::parse(&String::from_utf8(fixtures.read(name, "fingerprint")).unwrap());
    failures.extend(compare_lines(
        &label,
        &fingerprint_lines(&events),
        &committed,
    ));

    // Tampered copies. Each is rejected, and those that reach the final
    // MSMs are rejected there: a wrong host-curve IPA scalar fails the host
    // MSM, and a wrong nested one passes the host MSM and fails the nested.
    let mut rejected = |what: &str, proof: CompressedProof<C>, expected: Option<&[bool]>| {
        let (verdict, events) = verifier_run::<C, H>(app, data.clone(), proof);
        if !matches!(verdict, Ok(false)) {
            failures.push(format!("{label}: a proof with {what} was not rejected"));
        } else if let Some(expected) = expected
            && msm_verdicts(&events) != expected
        {
            failures.push(format!(
                "{label}: a proof with {what} was rejected at the wrong check"
            ));
        }
    };

    let mut tampered = proof.clone();
    tampered.native.opening.c += Fp::ONE;
    rejected("a wrong host IPA scalar", tampered, Some(&[false]));

    let mut tampered = proof.clone();
    tampered.nested.opening.c += C::ScalarField::ONE;
    rejected("a wrong nested IPA scalar", tampered, Some(&[true, false]));

    // Exercise InvalidWitness handling before either IPA MSM. Accepting a
    // transcript error must fail even when all honest captures still match.
    let mut tampered = proof.clone();
    for commitment in &mut tampered.instance.nested {
        *commitment = C::NestedCurve::identity();
    }
    rejected("identity stage commitments", tampered, Some(&[]));

    let mut tampered = proof;
    tampered.instance.v += Fp::ONE;
    rejected("a wrong claimed v", tampered, None);
}

/// The verifier accepts every committed compressed proof of `C`'s profile,
/// as its committed fingerprint records, and rejects tampered copies.
fn verifier_fixtures<C: FixtureCycle>() {
    if writing() {
        // The prover test is rewriting the files, fingerprints included.
        return;
    }
    let fixtures = Fixtures::of::<C>();
    let app = C::app();
    let mut failures = Vec::new();
    verify_fixture::<C, ()>(&app, &fixtures, BOOTSTRAP, &mut failures);
    for name in [SEED_A, UNIT_LEFT, MERGE_AB, MERGE_ABCD, RERANDOMIZE] {
        verify_fixture::<C, Value>(&app, &fixtures, name, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "the verifier fixtures changed:\n  {}\n\nIf the change is intended, regenerate them with\n    {REGENERATE}\nand review the diff.",
        failures.join("\n  ")
    );
}

/// The wallet's profile.
mod standard {
    use super::*;

    #[cfg_attr(
        debug_assertions,
        ignore = "production-rank proving is impractically slow without --release"
    )]
    #[test]
    fn prover() {
        prover_fixtures::<Pasta>();
    }

    #[cfg_attr(
        debug_assertions,
        ignore = "production-rank proving is impractically slow without --release"
    )]
    #[test]
    fn verifier() {
        verifier_fixtures::<Pasta>();
    }
}

/// The aggregator's profile.
mod aggregator {
    use super::*;

    type C = Profiled<Pasta, Aggregator>;

    #[cfg_attr(
        debug_assertions,
        ignore = "production-rank proving is impractically slow without --release"
    )]
    #[test]
    fn prover() {
        // Standard is the only writer of the shared fixtures. In check
        // mode, both profiles must independently reproduce them.
        if !writing() {
            prover_fixtures::<C>();
        }
    }

    #[cfg_attr(
        debug_assertions,
        ignore = "production-rank proving is impractically slow without --release"
    )]
    #[test]
    fn verifier() {
        verifier_fixtures::<C>();
    }
}
