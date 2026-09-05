#![cfg(feature = "unstable-fuzzing")]
//! Handing the internal recursion circuits, their honest witnesses and their
//! oracle specifications to a patcher harness (issue #793).
//!
//! The engine's under-constraint machinery (`ragu_testing::patcher`) runs
//! against any [`Circuit`] through its public API, but two things it needs
//! exist only here.
//!
//! The internal circuits' honest witnesses exist only mid-fuse — they depend
//! on every interstitial witness and on the shared instance. A finished
//! [`Proof`](crate::Proof) does not carry them, so there is no post-hoc seam
//! the way there is for proof corruption in [`corrupt`](crate::fuzzing::corrupt).
//!
//! And the *specification* the pinned-input oracle judges against — which
//! wires each circuit is responsible for — is knowledge of the circuits, not
//! of their constraint graphs. A graph cannot tell a received input from an
//! output that was left unconstrained: both are wires nothing derives, and
//! the second is exactly the bug the oracle hunts. So the declaration has to
//! come from the side that knows what each circuit promises.
//!
//! [`capture_internal_circuits`] is
//! that seam: it reproduces the fuse witness-generation (calling the same
//! private helpers `fuse` does) and, instead of tracing each internal
//! circuit into a proof, hands it, its honest witness and its
//! [`CircuitSpec`] to an [`InternalCircuitVisitor`]. A patcher harness
//! supplies a visitor that captures each circuit and hunts
//! under-constraints; this module itself depends on nothing in
//! `ragu_testing`, exactly like `fuzzing::corrupt`.
//!
//! # What a circuit is responsible for
//!
//! Every internal circuit is a [`MultiStage`] circuit over the shared
//! `unified` instance. Its outputs under the oracle are the wires its
//! constraints must determine once everything it merely *reads* is held
//! fixed:
//!
//! * the unified slots it covers — `provide`s, or `receive`s and checks —
//!   read off the `Coverage` it reports; and
//! * the stage values it checks against an in-circuit computation: the
//!   collapsed claims `inner_collapse` folds to, the $k(y)$ evaluations
//!   `outer_collapse` recomputes, the sponge state `hashes_1` saves. These
//!   are reserved stage wires, committed outside the circuit, and the
//!   circuit that checks them is the one that binds them.
//!
//! Everything else — the remaining instance wires and the remaining stage
//! wires — is an input the oracle pins. A covered slot a circuit reads
//! straight from a stage (`hashes_2`'s $\mu$ and $\nu$ are the resumed sponge
//! state) resolves to a stage wire and is demoted to an input by
//! [`CircuitSpec::resolve`]: the circuit derives nothing there, and the
//! binding lives with `hashes_1`, which checks that state.
//!
//! The nested (scalar-field) endoscaling step circuits follow the same
//! pattern — each checks one interstitial of the points stage against its
//! Horner accumulation — and are handed to
//! [`InternalCircuitVisitor::visit_nested`]. The remaining nested circuits,
//! `loading` and `copying`, are bonding claims over stage polynomials with
//! no witness of their own to capture.
//!
//! Like the rest of the fuzzing surface it is gated behind `unstable-fuzzing`
//! — by the inner attribute at the top of this file, so the pipeline modules
//! carry none — and is **not** part of the stable API. The source lives in
//! `src/fuzzing/` with the rest of that surface, but the module is mounted
//! under `fuse` (see `fuse/mod.rs`) because it calls the pipeline's
//! `pub(super)` steps; harnesses reach it through
//! [`fuzzing::patcher`](crate::fuzzing::patcher). It deliberately mirrors
//! [`fuse`](Application::fuse) rather than hooking into it, so the production
//! proving path is untouched; a change to `fuse` that this mirror does not
//! track will surface as a failing patcher test.

use alloc::{format, string::String, vec::Vec};
use core::marker::PhantomData;

use ragu_arithmetic::{Coeff, Cycle, ff::Field, rand::CryptoRng};
use ragu_circuits::{
    Circuit,
    polynomials::Rank,
    staging::{MultiStage, Stage, StageExt},
};
use ragu_core::{
    Result,
    convert::WireMap,
    drivers::{
        Driver, DriverTypes,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget},
    maybe::{Always, Empty, Maybe, MaybeKind},
};
use ragu_primitives::{
    EndoscalarChallenge, GadgetExt, Point, extract_endoscalar,
    vec::{CollectFixed, Len},
};

use super::FuseProofSource;
use crate::{
    Application, Pcd, RAGU_TAG,
    internal::{
        endoscalar::{
            EndoscalarStage, EndoscalingStep, EndoscalingStepWitness, NumStepsLen, PointsStage,
            PointsWitness,
        },
        native::{self, RxComponent, RxIndex, total_circuit_counts},
        nested::NUM_ENDOSCALING_POINTS,
        transcript::Transcript,
    },
    proof::ProofBuilder,
    step::Step,
};

/// A wire an internal circuit is responsible for, named the way a capture
/// exposes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputRef {
    /// The `n`-th wire of the circuit's public instance, in $k(Y)$ order.
    Instance(usize),
    /// The `n`-th reserved stage wire, in reservation order across the whole
    /// stage chain — the numbering `StageGuard` injects.
    Stage(usize),
}

/// What a patcher harness must know about an internal circuit beyond its
/// [`Circuit`] impl: which wires its constraints are responsible for
/// determining.
#[derive(Clone, Debug)]
pub struct CircuitSpec {
    /// The circuit's name, for diagnostics (the endoscaling steps are
    /// numbered).
    pub name: String,
    /// The wires it is responsible for: its outputs under the pinned-input
    /// oracle (see the `fuse::patcher` module docs).
    pub outputs: Vec<OutputRef>,
}

/// A [`CircuitSpec`] resolved against one capture's wires.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// Every instance and stage wire that is not an output — what the oracle
    /// pins.
    pub inputs: Vec<usize>,
    /// The declared outputs — what the oracle watches.
    pub outputs: Vec<usize>,
    /// Declared instance outputs that resolved to reserved stage wires and
    /// were therefore counted among the inputs instead.
    pub demoted: Vec<usize>,
}

impl CircuitSpec {
    /// Resolves the declared outputs against a capture's instance wires (in
    /// $k(Y)$ order) and reserved stage wires (in reservation order).
    ///
    /// A declared instance output that is itself a reserved stage wire is
    /// demoted to an input: the circuit reads it from a stage rather than
    /// deriving it, so its binding is another circuit's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidWitness`](ragu_core::Error::InvalidWitness) if a
    /// declared position lies beyond the capture's instance or stage wires.
    pub fn resolve(&self, instance: &[usize], stage_wires: &[usize]) -> Result<Resolution> {
        let n = instance
            .iter()
            .chain(stage_wires)
            .copied()
            .max()
            .map_or(0, |w| w + 1);
        let mut is_stage = alloc::vec![false; n];
        for &w in stage_wires {
            is_stage[w] = true;
        }

        let mut is_output = alloc::vec![false; n];
        let mut outputs = Vec::new();
        let mut demoted = Vec::new();
        for output in &self.outputs {
            let wire = match *output {
                OutputRef::Instance(i) => *instance.get(i).ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        format!(
                            "{}: declared instance output {i} is beyond the {}-wire instance",
                            self.name,
                            instance.len()
                        )
                        .into(),
                    )
                })?,
                OutputRef::Stage(i) => *stage_wires.get(i).ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        format!(
                            "{}: declared stage output {i} is beyond the {} reserved wires",
                            self.name,
                            stage_wires.len()
                        )
                        .into(),
                    )
                })?,
            };
            if matches!(output, OutputRef::Instance(_)) && is_stage[wire] {
                if !demoted.contains(&wire) {
                    demoted.push(wire);
                }
            } else if !is_output[wire] {
                is_output[wire] = true;
                outputs.push(wire);
            }
        }

        let mut seen = alloc::vec![false; n];
        let inputs = instance
            .iter()
            .chain(stage_wires)
            .copied()
            .filter(|&w| !is_output[w] && !core::mem::replace(&mut seen[w], true))
            .collect();

        Ok(Resolution {
            inputs,
            outputs,
            demoted,
        })
    }
}

/// Receives each native internal recursion circuit, its specification and
/// its honest witness during
/// [`capture_internal_circuits`].
///
/// `make_witness` builds the circuit's honest witness on demand; it is a
/// builder rather than a value so the visitor can run the circuit through
/// more than one driver (e.g. capture *and* an independent playback), which
/// consuming a single witness would not allow.
pub trait InternalCircuitVisitor<C: Cycle> {
    /// Visit the native (circuit-field) `circuit`, described by `spec`,
    /// whose honest witness is `make_witness()` and whose reserved stage
    /// wires honestly hold `stage_values` (two per reserved gate, in
    /// reservation order — see `capture_with_stage_values` in
    /// `ragu_testing::patcher`).
    ///
    /// # Errors
    ///
    /// Propagates any error the visitor raises, or from `make_witness`.
    fn visit<'w, Cir: Circuit<C::CircuitField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::CircuitField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()>;

    /// Visit a nested (scalar-field) `circuit` — one of the endoscaling
    /// steps — described by `spec`, with its honest witness and stage values
    /// as for [`visit`](Self::visit). Skipped by default.
    ///
    /// # Errors
    ///
    /// Propagates any error the visitor raises, or from `make_witness`.
    fn visit_nested<'w, Cir: Circuit<C::ScalarField>>(
        &mut self,
        spec: &CircuitSpec,
        circuit: &Cir,
        stage_values: &[C::ScalarField],
        make_witness: impl Fn() -> Result<Cir::Witness<'w>>,
    ) -> Result<()> {
        let _ = (spec, circuit, stage_values, make_witness);
        Ok(())
    }
}

/// The honest values of stage `S`'s reserved wires, in injection order and
/// padded with zeros to the two wires per gate the stage reserves: what its
/// stage polynomial commits to, alpha aside. Runs the stage on the extractor
/// emulator, as `StageExt::rx` does.
fn stage_values<'source, F: Field, R: Rank, S: Stage<F, R> + Default>(
    witness: S::Witness<'source>,
) -> Result<Vec<F>> {
    let mut dr = Emulator::extractor();
    let output = S::default().witness(&mut dr, Always::maybe_just(|| witness))?;
    let mut values = dr.wires(&output)?;
    values.resize(2 * <S as StageExt<F, R>>::num_gates(), F::ZERO);
    Ok(values)
}

/// The unified element slots a circuit covers, as instance positions, read
/// off the `Coverage` the circuit reports after one execution of its witness
/// on a wireless emulator.
fn covered_elements<'w, F: Field, Cir: Circuit<F>>(
    circuit: &Cir,
    witness: Cir::Witness<'w>,
    coverage: impl FnOnce(Cir::Aux<'w>) -> Vec<usize>,
) -> Result<Vec<usize>> {
    let aux = circuit
        .witness(&mut Emulator::execute(), Always::maybe_just(|| witness))?
        .into_aux();
    Ok(coverage(aux.take()))
}

/// The positions, in the unified output's $k(Y)$ order, of the covered
/// *element* slots of `coverage`: the values the covering circuit derives
/// in-circuit (`Slot::provide`) or receives and checks (`Slot::receive`).
/// Covered *point* slots are received commitments, which no circuit derives,
/// so they are omitted; a point writes two wires and an element one, which is
/// how the two are told apart.
///
/// This is a circuit's output declaration for the harness: with every other
/// instance wire pinned, these are the wires its constraints must determine.
fn covered_element_positions(coverage: &native::unified::Coverage) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut position = 0;
    coverage.for_each_slot(|_, covered, wires| {
        if wires == 1 && covered {
            positions.push(position);
        }
        position += wires;
    });
    positions
}

/// A driver that is never driven: its `usize` wires let a stage gadget be
/// rebound onto reservation indices, exactly as `StageGuard` rebinds it
/// onto the reserved wires, so a harness can name a stage field by index.
struct Indexed<F>(PhantomData<F>);

impl<F: Field> DriverTypes for Indexed<F> {
    type ImplField = F;
    type ImplWire = usize;
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
    type Extra = ();

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(usize, usize, usize, ())> {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }

    fn assign_extra(&mut self, _: (), _: impl Fn() -> Result<Coeff<F>>) -> Result<usize> {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }
}

impl<'dr, F: Field> Driver<'dr> for Indexed<F> {
    type F = F;
    type Wire = usize;
    const ONE: usize = usize::MAX;

    fn add(&mut self, _: impl Fn(())) -> usize {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }

    fn enforce_zero(&mut self, _: impl Fn(())) -> Result<()> {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }
}

/// Hands out successive reservation indices, the way `StageWireInjector`
/// hands out successive reserved wires.
struct Indexer<F> {
    next: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> WireMap<F> for Indexer<F> {
    type Src = Emulator<Wireless<Empty, F>>;
    type Dst = Indexed<F>;

    fn convert_wire(&mut self, _: &()) -> Result<usize> {
        let index = self.next;
        self.next += 1;
        Ok(index)
    }
}

/// Collects the wires of a gadget already bound to [`Indexed`], in
/// traversal order — the same order the stage injector assigns them.
struct WireCollector<F> {
    wires: Vec<usize>,
    _marker: PhantomData<F>,
}

impl<F: Field> WireMap<F> for WireCollector<F> {
    type Src = Indexed<F>;
    type Dst = Indexed<F>;

    fn convert_wire(&mut self, wire: &usize) -> Result<usize> {
        self.wires.push(*wire);
        Ok(*wire)
    }
}

/// The reservation indices of a sub-gadget of a stage output rebound by
/// [`stage_wire_indices`] (a `Point` yields its two coordinates).
fn wires_of<'dr, F: Field, G: Gadget<'dr, Indexed<F>>>(gadget: &G) -> Result<Vec<usize>> {
    let mut collector = WireCollector::<F> {
        wires: Vec::new(),
        _marker: PhantomData,
    };
    gadget.map(&mut collector)?;
    Ok(collector.wires)
}

/// The reservation indices of the wires `select` picks from stage `S`'s
/// output gadget.
///
/// Runs the stage on the counter emulator, as `configure_stage` does to lay
/// the stage out, then rebinds the gadget onto indices starting at the
/// stage's first reserved wire — `2 · (skip_gates − 1)` wires precede it,
/// two per gate of every ancestor stage, the SYSTEM gate aside.
fn stage_wire_indices<F: Field, R: Rank, S: Stage<F, R> + Default>(
    select: impl for<'dst> FnOnce(Bound<'dst, Indexed<F>, S::OutputKind>) -> Result<Vec<usize>>,
) -> Result<Vec<usize>> {
    let mut counter = Emulator::counter();
    let stage = S::default();
    let gadget = stage.witness(&mut counter, Empty)?;
    let mut indexer = Indexer::<F> {
        next: 2 * (S::skip_gates() - 1),
        _marker: PhantomData,
    };
    let rebound = gadget.map(&mut indexer)?;
    select(rebound)
}

/// Runs the fuse witness-generation for `step` over `left` and `right` and
/// hands each native internal recursion circuit, its [`CircuitSpec`] and its
/// honest witness to `visitor`, in place of tracing them into a proof.
///
/// This mirrors [`fuse`](Application::fuse) up to the internal-circuit step;
/// the challenges, interstitial witnesses, and shared instance are computed
/// exactly as the prover computes them. The `unified` instance is rebuilt
/// fresh for each circuit from the finished builder (its coverage
/// bookkeeping does not affect the emitted constraints), so no proof is
/// produced and the children's proofs are not consumed for one. That fresh
/// coverage is also what makes each circuit's reported `Coverage` *its own*
/// contribution, which the spec reads as the unified slots it is responsible
/// for.
///
/// # Errors
///
/// Propagates any error from witness generation, from laying out a stage, or
/// from the visitor.
pub fn capture_internal_circuits<'source, C, R, const HEADER_SIZE: usize, B, RNG, S, V>(
    app: &Application<'_, C, R, HEADER_SIZE, B>,
    rng: &mut RNG,
    step: S,
    witness: S::Witness<'source>,
    left: Pcd<C, R, S::Left>,
    right: Pcd<C, R, S::Right>,
    visitor: &mut V,
) -> Result<()>
where
    C: Cycle,
    R: Rank,
    B: crate::SelectableBackend,
    RNG: CryptoRng,
    S: Step<C>,
    V: InternalCircuitVisitor<C>,
{
    app.capture_internal_circuits_at(rng, step, witness, left, right, false, visitor)
}

/// [`capture_internal_circuits`] at the base case — the internal bootstrap
/// fuse [`ApplicationBuilder::finalize`](crate::ApplicationBuilder::finalize)
/// performs over two synthesized dummy children.
///
/// `outer_collapse` deliberately leaves the final claim `c` unconstrained
/// there (the prover may witness any `c` to start the recursion), so its
/// spec drops `c` at this point; its checks on the children's $k(y)$ values
/// stay.
///
/// # Errors
///
/// As [`capture_internal_circuits`].
pub fn capture_internal_circuits_bootstrap<C, R, const HEADER_SIZE: usize, B, RNG, V>(
    app: &Application<'_, C, R, HEADER_SIZE, B>,
    rng: &mut RNG,
    visitor: &mut V,
) -> Result<()>
where
    C: Cycle,
    R: Rank,
    B: crate::SelectableBackend,
    RNG: CryptoRng,
    V: InternalCircuitVisitor<C>,
{
    app.capture_internal_circuits_at(
        rng,
        crate::step::internal::bootstrap::Bootstrap::new(),
        (),
        app.dummy_pcd(),
        app.dummy_pcd(),
        true,
        visitor,
    )
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, B: crate::SelectableBackend>
    Application<'_, C, R, HEADER_SIZE, B>
{
    #[allow(clippy::too_many_arguments)]
    fn capture_internal_circuits_at<'source, RNG, S, V>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
        base_case: bool,
        visitor: &mut V,
    ) -> Result<()>
    where
        RNG: CryptoRng,
        S: Step<C>,
        V: InternalCircuitVisitor<C>,
    {
        let mut builder = ProofBuilder::new(self.params, C::ScalarField::random(&mut *rng));

        let (left, right, _application_data, _application_aux) =
            self.compute_application_proof(rng, step, witness, left, right, &mut builder)?;

        let mut dr = Emulator::execute();
        let mut transcript = Transcript::new(&mut dr, C::circuit_poseidon(self.params), RAGU_TAG)?;

        let preamble_witness = self.compute_preamble(rng, &left, &right, &mut builder)?;
        let preamble_commitment = Point::constant(&mut dr, builder.bridge_preamble_commitment())?;
        preamble_commitment.write(&mut dr, &mut transcript)?;
        let w = transcript.challenge(&mut dr)?;
        let native_registry = self.native_registry.at(*w.value().take());

        let native_s_prime =
            self.compute_s_prime(rng, &native_registry, &left, &right, &mut builder)?;
        let s_prime_commitment = Point::constant(&mut dr, builder.bridge_s_prime_commitment())?;
        s_prime_commitment.write(&mut dr, &mut transcript)?;
        let y = transcript.challenge(&mut dr)?;
        let z = transcript.challenge(&mut dr)?;

        let source = FuseProofSource {
            left: &left,
            right: &right,
        };

        let (inner_error_witness, claims, registry_wy) =
            self.inner_error_terms(rng, &native_registry, &y, &z, &source, &mut builder)?;
        let inner_error_commitment =
            Point::constant(&mut dr, builder.bridge_inner_error_commitment())?;
        inner_error_commitment.write(&mut dr, &mut transcript)?;

        let saved_transcript_state = transcript
            .clone()
            .save_state(&mut dr)
            .expect("save_state should succeed after absorbing")
            .into_elements()
            .into_iter()
            .map(|e| *e.value().take())
            .collect_fixed()?;

        let mu = transcript.challenge(&mut dr)?;
        let nu = transcript.challenge(&mut dr)?;

        let (outer_error_witness, a, b) = self.outer_error_terms(
            rng,
            &preamble_witness,
            &inner_error_witness,
            claims,
            &y,
            &mu,
            &nu,
            saved_transcript_state,
            &mut builder,
        )?;
        let outer_error_commitment =
            Point::constant(&mut dr, builder.bridge_outer_error_commitment()?)?;
        outer_error_commitment.write(&mut dr, &mut transcript)?;
        let mu_prime = transcript.challenge(&mut dr)?;
        let nu_prime = transcript.challenge(&mut dr)?;

        self.compute_ab(a, b, &source, &mu_prime, &nu_prime, &mut builder)?;
        let ab_commitment = Point::constant(&mut dr, builder.bridge_ab_commitment()?)?;
        ab_commitment.write(&mut dr, &mut transcript)?;
        let x = transcript.challenge(&mut dr)?;

        let query_witness = self.compute_query(
            rng,
            &w,
            &x,
            &y,
            &z,
            &registry_wy,
            &left,
            &right,
            &mut builder,
        )?;
        let query_commitment = Point::constant(&mut dr, builder.bridge_query_commitment()?)?;
        query_commitment.write(&mut dr, &mut transcript)?;
        let alpha = transcript.challenge(&mut dr)?;

        let native_f = self.compute_f(
            rng,
            &w,
            &y,
            &z,
            &x,
            &alpha,
            &native_s_prime,
            &registry_wy,
            &mut builder,
            &left,
            &right,
        )?;
        let f_commitment = Point::constant(&mut dr, builder.bridge_f_commitment())?;
        f_commitment.write(&mut dr, &mut transcript)?;
        let u = transcript.challenge(&mut dr)?;

        let eval_witness =
            self.compute_eval(&u, &left, &right, &native_s_prime, &registry_wy, &builder);

        // Mirrors `fuse`: `pre_beta` is ground rather than squeezed once, so
        // each attempt re-blinds the eval commitment and re-derives it from a
        // fresh transcript clone until it lands in endoscalar range.
        let (pre_beta, eval_rx) = EndoscalarChallenge::sample(&mut dr, |dr| {
            let (eval_rx, bridge_eval_commitment) =
                self.sample_eval_commitment(rng, &eval_witness, &builder)?;

            let mut transcript = transcript.clone();
            let eval_commitment = Point::constant(dr, bridge_eval_commitment)?;
            eval_commitment.write(dr, &mut transcript)?;
            let pre_beta = transcript.challenge(dr)?;

            Ok((pre_beta, eval_rx))
        })?;
        builder.set_native_eval_rx(eval_rx);

        self.compute_p(
            rng,
            &pre_beta,
            &left,
            &right,
            &native_s_prime,
            &registry_wy,
            &native_f,
            &mut builder,
        )?;

        builder.set_w(*w.value().take());
        builder.set_y(*y.value().take());
        builder.set_z(*z.value().take());
        builder.set_mu(*mu.value().take());
        builder.set_nu(*nu.value().take());
        builder.set_mu_prime(*mu_prime.value().take());
        builder.set_nu_prime(*nu_prime.value().take());
        builder.set_x(*x.value().take());
        builder.set_alpha(*alpha.value().take());
        builder.set_u(*u.value().take());
        builder.set_pre_beta(*pre_beta.element().value().take());

        builder.set_child_left_stage_rx(left.as_child_stage_rx());
        builder.set_child_right_stage_rx(right.as_child_stage_rx());

        // Rebuild the shared instance from the finished builder for each
        // circuit. Threading the accumulated coverage (as the prover does) is
        // unnecessary here: coverage is prover bookkeeping and does not affect
        // the constraints a circuit emits, so a fresh instance yields the same
        // capture — and reports each circuit's own coverage.
        let make_unified =
            |builder: &ProofBuilder<'_, C, R, B>| -> Result<native::unified::Instance<C>> {
                Ok(native::unified::Instance {
                    bridge_preamble_commitment: builder.bridge_preamble_commitment(),
                    w: builder.w(),
                    bridge_s_prime_commitment: builder.bridge_s_prime_commitment(),
                    y: builder.y(),
                    z: builder.z(),
                    bridge_inner_error_commitment: builder.bridge_inner_error_commitment(),
                    mu: builder.mu(),
                    nu: builder.nu(),
                    bridge_outer_error_commitment: builder.bridge_outer_error_commitment()?,
                    mu_prime: builder.mu_prime(),
                    nu_prime: builder.nu_prime(),
                    c: builder.c(),
                    bridge_ab_commitment: builder.bridge_ab_commitment()?,
                    x: builder.x(),
                    bridge_query_commitment: builder.bridge_query_commitment()?,
                    alpha: builder.alpha(),
                    bridge_f_commitment: builder.bridge_f_commitment(),
                    u: builder.u(),
                    bridge_eval_commitment: builder.bridge_eval_commitment()?,
                    pre_beta: builder.pre_beta(),
                    v: builder.v(),
                    coverage: Default::default(),
                })
            };
        let coverage = |unified: native::unified::Instance<C>| -> Vec<usize> {
            covered_element_positions(&unified.coverage)
        };

        type OuterError<C, R, const HEADER_SIZE: usize> =
            native::stages::outer_error::Stage<C, R, HEADER_SIZE, native::RevdotParameters>;

        // The honest stage values, per stage, for the overlay: each circuit's
        // chain is the concatenation in `add_stage` order (a skipped stage is
        // reserved all the same, so it is included).
        let preamble_values =
            stage_values::<_, R, native::stages::preamble::Stage<C, R, HEADER_SIZE>>(
                &preamble_witness,
            )?;
        let outer_error_values =
            stage_values::<_, R, OuterError<C, R, HEADER_SIZE>>(&outer_error_witness)?;
        let inner_error_values = stage_values::<
            _,
            R,
            native::stages::inner_error::Stage<C, R, HEADER_SIZE, native::RevdotParameters>,
        >(&inner_error_witness)?;
        let query_values =
            stage_values::<_, R, native::stages::query::Stage<C, R, HEADER_SIZE>>(&query_witness)?;
        let eval_values =
            stage_values::<_, R, native::stages::eval::Stage<C, R, HEADER_SIZE>>(&eval_witness)?;
        let chain = |stages: &[&[C::CircuitField]]| -> Vec<C::CircuitField> { stages.concat() };
        let preamble_outer_error = chain(&[&preamble_values, &outer_error_values]);

        // hashes_1 squeezes w, y, z and checks the sponge state the
        // outer_error stage carries over to hashes_2.
        let hashes_1 = native::circuits::hashes_1::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(
            self.params,
            total_circuit_counts(self.num_application_steps).1,
        );
        let hashes_1_witness = || {
            Ok(native::circuits::hashes_1::Witness {
                unified: make_unified(&builder)?,
                preamble_witness: &preamble_witness,
                outer_error_witness: &outer_error_witness,
            })
        };
        let hashes_1_spec = CircuitSpec {
            name: "hashes_1".into(),
            outputs: covered_elements(&hashes_1, hashes_1_witness()?, coverage)?
                .into_iter()
                .map(OutputRef::Instance)
                .chain(
                    stage_wire_indices::<_, R, OuterError<C, R, HEADER_SIZE>>(|stage| {
                        Ok(stage
                            .sponge_state
                            .into_elements()
                            .iter()
                            .map(|e| *e.wire())
                            .collect())
                    })?
                    .into_iter()
                    .map(OutputRef::Stage),
                )
                .collect(),
        };
        visitor.visit(
            &hashes_1_spec,
            &hashes_1,
            &preamble_outer_error,
            hashes_1_witness,
        )?;

        // hashes_2 resumes from that sponge state and squeezes the rest of
        // the challenges; mu and nu are the resumed state itself and resolve
        // to stage wires, so `resolve` demotes them to inputs.
        let hashes_2 = native::circuits::hashes_2::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new(self.params);
        let hashes_2_witness = || {
            Ok(native::circuits::hashes_2::Witness {
                unified: make_unified(&builder)?,
                outer_error_witness: &outer_error_witness,
            })
        };
        let hashes_2_spec = CircuitSpec {
            name: "hashes_2".into(),
            outputs: covered_elements(&hashes_2, hashes_2_witness()?, coverage)?
                .into_iter()
                .map(OutputRef::Instance)
                .collect(),
        };
        visitor.visit(
            &hashes_2_spec,
            &hashes_2,
            &preamble_outer_error,
            hashes_2_witness,
        )?;

        // inner_collapse covers no unified slot: it folds the inner error
        // terms and checks the result against the collapsed claims the
        // outer_error stage witnessed.
        let inner_collapse = native::circuits::inner_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new();
        let inner_collapse_witness = || {
            Ok(native::circuits::inner_collapse::Witness {
                preamble_witness: &preamble_witness,
                unified: make_unified(&builder)?,
                outer_error_witness: &outer_error_witness,
                inner_error_witness: &inner_error_witness,
            })
        };
        let inner_collapse_spec = CircuitSpec {
            name: "inner_collapse".into(),
            outputs: stage_wire_indices::<_, R, OuterError<C, R, HEADER_SIZE>>(|stage| {
                Ok(stage.collapsed.iter().map(|e| *e.wire()).collect())
            })?
            .into_iter()
            .map(OutputRef::Stage)
            .collect(),
        };
        visitor.visit(
            &inner_collapse_spec,
            &inner_collapse,
            &chain(&[&preamble_values, &outer_error_values, &inner_error_values]),
            inner_collapse_witness,
        )?;

        // outer_collapse recomputes the children's k(y) values from the
        // preamble and checks them against the outer_error stage, then folds
        // to the final claim c it receives (and checks, outside the base
        // case).
        let outer_collapse = native::circuits::outer_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            native::RevdotParameters,
        >::new();
        let outer_collapse_witness = || {
            Ok(native::circuits::outer_collapse::Witness {
                unified: make_unified(&builder)?,
                preamble_witness: &preamble_witness,
                outer_error_witness: &outer_error_witness,
            })
        };
        // At the base case the covered slot, c, is left free by design, so
        // only the k(y) checks remain as outputs.
        let outer_collapse_covered = if base_case {
            Vec::new()
        } else {
            covered_elements(&outer_collapse, outer_collapse_witness()?, coverage)?
        };
        let outer_collapse_spec = CircuitSpec {
            name: "outer_collapse".into(),
            outputs: outer_collapse_covered
                .into_iter()
                .map(OutputRef::Instance)
                .chain(
                    stage_wire_indices::<_, R, OuterError<C, R, HEADER_SIZE>>(|stage| {
                        Ok([&stage.left, &stage.right]
                            .into_iter()
                            .flat_map(|child| {
                                [&child.application, &child.unified, &child.unified_bridge]
                            })
                            .map(|e| *e.wire())
                            .collect())
                    })?
                    .into_iter()
                    .map(OutputRef::Stage),
                )
                .collect(),
        };
        visitor.visit(
            &outer_collapse_spec,
            &outer_collapse,
            &preamble_outer_error,
            outer_collapse_witness,
        )?;

        // compute_v derives the expected evaluation v.
        let compute_v = native::circuits::compute_v::Circuit::<C, R, HEADER_SIZE>::new();
        let compute_v_witness = || {
            Ok(native::circuits::compute_v::Witness {
                unified: make_unified(&builder)?,
                preamble_witness: &preamble_witness,
                query_witness: &query_witness,
                eval_witness: &eval_witness,
            })
        };
        let compute_v_spec = CircuitSpec {
            name: "compute_v".into(),
            outputs: covered_elements(&compute_v, compute_v_witness()?, coverage)?
                .into_iter()
                .map(OutputRef::Instance)
                .collect(),
        };
        visitor.visit(
            &compute_v_spec,
            &compute_v,
            &chain(&[&preamble_values, &query_values, &eval_values]),
            compute_v_witness,
        )?;

        // The nested endoscaling steps, on the scalar field. Each one
        // Horner-accumulates four of the host-curve commitments `compute_p`
        // folds into p(X), under the endoscalar extracted from pre_beta, and
        // checks the result against the interstitial the points stage
        // witnessed: that interstitial is its output; the endoscalar bits and
        // every other point are inputs. The commitments are collected in
        // `compute_p`'s order from the same objects it used; any valid point
        // list exercises the step circuits identically, so the order only
        // keeps the capture faithful to the prover's.
        let beta_endo = extract_endoscalar(builder.pre_beta())?;
        let mut points: Vec<C::HostCurve> = Vec::with_capacity(NUM_ENDOSCALING_POINTS);
        points.push(native_f.commitment);
        for proof in [&left, &right] {
            for &id in &RxIndex::ALL {
                points.push(proof.native_rx_commitment(id));
            }
            points.push(proof.native_commitment(RxComponent::AbA));
            points.push(proof.native_commitment(RxComponent::AbB));
            points.push(proof.native_registry_xy_commitment());
            points.push(proof.native_p_commitment());
        }
        points.push(native_s_prime.registry_wx0_commitment);
        points.push(native_s_prime.registry_wx1_commitment);
        points.push(registry_wy.commitment);
        points.push(builder.native_a_commitment());
        points.push(builder.native_b_commitment());
        points.push(builder.native_registry_xy_commitment());
        debug_assert_eq!(points.len(), NUM_ENDOSCALING_POINTS);
        let points_witness =
            PointsWitness::<C::HostCurve, NUM_ENDOSCALING_POINTS>::new(beta_endo, &points);
        let endoscaling_values: Vec<C::ScalarField> = [
            stage_values::<C::ScalarField, R, EndoscalarStage>(beta_endo)?,
            stage_values::<_, R, PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS>>(
                &points_witness,
            )?,
        ]
        .concat();

        for step in 0..NumStepsLen::<NUM_ENDOSCALING_POINTS>::len() {
            let circuit = MultiStage::new(
                EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(step),
            );
            let spec = CircuitSpec {
                name: format!("endoscaling_step_{step}"),
                outputs: stage_wire_indices::<
                    C::ScalarField,
                    R,
                    PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS>,
                >(|points| wires_of(&points.interstitials[step]))?
                .into_iter()
                .map(OutputRef::Stage)
                .collect(),
            };
            visitor.visit_nested(&spec, &circuit, &endoscaling_values, || {
                Ok(EndoscalingStepWitness {
                    endoscalar: beta_endo,
                    points: &points_witness,
                })
            })?;
        }

        Ok(())
    }
}
