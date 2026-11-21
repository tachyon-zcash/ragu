//! Proof decompression: a compressed proof verified inside a fresh
//! accumulator proof, so that the recursion can continue from it.
//!
//! [`Application::verify_compressed`](crate::Application::verify_compressed)
//! runs natively: it replays the compression's transcript, folds the revdot
//! claims and checks the split, the batch and one IPA opening per curve.
//! Decompression checks the wallet verifier's equations in circuits of a
//! new proof over the same cycle, with the wallet statement as its output
//! header. The fuse can take this proof as a child.
//!
//! - **Transcript.** The native verifier squeezes its challenges from a
//!   Poseidon transcript over the instance and its messages. The transcript
//!   chunks follow the same absorption order with the Poseidon `Sponge`
//!   gadget, sliced at the sponge's permutation boundaries. Each run of
//!   host-curve points and scalar-field values enters as the nested-curve
//!   commitment of the stage that holds it, before the next challenge
//!   (see *What binds the two sides*).
//! - **Field identities.** The fold's weights and $W(r)$, the public parts
//!   of the folded claims, the split identity, the batch's $f(u)$ and $v$
//!   and the IPA's $b$ are arithmetic in one field: [`Element`] arithmetic
//!   in the circuit over that field, with inverses as advised witnesses.
//! - **Registry evaluations.** The native verifier evaluates the wallet
//!   registry at $(w, r, y)$, at the circuits' $\omega_c$ and at the
//!   children's points. The chunks take these as stage wires and hold each
//!   to a claimed value of the aggregator's online batch, which the step's
//!   fuse proves is the wallet registry's (see *Registry evaluations*).
//! - **Derived commitments.** $\[A\]$, the dilated and raw polynomials'
//!   commitments, the batched $\[H\]$ and the IPA's folded commitment are
//!   multi-scalar multiplications of the instance's points. Those live on
//!   the other curve, so the circuit over the points' base field derives
//!   them by endoscalar Horner chains, as the fuse's endoscaling steps do,
//!   which asks the compression to lift its point-multiplying challenges
//!   to endoscalars.
//! - **Curve membership.** The chunks load their stages unenforced, so the
//!   curve equation a point's allocation emits reaches no circuit on its
//!   own; one chunk per side holds every point the prover supplies, the
//!   instance's and the messages' commitments, the runs' and the IPA's
//!   witness points, to the curve, as `bind_endoscalar` does for the fuse's
//!   points stages. A chunk's own points are sums and scalings of those and
//!   of the generators. Without it an off-curve point with $x = 0$ leaves
//!   an endoscaling's output unconstrained.
//! - **$G'$.** The IPA's final generator $G' = \langle s, G \rangle$ is the
//!   commitment to $s(X)$ over the same generators, so the circuit takes
//!   $G'$ as a witness point and holds it to a commitment of $s$ the
//!   decompression step made before its challenge, one evaluation of
//!   which that step's own fuse batches into its opening accumulator.
//!   Both curves' are bound so, over round challenges a digest that step
//!   committed with them fixes (see *The step binding*).
//!
//! The scalar checks are written once as [`Driver`]-generic gadget code
//! and run in the circuit over the matching field: the host curve's in the
//! native circuits, the nested curve's in the nested ones.
//!
//! # Layout
//!
//! - [`revdot`], [`batch`] and [`ipa`]: the fold and split, the batch's
//!   $f(u)$, $v$ and $\beta$ weights, and the IPA's round inverses, $b$
//!   and final-check scalars, as gadgets, with $s$ at any point
//!   ([`ipa::s_at`]), which the step binding checks an opening against.
//! - The compression's transcript over the allocated instance and messages,
//!   squeezing the native challenges; the derived commitments, $\[H\]$ and
//!   the IPA's final check as endoscalar chains over the other curve's
//!   points; and the verifier assembled from the gadgets as the two
//!   circuits of the cycle, each side one circuit, which the tests run end
//!   to end.
//! - [`program`], [`stages`], [`run`], [`side`] and [`chunk`]: each side
//!   cut into chunk circuits under the gate budget, every chunk loading
//!   the compressed proof's data from stages and leaving its results in a
//!   work stage for later chunks, with the prover's native run of the same
//!   program filling the stages. The chunk circuits take two ranks, the
//!   compressed proof's and their own, so that an aggregator at
//!   [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank) cuts a
//!   wallet's wallet-rank proof into fewer chunks, whose circuit counts
//!   the aggregator profile pins
//!   ([`native_circuits`](crate::profile::Aggregator::native_circuits) and
//!   [`NESTED_CIRCUITS`](crate::profile::Aggregator::NESTED_CIRCUITS)).
//! - [`extension`] and [`prover`]: the chunk circuits as the aggregator
//!   profile's extension, declared from the pinned counts and registered
//!   through the profile's hooks, and their polynomials for every proof
//!   from the canonical compressed proof the application holds.
//! - The decompression step
//!   ([`decompress`](crate::step::internal::decompress)): the one step
//!   whose output header is the decompressed proof's, with the native
//!   extension's statement circuit ([`chunk::StatementCircuit`]) exposing
//!   the header the chunks verified and its claim's $k(y)$ holding the
//!   step's output header to it.
//!
//! # Integration
//!
//! The [`chunk`] circuits check the verifier's equations on both sides over
//! the stages of [`stages`]. [`extension`] lays the chunk circuits and their
//! stages out as a profile's extension (see [`profile`](crate::profile))
//! and registers them through the profile's hooks beside the fuse's
//! circuits, on both registries; [`prover`] fills their polynomials for
//! every proof from a compressed proof's prepared sides. The aggregator
//! profile declares it, at the aggregator rank: every chunk then runs in
//! every proof of that profile, over the canonical compressed proof the
//! application's [`Decompression`](crate::profile::Decompression) holds,
//! so each child carries the extension's polynomials, which
//! [`Shape`](crate::profile::Shape) counts, for the fuse to hash, evaluate
//! and fold, which the fuse's circuits carry at four times the wallet
//! rank's budget. The decompression
//! step runs the chunks over the wallet's proof it is given and outputs
//! that proof's header, which the statement circuit's claim holds to the
//! header the chunks verified.
//!
//! # What binds the two sides
//!
//! Everything that passes between the sides, the challenges the
//! scalar-field side lifts from their bits, the digits of the full-width
//! scalars each side scales the other curve's points by, and the
//! commitments of the runs of the scalar field's values and the host
//! curve's points the circuit-field transcript absorbs, is a witness the
//! receiving side allocates, chunk by chunk: a witness one chunk allocates
//! binds no other chunk's, so a chunk that scales by a challenge from bits
//! holds its bits' lift to the lifts stage slot the challenge's lift chunk
//! fills, and a scalar's digits are allocated once, across the parts of
//! its one scaling. What holds a witness to the sending side is the fuse's
//! design. The sending side holds the values in stage wires. The receiving
//! side recomputes the zero-alpha commitment from the values it took, or
//! takes the commitment itself as a witness, as the transcript does for a
//! run. Its binding circuit exposes the point for the proof's consumer to
//! hold to the stage's actual commitment through the circuit's claim (see
//! [`stages`] for the stages,
//! [`chunk::BindingCircuit`] for the circuit and
//! [`Binding`](crate::profile::Binding) for the consumer's check).
//!
//! Each run commitment binds the checked values before the transcript
//! squeezes the next challenge. In an honest proof, the unused coefficients
//! are zero and the commitment matches the one native verification computes
//! from the run values. The mask permits nonzero values in those slots,
//! so the circuit can derive different challenges for the same proof fields.
//! Both sides' checks use the challenges from that circuit transcript.
//! The soundness argument for the wallet header must account for adaptive
//! queries to the transcript in the random oracle model, including trials
//! with different unused coefficients. A bound covering those choices
//! across the full verifier remains to be established.
//!
//! # The step binding
//!
//! The chunks run in every proof of the profile, and what they verify is
//! the statement of one step alone, the decompression step, whose output
//! header the statement circuit's claim holds to the header they verified
//! ([`statement_ky`]). The same claim carries the step binding, four
//! values of the instance stage after the header: a flag, one in a proof
//! of the decompression step and zero in any other, the point and value
//! at which that step opened its first output slot, and the transcript
//! digest that step staged, all zero in any other. A step folds its own
//! application claim, so its openings stay in its own preamble: its
//! `hashes_1` exports these three after its output header and circuit
//! id, and the step that consumes its proof holds its copy to that
//! export
//! ([`StepBindingLen`](crate::recursion::native::online::StepBindingLen)).
//! Through them both IPAs' round challenges are fixed before the step's
//! challenge $\zeta = w$, and the host curve's $G'$ is bound:
//!
//! - The decompression step stages the transcript digest: the last
//!   squeeze of the compression's transcript over the proof it
//!   decompresses, taken after every round message of both curves' IPAs
//!   ([`Regions::digest`](program::Regions::digest)). The application
//!   stage holds it, so the proof commits it before $w$, and the step
//!   makes it public as the point at which it opens its left input's
//!   first slot ([`Decompress`]). Under the flag, the circuit-field side
//!   holds that value to the last squeeze of the transcript it runs. The
//!   transcript is one sponge over the statement and both curves'
//!   messages, and a round challenge is a squeeze of what was absorbed
//!   before it, so a prover who committed the digest before $w$ fixed
//!   both IPAs' round challenges then, unless it finds a second
//!   transcript with the same last squeeze, or the first for a digest it
//!   chose: a collision or a preimage in the sponge.
//! - The decompression step commits $s(X)$ of the host curve's IPA, over
//!   the round challenges of the proof it decompresses, in its first
//!   output slot, before $\zeta$, and opens the slot at $\zeta$. Its
//!   fuse proves the opening is of the committed polynomial, as it does
//!   an application's.
//! - Under the flag, the circuit-field side holds the opened value to
//!   [`ipa::s_at`] at that point over the round challenges its transcript
//!   squeezed. The committed polynomial and, by the digest, the round
//!   challenges were fixed before $\zeta$, so the two agree at $\zeta$
//!   only if the slot holds that proof's $s(X)$, except with the
//!   probability that $\zeta$ is a root of their difference: at most the
//!   rank's coefficient count over the size of the challenge's range.
//! - The flag crosses to the scalar-field side as a digit of the
//!   circuit-field side's digits stage, which that side's binding circuit
//!   recomputes. Its binding circuit also exposes a point the proof's
//!   consumer holds to the commitment of the proof's first output slot
//!   ([`Binding::online`](crate::profile::Binding::online)), and under
//!   the flag the side holds its $G'$ to that point. The slot's
//!   commitment is over the generators the IPA folds, with no other term,
//!   so it is $\langle s, G \rangle$.
//!
//! In any other step the flag is zero and nothing is held: the chunks
//! verify the canonical proof, whose statement is the unit header's and
//! binds nothing, and the slot is the application's.
//!
//! The nested curve's $s(X)$ is over the scalar field, which no output
//! slot holds, so its $G'$ is bound through the step's online polynomial
//! of that field ([`Profile::ONLINE_FQ_POLYS`](crate::profile::Profile::ONLINE_FQ_POLYS)),
//! which is the profile's own in every step, so its checks need no flag:
//!
//! - Every step commits $s(X)$ of the nested curve's IPA of the proof its
//!   chunks run over, the proof it decompresses or the canonical one, as
//!   that polynomial, before its challenge $w$, and its nested
//!   `compute_v` opens it at $\zeta_q$, the lift of $w$, and folds the
//!   opening into the step's own nested batch.
//! - The step exports the commitment and the opening to its parent, each
//!   through the instance of the fuse circuit that holds it:
//!   `bind_endoscalar`, which takes the commitment from the stage the
//!   walk does, and the nested `compute_v`. The chunks' binding circuits
//!   expose what they took, the circuit-field side its $G'$ and the
//!   scalar-field side an opening, and the parent computes both claims'
//!   $k(y)$ of each pair from one copy it holds
//!   ([`Binding::online`](crate::profile::Binding::online) and
//!   [`Binding::openings`](crate::profile::Binding::openings)). So the
//!   circuit-field side's $G'$ is the commitment the step made before
//!   $w$, and the opening the scalar-field side took is the one the step
//!   folded.
//! - The scalar-field side holds that opening's value to [`ipa::s_at`]
//!   at its point over the round challenges it holds, which the
//!   circuit-field side's transcript squeezed and its lifts stage binds.
//!   The argument is the host curve's: the polynomial was fixed before
//!   $w$, and so before $\zeta_q$, and in the decompression step the
//!   digest fixed the round challenges before $w$ too. There $\zeta_q$
//!   is the lift of a 143-bit endoscalar and the polynomials have at
//!   most $2^{15}$ coefficients at the aggregator rank, so another
//!   polynomial passes with probability at most $2^{-128}$.
//!
//! These checks run in every step, but only the decompression step
//! holds the digest. In any other step the round challenges of the proof
//! the chunks run over are not fixed before $w$, and the opening does not
//! establish that proof's $G'$; nothing rests on it, since that proof's
//! statement binds nothing.
//!
//! A decompressed proof's first output slot therefore holds $s(X)$, not
//! the constant one; the header types a decompressed statement can carry
//! leave their slots to padding, which `finalize_with` checks ([`Decompress`]).
//!
//! [`statement_ky`]: crate::recursion::native::stages::preamble::ProofInputs::statement_ky
//! [`Decompress`]: crate::step::internal::decompress
//!
//! # Registry evaluations
//!
//! The native verifier evaluates the wallet registry $m(W, X, Y)$ itself:
//! at the circuits' $\omega_c$ for the claims' wiring restrictions, at
//! the instance's opening point, and at the proof's and its children's
//! points for the values the wire bindings expect. The chunks read these
//! evaluations from the work stage, where the prover writes them
//! ([`Regions::restrictions`](program::Regions::restrictions),
//! [`Regions::restriction_at_w`](program::Regions::restriction_at_w) and
//! [`Regions::registry_values`](program::Regions::registry_values)), and
//! one chunk ([`Chunk::Online`](program::Chunk::Online)) holds every one of
//! them to the aggregator's online batch of its field, which [`online`]
//! declares:
//!
//! - Each evaluation is a value of one of nine restrictions $m(W, a, b)$
//!   of the registry, on each field. A step commits the nine before its
//!   challenge $w$, with their coordinates and the points they are read
//!   at in its online input stage, and claims each evaluation as an
//!   opening whose value is a wire of its online query stage. Its fuse
//!   batches the openings into its accumulator, as it does an
//!   application's.
//! - The source-registry mesh holds each committed polynomial to the
//!   wallet registry's restriction at its coordinates, through the
//!   outgoing restriction the step's parent inherits. Compression closes
//!   the root's: the verifier of an aggregator's compressed proof
//!   evaluates the wallet registry it holds, once per field.
//! - Every circuit of the extension loads the two online stages first, as
//!   the fuse's helper does, so the wires the chunks read are the ones
//!   the fuse committed. The chunks hold the input stage's coordinates
//!   and points to the values they derive from the compressed proof: the
//!   lifts of its compression's challenges, its fuse's challenges, its
//!   children's values and its circuits' domain points. The step commits
//!   that stage before its $w$, so the restrictions are fixed before the
//!   challenges that test them.
//! - The helper holds the proof's own circuit's domain point to the
//!   wallet registry's domain, as the native verifier holds the circuit
//!   id.
//!
//! The wallet application is so part of what a verifier of aggregator
//! proofs builds. The helper circuits fix the wallet registries' tags,
//! which makes them part of the aggregator's registry, and the terminal
//! checks evaluate the wallet registries themselves: an aggregator built
//! over another wallet application is another application, and a prover
//! who writes values of another registry, or of none, leaves a chunk or
//! the batch unsatisfied.
//!
//! # What remains
//!
//! One cost remains. Every proof of the profile carries the chunk
//! circuits' polynomials, so an aggregator step that decompresses nothing
//! still runs every chunk, over the wallet application's canonical
//! compressed proof: in a tree over $n$ wallet proofs, $n - 1$ of its
//! $2n - 1$ steps. Letting such a step carry an empty extension needs the
//! fuse to accept trivial claims for the extension's circuits under a
//! flag bound in the instance, so that a decompression step cannot claim
//! it; until then the cost is fixed per step.
//!
//! TODO: let a step that decompresses nothing carry an empty extension,
//! as above.
//!
//! The controls with the real circuits cover a wallet proof's
//! decompression, a relabelled one, mixed sides, swapped chunk circuits,
//! another application's registry, the dummy suffix and two levels of
//! recursion over decompressed proofs, and were checked against builds
//! with a check disabled: without the lifts-stage binding of a chunk's
//! challenge bits, or without the enforcement of a chunk's work-stage
//! writes, the chunk tests that target them fail.

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

pub(crate) mod aggregator;
pub(crate) mod batch;
pub(crate) mod chunk;
pub(crate) mod circuit;
pub(crate) mod derive;
pub(crate) mod extension;
pub(crate) mod ipa;
pub(crate) mod online;
pub(crate) mod program;
pub(crate) mod prover;
pub(crate) mod revdot;
pub(crate) mod run;
pub(crate) mod side;
pub(crate) mod stages;
#[cfg(test)]
pub(crate) mod transcript;

#[cfg(test)]
#[path = "../../tests/decompression/support.rs"]
pub(crate) mod support;

/// An element's powers $x^{2^i}$, for raising it to constant exponents by
/// square-and-multiply.
pub(crate) struct Powers<'dr, D: Driver<'dr>> {
    squares: Vec<Element<'dr, D>>,
}

impl<'dr, D: Driver<'dr>> Powers<'dr, D> {
    /// The squares of `base` up to $x^{2^{\text{bits} - 1}}$, so that every
    /// exponent below $2^\text{bits}$ can be formed. Costs `bits - 1`
    /// gates.
    pub(crate) fn new(dr: &mut D, base: &Element<'dr, D>, bits: u32) -> Result<Self> {
        let mut squares = Vec::with_capacity(bits as usize);
        let mut current = base.clone();
        for i in 0..bits {
            if i > 0 {
                current = current.square(dr)?;
            }
            squares.push(current.clone());
        }
        Ok(Powers { squares })
    }

    /// $x^{2^i}$ for each $i$ below the prepared bits, in order.
    pub(crate) fn squares(&self) -> &[Element<'dr, D>] {
        &self.squares
    }

    /// $x^e$ for the constant `exponent`: one gate per set bit beyond the
    /// first.
    ///
    /// # Panics
    ///
    /// Panics if the exponent needs more bits than [`new`](Self::new)
    /// prepared.
    pub(crate) fn pow(&self, dr: &mut D, exponent: usize) -> Result<Element<'dr, D>> {
        assert!(
            exponent >> self.squares.len() == 0,
            "exponent {exponent} exceeds the prepared {} bits",
            self.squares.len()
        );
        let mut result: Option<Element<'dr, D>> = None;
        for (i, square) in self.squares.iter().enumerate() {
            if (exponent >> i) & 1 == 1 {
                result = Some(match result {
                    None => square.clone(),
                    Some(acc) => acc.mul(dr, square)?,
                });
            }
        }
        Ok(result.unwrap_or_else(Element::one))
    }
}

/// $1, x, x^2, \ldots, x^{\text{count} - 1}$: `count - 2` gates.
pub(crate) fn consecutive_powers<'dr, D: Driver<'dr>>(
    dr: &mut D,
    base: &Element<'dr, D>,
    count: usize,
) -> Result<Vec<Element<'dr, D>>> {
    let mut powers: Vec<Element<'dr, D>> = Vec::with_capacity(count);
    for i in 0..count {
        let next = match i {
            0 => Element::one(),
            1 => base.clone(),
            _ => powers[i - 1].mul(dr, base)?,
        };
        powers.push(next);
    }
    Ok(powers)
}
