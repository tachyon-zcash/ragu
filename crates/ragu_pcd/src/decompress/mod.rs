//! Proof decompression: a compressed proof verified inside a fresh
//! accumulator proof, so that the recursion can continue from it.
//!
//! [`Application::verify_compressed`](crate::Application::verify_compressed)
//! runs natively: it replays the compression's transcript, folds the revdot
//! claims and checks the split, the batch and one IPA opening per curve.
//! Decompression re-executes that verifier as circuits of a new proof over
//! the same cycle, so that the compressed proof's statement becomes an
//! ordinary accumulator the fuse can take as a child. Each kind of check
//! the native verifier makes has a circuit mechanism:
//!
//! - **Transcript.** The native verifier squeezes its challenges from a
//!   Poseidon transcript over the instance and its messages. The circuit
//!   replays it with the [`Transcript`](crate::internal::transcript::Transcript)
//!   gadget over the allocated messages; host-curve points, whose
//!   coordinates lie in the other field, enter through bridge-stage
//!   commitments as the fuse's do.
//! - **Field identities.** The fold's weights and $W(r)$, the public parts
//!   of the folded claims, the split identity, the batch's $f(u)$ and $v$
//!   and the IPA's $b$ are arithmetic in one field: [`Element`] arithmetic
//!   in the circuit over that field, with inverses as advised witnesses.
//! - **Registry evaluations.** The native verifier evaluates the registry
//!   at $(w, r, y)$ and at the circuits' $\omega_c$. The circuit takes
//!   these as stage wires the new proof's decider checks against the
//!   registry, as the fuse's query stage holds its own.
//! - **Derived commitments.** $\[A\]$, the dilated and raw polynomials'
//!   commitments, the batched $\[p\]$ and the IPA's folded commitment are
//!   multi-scalar multiplications of the instance's points. Those live on
//!   the other curve, so the circuit over the points' base field derives
//!   them by endoscalar Horner chains, as the fuse's endoscaling steps do,
//!   which asks the compression to lift its point-multiplying challenges
//!   to endoscalars.
//! - **$G'$.** The IPA's final generator $G' = \langle s, G \rangle$ is the
//!   commitment to $s(X)$ over the same generators, so $s(X)$ becomes a
//!   stage polynomial whose commitment is $G'$ and whose coefficients the
//!   circuit constrains from the round challenges.
//!
//! The scalar checks are written once as [`Driver`]-generic gadget code
//! and run in the circuit over the matching field: the host curve's in the
//! native circuits, the nested curve's in the nested ones.
//!
//! # Roadmap
//!
//! 1. This module and its design. *Done.*
//! 2. [`revdot`]: the fold and split as a gadget, tested against the
//!    native verifier on a real compressed proof. *Done.*
//! 3. [`batch`]: $f(u)$, $v$ and the $\beta$ weights as a gadget. *Done.*
//! 4. [`ipa`]: $b$, the round inverses and the scalars of the final check
//!    as a gadget. *Done.* $s(X)$ as a stage polynomial is item 7's.
//! 5. [`transcript`]: the compression's transcript over the allocated
//!    instance and messages, squeezing the native challenges. *Done*,
//!    with the bridges allocated; binding them is item 7's.
//! 6. The derived commitments, $\[H\]$ and the IPA folds as endoscalar
//!    Horner chains over the other curve's points. Needs the compression
//!    to squeeze endoscalar challenges, below.
//! 7. The decompression step: the circuits assembled into a proof the fuse
//!    takes as a child, with an end-to-end test from a compressed proof
//!    through decompression and a fuse back to compression.
//!
//! # What remains
//!
//! The gadgets re-execute every field check of the compressed verifier
//! over allocated inputs and squeeze its challenges. What stands between
//! them and a proof the fuse takes as a child changes the compression's
//! encoding and the proof's circuit set rather than a gadget:
//!
//! - **Circuits on both sides.** A circuit of a rank holds
//!   [`n`](ragu_circuits::polynomials::Rank::n) gates, $2^{11}$ for the
//!   production rank. The transcript gadget costs 33,746 gates and the
//!   revdot gadget 2,891 natively and 2,366 nested, so the verifier spreads
//!   over many circuits, as the fuse spreads over its internal circuits.
//!   The host curve's field checks and the nested curve's point
//!   derivations are arithmetic over the circuit field and run in native
//!   circuits; the nested curve's field checks and the host curve's point
//!   derivations are arithmetic over the scalar field and need nested
//!   circuits, which only the internal registry has. A chain of
//!   [`Step`](crate::step::Step)s can carry the transcript's saved state
//!   and partial results between native circuits in its headers, but
//!   cannot reach the scalar field, so the step registers internal
//!   circuits of its own on both registries, as the fuse does, or does the
//!   scalar field's arithmetic natively as foreign-field arithmetic at a
//!   far higher cost.
//! - **Bridges and registry wires as stages.** The transcript gadget
//!   absorbs each bridge as an allocated point and the revdot gadget takes
//!   the registry restrictions as allocated elements. In the fuse both are
//!   stage wires: the scalar field's values sit in a nested stage whose
//!   commitment is the bridge, and the restrictions in the query stage,
//!   which the decider checks against the registry. The decompression
//!   circuits need the same stages. The compression's bridge then becomes
//!   the commitment to such a stage, where today
//!   [`CycleTranscript`](crate::ipa::CycleTranscript) commits a point's
//!   two coordinates to the first two nested generators and a scalar to
//!   the first: the bridge's coefficient layout must follow the stage's.
//! - **Endoscalar challenges.** Every challenge that scales a point when a
//!   circuit derives a commitment must be an endoscalar as the fuse's are,
//!   so that the derivation is a Horner chain of
//!   [`group_scale`](ragu_primitives::Endoscalar::group_scale) steps and
//!   the field checks use its lift: $z$ in the bonding claims' weights, the
//!   fold's $\mu$, $\nu$, $\mu'$ and $\nu'$, the batch's $\beta$, and the
//!   IPA's $\xi$ and $u_j$. The compression squeezes full field elements
//!   today, so it must extract endoscalars from its squeezes by rejection
//!   sampling, as the fuse does, and its nested challenges become lifts
//!   rather than canonical integers. The IPA's $u_j^{-1}$ is no
//!   endoscalar: the circuit takes $u_j^{-1} L_j$ as a witness point and
//!   checks that $u_j$ times it is $L_j$. The prover's $c$ is a full
//!   scalar, so $c G'$ and $c b z U$ cost a full-width scalar
//!   multiplication each.
//! - **$G'$.** $G' = \langle s, G \rangle$ is the commitment to $s(X) =
//!   \prod_{i < k} (1 + u_{k-1-i} X^{2^i})$ over the same generators. As a
//!   stage polynomial of the decompression proof it is committed by the
//!   prover and bound to the round challenges by one evaluation: at a
//!   fresh point the decider opens the stage polynomial and the circuit
//!   computes [`ipa::s_at`] in $2k - 1$ gates. That opening is a revdot
//!   claim with a public $b$ the decider does not make today, so the
//!   decider's claims grow by one kind. The alternative is Halo's
//!   deferral, carrying $(G', u)$ in the accumulator for the next step
//!   to check, which the fuse's accumulator has no slot for.
//!
//! The first three change `compress` and the proof format together, so
//! they come as one change with the circuits that consume them; the
//! choice between the two ways to handle $G'$ decides whether the decider
//! changes too.

// The gadgets have no caller until the decompression step assembles them,
// so until then only their tests use them.
#![allow(dead_code)]

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

pub(crate) mod batch;
pub(crate) mod ipa;
pub(crate) mod revdot;
pub(crate) mod transcript;

#[cfg(test)]
#[path = "../../tests/decompress_support.rs"]
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
