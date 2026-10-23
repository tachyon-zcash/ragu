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
//!   gadget over the allocated messages; host-curve points and scalar-field
//!   values, which lie in the other field, enter through bridges as the
//!   fuse's do, each the value at its position in a stage of the other
//!   side, so that the bridges sum to that stage's commitment (see
//!   [`stages`]).
//! - **Field identities.** The fold's weights and $W(r)$, the public parts
//!   of the folded claims, the split identity, the batch's $f(u)$ and $v$
//!   and the IPA's $b$ are arithmetic in one field: [`Element`] arithmetic
//!   in the circuit over that field, with inverses as advised witnesses.
//! - **Registry evaluations.** The native verifier evaluates the registry
//!   at $(w, r, y)$ and at the circuits' $\omega_c$. The circuit takes
//!   these as stage wires, for the new proof's decider to check against
//!   the registry as the fuse's query stage holds its own; that check is
//!   not yet made (see *What remains*).
//! - **Derived commitments.** $\[A\]$, the dilated and raw polynomials'
//!   commitments, the batched $\[p\]$ and the IPA's folded commitment are
//!   multi-scalar multiplications of the instance's points. Those live on
//!   the other curve, so the circuit over the points' base field derives
//!   them by endoscalar Horner chains, as the fuse's endoscaling steps do,
//!   which asks the compression to lift its point-multiplying challenges
//!   to endoscalars.
//! - **$G'$.** The IPA's final generator $G' = \langle s, G \rangle$ is the
//!   commitment to $s(X)$ over the same generators, so $s$ can be a
//!   polynomial of the decompression proof whose commitment is $G'$, with
//!   one evaluation of it deferred to the fuse that consumes the proof.
//!   Today the circuit takes $G'$ as a witness point (see *What remains*).
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
//!    as a gadget. *Done.* Binding $G'$ through $s(X)$ is in *What
//!    remains*, below.
//! 5. [`transcript`]: the compression's transcript over the allocated
//!    instance and messages, squeezing the native challenges. *Done*.
//! 6. [`derive`](mod@derive): the derived commitments, $\[H\]$ and the IPA's final
//!    check as endoscalar chains over the other curve's points, the
//!    compression's challenges squeezed as endoscalars for them. *Done.*
//! 7. [`circuit`]: the verifier assembled from the gadgets as the two
//!    circuits of the cycle, with the witness both allocate prepared from
//!    a compressed proof, and tested end to end under the simulators.
//!    *Done* up to the proof system's integration, below.
//! 8. [`program`], [`stages`], [`run`], [`side`] and [`chunk`]: each side
//!    cut into chunk circuits under the gate budget, every chunk loading
//!    the compressed proof's data from stages and leaving its results in
//!    a work stage for later chunks, with the prover's native run of the
//!    same program filling the stages. *Done*: every chunk of both sides
//!    fits the gate budget with its stages loaded, at the smallest rank
//!    the digits stage leaves room at and, with the chunks' limits scaled
//!    to its budget, at the aggregator rank, and is satisfied on a real
//!    compressed proof; a tampered stage fails some chunk. The chunk
//!    circuits take two ranks, the compressed proof's and their own, so
//!    that an aggregator at
//!    [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank) can
//!    cut a wallet's production-rank proof into fewer chunks, which pack
//!    into 52 native and 32 nested circuits at the tests' header size.
//! 9. [`extension`] and [`prover`]: the chunk circuits as the aggregator
//!    profile's extension, declared from pinned counts and registered
//!    through the profile's hooks, and their polynomials for every proof
//!    from the canonical compressed proof the application holds. *Done*:
//!    an aggregator application proves, verifies and compresses at the
//!    aggregator rank.
//! 10. The decompression step
//!     ([`decompress`](crate::step::internal::decompress)): the one step
//!     whose output header is the decompressed proof's, with the native
//!     extension's statement circuit ([`chunk::StatementCircuit`]) exposing
//!     the header the chunks verified and its claim's $k(y)$ holding the
//!     step's output header to it. *Done*: a wallet's compressed proof
//!     decompresses into a proof of the aggregator its own steps fuse, and
//!     a relabelled one fails.
//!
//! # Integration
//!
//! [`chunk`] is the complete verifier as circuits: every check the native
//! verifier makes runs in some chunk of one side or the other, over the
//! stages of [`stages`]. [`extension`] lays the chunk circuits and their
//! stages out as a profile's extension (see [`profile`](crate::profile))
//! and registers them through the profile's hooks beside the fuse's
//! circuits, on both registries; [`prover`] fills their polynomials for
//! every proof from a compressed proof's prepared sides. The aggregator
//! profile declares it, at the aggregator rank: every chunk then runs in
//! every proof of that profile, over the canonical compressed proof the
//! application's [`Decompression`](crate::profile::Decompression) holds,
//! so each child carries 98 more polynomials at the tests' header size
//! for the fuse to hash, evaluate and fold, which the fuse's circuits
//! carry at four times the production rank's budget. The decompression
//! step runs the chunks over the wallet's proof it is given and outputs
//! that proof's header, which the statement circuit's claim holds to the
//! header the chunks verified.
//!
//! # What binds the two sides
//!
//! Everything that passes between the sides, the challenges the
//! scalar-field side lifts from their bits, the digits of the full-width
//! scalars each side scales the other curve's points by, and the bridges
//! through which the circuit-field transcript absorbs the scalar field's
//! values and the host curve's points, is a witness the receiving side
//! allocates. What holds it to the sending side is the fuse's design: the
//! sending side holds the value as wires of an unblinded stage, the
//! receiving side recomputes that stage's commitment from the witness it
//! took, and its binding circuit exposes the recomputation for the
//! proof's consumer to hold to the stage's actual commitment, through the
//! circuit's claim (see [`stages`] for the stages,
//! [`chunk::BindingCircuit`] for the circuit and
//! [`Binding`](crate::profile::Binding) for the consumer's check). A
//! prover who prepares the two sides from different compressed proofs,
//! each consistent with itself, fails that claim.
//!
//! # What remains
//!
//! The decompression proof is sound for an honest prover, which is what
//! the end-to-end tests and the measurements cover, and not yet against a
//! dishonest one: two of the native verifier's checks are not enforced
//! on it, and a prover who skips either has the aggregator accept a
//! compressed proof the wallet's verifier would reject. In the verifier's
//! order:
//!
//! 1. **The registry's evaluations are unchecked.** The native verifier
//!    evaluates the wallet registry at $(w, r, y)$ and at the circuits'
//!    $\omega_c$ itself; the chunks read these evaluations from the work
//!    stage and take the values a prover writes there. The design is the
//!    fuse's query stage's: the decider recomputes the evaluations at the
//!    decompressed proof's challenges against the wallet registry and
//!    holds the stage's wires to them, through the polynomial-query hooks
//!    [#821](https://github.com/tachyon-zcash/ragu/pull/821) proposes, as
//!    $G'$ below does. Waits on #821. Until then nothing ties a proof to
//!    the canonical wallet application either: an aggregator that builds
//!    its [`Decompression`](crate::profile::Decompression) over a different
//!    wallet application, or writes values of no registry at all, has its
//!    proofs accepted. The check pins it once it exists, since the decider
//!    recomputes the evaluations from the wallet registry it holds, which
//!    makes the wallet application part of what a verifier of aggregator
//!    proofs builds. Pinning a digest of the wallet registry in the
//!    aggregator's registry tag is the alternative, still to decide.
//! 2. **$G'$ is unbound.** The IPA's final check takes $G' = \langle s,
//!    G \rangle$ as a witness point, so as the circuits stand that check
//!    binds nothing: a prover who chooses $G'$ satisfies it for any
//!    left-hand side. Everything before the IPA's final check is bound.
//!    $G'$ is the commitment to $s(X) = \prod_{i < k} (1 + u_{k-1-i}
//!    X^{2^i})$ over the same generators, so the fix is to witness $s$ as
//!    a polynomial of the decompression proof, take its commitment as
//!    $G'$, and defer one evaluation claim, $s$ at a fresh point against
//!    [`ipa::s_at`], to the fuse that consumes the proof. The hooks #821
//!    proposes, `witness_polynomial`, `derive_challenge` and
//!    `enforce_poly_query`, first drafted in
//!    [#783](https://github.com/tachyon-zcash/ragu/pull/783) and since
//!    closed, are exactly that for a circuit-field polynomial, which
//!    covers the host curve's $G'$. The nested curve's $G'$ is the
//!    commitment to a scalar-field polynomial on the nested curve, which
//!    those hooks do not reach, so it needs the same mechanism on the
//!    nested side. Waits on #821 and a nested counterpart.
//!
//! The two are independent and land in either order; the aggregator's
//! proofs are sound against a dishonest prover once both have.
//!
//! TODO: complete [`profile`](crate::profile)'s isolation follow-up: enforce the
//! outer aggregator's and inner wallet's expected setups, preserve Standard's
//! transcript domains, and test proof substitution through the recursive and
//! compressed verifiers. Setup identity does not replace the checks above.

// The chunk circuits use the gadgets piecewise. The whole-side verifier in
// `circuit` and the entry points only it calls, such as the transcript
// replay and the claim derivation, are reached from the tests alone.
#![allow(dead_code)]

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

pub(crate) mod batch;
pub(crate) mod chunk;
pub(crate) mod circuit;
pub(crate) mod derive;
pub(crate) mod extension;
pub(crate) mod ipa;
pub(crate) mod program;
pub(crate) mod prover;
pub(crate) mod revdot;
pub(crate) mod run;
pub(crate) mod side;
pub(crate) mod stages;
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
