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
//!   and the IPA's $b$ are arithmetic in one field:
//!   [`Element`](ragu_primitives::Element) arithmetic in the circuit over
//!   that field, with inverses as advised witnesses.
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
//! The scalar checks are written once as [`Driver`](ragu_core::drivers::Driver)-generic gadget code
//! and run in the circuit over the matching field: the host curve's in the
//! native circuits, the nested curve's in the nested ones.
//!
//! # Layout
//!
//! - [`gadgets`]: the verifier's checks as gadgets: the fold and split,
//!   the batch's $f(u)$, $v$ and $\beta$ weights, and the IPA's round
//!   inverses, $b$ and final-check scalars, with $s$ at any point
//!   ([`ipa::s_at`](gadgets::ipa::s_at)), which the step binding checks
//!   an opening against; and the derived commitments, $\[H\]$ and the
//!   IPA's final check as endoscalar chains over the other curve's points.
//! - [`side`], [`program`], [`stages`] and [`circuits`]: each side cut into
//!   chunk circuits under the gate budget, every chunk loading the
//!   compressed proof's data from stages and leaving its results in a work
//!   stage for later chunks. The chunk circuits take two ranks, the
//!   compressed proof's and their own, so that an aggregator at
//!   [`AggregatorRank`](ragu_circuits::polynomials::AggregatorRank) cuts a
//!   wallet's wallet-rank proof into fewer chunks, whose circuit counts
//!   the aggregator profile pins
//!   ([`native_circuits`](crate::profile::Aggregator::native_circuits) and
//!   [`NESTED_CIRCUITS`](crate::profile::Aggregator::NESTED_CIRCUITS)).
//! - [`aggregator`] and [`online`]: the aggregator profile, which declares
//!   the chunk circuits as its extension from the pinned counts and
//!   registers them through its hooks, and its online batches, which
//!   hold the registry evaluations the chunks read.
//! - [`prover`]: the prover's native run of the same program filling the
//!   stages, and the extension's polynomials for every proof from the
//!   canonical compressed proof the application holds.
//! - The decompression step
//!   ([`decompress`](crate::step::internal::decompress)): the one step
//!   whose output header is the decompressed proof's, with the native
//!   extension's statement circuit
//!   ([`StatementCircuit`](circuits::StatementCircuit)) exposing the
//!   header the chunks verified and its claim's $k(y)$ holding the step's
//!   output header to it.
//!
//! The tests run the verifier assembled from the gadgets as two
//! whole-side circuits, one per field of the cycle, beside the chunks
//! (`tests/decompression/oracle.rs`).
//!
//! # Integration
//!
//! The [`circuits`] check the verifier's equations on both sides over
//! the stages of [`stages`]. [`aggregator`] lays the chunk circuits and their
//! stages out as a profile's extension (see [`profile`](crate::profile))
//! and registers them through the profile's hooks beside the fuse's
//! circuits, on both registries; [`prover`] fills their polynomials for
//! every proof from a compressed proof's prepared sides. The aggregator
//! profile declares it, at the aggregator rank: every chunk then runs in
//! every proof of that profile, over the canonical compressed proof the
//! application's [`Decompression`](crate::profile::Decompression) holds,
//! so each child carries the extension's polynomials, which
//! [`Shape`](crate::profile::Shape) counts, for the fuse to hash, evaluate
//! and fold, which the fuse's circuits do in pages at that rank, the
//! wallet's (see [`paging`](crate::profile::paging)). The decompression
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
//! [`BindingCircuit`](circuits::BindingCircuit) for the circuit and
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
//! ([`statement_ky`]). The same claim binds the step's circuit-id flag
//! and the digest the step staged. The step opens the bootstrap's first
//! slot at the staged digest and exports the point through `hashes_1`.
//! The native chunks hold the digest to the compression transcript's
//! last squeeze, fixing both IPAs' round messages before the step's $w$.
//!
//! The host IPA's $s(X)$ is a native profile batch polynomial committed
//! in BridgeSPrime, before the step's $y$, and opened at $y$. The native
//! chunks hold that PCS opening to [`ipa::s_at`](gadgets::ipa::s_at) over
//! the previously fixed round challenges. This tests equality of the
//! polynomials at a fresh point. The nested chunks hold the host IPA's
//! $G'$ to that batch commitment and hold both application output
//! commitments to their counterparts in the verified wallet proof.
//! The nested binding claim ties these points to the ones carried by
//! the aggregator proof. All three comparisons use the same flag,
//! bound by the recomputed native digits stage commitment.
//!
//! The nested IPA's $s(X)$ is a nested profile batch polynomial at the
//! same deadlines: committed before the step's $y$ and opened at the
//! lift of $y$. Its checks need no flag:
//!
//! - Every step commits $s(X)$ of the nested curve's IPA of the proof its
//!   chunks run over, the proof it decompresses or the canonical one.
//! - The nested chunks hold the PCS opening to
//!   [`ipa::s_at`](gadgets::ipa::s_at) at the lift of $y$, over the round
//!   challenges they hold, which the circuit-field side's transcript
//!   squeezed and its lifts stage binds.
//! - The native chunks take the nested IPA's $G'$ as a witness point and
//!   the native binding circuit exposes it. The native binding claim
//!   holds it to the batch commitment the step's walk folded
//!   ([`Binding::batch`](crate::profile::Binding::batch)). The parent
//!   computes that claim's $k(y)$ and the step's `bind_endoscalar`
//!   claim's from one copy of the commitment in its native preamble.
//! - The argument is the host curve's. The polynomial was fixed before
//!   $y$, and in the decompression step the digest fixed the round
//!   challenges before $w$, and so before $y$. The opening point is the
//!   lift of a 143-bit endoscalar and the polynomials have at most
//!   $2^{14}$ coefficients at the aggregator rank, so another polynomial
//!   passes with probability at most $2^{-128}$.
//!
//! The nested checks run in every step, but only the decompression step
//! holds the digest. In any other step the round challenges of the proof
//! the chunks run over are not fixed before $y$, and the opening does not
//! establish that proof's $G'$; nothing rests on it, since that proof's
//! statement binds nothing.
//!
//! The application can supply both polynomials when decompressing a
//! wallet proof. The output retains the wallet commitments and its
//! openings are checked by the usual PCS batch. Setup refuses an
//! aggregator that does not register every wallet output header.
//!
//! [`statement_ky`]: crate::internal::native::stages::preamble::ProofInputs::statement_ky
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

pub(crate) mod aggregator;
pub(crate) mod circuits;
pub(crate) mod gadgets;
pub(crate) mod online;
pub(crate) mod program;
pub(crate) mod prover;
pub(crate) mod side;
pub(crate) mod stages;

#[cfg(test)]
#[path = "../../tests/decompression/oracle.rs"]
pub(crate) mod oracle;
#[cfg(test)]
#[path = "../../tests/decompression/support.rs"]
pub(crate) mod support;
