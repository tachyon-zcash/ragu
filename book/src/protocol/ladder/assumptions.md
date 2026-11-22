# Assumptions of the Argument

The ladder gives a reason, rung by rung, why a false claim does not survive.
Those reasons rest on the following assumptions, and on analysis that these
chapters do not supply.

- **Binding commitments.** No nontrivial linear relation among the generators is
  known, which is the
  [discrete log relation assumption](../construction/cycle.md#commitments). This
  is what "fixed before the challenge" relies on at every rung.
- **Extraction.** The arguments above speak of "the committed polynomial". To
  apply them to an arbitrary prover, an extractor must be able to produce that
  polynomial, with its degree bound, from the prover. Binding alone does not
  give this. It is a knowledge assumption on the commitment scheme.
- **Random oracle.** Poseidon is modeled as a random oracle
  ([rung 13](rung_13.md)). A bound on a cheating prover must count every
  transcript query, including discarded attempts.
- **Registry tags.** Each tag is a BLAKE2b hash of its registry's wiring
  polynomials ([rung 14](rung_14.md)), and what the tag rules out is argued with
  that hash modeled as a random oracle as well. The hash relies on circuit code
  that emits the same constraints every time it is synthesized. The code accepts
  a tag of zero, which has probability about $1 / |\F|$ over the hash for each
  registry. An argument that needs nonzero tags must add that term. The `Tag`
  documentation in `ragu_circuits::registry` bounds what trying many
  registries gains against a registry check whose challenges are full-width,
  as those of a fuse's native side are. The bound does not cover a registry
  check whose challenges have $143$ bits, as those of a fuse's nested side and
  of a compression on both curves do: an adaptive choice among registries
  against such a check needs further analysis.

Each individual test fails to detect an error with probability at most
$d / |S|$, where $d$ is on the order of $4n$ or of the number of claims. The set
$S$ depends on the challenge ([rung 11](rung_11.md)). Within a fuse it is nearly
all of $\F_p$ for the eight native challenges before $\beta$, and a set of
$2^{143}$ lifts for the native $\beta$ and for every nested challenge. The
compression's own challenges are lifts on both curves
([rung 16](rung_16.md)), so each of them ranges over $2^{143}$ values.

These are bounds on single tests. They do not by themselves give a security
level for the scheme. A full soundness statement must combine them across every
test in every node of an adversarially chosen tree, through an extraction
argument that handles recursion. The ladder explains why each merge preserves
falsehood. It is not that end-to-end proof.

Zero knowledge is a separate property that the protocol does not currently
provide. Uncompressed proofs contain witness polynomials, and compressed proofs
reveal evaluations of them. In the standard profile, [rerandomization] aims
to hide which valid input was used given the published application data and
a shared bootstrap proof. Joint hiding of the output fields remains unproved.

[rerandomization]: ../../implementation/proofs.md#rerandomization
