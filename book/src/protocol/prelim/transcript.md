# Transcript

Ragu employs a Fiat-Shamir transform to make the interactive proof protocol
non-interactive. The transcript construction uses
[Poseidon](https://eprint.iacr.org/2019/458) as the hash function for
challenge generation, modeling it as a
[random oracle](assumptions.md#random-oracle-model).

## Transcript Construction

Ragu's transcript construction differs from standard sponge-based approaches:

- **Single hash function over $\F_p$**: All transcript operations use a
  single Poseidon instance over the circuit field
- **Fixed-length hash usage**: The Poseidon permutation is effectively used
  as a fixed-length hash rather than as a full sponge construction
- **Hybrid commitment scheme**: The transcript combines two cryptographic
  primitives:
  - **Pedersen commitments**: Staging polynomials create Pedersen vector
    commitments (collision-resistant hashes of witness data)
  - **Poseidon hashing**: These commitments, along with other protocol
    elements, are absorbed into the Poseidon-based transcript

This hybrid approach leverages both the algebraic properties of Pedersen
commitments and Poseidon's random oracle properties.

## Domain Separation and Versioning {#domain-separation}

Every transcript starts from a protocol tag absorbed at construction, so
protocols with different interaction sequences never share a Poseidon state.
Two tags are in use:

| Tag | Covers |
| --- | --- |
| `ragu-pcd-v1` | the fuse protocol, from the preamble through the final stage; replayed by the [decider](../../appendix/terminology.md) and again by the compressed verifier |
| `ragu-ipa-v1` | [compression](../recursion/compression.md), from the compressed instance through the revdot reductions to the inner-product arguments |

The tags version the protocol, not the crates, and the prover and every
verifier path must agree on them. Proofs produced under an earlier tag do not
verify under a later one.

Absorption into the Poseidon state is additive, so absorbing a zero element is
indistinguishable from absorbing nothing. Ragu length-prefixes only the tag,
not the messages that follow it, unlike general-purpose transcript libraries.
The circuit code fixes the number and order of absorbed elements at every
point, so a prover that inserts or drops an element changes the sequence the
verifier replays, and the proof is rejected.
