# Fiat-Shamir Transcript

Ragu employs a Fiat-Shamir transform to make the interactive proof protocol non-interactive. The transcript construction uses [Poseidon](https://eprint.iacr.org/2019/458) as the hash function for challenge generation.

## Poseidon as Random Oracle

**Security Assumption:** Poseidon is modeled as a **random oracle**, not merely as a collision-resistant hash function. This is a stronger assumption than collision resistance alone. When properly instantiated with appropriate parameters, Poseidon is believed to be indistinguishable from a random oracle.

## Transcript Construction

Ragu's transcript construction differs from standard sponge-based approaches:

- **Single hash function over $\F_p$**: All transcript operations use a single Poseidon instance over the circuit field
- **Fixed-length hash usage**: The Poseidon permutation is effectively used as a fixed-length hash rather than as a full sponge construction
- **Hybrid commitment scheme**: The transcript combines two cryptographic primitives:
  - **Pedersen commitments**: Staging polynomials create Pedersen vector commitments (collision-resistant hashes of witness data)
  - **Poseidon hashing**: These commitments, along with other protocol elements, are absorbed into the Poseidon-based transcript

This hybrid approach leverages both the algebraic properties of Pedersen commitments and Poseidon's random oracle properties.
