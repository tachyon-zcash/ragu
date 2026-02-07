# Nullifier Derivation

In **Orchard**, the nullifiers are used to prevent double-spends, resist faerie gold attacks, and are constructed to be circuit-friendly. To get these properties, Orchard's nullifier mixes several ingredients:

$$
\mathsf{nf} = \mathsf{Extract}_P((F_{\mathsf{nk}}(\rho) + \psi \mod p) \cdot G + \mathsf{cm}).
$$

**Tachyon** drops much of this machinery, specifically the notion of a global uniqueness requirement inside the formula, and settles for a simpler nullifier design:

$$
\mathsf{nf} = F_{\mathsf{nk}}(\Psi \parallel \mathsf{flavor})
$$

where $\Psi$ is the nullifier trapdoor (user-controlled randomness) and *flavor* is simply interpreted as an epoch-id. The observation here is that unlike the existing nullifier derivation in Orchard which requires a globally unique $\rho$ to the output note being spent, this simpler derivation doesn't require that and $\Psi$ is also not required to be unique.

## Proposed: Nullifier Derivation Scheme

We propose a more refined derivation scheme that adheres to the following properties and requirements:

1. **Range-restricted capability:** a delegated key $\Psi_t$ permits evaluating the nullifier PRF only for epochs $e$ with $0 \leq e \leq t$ (where $t$ is the epoch-ID bound), and never for any $e > t$. The service can therefore derive all past-epoch nullifiers up to $t$.

2. **Symmetric-only construction (no Discrete Log):** Nullifier derivation and delegation rely only on symmetric primitives, using SNARK-friendly hashing.

Dan Boneh and Brent Waters introduced the "Constrained Pseudorandom Functions and Their Applications" paper in 2013 which describes: "We put forward a new notion of pseudorandom functions (PRFs) we call *constrained PRFs*. In a standard PRF there is a master key $K$ that enables one to evaluate the function at all points in the domain of the function. In a constrained PRF it is possible to derive constrained keys $K_s$ from the master key $K$. A constrained key $K_s$ enables the evaluation of the PRF at a certain subset $S$ of the domain and nowhere else."

The paper mentions a **GGM (Goldreich-Goldwasser-Micali) Tree PRF** construction whereby:

- For a prefix $v \in \{0, 1\}^l$, the constrained key $k_v$ is the GGM node reached by following the bits of $v$ from the root,
- This enables the evaluation of $F(k, v \parallel x)$ for any $x \in \{0, 1\}^{n-|v|}$

This seems like a suitable candidate that satisfies the aforementioned requirements.

## API Design

Let $F_K$ be a GGM tree PRF instantiated from a Poseidon algebraic sponge construction. The wallet derives the master root key, $\mathsf{mk}$, for the GGM tree as $\mathsf{mk} = \mathsf{KDF}(\psi, \mathsf{nk})$.

1. **Compute the minimal prefix cover of $[0..t]$.**

   Decompose the integer range into power-of-two aligned subranges (dyadic intervals), and each subrange corresponds to a binary prefix over epoch bits.

2. **Derive and send the prefix node seeds.**

   From the wallet's root key, $\mathsf{mk}$, derive the GGM node seed $\Psi_t$ for each prefix and send those seeds to the oblivious syncing service. Importantly, a node seed authorizes PRF evaluation of the leaves only inside its subtree.

3. **Oblivious syncing service evaluates the PRF for authorized epochs.**

   The OSS can evaluate $F_{\mathsf{mk}}(e)$ for any $e \leq t$. Given an epoch $e \leq t$, the service picks the covering prefix (starts at the node whose subtree contains the requested epoch), walks the GGM path from that prefix key, $\Psi_t$, using the remaining bits of $e$, and evaluates the PRF to output nullifiers $\mathsf{nf}_e = F_{\mathsf{mk}}(e)$ (keyed PRF outputs). It cannot compute for any $e > t$ because it has no seeds for those subtrees.

4. **Chain state advances.**

   When the chain advances to $t' > t$, engage in the same protocol rounds and only send the delta for $(t..t']$.

## Privacy Considerations

The oblivious syncing service learns which epochs the wallet requested, and we can optionally pad with dummy epochs or perform some kind of local filtering over a broader range of nullifiers that we request.

## Motivation

The Oblivious Syncing Service (**OSS**) is granted key capability that allows it to derive nullifiers for a specified range of epochs, but never for any future epochs. When the wallet comes online, it will notify the service that the blockchain has advanced by a certain number of epochs. We then query the service to prove that our notes remain unspent. To do this, the service provides the new nullifiers for the relevant epochs, which can be used to construct the proof — so we must grant the service the capability to derive them.

From a bandwidth narrative, the wallet-service handshakes incurs an *amortized* bandwidth complexity (logarithmic in the delegation material) which is favorable.

## Assumptions

This currently assumes a fixed-depth tree.
