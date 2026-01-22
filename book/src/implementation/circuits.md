# Circuit Representation

> Normal circuit, multi-stage circuits etc.

## Maybe Values

Explains the `Maybe<T>` abstraction for type-level encoding of optional witness data, enabling zero-cost optimizations.

## Witness Structure

The prover's witness $\v{r}$ is defined by $\v{a}, \v{b}, \v{c} \in \F^n$, where $n = 2^k$. Individual elements of this witness are known as _wires_—specifically, _allocated_ wires, because the prover must commit to them and thus they exist at a cost. They are referred to as "wires," rather than "variables," because they principally behave as inputs and outputs to multiplication gates.

Ragu defines the witness $\v{r}$ as the concatenation $\v{c} || \v{\hat{b}} || \v{a} || \v{0^n}$, which is an example of a [structured vector](../protocol/prelim/structured_vectors.md).

### Virtual Wires

The left-hand side of all linear constraints are linear combinations of elements within $\v{a}, \v{b}, \v{c}$. Any linear combination of wires can itself be considered a _virtual_ wire (as opposed to an allocated wire) which imposes no cost on the protocol.

### `ONE`

Circuits always have the specially-labeled `ONE` wire $\v{c}_0 = 1$. This is enforced with the [linear constraint](../protocol/prelim/cs.md#linear-constraints) $\v{c}_0 = \v{k}_0 = 1$.
