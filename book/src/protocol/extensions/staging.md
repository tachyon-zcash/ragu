# Staging Polynomials

The simplest circuits in Ragu involve a single polynomial $r(X)$ that commits to the entire witness. However, in several subprotocols of the construction it is necessary to commit to $r(X)$ in _stages_. As examples:

1. It may be necessary to obtain a verifier challenge inside of a circuit, based on values already witnessed by the prover. However, to do this safely would require hashing all of the inputs within the circuit, which could be prohibitively expensive. **Partial witnesses are effectively Pedersen vector commitments, or collision resistant hashes, of possibly hundreds of wires.** Hashing commitments to these partial witnesses _is_ feasible and far more efficient.
2. It may be necessary for multiple circuits to operate over the same information, but may be prohibitively expensive for that information to be communicated via public inputs. If the prover could commit to the information partially beforehand, and then separate independent circuits could access that information _as though it were part of that circuit's witness_, it would also improve efficiency.

In order to support this, Ragu occasionally employs a concept called **staged witnesses.** The $r(X)$ of a circuit can be linearly decomposed into several pieces like so:

$$
r(X) = r'(X) + a(X) + b(X) + \cdots
$$

In this equation, $r(X)$ is the multi-stage witness polynomial with enforced linear and multiplication gates. However, the prover does not commit to $r(X)$ but instead commits to the components $r'(X), a(X), b(X), \cdots$ independently. The polynomial $r'(X)$ can be called the "final witness" (for a multi-stage circuit) and the polynomials $a(X), b(X), \cdots$ can be called "stage polynomials."

In order for this to be safe, e.g. $a(X)$ must be linearly independent of $r'(X), b(X), \cdots$, or in other words $a(X)$ should not contain allocated wires in locations that would overwrite or become overwritten by the other terms in the sum $r'(X) + a(X) + b(X) + \cdots$.

In order to enforce this, we use a special "stage mask" that performs a well-formed check on each of the stage polynomials. The stage mask is defined by the start and size of the portion of the partial witness that is reserved for that polynomial; in order to be safe, all wires in $a(X)$ should be set to zero if they are not within this range. The stage mask simply enforces that everything must be nonzero in this range via simple linear constraints.

In order to check that a stage polynomial satisfies this well-formed check, we perform a revdot claim like so:

$$\revdot{\v{a}}{\v{s}}$$

where $\v{s}$ is the polynomial derived from the stage mask. Notice, this is expressly different from the traditional revdot claim that would be seen in a full circuit evaluation, which takes the form

$$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{s} + \v{t}}
$$

because the stage polynomials must individually only be well-formed, not necessarily satisfy any multiplication constraints or any non-trivial linear constraints. Those are enforced on the stage (and the final witness) later in the multi-stage circuit.

Note that two stages that must be enforced in this way can share a revdot claim! That is, enforcing this on $\v{a}$ and $\v{b}$ can be combined using a challenge

$$\revdot{\v{a} + z \v{b}}{\v{s}}$$

because the linear constraints encoded in $\v{s}$ via the stage mask are only `enforce_zero` and **there are no public inputs for well-formedness checks**.