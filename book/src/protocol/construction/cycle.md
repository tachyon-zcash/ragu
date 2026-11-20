# Curve Cycle {#cycle}

[Arithmetic circuits](arithmetization.md), their
[wiring polynomials](wiring.md), [stages](staging.md) and the
[registry](registry.md) are defined over one field $\F$. The scheme uses them
twice, over the two fields of a cycle of curves, and three things connect the
two uses: commitments, endoscalars and the transcript.

## Fields and Curves {#fields}

We write $\F_p$ and $\F_q$ for the two fields. $\E_p$ is the curve over $\F_p$
whose scalar field is $\F_q$, and $\E_q$ is the curve over $\F_q$ whose scalar
field is $\F_p$. For the Pasta cycle, $\F_p$ and $\F_q$ are the base and scalar
fields of Pallas, $\E_p$ is Pallas and $\E_q$ is Vesta. The wallet rank
(`WalletRank`) is $13$, so $n = 2^{11}$ and a polynomial has $2^{13}$
coefficients.

An object over $\F_p$ is **native** and an object over $\F_q$ is **nested**. A
subscript $q$ marks the nested counterpart of a native object, as in $m_q$,
$A_q$, $p_q$ and $c_q$.

## Commitments {#commitments}

Each curve has a vector of generators $G_0, \dots, G_{4n - 1}$. A polynomial
$\phi(X) = \sum_i \phi_i X^i$ with $4n$ coefficients is committed as

$$[\phi] = \sum_{i=0}^{4n-1} \phi_i \cdot G_i.$$

A polynomial over $\F_p$ is committed with the generators of $\E_q$, and its
commitment is a point of $\E_q$. A polynomial over $\F_q$ is committed with the
generators of $\E_p$, and its commitment is a point of $\E_p$. A commitment
takes the mark of its polynomial, so the commitment $P_q$ of $p_q$ is a point of
$\E_p$.

The generators of a curve are outputs of a hash to that curve, so that no linear
relation among them is known. A commitment binds the prover to its polynomial
for as long as none is found: two polynomials with the same commitment differ by
a nonzero $\delta$ for which $[\delta]$ is the identity. That no such $\delta$
can feasibly be found is the **discrete log relation assumption**. It rests on
the elliptic-curve discrete logarithm problem (ECDLP), which is to find $a$
given a point $G$ and its multiple $a \cdot G$: for generators that are
independent and uniformly random, as the outputs of the hash are modeled to be,
a method that finds relations also finds discrete logarithms.

Commitments have no separate blinding generator. The one coefficient of a trace
that
carries an arbitrary value is that of $X^{2n - 1}$, the
[$\v{a}_0$ of the `SYSTEM` gate](wiring.md#system-gate).

## Endoscalars {#endoscalars}

Challenges are drawn over $\F_p$ only. The nested side uses each of them as an
element of $\F_q$, and circuits on both sides multiply curve points by them. A
challenge crosses the cycle as an **endoscalar**, a string of bits that either
field can turn into one of its own elements.

An endoscalar has $143$ bits. Bits $0$ and $1$ are a sign $s_0$ and a selector
$e_0$. The remaining $141$ bits form $47$ digits, and digit $i$ has a sign
$s'_i$ at bit $2 + 3i$ and selectors $e_{1,i}$, $e_{2,i}$ at bits $3 + 3i$ and
$4 + 3i$.

For a field element $\chi$ whose canonical integer is below $2^{254}$,
$\text{endo}(\chi)$ is its low $143$ bits. It is undefined otherwise.

With $\lambda$ the field's chosen primitive cube root of unity, the **lift** of
an endoscalar is

$$\text{lift}(e) = 2 \cdot 3^{47} (-1)^{s_0} \lambda^{e_0} + \sum_{i=0}^{46} 3^{46-i} (-1)^{s'_i} \, v_i, \qquad v_i = \begin{cases} 1 & (e_{1,i}, e_{2,i}) = (0, 0) \\ \lambda & (1, 0) \\ \lambda^2 & (0, 1) \\ 1 - \lambda & (1, 1) \end{cases}$$

$\text{lift}_p$ and $\text{lift}_q$ are this formula in $\F_p$ and $\F_q$. The
nested counterpart of a native challenge $\chi$ is

$$\chi_q = \text{lift}_q(\text{endo}(\chi)).$$

A challenge that is uniform below $2^{254}$ has a uniform endoscalar, and
different endoscalars have different lifts in either field.[^injective] The lift
of such a challenge is therefore uniform on a set of $2^{143}$ elements, and it
determines the endoscalar that it was lifted from.

Endoscaling a curve point $C$ by $e$ computes $\text{lift}(e) \cdot C$, with the
lift taken in the scalar field of $C$'s curve. The curve has an endomorphism
$(x, y) \mapsto (\zeta x, y)$, for a cube root of unity $\zeta$ of its
coordinate field, that multiplies every point by the $\lambda$ of the scalar
field. Endoscaling starts from $A_0 = 2 (-1)^{s_0} \lambda^{e_0} \cdot C$ and
takes in one digit at a time,[^radix]

$$A_{i+1} = 3 \cdot A_i + (-1)^{s'_i} \, v_i \cdot C \quad (i = 0, \dots, 46),$$

so that $A_{47} = \text{lift}(e) \cdot C$. The circuit that runs this recurrence
is over the coordinate field of the curve. A circuit over $\F_q$ thus computes
$\text{lift}_p(e) \cdot C$ for $C \in \E_q$, and a circuit over $\F_p$ computes
$\text{lift}_q(e) \cdot C$ for $C \in \E_p$. The point must not be the identity.

A **hoisted** endoscalar is the $143$ bits together with $94$ product wires, two
per digit: $e_{1,i} e_{2,i}$ and $e_{1,i} e_{2,i} s'_i$. With the products as
wires, an endoscaling selects each digit's multiple of $C$ in two gates rather
than three, which brings its cost from $480$ gates to $433$. The products are
worth their wires when many circuits scale by one endoscalar, as the circuits of
a [walk](walks.md) do: they are allocated once, in a stage that those circuits
share.

[^injective]: The formula of the lift also defines an element of the ring
    $\mathbb{Z}[\lambda]$, in which $\lambda^2 + \lambda + 1 = 0$. There the
    eight values $\pm 1, \pm \lambda, \pm \lambda^2, \pm (1 - \lambda)$ of a
    digit are the nonzero residues modulo $3$, so the digits can be recovered
    one at a time, and two endoscalars that give the same element are equal.
    Different elements stay different in $\F_p$ and in $\F_q$: an element that
    maps to zero in a field of characteristic $r$ has a norm divisible by $r$,
    and the difference of two of these elements has a norm below $2^{156}$. The
    formal verification of the gadgets proves this for both fields, as
    `LiftInjectivity`.

[^radix]: Endoscaling was introduced in
    [Halo](https://eprint.iacr.org/2019/1021), where the running point is
    doubled once for every two bits of the endoscalar. Tripling it once for
    every three bits costs fewer gates per bit.

## Transcript {#transcript}

A fuse has one transcript, a Poseidon sponge over $\F_p$ with state width $5$
and rate $4$. The nested side squeezes nothing: every challenge that it uses is
the lift of a native one. The sponge has these operations.

- An absorb buffers its element. If the buffer already holds $4$ elements, the
  sponge first adds the buffer into the state and permutes.
- A squeeze, if elements are buffered, adds them into the state, permutes and
  returns state element $0$. Later squeezes return elements $1$, $2$, $3$ before
  the sponge permutes again.
- An absorb after a squeeze continues from the same state, and the elements not
  yet squeezed are dropped.
- A save adds the buffer into the state, permutes and outputs the $5$ state
  elements.
- A resume starts squeezing from a saved state, and the next squeezes return
  elements $0$, $1$, $2$, $3$ of that state.

The transcript starts by absorbing the byte length of the tag `ragu-pcd-v1` and
then the tag as one field element. The tag keeps protocols with different
sequences of messages from sharing a sponge state:
[compression](../recursion/compression.md) runs a transcript of its own, under
the tag `ragu-ipa-v1`. A tag names a version of the protocol, not of a crate. It
changes whenever the transcript's schedule, an encoding, the derivation of a
challenge or the meaning of a check changes incompatibly, and a proof made under
one tag does not verify under another.

A curve point is absorbed as its $x$ coordinate followed by its $y$ coordinate.
Every point that the transcript absorbs is a point of $\E_p$.

Absorption is additive and unpadded. The sequence of absorbs and squeezes is
determined by the protocol, so no length prefix is needed.

## Notation {#notation}

A fuse has two children, indexed by $i \in \{0, 1\}$ for left and right. An
object of child $i$ carries the superscript $(i)$, as in $x^{(i)}$, $A^{(i)}$ or
$P^{(i)}$. Objects of the current fuse are unadorned.

The challenges of a fuse are
$w, y, z, \mu, \mu', x, \alpha, u, \text{pre\_beta} \in \F_p$, in the
[order](protocol.md#rounds) in which they are drawn. An uppercase $W$, $X$, $Y$
or $Z$ is a variable, and the lowercase letter is the challenge substituted for
it.

An **rx polynomial** is either a [stage polynomial](staging.md#stage-polynomial)
or the own polynomial of a circuit. The rx polynomials that a proof stores are
indexed in the code by an enum on each side, and we name each polynomial by its
variant:
$r[\texttt{Preamble}]$ is the native rx polynomial at
`native::RxIndex::Preamble`, and $r_q[\texttt{BridgePreamble}]$ is the nested
one at `nested::RxIndex::BridgePreamble`. Their commitments are written
$R[\texttt{Preamble}]$ and $R_q[\texttt{BridgePreamble}]$.

| Symbol | Meaning | Code |
|---|---|---|
| $\F_p$ | native field | `C::CircuitField` |
| $\F_q$ | nested field | `C::ScalarField` |
| $\E_p$ | curve over $\F_p$ with scalar field $\F_q$ | `C::NestedCurve` |
| $\E_q$ | curve over $\F_q$ with scalar field $\F_p$ | `C::HostCurve` |
| $n$ | gates per circuit, $2^{\text{RANK} - 2}$; a polynomial has $4n$ coefficients | `Rank::n()` |
| $[\phi]$ | commitment of the polynomial $\phi$ | `sparse_commit_to_affine` |
| $\revdot{\phi}{\phi'}$ | [revdot product](arithmetization.md) | `Polynomial::revdot` |
| $\text{Horner}_t[c_1, \dots, c_k]$ | $\sum_{j=1}^{k} c_j \, t^{k - j}$, a [list in the order written](wiring.md#public-inputs) | `Horner`, `Polynomial::fold` |
| $\text{endo}(\chi)$ | endoscalar of a native challenge $\chi$ | `extract_endoscalar` |
| $\text{lift}_p$, $\text{lift}_q$ | lift of an endoscalar into $\F_p$, $\F_q$ | `lift_endoscalar` |

The code uses Horner lists for $k(y)$, for folding polynomials with $z$, and for
both batching challenges.
