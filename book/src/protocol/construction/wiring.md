# Wiring and Instance Polynomials {#wiring}

The combined [verifier check](arithmetization.md#combinedcheck) aggregates the
circuit's $4n$ constraints into a single structured vector $\v{s}$, using powers
of $y \in \F$ as weights. The vector $\v{s}$ encodes the $Y = y$ restriction of
a bivariate **wiring polynomial** $s(X, Y)$. It is _this_ polynomial which is
fixed by the circuit definition (as it encodes the weights and their
corresponding wire associations), and the $\v{s}$ vector is one way it is
materialized in the protocol after a verifier challenge $y$ is sampled.

In practice, a proof never needs $s(X, Y)$ in its full bivariate form, only
partially or fully evaluated at concrete points.[^written-out] Circuits
synthesize into wiring polynomials through a procedural API—create a gate, add
a constraint, etc.—and [drivers](../../guide/drivers/index.md) interpret these
calls for different purposes. Because the protocol only ever requires (partial)
evaluations of wiring polynomials, the construction is organized around
per-driver specialization, with $s(X, Y)$ shaped to make each driver's
evaluation path efficient.

[^written-out]: The one place where a wiring polynomial is written out in full
    is the setup: to derive its [tag](registry.md#tag), a registry lists the
    nonzero monomials of every polynomial that it holds, once.

```admonish info
The protocol also requires the univariate restriction $s(x, Y)$ to be evaluated
and manipulated: a fuse [commits](batch.md#registry-chain) to a combination of
such restrictions, which is a polynomial in $Y$, before $y$ is drawn. In order
to provide for a homogeneous degree bound, the degree of $s(X, Y)$ is less than
$4n$ in each variable separately. As a consequence, there are only $4n$ possible
constraints in a circuit arithmetization.
```

For example, the driver that computes $s(x, y)$ uses [Horner's
rule](https://en.wikipedia.org/wiki/Horner%27s_method) as its evaluation loop.
Each newly emitted constraint folds into the accumulating wiring polynomial via
the update $s(X, Y) \leftarrow Y \cdot s(X, Y) + u(X)$, where $u(X)$ is the
constraint's linear form over wires. Among the constraints that a circuit emits
outside of any routine, this lands the first-emitted at the highest $Y$ power
and the last-emitted at $Y^0$.[^segments]

[^segments]: The constraints of each [routine](../../guide/routines.md) call
    form a separate segment, which occupies its own block of powers of $Y$
    above the constraints emitted outside of any routine. The same ordering
    holds within each block.

## Public Inputs {#public-inputs}

The instance vector $\v{k}$ records the expected values imposed by the circuit's
[constraints](arithmetization.md) on linear combinations of wires. Public input
constraints are designated constraints whose corresponding entries in $\v{k}$
are explicitly set during verification.

In practice, public inputs often represent the final outputs of a circuit
computation. For this reason, their constraints are emitted last, allowing them
to refer naturally to any previously emitted wire. Ragu therefore also refers to
them as "public outputs" when describing them from the circuit's perspective.

This gives the layout

$$
\v{k} = \bigl(\,
  \underbrace{1}_{\v{k}_0}\,,\;
  \underbrace{\v{k}_1, \ldots, \v{k}_\ell}_{\text{public outputs}}\,,\;
  \underbrace{0, \ldots, 0}_{\text{constraints}}\,
\bigr)
$$

because of the Horner ordering described above: the last emitted constraints
occupy the lowest powers of $Y$. This layout is also convenient for the
verifier, since $\v{k}$ represents the coefficients of a low-degree polynomial
$k(Y)$, the **instance polynomial**.

The first value, $\v{k}_0 = 1$, seeds the circuit with a stable constant value;
it acts like a public input that is always set to $1$.[^instance-literature]
The remaining entries of $\v{k}$ are implicitly zero because circuit
implementations only emit constraints through
[`enforce_zero`](ragu_core::drivers::Driver::enforce_zero).

A circuit writes its public outputs as a list of elements, and the constraint of
an element written earlier is emitted earlier. The first element written is
therefore $\v{k}_\ell$ and the last is $\v{k}_1$, and

$$
k(Y) = 1 + \sum_{j=1}^{\ell} \v{k}_j \, Y^j.
$$

Later pages write such a polynomial as a list in the order written,

$$
\text{Horner}_Y[c_1, \dots, c_m] = \sum_{j=1}^{m} c_j \, Y^{m-j},
$$

so that $k(Y) = \text{Horner}_Y[\v{k}_\ell, \dots, \v{k}_1, 1]$ and the first
entry of a list has the highest power. A circuit that writes the outputs $2$
and then $3$, for example, has

$$
k(Y) = \text{Horner}_Y[2, 3, 1] = 2 Y^2 + 3 Y + 1.
$$

The outputs take descending powers in the order written, and the `ONE`
constraint supplies the constant term.

[^instance-literature]: In the literature, the public instance is often
presented as the pair $(1, \v{x})$, combining the constant $1$ with the public
inputs $\v{x}$ into a single vector. Ragu's $\v{k}$ follows this convention.

## The `SYSTEM` Gate {#system-gate}

There is a special gate in all wiring polynomials called the `SYSTEM` gate,
which is the first gate over wires $\v{a}_0, \v{b}_0, \v{c}_0, \v{d}_0$:

* The wire $\color{blue}{\v{d}_0}$ is a special wire called [`ONE`] which is the
  constant wire; in wiring polynomials that verify circuits, it is enforced to
  equal $1$ through the final constraint, via $k(0) = s(X, 0) = X^0 = 1$. In a
  sense, the `ONE` wire stashes the $1$ value provided at $\v{k}_0$ by the
  verifier so that it is available in all future constraints.
* The $\color{#7e22ce}{\v{c}_0 = 0}$ wire assignment ensures $r(0) = 0$ for
  every trace. This assignment is forced by the gate equations when
  $\color{blue}{\v{d}_0 = 1}$ anyway.
* The $\color{#dc2626}{\v{a}_0}$ slot carries an arbitrary value
  $\color{#dc2626}{\gamma}$ for every trace, with $\v{b}_0 = 0$ chosen so the
  gate equations remain satisfied.[^conventionally] This value is meant to keep
  adversarially-determined linear combinations of polynomial commitments away
  from the point at infinity. It is also one of the three
  [free coefficients](#blind-gate) of a trace. The prover draws it uniformly at
  random for the trace of a circuit.

The presence of the `SYSTEM` gate reduces the number of usable gates to $n - 1$,
and the [blind gate](#blind-gate) reduces it to $n - 2$.

There is also a special constraint $\color{#7e22ce}{\kappa} \v{c}_0 = 0$
injected in all wiring polynomials at the $Y^{4n - 1}$ position; circuits are
restricted in the number of constraints they emit, to at most $4n - 1$, to avoid
overlapping this term. This so-called [registry constraint](registry.md#tag) is
trivially satisfied for all values of $\color{#7e22ce}{\kappa}$, since $\v{c}_0
= 0$ anyway. In practice, $\color{#7e22ce}{\kappa}$ is the public registry
binding tag: a hash of every wiring polynomial in the registry, written out as
its monomials, which the registry derives when it is finalized; see
[Registry Tags](../../guide/configuration.md#registry-tags). Its purpose is to
keep whoever chooses the circuits from adapting them to challenges already
derived: any change to the circuits' wiring polynomials changes
$\color{#7e22ce}{\kappa}$, and with it this coefficient of every wiring
polynomial. $\color{#7e22ce}{\kappa}$ is public, so the circuit author can
compute it too; the `Tag` documentation in `ragu_circuits::registry` bounds
what trying many circuits gains, and states what the tag trusts the circuit
code to do.

[^conventionally]: There is nothing preventing the roles of $\v{a}_0$ and
    $\v{b}_0$ from being swapped, since neither wire is actually constrained in
    practice. However, because $\v{a}_0$ and $\v{d}_0$ are used as "free" wires
    during allocation for symmetry, this is maintained in the `SYSTEM` gate as a
    convention.

## The Blind Gate {#blind-gate}

A fuse shows three values of every trace that it takes from a child on its
own: the commitment, which one of its [stages](stage_contents.md) holds, and
the evaluations at $xz$ and at $u$ that its [batched opening](batch.md)
claims.
Those values should not determine anything else about the trace. Every trace
therefore has three coefficients that no constraint reads, as many as the
values shown, and the prover draws them uniformly at random.

One of the three is the $\color{#dc2626}{\v{a}_0}$ of the `SYSTEM` gate. The
other two are wires of the **blind gate**, which is the last gate of every
circuit, over the wires $\v{a}_{n-1}, \v{b}_{n-1}, \v{c}_{n-1}, \v{d}_{n-1}$. A
circuit has at most $n - 1$ gates, the `SYSTEM` gate among them, so no circuit
allocates the blind gate, and no wiring polynomial has a weight for
$\v{a}_{n-1}$ or $\v{d}_{n-1}$. With $\v{b}_{n-1} = \v{c}_{n-1} = 0$ the gate
equations hold there for any values of those two wires.

We call $\v{a}_0$, $\v{a}_{n-1}$ and $\v{d}_{n-1}$ the **free coefficients** of
a trace. They are its coefficients of $X^{2n-1}$, $X^{n}$ and $X^{3n}$. When
all three are uniformly random, so are the commitment and the two evaluations,
whatever the other coefficients are.[^free-three]

The free coefficients protect a polynomial only in what a later fuse shows of
it on its own. That fuse also shows sums over a child's traces, through its
folded $B$. A proof stores its own polynomials in full, and its stages hold
the commitments and challenges of its children as they are. The free
coefficients are there for
[`Application::rerandomize`](ragu_pcd::Application::rerandomize), which also
relies on the randomizers every fuse folds and batches.

[^free-three]: The two evaluations fix the three coefficients up to a line,
    provided that the two points are distinct and nonzero. Along that line the
    commitment takes every value once, unless one combination of three
    [generators](cycle.md#commitments) is the identity, which would be a
    discrete log relation. The three coefficients and the three values then
    determine each other.

## Layout for Wiring Polynomials {#layout}

| trace $\uparrow$ | monomials | wiring $\downarrow$ | $Y^0$ | $\cdots$ | $Y^{4n-1}$ |
|:--:|:--:|:--:|:--:|:--:|:--:|
| $\left.\begin{array}{ll} \v{d}_0 & = \color{blue}{0 \, \text{or} \, 1} \\ \v{d}_1 \\ \vdots \\ \v{d}_{n-1} \end{array}\right\}\v{d}$ | $\begin{array}{c} X^{4n-1} \\ X^{4n-2} \\ \vdots \\ X^{3n} \end{array}$ | $\v{c}\left\{\begin{array}{c} \color{#7e22ce}{\v{c}_0} \\ \v{c}_1 \\ \vdots \\ \v{c}_{n-1} \end{array}\right.$ | $\begin{array}{c} \color{#7e22ce}{0} \\ \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \end{array}$ | $\begin{array}{c} \color{#7e22ce}{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \phantom{0} \end{array}$ | $\begin{array}{c} \color{#7e22ce}{\kappa} \\ \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \end{array}$ |
| $\left.\begin{array}{ll} \v{b}_{n-1} & \phantom{= 0 \, \text{or} \, 1} \\ \vdots \\ \v{b}_1 \\ \v{b}_0 & = 0 \end{array}\right\}\v{b}$ | $\begin{array}{c} X^{3n-1} \\ \vdots \\ X^{2n+1} \\ X^{2n} \end{array}$ | $\v{a}\left\{\begin{array}{c} \v{a}_{n-1} \\ \vdots \\ \v{a}_1 \\ \color{#dc2626}{\v{a}_0} \end{array}\right.$ | $\begin{array}{c} \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \color{#dc2626}{0} \end{array}$ | $\begin{array}{c} \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \color{#dc2626}{0} \end{array}$ | $\begin{array}{c} \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \color{#dc2626}{0} \end{array}$ |
| $\left.\begin{array}{ll} \color{#dc2626}{\v{a}_0} & = \color{#dc2626}{\gamma} \\ \v{a}_1 & \phantom{= 0 \, \text{or} \, 1} \\ \vdots \\ \v{a}_{n-1} \end{array}\right\}\v{a}$ | $\begin{array}{c} X^{2n-1} \\ X^{2n-2} \\ \vdots \\ X^n \end{array}$ | $\v{b}\left\{\begin{array}{c} \v{b}_0 \\ \v{b}_1 \\ \vdots \\ \v{b}_{n-1} \end{array}\right.$ | $\begin{array}{c} 0 \\ \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \end{array}$ | $\begin{array}{c} 0 \\ \phantom{\vdots} \\ \phantom{0} \\ \phantom{0} \end{array}$ | $\begin{array}{c} 0 \\ \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \end{array}$ |
| $\left.\begin{array}{ll} \v{c}_{n-1} & \phantom{= 0 \, \text{or} \, 1} \\ \vdots \\ \v{c}_1 \\ \color{#7e22ce}{\v{c}_0} & \color{#7e22ce}{= 0} \end{array}\right\}\v{c}$ | $\begin{array}{c} X^{n-1} \\ \vdots \\ X^1 \\ X^0 \end{array}$ | $\v{d}\left\{\begin{array}{c} \v{d}_{n-1} \\ \vdots \\ \v{d}_1 \\ \color{blue}{\v{d}_0} \end{array}\right.$ | $\begin{array}{c} \phantom{0 \, \text{or} \, 1} \\ \phantom{\vdots} \\ \phantom{0 \, \text{or} \, 1} \\ \color{blue}{0 \, \text{or} \, 1} \end{array}$ | $\begin{array}{c} \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \phantom{0} \end{array}$ | $\begin{array}{c} \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \phantom{0} \end{array}$ |

Beside each monomial of $X$, the table lists the wire that a trace holds there
and the wire whose weight a wiring polynomial holds there. The revdot product
pairs the two columns in opposite directions, as the arrows indicate, so that
each wire of the trace meets its own weight: a constraint's weight for
$\v{a}_i$ is its coefficient of $X^{2n+i}$, for $\v{b}_i$ of $X^{2n-1-i}$, for
$\v{c}_i$ of $X^{4n-1-i}$ and for $\v{d}_i$ of $X^{i}$. The columns of $Y$ show
the weights of the `SYSTEM` wires that all wiring polynomials have in common.

All wiring polynomials share the same layout. Circuit wiring polynomials have
$s(X, 0) = 1$ (because of the `ONE` constraint against $\v{k}_0$) but
[masks](staging.md#masks) skip this constraint with
$s(X, 0) = 0$. Likewise, $\v{d}_0$ is $1$ in the trace of a circuit and $0$ in a
[stage polynomial](staging.md#stage-polynomial).

[`ONE`]: ragu_core::drivers::Driver::ONE
