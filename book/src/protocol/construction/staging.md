# Stages and Bonding Polynomials {#staging}

The [combined check](arithmetization.md#combinedcheck) takes the trace of a
circuit as one polynomial $r(X)$. There are two situations in which a prover
commits to part of a trace on its own. A challenge may have to depend on that
part, so that its commitment must exist before the challenge is drawn. Or
several circuits may read the same wires, and equating those wires through
public inputs would cost each circuit constraints. Ragu therefore allows a trace
to be committed in pieces, and uses wiring polynomials of a second kind to keep
each piece in its place.

## Stages {#stages}

A **stage** is a block of consecutive gates whose wires are committed apart from
the circuits that read them. A stage is parameterized by two integers $(g, m)$
with $g \geq 1$, $m \geq 0$, and $g + m \leq n$; it owns the $m$ consecutive
gates $g, g+1, \ldots, g+m-1$ and their $4m$ wire positions. The code calls $g$
the stage's `skip_gates`.

Stages are built on top of one another. Each stage declares a parent and a
number of values, and its gates begin where the gates of its parent end:

$$
g = g_{\text{parent}} + m_{\text{parent}}, \qquad
m = \left\lceil \text{values} / 2 \right\rceil.
$$

The chain of parents ends at a root stage that has no values and starts after
the `SYSTEM` gate, with $(g, m) = (1, 0)$.

A gate holds two values of a stage. Value $k$ is in gate
$g + \lfloor k / 2 \rfloor$, on the wire $\v{a}$ if $k$ is even and on the wire
$\v{d}$ if $k$ is odd. With $\v{b}_i = \v{c}_i = 0$, the gate equations hold for
any $\v{a}_i$ and $\v{d}_i$, so these two wires are free to carry values. The
values are the wires of the stage's output gadget in field declaration order,
and a curve point contributes its $x$ coordinate and then its $y$ coordinate.

### Stage Polynomials {#stage-polynomial}

The **stage polynomial** of a stage with values $\nu_0, \nu_1, \ldots$ is the
partial trace that holds those values and one more coefficient, the
$\color{#dc2626}{\v{a}_0}$ of the [`SYSTEM` gate](wiring.md#system-gate):

$$
\color{#dc2626}{\v{a}_0} \, X^{2n-1}
+ \sum_{k \text{ even}} \nu_k \, X^{2n-1-g-k/2}
+ \sum_{k \text{ odd}} \nu_k \, X^{4n-1-g-(k-1)/2}.
$$

All of its other coefficients are zero. In particular $\v{d}_0 = 0$: a stage has
no `ONE` wire. Without $\color{#dc2626}{\v{a}_0}$, a stage polynomial could be
zero, or could cancel in a linear combination of stage polynomials, and either
would give a commitment at the point at infinity. The prover therefore draws
$\color{#dc2626}{\v{a}_0}$ uniformly at random, except in the few stages of the
scheme whose [contents](stage_contents.md#nested-stages) call for a value that
is fixed or derived.

Laid out beside the monomials of a trace, a stage polynomial has this form.

| trace $\uparrow$ | monomials | stage polynomial |
|:--:|:--:|:--:|
| $\left.\begin{array}{l} \v{d}_0 \\ \vdots \\ \v{d}_g \\ \vdots \\ \v{d}_{g+m-1} \\ \vdots \\ \v{d}_{n-1} \end{array}\right\}\v{d}$ | $\begin{array}{c} X^{4n-1} \\ \vdots \\ X^{4n-1-g} \\ \vdots \\ X^{4n-g-m} \\ \vdots \\ X^{3n} \end{array}$ | $\begin{array}{c} \color{blue}{0} \\ 0 \\ \nu_1 \\ \vdots \\ \nu_{2m-1} \\ 0 \\ 0 \end{array}$ |
| $\left.\begin{array}{l} \v{b}_{n-1} \\ \vdots \\ \v{b}_0 \end{array}\right\}\v{b}$ | $\begin{array}{c} X^{3n-1} \\ \vdots \\ X^{2n} \end{array}$ | $\begin{array}{c} 0 \\ \vdots \\ 0 \end{array}$ |
| $\left.\begin{array}{l} \color{#dc2626}{\v{a}_0} \\ \vdots \\ \v{a}_g \\ \vdots \\ \v{a}_{g+m-1} \\ \vdots \\ \v{a}_{n-1} \end{array}\right\}\v{a}$ | $\begin{array}{c} X^{2n-1} \\ \vdots \\ X^{2n-1-g} \\ \vdots \\ X^{2n-g-m} \\ \vdots \\ X^{n} \end{array}$ | $\begin{array}{c} \color{#dc2626}{\v{a}_0} \\ 0 \\ \nu_0 \\ \vdots \\ \nu_{2m-2} \\ 0 \\ 0 \end{array}$ |
| $\left.\begin{array}{l} \v{c}_{n-1} \\ \vdots \\ \v{c}_0 \end{array}\right\}\v{c}$ | $\begin{array}{c} X^{n-1} \\ \vdots \\ X^0 \end{array}$ | $\begin{array}{c} 0 \\ \vdots \\ \color{#7e22ce}{0} \end{array}$ |

The values fill the gates of the stage in order, two to a gate. A stage with an
odd number of values has no $\nu_{2m-1}$, and its last wire $\v{d}_{g+m-1}$ is
zero. When $g = 1$ the run of zeros before the stage is empty, and when
$g + m = n$ so is the run after it.

A circuit that reads a stage **loads** it: the circuit reserves the gates of the
stage and leaves them zero in its own witness. A circuit names one stage as its
last, and reserves the gates of every stage on the path from the root to that
stage, whether or not it loads them. What the prover commits for the circuit
itself is its **own polynomial**, the part of its trace that no stage
holds.[^final] The trace that enters the combined check is the sum of the own
polynomial and the polynomials of the stages that the circuit loads.

[^final]: The code calls the own polynomial the final stage of the circuit,
    which is where the final masks below get their name.

The gates that a circuit reserves for a stage carry none of the stage's own
constraints. A stage that is loaded **enforced** has the contracts of its output
gadget, such as curve membership of a point, re-emitted in the loading circuit.
A stage that is loaded **unenforced** has no constraint emitted, which leaves
those contracts to another circuit. A **skipped** stage only has its gates
reserved.

The sum is a trace of the circuit only if each summand stays within its own
gates, and the combined check does not say so: a stage polynomial with a nonzero
wire outside its gates would add to wires that the circuit or another stage
holds. Each stage polynomial and each own polynomial is therefore checked
separately.

## Bonding Polynomials {#bonding}

Wiring polynomials typically verify constraints for circuit traces, but there do
exist wiring polynomials that only enforce constraints on incomplete traces.
These exist internally to Ragu and are called **bonding polynomials**.

Unlike circuit wiring polynomials, which are checked with
$
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}} + \v{t} + \v{s}} = \dot{\v{k}}{\v{y^{4n}}}
$,
bonding polynomials instead appear in claims of the form
$\revdot{\v{r}}{\v{s}} = 0$, which do not enforce the gate equations on the
trace and permit batching.[^batching]

[^batching]: As an example, if two separate $\v{r_0}$ and $\v{r_1}$ must satisfy
a bonding revdot claim then $\revdot{z \v{r_0} + \v{r_1}}{\v{s}} = 0$ for a
random $z$ suffices to check both at once.

In order to distinguish these polynomials from ordinary circuit wiring
polynomials, the $0$th constraint is not emitted in bonding polynomials, forcing
$k(0) = s(X, 0) = 0$. The verifier enforces the kind of wiring polynomial by
choosing $\v{k}_0$, since the revdot claim alone does not distinguish the two.

### Masking Polynomials {#masks}

Masking polynomials are bonding polynomials used to constrain partial trace
polynomials so that nonzero wire assignments appear only at designated gate
positions.

The simplest theoretical mask $s_{\max}(X, Y) = \sum_{i=0}^{4n-1}(XY)^i$ would
zero every wire of every gate. Since `SYSTEM` gate wires are either unused or
constrained elsewhere, we instead use the _global mask polynomial_

$$s_{\text{global}}(X, Y) = s_{\max}(X, Y) - \bigl(1 + (XY)^{2n}\bigr)\bigl(1 + (XY)^{2n-1}\bigr),$$

which zeros every wire belonging to a non-`SYSTEM` gate (gates $1, 2, \ldots,
n-1$).

The **stage mask** of a stage $(g, m)$ is $s_{\text{global}}$ with the $4m$ wire
positions of the stage removed:

$$
\begin{array}{ll}
s_{\text{mask}}(X, Y) &= \color{#7e22ce}{\kappa}\color{black} \cdot (XY)^{4n - 1} + s_{\text{global}}(X, Y) \\
&- \bigl(1 + (XY)^{2n}\bigr)\bigl((XY)^g + (XY)^{2n-g-m}\bigr)\sum_{i=0}^{m-1}(XY)^i.
\end{array}
$$

Each monomial $(XY)^i$ of a mask is the constraint that one wire is zero, so the
stage mask forces to zero every wire of the gates $1, \ldots, n-1$ outside the
stage. It constrains no wire of the stage's own gates, so it does not force the
wires $\v{b}$ and $\v{c}$ there to be zero. Of the `SYSTEM` gate it constrains
only $\v{c}_0$, through the term $\color{#7e22ce}{\kappa} \cdot (XY)^{4n-1}$:
this is the [registry constraint](wiring.md#system-gate)
$\color{#7e22ce}{\kappa} \v{c}_0 = 0$, which every wiring polynomial carries.

The own polynomial of a circuit is confined by a mask of the same family. A
circuit whose last stage is $(g, m)$ reserves the gates $1, \ldots, g+m-1$, and
its own polynomial must be zero on all of them. The mask that says so has the
parameters $(g + m,\, n - g - m)$: it treats every gate from $g + m$ onward as
owned. It is called the **final mask** of the stage $(g, m)$.

A stage mask is claimed against the stage's polynomial. A final mask is claimed
against the own polynomials of the circuits whose last stage is the mask's
stage.

### Stripped Circuits {#stripped}

A bonding polynomial need not be a mask. A circuit that has no gates of its own,
only constraints among the wires of the stages that it loads, has no own
polynomial to commit, and nothing in it depends on the gate equations. Ragu
registers the wiring polynomial of such a circuit with its `ONE` constraint
stripped, so that $s(X, 0) = 0$. The result is a **stripped circuit**, and its
claim is a bonding claim over the sum of the stage polynomials that the circuit
loads.

## Layout of the Stage-Mask Bonding Polynomial {#mask-layout}

For the stage-mask bonding polynomial $s_{\text{mask}}(X, Y)$ defined above,
its coefficient matrix has the following four diagonal blocks:

| reversed trace | monomials          | $Y^0..Y^{n-1}$ | $Y^n..Y^{2n-1}$ | $Y^{2n}..Y^{3n-1}$ | $Y^{3n}..Y^{4n-1}$ |
|:--------:|:------------------:|:--------------:|:---------------:|:------------------:|:------------------:|
| $\v{d}$  | $X^0..X^{n-1}$     | $D_{\v{d}}$    | $\mathbf{0}$    | $\mathbf{0}$       | $\mathbf{0}$       |
| $\rv{b}$ | $X^n..X^{2n-1}$    | $\mathbf{0}$   | $D_{\rv{b}}$    | $\mathbf{0}$       | $\mathbf{0}$       |
| $\v{a}$  | $X^{2n}..X^{3n-1}$ | $\mathbf{0}$   | $\mathbf{0}$    | $D_{\v{a}}$        | $\mathbf{0}$       |
| $\rv{c}$ | $X^{3n}..X^{4n-1}$ | $\mathbf{0}$   | $\mathbf{0}$    | $\mathbf{0}$       | $D_{\rv{c}}$       |

In this stage-mask matrix, each diagonal block is an $n \times n$ main-diagonal
matrix with $1$ at every position where the corresponding wire is forced to $0$ (via
$\revdot{\v{r}}{\v{s}} = 0$) and $0$ at every stage-gate position that this mask
leaves unconstrained. The `SYSTEM` corners are also $0$, except that the
registry tag contribution changes the $\v{c}_0$ entry to $\kappa$, as explained
below.

The diagrams below show the generic case with distinct boundary positions. When
$m = 1$, the two labeled boundary entries coincide; when $g = 1$ or $g + m = n$,
the corresponding run of $1$s is empty and omitted. When $m = 0$, the stage owns
no gates and the carve-out is empty, so all non-`SYSTEM` positions remain masked.
A final mask always has $g + m = n$.

Drawing all four blocks (with
`SYSTEM`-wire $0$ subscripted by the wire name, stage $0$s subscripted only
at the boundaries of the carve-out, and plain $1$s in between):

$$
D_{\v{d}}^{(g,m)} =
\begin{bmatrix}
\color{blue}{0_{\v{d}_0}} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & 1 & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{d}_g} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{d}_{g+m-1}} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 1 & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 1 \\
\end{bmatrix}
\qquad
D_{\rv{b}}^{(g,m)} =
\begin{bmatrix}
1 & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & 1 & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{b}_{g+m-1}} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{b}_g} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 1 & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{b}_0} \\
\end{bmatrix}
$$

$$
D_{\v{a}}^{(g,m)} =
\begin{bmatrix}
\color{#dc2626}{0_{\v{a}_0}} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & 1 & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{a}_g} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{a}_{g+m-1}} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 1 & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 1 \\
\end{bmatrix}
\qquad
D_{\rv{c}}^{(g,m)} =
\begin{bmatrix}
1 & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & 1 & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{c}_{g+m-1}} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \ddots & \phantom{0} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 0_{\v{c}_g} & \phantom{0} & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & 1 & \phantom{0} \\
\phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \phantom{0} & \color{#7e22ce}{\kappa_{\v{c}_0}} \\
\end{bmatrix}
$$

The bottom-right of $D_{\rv{c}}$ holds $\color{#7e22ce}{\kappa}$ rather than
$0$: $\v{c}_0$'s `SYSTEM` exemption would put a $0$ at $(X^{4n-1}, Y^{4n-1})$,
but the registry adds $\kappa \cdot (XY)^{4n-1}$ at exactly that slot (see the
[`SYSTEM` gate](wiring.md#system-gate)), so the effective coefficient once the
bonding polynomial is assembled into the [registry polynomial](registry.md) is
$\kappa$. The other three `SYSTEM` corners stay $0$ — $\kappa$ touches only the
$\v{c}_0$ slot.

