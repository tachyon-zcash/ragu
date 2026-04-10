# Wiring Polynomials

Each circuit in Ragu has its own structured vector $\v{s}$ (determined by the
challenge $y$) used in the combined revdot check. This vector is the coefficient
vector of a bivariate **wiring polynomial** $s(X, Y)$ at the restriction $Y =
y$. Ragu never materializes wiring polynomials in their full coefficient form;
they are only accessed via restrictions (at $X$, or $Y$, or both) by specialized
evaluator drivers.

## Public Inputs and Outputs

All circuits place the verifier's public inputs in the first elements of $\v{k}$
so that the verifier can compute $\dot{\v{k}}{\v{y^{4n}}} = k(y)$ as the
evaluation of a low degree polynomial. During circuit synthesis,
constraints are inserted from highest to lowest degree. The evaluation drivers
(especially $s(x, y)$ and $s(X, y)$) use Horner's rule to evaluate the wiring
polynomial incrementally, and so the public input constraints (optimally) appear
last.

This natural design is why we sometimes refer to the public inputs as "public
outputs" from the perspective of the circuit itself, since they are
produced at the end of circuit synthesis—_not_ allocated a prescribed value that 
is then constrained. In our construction, this is ideal for efficiency, as it
encourages avoiding unnecessary wire allocations by constraining public inputs
in terms of every real wire.

## Layout

| trace $\uparrow$ | monomials | wiring $\downarrow$ | $Y^0$ | $\cdots$ | $Y^{4n-1}$ |
|:--:|:--:|:--:|:--:|:--:|:--:|
| $\left.\begin{array}{ll} \v{d}_0 & = \color{#dc2626}{\alpha} \\ \v{d}_1 \\ \vdots \\ \v{d}_{n-1} \end{array}\right\}\v{d}$ | $\begin{array}{c} X^{4n-1} \\ X^{4n-2} \\ \vdots \\ X^{3n} \end{array}$ | $\v{c}\left\{\begin{array}{c} \color{#7e22ce}{\v{c}_0} \\ \v{c}_1 \\ \vdots \\ \v{c}_{n-1} \end{array}\right.$ | $\begin{array}{c} \phantom{1} \\ \phantom{1} \\ \phantom{\vdots} \\ \phantom{1} \end{array}$ | $\vdots$ | $\begin{array}{c} \color{#7e22ce}{\kappa} \\ \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \end{array}$ |
| $\left.\begin{array}{ll} \v{a}_{n-1} \\ \vdots \\ \v{a}_1 \\ \v{a}_0 & = 0 \end{array}\right\}\v{a}$ | $\begin{array}{c} X^{3n-1} \\ \vdots \\ X^{2n+1} \\ X^{2n} \end{array}$ | $\v{b}\left\{\begin{array}{c} \v{b}_{n-1} \\ \vdots \\ \v{b}_1 \\ \color{blue}{\v{b}_0} \end{array}\right.$ | $\begin{array}{c} \phantom{1} \\ \phantom{\vdots} \\ \phantom{1} \\ \color{blue}{1} \end{array}$ | $\vdots$ | |
| $\left.\begin{array}{ll} \color{blue}{\v{b}_0} & = \color{blue}{1} \\ \v{b}_1 \\ \vdots \\ \v{b}_{n-1} \end{array}\right\}\v{b}$ | $\begin{array}{c} X^{2n-1} \\ X^{2n-2} \\ \vdots \\ X^n \end{array}$ | $\v{a}\left\{\begin{array}{c} \v{a}_0 \\ \v{a}_1 \\ \vdots \\ \v{a}_{n-1} \end{array}\right.$ | | $\vdots$ | |
| $\left.\begin{array}{ll} \v{c}_{n-1} \\ \vdots \\ \v{c}_1 \\ \color{#7e22ce}{\v{c}_0} & \color{#7e22ce}{= 0} \end{array}\right\}\v{c}$ | $\begin{array}{c} X^{n-1} \\ \vdots \\ X^1 \\ X^0 \end{array}$ | $\v{d}\left\{\begin{array}{c} \v{d}_{n-1} \\ \vdots \\ \v{d}_1 \\ \v{d}_0 \end{array}\right.$ | $\begin{array}{c} \phantom{1} \\ \phantom{\vdots} \\ \phantom{1} \\ \phantom{1} \end{array}$ | $\begin{array}{c} \phantom{\v{c}_0} \\ \phantom{\vdots} \\ \phantom{\v{c}_1} \\ \color{#dc2626}{s(0,Y)\!=\!0} \end{array}$ | $\begin{array}{c} \phantom{0} \\ \phantom{\vdots} \\ \phantom{0} \\ \phantom{\color{#dc2626}{0}} \end{array}$ |

Ragu reserves some of the layout of all wiring polynomials for special purposes.
The $0$th gate of all traces is used to reserve the constant wire $b_0 = 1$
(also called [`ONE`]) and an optional blinding wire $d_0 = \alpha$. The former
is enforced by the verifier in the $0$th constraint via $\v{k}_0 = 1$ when the
wiring polynomial is used for a circuit; other kinds of wiring polynomials
deliberately omit the $0$th constraint so that they are not satisfiable for
verifiers that set $k(Y) = 0$.

The last constraint (for $j = 4n - 1$) is reserved for the registry, which injects a
fixed value $\kappa$ into a meaningless constraint over the $\v{c}_0$ wire, ensuring
that all non-trivial evaluations of $s(X, Y)$ are unpredictable. This has no effect on
the trace, since $c_0 = 0$ is the only satisfying assignment in practice, which also
induces the property $r(0) = 0$.

Due to these special gates and constraints, wiring polynomials can only enforce
$4n - 2$ of their own unique constraints, and can only leverage $n - 1$ gates since
the first gate is special-purpose.

## Bonding Polynomials

Wiring polynomials that are not applied specifically to complete circuit traces
are called **bonding polynomials** and have the aforementioned property that
$s(X, 0) = 0$, or in other words that the first constraint is not enforced. This
ensures they cannot be substituted for circuit wiring polynomials. As with all
wiring polynomials, they must contain the $\kappa$ constraint.

These polynomials are exclusively used in revdots of the form
$\revdot{\v{r}}{\v{s}} = 0$.
Revdot checks against a shared bonding polynomial can be batched using a
challenge $z$: $\revdot{\sum_i z^i \v{r}_i}{\v{s}} = 0$.

### Masking Polynomials

Masking polynomials are bonding polynomials that are used to enforce that
partial trace polynomials (stages) only contain assignments at designated
positions.

We start with a masking polynomial that enforces the trace polynomial to be the
zero polynomial (i.e. all wire assignments are zeroes):

$$
s_{all}(X, Y) = \sum_i X^i Y^{\sigma(i)}
$$

where $\sigma$ is a permutation. The resulting wiring layout matrix is a
_permutation matrix_ where exactly one entry of each row and each columns is $1$
while the rest is all zeroes. Subsequently,
$\revdot{\v{r}}{\v{s}} = \sum_i \rv{r}_i \cdot y^{\sigma(i)} = 0$
enforces $\v{r} = \v{0}$.
To allow active sub-regions of the trace, we simply drop $X^i Y^{\sigma(i)}$
terms with the corresponding $X^i$ from the mask. This zeroes out the rows
of the permutation matrix, leaving those trace positions unconstrained with any
possible wire assignments. For example, unmasking/activating $\v{b}_{1\ldots 5}$
region requires $s_{all} -\sum_{i\in [2n+1, 2n+5]} X^i Y^{\sigma(i)}$.

The simplest permutation is $\sigma(i) = i$ which renders a masking polynomial
$\sum_i (XY)^i$ and the wiring matrix as the anti-diagonal permutation matrix.
All masking polynomials must satisfy $s(X, 0) = 0$ which leaves the four wires of
the SYSTEM gate (gate 0) unconstrained. Furthermore, like any wiring polynomial,
the registry key $\kappa$ needs to be injected in the last (reserved) constraint.
Thus, we could define a **global mask polynomial**

$$
\begin{aligned}
s_\text{global}(X, Y)
&= \sum_{i=0}^{4n - 1} (XY)^i - \sum_{j\in\{0, 2n-1, 2n, 4n-1 \}} (XY)^j &+ \kappa\cdot(XY)^{4n-1} \\
&= \sum_{i=0}^{4n - 1} (XY)^i - \left((XY)^{2n} + 1\right)\left((XY)^{2n-1} + 1\right) &+ \kappa\cdot(XY)^{4n-1}
\end{aligned}
$$

Given $g = \text{skip\_gates}$ (the starting active gate index) and
$m = \text{num\_gates}$ (the number of active gates in the stage), we can define
a specific stage polynomial's masking polynomial as $s_\text{global}$ subtracted
by a **notch polynomial**

$$
\sum\limits_{i=0}^{m - 1} \left( (XY)^{g + i} + (XY)^{2n - 1 - g - i} + (XY)^{2n + g + i} + (XY)^{4n - 1 - g - i} \right)
$$

### Routing Polynomials

More generally, non-overlapping stages can also have (linear) constraints
imposed between them, used to route information from one partial trace to
another during recursion.

[`ONE`]: ragu_core::drivers::Driver::ONE
