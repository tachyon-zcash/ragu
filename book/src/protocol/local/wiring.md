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
evaluation of a low degree polynomial. During circuit synthesis, linear
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

### Masking Polynomials

Masking polynomials are bonding polynomials that are used to enforce that
partial trace polynomials (stages) only contain assignments at designated
positions.

We could naively define the simplest possible masking polynomial $\sum_i
(XY)^i$, since this could be used to enforce a (partial) trace contains no wire
assignments, and we could define all masking polynomials as a difference between
this global mask and a sparse polynomial. However, we must satisfy $s(X, 0) = 0$
for bonding polynomials.

Thus, we could define the global mask

$$
s_\text{global}(X, Y) = \sum_{i=0}^{4n - 1} (XY)^i - (XY)^{2n} - 1
$$

which enforces that every wire _except_ $b_0$ and $d_0$ are
zero. We must subtract $(XY)^{2n}$ to ensure $b_0$ is not enforced zero,
as it may be nonzero in a partial trace polynomial, and is constrained to
equal $1$ anyway by the circuit wiring polynomial. We must also subtract $1$
to ensure $s(X, 0) = 0$, which leaves $d_0$ free for use as an arbitrary
blinding factor.

Given $g = \text{skip\_gates}$ (the starting active gate index) and
$m = \text{num\_gates}$ (the number of active gates in the stage), we can define
a specific stage polynomial's masking polynomial as $s_\text{global}$ subtracted
by

$$
\sum\limits_{i=0}^{m - 1} \left( (XY)^{g + i} + (XY)^{2n - 1 - g - i} + (XY)^{2n + g + i} + (XY)^{4n - 1 - g - i} \right)
$$

### Routing Polynomials

More generally, non-overlapping stages can also have (linear) constraints
imposed between them, used to route information from one partial trace to
another during recursion.

[`ONE`]: ragu_core::drivers::Driver::ONE
