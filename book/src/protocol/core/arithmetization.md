# Arithmetization

> explain Bootle16 CS -> revdot product relation

**Additional Notation**:
We further generalize the power vector notation to arbitrary range $[n,m)$ in the
exponent: $\v{z^{n:m}}=(z^n,\ldots,z^{m-1})$.
Combining the power vector and vector reversal:
$\rv{z}^{\mathbf{n:2n}}=(z^{2n-1},\ldots,z^n)$ and
$\v{z^{2n:3n}}=(z^{2n},\ldots,z^{3n-1})$.

**Userful Facts**:
A few arithmetic facts (assume all vectors have the same length):
- $\dot{\v{a}\|\v{b}}{\v{c}\|\v{d}} = \dot{\v{a}}{\v{c}} + \dot{\v{b}}{\v{d}}$
- $\alpha\cdot \dot{\v{a}}{\v{c}} + \beta\cdot \dot{\v{b}}{\v{c}} =
\dot{\alpha\cdot\v{a}+\beta\cdot\v{b}}{\v{c}}$ where $\alpha,\beta\in\F$
- $\dot{\rv{a}}{\rv{a}}=\dot{\v{a}}{\v{a}}$
- $\dot{\rv{b}}{\rv{a} \circ \v{d}} = \dot{\v{b}}{\widehat{\rv{a}\circ\v{d}}}=
\dot{\v{b}}{\v{a}\circ\rv{d}}$

## Constraint System

The witness vectors $\v{a}, \v{b}, \v{c} \in \F^n$ must satisfy $n$ _multiplication constraints_, where the $i$th such constraint takes the form $\v{a}_i \cdot \v{b}_i = \v{c}_i$. In addition, the witness must satisfy a set of $4n$ _linear constraints_, where the $j$th such constraint is of the form

$$
\sum_{i = 0}^{n - 1} \big( \v{u}_{j,i} \cdot \mathbf{a}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{v}_{j,i} \cdot \mathbf{b}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{w}_{j,i} \cdot \mathbf{c}_i \big) =
\v{k}_j
$$

for some (sparse) public input vector $\v{k} \in \F^{4n}$ and fixed matrices $\v{u}, \v{v}, \v{w} \in \F^{n \times 4n}$, where $\v{u_{j}}, \v{v_{j}}, \v{w_{j}} \in \F^{4n}$ denote the _j-th row_ of those matrices. Because $n$ is fixed, individual circuits vary only by these matrices after this reduction.

## Multiplication Constraints

The multiplication constraints over the witness can be rewritten as
$\v{a} \circ \v{b} = \v{c}$. It is possible to _probabilistically_ reduce this
to a dot product claim using a random challenge $z \in \F$:

$$
\boxed{\v{a} \circ \v{b} = \v{c}} \;\Longleftrightarrow\;
\boxed{\sum_{i=0}^{n-1} z^{i}\,\big(\mathbf a_i \mathbf b_i - \mathbf c_i\big) = 0}
\;\Longleftrightarrow\;
\boxed{\dot{\v{a}}{\v{z^{n}} \circ \v{b}} - \dot{\v{c}}{\v{z^{n}}} = 0}.
$$

Define a [structured](../prelim/structured_vectors.md) witness vector
$\v{r}=(\v{c}\|\rv{b}\|\v{a}\|\v{0})\in\F^{4n}$ (with $\v{d}=\v{0^n}$).
Reminded that its reverse $\rv{r}=(\v{0}\|\rv{a}\|\v{b}\|\rv{c})$.
We observe the expansion:

$$
\begin{align*}
\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}}
&=\dot{\rv{b}}{\rv{a}\circ\v{z^{n:2n}}} + \dot{\v{a}}{\v{b}\circ\v{z^{2n:3n}}}\\
&=\dot{\v{b}}{\v{a}\circ\rv{z}^{\bf n:2n}} + \dot{\v{a}}{\v{b}\circ\v{z^{2n:3n}}}\\
&=(\rv{z}^{\bf n:2n} + \v{z}^{\bf 2n:3n})\cdot \dot{\v{a}}{\v{b}}
\end{align*}
$$

For any $z\in\F$, let
$\v{t} = (\v{0^{3n}}\|\, (\rv{z}^{\bf n:2n} + \v{z}^{\bf 2n:3n})\cdot \rv{1})$.
We observe the expansion:

$$
\revdot{\v{r}}{\v{t}}
=\dot{\rv{c}}{(\rv{z}^{\bf n:2n} + \v{z}^{\bf 2n:3n})\cdot \rv{1}}
=\dot{\v{c}}{(\rv{z}^{\bf n:2n} + \v{z}^{\bf 2n:3n})\cdot \v{1}}
$$

Therefore, for a random $z\sample\F$, the following expression holds with high
probability _if and only if_ all multiplication constraints are satisfied:

$$
\revdot{\v{r}}{\v{r}\circ\v{z^{4n}} - \v{t}} = 0
$$

<details>
<summary>Hints: what $\v{t}$ vector expands to</summary>
 
Let $\v{t'} =(\rv{z}^{\bf n:2n} + \v{z}^{\bf 2n:3n}) = [z^{2n-1-i}+z^{2n+i}]_{i=0}^{n-1}$.
    
The first $3n$ entries are all zeros, the last $n$ entries is the reversal of $\v{t'}$
 
$$
\v{t}=(\v{0}\|\v{0}\|\v{0}\|\rv{t'})
=(\v{0^{3n}}\| [z^{n+i} + z^{3n-1-i}]_{i=0}^{n-1})
$$
</details>

## Linear Constraints

Given a choice of witness $\v{a},\v{b},\v{c}$ and some random $y\sample\F$, if

$$
\sum_{j=0}^{q - 1} y^j \cdot \Bigg(
    \dot{\v{u}_j}{\v{a}} + \dot{\v{u}_j}{\v{b}} + \dot{\v{w}_j}{\v{c}} - \v{k}_j
\Bigg) = 0
$$

holds, then with high probability the $q$ linear constraints are all satisfied
as well. Let
$\v{s}=(\v{0}\| \sum_{j=0}^{q-1}y^j\cdot\rv{u}_j \| \sum_j y^j\cdot\v{v}_j \| \sum_j y^j\cdot \rv{w}_j)$,
where each subvector is a random linear combination of the wiring constraints,
we observe that:

$$
\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^q}}
$$

## Consolidated Constraints

The equation for enforcing _multiplication constraints_ (using random challenge
$z$) and _linear constraints_ (using random challenge $y$) can be combined into
a single equation:

$$
\revdot{\v{r}}{\v{s} + \v{r} \circ{\v{z^{4n}}} - \v{t}} = \dot{\v{k}}{\v{y^{4n}}}
$$

because $\v{r} \circ \v{z^{4n}} - \v{t}$ is made independent of $\v{s}$ by random
$z$ except at $\v{r}_0$, where $\v{s}_0 = 0$.
