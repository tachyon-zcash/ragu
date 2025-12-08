# Arithmetization

> explain Bootle16 CS -> revdot product relation

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

The multiplication constraints over the witness can be rewritten as $\v{a} \circ \v{b} = \v{c}$. It is possible to _probabilistically_ reduce this to a dot product claim using a random challenge $z \in \F$:

$$
\boxed{\v{a} \circ \v{b} = \v{c}} \;\Longleftrightarrow\; \boxed{\sum_{i=0}^{n-1} z^{i}\,\big(\mathbf a_i \mathbf b_i - \mathbf c_i\big) = 0} \;\Longleftrightarrow\; \boxed{\dot{\v{a}}{\v{z^{n}} \circ \v{b}} - \dot{\v{c}}{\v{z^{n}}} = 0}.
$$

By the definition of $\v{r}$ (as a [structured vector](../prelim/structured_vectors.md)) we can
do something identical. Observe the expansion

$$\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}} =

\sum\limits_{i = 0}^{n - 1} \Big(
  \v{a}_i \v{b}_i  \big( \textcolor{green}{z^{2n - 1 - i} + z^{2n + i} } \big)
+ {\v{c}_i \v{d}_i}  \big( {z^{i} + z^{4n - 1 - i}} \big)
\Big)

$$

and notice that for all $z \in \F$ and for any choice of $\v{r}$ there exists a unique vector[^tvectorcomputation] $\v{t} \in \F^{4n}$ such that

$$
\revdot{\v{r}}{\v{t}} = -\sum_{i = 0}^{n - 1} \v{c}_i \Big( \textcolor{green}{ z^{2n - 1 - i} + z^{2n + i} } \Big)
$$

and so by adding the two equalities, we get

$$
\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} + \v{t}} = 
\sum\limits_{i = 0}^{n - 1} \Big(
  (\textcolor{blue}{\v{a}_i \v{b}_i - \v{c}_i})  \big( \textcolor{green}{z^{2n - 1 - i} + z^{2n + i} } \big)
 + {\v{c}_i \v{d}_i}  \big( {z^{i} + z^{4n - 1 - i}} \big)
\Big).
$$

Therefore, if the expression

$$
\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} + \v{t}} = 0
$$

holds for a random $z$, then $\textcolor{blue}{\v{a} \circ \v{b} = \v{c}}$ and ${\v{c} \circ \v{d} = \v{0^n}}$ each hold with high probability. (The latter claim is useless and redundant for our purposes, since $\v{d} = \v{0^n}$ for witness vectors anyway.)

## Linear Constraints

Given a choice of witness $\v{a}, \v{b}, \v{c}$, if for some random choice of $y \in \F$ the equality

$$
\sum_{j=0}^{4n - 1} y^j \Bigg(
    \sum_{i = 0}^{n - 1} \big( \v{u}_{j,i} \cdot \mathbf{a}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{v}_{j,i} \cdot \mathbf{b}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{w}_{j,i} \cdot \mathbf{c}_i \big)
\Bigg) =
\sum_{j=0}^{4n - 1} y^j \v{k}_j
$$

holds, then with high probability the $4n$ linear constraints are all satisfied as well. It is possible to define a vector $\v{s}$ such that this is equivalent to

$$
\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}
$$

for some structured [witness]() vector $\v{r}$.

To define $\v{s}$, rewrite the above expression into

$$
\sum_{i=0}^{n-1}a_{i} \big( \sum_{j=0}^{4n-1}y^{j} \cdot u_{j,i}  \big) + \sum_{i=0}^{n-1}b_{i} \big(\sum_{j=0}^{4n-1}y^{j} \cdot v_{j,i}\big) + \sum_{i=0}^{n-1}c_{i} \big(\sum_{j=0}^{4n-1}y^{j} \cdot w_{j,i}\big)
$$

and properly arrange its $a$, $b$, and $c$ terms corresponding to a reversed structured vector (so it lines up when revdot'd with $\v{r}$), so you get:

$$
\v{s} = \begin{bmatrix}
0 \\ \\
0 \\ \\
\dots \\ \\
0
\end{bmatrix} ||
\begin{bmatrix}
\sum_{j=0}^{4n-1} \v{u}_{j,n-1} \cdot y^{j} \\ \\
\sum_{j=0}^{4n-1} \v{u}_{j,n-2} \cdot y^{j} \\ \\
\dots \\ \\
\sum_{j=0}^{4n-1} \v{u}_{j,0} \cdot y^{j} \\ \\
\end{bmatrix} ||
\begin{bmatrix}
\sum_{j=0}^{4n-1} \v{v}_{j,0} \cdot y^{j} \\ \\
\sum_{j=0}^{4n-1} \v{v}_{j,1} \cdot y^{j} \\ \\
\dots \\ \\
\sum_{j=0}^{4n-1} \v{v}_{j,n-1} \cdot y^{j} \\ \\
\end{bmatrix} ||
\begin{bmatrix}
\sum_{j=0}^{4n-1} \v{w}_{j,n-1} \cdot y^{j} \\ \\
\sum_{j=0}^{4n-1} \v{w}_{j,n-2} \cdot y^{j} \\ \\
\dots \\ \\
\sum_{j=0}^{4n-1} \v{w}_{j,0} \cdot y^{j} \\ \\
\end{bmatrix}
$$

## Consolidated Constraints

The equation for enforcing _multiplication constraints_ (using random challenge $z$) and _linear constraints_ (using random challenge $y$) can be combined into a single equation

$$
\revdot{\v{r}}{\v{s} + \v{r} \circ{\v{z^{4n}}} - \v{t}} = \dot{\v{k}}{\v{y^{4n}}}
$$

because $\v{r} \circ \v{z^{4n}} - \v{t}$ is made independent of $\v{s}$ by random $z$ except at $\v{r}_0$, where $\v{s}_0 = 0$.

[^tvectorcomputation]: $\v{t} \in \F^{4n}$ is defined such that $\v{t}_i = 0$ for all $i$ except that $\v{t}_{4n - 1 - i} = - (z^{2n - 1 - i} + z^{2n + i} )$ for $i$ between $0$ and $n -1$ inclusive.
