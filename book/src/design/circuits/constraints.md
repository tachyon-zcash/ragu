# Constraint System

The witness vectors $\v{a}, \v{b}, \v{c} \in \F^n$ must satisfy $n$ _multiplication constraints_, where the $i$th such constraint takes the form $\v{a}_i \cdot \v{b}_i = \v{c}_i$. In addition, the witness must satisfy a set of $4n$ _linear constraints_, where the $j$th such constraint is of the form

$$
\sum_{i = 0}^{n - 1} \big( \v{u}_{i,j} \cdot \mathbf{a}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{v}_{i,j} \cdot \mathbf{b}_i \big) +
\sum_{i = 0}^{n - 1} \big( \v{w}_{i,j} \cdot \mathbf{c}_i \big) =
\v{k}_j
$$

for some (sparse) public input vector $\v{k} \in \F^{4n}$ and fixed matrices $\v{u}, \v{v}, \v{w} \in \F^{n \times 4n}$, where $\v{u_{j}}, \v{v_{j}}, \v{w_{j}} \in \F^{4n}$ denote the _j-th column_ of those matrices. Because $n$ is fixed, individual circuits vary only by these matrices after this reduction.

## Multiplication Constraints

The multiplication constraints over the witness can be rewritten as $\v{a} \circ \v{b} = \v{c}$. It is possible to probabilistically reduce this to a dot product claim using a random challenge $z \in \F$, using the "folded" claim

$$
\sum_{i=0}^{n-1} z^{i}\,\big(\mathbf a_i \mathbf b_i - \mathbf c_i\big) = 0 \;\Longleftrightarrow\; \dot{\v{a}}{\v{z^{n}} \circ \v{b}} - \dot{\v{c}}{\v{z^{n}}} = 0.
$$

By the definition of $\v{r}$ (as a [structured vector](../structured.md)) we can do something mathematically identical. Observe the expansion

$$\revdot{\v{r}}{\v{r} \circ \v{z^{4n}}} =

\sum\limits_{i = 0}^{n - 1} \left(
  \v{a}_i \v{b}_i  \big( \underline{z^{2n - 1 - i} + z^{2n + i} } \big)
+ \v{c}_i \v{d}_i  \big( z^{i} + z^{4n - 1 - i} \big)
\right)

$$

and notice that for all $z \in \F$ and for any choice of $\v{r}$ there exists a unique vector $\v{t}$ such that

$$
\revdot{\v{r}}{\v{t}} = -\sum_{i = 0}^{n - 1} \v{c}_i \big( \underline{ z^{2n - 1 - i} + z^{2n + i} } \big). \\
$$
Where $\v{t}$ is computed like:
$$
\v{t} =  
\begin{bmatrix}
0 \\ 
0 \\
\dots \\
0
\end{bmatrix} ||
\begin{bmatrix}
0 \\ 
0 \\
\dots \\
0
\end{bmatrix} ||
\begin{bmatrix}
0 \\ 
0 \\
\dots \\
0
\end{bmatrix} ||
\begin{bmatrix}
-1(z^{2n-1-(n-1)} + z^{2n+(n-1)}) \\
-1(z^{2n-1-(n-2)} + z^{2n+(n-2)}) \\
\dots \\
-1(z^{2n-1} + z^{2n})
\end{bmatrix}
$$

and so if for a random challenge $z$

$$
\revdot{\v{r}}{\v{r} \circ{\v{z^{4n}}} + \v{t}} = 0
$$

holds, then $\v{a} \circ \v{b} = \v{c}$ holds with high probability.

## Linear Constraints

Given a choice of witness $\v{a}, \v{b}, \v{c}$, if for some random choice of $y \in \F$ the equality

$$
\sum_{j=0}^{4n - 1} y^j \Bigg(
    \sum_{i = 0}^{n - 1} \big( \v{u}_{i,j} \cdot \mathbf{a}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{v}_{i,j} \cdot \mathbf{b}_i \big) +
    \sum_{i = 0}^{n - 1} \big( \v{w}_{i,j} \cdot \mathbf{c}_i \big)
\Bigg) =
\sum_{j=0}^{4n - 1} y^j \v{k}_j
$$

holds, then with high probability the $4n$ linear constraints are all satisfied as well. After some trivial manipulation, it is possible to define a vector $\v{s}$ such that this is equivalent to

$$
\revdot{\v{r}}{\v{s}} = \dot{\v{k}}{\v{y^{4n}}}
$$

for the [witness](../witness.md) vector $\v{r}$.

## Consolidated Constraints

The equation for enforcing _multiplication constraints_ (using random challenge $z$) and _linear constraints_ (using random challenge $y$) can be combined into a single equation

$$
\revdot{\v{r}}{\v{s} + \v{r} \circ{\v{z^{4n}}} - \v{t}} = \dot{\v{k}}{\v{y^{4n}}}
$$

because $\v{r} \circ \v{z^{4n}} - \v{t}$ is made independent of $\v{s}$ by random $z$ except at $\v{r}_0$, where $\v{s}_0 = 0$.

