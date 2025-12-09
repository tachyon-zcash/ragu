# Structured Vectors

Ragu uses a particular arrangement for vectors to encode witness data and
various polynomials in its construction: a _structured vector_ $\v{r} \in \F^{4n}$
can be written as the concatenation

$$
\v{c} || \v{\hat{b}} || \v{a} || \v{\hat{d}}
$$

for some vectors $\v{a}, \v{b}, \v{c}, \v{d} \in \F^n$. These vectors have the
property that $\v{\hat{r}}$ (its [reversed vector](./notation.md#reversed-vector-notation))
can be written

$$
\v{d} || \v{\hat{a}} || \v{b} || \v{\hat{c}}
$$

which remains a structured vector but with $\v{a}$ swapped with $\v{b}$ and
$\v{c}$ swapped with $\v{d}$.

## Revdot Product

The [revdot product](./notation.md#revdot-product)
$\revdot{\v{a}}{\v{b}} = \dot{\v{a}}{\v{\hat{b}}} = \dot{\v{\hat{a}}}{\v{b}}$ is
a central component of Ragu's accumulation-based recursive SNARK protocol
because it is natural to reduce into claims about univariate polynomials: given
two polynomials $a, b \in \F[X]$ defined by the coefficient vectors $\v{a},
\v{b} \in \F^n$ (respectively), the $n - 1$ degree coefficient of the product
polynomial $a \cdot b$ is $\revdot{\v{a}}{\v{b}}$.

Further, observe that a structured vector $\v{r} = \v{c} || \v{\hat{b}} || \v{a} || \v{0}$
has the expansion

$$
\begin{array}{ll}
\revdot{\v{r}}{\v{r}} = 2 \sum_i \v{a}_i \v{b}_i
\end{array}
$$

and so we can encode [multiplication constraints](./cs.md#multiplication-constraints)
into claims about such vectors, using verifier challenges to keep the claims linearly independent.

### Folding

It is trivial to accumulate multiple instances $(\v{a_i}, \v{b_i}, c_i)$ of the
claim $c_i = \revdot{\v{a_i}}{\v{b_i}}$ together by leveraging the linearity of
inner products. The accumulation prover commits to the "error" matrix $E$ where
$E_{i j} = \revdot{\v{a_i}}{\v{b_j}}$, except that the verifier enforces the
diagonal $E_{i i} = c_i \forall i$. The verifier samples random challenges $\mu,
\nu \in \F$ and computes the reduced claim $(\v{a'}, \v{b'}, c')$ as

$$
\begin{array}{lllll}
&\v{a'}&=& \sum_{i} (\mu\nu)^i \mathbf{a_i} \\
&\v{b'}&=& \sum_{j} \mu^{-j} \mathbf{b_j} \\
&c'&=& \sum_{i,j} \mu^{i - j} \nu^i E_{i j}
\end{array}
$$

### Reduction to Polynomial Queries

Given a claim $(\v{a}, \v{b}, c)$ where $a, b \in \F[X]$ are polynomials
described by the respective coefficient vectors $\v{a}, \v{b} \in \F^{n}$, the
product polynomial $a \cdot b$ can be written as

$$
X^{n - 1} p(1 / X) + X^n q(X)
$$

for specially-constructed polynomials $p, q \in \F[X]$ of maximal degree $n - 1$. The prover can commit to $p, q$
and the verifier can test at a random point to ensure correctness. The claim is
then reduced to the equality $p(0) = c$.

To construct $p$ and $q$, observe:

$$
c(X) = \underbrace{c_{0} + c_{1}X + \dots + c_{n-1}X^{n-1}}_{\text{lower half}} + \underbrace{c_{n}X^{n} + \dots + c_{2n-2}X^{2n-2}}_{\text{upper half}}
$$

Recall from above that the $n - 1$ degree coefficient, $c_{n-1}$, equals the revdot product of the vectors, $\revdot{\v{a}}{\v{b}}$. To construct $p$, we take the lower half of $c$ and reverse its coefficients, so the $c_{n-1}$ coefficient becomes the constant term (and thus, $p(0) = c = \revdot{\v{a}}{\v{b}}$):

$$
p(X) = c_{n-1} + c_{n-2}X + \dots + c_{0}X^{n-1}
$$

$q(x)$ is constructed from the coefficients of the upper half.

> This reduction requires the prover to compute $a \cdot b$, which can be done
> efficiently with an FFT, but should still be performed as infrequently as
> possible. Ragu only requires this computation to be performed at locations in
> the PCD tree where succinctness is required.
