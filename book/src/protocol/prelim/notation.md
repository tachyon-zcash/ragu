# Notation

## Groups and Fields

Group elements are written in uppercase letters $G, H, P\in\G$, 
scalars and field elements are in lowercase $a, b, c\in\F$.
In Ragu, there are only two finite fields used: the scalar field of 
Vesta Curve $\F_p$ and that of Pallas Curve $\F_q$.

## Vectors

We write a vector $\v{a} \in \F^n$ in bold type, and generally use capital
letters like $\v{G} \in \mathbb{G}^n$ to represent vectors of group elements.
Similarly, individual field and group elements are written in a normal typeface
like $a \in \F$ or $H \in \mathbb{G}$. All vectors are zero-indexed.
Vector concatenation is denoted as $\v{a}\|\v{b}\in\F^{2n}$.

Dot (inner) products as $\dot{\v{a}}{\v{b}}=\sum_i \v{a}_i\cdot\v{b}_i \in\F$
and Hadamard (pair-wise) products as $\v{a} \circ \v{b}\in\F^n$.

We use $\v{z^{n}}$ to denote power vector $(z^0, z^1, \cdots, z^{n - 1})$.
Further generalize this notation to arbitrary range $[n,m)$ in the exponent:
$\v{z}^{n:m}=(z^n,\ldots,z^{m-1})$. One natural exception in notation: 
$\v{0^n}=(\underbrace{0,\ldots,0}_{n\text{ zeros}})$ is a zero vector, 
not $(1,0,\ldots)$ even though $0^0=1$. 

### Reversed Vector

Given a vector $\v{a} \in \F^n$ we denote its reverse (mirror) as $\v{\hat{a}}$
such that $\v{\hat{a}}_i = \v{a}_{n - 1 - i} \forall i$.
Combining the power vector and vector reversal, two commonly seen vectors later:
$\rv{z}^{n:2n}=(z^{2n-1},\ldots,z^n)$ and 
$\v{z}^{2n:3n}=(z^{2n},\ldots,z^{3n-1})$.

### Revdot Product

We use a special notation $\revdot{\v{a}}{\v{b}}$ for 
$\dot{\v{a}}{\rv{b}} = \dot{\rv{a}}{\v{b}}$,
which we referred to as **revdot products**, a special case of dot products.

A few useful arithmetic facts (assume all vectors have the same length):
- $\dot{\v{a}\|\v{b}}{\v{c}\|\v{d}} = \dot{\v{a}}{\v{c}} + \dot{\v{b}}{\v{d}}$
- $\alpha\cdot \dot{\v{a}}{\v{c}} + \beta\cdot \dot{\v{b}}{\v{c}} =
\dot{\alpha\cdot\v{a}+\beta\cdot\v{b}}{\v{c}}$ where $\alpha,\beta\in\F$
- $\dot{\rv{a}}{\rv{a}}=\dot{\v{a}}{\v{a}}$
- $\dot{\rv{b}}{\rv{a} \circ \v{d}} = \dot{\v{b}}{\widehat{\rv{a}\circ\v{d}}}=
\dot{\v{b}}{\v{a}\circ\rv{d}}$

## Polynomials

Given a univariate polynomial $p \in \F[X]$ of maximal degree $n - 1$ there
exists a (canonical) coefficient vector $\v{p} \in \F^n$ ordered such that
$\v{p}_{n - 1}$ is the leading coefficient. Given $z \in \F$ the evaluation
$p(z)$ is thus given by the inner (dot) product $\langle \v{p}, \v{z^n} \rangle$
where $\v{z^n}$ denotes the power vector $(z^0, z^1, \cdots, z^{n - 1})$. We
write the _dilation_ $p(zX)$ using the Hadamard (pairwise) product $\v{z^n}
\circ \v{p}$.

Similar to vector reversal, reversed polynomial with coefficients $\rv{p}$ 
represents: $\hat{p}(X)=X^{n-1}p(X^{-1})=X^{n-1}\cdot
\dot{(p_0,p_1,\ldots,p_{n-1})}{(1, X^{-1},X^{-2},\ldots,X^{-(n-1)})}$.
