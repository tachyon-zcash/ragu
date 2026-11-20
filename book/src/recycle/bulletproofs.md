# Bulletproofs IPA

**This page is retained from an earlier version of the book and has not
been revised.** [Construction](../protocol/construction/index.md) describes
the current protocol.

****Inner product argument**** (IPA) is an argument system for the relation:

$$
\Rel_{ipa}=\{
\inst:=(\v{G},\v{H}\in\G^n, P,Q\in\G);
\wit:=(\v{a},\v{b}\in\Z_q^n):
P = \dot{\v{a}}{\v{G}} + \dot{\v{b}}{\v{H}} + \dot{\v{a}}{\v{b}}\cdot Q
\}
$$

[[BCCGP16]](https://eprint.iacr.org/2016/263) and Bulletproof constructed a 
transparent SNARK for this relation with $O(\log n)$ proof size
but $O(n)$ verifier time.
We skip presenting the full protocol and refer readers to existing
resources [^bp-learn] for details. We only provide a high-level description
here.

Bulletproof IPA proceeds in $k=\log_2 n$ rounds, indexed by $j=k,\ldots,1$.
In each round, the prover sends some cross terms $L_j, R_j\in\G$ to the verifier
who samples a challenge $u_j\sample\F$. Then the prover use the challenge to 
fold/halve the instance and witness from the last round:

$$
\begin{align}
\v{a}^{(j-1)}&\leftarrow \v{a}^{(j)}_{lo} \cdot u_j + u_j^{-1} \cdot \v{a}^{(j)}_{hi}\\
\v{b}^{(j-1)}&\leftarrow \v{b}^{(j)}_{lo} \cdot u_j^{-1} + u_j \cdot \v{b}^{(j)}_{hi}\\
\v{G}^{(j-1)}&\leftarrow \v{G}^{(j)}_{lo} \cdot u_j^{-1} + u_j \cdot \v{G}^{(j)}_{hi}\\
\v{H}^{(j-1)}&\leftarrow \v{H}^{(j)}_{lo} \cdot u_j + u_j^{-1} \cdot \v{H}^{(j)}_{hi}
\end{align}
$$

The verifier can fold the instance $\v{G}, \v{H}$ on its own, effectively 
reducing the instance $\inst$ to half of its size.
After $k$ rounds of folding, in the last $j=1$ round, the prover sends over
$\v{a}^0, \v{b}^0$, which are just single element vector, for verification.
In the non-interactive argument, as an optimization, the verifier computes the 
final $\v{G}^{(0)}=(G_0), \v{H}^{(0)}=(H_0)$ in a single multi-scalar 
multiplication (MSM) instead of computing them round-by-round.
Computing $G_0, H_0$ is also the dominant verifier cost and the culprit of 
the linear-time verifier. Concretely, 
$G_0=\dot{\v{s}}{\v{G}}, H_0=\dot{\v{s^{-1}}}{\v{H}}$ where:

$$
\v{s}= 
\begin{pmatrix}
u_1^{-1}\cdot u_2^{-1} \cdot\ldots\cdot u_k^{-1},\\
u_1\cdot u_2^{-1} \cdot\ldots\cdot u_k^{-1},\\
u_1^{-1}\cdot u_2 \cdot\ldots\cdot u_k^{-1},\\
\ldots\\
u_1\cdot u_2 \cdot\ldots\cdot u_k\\
\end{pmatrix}
$$

## Polynomial Commitment via IPA

With Bulletproof for $\Rel_{ipa}$, we can translate the PCS evaluation relation
into an IPA, thus build the Bulletproof PCS.
We only showcase the non-hiding PCS here for simplicity.
Interested readers may also find a more detailed exposition in
[Halo2's Appendix](https://zcash.github.io/halo2/background/pc-ipa.html).

For polynomial $f(X)\in\F[X]$ with coefficient vector $\v{f}\in\F^n$, 
we commit the polynomial using Pedersen commitment over its coefficient: 
$F\leftarrow \dot{\v{f}}{\v{G}}$ where $\v{G}$ is the list of group generators.

To prove $f(x)=y$, we set $\v{b}=\v{x^{n}}=(1,x,x^2,\ldots,x^{n-1})$, 
we discard $\v{H}=\vec{0_\G}$, then PCS evaluation proof is exactly an IPA:
given $\v{G}, P, Q, x, y$, there exists $\v{f}$ such that 
$P=F+y\cdot Q=\dot{\v{f}}{\v{G}} + \dot{\v{f}}{\v{b}}\cdot Q$.
Therefore the _PCS evaluation proof is exactly an IPA proof_.

[^bp-learn]: `dalek-crypto`'s
[writeup](https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html)
is great and engineer-friendly; Chapter 14.4 of Justin Thaler's
[PAZK textbook](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.html)
provides more details and context; Yupeng Zhang's
[lecture](https://www.youtube.com/watch?v=WyT5KkKBJUw) and Yingtong's
[whiteboard session](https://www.youtube.com/watch?v=RaEs5mnXIhY)
are also highly recommended.

---

The IPA and PCS constructed here provide polynomial commitment without a trusted
setup, at the cost of linear-time verification. This cost motivates the
[split-accumulation techniques](accumulation.md), which defer expensive
verification to achieve efficient recursion.
