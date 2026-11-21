# Claims and Fold {#claims-and-fold}

Everything that a fuse must establish about its two children and about its own
step has one form: a revdot product with a stated value. A fuse gathers these
claims into an ordered list on each side and reduces each list to one claim,
which the next fuse takes up in turn. A claim's position in its list determines
its weight in the fold.

## Claims {#claims}

A **revdot claim** $(a, b;\ \text{tgt})$ asserts that
$\revdot{a}{b} = \text{tgt}$, and $\text{tgt}$ is its **target**. A claim is of
one of three kinds.

A **circuit claim** is the [combined check](arithmetization.md#combinedcheck) of
a circuit. For a trace $r$ and the wiring polynomial at registry index $j$, it
is

$$\left( r,\ r(zX) + s_j(X, y) + t(X, z);\ k(y) \right),$$

with $k$ the instance polynomial of the circuit. The trace of a circuit that
loads stages is the [sum](staging.md#stage-polynomial) of its own polynomial and
the polynomials of those stages, so the $a$ side of a circuit claim is in
general a sum.

A **bonding claim** is the check of a [bonding polynomial](staging.md#bonding).
It has no gate equations to enforce, so one claim serves a whole list of partial
traces $r_1, r_2, \dots$:

$$\left( \text{Horner}_z[r_1, r_2, \dots],\ s_j(X, y);\ 0 \right).$$

It holds as an identity in $y$ and $z$ exactly when each entry of the list
separately satisfies the constraints of $s_j$. An entry may itself be a sum of
polynomials, in which case the constraints apply to the sum. If some entry of a
list of $L$ violates a constraint, the claim holds for $y$ and $z$ drawn
uniformly from a set $S$ with probability at most
$(4n - 2 + L)/|S|$.[^bonding-bound]

[^bonding-bound]: The product of the claim is
    $z^{L-1} \revdot{r_1}{s_j(X, y)} + \dots + \revdot{r_L}{s_j(X, y)}$. Each
    $\revdot{r}{s_j(X, Y)}$ is a polynomial in $Y$ of degree at most $4n - 1$
    whose coefficients are the values of the constraints on $r$. The product
    is therefore a polynomial in $y$ and $z$ of total degree at most
    $(4n - 1) + (L - 1)$, it is nonzero when some entry violates a constraint,
    and the bound is that of Schwartz–Zippel.

A **raw claim** $(A, B;\ c)$ has no such structure. It is what a fold leaves
behind, and each child brings one.

On this page, $y$ and $z$ are the challenges of the current fuse. Every
polynomial belongs to a child, except the two of the fuse's own
[step circuit](setup.md#step-circuit) and its two
[fold randomizers](#randomizer). Indices refer to the
[native](setup.md#native-registry) and [nested](setup.md#nested-registry)
registries.

## Fold {#fold}

The fold takes a list of claims and reduces it to one. A random linear
combination of the claims would not do. Revdot is bilinear, so the product of
two combined sides contains every cross product $\revdot{a_k}{b_{k'}}$, and the
claims say nothing about those. The fold instead interpolates the claims over a
set of nodes, and the prover commits to a quotient that accounts for the cross
products before the challenge that combines the sides is drawn.[^protogalaxy]

[^protogalaxy]: This specializes to revdot claims the Lagrange and vanishing
    polynomial identity of [ProtoGalaxy](https://eprint.iacr.org/2023/1106).

The claims are placed in a grid of $N$ groups of $M$ **slots**, and the grid is
folded in two layers: each group is reduced to one claim, and the $N$ results
are then reduced to one. We write $(a_{g,j}, b_{g,j};\ \text{tgt}_{g,j})$ for
the claim in slot $j < M$ of group $g < N$. The native fold has
$(M, N) = (8, 15)$ and uses $\mu, \mu'$. The nested fold has $(M, N) = (9, 12)$
and uses $\mu_q, \mu'_q$, and its objects carry a subscript $q$.[^whysplit]

[^whysplit]: For $MN$ slots, the two layers commit $N(M - 1) + (N - 1) = MN - 1$
    quotient coefficients whatever the split. The prover's count of revdot
    products, $N M^2 + N^2$, is smallest near $M = (2MN)^{1/3}$, and the native
    split of fifteen groups of eight sits near that minimum.

Each layer interpolates over integer nodes: $0, \dots, M - 1$ in the first layer
and $0, \dots, N - 1$ in the second. For the first layer, let

$$\ell^{(M)}_j(T) = \prod_{j' < M, \, j' \ne j} \frac{T - j'}{j - j'}, \qquad V^{(M)}(T) = \prod_{j < M} (T - j),$$

and define $\ell^{(N)}_g$ and $V^{(N)}$ in the same way over the $N$ nodes of
the second layer.

### First Layer {#fold-layer-1}

For each group $g < N$, interpolating the two sides of its claims over the nodes
and taking the revdot product gives a polynomial in $T$,

$$\text{prod}_g(T) = \sum_{j, j' < M} \revdot{a_{g,j}}{b_{g,j'}} \, \ell^{(M)}_j(T) \, \ell^{(M)}_{j'}(T),$$

whose value at node $j$ is the product $\revdot{a_{g,j}}{b_{g,j}}$ of one
claim. Before $\mu$ is drawn, the prover forms

$$\text{prod}_g(T) - \sum_{j < M} \revdot{a_{g,j}}{b_{g,j}} \, \ell^{(M)}_j(T),$$

which is $\text{prod}_g$ less the interpolant of its own values at the nodes. It
vanishes at every node, so it equals $V^{(M)}(T) \, \text{quo}_g(T)$ for a
quotient $\text{quo}_g(T) = \sum_{k < M - 1} \text{quo}_{g,k} T^k$. The prover
commits the coefficients $\text{quo}_{g,k}$.

After $\mu$ is drawn, the group folds to

$$a'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, a_{g,j}, \qquad b'_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, b_{g,j},$$

and its **collapsed value** is defined from the targets, not from the
polynomials:

$$\text{col}_g = \sum_{j < M} \ell^{(M)}_j(\mu) \, \text{tgt}_{g,j} + V^{(M)}(\mu) \, \text{quo}_g(\mu).$$

### Second Layer {#fold-layer-2}

Before $\mu'$ is drawn, the prover repeats the construction over the $N$ pairs
$(a'_g, b'_g)$ and commits the quotient
$\text{quo}'(T) = \sum_{k < N - 1} \text{quo}'_k T^k$ together with the values
$\text{col}_g$. After $\mu'$ is drawn,

$$A = \sum_{g < N} \ell^{(N)}_g(\mu') \, a'_g = \sum_{g < N} \sum_{j < M} \text{wt}_{g,j} \, a_{g,j}, \qquad B = \sum_{g < N} \sum_{j < M} \text{wt}_{g,j} \, b_{g,j}, \qquad \text{wt}_{g,j} = \ell^{(N)}_g(\mu') \, \ell^{(M)}_j(\mu).$$

The scalars $\text{wt}_{g,j}$ are the **fold weights**. The new raw claim is
$(A, B; c)$ with $c = \revdot{A}{B}$. The relation that the native
[`collapse`](internal_circuits.md#native-collapse) circuit and the nested
[`Collapse`](internal_circuits.md#nested-collapse) circuit check is

$$c = \sum_{g < N} \ell^{(N)}_g(\mu') \, \text{col}_g + V^{(N)}(\mu') \, \text{quo}'(\mu').$$

### Fold Identity {#fold-identity}

The quotients are built from the actual revdot products. From the two divisions,

$$\text{col}_g = \revdot{a'_g}{b'_g} + \sum_{j < M} \ell^{(M)}_j(\mu) \left( \text{tgt}_{g,j} - \revdot{a_{g,j}}{b_{g,j}} \right),$$

$$\sum_{g < N} \ell^{(N)}_g(\mu') \, \text{col}_g + V^{(N)}(\mu') \, \text{quo}'(\mu') = \revdot{A}{B} + \sum_{g < N} \ell^{(N)}_g(\mu') \left( \text{col}_g - \revdot{a'_g}{b'_g} \right).$$

When every claim holds, both corrections vanish and the relation holds. When a
claim is false, $\text{col}_g$ is still given by its defining formula, so the
first-layer checks of `collapse` and `Collapse` still pass, and the final
relation is the only one that can fail. The [base case](base_case.md) waives
that relation.

In the other direction, suppose that a claim of group $g$ is false, whatever
quotient the prover has committed. The polynomial

$$\text{prod}_g(T) - \sum_{j < M} \ell^{(M)}_j(T) \, \text{tgt}_{g,j} - V^{(M)}(T) \, \text{quo}_g(T)$$

is then nonzero at the node of that claim. Its degree is at most $2M - 2$, and
its value at $\mu$ is $\revdot{a'_g}{b'_g} - \text{col}_g$. The folded claim
$(a'_g, b'_g;\ \text{col}_g)$ is therefore false as well, except with
probability at most $(2M - 2)/|S|$ for a challenge that is uniform on a set $S$.
The second layer loses at most $(2N - 2)/|S|$ in the same way.[^support]

[^support]: On the native side $S$ is the field. A nested challenge is the lift
    of an endoscalar of $143$ bits, so on the nested side $|S| = 2^{143}$.

## Randomizer {#randomizer}

A fold leaves two things in a proof: the coefficients of its quotients, which
two stages hold, and the folded polynomials $A$ and $B$, which the proof stores
in full. If the grid held only the claims of the list, each of these would be a
fixed function of the polynomials in those claims. A fuse therefore adds two
claims of its own to the grid, about two polynomials $a_\star$ and $b_\star$
whose coefficients it draws uniformly at random:

$$(a_\star,\ b_\star;\ c_\star) \quad \text{with} \quad c_\star = \revdot{a_\star}{b_\star}, \qquad\qquad (a_\star,\ 0;\ 0).$$

The first is the **randomizer claim** and the second is the **half-claim**.
Both hold for any two polynomials. We call $a_\star$ and $b_\star$ the **fold
randomizers**. The nested fold has its own, $a_{q,\star}$ and $b_{q,\star}$,
with the target $c_{q,\star}$.

The grid is filled as follows.

- Each group $g < N - 1$ takes the next $M - 1$ claims of the list in its slots
  $0, \dots, M - 2$, and the randomizer claim in its last slot. The claim at
  position $k$ of the list is thus in group $\lfloor k / (M - 1) \rfloor$, at
  slot $k \bmod (M - 1)$.
- The last group holds the half-claim in slot $0$ and the zero claim
  $(0, 0;\ 0)$ in its other slots.

The list is padded with zero claims to $(M - 1)(N - 1)$ entries, which is $98$
on the native side and $88$ on the nested side. We write $\text{wt}_k$ for the
fold weight of the slot that holds claim $k$ of the list, and
$\text{wt}_\star = \sum_{g < N - 1} \text{wt}_{g, M-1}$ for the sum over the
slots of the randomizer claim. Then

$$A = \sum_{k} \text{wt}_k \, a_k + \left( \text{wt}_\star + \text{wt}_{N-1, 0} \right) a_\star, \qquad B = \sum_{k} \text{wt}_k \, b_k + \text{wt}_\star \, b_\star,$$

so that $A$ and $B$ are each uniformly random when the weight of its randomizer
is nonzero.

### Randomized Quotients {#randomized-quotients}

The layout is chosen for the quotients. In a group $g < N - 1$, the randomizer
claim adds to $\text{prod}_g(T)$ the cross products

$$\sum_{j < M - 1} \left( \revdot{a_\star}{b_{g,j}} + \revdot{a_{g,j}}{b_\star} \right) \ell^{(M)}_{M-1}(T) \, \ell^{(M)}_j(T).$$

The $M - 1$ polynomials $\ell^{(M)}_{M-1} \, \ell^{(M)}_j / V^{(M)}$ are a
basis of the polynomials of degree at most $M - 2$.[^star-basis] The
coefficients of $\text{quo}_g$ are therefore the image, under a bijection, of
the $M - 1$ sums in parentheses, shifted by terms that do not contain them.

The last group folds to $a'_{N-1} = \ell^{(M)}_0(\mu) \, a_\star$ and
$b'_{N-1} = 0$, and plays the same part in the second layer: when
$\ell^{(M)}_0(\mu)$ is nonzero, the coefficients of $\text{quo}'$ are the
image, shifted in the same way, of the $N - 1$ values
$\revdot{a_\star}{b'_g}$ for $g < N - 1$. This is why the
last group holds half of the claim. With $b_\star$ on its $b$ side as well, each
of those values would be $\revdot{a_\star}{b'_g} + \revdot{a'_g}{b_\star}$,
which is a combination of the first layer's sums and $c_\star$. The half
$\revdot{a_\star}{b'_g}$ is not, because the first layer holds each
$\revdot{a_\star}{b_{g,j}}$ only in a sum with its counterpart. The quotient of
the last group is zero, because every $b$ side in that group is zero.

The groups hold the whole claim, and not half of it, because of the claims that
they hold. The sums of the first layer take every combination of values as the
randomizers vary exactly when the pairs $(a_{g,j}, b_{g,j})$ of the claims are
linearly independent. The $a$ sides alone are not, and neither are the $b$
sides: the $a$ side of a final mask's claim is a Horner list of polynomials that
other claims hold, and the $b$ sides of the masks' claims satisfy identities
among themselves.

A proof stores $A$ and $B$ in full. From them, someone who knows the other
polynomials of the grid can solve for $a_\star$ and $b_\star$, and with these
for every value above. The randomizers therefore conceal nothing from such an
observer. They are there for
[`Application::rerandomize`](ragu_pcd::Application::rerandomize), which fuses a
proof twice so that the second fuse folds polynomials that no observer holds.
**The argument for rerandomization is out of scope for this section.**

[^star-basis]: The quotient
    $\ell^{(M)}_{M-1} \, \ell^{(M)}_j / V^{(M)}$ is a nonzero multiple of the
    product of $T - j'$ over the nodes $j'$ other than $j$ and $M - 1$. Up to
    scalars, these products are the Lagrange basis of the nodes
    $0, \dots, M - 2$.

## Native Claims {#native-claims}

The native list has the raw claim of each child, then the claim of the fuse's
own step circuit, then one circuit claim for each of the $37$ internal circuits
of each child's [frontier](proof.md#frontier). It ends with one bonding claim
for each of the $18$ native bonding polynomials. Sixteen of these cover both
children, and the two of the application stage cover the fuse's own polynomials.

In each row, $i$ ranges over the children, left before right. We abbreviate the
sum of a child's six points stages as

$$r^{(i)}[\text{points}] = r^{(i)}[\texttt{PointsBinding}] + r^{(i)}[\texttt{PointsPreamble}] + r^{(i)}[\texttt{PointsRegistryWx}] + r^{(i)}[\texttt{PointsAb}] + r^{(i)}[\texttt{PointsF}] + r^{(i)}[\texttt{PointsWalk}].$$

| Position | Kind | Index | $a$ Side | Target |
|---|---|---|---|---|
| $i$ | raw | | $A^{(i)}$, with $b$ side $B^{(i)}$ | $c^{(i)}$ |
| $2$ | circuit | $\text{id}$ | $r[\texttt{Application}] + r[\texttt{ApplicationStage}]$ | $k_{\text{app}}(y)$ |
| $3 + i$ | circuit | 0 | $r^{(i)}[\texttt{Hashes1}] + r^{(i)}[\texttt{Preamble}] + r^{(i)}[\texttt{OuterError}]$ | $k^{(i)}_{\text{bridge}}(y)$ |
| $5 + i$ | circuit | 1 | $r^{(i)}[\texttt{Hashes2}] + r^{(i)}[\texttt{OuterError}]$ | $k^{(i)}_{\text{uni}}(y)$ |
| $7 + i$ | circuit | 2 | $r^{(i)}[\texttt{Collapse}] + r^{(i)}[\texttt{Preamble}] + r^{(i)}[\texttt{InnerError}] + r^{(i)}[\texttt{OuterError}]$ | $k^{(i)}_{\text{uni}}(y)$ |
| $9 + i$ | circuit | 3 | $r^{(i)}[\texttt{ComputeV}] + r^{(i)}[\texttt{Preamble}] + r^{(i)}[\texttt{Query}] + r^{(i)}[\texttt{Eval}]$ | $k^{(i)}_{\text{cv}}(y)$ |
| $11 + 2k + i$, $k < 4$ | circuit | $4 + k$ | $r^{(i)}[\texttt{BindChallenges}(k)] + r^{(i)}[\texttt{Preamble}] + r^{(i)}[\texttt{Query}] + r^{(i)}[\texttt{Eval}]$ | $k^{(i)}_{\text{uni}}(y)$ |
| $19 + i$ | circuit | 8 | $r^{(i)}[\texttt{BindBeta}] + r^{(i)}[\texttt{PointsBinding}] + r^{(i)}[\texttt{Preamble}]$ | $k^{(i)}_{\text{uni}}(y)$ |
| $21 + i$ | circuit | 9 | $r^{(i)}[\texttt{BindEndoscalar}] + r^{(i)}[\text{points}]$ | $k^{(i)}_{\text{uni}}(y)$ |
| $23 + 2s + i$, $s < 27$ | circuit | $10 + s$ | $r^{(i)}[\texttt{EndoscalingStep}(s)] + r^{(i)}[\text{points}]$ | $1$ |
| $77, \dots, 87$ | bonding | $37, \dots, 47$ | $z \, r^{(0)}[S] + r^{(1)}[S]$ for the stage $S$ of the mask: `Preamble`, `InnerError`, `OuterError`, `Query`, `Eval`, `PointsBinding`, `PointsPreamble`, `PointsRegistryWx`, `PointsAb`, `PointsF`, `PointsWalk` | $0$ |
| 88 | bonding | 48 | $z \, r^{(0)}[\texttt{Collapse}] + r^{(1)}[\texttt{Collapse}]$ | $0$ |
| 89 | bonding | 49 | $\text{Horner}_z$ of `Hashes1` then `Hashes2` | $0$ |
| 90 | bonding | 50 | $\text{Horner}_z$ of `ComputeV`, then `BindChallenges(0..=3)` | $0$ |
| 91 | bonding | 51 | $\text{Horner}_z$ of `BindEndoscalar`, then `EndoscalingStep(0..=26)` | $0$ |
| 92 | bonding | 52 | $z \, r^{(0)}[\texttt{BindBeta}] + r^{(1)}[\texttt{BindBeta}]$ | $0$ |
| 93 | bonding | 53 | $r[\texttt{ApplicationStage}]$ | $0$ |
| 94 | bonding | 54 | $r[\texttt{Application}]$ | $0$ |
| $95, 96, 97$ | padding | | $0$ | $0$ |

In rows $89$ to $91$, each named polynomial contributes its left and then its
right instance to the Horner list. Row $89$, for example, is

$$z^3 \, r^{(0)}[\texttt{Hashes1}] + z^2 \, r^{(1)}[\texttt{Hashes1}] + z \, r^{(0)}[\texttt{Hashes2}] + r^{(1)}[\texttt{Hashes2}].$$

Rows $88$ to $92$ and $94$ are the [final masks](staging.md#masks). Each is
claimed over the own polynomials of the circuits whose last stage is the mask's
stage.

Rows $2$, $93$ and $94$ are the three claims of the fuse's own step: the circuit
claim of its trace, and the two masks that keep the application stage and the
step circuit's own polynomial apart. No child brings a claim of this kind,
because each child folded its own.

The target of an `endoscaling_step` claim is $1$, because the instance
polynomial of that circuit is the
[constant one](internal_circuits.md#native-endoscaling-step). Rows $95$ to $97$
pad the list to the $14 \cdot 7 = 98$ claims that the [fold](#randomizer) has
room for.

### Native Targets {#native-targets}

The target of a raw claim is the wire $c^{(i)} = U^{(i)}_{16}$. The target of a
child's circuit claim is the instance polynomial of the child's circuit,
evaluated at the current $y$ over the wires that the `preamble` stage holds for
child $i$. We mark such a polynomial with the superscript $(i)$, and write
$\text{hdr}^{(i)}_O$ for the child's output header and
$\omega^{(i)}_{\text{id}}$ for the domain point of its `circuit_id`.

The targets $k^{(i)}_{\text{uni}}(y)$, $k^{(i)}_{\text{bridge}}(y)$ and
$k^{(i)}_{\text{cv}}(y)$ are the polynomials of the
[native unified instance](proof.md#native-unified) over the wires $U^{(i)}$.
The second belongs to the child's `hashes_1`, whose output carries the child's
own output header and index,

$$k^{(i)}_{\text{bridge}}(y) = \text{Horner}_y[U^{(i)}_1, \dots, U^{(i)}_{39}, \text{hdr}^{(i)}_O, \omega^{(i)}_{\text{id}}, 0, 1],$$

and the third is equal to the first.

The target of the step circuit's claim is $k_{\text{app}}(y)$ of the
[step circuit](setup.md#step-circuit) that this fuse ran. Every entry is a value
of the current fuse: $\zeta$ is $w$, $(h_x, h_y)$ is $R_q[\texttt{BridgeHash}]$,
and the openings and $\text{hdr}_O$ are the fuse's own wires of the `preamble`
stage. The two input headers are the children's output headers:

$$k_{\text{app}}(y) = \text{Horner}_y[w, \xi_0, \eta_0, \dots, \xi_5, \eta_5, h_x, h_y, \text{hdr}^{(0)}_O, \text{hdr}^{(1)}_O, \text{hdr}_O, 1].$$

The targets share wires. The input headers in $k_{\text{app}}(y)$ are the wires
$\text{hdr}^{(i)}_O$ of $k^{(i)}_{\text{bridge}}(y)$, which binds the headers
that the step circuit read to the output headers that the children exported.
The openings in $k_{\text{app}}(y)$ are the wires that
[`compute_v`](internal_circuits.md#native-compute-v) folds into the batch, which
binds the step circuit to the openings that the batch proves. And
$\text{hdr}_O$ is the header that this fuse's own `hashes_1` exports, for a
parent to bind in the same way.

## Nested Claims {#nested-claims}

The nested list has the same shape: for each child, the raw claim and one
circuit claim for each of the $33$ nested circuits, and then one bonding claim
for each of the $15$ nested bonding polynomials.

Here the challenges are $y_q$ and $z_q$ and the registry is $m_q$. We abbreviate
two sums of a child's stage polynomials.

$$r_q^{(i)}[\text{all}] = \sum_{S} r_q^{(i)}[S] \quad \text{over all twelve nested stages } S,$$

$$r_q^{(i)}[\text{loading}] = \sum_{S} r_q^{(i)}[S] \quad \text{over } S \in \{\texttt{PointsStage}, \texttt{BridgePreamble}, \texttt{BridgeSPrime}, \texttt{BridgeInnerError}, \texttt{BridgeAB}, \texttt{BridgeQuery}, \texttt{BridgeF}\}.$$

| Position | Kind | Index | $a$ Side | Target |
|---|---|---|---|---|
| $i$ | raw | | $A_q^{(i)}$, with $b$ side $B_q^{(i)}$ | $c_q^{(i)}$ |
| $2 + 2s + i$, $s < 31$ | circuit | $s$ | $r_q^{(i)}[\texttt{EndoscalingStep}(s)] + r_q^{(i)}[\texttt{EndoscalarStage}] + r_q^{(i)}[\texttt{PointsStage}]$ | $1$ |
| $64 + i$ | circuit | 31 | $r_q^{(i)}[\texttt{Collapse}] + r_q^{(i)}[\text{all}]$ | $k^{(i)}_{q}(y_q)$ |
| $66 + i$ | circuit | 32 | $r_q^{(i)}[\texttt{ComputeV}] + r_q^{(i)}[\text{all}]$ | $k^{(i)}_{q}(y_q)$ |
| 68, 69 | bonding | 33, 34 | $z_q \, r_q^{(0)}[S] + r_q^{(1)}[S]$ for `EndoscalarStage`, `PointsStage` | $0$ |
| 70 | bonding | 35 | $\text{Horner}_{z_q}$ of `EndoscalingStep(0..=30)` | $0$ |
| $71, \dots, 80$ | bonding | $36, \dots, 45$ | $z_q \, r_q^{(0)}[S] + r_q^{(1)}[S]$ for the nine bridge stages in registry order, then `ChallengeStage` | $0$ |
| 81 | bonding | 46 | $\text{Horner}_{z_q}$ of `Collapse` then `ComputeV` | $0$ |
| 82 | bonding | 47 | $z_q \, r_q^{(0)}[\text{loading}] + r_q^{(1)}[\text{loading}]$ | $0$ |
| $83, \dots, 87$ | padding | | $0$ | $0$ |

As on the native side, a Horner list takes the left and then the right instance
of each named polynomial. Row $70$ is the final mask of the endoscaling steps,
row $81$ is the final mask of the two instance circuits, and row $82$ is the
[loading](internal_circuits.md#loading) relation. Rows $83$ to $87$ pad the
list to $11 \cdot 8 = 88$ claims.

### Nested Targets {#nested-targets}

The two raw targets are the wires $c_q^{(i)}$ of the `BridgePreamble` stage. The
target of the instance circuits is the child's
[nested instance polynomial](proof.md#nested-unified) at $y_q$, over the copies
in that stage:

$$k^{(i)}_{q}(y_q) = \text{Horner}_{y_q}[c_q^{(i)}, v_q^{(i)}, x_q^{(i)}, y_q^{(i)}, u_q^{(i)}, E^{(i)}_0, \dots, E^{(i)}_{15}, 1].$$

Both instance circuits of a child take the same target.

## Groups {#fold-groups}

The position of a claim fixes its slot, as the grids below show. A cell gives
the registry index of the claim's wiring polynomial, with $\text{id}$ for the
fuse's own step circuit. An index that appears twice is an internal circuit,
which is claimed once for each child. The step circuit and each bonding
polynomial appear once. A cell marked $\star$ holds the randomizer claim, the
cell marked half holds the half-claim, and a cell marked pad holds the zero
claim.

The native grid has $15$ groups of $8$.

| | $j = 0$ | $1$ | $2$ | $3$ | $4$ | $5$ | $6$ | $7$ |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| $g = 0$ | raw | raw | $\text{id}$ | $0$ | $0$ | $1$ | $1$ | $\star$ |
| $g = 1$ | $2$ | $2$ | $3$ | $3$ | $4$ | $4$ | $5$ | $\star$ |
| $g = 2$ | $5$ | $6$ | $6$ | $7$ | $7$ | $8$ | $8$ | $\star$ |
| $g = 3$ | $9$ | $9$ | $10$ | $10$ | $11$ | $11$ | $12$ | $\star$ |
| $g = 4$ | $12$ | $13$ | $13$ | $14$ | $14$ | $15$ | $15$ | $\star$ |
| $g = 5$ | $16$ | $16$ | $17$ | $17$ | $18$ | $18$ | $19$ | $\star$ |
| $g = 6$ | $19$ | $20$ | $20$ | $21$ | $21$ | $22$ | $22$ | $\star$ |
| $g = 7$ | $23$ | $23$ | $24$ | $24$ | $25$ | $25$ | $26$ | $\star$ |
| $g = 8$ | $26$ | $27$ | $27$ | $28$ | $28$ | $29$ | $29$ | $\star$ |
| $g = 9$ | $30$ | $30$ | $31$ | $31$ | $32$ | $32$ | $33$ | $\star$ |
| $g = 10$ | $33$ | $34$ | $34$ | $35$ | $35$ | $36$ | $36$ | $\star$ |
| $g = 11$ | $37$ | $38$ | $39$ | $40$ | $41$ | $42$ | $43$ | $\star$ |
| $g = 12$ | $44$ | $45$ | $46$ | $47$ | $48$ | $49$ | $50$ | $\star$ |
| $g = 13$ | $51$ | $52$ | $53$ | $54$ | pad | pad | pad | $\star$ |
| $g = 14$ | half | pad | pad | pad | pad | pad | pad | pad |

The nested grid has $12$ groups of $9$.

| | $j = 0$ | $1$ | $2$ | $3$ | $4$ | $5$ | $6$ | $7$ | $8$ |
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| $g = 0$ | raw | raw | $0$ | $0$ | $1$ | $1$ | $2$ | $2$ | $\star$ |
| $g = 1$ | $3$ | $3$ | $4$ | $4$ | $5$ | $5$ | $6$ | $6$ | $\star$ |
| $g = 2$ | $7$ | $7$ | $8$ | $8$ | $9$ | $9$ | $10$ | $10$ | $\star$ |
| $g = 3$ | $11$ | $11$ | $12$ | $12$ | $13$ | $13$ | $14$ | $14$ | $\star$ |
| $g = 4$ | $15$ | $15$ | $16$ | $16$ | $17$ | $17$ | $18$ | $18$ | $\star$ |
| $g = 5$ | $19$ | $19$ | $20$ | $20$ | $21$ | $21$ | $22$ | $22$ | $\star$ |
| $g = 6$ | $23$ | $23$ | $24$ | $24$ | $25$ | $25$ | $26$ | $26$ | $\star$ |
| $g = 7$ | $27$ | $27$ | $28$ | $28$ | $29$ | $29$ | $30$ | $30$ | $\star$ |
| $g = 8$ | $31$ | $31$ | $32$ | $32$ | $33$ | $34$ | $35$ | $36$ | $\star$ |
| $g = 9$ | $37$ | $38$ | $39$ | $40$ | $41$ | $42$ | $43$ | $44$ | $\star$ |
| $g = 10$ | $45$ | $46$ | $47$ | pad | pad | pad | pad | pad | $\star$ |
| $g = 11$ | half | pad | pad | pad | pad | pad | pad | pad | pad |

A group is not aligned with the kinds of claim or with the children: the two
claims of the native index $5$ fall in different groups. The paddings of the
list fall at the end of the last group that holds claims.

## Commitment Schedule {#fold-schedule}

Each object of the fold is fixed before the challenge that follows it. The
commitments $[a_\star]$ and $[b_\star]$ are held in the `BridgeSPrime` stage,
and $[a_{q,\star}]$ and $[b_{q,\star}]$ in the native `points::RegistryWxStage`,
before $y$ and $z$. The first-layer coefficients $\text{quo}_{g,k}$ and the
target $c_\star$ are held in the `inner_error` stage, and the nested ones in the
`BridgeInnerError` stage, before $\mu$. The second-layer coefficients
$\text{quo}'_k$ and the collapsed values $\text{col}_g$ are held in the
`outer_error` stage, and the nested ones in the `BridgeOuterError` stage, before
$\mu'$. The commitments of the folded polynomials are fixed before $x$, and each
is held by a stage of the other side: $[A]$ and $[B]$ are points of $\E_q$, so
the nested `BridgeAB` stage holds them, and the native `points::AbStage` holds
$[A_q]$ and $[B_q]$.

In practice, the native $[A]$ is not computed by committing $A$. Every $a_k$ is
a linear combination of the children's stored polynomials and the two
polynomials of the step circuit's trace, with each coefficient equal to one or
to a power of $z$, so

$$[A] = \sum_{i \in \{0, 1\}} \sum_{\phi} \text{wt}_{i, \phi} \cdot [\phi^{(i)}] + \text{wt}_{\texttt{Application}} \cdot R[\texttt{Application}] + \text{wt}_{\texttt{ApplicationStage}} \cdot R[\texttt{ApplicationStage}] + \left( \text{wt}_\star + \text{wt}_{N-1, 0} \right) \cdot [a_\star],$$

where $\phi$ ranges over $A$ and the $48$ native rx polynomials, and the
aggregate weight of a polynomial is the sum over $k$ of $\text{wt}_k$ times the
coefficient of that polynomial in $a_k$. The commitments $[B]$, $[A_q]$ and
$[B_q]$ are computed from their polynomials.
