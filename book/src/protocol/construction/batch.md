# Batched Opening {#batched-opening}

The fold leaves evaluation claims to check: that the folded $A$ and $B$ are the
stated combinations of the polynomials in the claims, that each child's own
batched opening holds, and that the registry restrictions are consistent. Each
side gathers its claims into one polynomial $p$ opened at one point.

## Batched Polynomial {#batch-structure}

A side has $Q$ **openings** $(\phi_i, \rho_i, \vartheta_i)$, each claiming
$\phi_i(\rho_i) = \vartheta_i$, and $J$ **batched polynomials**
$\psi_0, \dots, \psi_{J-1}$, which are the polynomials that the openings
name, each listed once. An opening holds exactly when
$\phi_i(X) - \vartheta_i$ is divisible by $X - \rho_i$. The prover combines
the $Q$ quotients into one polynomial $f$ with powers of a challenge $\alpha$,
and combines $f$ with the batched polynomials into one polynomial $p$ with
powers of a challenge $\beta$:

$$f(X) = \sum_{i=0}^{Q-1} \alpha^{Q-1-i} \, \frac{\phi_i(X) - \phi_i(\rho_i)}{X - \rho_i},$$

$$p(X) = \beta^{J} f(X) + \sum_{j=0}^{J-1} \beta^{J-1-j} \, \psi_j(X), \qquad P = \beta^{J} \cdot [f] + \sum_{j=0}^{J-1} \beta^{J-1-j} \cdot [\psi_j].$$

The quotients in $f$ are taken with the true values $\phi_i(\rho_i)$, so $f$ is
a polynomial whatever is claimed. The claimed values $\vartheta_i$ enter only
the value $v$ below.

The prover commits $f$ before $u$ is drawn and the evaluations
$\epsilon_j = \psi_j(u)$ before $\beta$ is fixed. The side's circuit, the native
[`compute_v`](internal_circuits.md#native-compute-v) or the nested
[`ComputeV`](internal_circuits.md#nested-compute-v), computes the value

$$v = \beta^{J} \sum_{i=0}^{Q-1} \alpha^{Q-1-i} \, \frac{\epsilon[\phi_i] - \vartheta_i}{u - \rho_i} + \sum_{j=0}^{J-1} \beta^{J-1-j} \, \epsilon_j,$$

where $\epsilon[\phi_i]$ is the evaluation of the batched polynomial that
opening $i$ names. If every opening holds and every $\epsilon_j$ is correct, then
$v = p(u)$. The claim $p(u) = v$ against $P$ is the side's new batched opening.

In the other direction, suppose that the new batched opening holds, where the
polynomial behind $[f]$ may be any that the prover chose, and that every
opening was fixed before $\alpha$: its polynomial $\phi_i$, its point $\rho_i$
and its claimed value $\vartheta_i$. Then every opening holds and every
$\epsilon_j$ is correct, except with probability at most

$$\frac{Q - 1}{|S_\alpha|} + \frac{4n - 1 + D}{|S_u|} + \frac{J}{|S_\beta|},$$

where each challenge is uniform on its set and $D$ is the number of distinct
points among the $\rho_i$.[^batch-bound] The three terms belong to the
challenges $\alpha$, $u$ and $\beta$.

One polynomial is not fixed before its side's $\alpha$. The nested side commits
its new restriction $m_q(W, x_q, y_q)$
[after $\alpha_q$](protocol.md#challenge-roles), and opens it at $w_q$, where
the two children's restrictions are opened as well. If the committed polynomial
is the registry's restriction, then its value at $w_q$ is determined by $w_q$,
$x_q$ and $y_q$, which precede $\alpha_q$, and the bound holds as stated. If it
is not, the three openings at $w_q$ can be false together while the batched
opening holds. The proof then carries a restriction that is not the registry's.
A parent opens that restriction at a $w_q$ of its own, where the same two cases
apply, and the [decider](decider.md) compares the root's with the registry.
What can be false in this second case is confined to the points at which the
new restriction is opened, which are $w_q$ and the $\omega_{q,j}$. An opening
at any other point is covered by the bound, and an opening of the restriction
that is alone at its point holds for every nonzero $\alpha_q$.

[^batch-bound]: Let $f$ stand for whatever polynomial is behind $[f]$. First,
    $p(u) - v$ is a polynomial in $\beta$ of degree at most $J$ whose
    coefficients are fixed before $\beta$: that of $\beta^{J-1-j}$ is
    $\psi_j(u) - \epsilon_j$, and that of $\beta^J$ is $f(u)$ less the first sum
    in the formula for $v$. If it vanishes at $\beta$ then, except with
    probability $J/|S_\beta|$, every $\epsilon_j$ is correct and $f(u)$ equals
    that sum. Second, group the openings by point, with
    $\text{num}_\rho(X) = \sum_{i : \rho_i = \rho} \alpha^{Q-1-i} (\phi_i(X) - \vartheta_i)$
    for each distinct point $\rho$. The equality for $f(u)$ says that $u$ is a
    root of
    $$f(X) \prod_{\rho} (X - \rho) - \sum_{\rho} \text{num}_\rho(X) \prod_{\rho' \ne \rho} (X - \rho'),$$
    a polynomial of degree at most $4n - 1 + D$ that is fixed before $u$. Its
    value at a point $\rho$ is a nonzero multiple of $\text{num}_\rho(\rho)$,
    so it is nonzero unless every $\text{num}_\rho(\rho)$ is zero. Third,
    $\text{num}_\rho(\rho)$ is a polynomial in $\alpha$ of degree at most
    $Q - 1$ whose coefficients, the differences $\phi_i(\rho_i) - \vartheta_i$,
    are fixed before $\alpha$ when every opening is, and it is nonzero when an
    opening at $\rho$ is false. On the native side $S_\alpha$ and $S_u$ are the
    field, and $D$ is at most $70$. On the nested side they have $2^{143}$
    elements, and $D$ is at most $56$. $S_\beta$ has $2^{143}$ elements on both
    sides, since $\beta$ and $\beta_q$ are lifts of one endoscalar.

| | Native | Nested |
|---|---|---|
| $Q$ | 172 | 150 |
| $J$ | 114 | 100 |
| $\alpha$, $u$ | $\alpha$, $u$ | $\alpha_q$, $u_q$ |
| $\beta$ | $\text{lift}_p(\text{endo}(\text{pre\_beta}))$ | $\beta_q = \text{lift}_q(\text{endo}(\text{pre\_beta}))$ |
| claimed values $\vartheta_i$ in | `query` stage | `BridgeQuery` stage |
| evaluations $\epsilon_j$ in | `eval` stage | `BridgeEval` stage |
| $P$ computed by | the [nested walk](walks.md#nested-walk) | the [native walk](walks.md#native-walk) |

$f$ and $f_q$ are committed as they are: neither is a trace, and no coefficient
of either is drawn at random.

## Native Openings {#native-openings}

The $172$ native openings fall into five groups, by what they establish.

- Openings $0$ and $1$ are the children's own batched openings.
- Openings $2$ to $12$ are the [registry chain](#registry-chain) and the value
  of the registry at the fuse's own step circuit.
- Openings $13$ to $112$ concern $A$, $B$, the children's $A^{(i)}$ and
  $B^{(i)}$, the two polynomials of the step circuit's trace and every rx
  polynomial of the children, at $xz$ or $x$. The circuit [recomputes](#ax-bx)
  the values of $A$ and $B$ from the others.
- Openings $113$ to $165$ read the registry at the fixed domain points.
- Openings $166$ to $171$ are the online openings of the step.

The claimed values in the last column are fields of the
[`query` stage](stage_contents.md#native-query) unless stated otherwise.

| $i$ | Polynomial $\phi_i$ | Point $\rho_i$ | Claimed Value $\vartheta_i$ |
|---|---|---|---|
| 0, 1 | $p^{(0)}$, $p^{(1)}$ | $u^{(0)}$, $u^{(1)}$ | $v^{(0)}$, $v^{(1)}$ from `preamble` |
| 2, 3 | $m(W, x^{(0)}, y^{(0)})$, $m(W, x^{(1)}, y^{(1)})$ | $w$ | `child_registry_xy_at_current_w` |
| 4, 5 | $m(w, x^{(0)}, Y)$, $m(w, x^{(1)}, Y)$ | $y^{(0)}$, $y^{(1)}$ | the same wires as $2$, $3$ |
| 6, 7 | $m(w, x^{(0)}, Y)$, $m(w, x^{(1)}, Y)$ | $y$ | `current_registry_wy_at_child_x` |
| 8, 9 | $m(w, X, y)$ | $x^{(0)}$, $x^{(1)}$ | the same wires as $6$, $7$ |
| 10 | $m(w, X, y)$ | $x$ | `registry_wxy` |
| 11 | $m(W, x, y)$ | $w$ | the same wire as $10$ |
| 12 | $m(W, x, y)$ | $\omega_{\text{id}}$ | `registry_xy_at_circuit_id` |
| 13, 14 | $A^{(0)}$, $B^{(0)}$ | $xz$, $x$ | `left.a_poly_at_xz`, `left.b_poly_at_x` |
| 15, 16 | $A^{(1)}$, $B^{(1)}$ | $xz$, $x$ | `right.a_poly_at_xz`, `right.b_poly_at_x` |
| 17, 18 | $A$, $B$ | $xz$, $x$ | $\text{ax}$, $\text{bx}$, [computed in circuit](#ax-bx) |
| 19, 20 | $r[\texttt{Application}]$, $r[\texttt{ApplicationStage}]$ | $xz$ | `application_at_xz`, `application_stage_at_xz` |
| $21 + t$, $t < 46$ | $r^{(0)}[\cdot]$ in [rx order](setup.md#rx-order) | $xz$ | `left.rx` |
| $67 + t$, $t < 46$ | $r^{(1)}[\cdot]$ in rx order | $xz$ | `right.rx` |
| $113 + j$, $j < 53$ | $m(W, x, y)$ | $\omega_j$ | `fixed_registry` |
| $166 + s$, $s < 6$ | the online slot polynomial $s$ | $\xi_s$ | $\eta_s$ from `preamble` |

### Native Batched Polynomials {#native-p}

| $j$ | $\psi_j$ |
|---|---|
| $50i + t$, $t < 46$ | $r^{(i)}[\cdot]$ in rx order |
| $50i + 46$, $50i + 47$ | $A^{(i)}$, $B^{(i)}$ |
| $50i + 48$ | $m(W, x^{(i)}, y^{(i)})$ |
| $50i + 49$ | $p^{(i)}$ |
| 100, 101 | $m(w, x^{(0)}, Y)$, $m(w, x^{(1)}, Y)$ |
| 102, 103 | $r[\texttt{Application}]$, $r[\texttt{ApplicationStage}]$ |
| 104 | $m(w, X, y)$ |
| 105, 106 | $A$, $B$ |
| 107 | $m(W, x, y)$ |
| 108 to 113 | $o^{(0)}_0, o^{(0)}_1, o^{(1)}_0, o^{(1)}_1, o_0, o_1$ |

## Nested Openings {#nested-openings}

The claimed values are fields of the
[`BridgeQuery` stage](stage_contents.md#bridge-query) unless stated otherwise.

| $i$ | Polynomial $\phi_i$ | Point $\rho_i$ | Claimed Value $\vartheta_i$ |
|---|---|---|---|
| 0, 1 | $p_q^{(0)}$, $p_q^{(1)}$ | $u_q^{(0)}$, $u_q^{(1)}$ | $v_q^{(0)}$, $v_q^{(1)}$ from `BridgePreamble` |
| 2, 3 | $m_q(W, x_q^{(0)}, y_q^{(0)})$, $m_q(W, x_q^{(1)}, y_q^{(1)})$ | $w_q$ | `child_registry_xy_at_current_w` |
| 4, 5 | $m_q(w_q, x_q^{(0)}, Y)$, $m_q(w_q, x_q^{(1)}, Y)$ | $y_q^{(0)}$, $y_q^{(1)}$ | the same wires as $2$, $3$ |
| 6, 7 | $m_q(w_q, x_q^{(0)}, Y)$, $m_q(w_q, x_q^{(1)}, Y)$ | $y_q$ | `current_registry_wy_at_child_x` |
| 8, 9 | $m_q(w_q, X, y_q)$ | $x_q^{(0)}$, $x_q^{(1)}$ | the same wires as $6$, $7$ |
| 10 | $m_q(w_q, X, y_q)$ | $x_q$ | `registry_wxy` |
| 11 | $m_q(W, x_q, y_q)$ | $w_q$ | the same wire as $10$ |
| 12, 13 | $A_q^{(0)}$, $B_q^{(0)}$ | $x_q z_q$, $x_q$ | `left.a_poly_at_xz`, `left.b_poly_at_x` |
| 14, 15 | $A_q^{(1)}$, $B_q^{(1)}$ | $x_q z_q$, $x_q$ | `right.a_poly_at_xz`, `right.b_poly_at_x` |
| 16, 17 | $A_q$, $B_q$ | $x_q z_q$, $x_q$ | $\text{ax}_q$, $\text{bx}_q$, [computed in circuit](#ax-bx) |
| $18 + t$, $t < 43$ | $r_q^{(0)}[\cdot]$ in rx order | $x_q z_q$ | `left.rx` |
| $61 + t$, $t < 43$ | $r_q^{(1)}[\cdot]$ in rx order | $x_q z_q$ | `right.rx` |
| $104 + j$, $j < 46$ | $m_q(W, x_q, y_q)$ | $\omega_{q,j}$ | `fixed_registry` |

The nested list has no opening at the index of a step circuit, because every
nested circuit has a fixed registry index. It also has no online openings.

### Nested Batched Polynomials {#nested-p}

| $j$ | $\psi_{q,j}$ |
|---|---|
| $47i + t$, $t < 43$ | $r_q^{(i)}[\cdot]$ in rx order |
| $47i + 43$, $47i + 44$ | $A_q^{(i)}$, $B_q^{(i)}$ |
| $47i + 45$ | $m_q(W, x_q^{(i)}, y_q^{(i)})$ |
| $47i + 46$ | $p_q^{(i)}$ |
| 94, 95 | $m_q(w_q, x_q^{(0)}, Y)$, $m_q(w_q, x_q^{(1)}, Y)$ |
| 96 | $m_q(w_q, X, y_q)$ |
| 97, 98 | $A_q$, $B_q$ |
| 99 | $m_q(W, x_q, y_q)$ |

## Registry Chain {#registry-chain}

Each child brings a claim about a restriction of the
[registry polynomial](registry.md) at its own challenges,
$m(W, x^{(i)}, y^{(i)})$. The fuse needs the registry at fresh $x$ and $y$, and
gets there one variable at a time, through restrictions that it commits. The
code names them.

| Name | Polynomial |
|---|---|
| `registry_wx0`, `registry_wx1` | $m(w, x^{(0)}, Y)$, $m(w, x^{(1)}, Y)$ |
| `registry_wy` | $m(w, X, y)$ |
| `registry_xy` | $m(W, x, y)$, of degree less than the size of the domain |

Two consecutive restrictions agree at one point, and the batch states the
agreement by giving two openings the same claimed-value wire.

| Shared By | Common Value | Polynomials Related |
|---|---|---|
| 2 and 4, 3 and 5 | $m(w, x^{(i)}, y^{(i)})$ | the child's `registry_xy` and this fuse's `registry_wx` |
| 6 and 8, 7 and 9 | $m(w, x^{(i)}, y)$ | this fuse's `registry_wx` and `registry_wy` |
| 10 and 11 | $m(w, x, y)$ | this fuse's `registry_wy` and `registry_xy` |

The chain thus carries a child's claim about $m(W, x^{(i)}, y^{(i)})$ over to a
claim about $m(W, x, y)$. `registry_wx` is committed before $y$ is drawn, and
`registry_wy` before $x$. `registry_xy` depends on $x$ and $y$, so it is
committed after $w$. The next fuse opens it at its own $w$, as openings $2$ and
$3$ do here for the children.

The new restriction $m(W, x, y)$ is then read at the domain points: opening
$113 + j$ gives $s_j(x, y)$ for each of the $53$ fixed indices, and opening $12$
gives $s_{\text{id}}(x, y)$ for the fuse's own step circuit. The nested chain is
the same, with the nested registry.

## Values of the Folded Polynomials {#ax-bx}

No stage holds a claimed value for openings $17$ and $18$. The `compute_v`
circuit computes $A(xz)$ and $B(x)$ from the other opened values, which binds
the folded polynomials to the [claim list](claims.md#native-claims).

For claim $k$, let $\text{ax}_k$ be its $a$ side with each polynomial replaced by
that polynomial's opened value at $xz$. A sum stays a sum and a Horner list in
$z$ stays a Horner list. The value $\text{bx}_k$ follows from the kind of the
claim, with $s_j(x, y)$ taken from `fixed_registry`, or from
`registry_xy_at_circuit_id` for the step circuit.

| Claim Kind | $\text{ax}_k$ | $\text{bx}_k$ |
|---|---|---|
| raw | $A^{(i)}(xz)$ | $B^{(i)}(x)$ |
| circuit at index $j$ | as above | $\text{ax}_k + s_j(x, y) + t(x, z)$ |
| bonding at index $j$ | as above | $s_j(x, y)$ |

The two values are

$$\text{ax} = \sum_{k} \text{wt}_k \, \text{ax}_k, \qquad \text{bx} = \sum_{k} \text{wt}_k \, \text{bx}_k,$$

with the [fold weights](claims.md#fold-layer-2) $\text{wt}_k$. A circuit claim's
$b$ side at $x$ is $a(xz) + s_j(x, y) + t(x, z)$, so the same opened values are
used for both sides. The nested circuit does the same over the nested claims,
with $x_q$, $z_q$, $\mu_q$ and $\mu'_q$.
