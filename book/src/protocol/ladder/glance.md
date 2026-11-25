# The Ladder at a Glance

| Rung | Refinement | Deferred or Opened | Paid or Closed By |
| --- | --- | --- | --- |
| [0](rung_00.md) | check the whole history | nothing | the verifier, in full |
| [1](rung_01.md) | one revdot equation per circuit | nothing | the verifier, at random $y$, $z$ |
| [2](rung_02.md) | commit before challenging | three linear-cost jobs per node | rungs [3](rung_03.md) to [10](rung_10.md) |
| [3](rung_03.md) | carry an accumulator | the three jobs, to the root | rungs [15](rung_15.md), [16](rung_16.md) |
| [4](rung_04.md), [5](rung_05.md), [6](rung_06.md) | fold revdot claims with a committed quotient, in two layers | correctness of $[A]$, $[B]$ | [rung 7](rung_07.md) |
| [7](rung_07.md) | test the folded polynomials at $x$ | evaluations; wiring values | rungs [8](rung_08.md), [9](rung_09.md) |
| [8](rung_08.md) | registry polynomial and restriction chain | more evaluations; a new wiring claim | rungs [9](rung_09.md), [15](rung_15.md) |
| [9](rung_09.md), [10](rung_10.md) | quotient batching, then one combined opening | group arithmetic for $P$ | [rung 11](rung_11.md) |
| [11](rung_11.md) | curve cycle with a mirrored accumulator; challenges as lifts of 143 bits | a large verifier on each side; cross-curve consistency | rungs [12](rung_12.md), [14](rung_14.md) |
| [12](rung_12.md) | stages and masks | stage support | mask claims in the fold |
| [13](rung_13.md) | Fiat-Shamir, recomputed in circuit | binding of the last challenge | the parent, or the decider |
| [14](rung_14.md) | statement, base case, walk and setup bindings | the root's own checks | [rung 15](rung_15.md) |
| [15](rung_15.md) | decider | proof size | [rung 16](rung_16.md) |
| [16](rung_16.md) | absorb the statement, then compress to one opening proof per curve | nothing | the verifier of the compressed proof |
