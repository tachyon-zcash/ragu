# Step Capacity and Proving Cost

```admonish warning
The current production rank is `R<14>`, with 4,096 gates and 16,384 polynomial
coefficients. The historical measurements below have not been rerun at that
rank. Rerunning them is tracked in
[#900](https://github.com/tachyon-zcash/ragu/issues/900).
```

Designing a PCD application means answering two separate questions: how much
work fits inside a step, and how that work affects proving time. The answers
are not interchangeable, and the second is less intuitive than the first.

The figures below were measured under the former `ProductionRank` (`R<13>`),
which permits 2,048 gates and 8,192 constraints. The capacity sweeps used a
two-element header; the proving-time and witness sweeps used a four-element
header. Gate tables report complete registered-circuit counts, including fixed
synthesis overhead, so differences between rows isolate the added operation.

Structural counts do not depend on the machine that ran them, though they do
depend on the circuit implementation and configuration. The wall-clock figures
came from a release build with the `multicore` feature on a single developer
machine. Treat those timings as evidence about relationships and scale, not as
performance numbers that other hardware will reproduce.

## Capacity

In these sweeps the gate limit was reached before the constraint limit. The
marginal counts below are useful planning units, but mixed application logic
can share gates differently, and a synthesized circuit's final gate and
constraint counts remain authoritative.

### Poseidon Permutations

Chaining independent Poseidon permutations added 288 gates per permutation:

| permutations | gates |
| -----------: | ----: |
| 1 | 290 |
| 2 | 578 |
| 4 | 1,154 |
| 7 | 2,018 |
| 8 | exceeds the limit |

Seven chained permutations fit in the measured `R<13>` step.

### Endoscalar Operations

Chained endoscalar operations added 455 gates per operation:

| operations | gates |
| ---------: | ----: |
| 1 | 588 |
| 2 | 1,043 |
| 4 | 1,953 |
| 5 | exceeds the limit |

Four chained endoscalar operations fit.

### Repeated Squeezes

Squeezing several field elements from one sponge cost less than creating a new
sponge for every output. The gate count rose only when another permutation was
required:

| squeezes | gates |
| -------: | ----: |
| 1 | 290 |
| 4 | 290 |
| 5 | 578 |
| 8 | 578 |
| 16 | 1,154 |
| 28 | 2,018 |

Within the sponge's rate, additional squeezes added no gates.

### Witness Allocations

An allocation-only step reached 4,092 witness elements before its gate count
approached the production limit. Pure allocations emitted no constraints, and
paired allocations grew the gate count at roughly half the number of wires.

That bound belongs to the allocation-only circuit under test, not to
applications in general. Other operations, headers, and bindings draw on the
same step budget.

## Proving Cost

Within the application under test, filling a step did not increase proving time
in proportion to its gate count. Growing one step from 2 gates to 2,018 gates
moved its time by a few percent:

| gates | fuse (ms) | seed (ms) |
| ----: | --------: | --------: |
| 2 | 197.8 | 352.1 |
| 290 | 199.8 | 361.3 |
| 866 | 203.8 | 353.6 |
| 1,442 | 204.1 | 355.7 |
| 2,018 | 210.8 | 359.9 |

Gate count was therefore primarily a capacity constraint, not a useful
predictor of proving time within a step. The seed path took roughly 1.75 times
as long as the fuse path.

The witness sweep showed the same shape. Growing an allocation-only leaf step
from 1 to 4,092 witnesses moved total proving time for a fixed seven-node tree
by a few percent.

### Executed Nodes

Executed node count was the dominant scaling variable tested:

| depth | nodes | total (ms) | per node (ms) |
| ----: | ----: | ---------: | ------------: |
| 1 | 3 | 887.2 | 295.7 |
| 2 | 7 | 1,969.8 | 281.4 |
| 3 | 15 | 4,139.4 | 276.0 |
| 4 | 31 | 8,541.6 | 275.5 |

Total proving time grew linearly with the number of executed nodes over this
range, converging to roughly 276 milliseconds per node.

Using distinct step types, threading distinct headers through the tree, and
crossing a `log2_circuits` boundary added no per-node cost over the tested
range. Each converged to about the same per-node time as a tree that reused
its step types.

## Design Guidance

When a step exceeds its rank, split the computation, as
[Configuration](configuration.md) suggests. Each additional executed node still
incurs the fixed cost of another proof operation, but these sweeps found no
separate proving-time penalty from distributing circuit work across distinct
steps.

Packing work into an existing step is worthwhile when it avoids an additional
node. Shaving gates without changing the node count showed little benefit, so
optimize a step's gate count when it approaches capacity rather than assuming a
smaller circuit proves proportionally faster.

These figures cover step capacity and proving time for specific configurations.
They do not characterize verification cost, proof size, memory usage, or every
combination of operations. Re-measure when a change to the circuit
implementation or application configuration could move a boundary.
