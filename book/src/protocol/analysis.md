# Analysis

This chapter examines performance characteristics and practical considerations
for deploying Ragu. Understanding these trade-offs helps evaluate when Ragu's
aggregated verification approach provides benefits over traditional batch
verification methods.

## Performance Analysis

### Ragu Aggregated Verification vs. Orchard Batch Verification

A central question for Ragu's practical deployment is: _at what point does
aggregated proof verification outperform batch verification of independent
proofs?_ This section establishes rough bounds for when Ragu becomes more
efficient than Orchard's batch verification.

#### Background

[Orchard](https://zcash.github.io/orchard/) is Zcash's shielded transaction
protocol, which uses [Halo2](https://zcash.github.io/halo2/)—a SNARK system
based on the Halo construction. Orchard currently uses batch verification of
Halo2 proofs, achieving verification times of approximately 10–15ms per proof
on a single thread. Batch verification provides sublinear scaling: verifying
$n$ proofs costs roughly $O(n / \log n)$ rather than $O(n)$ due to multi-scalar
multiplication (MSM) batching.

Ragu, in contrast, uses proof-carrying data (PCD) to recursively aggregate
proofs. The verifier only needs to check a single aggregated proof regardless
of how many underlying transactions were folded together. However, this
aggregated proof is more expensive to verify than a single Orchard proof.

#### Ragu Verification Cost Drivers

Ragu's verification cost is primarily determined by:

1. **Circuit constraint count**: The verifier circuit contains $4N$ linear
   constraints, where $N = 2^K$ and $K$ is the recursion threshold (preferred
   value: $K = 11$). The factor of 4 arises from the circuit structure across
   multiple stages.

2. **Multi-scalar multiplication size**: This corresponds to an MSM of size
   $4N = 4 \cdot 2^{11} = 2^{13} = 8192$ group elements, which dominates the
   verifier's computational cost.

3. **Curve cycle overhead**: Ragu operates over a cycle of curves (Pasta),
   which introduces additional overhead compared to single-curve constructions.

Based on these factors, we estimate Ragu verification at approximately
**100ms** for the preferred recursion threshold of $K = 11$.

#### Break-Even Analysis

Comparing the two approaches:

| Approach | Cost Model |
|----------|------------|
| Orchard batch | $N_{\text{tx}} \times 10\text{ms} \;/\; \log(N_{\text{tx}})$ |
| Ragu aggregated | $\approx 100\text{ms}$ (constant for fixed $K$) |

Solving for the break-even point where Ragu becomes more efficient:

$$
\frac{N_{\text{tx}} \times 10\text{ms}}{\log(N_{\text{tx}})} \approx 100\text{ms}
$$

This yields approximately $N_{\text{tx}} \approx 50$ transactions as the
crossover point.

```admonish note
These are rough estimates that should be validated with empirical benchmarks.
The actual break-even point will depend on hardware, implementation
optimizations, and the specific circuit configurations used.
```

The break-even analysis above assumes a fixed recursion threshold of $K = 11$,
but this parameter itself presents important design choices.

#### Recursion Threshold Trade-offs

The recursion threshold $K$ presents an interesting trade-off space:

- **Larger $K$**: Larger circuits mean higher verification cost per proof, but
  shallower PCD trees are needed (fewer recursive steps to aggregate many
  proofs).

- **Smaller $K$**: Smaller circuits mean lower verification cost per proof, but
  deeper PCD trees are required to aggregate the same number of proofs.

#### Future Work

More rigorous analysis should:

1. Establish precise MSM cost models for both Pallas and Vesta curves
2. Account for parallelization opportunities in both batch and aggregated
   verification
3. Consider amortization across multiple blocks and the full PCD tree structure
4. Benchmark actual implementations to validate theoretical predictions

---

In summary, Ragu's aggregated verification becomes advantageous over Orchard's
batch verification at roughly 50 transactions for the default $K = 11$
threshold.
