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

The estimates in this section use the former production configuration:
gate capacity $N = 2^{11}$ and recursion threshold $\mathrm{RT} = 4N = 8192$.
The current production configuration has gate capacity $N = 2^{12}$ and
recursion threshold $\mathrm{RT} = 4N = 16384$; these historical estimates
have not been rerun for it.

Ragu's verification cost is primarily determined by:

1. **Polynomial coefficient capacity**: A rank-$r$ polynomial has $4N = 2^r$
   coefficients, where $N = 2^{r-2}$ is the gate capacity. The estimates here
   use the former production rank $r = 13$.

2. **Multi-scalar multiplication size**: This corresponds to an MSM of size
   $4N = 4 \cdot 2^{11} = 2^{13} = 8192$ group elements, which dominates the
   verifier's computational cost.

3. **Curve cycle overhead**: Ragu operates over a cycle of curves (Pasta),
   which introduces additional overhead compared to single-curve constructions.

Based on these factors, we estimate Ragu verification at approximately
**100ms** for the former gate capacity $N = 2^{11}$.

#### Break-Even Analysis

Comparing the two approaches:

| Approach | Cost Model |
|----------|------------|
| Orchard batch | $N_{\text{tx}} \times 10\text{ms} \;/\; \log(N_{\text{tx}})$ |
| Ragu aggregated | $\approx 100\text{ms}$ (constant for fixed $\mathrm{RT}$) |

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

The break-even analysis above uses the former recursion threshold
$\mathrm{RT} = 8192$. Choosing the threshold itself presents further design
trade-offs.

#### Recursion Threshold Trade-offs

The recursion threshold $\mathrm{RT} = 4N$ presents a trade-off space:

- **Larger RT**: Larger polynomials increase MSM size and dense storage per
  polynomial.
  Larger circuits can pack more endoscalings and application work, reducing
  the number of internal circuits and potentially application steps. Fewer
  recursive commitments can offset the larger MSM, so verification cost must
  be measured for each configuration.

- **Smaller RT**: Smaller polynomials reduce MSM size and dense storage per
  polynomial, but the same workload may require more internal circuits and
  application steps.

#### Future Work

More rigorous analysis should:

1. Establish precise MSM cost models for both Pallas and Vesta curves
2. Account for parallelization opportunities in both batch and aggregated
   verification
3. Consider amortization across multiple blocks and the full PCD tree structure
4. Benchmark actual implementations to validate theoretical predictions

---

The historical model estimates a crossover near 50 transactions for the
former $\mathrm{RT} = 8192$ configuration. The current
$\mathrm{RT} = 16384$ configuration requires separate benchmarks.
