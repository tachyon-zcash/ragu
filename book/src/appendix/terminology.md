# Terminology

## Registry, Stage, and Circuit Terminology Mapping

| Concept | Term | Code Reference |
|---------|------|----------------|
| Defines stage structure; specifies wire range and corresponds with a stage polynomial that represents a partial witness | **Stage** | `preamble::Stage` |
| Input data for a stage | **Stage witness** | `Stage::witness()` |
| Well-formedness check for a stage; $s$ polynomial enforcing linear independence (for multi-stage circuits, these masks are batched in the revdot check) | **Stage mask** | `Stage::mask()` or `Stage::final_mask()` |
| Circuit using staged witnesses | **Multi-stage circuit** | `MultiStageCircuit` |
| Combined witness across all stages | **Multi-stage witness** | implicit, concatenation of stage witness |
| Combined $r(X) = a(X) + b(X) + \cdots + f(X)$ | **Multi-stage witness polynomial $r(X)$** | implicit, sum of all `Stage::rx()` |
| Collection of circuits indexed by $\omega^i$; $m(W, X, Y)$ interpolating wiring polynomials | **Registry** | `Registry`, `RegistryBuilder` |
