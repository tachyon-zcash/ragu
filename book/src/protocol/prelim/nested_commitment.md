# Nested Commitments

Ragu uses a curve cycle (Pallas/Vesta) where each curve's scalar field is the other's base field. During recursive proofs, you often need to commit to data that lives in the "wrong" field — for example, representing Vesta points (with $F_q$ coordinates) inside an $F_p$ circuit.

A **nested commitment** solves this by wrapping a commitment from one curve in a commitment on the other:

* Build a staging polynomial on the foreign curve encoding the data you need,
* Commit to that staging polynomial,
* The resulting commitment point has coordinates in the native field that are hashable in the transcript

### Example

You're in an $F_p$ circuit and need to work with Vesta points $R_i$ (which have $F_q$ coordinates). You can't hash $F_q$ elements directly in $F_p$.

| Step                                        | Curve  | Result                             |
|---------------------------------------------|--------|------------------------------------|
| Encode $R_i$ in a staging polynomial        | —      | Polynomial with $F_q$ coefficients |
| Commit using Pallas generators              | Pallas | Pallas point $Q$                   |
| Use $Q$'s coordinates in circuit/transcript | —      | $Q.x, Q.y \in F_p$                 |

The *nested commitment* $Q$ cryptographically binds the original Vesta data while being native to the $F_p$ circuit. The next proof is responsible for checking that deferred arithmetic.

### Deferreds

Everything inside a *nested commitment* is deferred — the current proof can hash and use the commitment, but cannot verify the underlying data was encoded correctly (that would require foreign-field arithmetic).

The next proof in the recursion, operating over the other field, checks the deferred work:
- Verify the staging polynomial was well-formed,
- Verify any deferred operations (ie. endoscalings) were computed correctly
