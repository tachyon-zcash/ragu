# Fingerprint Equivalence Check

The deterministic connection between the Rust extractor trace and the Lean
reimplementations is established by a *fingerprint equivalence check*, in the
style of comparing verification keys. CI retains this exact check as a stable
diagnostic alongside the complementary
[direct randomized polynomial check](./polynomial-fingerprint.md).

A fingerprint is the SHA-256 digest of a canonical byte encoding of a
circuit's operation trace and output expressions, with every expression
taken in its *polynomial normal form* (below). It is computed twice, through
two independent implementations:

- The **Rust extractor** computes it directly from its in-memory extracted
  trace: `cargo run -p lean_extraction -- fingerprint` prints one
  `<module name> <digest>` line per exported instance.
- The **Lean side** computes it from each `FormalInstance`'s `reimplementation`
  — the structured `Clean` circuit — instantiated at a canonical input vector:
  `lake exe fingerprints` prints lines in the same format. (CI runs the entry
  point through the Lean interpreter instead,
  `lake env lean --run Ragu/Fingerprint/Main.lean`, which avoids building native
  code for the whole import closure.)

CI compares the two outputs and fails on any mismatch. Because the Rust output
enumerates every exported instance, a missing or stale entry on the Lean side
also fails the comparison.

## What a match means

Expressions are not hashed in the tree shape a driver happened to build them
in but as canonical polynomials over the wire variables: a sorted list of
monomials with their coefficients, zero terms dropped. `w + w` and `2 · w`
therefore encode identically, as do `(a + b) + c` and `a + (b + c)`. This is
the semantics a constraint system actually has — a constraint `e = 0` and a
virtual wire `e` depend on `e` only as a polynomial in the wires, which is
exactly what a production driver flattens an `add`/`enforce_zero` linear
combination into. It is also what makes the check total: a gadget such as
`Endoscalar::lift` feeds its own virtual output back into itself 47 times, and
its output is compared as a polynomial of a few hundred terms however either
side happened to build the tree.

The encoding of a normal form is injective: every token is either fixed-width
or length-prefixed, so the normalized trace can be unambiguously decoded from
the digest preimage. Two traces therefore produce the same digest only if
they are identical as polynomials, up to SHA-256 collisions.

A match consequently shows that the reimplementation emits exactly the same
witness allocations, constraints, and outputs as the Rust
`ExtractionDriver` reports, modulo polynomial normalization. This is an exact
statement about that three-wire symbolic model, not by itself a statement
about every production-driver detail. In particular, the extractor omits the
production gate's `D` slot and `C * D = 0` relation. The direct randomized check
runs the production gadget through a separate four-slot driver and covers that
gap probabilistically.

No Lean source code is generated from the extracted traces: the digest is the
only artifact that crosses the Rust-to-Lean boundary, and it is compared outside
the formalization, in CI.

## Trust assumptions

The fingerprint check is a computational consistency check between two
implementations of the encoding (Rust:
`qa/fv/extraction/src/fingerprint.rs`; Lean:
`qa/fv/Ragu/Fingerprint.lean`), not a kernel-checked proof:

- The check trusts that both encoder implementations realize the documented
  encoding, and it trusts SHA-256 collision resistance.
- It trusts that both normalizers compute the same normal form. The Rust
  extractor keeps expressions as reference-counted DAGs and normalizes them
  with a pass memoized by node address; the Lean side normalizes `Clean`'s
  `Expression` trees structurally. Both are small, deterministic functions
  (`normalize` in each encoder) and are part of the trusted base.
- The reimplementation is instantiated at one canonical input vector rather
  than universally quantified over symbolic inputs. Since the trace is a
  function of the input expressions only through their occurrence inside
  expressions, agreement at the canonical input pins down the trace shape;
  a contrived reimplementation could in principle special-case the canonical
  input, but the reimplementations are part of the reviewed proof
  development.
- Witness computation functions are not encoded: the digest captures
  allocations, constraints, and outputs, not witness generation. (The
  completeness theorems reason about the Lean witness generators, which are not
  compared against Rust; this matches the prior state of the project.)
- Lookup operations are not supported by the encoding and fail loudly.
- The extractor's three-wire gate shim is trusted. Its omission of `D`,
  `C * D = 0`, and the production identity of an `assign_extra` token is not
  repaired by hashing; see the direct randomized check for the complementary
  four-slot evaluation.

## Encoding

All integers are unsigned 64-bit little-endian; field elements and the modulus
are 32-byte little-endian. The digest preimage is:

```text
"ragu-fv-fingerprint-v2"      (22 raw ASCII bytes, domain separator)
modulus                       (32 bytes)
inputLen                      (u64)
outputLen                     (u64)
opCount                       (u64)
op*                           (opCount operations)
output*                       (outputLen polynomials)
```

Operations (`FlatOperation`, after flattening subcircuits):

```text
witness: 0x01 ++ count (u64)
assert:  0x02 ++ poly
```

Polynomials, the normal form of an expression:

```text
poly: termCount (u64) ++ term*
term: degree (u64) ++ varIndex (u64) × degree ++ coefficient (32 bytes)
```

A term's variable indices are ascending, with multiplicity (`x₃²` is
`[3, 3]`); the empty monomial is the constant term. Terms are sorted by
monomial in lexicographic order, a proper prefix sorting first (the constant
term, if any, comes first), and terms with a zero coefficient are omitted, so
the constant `0` is the empty polynomial. Normalization expands `add` into a
merge of the two operands' terms and `mul` into the distributed product with
each product monomial re-sorted.

`Clean`'s `Expression` type has no constructor for input variables, so the
Lean side instantiates the reimplementation at the canonical input vector
`#v[var ⟨2³² + 0⟩, var ⟨2³² + 1⟩, ...]`. Correspondingly, the Rust encoder
maps `Expr::InputVar(i)` to a `var` with index `2³² + i`. The Rust encoder
rejects ordinary wire indices at or above `2³²`, and the Lean encoder
rejects indices beyond the input region (`≥ 2³² + inputLen`). Inside the
input region the Lean encoder cannot tell a substituted input apart from a
raw `var` with the same index — `Clean` allocates variable indices
structurally from offsets, so such an index cannot arise from a well-formed
reimplementation; a contrived one falls under the trust assumptions above.

## Maintenance

The list of fingerprinted instances,
`qa/fv/Ragu/Fingerprint/Instances.lean`, is generated by the exporter
(together with the `Ragu/Instances.lean` import root) and kept up to date by
`cargo run -p lean_extraction -- check`, so adding a new instance to the
exporter's target table automatically enrolls it in the fingerprint check and
requires the corresponding `formal_instance` to exist. The SHA-256
implementations are hand-rolled on both sides (the digest comparison is a
consistency check between two implementations we control, not a security
boundary exposed to attackers) and validated against the FIPS 180-2 test
vectors at build time.
