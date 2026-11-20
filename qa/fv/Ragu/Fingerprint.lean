import Ragu.Core
import Ragu.Fingerprint.Sha256

/-!
# Canonical circuit fingerprints

Computes the SHA-256 digest of a canonical byte encoding of the operation
trace and output expressions a `FormalInstance`'s reimplementation emits,
instantiated at the canonical input vector `#v[var ⟨2³² + 0⟩, ...]`.
Expressions are hashed in their *polynomial normal form* (`normalize`) — a
sorted list of monomials over variables with their coefficients — not in the
tree shape they were built in, so `w + w` and `2 · w` are the same
constraint, exactly as they are for the constraint system. The Rust
extractor computes the same digest from its in-memory extracted trace, and CI
compares the two: a match means the reimplementation emits exactly the
operations and outputs of the Rust circuit.

The byte-level encoding, the input-variable index convention, and the trust
assumptions of the check are specified in the FV book
(`src/fv/circuits/fingerprint.md` in the `fv` repository); this module and
`qa/fv/extraction/src/fingerprint.rs` implement that spec and must
stay in lockstep.
-/

namespace Ragu.Fingerprint

/-- Wire index at which canonical input variables start (`2³²`). -/
def inputVarOffset : ℕ := 2 ^ 32

/-- Append `n` to `buf` as `bytes` little-endian bytes.

Truncates if `n ≥ 2^(8 * bytes)`; callers must bound-check first, or the
encoding loses injectivity. -/
def pushNatLE (bytes : ℕ) (buf : ByteArray) (n : ℕ) : ByteArray :=
  (List.range bytes).foldl (fun acc i => acc.push (UInt8.ofNat ((n >>> (8 * i)) &&& 0xff))) buf

/-- Append a variable index or operation count as 8 little-endian bytes. -/
def pushNat64 : ByteArray → ℕ → ByteArray := pushNatLE 8

/-- Append a field element value or modulus as 32 little-endian bytes. -/
def pushNat256 : ByteArray → ℕ → ByteArray := pushNatLE 32

variable {p : ℕ}

/-! ### Polynomial normal form

The Rust extractor keeps expressions as DAGs and normalizes them to sparse
polynomials (`qa/fv/extraction/src/fingerprint.rs`); this is the
same normal form, computed structurally on `Clean`'s `Expression` trees. -/

/-- A monomial: the indices of the variables it multiplies, ascending, with
multiplicity (`[3, 3]` is `x₃²`). The empty monomial is the constant term. -/
abbrev Monomial := List ℕ

/-- Lexicographic order on monomials, a proper prefix sorting first — the
iteration order of the Rust encoder's `BTreeMap<Vec<u64>, _>`. -/
def Monomial.lt : Monomial → Monomial → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a < b then true else if b < a then false else Monomial.lt as bs

/-- A polynomial in canonical form: terms sorted by monomial, no zero
coefficients. -/
abbrev Poly (p : ℕ) := List (Monomial × F p)

/-- The polynomial `c · m`, empty when `c = 0`. -/
def Poly.single [Fact p.Prime] (m : Monomial) (c : F p) : Poly p :=
  if c = 0 then [] else [(m, c)]

/-- Sum of two canonical polynomials (a sorted merge that drops cancelled
terms). -/
def Poly.add [Fact p.Prime] : Poly p → Poly p → Poly p
  | [], q => q
  | q, [] => q
  | (m₁, c₁) :: t₁, (m₂, c₂) :: t₂ =>
    if Monomial.lt m₁ m₂ then (m₁, c₁) :: Poly.add t₁ ((m₂, c₂) :: t₂)
    else if Monomial.lt m₂ m₁ then (m₂, c₂) :: Poly.add ((m₁, c₁) :: t₁) t₂
    else if c₁ + c₂ = 0 then Poly.add t₁ t₂
    else (m₁, c₁ + c₂) :: Poly.add t₁ t₂
termination_by a b => a.length + b.length

/-- Product of two canonical polynomials: distribute, re-sorting every product
monomial. -/
def Poly.mul [Fact p.Prime] (a b : Poly p) : Poly p :=
  a.foldl (init := []) fun acc (m₁, c₁) =>
    b.foldl (init := acc) fun acc (m₂, c₂) =>
      acc.add (Poly.single ((m₁ ++ m₂).mergeSort) (c₁ * c₂))

/-- Canonical polynomial normal form of an expression. -/
def normalize [Fact p.Prime] : Expression (F p) → Poly p
  | .var v => Poly.single [v.index] 1
  | .const c => Poly.single [] c
  | .add x y => (normalize x).add (normalize y)
  | .mul x y => (normalize x).mul (normalize y)

/-- Append the canonical encoding of a polynomial: its term count, then each
term as the monomial's degree, the monomial's variable indices, and the
coefficient.

Fails on variable indices at or above `bound` (the end of the canonical
input region), which could otherwise collide with encoded input variables. -/
def pushPoly (bound : ℕ) (buf : ByteArray) (poly : Poly p) : Except String ByteArray := do
  let mut buf := pushNat64 buf poly.length
  for (m, c) in poly do
    buf := pushNat64 buf m.length
    for v in m do
      if v < bound then
        buf := pushNat64 buf v
      else
        throw s!"variable index {v} collides with the input variable region"
    buf := pushNat256 buf c.val
  return buf

/-- Append the canonical encoding of a flat operation. Witness computation
functions are not encoded; lookups and channel interactions are unsupported. -/
def pushFlatOp [Fact p.Prime] (bound : ℕ) (buf : ByteArray)
    : FlatOperation (F p) → Except String ByteArray
  | .witness m _ =>
    if m < 2 ^ 64 then
      pure (pushNat64 (buf.push 0x01) m)
    else
      throw s!"witness count {m} does not fit in 64 bits"
  | .assert e => pushPoly bound (buf.push 0x02) (normalize e)
  | .lookup _ => throw "lookup operations are not supported by the fingerprint encoding"
  | .interact _ => throw "channel interactions are not supported by the fingerprint encoding"

end Ragu.Fingerprint

open Ragu.Fingerprint in
/-- The canonical fingerprint of this instance's `reimplementation`,
instantiated at the canonical input vector, as a lowercase hex digest.

CI compares this against the digest the Rust extractor computes from its
extracted trace; see the module documentation of `Ragu.Fingerprint`. -/
def Ragu.Core.Statements.FormalInstance.fingerprint
    (inst : Ragu.Core.Statements.FormalInstance) : Except String String :=
  letI := inst.pPrime
  letI := inst.InputCircuit
  letI := inst.InputValueProvable
  letI := inst.OutputProvable
  let inputLen := size (Value inst.Input)
  let outputLen := size inst.Output
  let bound := inputVarOffset + inputLen
  let input : Vector (Expression (F inst.p)) inputLen :=
    .ofFn fun i => var ⟨inputVarOffset + i.val⟩
  let circuit := inst.reimplementation (inst.deserializeInput input)
  let ops := (circuit.operations 0).toFlat
  let outputs := inst.serializeOutput (circuit.output 0)
  do
    -- `pushNatLE` truncates out-of-range values, so reject them up front.
    if inst.p ≥ 2 ^ 256 then
      throw s!"modulus does not fit in 256 bits"
    if inputLen ≥ inputVarOffset then
      throw s!"input length {inputLen} overflows the input variable region"
    let mut buf := "ragu-fv-fingerprint-v2".toUTF8
    buf := pushNat256 buf inst.p
    buf := pushNat64 buf inputLen
    buf := pushNat64 buf outputLen
    buf := pushNat64 buf ops.length
    for op in ops do
      buf ← pushFlatOp bound buf op
    for output in outputs.toList do
      buf ← pushPoly bound buf (normalize output)
    return Sha256.hexDigest (Sha256.hash buf)
