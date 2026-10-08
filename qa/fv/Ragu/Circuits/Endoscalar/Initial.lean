import Clean.Circuit
import Clean.Gadgets.Boolean
import Mathlib.Tactic.LinearCombination
import Ragu.Circuits.Element.Mul
import Ragu.Circuits.Element.Square
import Ragu.Circuits.Point.Spec

namespace Ragu.Circuits.Endoscalar.Initial
variable {p : ℕ} [Fact p.Prime] [NeZero (2 : F p)]

/-- The normalized base's coordinate `r` and the endoscalar's two initial
bits: the sign `s₀` and the twist `e₀`. -/
structure Input (F : Type) where
  r : F
  s0 : F
  e0 : F
deriving ProvableStruct

/-- The walk's initial accumulator `A₀ = [2] (-1)^{s₀} φ^{e₀} (r, r)` in four
gates, mirroring `crates/ragu_primitives/src/endoscalar.rs::walk`: the
tangent at `(r, r)` has the linear slope `t = 3r / 2`, so the doubling is
`x₂ = t² - 2r` (square) and `y₂ = t (r - x₂) - r` (mul); then
`x = x₂ (1 + (ζ - 1) e₀)` and `y = y₂ (1 - 2 s₀)` (two muls) apply the
twist and the sign. -/
def main (curveParams : Point.Spec.CurveParams p) (input : Var Input (F p))
    : Circuit (F p) (Var Point.Spec.Point (F p)) := do
  let ⟨r, s0, e0⟩ := input
  let t := Expression.const (3 * (2 : F p)⁻¹) * r
  let t_sq ← Element.Square.circuit t
  let x2 := t_sq - (r + r)
  let y_term ← Element.Mul.circuit ⟨t, r - x2⟩
  let y2 := y_term - r
  let twist := 1 + Expression.const (curveParams.ζ - 1) * e0
  let sign := 1 + Expression.const (-2) * s0
  let x ← Element.Mul.circuit ⟨x2, twist⟩
  let y ← Element.Mul.circuit ⟨y2, sign⟩
  return ⟨x, y⟩

/-- `[2] (-1)^{s₀} φ^{e₀} (r, r)`, `none` when the doubling is degenerate
(only for `r = 0`). -/
def initNative (curveParams : Point.Spec.CurveParams p) (r s0 e0 : F p)
    : Option (Point.Spec.Point (F p)) :=
  match (⟨r, r⟩ : Point.Spec.Point (F p)).double with
  | none => none
  | some d =>
    let d := if e0 = 1 then d.endo curveParams else d
    some (if s0 = 1 then d.negate else d)

def Assumptions (_curveParams : Point.Spec.CurveParams p) (input : Input (F p)) :=
  IsBool input.s0 ∧ IsBool input.e0 ∧ input.r ≠ 0

def Spec (curveParams : Point.Spec.CurveParams p) (input : Input (F p))
    (output : Point.Spec.Point (F p)) :=
  initNative curveParams input.r input.s0 input.e0 = some output

/-- The output on the layout: the two trailing Muls' product wires. -/
@[circuit_norm]
def output (offset : ℕ) : Var Point.Spec.Point (F p) :=
  ⟨varFromOffset field (offset + 3 + 3 + 2), varFromOffset field (offset + 3 + 3 + 3 + 2)⟩

instance elaborated (curveParams : Point.Spec.CurveParams p)
    : ElaboratedCircuit (F p) Input Point.Spec.Point (main curveParams) where
  -- Square (3) + Mul (3) + Mul (3) + Mul (3)
  localLength _ := 12
  output _ offset := output offset
  output_eq := by
    intro input offset
    rcases input with ⟨r, s0, e0⟩
    simp [main, output, circuit_norm, Element.Square.circuit, Element.Mul.circuit]

/-- The doubling of `(r, r)` on the wires: with `t = 3r / 2`, the point
`(t² - 2r, t (r - (t² - 2r)) - r)`. -/
private lemma double_rr (r : F p) (hr : r ≠ 0) :
    (⟨r, r⟩ : Point.Spec.Point (F p)).double =
      some ⟨(3 * (2 : F p)⁻¹ * r) ^ 2 - (r + r),
        3 * (2 : F p)⁻¹ * r * (r - ((3 * (2 : F p)⁻¹ * r) ^ 2 - (r + r))) - r⟩ := by
  have h2 : (2 : F p) ≠ 0 := NeZero.ne 2
  have hlam : 3 * r ^ 2 / (2 * r) = 3 * (2 : F p)⁻¹ * r := by
    field_simp
  simp only [Point.Spec.Point.double, if_neg hr, hlam, Option.some.injEq,
    Point.Spec.Point.mk.injEq]
  exact ⟨by ring, by ring⟩

theorem soundness (curveParams : Point.Spec.CurveParams p) :
    Soundness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
      (Assumptions curveParams) (Spec curveParams) := by
  circuit_proof_start [Element.Square.circuit, Element.Square.Assumptions, Element.Square.Spec,
    Element.Mul.circuit, Element.Mul.Assumptions, Element.Mul.Spec, output]
  obtain ⟨h_s0, h_e0, h_r⟩ := h_assumptions
  obtain ⟨h_sq, h_yt, h_x, h_y⟩ := h_holds
  simp only [initNative, double_rr input_r h_r]
  simp only [Option.some.injEq]
  rw [h_x, h_y, h_yt, h_sq]
  rcases h_s0 with hs | hs <;> rcases h_e0 with he | he <;>
    simp only [hs, he, zero_ne_one, if_false, if_true, Point.Spec.Point.endo,
      Point.Spec.Point.negate, Point.Spec.Point.mk.injEq] <;>
    exact ⟨by ring, by ring⟩

omit [NeZero (2 : F p)] in
theorem completeness (curveParams : Point.Spec.CurveParams p) :
    Completeness (F p) (Input := Input) (Output := Point.Spec.Point) (main curveParams)
      (Assumptions curveParams) := by
  circuit_proof_start [Element.Square.circuit, Element.Square.Assumptions,
    Element.Mul.circuit, Element.Mul.Assumptions]

def circuit (curveParams : Point.Spec.CurveParams p) :
    FormalCircuit (F p) Input Point.Spec.Point :=
  { main := main curveParams,
    elaborated := elaborated curveParams,
    Assumptions := Assumptions curveParams
    Spec := Spec curveParams
    soundness := soundness curveParams
    completeness := completeness curveParams }

end Ragu.Circuits.Endoscalar.Initial
