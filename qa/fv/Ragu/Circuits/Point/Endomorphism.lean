import Ragu.Foundation.Pasta.Basic
import Ragu.Foundation.Pasta.CoordinateMap
import Ragu.Circuits.Point.Spec
import Mathlib.GroupTheory.SpecificGroups.Cyclic.Basic

/-!
# Matching coordinate roots with scalar-field eigenvalues

The two nontrivial cube roots are not interchangeable across the curve
cycle. The deployed coordinate root acts by the opposite field's deployed
root, rather than its square. Check this on the nonzero point `(-1, 2)` by
kernel reduction, then extend to the entire prime-order group.

The closed scalar multiplications use `decide +kernel`, not `native_decide`.
The extension to all points reuses the existing Pasta group-order
certificates and introduces no new axiom or native certificate.
-/

namespace Ragu.Circuits.Point.Endomorphism

open Spec Ragu.Foundation.Pasta CompElliptic.Curves.Pasta

/-- An additive map on a prime-order group is determined by any nonzero
point, so checking one generator pins the scalar action everywhere. -/
theorem eq_nsmul_of_generator {G : Type*} [AddCommGroup G] {q : ℕ} [Fact q.Prime]
    (hcard : Nat.card G = q) (φ : G →+ G) (k : ℕ) (g : G) (hg : g ≠ 0)
    (hgen : φ g = k • g) (P : G) : φ P = k • P := by
  have hmem : P ∈ AddSubgroup.zmultiples g := mem_zmultiples_of_prime_card hcard hg
  obtain ⟨n, hn⟩ := AddSubgroup.mem_zmultiples_iff.mp hmem
  rw [← hn, map_zsmul, hgen, smul_comm]

/-- Kernel-checked orientation of Pallas's coordinate endomorphism. -/
theorem pallas_generator :
    CoordinateMap.endo Pallas.curve rfl EpAffineParams.ζ EpAffineParams.h_small_order Pallas.Gpt =
      EqAffineParams.ζ.val • Pallas.Gpt := by
  decide +kernel

/-- Kernel-checked orientation of Vesta's coordinate endomorphism. -/
theorem vesta_generator :
    CoordinateMap.endo Vesta.curve rfl EqAffineParams.ζ EqAffineParams.h_small_order Vesta.Gpt =
      EpAffineParams.ζ.val • Vesta.Gpt := by
  decide +kernel

/-- Pallas's coordinate map is multiplication by the deployed Fq root. -/
theorem pallas_endo (P : PallasPoint) :
    CoordinateMap.endo Pallas.curve rfl EpAffineParams.ζ EpAffineParams.h_small_order P =
      EqAffineParams.ζ.val • P :=
  eq_nsmul_of_generator pallas_group_order _ _ Pallas.Gpt Pallas.Gpt_ne_zero pallas_generator P

/-- Vesta's coordinate map is multiplication by the deployed Fp root. -/
theorem vesta_endo (P : VestaPoint) :
    CoordinateMap.endo Vesta.curve rfl EqAffineParams.ζ EqAffineParams.h_small_order P =
      EpAffineParams.ζ.val • P :=
  eq_nsmul_of_generator vesta_group_order _ _ Vesta.Gpt Vesta.Gpt_ne_zero vesta_generator P

end Ragu.Circuits.Point.Endomorphism
