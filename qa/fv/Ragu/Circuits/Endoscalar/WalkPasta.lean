import Ragu.Circuits.Endoscalar.WalkGroup
import Ragu.Foundation.Pasta.Basic

/-!
# Unconditional non-degeneracy on the Pasta curves

The generic group proof applies to both directions of the cycle, using the
already pinned CompElliptic group-order certificates. Every affine on-curve
input admits all 47 steps. There is no `groupScaleNative ≠ none` premise.
-/

namespace Ragu.Circuits.Endoscalar.WalkPasta

open Point.Spec Walk Core.Primes Ragu.Foundation.Pasta
open CompElliptic.Curves.Pasta

/-- The deployed collision bound is below the Vesta group order. -/
theorem collisionBound_lt_p : Ragu.Lemmas.EndoscalarProof.groupScaleCollisionBound < p := by
  decide

/-- The deployed collision bound is below the Pallas group order. -/
theorem collisionBound_lt_q : Ragu.Lemmas.EndoscalarProof.groupScaleCollisionBound < q := by
  decide

/-- All 47 affine steps exist on Pallas for every native selector input. -/
theorem ep_groupScaleNative_ne_none (pt : Point (F p)) (hpt : pt.isOnCurve EpAffineParams)
    (bits : Vector (F p) numBits) : groupScaleNative EpAffineParams pt bits ≠ none := by
  exact WalkGroup.groupScaleNative_ne_none (p := p) (q := q) Pallas.curve rfl EpAffineParams rfl
    pallas_group_order collisionBound_lt_q (by decide) epAffineParams_nonzeroCoordinates pt hpt bits

/-- All 47 affine steps exist on Vesta for every native selector input. -/
theorem eq_groupScaleNative_ne_none (pt : Point (F q)) (hpt : pt.isOnCurve EqAffineParams)
    (bits : Vector (F q) numBits) : groupScaleNative EqAffineParams pt bits ≠ none := by
  exact WalkGroup.groupScaleNative_ne_none (p := q) (q := p) Vesta.curve rfl EqAffineParams rfl
    vesta_group_order collisionBound_lt_p (by decide) eqAffineParams_nonzeroCoordinates pt hpt bits

end Ragu.Circuits.Endoscalar.WalkPasta
