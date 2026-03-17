//! Nested field circuits for endoscaling verification.
//!
//! These circuits operate over the scalar field and verify that the
//! commitment accumulation was computed correctly via Horner's rule.

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    polynomials::Rank,
    registry::{CircuitIndex, RegistryBuilder},
    staging::MultiStage,
};
use ragu_core::Result;

use crate::internal::endoscalar;

/// Number of curve points accumulated during `compute_p` for nested field
/// endoscaling verification.
///
/// This is the sum of:
/// - 2 proofs × 15 commitment components = 30
/// - 6 stage proof components (registry_wx0, registry_wx1, registry_wy, ab.a, ab.b, registry_xy)
/// - 1 f.commitment (base polynomial)
///
/// The endoscaling circuits process these points across
/// [`NUM_ENDOSCALING_STEPS`] steps.
pub const NUM_ENDOSCALING_POINTS: usize = 37;

/// Number of endoscaling steps, derived from [`NUM_ENDOSCALING_POINTS`] via
/// [`endoscalar::num_steps`].
const NUM_ENDOSCALING_STEPS: usize = endoscalar::num_steps(NUM_ENDOSCALING_POINTS);

/// Index of internal nested circuits registered into the registry.
///
/// These correspond to the circuit objects registered in [`register_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternalCircuitIndex {
    /// `EndoscalingStep` circuit at given step.
    EndoscalingStep(u32),
    /// `EndoscalarStage` stage mask.
    EndoscalarStage,
    /// `PointsStage` stage mask.
    PointsStage,
    /// `PointsStage` final staged mask.
    PointsFinalStaged,
}

/// The number of internal circuits registered by [`register_all`],
/// equal to the number of entries in [`InternalCircuitIndex::ALL`].
pub const NUM_INTERNAL_CIRCUITS: usize = NUM_ENDOSCALING_STEPS + 3;

impl InternalCircuitIndex {
    /// All variants in canonical iteration order.
    ///
    /// This order must match the registry finalization concatenation order
    /// in [`RegistryBuilder::finalize()`](ragu_circuits::registry::RegistryBuilder::finalize)
    /// (circuits before masks), since [`circuit_index()`](Self::circuit_index)
    /// derives indices from position in this array.
    pub const ALL: [Self; NUM_INTERNAL_CIRCUITS] = unwrap_all(Self::all_slots());

    const fn all_slots() -> [Option<Self>; NUM_INTERNAL_CIRCUITS] {
        let mut slots = [None; NUM_INTERNAL_CIRCUITS];
        let mut i = 0;
        while i < NUM_ENDOSCALING_STEPS {
            slots[i] = Some(Self::EndoscalingStep(i as u32));
            i += 1;
        }
        slots[NUM_ENDOSCALING_STEPS] = Some(Self::EndoscalarStage);
        slots[NUM_ENDOSCALING_STEPS + 1] = Some(Self::PointsStage);
        slots[NUM_ENDOSCALING_STEPS + 2] = Some(Self::PointsFinalStaged);
        slots
    }

    /// Convert to a [`CircuitIndex`] for registry lookup.
    ///
    /// Circuit indices follow the `RegistryBuilder::finalize()` concatenation
    /// order: internal circuits first, then internal masks.
    pub fn circuit_index(self) -> CircuitIndex {
        let pos = Self::ALL
            .iter()
            .position(|&v| v == self)
            .expect("every variant appears in ALL");
        CircuitIndex::new(pos)
    }
}

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
///
/// Analogous to [`native::RxIndex`](super::native::RxIndex) for the scalar
/// field. Each variant maps to a polynomial in
/// [`NestedP`](crate::proof::components::NestedP).
#[derive(Clone, Copy, Debug)]
pub enum RxIndex {
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(u32),
}

pub mod claims;

pub mod stages;

/// Registers internal nested circuits into the provided registry.
///
/// Circuits are registered as internal to ensure they occupy prefix indices
/// before application steps.
pub fn register_all<'params, C: Cycle, R: Rank>(
    mut registry: RegistryBuilder<'params, C::ScalarField, R>,
) -> Result<RegistryBuilder<'params, C::ScalarField, R>> {
    let initial_internal_circuits = registry.num_internal_circuits();

    // Circuits first, then masks — matching RegistryBuilder::finalize()
    // concatenation order and InternalCircuitIndex::circuit_index().
    for &id in &InternalCircuitIndex::ALL {
        use InternalCircuitIndex::*;
        registry = match id {
            EndoscalingStep(step) => {
                let step_circuit =
                    endoscalar::EndoscalingStep::<C::HostCurve, R, NUM_ENDOSCALING_POINTS>::new(
                        step as usize,
                    );
                let staged = MultiStage::new(step_circuit);
                registry.register_internal_circuit(staged)?
            }
            EndoscalarStage => {
                registry.register_internal_mask::<endoscalar::EndoscalarStage>()?
            }
            PointsStage => {
                registry.register_internal_mask::<endoscalar::PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS>>()?
            }
            PointsFinalStaged => {
                registry.register_internal_final_mask::<endoscalar::PointsStage<C::HostCurve, NUM_ENDOSCALING_POINTS>>()?
            }
        };
    }

    assert_eq!(
        registry.num_internal_circuits(),
        initial_internal_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(registry)
}

/// Unwraps every element of an `Option` array at compile time.
///
/// Panics (at compile time) if any slot is `None`.
const fn unwrap_all<T: Copy, const N: usize>(slots: [Option<T>; N]) -> [T; N] {
    // The filler is immediately overwritten for every index; it exists only
    // because `[T; N]` requires an initializer in const context.
    let mut arr = [slots[0].unwrap(); N];
    let mut i = 1;
    while i < N {
        arr[i] = slots[i].unwrap();
        i += 1;
    }
    arr
}
