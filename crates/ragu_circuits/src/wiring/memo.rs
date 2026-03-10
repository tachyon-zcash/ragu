//! Memoization scaffolding for routine contributions to $s(x, y)$.
//!
//! [`MemoCache`] stores a routine's evaluated contribution together with the
//! values of its output-gadget wires, keyed by the routine's fingerprint and
//! its canonical position in the [`FloorPlan`](crate::floor_plan::FloorPlan).
//! On a cache hit, [`WireInjector`] rebuilds the output gadget from the cached
//! wire values without re-executing the routine.

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{Error, Result, convert::WireMap, drivers::DriverTypes};
use udon::field::Field;

use crate::{DeepFingerprint, floor_plan::RegistryPosition};

/// Cached polynomial contribution from a routine at a canonical floor plan position.
///
/// On cache hit, the `output_wires` can be used to reconstruct the output gadget
/// without re-executing the routine, enabling full memoization.
#[derive(Clone, Debug)]
pub(crate) struct CachedRoutine<F> {
    /// The routine's contribution to the polynomial evaluation.
    pub(crate) contribution: F,

    /// Number of gates consumed by this routine.
    #[allow(dead_code)]
    pub(crate) num_gates: usize,

    /// Number of constraints consumed by this routine.
    #[allow(dead_code)]
    pub(crate) num_constraints: usize,

    /// Output wire values for reconstructing the output gadget on cache hit.
    pub(crate) output_wires: Vec<F>,
}

/// Cache for routine contributions, keyed by `(DeepFingerprint, canonical_position)`.
///
/// Used for inter-circuit memoization: when evaluating multiple circuits,
/// routines at the same canonical position can reuse cached contributions.
#[derive(Clone)]
pub(crate) struct MemoCache<F> {
    entries: BTreeMap<(DeepFingerprint, RegistryPosition), CachedRoutine<F>>,
}

impl<F> Default for MemoCache<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> MemoCache<F> {
    /// Creates an empty cache.
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Retrieves a cached routine contribution by canonical position.
    pub(crate) fn get(
        &self,
        fingerprint: &DeepFingerprint,
        canonical_position: RegistryPosition,
    ) -> Option<&CachedRoutine<F>> {
        self.entries.get(&(*fingerprint, canonical_position))
    }

    /// Stores a routine contribution in the cache.
    pub(crate) fn insert(
        &mut self,
        fingerprint: DeepFingerprint,
        canonical_position: RegistryPosition,
        entry: CachedRoutine<F>,
    ) {
        self.entries
            .insert((fingerprint, canonical_position), entry);
    }
}

/// Injects cached wire values into a gadget template.
///
/// Where [`extract_wires`](ragu_core::convert::extract_wires) captures wires
/// from a gadget into a cache, the injector reconstructs a gadget from cached
/// wires. Used on cache hit to avoid re-executing routines.
///
/// The injector implements [`WireMap`] to convert from a wire-erased driver
/// (with `Wire = ()`) to a target driver with `Wire = F`, popping cached wires
/// in the same order that [`map_gadget`] visits them.
///
/// [`map_gadget`]: ragu_core::gadgets::GadgetKind::map_gadget
pub(crate) struct WireInjector<'a, F, Src: DriverTypes, Dst: DriverTypes> {
    wires: core::slice::Iter<'a, F>,
    _marker: PhantomData<(Src, Dst)>,
}

impl<'a, F, Src: DriverTypes, Dst: DriverTypes> WireInjector<'a, F, Src, Dst> {
    /// Creates a new wire injector from a slice of cached wires.
    pub(crate) fn new(wires: &'a [F]) -> Self {
        Self {
            wires: wires.iter(),
            _marker: PhantomData,
        }
    }

    /// Returns true if all cached wires have been consumed.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.wires.len() == 0
    }
}

impl<F, Src, Dst> WireMap<F> for WireInjector<'_, F, Src, Dst>
where
    F: Field,
    Src: DriverTypes<ImplField = F, ImplWire = ()>,
    Dst: DriverTypes<ImplField = F, ImplWire = F>,
{
    type Src = Src;
    type Dst = Dst;

    fn convert_wire(&mut self, _wire: &()) -> Result<F> {
        self.wires
            .next()
            .copied()
            .ok_or_else(|| Error::InvalidWitness("wire cache underflow".into()))
    }
}
