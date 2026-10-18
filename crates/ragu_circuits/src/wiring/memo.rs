//! Memoization scaffolding for routine contributions to $s(x, y)$.
//!
//! [`MemoCache`] stores a routine's evaluated contribution together with the
//! values of its output-gadget wires, keyed by the routine's fingerprint and
//! its canonical position in the [`FloorPlan`](crate::floor_plan::FloorPlan).
//! On a cache hit, [`WireInjector`] rebuilds the output gadget from the cached
//! wire values without re-executing the routine.
//!
//! # What a cached value depends on
//!
//! The cached scalar is the routine's *absolute* contribution to $s(x, y)$,
//! including its nested sub-routines. Besides the routine's structure (bound
//! by the [`DeepFingerprint`]), that value depends on:
//!
//! - the segment's absolute gate offset, which fixes the $X$-monomials of
//!   every wire allocated inside the routine;
//! - the segment's absolute constraint offset, which fixes the $Y$-powers;
//! - the values of the input gadget's wires, which appear in the routine's
//!   interface constraints (the book's *interface contribution*).
//!
//! The canonical position is a planning key: it groups invocations that the
//! floor planner *intends* to align, but the per-circuit floor plan still
//! places segments by DFS order. Until segments are actually relocated and
//! interface terms are separated from the cached value, an entry is only
//! valid for an invocation with the same offsets and the same input wires, so
//! [`MemoCache::lookup`] checks those before reporting a hit.

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{Error, Result, convert::WireMap, drivers::DriverTypes};
use udon::field::Field;

use crate::{DeepFingerprint, floor_plan::RegistryPosition};

/// Cached contribution of one top-level routine invocation (including its
/// nested sub-routines) at a canonical floor plan position.
///
/// On cache hit, the `output_wires` can be used to reconstruct the output gadget
/// without re-executing the routine, enabling full memoization.
#[derive(Clone, Debug)]
pub(crate) struct CachedRoutine<F> {
    /// Absolute gate offset of the segment the entry was recorded at.
    pub(crate) gate_start: usize,

    /// Absolute constraint offset of the segment the entry was recorded at.
    pub(crate) constraint_start: usize,

    /// Values of the input gadget's wires at recording time.
    pub(crate) input_wires: Vec<F>,

    /// The routine's absolute contribution to $s(x, y)$, nested
    /// sub-routines included.
    pub(crate) contribution: F,

    /// Output wire values for reconstructing the output gadget on cache hit.
    pub(crate) output_wires: Vec<F>,

    /// Number of DFS segments spanned by the routine and its sub-routines.
    /// A cache hit skips this many segments of the floor plan.
    pub(crate) num_segments: usize,
}

/// Cache for routine contributions, keyed by `(DeepFingerprint, canonical_position)`.
///
/// Used for inter-circuit memoization: when evaluating multiple circuits,
/// routines at the same canonical position can reuse cached contributions.
/// See the [module documentation](self) for the conditions under which an
/// entry is reusable.
#[derive(Clone)]
pub(crate) struct MemoCache<F> {
    entries: BTreeMap<(DeepFingerprint, RegistryPosition), CachedRoutine<F>>,
    hits: usize,
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
            hits: 0,
        }
    }

    /// Number of successful lookups so far.
    #[cfg(test)]
    pub(crate) fn hits(&self) -> usize {
        self.hits
    }

    /// Number of stored entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Stores a routine contribution in the cache.
    ///
    /// Keeps the first entry recorded for a key; later invocations at the
    /// same canonical position with a different layout are not cached.
    pub(crate) fn insert(
        &mut self,
        fingerprint: DeepFingerprint,
        canonical_position: RegistryPosition,
        entry: CachedRoutine<F>,
    ) {
        self.entries
            .entry((fingerprint, canonical_position))
            .or_insert(entry);
    }
}

impl<F: Field> MemoCache<F> {
    /// Looks up a reusable entry for an invocation of `fingerprint` at
    /// `canonical_position`.
    ///
    /// Returns `None` unless the stored entry was recorded at the same
    /// absolute offsets with the same input wires; see the
    /// [module documentation](self).
    pub(crate) fn lookup(
        &mut self,
        fingerprint: &DeepFingerprint,
        canonical_position: RegistryPosition,
        gate_start: usize,
        constraint_start: usize,
        input_wires: &[F],
    ) -> Option<&CachedRoutine<F>> {
        let entry = self.entries.get(&(*fingerprint, canonical_position))?;
        let reusable = entry.gate_start == gate_start
            && entry.constraint_start == constraint_start
            && entry.input_wires == input_wires;
        if reusable {
            self.hits += 1;
            Some(entry)
        } else {
            None
        }
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
