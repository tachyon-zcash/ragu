//! Memoization scaffolding for routine contributions to $s(x, y)$.
//!
//! [`MemoCache`] stores a routine's evaluated contribution together with the
//! values of its output-gadget wires, keyed by the routine's fingerprint and
//! the [`Placement`] of its segment. On a cache hit, [`WireInjector`] rebuilds
//! the output gadget from the cached wire values without re-executing the
//! routine.
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
//! The first two form the cache key; [`MemoCache::lookup`] checks the third
//! before reporting a hit. Reuse therefore requires an identical placement,
//! which the per-circuit floor plan only produces for circuits that emit the
//! same prefix. Position-independent caching (factoring the placement out and
//! computing interface terms per invocation) is future work.

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{Error, Result, convert::WireMap, drivers::DriverTypes};
use udon::field::Field;

use crate::DeepFingerprint;

/// Absolute offsets of a routine's segment in the polynomial layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Placement {
    /// Gate index where the segment begins.
    pub(crate) gate_start: usize,
    /// Constraint index where the segment begins.
    pub(crate) constraint_start: usize,
}

/// Cached contribution of one top-level routine invocation (including its
/// nested sub-routines) at a given [`Placement`].
///
/// On cache hit, the `output_wires` can be used to reconstruct the output gadget
/// without re-executing the routine, enabling full memoization.
#[derive(Clone, Debug)]
pub(crate) struct CachedRoutine<F> {
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

/// Cache for routine contributions, keyed by `(DeepFingerprint, Placement)`.
///
/// Used for inter-circuit memoization: when evaluating multiple circuits,
/// routines with the same placement can reuse cached contributions. See the
/// [module documentation](self) for the conditions under which an entry is
/// reusable.
#[derive(Clone)]
pub(crate) struct MemoCache<F> {
    entries: BTreeMap<(DeepFingerprint, Placement), CachedRoutine<F>>,
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
    /// same placement with different inputs are not cached.
    pub(crate) fn insert(
        &mut self,
        fingerprint: DeepFingerprint,
        placement: Placement,
        entry: CachedRoutine<F>,
    ) {
        self.entries
            .entry((fingerprint, placement))
            .or_insert(entry);
    }
}

impl<F: Field> MemoCache<F> {
    /// Looks up a reusable entry for an invocation of `fingerprint` at
    /// `placement`.
    ///
    /// Returns `None` unless the stored entry was recorded with the same
    /// input wires; see the [module documentation](self).
    pub(crate) fn lookup(
        &mut self,
        fingerprint: &DeepFingerprint,
        placement: Placement,
        input_wires: &[F],
    ) -> Option<&CachedRoutine<F>> {
        let entry = self.entries.get(&(*fingerprint, placement))?;
        if entry.input_wires == input_wires {
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
