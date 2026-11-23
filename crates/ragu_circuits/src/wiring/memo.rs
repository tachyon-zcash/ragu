//! Memoization of routine contributions to $s(x, y)$.
//!
//! [`MemoCache`] stores, per routine fingerprint, the position-free
//! [`Recorded`] contribution produced by the [`record`](super::record)
//! module. Because a recording is relative to the routine's own placement and
//! symbolic in its inputs, it can be replayed for any invocation with the
//! same [`DeepFingerprint`] — at a different offset, with different inputs,
//! within one circuit or across circuits — by evaluating
//! $y^{\ell}(x^m g_{+} + x^{-m} g_{-} + g_1 + \sum_j h_j w_j)$ at the new
//! placement. On a cache hit, [`WireInjector`] rebuilds the output gadget
//! from the replayed output wires without re-executing the routine.
//!
//! Only top-level routines are memoized; an entry covers the routine's whole
//! subtree, which is what deep-fingerprint equality guarantees to match.
//!
//! # Sharing across circuits
//!
//! When the registry evaluates many circuits at the same point, blocks that
//! sit at the same [`Placement`] in several circuits (the floor planner aligns
//! them on purpose) contribute the same position-independent vector to each.
//! In *sharing* mode the `sx`/`sy` evaluators leave that part out of their
//! per-circuit result and note the block instead; the registry then adds the
//! vector once, scaled by the sum of the circuits' Lagrange coefficients. The
//! interface part depends on each circuit's own input wires and stays
//! per-circuit.

use alloc::{collections::BTreeMap, vec::Vec};
use core::marker::PhantomData;

use ragu_core::{Error, Result, convert::WireMap, drivers::DriverTypes};
use udon::field::Field;

use super::record::Recorded;
use crate::DeepFingerprint;

/// Absolute offsets of a routine block's segment in the polynomial layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Placement {
    /// Gate index where the block begins.
    pub(crate) gate_start: usize,
    /// Constraint index where the block begins.
    pub(crate) constraint_start: usize,
}

/// Cache of recorded routine contributions, keyed by [`DeepFingerprint`].
#[derive(Clone)]
pub(crate) struct MemoCache<F> {
    entries: BTreeMap<DeepFingerprint, Recorded<F>>,
    hits: usize,
    /// Whether evaluators leave blocks' position-independent parts to the
    /// registry; see the [module documentation](self).
    sharing: bool,
    /// Blocks replayed since the last [`take_shared`](Self::take_shared),
    /// in sharing mode.
    shared: Vec<(DeepFingerprint, Placement)>,
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
            sharing: false,
            shared: Vec::new(),
        }
    }

    /// Enables sharing mode; see the [module documentation](self).
    pub(crate) fn with_sharing(mut self) -> Self {
        self.sharing = true;
        self
    }

    /// Whether sharing mode is on.
    pub(crate) fn is_sharing(&self) -> bool {
        self.sharing
    }

    /// Notes a block whose position-independent part was left out.
    pub(crate) fn note_shared(&mut self, fingerprint: DeepFingerprint, placement: Placement) {
        self.shared.push((fingerprint, placement));
    }

    /// Takes the blocks noted since the previous call.
    pub(crate) fn take_shared(&mut self) -> Vec<(DeepFingerprint, Placement)> {
        core::mem::take(&mut self.shared)
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

    /// Returns the recording for `fingerprint`, counting a hit if present.
    pub(crate) fn lookup(&mut self, fingerprint: &DeepFingerprint) -> Option<&Recorded<F>> {
        let entry = self.entries.get(fingerprint)?;
        self.hits += 1;
        Some(entry)
    }

    /// Returns the recording for `fingerprint` without counting a hit.
    pub(crate) fn get(&self, fingerprint: &DeepFingerprint) -> Option<&Recorded<F>> {
        self.entries.get(fingerprint)
    }

    /// Stores a recording for `fingerprint`.
    pub(crate) fn insert(&mut self, fingerprint: DeepFingerprint, recorded: Recorded<F>) {
        self.entries.insert(fingerprint, recorded);
    }
}

/// Injects replayed wire values into a gadget template.
///
/// Where [`extract_wires`](ragu_core::convert::extract_wires) captures wires
/// from a gadget, the injector reconstructs a gadget from a wire stream. Used
/// on cache hit to avoid re-executing routines.
///
/// The injector implements [`WireMap`] to convert from a wire-erased driver
/// (with `Wire = ()`) to a target driver with wires of type `W`, popping
/// wires in the same order that [`map_gadget`] visits them.
///
/// [`map_gadget`]: ragu_core::gadgets::GadgetKind::map_gadget
pub(crate) struct WireInjector<'a, W, Src: DriverTypes, Dst: DriverTypes> {
    wires: core::slice::Iter<'a, W>,
    _marker: PhantomData<(Src, Dst)>,
}

impl<'a, W, Src: DriverTypes, Dst: DriverTypes> WireInjector<'a, W, Src, Dst> {
    /// Creates a new wire injector from a slice of wires.
    pub(crate) fn new(wires: &'a [W]) -> Self {
        Self {
            wires: wires.iter(),
            _marker: PhantomData,
        }
    }

    /// Returns true if all wires have been consumed.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.wires.len() == 0
    }
}

impl<F, W, Src, Dst> WireMap<F> for WireInjector<'_, W, Src, Dst>
where
    F: Field,
    W: Clone,
    Src: DriverTypes<ImplField = F, ImplWire = ()>,
    Dst: DriverTypes<ImplField = F, ImplWire = W>,
{
    type Src = Src;
    type Dst = Dst;

    fn convert_wire(&mut self, _wire: &()) -> Result<W> {
        self.wires
            .next()
            .cloned()
            .ok_or_else(|| Error::InvalidWitness("wire cache underflow".into()))
    }
}
