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

use alloc::collections::BTreeMap;
use core::marker::PhantomData;

use ragu_core::{Error, Result, convert::WireMap, drivers::DriverTypes};
use udon::field::Field;

use super::record::Recorded;
use crate::DeepFingerprint;

/// Cache of recorded routine contributions, keyed by [`DeepFingerprint`].
#[derive(Clone)]
pub(crate) struct MemoCache<F> {
    entries: BTreeMap<DeepFingerprint, Recorded<F>>,
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
/// (with `Wire = ()`) to a target driver with `Wire = F`, popping wires in
/// the same order that [`map_gadget`] visits them.
///
/// [`map_gadget`]: ragu_core::gadgets::GadgetKind::map_gadget
pub(crate) struct WireInjector<'a, F, Src: DriverTypes, Dst: DriverTypes> {
    wires: core::slice::Iter<'a, F>,
    _marker: PhantomData<(Src, Dst)>,
}

impl<'a, F, Src: DriverTypes, Dst: DriverTypes> WireInjector<'a, F, Src, Dst> {
    /// Creates a new wire injector from a slice of wire values.
    pub(crate) fn new(wires: &'a [F]) -> Self {
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
