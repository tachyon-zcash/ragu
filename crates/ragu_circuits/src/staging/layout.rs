//! Stage wire indices and their locations in rx polynomials.
//!
//! A stage's rx polynomial carries its values as plain coefficients:
//! [`StageExt::rx`](super::StageExt::rx) puts the `alpha` value at the
//! SYSTEM gate alone and the values, two per gate, at the $a$ and $d$
//! wires of the stage's reserved gates in allocation order. A value can be
//! named by its reservation index (the order the stage's output gadget
//! traverses its wires) and read straight off the polynomial at the degree
//! that index maps to. These helpers let consumers identify stage fields and
//! read their values using the same layout as stage construction and loading.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_core::{
    Coeff, Result,
    convert::WireMap,
    drivers::{
        Driver, DriverTypes,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget},
    maybe::Empty,
};
use udon::field::Field;

use super::Stage;
use crate::polynomials::{Rank, sparse};

/// A driver that is never driven: its `usize` wires let a stage gadget be
/// rebound onto reservation indices, exactly as [`StageGuard`](super::StageGuard)
/// rebinds it onto the reserved wires, so a stage field can be named by index.
pub struct Indexed<F>(PhantomData<F>);

impl<F: Field> DriverTypes for Indexed<F> {
    type ImplField = F;
    type ImplWire = usize;
    type MaybeKind = Empty;
    type LCadd = ();
    type LCenforce = ();
    type Extra = ();

    fn gate(
        &mut self,
        _: impl Fn() -> Result<(Coeff<F>, Coeff<F>, Coeff<F>)>,
    ) -> Result<(usize, usize, usize, ())> {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }

    fn assign_extra(&mut self, _: (), _: impl Fn() -> Result<Coeff<F>>) -> Result<usize> {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }
}

impl<'dr, F: Field> Driver<'dr> for Indexed<F> {
    type F = F;
    type Wire = usize;
    const ONE: usize = usize::MAX;

    fn add(&mut self, _: impl Fn(())) -> usize {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }

    fn enforce_zero(&mut self, _: impl Fn(())) -> Result<()> {
        unreachable!("`Indexed` only rebinds wires; it is never driven")
    }
}

/// Hands out successive reservation indices, the way `StageWireInjector`
/// hands out successive reserved wires.
struct Indexer<F> {
    next: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> WireMap<F> for Indexer<F> {
    type Src = Emulator<Wireless<Empty, F>>;
    type Dst = Indexed<F>;

    fn convert_wire(&mut self, _: &()) -> Result<usize> {
        let index = self.next;
        self.next += 1;
        Ok(index)
    }
}

/// Collects the wires of a gadget already bound to [`Indexed`], in
/// traversal order — the same order the stage injector assigns them.
struct WireCollector<F> {
    wires: Vec<usize>,
    _marker: PhantomData<F>,
}

impl<F: Field> WireMap<F> for WireCollector<F> {
    type Src = Indexed<F>;
    type Dst = Indexed<F>;

    fn convert_wire(&mut self, wire: &usize) -> Result<usize> {
        self.wires.push(*wire);
        Ok(*wire)
    }
}

/// The reservation indices of a sub-gadget of a stage output rebound by
/// [`stage_wire_indices`] (a `Point` yields its two coordinates).
pub fn wires_of<'dr, F: Field, G: Gadget<'dr, Indexed<F>>>(gadget: &G) -> Result<Vec<usize>> {
    let mut collector = WireCollector::<F> {
        wires: Vec::new(),
        _marker: PhantomData,
    };
    gadget.map(&mut collector)?;
    Ok(collector.wires)
}

/// The reservation indices of the wires `select` picks from stage `S`'s
/// output gadget.
///
/// Runs the stage on the counter emulator, as `configure_stage` does to lay
/// the stage out, then rebinds the gadget onto indices starting at the
/// stage's first reserved wire — `2 · (skip_gates − 1)` wires precede it,
/// two per gate of every ancestor stage, the SYSTEM gate aside.
pub fn stage_wire_indices<F: Field, R: Rank, S: Stage<F, R> + Default>(
    select: impl for<'dst> FnOnce(Bound<'dst, Indexed<F>, S::OutputKind>) -> Result<Vec<usize>>,
) -> Result<Vec<usize>> {
    let mut counter = Emulator::counter();
    let stage = S::default();
    let gadget = stage.witness(&mut counter, Empty)?;
    let mut indexer = Indexer::<F> {
        next: 2 * (S::skip_gates() - 1),
        _marker: PhantomData,
    };
    let rebound = gadget.map(&mut indexer)?;
    select(rebound)
}

/// The degree at which a stage rx polynomial carries the value at
/// reservation index `index`: the $a$ wire of its gate for an even index,
/// the $d$ wire for an odd one, in the trace layout (`a[g]` at
/// $2n - 1 - g$, `d[g]` at $4n - 1 - g$), the SYSTEM gate being gate zero.
///
/// `index` must name a reserved stage wire within the rank's gate capacity.
pub fn wire_degree<R: Rank>(index: usize) -> usize {
    let gate = 1 + index / 2;
    if index.is_multiple_of(2) {
        2 * R::n() - 1 - gate
    } else {
        4 * R::n() - 1 - gate
    }
}

/// Reads a stage's values off its rx polynomial by reservation index.
pub struct StageReader<F, R> {
    coeffs: Vec<F>,
    _marker: PhantomData<R>,
}

impl<F: Field, R: Rank> StageReader<F, R> {
    /// Takes the polynomial's coefficients, densely.
    pub fn new(rx: &sparse::Polynomial<F, R>) -> Self {
        Self {
            coeffs: rx.iter_coeffs().collect(),
            _marker: PhantomData,
        }
    }

    /// The value at reservation index `index`.
    ///
    /// `index` must name a reserved stage wire within the rank's gate capacity.
    pub fn read(&self, index: usize) -> F {
        self.coeffs[wire_degree::<R>(index)]
    }
}
