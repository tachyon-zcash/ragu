//! Compositional gadget that appends an extra element during serialization.

use ragu_arithmetic::ff::Field;
use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind, Kind},
};

use crate::{
    Element, GadgetExt,
    comparison::GadgetEquals,
    consistent::Consistent,
    io::{Buffer, Write},
};

/// Compositional gadget that wraps another gadget with a suffix element appended
/// during serialization.
#[derive(Gadget)]
pub struct WithSuffix<'dr, D: Driver<'dr>, G: GadgetKind<D::F>> {
    #[ragu(gadget)]
    inner: Bound<'dr, D, G>,
    #[ragu(gadget)]
    suffix: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>, G: GadgetKind<D::F>> WithSuffix<'dr, D, G> {
    /// Create a new `WithSuffix` wrapping `inner` with the given `suffix`
    /// element appended during serialization.
    pub fn new(inner: Bound<'dr, D, G>, suffix: Element<'dr, D>) -> Self {
        WithSuffix { inner, suffix }
    }
}

impl<F: Field, K: GadgetKind<F> + Write<F>> Write<F> for Kind![F; @WithSuffix<'_, _, K>] {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Bound<'dr, D, Self>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        K::write_gadget(&this.inner, dr, buf)?;
        buf.write(dr, &this.suffix)
    }
}

impl<F: Field, K: GadgetEquals<F>> GadgetEquals<F> for Kind![F; @WithSuffix<'_, _, K>] {
    fn enforce_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        dr: &mut D1,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        K::enforce_equal_gadget(dr, &a.inner, &b.inner)?;
        a.suffix.enforce_equal(dr, &b.suffix)
    }
}

impl<'dr, D: Driver<'dr>, G: GadgetKind<D::F>> Consistent<'dr, D> for WithSuffix<'dr, D, G>
where
    Bound<'dr, D, G>: Consistent<'dr, D>,
{
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        self.inner.enforce_consistent(dr)?;
        self.suffix.enforce_consistent(dr)
    }
}
