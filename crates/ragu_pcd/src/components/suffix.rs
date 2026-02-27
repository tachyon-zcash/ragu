use ff::Field;
use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Bound, Consistent, Gadget, GadgetKind, Kind},
};
use ragu_primitives::{
    Element,
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

impl<'dr, D: Driver<'dr>, G: GadgetKind<D::F>> Consistent<'dr, D> for WithSuffix<'dr, D, G>
where
    Bound<'dr, D, G>: Consistent<'dr, D>,
{
    fn enforce_consistent(&self, dr: &mut D) -> Result<()> {
        self.inner.enforce_consistent(dr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ragu_core::{drivers::emulator::Emulator, gadgets::Kind, maybe::Maybe};
    use ragu_pasta::Fp;
    use ragu_primitives::GadgetExt;

    /// Issue #347: Write serializes inner first, then suffix.
    #[test]
    fn write_appends_suffix_after_inner() -> Result<()> {
        let dr = &mut Emulator::execute();
        let inner = Element::constant(dr, Fp::from(10));
        let suffix = Element::constant(dr, Fp::from(20));
        let ws: WithSuffix<'_, _, Kind![Fp; Element<'_, _>]> = WithSuffix::new(inner, suffix);

        let mut buffer = vec![];
        ws.write(dr, &mut buffer)?;

        assert_eq!(buffer.len(), 2);
        assert_eq!(*buffer[0].value().take(), Fp::from(10));
        assert_eq!(*buffer[1].value().take(), Fp::from(20));
        Ok(())
    }

    /// Issue #347: enforce_consistent delegates to inner gadget.
    #[test]
    fn consistent_delegates_to_inner() -> Result<()> {
        let dr = &mut Emulator::execute();
        let inner = Element::constant(dr, Fp::from(10));
        let suffix = Element::constant(dr, Fp::from(20));
        let ws: WithSuffix<'_, _, Kind![Fp; Element<'_, _>]> = WithSuffix::new(inner, suffix);

        // Element's Consistent is a no-op; verify delegation succeeds
        ws.enforce_consistent(dr)?;
        Ok(())
    }
}
